from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from cowrie_hardware_fusion.cli import main as cli_main
from cowrie_hardware_fusion.dataset import DatasetContractError, build_training_window


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _example(name: str) -> dict:
    path = PROJECT_ROOT / "schemas" / "examples" / name
    return json.loads(path.read_text(encoding="utf-8"))


def _fixture_run(workload_cpu: list[float] | None = None) -> tuple[dict, list[dict]]:
    manifest = _example("experiment_run_manifest.v1.example.json")
    manifest["state"] = "completed"
    sample_template = _example("hardware_telemetry_sample.v1.example.json")
    workload_cpu = workload_cpu or [float(value) for value in range(10, 40)]
    assert len(workload_cpu) == 30

    samples: list[dict] = []
    for sequence in range(60):
        sample = deepcopy(sample_template)
        sample["sample_id"] = f"sample-test-{sequence:06d}"
        sample["phase"] = "baseline" if sequence < 30 else "workload"
        sample["time"]["sequence"] = sequence
        sample["time"]["monotonic_ns"] = (sequence + 1) * 1_000_000_000
        sample["time"]["observed_at"] = f"2026-09-01T08:00:{sequence:02d}Z"
        cpu = 10.0 if sequence < 30 else workload_cpu[sequence - 30]
        sample["cpu"]["total_percent"] = cpu
        sample["cpu"]["per_core_percent"] = [cpu, cpu, cpu, cpu]
        samples.append(sample)
    return manifest, samples


def _build(manifest: dict, samples: list[dict], **overrides: object) -> dict:
    arguments = {
        "metric_scope": "pi_sensor",
        "phase": "workload",
        "horizon_seconds": 30,
        "minimum_coverage": 0.99,
    }
    arguments.update(overrides)
    return build_training_window(manifest, samples, **arguments)


def test_builds_xgboost_features_and_fixed_length_tcn_channels() -> None:
    manifest, samples = _fixture_run()

    record = _build(manifest, samples)

    features = record["xgboost"]["features"]
    assert features["cpu_mean"] == pytest.approx(24.5)
    assert features["cpu_max"] == 39.0
    assert features["cpu_p95"] == pytest.approx(37.55)
    assert features["cpu_delta_from_baseline_mean"] == pytest.approx(14.5)
    assert features["cpu_slope_per_second"] == pytest.approx(1.0)
    assert record["tcn"]["channels"]["cpu_total_percent"] == [
        float(value) for value in range(10, 40)
    ]
    assert record["tcn"]["sample_present"] == [1] * 30
    assert all(len(values) == 30 for values in record["tcn"]["channels"].values())
    assert "run_id" not in features
    assert "scenario_id" not in features


def test_cpu_p95_is_not_changed_by_one_isolated_maximum() -> None:
    manifest, samples = _fixture_run([10.0] * 29 + [100.0])

    record = _build(manifest, samples)

    assert record["xgboost"]["features"]["cpu_p95"] == 10.0
    assert record["xgboost"]["features"]["cpu_max"] == 100.0


def test_missing_sample_fails_default_gate_but_is_masked_when_explicitly_allowed() -> None:
    manifest, samples = _fixture_run()
    samples = [sample for sample in samples if sample["time"]["sequence"] != 45]

    with pytest.raises(DatasetContractError, match="target sample coverage"):
        _build(manifest, samples)

    record = _build(manifest, samples, minimum_coverage=0.95)
    assert record["quality"]["sample_coverage"] == pytest.approx(29 / 30)
    assert record["quality"]["missing_sequences"] == [45]
    assert record["tcn"]["sample_present"][15] == 0
    assert record["tcn"]["channels"]["cpu_total_percent"][15] == 0.0


def test_missing_first_workload_sample_does_not_shift_window_alignment() -> None:
    manifest, samples = _fixture_run()
    samples = [sample for sample in samples if sample["time"]["sequence"] != 30]

    record = _build(manifest, samples, minimum_coverage=0.95)

    assert record["window"]["start_sequence"] == 30
    assert record["quality"]["missing_sequences"] == [30]
    assert record["tcn"]["sample_present"][0] == 0


def test_duplicate_sample_identity_is_rejected() -> None:
    manifest, samples = _fixture_run()
    samples.append(deepcopy(samples[-1]))

    with pytest.raises(DatasetContractError, match="duplicate sample_id"):
        _build(manifest, samples)


def test_mismatched_run_is_rejected() -> None:
    manifest, samples = _fixture_run()
    samples[0]["run_id"] = "different-run"

    with pytest.raises(DatasetContractError, match="run_id does not match"):
        _build(manifest, samples)


def test_output_is_deterministic_and_validates_against_schema() -> None:
    manifest, samples = _fixture_run()

    first = _build(manifest, samples)
    second = _build(manifest, list(reversed(samples)))

    assert first == second
    schema = json.loads(
        (PROJECT_ROOT / "schemas" / "derived_training_window.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator(schema).validate(first)


def test_cli_validates_sources_and_writes_a_derived_record(tmp_path: Path) -> None:
    manifest, samples = _fixture_run()
    manifest_path = tmp_path / "manifest.json"
    telemetry_path = tmp_path / "telemetry.jsonl"
    output_path = tmp_path / "window.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    telemetry_path.write_text(
        "".join(json.dumps(sample) + "\n" for sample in samples),
        encoding="utf-8",
    )

    exit_code = cli_main(
        [
            "build-window",
            "--manifest",
            str(manifest_path),
            "--telemetry",
            str(telemetry_path),
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == 0
    record = json.loads(output_path.read_text(encoding="utf-8"))
    assert record["schema_version"] == "derived_training_window.v1"
    assert record["quality"]["sample_coverage"] == 1.0
