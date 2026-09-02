from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from cowrie_hardware_fusion.instrumentation import (
    build_service_pressure_instrumentation_matrix,
    summarize_service_pressure_signals,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _build() -> tuple[dict, list[tuple[dict, dict | None]]]:
    return build_service_pressure_instrumentation_matrix(
        generation="v1",
        experiment_id="service-pressure-instrumentation-v1",
        image_id="sha256:" + "1" * 64,
        implementation_sha256="2" * 64,
        repo_commit="3" * 40,
        environment_signature_sha256="4" * 64,
        sensor_id="sensor-redacted",
        host_id="pi-host-pseudonymous-01",
        collector_id="experimental-telemetry-collector",
        protocol_path=PROJECT_ROOT
        / "configs"
        / "hardware_impact_experiment_protocol.v2.json",
        catalog_path=PROJECT_ROOT / "configs" / "scenario_catalog.v1.json",
        schema_dir=PROJECT_ROOT / "schemas",
    )


def test_instrumentation_matrix_is_hash_bound_excluded_and_schema_valid() -> None:
    matrix, documents = _build()
    Draft202012Validator(
        _load_json(
            PROJECT_ROOT
            / "schemas"
            / "service_pressure_instrumentation_matrix.v1.schema.json"
        )
    ).validate(matrix)
    manifest_validator = Draft202012Validator(
        _load_json(PROJECT_ROOT / "schemas" / "experiment_run_manifest.v1.schema.json")
    )
    specification_validator = Draft202012Validator(
        _load_json(
            PROJECT_ROOT / "schemas" / "service_pressure_workload_spec.v1.schema.json"
        )
    )

    assert matrix["run_count"] == 7
    assert matrix["estimated_total_seconds"] == 630
    assert matrix["pilot_only"] is True
    assert matrix["training_eligible"] is False
    assert matrix["changes_frozen_feature_set"] is False
    assert len(documents) == 7
    for manifest, specification in documents:
        manifest_validator.validate(manifest)
        assert manifest["provenance"]["pilot_only"] is True
        if specification is not None:
            specification_validator.validate(specification)


def test_matched_benign_malicious_pairs_have_identical_hardware_treatment() -> None:
    _, documents = _build()
    specifications = {
        manifest["workload"]["scenario_id"]: specification
        for manifest, specification in documents
        if specification is not None
    }
    for benign_id, malicious_id in (
        ("v2_benign_compute_high", "v2_t1496_001_compute_high"),
        ("v2_benign_service_high", "v2_t1499_002_service_high"),
    ):
        benign = specifications[benign_id]
        malicious = specifications[malicious_id]
        assert benign is not None and malicious is not None
        assert benign["treatment"] == malicious["treatment"]
        assert benign["limits"] == malicious["limits"]
        benign_parameters = dict(benign["parameters"])
        malicious_parameters = dict(malicious["parameters"])
        benign_parameters.pop("deterministic_seed")
        malicious_parameters.pop("deterministic_seed")
        assert benign_parameters == malicious_parameters


def test_signal_report_measures_host_delta_and_target_workload_availability() -> None:
    _, documents = _build()
    manifest = deepcopy(documents[2][0])
    manifest["state"] = "completed"
    template = _load_json(
        PROJECT_ROOT
        / "schemas"
        / "examples"
        / "hardware_telemetry_sample.v1.example.json"
    )
    samples: list[dict] = []
    for sequence in range(90):
        phase = "baseline" if sequence < 30 else "workload" if sequence < 60 else "recovery"
        sample = deepcopy(template)
        sample["sample_id"] = f"sample-v1-{sequence:040d}"
        sample["run_id"] = manifest["run_id"]
        sample["experiment_id"] = manifest["experiment_id"]
        sample["phase"] = phase
        sample["time"]["sequence"] = sequence
        sample["time"]["monotonic_ns"] = (sequence + 1) * 1_000_000_000
        stall_rate = 100.0 if phase == "baseline" else 400.0 if phase == "workload" else 150.0
        sample["cpu"]["pressure"] = {
            "some": {
                "avg10_percent": 0.0,
                "avg60_percent": 0.0,
                "avg300_percent": 0.0,
                "total_stall_usec": sequence * 100,
                "stall_usec_per_second": stall_rate,
            }
        }
        if phase == "workload":
            sample["process"]["target"] = {
                "process_id_hash": "5" * 64,
                "parent_process_id_hash": None,
                "cpu_percent_single_core_basis": 50.0,
                "rss_bytes": 4096,
                "thread_count": 1,
                "socket_count": 3,
                "cgroup_id": "6" * 64,
                "cgroup": {"cpu": {"usage_usec_per_second": 250000.0}},
            }
        else:
            sample["process"]["target"] = None
        samples.append(sample)

    report = summarize_service_pressure_signals(
        manifest,
        samples,
        collection_receipt_sha256="8" * 64,
        source_segments=[{"filename": "part-test.jsonl", "sha256": "7" * 64}],
    )
    Draft202012Validator(
        _load_json(
            PROJECT_ROOT / "schemas" / "service_pressure_signal_report.v1.schema.json"
        )
    ).validate(report)
    by_id = {signal["signal_id"]: signal for signal in report["signals"]}

    assert by_id["host_cpu_psi_some"]["workload_delta_from_baseline_mean"] == 300.0
    assert by_id["host_cpu_psi_some"]["eligible_for_feature_freeze_review"] is True
    assert by_id["cgroup_cpu_usage_rate"]["baseline_applicable"] is False
    assert by_id["cgroup_cpu_usage_rate"]["workload"]["coverage"] == 1.0
    assert by_id["cgroup_cpu_usage_rate"]["workload_delta_from_baseline_mean"] is None
    assert report["model_feature_eligible"] is False
