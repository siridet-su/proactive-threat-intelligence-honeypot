from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

import cowrie_hardware_fusion.collector as collector_module
from cowrie_hardware_fusion.collector import (
    CollectorConfig,
    ProbeResult,
    collect_idle_run,
    collector_preflight,
    collector_source_sha256,
    finalize_idle_manifest,
)
from cowrie_hardware_fusion.dataset import DatasetContractError, build_training_window
from cowrie_hardware_fusion.spool import SpoolLimits


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class FakeClock:
    def __init__(self) -> None:
        self._origin_ns = 1_000_000_000
        self._current_ns = self._origin_ns
        self._origin_wall = datetime(2026, 9, 1, 8, 0, 0, tzinfo=timezone.utc)

    def monotonic_ns(self) -> int:
        return self._current_ns

    def now_utc(self) -> datetime:
        elapsed = (self._current_ns - self._origin_ns) / 1_000_000_000
        return self._origin_wall + timedelta(seconds=elapsed)

    def sleep_until_ns(self, deadline_ns: int) -> None:
        self._current_ns = max(self._current_ns, deadline_ns)


class FakeProbe:
    def __init__(self, sample_template: dict) -> None:
        self.boot_id_sha256 = "1" * 64
        self._template = sample_template
        self._sequence = 0

    def sample(self) -> ProbeResult:
        source = deepcopy(self._template)
        source["cpu"]["total_percent"] = 10.0 + self._sequence / 10.0
        source["cpu"]["per_core_percent"] = [source["cpu"]["total_percent"]] * 4
        self._sequence += 1
        return ProbeResult(
            cpu=source["cpu"],
            memory=source["memory"],
            disk=source["disk"],
            network=source["network"],
            thermal=source["thermal"],
            process=source["process"],
        )


def _manifest() -> dict:
    manifest = _load_json(
        PROJECT_ROOT / "schemas" / "examples" / "experiment_run_manifest.v1.example.json"
    )
    manifest["collection"]["collector_sha256"] = collector_source_sha256()
    return manifest


def _config(tmp_path: Path) -> CollectorConfig:
    document = _load_json(
        PROJECT_ROOT
        / "configs"
        / "experimental_collector.pi_sensor.pilot.example.json"
    )
    config = CollectorConfig.from_document(document)
    return replace(
        config,
        spool_directory=tmp_path,
        spool_limits=SpoolLimits(
            max_total_bytes=10_000_000,
            min_free_bytes=0,
            segment_max_bytes=100_000,
            segment_max_records=20,
        ),
    )


def test_example_config_validates_and_preflight_checks_real_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _manifest()
    config_document = _load_json(
        PROJECT_ROOT
        / "configs"
        / "experimental_collector.pi_sensor.pilot.example.json"
    )
    config_schema = _load_json(
        PROJECT_ROOT / "schemas" / "experimental_collector_config.v1.schema.json"
    )
    Draft202012Validator(config_schema).validate(config_document)
    config = _config(tmp_path)
    monkeypatch.setattr(
        collector_module.psutil,
        "net_io_counters",
        lambda *, pernic: {"wlan0": object(), "tailscale0": object(), "lo": object()},
    )
    monkeypatch.setattr(
        collector_module.psutil,
        "disk_io_counters",
        lambda *, perdisk: {"mmcblk0p2": object()},
    )

    report = collector_preflight(
        manifest,
        config,
        schema_dir=PROJECT_ROOT / "schemas",
        ntp_synchronized=True,
    )

    assert report["expected_records"] == 90
    assert report["available_disk_devices"] == ["mmcblk0p2"]
    assert report["optional_missing_interfaces"] == []


def _all_segment_samples(config: CollectorConfig, manifest: dict, receipt: dict) -> list[dict]:
    run_dir = (
        config.spool_directory
        / f"run={manifest['run_id']}"
        / f"scope={config.metric_scope}"
    )
    samples: list[dict] = []
    for segment in receipt["segments"]:
        for line in (run_dir / segment["filename"]).read_text(encoding="utf-8").splitlines():
            samples.append(json.loads(line))
    return samples


def test_idle_collector_spools_schema_valid_data_that_dataset_builder_can_replay(
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    config = _config(tmp_path)
    sample_template = _load_json(
        PROJECT_ROOT / "schemas" / "examples" / "hardware_telemetry_sample.v1.example.json"
    )

    receipt = collect_idle_run(
        manifest,
        config,
        schema_dir=PROJECT_ROOT / "schemas",
        probe=FakeProbe(sample_template),
        clock=FakeClock(),
        ntp_synchronized=True,
    )

    assert receipt["record_count"] == 90
    assert receipt["phase_record_counts"] == {
        "baseline": 30,
        "workload": 30,
        "recovery": 30,
    }
    assert [segment["record_count"] for segment in receipt["segments"]] == [20, 20, 20, 20, 10]

    receipt_schema = _load_json(
        PROJECT_ROOT / "schemas" / "experiment_collection_receipt.v1.schema.json"
    )
    Draft202012Validator(receipt_schema).validate(receipt)
    telemetry_schema = _load_json(
        PROJECT_ROOT / "schemas" / "hardware_telemetry_sample.v1.schema.json"
    )
    validator = Draft202012Validator(telemetry_schema)
    samples = _all_segment_samples(config, manifest, receipt)
    assert len(samples) == 90
    for sample in samples:
        validator.validate(sample)

    run_dir = (
        config.spool_directory
        / f"run={manifest['run_id']}"
        / f"scope={config.metric_scope}"
    )
    completed_manifest = finalize_idle_manifest(
        manifest,
        receipt,
        run_dir=run_dir,
        schema_dir=PROJECT_ROOT / "schemas",
    )
    assert completed_manifest["state"] == "completed"
    assert receipt["receipt_id"] in completed_manifest["labels"]["evidence_receipt_ids"]
    window = build_training_window(
        completed_manifest,
        samples,
        metric_scope="pi_sensor",
        phase="workload",
        horizon_seconds=30,
    )
    assert window["quality"]["sample_coverage"] == 1.0
    assert window["xgboost"]["features"]["cpu_p95"] == pytest.approx(15.755)


def test_manifest_finalization_rejects_tampered_segment(tmp_path: Path) -> None:
    manifest = _manifest()
    config = _config(tmp_path)
    sample_template = _load_json(
        PROJECT_ROOT / "schemas" / "examples" / "hardware_telemetry_sample.v1.example.json"
    )
    receipt = collect_idle_run(
        manifest,
        config,
        schema_dir=PROJECT_ROOT / "schemas",
        probe=FakeProbe(sample_template),
        clock=FakeClock(),
    )
    run_dir = (
        config.spool_directory
        / f"run={manifest['run_id']}"
        / f"scope={config.metric_scope}"
    )
    first_segment = run_dir / receipt["segments"][0]["filename"]
    first_segment.chmod(0o600)
    original = first_segment.read_bytes()
    first_segment.write_bytes(original + original.splitlines(keepends=True)[0])

    with pytest.raises(DatasetContractError, match="noncontiguous segment sequence"):
        finalize_idle_manifest(
            manifest,
            receipt,
            run_dir=run_dir,
            schema_dir=PROJECT_ROOT / "schemas",
        )


def test_idle_collector_rejects_non_idle_scenario_before_writing(tmp_path: Path) -> None:
    manifest = _manifest()
    manifest["workload"]["scenario_id"] = "compute_hijacking_simulation"
    config = _config(tmp_path)
    sample_template = _load_json(
        PROJECT_ROOT / "schemas" / "examples" / "hardware_telemetry_sample.v1.example.json"
    )

    with pytest.raises(DatasetContractError, match="restricted to neutral_idle"):
        collect_idle_run(
            manifest,
            config,
            schema_dir=PROJECT_ROOT / "schemas",
            probe=FakeProbe(sample_template),
            clock=FakeClock(),
        )

    assert not list(tmp_path.rglob("*"))
