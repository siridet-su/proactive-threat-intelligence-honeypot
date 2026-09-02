from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from cowrie_hardware_fusion.collector import CollectorConfig, ProbeResult
from cowrie_hardware_fusion.dataset import DatasetContractError
from cowrie_hardware_fusion.parity import (
    capture_experimental_snapshot,
    compare_hardware_snapshots,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _config() -> CollectorConfig:
    document = json.loads(
        (
            PROJECT_ROOT
            / "configs"
            / "experimental_collector.pi_sensor.pilot.example.json"
        ).read_text(encoding="utf-8")
    )
    return CollectorConfig.from_document(document)


class FakeProbe:
    def __init__(self, result: ProbeResult) -> None:
        self.result = result

    def sample(self) -> ProbeResult:
        return self.result


def _probe_result() -> ProbeResult:
    sample = json.loads(
        (
            PROJECT_ROOT
            / "schemas"
            / "examples"
            / "hardware_telemetry_sample.v1.example.json"
        ).read_text(encoding="utf-8")
    )
    return ProbeResult(
        cpu=sample["cpu"],
        memory=sample["memory"],
        disk=sample["disk"],
        network=sample["network"],
        thermal=sample["thermal"],
        process=sample["process"],
    )


def _go_snapshot(experimental: dict) -> dict:
    metrics = experimental["metrics"]
    values: dict = {
        "cpu_percent": str(metrics["cpu"]["total_percent"]),
        "mem_pressure_used_bytes": metrics["memory"]["used_bytes"],
        "mem_pressure_percent": str(metrics["memory"]["used_percent"]),
        "disk_used_bytes": metrics["disk"]["root_used_bytes"],
        "disk_percent": str(metrics["disk"]["root_used_percent"]),
        "temperature": str(metrics["thermal"]["temperature_c"]),
    }
    for interface in metrics["network"]["interfaces"]:
        prefix = "net_" + interface["name"] + "_"
        values[prefix + "up"] = int(interface["up"])
        for field in (
            "rx_bytes_total",
            "tx_bytes_total",
            "rx_packets_total",
            "tx_packets_total",
            "rx_errors_total",
            "tx_errors_total",
            "rx_bytes_per_second",
            "tx_bytes_per_second",
            "rx_packets_per_second",
            "tx_packets_per_second",
        ):
            values[prefix + field] = interface[field]
        values[prefix + "rx_dropped_total"] = interface["rx_drops_total"]
        values[prefix + "tx_dropped_total"] = interface["tx_drops_total"]
    return {
        "schema_version": "hardware_agent_snapshot.v1",
        "mode": "read_only_no_sink",
        "redis_write_attempted": False,
        "mongo_write_attempted": False,
        "production_service_used": False,
        "metrics": values,
    }


def test_capture_snapshot_is_explicitly_sink_free_and_hash_bound() -> None:
    slept: list[float] = []

    snapshot = capture_experimental_snapshot(
        _config(),
        interval_seconds=1.0,
        probe=FakeProbe(_probe_result()),
        sleeper=slept.append,
    )

    assert slept == [1.0]
    assert snapshot["mode"] == "read_only_no_sink"
    assert snapshot["redis_write_attempted"] is False
    assert snapshot["mongo_write_attempted"] is False
    assert snapshot["quality"]["valid"] is True
    assert len(snapshot["snapshot_sha256"]) == 64


def test_compare_reports_matching_common_metrics() -> None:
    experimental = capture_experimental_snapshot(
        _config(),
        probe=FakeProbe(_probe_result()),
        sleeper=lambda _: None,
    )

    report = compare_hardware_snapshots(_go_snapshot(experimental), experimental)

    assert report["summary"]["comparison_count"] == 19
    assert report["summary"]["within_tolerance"] == 19
    assert report["summary"]["observed_difference"] == 0
    assert report["summary"]["unavailable"] == 0
    assert report["summary"]["quality_gate_passed"] is True


def test_compare_surfaces_difference_and_missing_field() -> None:
    experimental = capture_experimental_snapshot(
        _config(),
        probe=FakeProbe(_probe_result()),
        sleeper=lambda _: None,
    )
    go_snapshot = _go_snapshot(experimental)
    go_snapshot["metrics"]["cpu_percent"] = "99.0"
    go_snapshot["metrics"].pop("net_wlan0_rx_packets_total")

    report = compare_hardware_snapshots(go_snapshot, experimental)

    assert report["summary"]["observed_difference"] == 1
    assert report["summary"]["unavailable"] == 1
    assert report["summary"]["quality_gate_passed"] is False


def test_compare_rejects_snapshot_without_sink_and_service_isolation() -> None:
    experimental = capture_experimental_snapshot(
        _config(),
        probe=FakeProbe(_probe_result()),
        sleeper=lambda _: None,
    )
    unsafe = deepcopy(_go_snapshot(experimental))
    unsafe["redis_write_attempted"] = True

    with pytest.raises(DatasetContractError, match="Redis write"):
        compare_hardware_snapshots(unsafe, experimental)

    unsafe = deepcopy(_go_snapshot(experimental))
    unsafe["production_service_used"] = True
    with pytest.raises(DatasetContractError, match="production-service isolation"):
        compare_hardware_snapshots(unsafe, experimental)

    invalid_experimental = deepcopy(experimental)
    invalid_experimental["quality"]["valid"] = False
    with pytest.raises(DatasetContractError, match="quality gate"):
        compare_hardware_snapshots(_go_snapshot(experimental), invalid_experimental)
