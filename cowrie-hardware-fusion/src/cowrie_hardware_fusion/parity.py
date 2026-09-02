"""Read-only Hardware Go Agent and experimental collector parity utilities."""

from __future__ import annotations

from collections.abc import Callable, Mapping
import math
import re
import time
from typing import Any

from .batch import canonical_sha256
from .collector import CollectorConfig, LinuxSystemProbe, ProbeResult
from .dataset import DatasetContractError


SNAPSHOT_SCHEMA_VERSION = "experimental_collector_snapshot.v1"
PARITY_REPORT_SCHEMA_VERSION = "hardware_collector_parity_report.v1"
PARITY_TOOL_VERSION = "0.1.0"


def capture_experimental_snapshot(
    config: CollectorConfig,
    *,
    interval_seconds: float = 1.0,
    probe: Any | None = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Warm and sample the experimental collector without creating a sink."""

    if not 0.1 <= interval_seconds <= 60.0:
        raise DatasetContractError(
            "parity snapshot interval_seconds must be between 0.1 and 60"
        )
    runtime_probe = probe or LinuxSystemProbe(config)
    sleeper(interval_seconds)
    result: ProbeResult = runtime_probe.sample()
    document: dict[str, Any] = {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "tool_version": PARITY_TOOL_VERSION,
        "mode": "read_only_no_sink",
        "requested_interval_seconds": interval_seconds,
        "redis_write_attempted": False,
        "mongo_write_attempted": False,
        "production_service_used": False,
        "collector": {
            "collector_id": config.collector_id,
            "collector_version": config.collector_version,
            "metric_scope": config.metric_scope,
        },
        "metrics": {
            "cpu": result.cpu,
            "memory": result.memory,
            "disk": result.disk,
            "network": result.network,
            "thermal": result.thermal,
            "process": result.process,
        },
        "quality": {
            "valid": result.valid,
            "missing_fields": list(result.missing_fields),
            "counter_resets": list(result.counter_resets),
            "collector_errors": list(result.collector_errors),
        },
    }
    document["snapshot_sha256"] = canonical_sha256(document)
    return document


def _nested(document: Mapping[str, Any], path: str) -> Any:
    value: Any = document
    for component in path.split("."):
        if not isinstance(value, Mapping) or component not in value:
            return None
        value = value[component]
    return value


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return float(int(value))
    if isinstance(value, (int, float)) and math.isfinite(float(value)):
        return float(value)
    if isinstance(value, str):
        try:
            parsed = float(value)
        except ValueError:
            return None
        return parsed if math.isfinite(parsed) else None
    return None


def _interface_prefix(name: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_")
    return f"net_{sanitized}_"


def _experimental_interfaces(snapshot: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    interfaces = _nested(snapshot, "metrics.network.interfaces")
    if not isinstance(interfaces, list):
        return {}
    result: dict[str, Mapping[str, Any]] = {}
    for interface in interfaces:
        if isinstance(interface, Mapping) and isinstance(interface.get("name"), str):
            result[str(interface["name"])] = interface
    return result


def _comparison(
    *,
    name: str,
    go_field: str,
    experimental_path: str,
    go_value: Any,
    experimental_value: Any,
    absolute_tolerance: float,
    relative_tolerance: float,
    semantics: str = "same_host_metric_near_simultaneous_not_atomic",
) -> dict[str, Any]:
    go_number = _number(go_value)
    experimental_number = _number(experimental_value)
    if go_number is None or experimental_number is None:
        return {
            "name": name,
            "go_field": go_field,
            "experimental_path": experimental_path,
            "status": "unavailable",
            "go_value": go_value,
            "experimental_value": experimental_value,
            "semantics": semantics,
        }
    difference = abs(go_number - experimental_number)
    allowed = max(
        absolute_tolerance,
        relative_tolerance * max(abs(go_number), abs(experimental_number)),
    )
    return {
        "name": name,
        "go_field": go_field,
        "experimental_path": experimental_path,
        "status": "within_tolerance" if difference <= allowed else "observed_difference",
        "go_value": go_number,
        "experimental_value": experimental_number,
        "absolute_difference": difference,
        "allowed_difference": allowed,
        "absolute_tolerance": absolute_tolerance,
        "relative_tolerance": relative_tolerance,
        "semantics": semantics,
    }


def compare_hardware_snapshots(
    go_snapshot: Mapping[str, Any],
    experimental_snapshot: Mapping[str, Any],
) -> dict[str, Any]:
    """Compare the metrics that both collectors claim to observe."""

    if go_snapshot.get("schema_version") != "hardware_agent_snapshot.v1":
        raise DatasetContractError("unexpected Hardware Go Agent snapshot version")
    if experimental_snapshot.get("schema_version") != SNAPSHOT_SCHEMA_VERSION:
        raise DatasetContractError("unexpected experimental collector snapshot version")
    for label, snapshot in (
        ("go", go_snapshot),
        ("experimental", experimental_snapshot),
    ):
        if snapshot.get("mode") != "read_only_no_sink":
            raise DatasetContractError(f"{label} snapshot is not read_only_no_sink")
        if snapshot.get("redis_write_attempted") is not False:
            raise DatasetContractError(f"{label} snapshot attempted a Redis write")
        if snapshot.get("mongo_write_attempted") is not False:
            raise DatasetContractError(f"{label} snapshot attempted a Mongo write")
        if snapshot.get("production_service_used") is not False:
            raise DatasetContractError(
                f"{label} snapshot did not prove production-service isolation"
            )

    experimental_quality = experimental_snapshot.get("quality")
    if not isinstance(experimental_quality, Mapping):
        raise DatasetContractError("experimental snapshot has no quality object")
    if experimental_quality.get("valid") is not True:
        raise DatasetContractError("experimental snapshot did not pass its quality gate")

    go_metrics = go_snapshot.get("metrics")
    if not isinstance(go_metrics, Mapping):
        raise DatasetContractError("Hardware Go Agent snapshot has no metrics object")
    experimental_interfaces = _experimental_interfaces(experimental_snapshot)
    comparisons: list[dict[str, Any]] = []

    scalar_specs = (
        ("cpu.total_percent", "cpu_percent", "metrics.cpu.total_percent", 8.0, 0.25),
        (
            "memory.used_bytes",
            "mem_pressure_used_bytes",
            "metrics.memory.used_bytes",
            8_388_608.0,
            0.01,
        ),
        (
            "memory.used_percent",
            "mem_pressure_percent",
            "metrics.memory.used_percent",
            0.25,
            0.01,
        ),
        (
            "disk.root_used_bytes",
            "disk_used_bytes",
            "metrics.disk.root_used_bytes",
            33_554_432.0,
            0.005,
        ),
        (
            "disk.root_used_percent",
            "disk_percent",
            "metrics.disk.root_used_percent",
            0.5,
            0.01,
        ),
        (
            "thermal.temperature_c",
            "temperature",
            "metrics.thermal.temperature_c",
            2.0,
            0.05,
        ),
    )
    for name, go_field, experimental_path, absolute, relative in scalar_specs:
        comparisons.append(
            _comparison(
                name=name,
                go_field=go_field,
                experimental_path=experimental_path,
                go_value=go_metrics.get(go_field),
                experimental_value=_nested(experimental_snapshot, experimental_path),
                absolute_tolerance=absolute,
                relative_tolerance=relative,
            )
        )

    interface_specs = (
        ("up", "up", 0.0, 0.0),
        ("rx_bytes_total", "rx_bytes_total", 1_048_576.0, 0.001),
        ("tx_bytes_total", "tx_bytes_total", 1_048_576.0, 0.001),
        ("rx_packets_total", "rx_packets_total", 2_000.0, 0.001),
        ("tx_packets_total", "tx_packets_total", 2_000.0, 0.001),
        ("rx_errors_total", "rx_errors_total", 0.0, 0.0),
        ("tx_errors_total", "tx_errors_total", 0.0, 0.0),
        ("rx_dropped_total", "rx_drops_total", 0.0, 0.0),
        ("tx_dropped_total", "tx_drops_total", 0.0, 0.0),
        ("rx_bytes_per_second", "rx_bytes_per_second", 16_384.0, 0.75),
        ("tx_bytes_per_second", "tx_bytes_per_second", 16_384.0, 0.75),
        ("rx_packets_per_second", "rx_packets_per_second", 128.0, 0.75),
        ("tx_packets_per_second", "tx_packets_per_second", 128.0, 0.75),
    )
    for interface_name, interface in sorted(experimental_interfaces.items()):
        prefix = _interface_prefix(interface_name)
        for go_suffix, experimental_field, absolute, relative in interface_specs:
            go_field = prefix + go_suffix
            comparisons.append(
                _comparison(
                    name=f"network.{interface_name}.{experimental_field}",
                    go_field=go_field,
                    experimental_path=(
                        f"metrics.network.interfaces[name={interface_name}].{experimental_field}"
                    ),
                    go_value=go_metrics.get(go_field),
                    experimental_value=interface.get(experimental_field),
                    absolute_tolerance=absolute,
                    relative_tolerance=relative,
                )
            )

    counts = {
        status: sum(item["status"] == status for item in comparisons)
        for status in ("within_tolerance", "observed_difference", "unavailable")
    }
    report: dict[str, Any] = {
        "schema_version": PARITY_REPORT_SCHEMA_VERSION,
        "tool_version": PARITY_TOOL_VERSION,
        "purpose": "collector_feature_parity_audit_not_training_data",
        "source": {
            "go_snapshot_sha256": canonical_sha256(go_snapshot),
            "experimental_snapshot_sha256": canonical_sha256(experimental_snapshot),
        },
        "summary": {
            "comparison_count": len(comparisons),
            **counts,
            "quality_gate_passed": counts["observed_difference"] == 0
            and counts["unavailable"] == 0,
        },
        "semantic_decisions": {
            "training_memory_used_semantics": "total_minus_available",
            "go_training_fields": [
                "mem_pressure_used_bytes",
                "mem_pressure_percent",
            ],
            "go_legacy_fields_preserved_for_dashboards": [
                "mem_used_bytes",
                "mem_percent",
            ],
            "legacy_memory_semantics": "total_minus_free_buffers_cached",
        },
        "comparisons": comparisons,
        "limitations": [
            "The two user-space collectors are started concurrently but are not atomic.",
            "CPU and rate fields may cover slightly different scheduler intervals.",
            "Repeat snapshots check semantics and plumbing, not long-term distribution drift.",
            "The snapshot must not be used as a training row.",
        ],
    }
    report["report_sha256"] = canonical_sha256(report)
    return report
