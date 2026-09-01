"""Create deterministic XGBoost features and TCN sequences from one experiment run.

This module deliberately keeps identifiers, labels, and split groups outside the model
input blocks. It does not normalize, impute from a population, or assign a dataset split;
those operations must be fit/frozen from the development partition later.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from hashlib import sha256
import json
import math
from statistics import fmean, pstdev
from typing import Any


BUILDER_VERSION = "0.1.0"
WINDOW_SCHEMA_VERSION = "derived_training_window.v1"
FEATURE_SCHEMA_VERSION = "xgboost_hardware_features.v1"
CHANNEL_SCHEMA_VERSION = "tcn_hardware_channels.v1"


class DatasetContractError(ValueError):
    """Raised when source records cannot produce an auditable training window."""


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DatasetContractError(message)


def _number(value: Any, path: str) -> float:
    _require(
        isinstance(value, (int, float)) and not isinstance(value, bool),
        f"{path} must be numeric",
    )
    result = float(value)
    _require(math.isfinite(result), f"{path} must be finite")
    return result


def _nested_number(document: Mapping[str, Any], path: str) -> float:
    current: Any = document
    for component in path.split("."):
        _require(isinstance(current, Mapping), f"{path} is missing")
        _require(component in current, f"{path} is missing")
        current = current[component]
    return _number(current, path)


def _percentile(values: Sequence[float], percentile: float) -> float:
    """Return a linearly interpolated percentile, equivalent to NumPy's default."""

    _require(values, "cannot calculate a percentile from an empty series")
    _require(0.0 <= percentile <= 100.0, "percentile must be between 0 and 100")
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile / 100.0
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    weight = position - lower
    return float(ordered[lower] * (1.0 - weight) + ordered[upper] * weight)


def _slope(points: Sequence[tuple[float, float]]) -> float:
    """Least-squares slope in metric units per second."""

    if len(points) < 2:
        return 0.0
    x_mean = fmean(point[0] for point in points)
    y_mean = fmean(point[1] for point in points)
    denominator = sum((x - x_mean) ** 2 for x, _ in points)
    if denominator == 0.0:
        return 0.0
    return sum((x - x_mean) * (y - y_mean) for x, y in points) / denominator


def _sum_items(
    sample: Mapping[str, Any],
    collection_path: str,
    value_name: str,
) -> float:
    current: Any = sample
    for component in collection_path.split("."):
        _require(isinstance(current, Mapping), f"{collection_path} is missing")
        _require(component in current, f"{collection_path} is missing")
        current = current[component]
    _require(isinstance(current, list), f"{collection_path} must be an array")
    total = 0.0
    for index, item in enumerate(current):
        _require(isinstance(item, Mapping), f"{collection_path}[{index}] must be an object")
        total += _number(item.get(value_name), f"{collection_path}[{index}].{value_name}")
    return total


def _optional_number(value: Any, path: str) -> float | None:
    if value is None:
        return None
    return _number(value, path)


def _validate_manifest(manifest: Mapping[str, Any]) -> None:
    _require(
        manifest.get("schema_version") == "experiment_run_manifest.v1",
        "unsupported run manifest schema_version",
    )
    _require(manifest.get("state") == "completed", "run manifest state must be completed")
    _require(isinstance(manifest.get("run_id"), str), "manifest run_id is missing")
    _require(isinstance(manifest.get("experiment_id"), str), "manifest experiment_id is missing")
    timing = manifest.get("timing")
    _require(isinstance(timing, Mapping), "manifest timing is missing")
    interval = _number(timing.get("sample_interval_seconds"), "timing.sample_interval_seconds")
    _require(interval > 0.0, "sample interval must be positive")
    _require(isinstance(manifest.get("labels"), Mapping), "manifest labels are missing")
    _require(isinstance(manifest.get("split_groups"), Mapping), "manifest split_groups are missing")


def _validate_samples(
    manifest: Mapping[str, Any],
    samples: Sequence[Mapping[str, Any]],
    metric_scope: str,
) -> list[Mapping[str, Any]]:
    _require(samples, "telemetry input is empty")
    run_id = manifest["run_id"]
    experiment_id = manifest["experiment_id"]
    seen_sample_ids: set[str] = set()
    seen_sequences: set[int] = set()
    boot_ids: set[str] = set()

    for position, sample in enumerate(samples):
        prefix = f"sample[{position}]"
        _require(
            sample.get("schema_version") == "hardware_telemetry_sample.v1",
            f"{prefix} has unsupported schema_version",
        )
        _require(sample.get("run_id") == run_id, f"{prefix} run_id does not match manifest")
        _require(
            sample.get("experiment_id") == experiment_id,
            f"{prefix} experiment_id does not match manifest",
        )
        _require(sample.get("metric_scope") == metric_scope, f"{prefix} metric_scope mismatch")
        sample_id = sample.get("sample_id")
        _require(isinstance(sample_id, str), f"{prefix} sample_id is missing")
        _require(sample_id not in seen_sample_ids, f"duplicate sample_id: {sample_id}")
        seen_sample_ids.add(sample_id)

        time = sample.get("time")
        _require(isinstance(time, Mapping), f"{prefix}.time is missing")
        sequence = time.get("sequence")
        _require(isinstance(sequence, int) and not isinstance(sequence, bool), f"{prefix} sequence is invalid")
        _require(sequence not in seen_sequences, f"duplicate sequence: {sequence}")
        seen_sequences.add(sequence)
        boot_id = time.get("boot_id_sha256")
        _require(isinstance(boot_id, str), f"{prefix} boot_id_sha256 is missing")
        boot_ids.add(boot_id)

        _require(isinstance(sample.get("quality"), Mapping), f"{prefix}.quality is missing")
        for required_block in ("cpu", "memory", "disk", "network", "thermal", "process"):
            _require(isinstance(sample.get(required_block), Mapping), f"{prefix}.{required_block} is missing")

    _require(len(boot_ids) == 1, "a training window cannot cross host boots")
    ordered = sorted(samples, key=lambda item: item["time"]["sequence"])
    monotonic_values: list[int] = []
    for position, item in enumerate(ordered):
        monotonic_ns = item["time"].get("monotonic_ns")
        _require(
            isinstance(monotonic_ns, int) and not isinstance(monotonic_ns, bool),
            f"ordered sample[{position}] monotonic_ns is invalid",
        )
        monotonic_values.append(monotonic_ns)
    _require(
        all(right > left for left, right in zip(monotonic_values, monotonic_values[1:])),
        "monotonic_ns must strictly increase with sequence",
    )
    return ordered


def _valid(sample: Mapping[str, Any]) -> bool:
    return sample["quality"].get("valid") is True


def _series(
    samples: Sequence[Mapping[str, Any]],
    start_sequence: int,
    interval: float,
    extractor: Callable[[Mapping[str, Any]], float | None],
) -> list[tuple[float, float]]:
    points: list[tuple[float, float]] = []
    for sample in samples:
        if not _valid(sample):
            continue
        value = extractor(sample)
        if value is None:
            continue
        offset_seconds = (sample["time"]["sequence"] - start_sequence) * interval
        points.append((offset_seconds, float(value)))
    return points


def _values(points: Sequence[tuple[float, float]]) -> list[float]:
    return [value for _, value in points]


def _mean_or_zero(values: Sequence[float]) -> float:
    return float(fmean(values)) if values else 0.0


def _max_or_zero(values: Sequence[float]) -> float:
    return float(max(values)) if values else 0.0


def _p95_or_zero(values: Sequence[float]) -> float:
    return _percentile(values, 95.0) if values else 0.0


def _std_or_zero(values: Sequence[float]) -> float:
    return float(pstdev(values)) if len(values) > 1 else 0.0


def _target_value(sample: Mapping[str, Any], field: str) -> float | None:
    target = sample["process"].get("target")
    if not isinstance(target, Mapping):
        return None
    return _optional_number(target.get(field), f"process.target.{field}")


def _temperature(sample: Mapping[str, Any]) -> float | None:
    return _optional_number(sample["thermal"].get("temperature_c"), "thermal.temperature_c")


def _per_core_imbalance(sample: Mapping[str, Any]) -> float:
    values = [
        _number(value, "cpu.per_core_percent[]")
        for value in sample["cpu"].get("per_core_percent", [])
    ]
    _require(values, "cpu.per_core_percent cannot be empty")
    return float(pstdev(values)) if len(values) > 1 else 0.0


def _aggregate_features(
    target: Sequence[Mapping[str, Any]],
    baseline: Sequence[Mapping[str, Any]],
    start_sequence: int,
    interval: float,
    sample_coverage: float,
    baseline_coverage: float,
) -> dict[str, float]:
    def points(extractor: Callable[[Mapping[str, Any]], float | None]) -> list[tuple[float, float]]:
        return _series(target, start_sequence, interval, extractor)

    def baseline_values(extractor: Callable[[Mapping[str, Any]], float | None]) -> list[float]:
        baseline_start = baseline[0]["time"]["sequence"] if baseline else 0
        return _values(_series(baseline, baseline_start, interval, extractor))

    cpu_points = points(lambda sample: _nested_number(sample, "cpu.total_percent"))
    cpu = _values(cpu_points)
    baseline_cpu = baseline_values(lambda sample: _nested_number(sample, "cpu.total_percent"))
    core_imbalance = _values(points(_per_core_imbalance))

    memory_percent = _values(points(lambda sample: _nested_number(sample, "memory.used_percent")))
    memory_bytes = _values(points(lambda sample: _nested_number(sample, "memory.used_bytes")))
    memory_available = _values(points(lambda sample: _nested_number(sample, "memory.available_bytes")))
    baseline_memory_percent = baseline_values(lambda sample: _nested_number(sample, "memory.used_percent"))
    baseline_memory_bytes = baseline_values(lambda sample: _nested_number(sample, "memory.used_bytes"))

    disk_read = _values(points(lambda sample: _sum_items(sample, "disk.devices", "read_bytes_per_second")))
    disk_write = _values(points(lambda sample: _sum_items(sample, "disk.devices", "write_bytes_per_second")))
    root_used = _values(points(lambda sample: _nested_number(sample, "disk.root_used_percent")))
    baseline_root_used = baseline_values(lambda sample: _nested_number(sample, "disk.root_used_percent"))

    net_rx_bytes = _values(points(lambda sample: _sum_items(sample, "network.interfaces", "rx_bytes_per_second")))
    net_tx_bytes = _values(points(lambda sample: _sum_items(sample, "network.interfaces", "tx_bytes_per_second")))
    net_rx_packets = _values(points(lambda sample: _sum_items(sample, "network.interfaces", "rx_packets_per_second")))
    net_tx_packets = _values(points(lambda sample: _sum_items(sample, "network.interfaces", "tx_packets_per_second")))
    connections = _values(points(lambda sample: _nested_number(sample, "network.connection_count")))
    sockets = _values(points(lambda sample: _nested_number(sample, "network.socket_count")))
    unique_destinations = _values(points(lambda sample: _number(sample["network"].get("unique_destination_count", 0), "network.unique_destination_count")))
    dns_qps = _values(points(lambda sample: _number(sample["network"].get("dns_queries_per_second", 0), "network.dns_queries_per_second")))
    baseline_connections = baseline_values(lambda sample: _nested_number(sample, "network.connection_count"))

    temperatures = _values(points(_temperature))
    baseline_temperatures = baseline_values(_temperature)
    valid_target = [sample for sample in target if _valid(sample)]
    throttled = [1.0 if sample["thermal"].get("throttled") is True else 0.0 for sample in valid_target]
    undervoltage = [1.0 if sample["thermal"].get("undervoltage") is True else 0.0 for sample in valid_target]

    process_counts = _values(points(lambda sample: _nested_number(sample, "process.process_count")))
    thread_counts = _values(points(lambda sample: _nested_number(sample, "process.thread_count")))
    baseline_process_counts = baseline_values(lambda sample: _nested_number(sample, "process.process_count"))
    baseline_thread_counts = baseline_values(lambda sample: _nested_number(sample, "process.thread_count"))
    target_cpu = _values(points(lambda sample: _target_value(sample, "cpu_percent_single_core_basis")))
    target_rss = _values(points(lambda sample: _target_value(sample, "rss_bytes")))
    target_sockets = _values(points(lambda sample: _target_value(sample, "socket_count")))

    valid_count = max(len(valid_target), 1)
    features = {
        "sample_coverage": sample_coverage,
        "baseline_coverage": baseline_coverage,
        "cpu_mean": _mean_or_zero(cpu),
        "cpu_max": _max_or_zero(cpu),
        "cpu_p95": _p95_or_zero(cpu),
        "cpu_std": _std_or_zero(cpu),
        "cpu_slope_per_second": _slope(cpu_points),
        "cpu_delta_from_baseline_mean": _mean_or_zero(cpu) - _mean_or_zero(baseline_cpu),
        "cpu_seconds_above_70": sum(interval for value in cpu if value > 70.0),
        "cpu_seconds_above_90": sum(interval for value in cpu if value > 90.0),
        "per_core_imbalance_mean": _mean_or_zero(core_imbalance),
        "memory_used_percent_mean": _mean_or_zero(memory_percent),
        "memory_used_percent_max": _max_or_zero(memory_percent),
        "memory_used_percent_p95": _p95_or_zero(memory_percent),
        "memory_used_percent_delta_from_baseline": _mean_or_zero(memory_percent) - _mean_or_zero(baseline_memory_percent),
        "memory_used_bytes_delta_from_baseline": _mean_or_zero(memory_bytes) - _mean_or_zero(baseline_memory_bytes),
        "memory_available_bytes_min": float(min(memory_available)) if memory_available else 0.0,
        "disk_read_bytes_per_second_max": _max_or_zero(disk_read),
        "disk_read_bytes_per_second_p95": _p95_or_zero(disk_read),
        "disk_write_bytes_per_second_max": _max_or_zero(disk_write),
        "disk_write_bytes_per_second_p95": _p95_or_zero(disk_write),
        "root_used_percent_delta_from_baseline": _mean_or_zero(root_used) - _mean_or_zero(baseline_root_used),
        "network_rx_bytes_per_second_max": _max_or_zero(net_rx_bytes),
        "network_rx_bytes_per_second_p95": _p95_or_zero(net_rx_bytes),
        "network_tx_bytes_per_second_max": _max_or_zero(net_tx_bytes),
        "network_tx_bytes_per_second_p95": _p95_or_zero(net_tx_bytes),
        "network_rx_packets_per_second_max": _max_or_zero(net_rx_packets),
        "network_rx_packets_per_second_p95": _p95_or_zero(net_rx_packets),
        "network_tx_packets_per_second_max": _max_or_zero(net_tx_packets),
        "network_tx_packets_per_second_p95": _p95_or_zero(net_tx_packets),
        "network_connection_count_max": _max_or_zero(connections),
        "network_connection_count_p95": _p95_or_zero(connections),
        "network_connection_count_delta_from_baseline": _mean_or_zero(connections) - _mean_or_zero(baseline_connections),
        "network_socket_count_max": _max_or_zero(sockets),
        "network_unique_destination_count_max": _max_or_zero(unique_destinations),
        "network_dns_queries_per_second_max": _max_or_zero(dns_qps),
        "temperature_available_fraction": len(temperatures) / valid_count,
        "baseline_temperature_available_fraction": (
            len(baseline_temperatures) / len(baseline) if baseline else 0.0
        ),
        "temperature_mean_c": _mean_or_zero(temperatures),
        "temperature_max_c": _max_or_zero(temperatures),
        "temperature_delta_from_baseline_c": (
            _mean_or_zero(temperatures) - _mean_or_zero(baseline_temperatures)
            if temperatures and baseline_temperatures
            else 0.0
        ),
        "thermal_throttled_fraction": _mean_or_zero(throttled),
        "thermal_undervoltage_fraction": _mean_or_zero(undervoltage),
        "process_count_mean": _mean_or_zero(process_counts),
        "process_count_max": _max_or_zero(process_counts),
        "process_count_delta_from_baseline": _mean_or_zero(process_counts) - _mean_or_zero(baseline_process_counts),
        "thread_count_max": _max_or_zero(thread_counts),
        "thread_count_delta_from_baseline": _mean_or_zero(thread_counts) - _mean_or_zero(baseline_thread_counts),
        "target_process_present_fraction": len(target_cpu) / valid_count,
        "target_cpu_percent_p95": _p95_or_zero(target_cpu),
        "target_cpu_percent_max": _max_or_zero(target_cpu),
        "target_rss_bytes_p95": _p95_or_zero(target_rss),
        "target_rss_bytes_max": _max_or_zero(target_rss),
        "target_socket_count_max": _max_or_zero(target_sockets),
    }
    return {name: float(value) for name, value in sorted(features.items())}


_SEQUENCE_EXTRACTORS: dict[str, Callable[[Mapping[str, Any]], float | None]] = {
    "cpu_total_percent": lambda sample: _nested_number(sample, "cpu.total_percent"),
    "memory_used_percent": lambda sample: _nested_number(sample, "memory.used_percent"),
    "disk_read_bytes_per_second": lambda sample: _sum_items(sample, "disk.devices", "read_bytes_per_second"),
    "disk_write_bytes_per_second": lambda sample: _sum_items(sample, "disk.devices", "write_bytes_per_second"),
    "network_rx_bytes_per_second": lambda sample: _sum_items(sample, "network.interfaces", "rx_bytes_per_second"),
    "network_tx_bytes_per_second": lambda sample: _sum_items(sample, "network.interfaces", "tx_bytes_per_second"),
    "network_rx_packets_per_second": lambda sample: _sum_items(sample, "network.interfaces", "rx_packets_per_second"),
    "network_tx_packets_per_second": lambda sample: _sum_items(sample, "network.interfaces", "tx_packets_per_second"),
    "network_connection_count": lambda sample: _nested_number(sample, "network.connection_count"),
    "network_socket_count": lambda sample: _nested_number(sample, "network.socket_count"),
    "temperature_c": _temperature,
    "process_count": lambda sample: _nested_number(sample, "process.process_count"),
    "thread_count": lambda sample: _nested_number(sample, "process.thread_count"),
    "target_cpu_percent": lambda sample: _target_value(sample, "cpu_percent_single_core_basis"),
    "target_rss_bytes": lambda sample: _target_value(sample, "rss_bytes"),
    "target_socket_count": lambda sample: _target_value(sample, "socket_count"),
}


def _sequence_channels(
    target_by_sequence: Mapping[int, Mapping[str, Any]],
    start_sequence: int,
    expected_count: int,
) -> tuple[dict[str, list[float]], list[int], dict[str, list[int]]]:
    channels = {name: [] for name in _SEQUENCE_EXTRACTORS}
    channel_present = {name: [] for name in _SEQUENCE_EXTRACTORS}
    sample_present: list[int] = []

    for sequence in range(start_sequence, start_sequence + expected_count):
        sample = target_by_sequence.get(sequence)
        sample_is_valid = sample is not None and _valid(sample)
        sample_present.append(1 if sample_is_valid else 0)
        for name, extractor in _SEQUENCE_EXTRACTORS.items():
            value = extractor(sample) if sample_is_valid and sample is not None else None
            channels[name].append(float(value) if value is not None else 0.0)
            channel_present[name].append(1 if value is not None else 0)

    return channels, sample_present, channel_present


def build_training_window(
    manifest: Mapping[str, Any],
    samples: Iterable[Mapping[str, Any]],
    *,
    metric_scope: str,
    phase: str = "workload",
    horizon_seconds: int = 30,
    minimum_coverage: float = 0.99,
) -> dict[str, Any]:
    """Build one deterministic hardware feature/sequence record.

    The target window starts at the first observed sequence labelled with ``phase``.
    Population-derived normalization and imputation are intentionally deferred until
    after the run-level split is frozen.
    """

    _validate_manifest(manifest)
    _require(phase in {"workload", "recovery"}, "phase must be workload or recovery")
    _require(horizon_seconds > 0, "horizon_seconds must be positive")
    _require(0.0 <= minimum_coverage <= 1.0, "minimum_coverage must be between 0 and 1")

    sample_list = list(samples)
    ordered = _validate_samples(manifest, sample_list, metric_scope)
    interval = _number(manifest["timing"]["sample_interval_seconds"], "timing.sample_interval_seconds")
    expected_float = horizon_seconds / interval
    expected_count = round(expected_float)
    _require(
        math.isclose(expected_float, expected_count, abs_tol=1e-9),
        "horizon_seconds must be an exact multiple of sample_interval_seconds",
    )

    baseline_expected_float = (
        _number(manifest["timing"]["baseline_seconds"], "timing.baseline_seconds") / interval
    )
    baseline_expected = round(baseline_expected_float)
    _require(
        math.isclose(baseline_expected_float, baseline_expected, abs_tol=1e-9),
        "baseline_seconds must be an exact multiple of sample_interval_seconds",
    )
    all_baseline = [sample for sample in ordered if sample.get("phase") == "baseline"]
    _require(all_baseline, "no telemetry samples found for phase=baseline")
    baseline_start_sequence = all_baseline[0]["time"]["sequence"]
    baseline_end_sequence = baseline_start_sequence + baseline_expected - 1
    baseline = [
        sample
        for sample in all_baseline
        if baseline_start_sequence <= sample["time"]["sequence"] <= baseline_end_sequence
    ]

    workload_expected_float = (
        _number(manifest["timing"]["workload_seconds"], "timing.workload_seconds") / interval
    )
    workload_expected = round(workload_expected_float)
    _require(
        math.isclose(workload_expected_float, workload_expected, abs_tol=1e-9),
        "workload_seconds must be an exact multiple of sample_interval_seconds",
    )
    phase_capacity_seconds = (
        _number(manifest["timing"]["workload_seconds"], "timing.workload_seconds")
        if phase == "workload"
        else _number(manifest["timing"]["recovery_seconds"], "timing.recovery_seconds")
    )
    _require(
        horizon_seconds <= phase_capacity_seconds,
        f"{horizon_seconds}s horizon exceeds the manifest {phase} duration",
    )
    phase_offset = baseline_expected if phase == "workload" else baseline_expected + workload_expected
    start_sequence = baseline_start_sequence + phase_offset
    end_sequence = start_sequence + expected_count - 1
    target = [
        sample
        for sample in ordered
        if sample.get("phase") == phase
        and start_sequence <= sample["time"]["sequence"] <= end_sequence
    ]
    _require(target, f"no telemetry samples found for phase={phase}")
    target_by_sequence = {sample["time"]["sequence"]: sample for sample in target}
    valid_target_count = sum(1 for sample in target if _valid(sample))
    coverage = valid_target_count / expected_count

    valid_baseline = [sample for sample in baseline if _valid(sample)]
    baseline_coverage = min(len(valid_baseline) / baseline_expected, 1.0) if baseline_expected else 0.0

    _require(coverage >= minimum_coverage, f"target sample coverage {coverage:.4f} is below {minimum_coverage:.4f}")
    _require(
        baseline_coverage >= minimum_coverage,
        f"baseline sample coverage {baseline_coverage:.4f} is below {minimum_coverage:.4f}",
    )
    _require(
        all(sample["time"].get("ntp_synchronized") is True for sample in [*valid_baseline, *target]),
        "baseline and target samples must report ntp_synchronized=true",
    )

    features = _aggregate_features(
        target,
        valid_baseline,
        start_sequence,
        interval,
        coverage,
        baseline_coverage,
    )
    channels, sample_present, channel_present = _sequence_channels(
        target_by_sequence,
        start_sequence,
        expected_count,
    )

    missing_sequences = [
        sequence
        for sequence in range(start_sequence, end_sequence + 1)
        if sequence not in target_by_sequence or not _valid(target_by_sequence[sequence])
    ]
    quality = {
        "expected_samples": expected_count,
        "observed_samples": len(target),
        "valid_samples": valid_target_count,
        "sample_coverage": coverage,
        "baseline_expected_samples": baseline_expected,
        "baseline_valid_samples": len(valid_baseline),
        "baseline_coverage": baseline_coverage,
        "missing_sequences": missing_sequences,
        "late_sample_count": sum(1 for sample in target if sample["quality"].get("sample_late") is True),
        "counter_reset_count": sum(len(sample["quality"].get("counter_resets", [])) for sample in target),
        "collector_error_count": sum(len(sample["quality"].get("collector_errors", [])) for sample in target),
    }

    record: dict[str, Any] = {
        "schema_version": WINDOW_SCHEMA_VERSION,
        "record_id": f"{manifest['run_id']}:{metric_scope}:{phase}:{horizon_seconds}s",
        "window": {
            "run_id": manifest["run_id"],
            "experiment_id": manifest["experiment_id"],
            "metric_scope": metric_scope,
            "phase": phase,
            "horizon_seconds": horizon_seconds,
            "sample_interval_seconds": interval,
            "start_sequence": start_sequence,
            "end_sequence": end_sequence,
        },
        "labels": {
            "scenario_disposition": manifest["labels"]["scenario_disposition"],
            "primary_impact": manifest["labels"]["primary_impact"],
            "observed_impacts": list(manifest["labels"]["observed_impacts"]),
            "ground_truth_ttps": list(manifest["labels"]["ground_truth_ttps"]),
        },
        "split_groups": dict(manifest["split_groups"]),
        "xgboost": {
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "features": features,
        },
        "tcn": {
            "channel_schema_version": CHANNEL_SCHEMA_VERSION,
            "channel_order": list(_SEQUENCE_EXTRACTORS),
            "channels": channels,
            "sample_present": sample_present,
            "channel_present": channel_present,
        },
        "quality": quality,
        "provenance": {
            "builder_version": BUILDER_VERSION,
            "manifest_content_sha256": _canonical_sha256(manifest),
            "contributing_samples_content_sha256": _canonical_sha256([*valid_baseline, *target]),
        },
    }
    record["record_sha256"] = _canonical_sha256(record)
    return record
