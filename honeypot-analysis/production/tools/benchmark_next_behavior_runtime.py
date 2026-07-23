"""Measure real CPU checkpoint loading and corrected-target inference."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import statistics
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence

from production.prediction.next_behavior_model import (
    load_checkpoint,
    predict_next_behavior,
    require_valid_model_spec,
    sha256_file,
)
from production.prediction.next_behavior_experiment_policy import (
    experiment_policy_sha256,
    load_experiment_policy,
    require_valid_experiment_policy,
)
from production.prediction.next_behavior_tensor import (
    require_valid_vocabulary,
    vocabulary_sha256,
)
from production.utils.serialization import stable_json


RUNTIME_BENCHMARK_SCHEMA_VERSION = "next_behavior_runtime_benchmark.v1"


class RuntimeBenchmarkError(ValueError):
    """Raised when real model inference cannot be measured safely."""


def _rss_bytes() -> int | None:
    """Read current process RSS without adding a mandatory dependency."""

    try:
        for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    except (OSError, UnicodeError, ValueError, IndexError):
        return None
    return None


def _percentile(values: Sequence[float], probability: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise RuntimeBenchmarkError("latency sample is empty")
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def benchmark_checkpoint_runtime(
    *,
    checkpoint_path: str | Path,
    expected_checkpoint_sha256: str,
    model_spec: Mapping[str, Any],
    tensor_inputs: Sequence[Mapping[str, Any]],
    experiment_policy: Mapping[str, Any],
    expected_experiment_policy_sha256: str,
    warmup_iterations: int = 25,
    measured_iterations: int = 200,
) -> Dict[str, Any]:
    """Benchmark checkpoint load and actual forward passes on CPU.

    Each measured operation calls the production inference function.  Saved
    predictions or lookup tables are neither accepted nor timed.
    """

    if (
        isinstance(warmup_iterations, bool)
        or not isinstance(warmup_iterations, int)
        or warmup_iterations < 1
    ):
        raise RuntimeBenchmarkError("warmup_iterations must be positive")
    if (
        isinstance(measured_iterations, bool)
        or not isinstance(measured_iterations, int)
        or measured_iterations < 1
    ):
        raise RuntimeBenchmarkError("measured_iterations must be positive")
    if (
        not isinstance(tensor_inputs, Sequence)
        or isinstance(tensor_inputs, (str, bytes))
        or not tensor_inputs
    ):
        raise RuntimeBenchmarkError("tensor_inputs must be a non-empty sequence")
    try:
        spec = require_valid_model_spec(dict(model_spec))
        policy = require_valid_experiment_policy(dict(experiment_policy))
    except Exception as exc:
        raise RuntimeBenchmarkError("frozen runtime configuration is invalid") from exc
    policy_hash = experiment_policy_sha256(policy)
    if policy_hash != expected_experiment_policy_sha256:
        raise RuntimeBenchmarkError("experiment policy hash mismatch")
    if spec["architecture"] != policy["architecture"]:
        raise RuntimeBenchmarkError("model architecture and experiment policy disagree")
    checkpoint = Path(checkpoint_path)
    rss_before = _rss_bytes()
    load_started = time.perf_counter_ns()
    try:
        model, metadata = load_checkpoint(
            checkpoint,
            expected_spec=spec,
            expected_checkpoint_sha256=expected_checkpoint_sha256,
        )
    except Exception as exc:
        raise RuntimeBenchmarkError("checkpoint load verification failed") from exc
    load_ns = time.perf_counter_ns() - load_started
    rss_after_load = _rss_bytes()
    if model.training:
        raise RuntimeBenchmarkError("loaded model is not in evaluation mode")
    if any(parameter.device.type != "cpu" for parameter in model.parameters()):
        raise RuntimeBenchmarkError("loaded model is not CPU resident")

    for index in range(warmup_iterations):
        predict_next_behavior(
            model,
            tensor_inputs[index % len(tensor_inputs)],
            spec=spec,
        )
    latencies_ns: list[int] = []
    output_hashes: list[str] = []
    rss_peak = _rss_bytes()
    measured_started = time.perf_counter_ns()
    for index in range(measured_iterations):
        tensor = tensor_inputs[index % len(tensor_inputs)]
        started = time.perf_counter_ns()
        output = predict_next_behavior(model, tensor, spec=spec)
        latencies_ns.append(time.perf_counter_ns() - started)
        output_hashes.append(
            hashlib.sha256(stable_json(output).encode("utf-8")).hexdigest()
        )
        current_rss = _rss_bytes()
        if current_rss is not None:
            rss_peak = max(rss_peak or current_rss, current_rss)
    measured_ns = time.perf_counter_ns() - measured_started
    latency_ms = [value / 1_000_000.0 for value in latencies_ns]
    distinct_by_tensor: Dict[str, set[str]] = {}
    for index, output_hash in enumerate(output_hashes):
        tensor_hash = str(tensor_inputs[index % len(tensor_inputs)].get("tensor_hash"))
        distinct_by_tensor.setdefault(tensor_hash, set()).add(output_hash)
    if any(len(values) != 1 for values in distinct_by_tensor.values()):
        raise RuntimeBenchmarkError("repeated inference is nondeterministic")
    checkpoint_size = checkpoint.stat().st_size
    load_seconds = load_ns / 1_000_000_000.0
    p95 = _percentile(latency_ms, 0.95)
    rss_delta = (
        None
        if rss_before is None or rss_peak is None
        else max(rss_peak - rss_before, 0)
    )
    budgets = policy["runtime_budgets"]
    checks = {
        "checkpoint_size": checkpoint_size <= budgets["maximum_checkpoint_bytes"],
        "checkpoint_load": load_seconds <= budgets["maximum_checkpoint_load_seconds"],
        "p95_single_case_latency": (
            p95 <= budgets["maximum_p95_single_case_latency_ms"]
        ),
        "process_rss_delta": (
            None
            if rss_delta is None
            else rss_delta <= budgets["maximum_process_rss_delta_bytes"]
        ),
    }
    return {
        "schema_version": RUNTIME_BENCHMARK_SCHEMA_VERSION,
        "status": "complete",
        "measurement": "real_cpu_checkpoint_load_and_forward_inference",
        "checkpoint_sha256": metadata["checkpoint_sha256"],
        "state_dictionary_sha256": metadata["state_dictionary_sha256"],
        "model_spec_sha256": spec["spec_sha256"],
        "architecture_sha256": spec["architecture_sha256"],
        "device": "cpu",
        "dtype": "float32",
        "experiment_policy_sha256": policy_hash,
        "checkpoint_size_bytes": checkpoint_size,
        "parameter_count": metadata["parameter_count"],
        "load_latency_ms": load_ns / 1_000_000.0,
        "warmup_iterations": warmup_iterations,
        "measured_iterations": measured_iterations,
        "tensor_count": len(tensor_inputs),
        "latency_ms": {
            "mean": statistics.fmean(latency_ms),
            "p50": _percentile(latency_ms, 0.50),
            "p95": p95,
            "p99": _percentile(latency_ms, 0.99),
            "minimum": min(latency_ms),
            "maximum": max(latency_ms),
        },
        "throughput_inferences_per_second": (
            measured_iterations / (measured_ns / 1_000_000_000.0)
        ),
        "throughput_mode": "repeated_real_single_case_forward_passes",
        "rss": {
            "available": rss_before is not None and rss_after_load is not None,
            "before_load_bytes": rss_before,
            "after_load_bytes": rss_after_load,
            "load_delta_bytes": (
                None
                if rss_before is None or rss_after_load is None
                else rss_after_load - rss_before
            ),
            "peak_during_inference_bytes": rss_peak,
        },
        "deterministic_replay": True,
        "unique_tensor_count": len(distinct_by_tensor),
        "budget_evaluation": {
            "budgets": budgets,
            "checks": checks,
            "passed": all(value is not False for value in checks.values()),
            "rss_check_available": checks["process_rss_delta"] is not None,
        },
    }


def runtime_failure_result(
    error: RuntimeBenchmarkError,
    *,
    expected_checkpoint_sha256: str,
    expected_experiment_policy_sha256: str,
) -> Dict[str, Any]:
    """Return a stable, non-sensitive failure receipt for an attempted run."""

    message = str(error)
    known_codes = {
        "frozen runtime configuration is invalid": "invalid_configuration",
        "experiment policy hash mismatch": "policy_hash_mismatch",
        "model architecture and experiment policy disagree": (
            "architecture_policy_mismatch"
        ),
        "checkpoint load verification failed": "checkpoint_verification_failed",
        "loaded model is not in evaluation mode": "model_not_in_eval_mode",
        "loaded model is not CPU resident": "model_not_cpu_resident",
        "repeated inference is nondeterministic": "nondeterministic_inference",
    }
    code = known_codes.get(message, "runtime_measurement_failed")
    return {
        "schema_version": RUNTIME_BENCHMARK_SCHEMA_VERSION,
        "status": "failed",
        "error_code": code,
        "expected_checkpoint_sha256": expected_checkpoint_sha256,
        "expected_experiment_policy_sha256": (
            expected_experiment_policy_sha256
        ),
        "failure_details": [],
    }


def write_runtime_result(path: str | Path, result: Mapping[str, Any]) -> None:
    """Create one result atomically and never overwrite an accepted measurement."""

    destination = Path(path)
    if destination.exists():
        raise RuntimeBenchmarkError("runtime output already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(stable_json(dict(result)) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary_name, destination)
    except FileExistsError as exc:
        raise RuntimeBenchmarkError("runtime output already exists") from exc
    finally:
        try:
            Path(temporary_name).unlink()
        except FileNotFoundError:
            pass


def _read_json(path: str | Path, *, name: str) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeBenchmarkError(f"{name} is not valid JSON") from exc


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--checkpoint-sha256", required=True)
    parser.add_argument("--model-spec", required=True)
    parser.add_argument("--vocabulary", required=True)
    parser.add_argument("--experiment-policy", required=True)
    parser.add_argument("--experiment-policy-sha256", required=True)
    parser.add_argument("--tensors", required=True)
    parser.add_argument("--warmup", type=int, default=25)
    parser.add_argument("--iterations", type=int, default=200)
    parser.add_argument("--output", required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        # Vocabulary verification is explicit even though tensors and model
        # spec bind its digest.
        vocabulary = require_valid_vocabulary(
            _read_json(args.vocabulary, name="vocabulary")
        )
        spec = require_valid_model_spec(
            _read_json(args.model_spec, name="model spec")
        )
        experiment_policy = load_experiment_policy(args.experiment_policy)
        if spec["vocabulary_sha256"] != vocabulary_sha256(vocabulary):
            raise RuntimeBenchmarkError("model spec and vocabulary disagree")
        tensors = _read_json(args.tensors, name="tensor inputs")
        result = benchmark_checkpoint_runtime(
            checkpoint_path=args.checkpoint,
            expected_checkpoint_sha256=args.checkpoint_sha256,
            model_spec=spec,
            tensor_inputs=tensors,
            experiment_policy=experiment_policy,
            expected_experiment_policy_sha256=args.experiment_policy_sha256,
            warmup_iterations=args.warmup,
            measured_iterations=args.iterations,
        )
    except Exception as exc:
        failure = (
            exc
            if isinstance(exc, RuntimeBenchmarkError)
            else RuntimeBenchmarkError("frozen runtime configuration is invalid")
        )
        result = runtime_failure_result(
            failure,
            expected_checkpoint_sha256=args.checkpoint_sha256,
            expected_experiment_policy_sha256=(
                args.experiment_policy_sha256
            ),
        )
        write_runtime_result(args.output, result)
        return 2
    write_runtime_result(args.output, result)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
