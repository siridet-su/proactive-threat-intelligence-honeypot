from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from production.tools import benchmark_next_behavior_runtime as runtime


TORCH_AVAILABLE = importlib.util.find_spec("torch") is not None


def test_percentile_is_interpolated_and_parameter_validation_fails_early() -> None:
    assert runtime._percentile([1.0, 2.0, 3.0], 0.5) == 2.0
    assert runtime._percentile([1.0, 2.0], 0.5) == 1.5
    with pytest.raises(runtime.RuntimeBenchmarkError, match="warmup"):
        runtime.benchmark_checkpoint_runtime(
            checkpoint_path="missing",
            expected_checkpoint_sha256="0" * 64,
            model_spec={},
            tensor_inputs=[{}],
            experiment_policy={},
            expected_experiment_policy_sha256="0" * 64,
            warmup_iterations=0,
        )


def test_runtime_result_is_atomic_and_never_overwritten(tmp_path: Path) -> None:
    output = tmp_path / "runtime.json"
    result = {
        "schema_version": runtime.RUNTIME_BENCHMARK_SCHEMA_VERSION,
        "status": "complete",
    }
    runtime.write_runtime_result(output, result)
    original = output.read_bytes()

    with pytest.raises(runtime.RuntimeBenchmarkError, match="already exists"):
        runtime.write_runtime_result(output, {"changed": True})
    assert output.read_bytes() == original
    assert not list(tmp_path.glob(".*.tmp"))


def test_cli_records_deterministic_failure_without_partial_output(
    tmp_path: Path,
) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{}\n", encoding="utf-8")
    output = tmp_path / "failed.json"
    status = runtime.main(
        [
            "--checkpoint",
            str(tmp_path / "missing.pt"),
            "--checkpoint-sha256",
            "1" * 64,
            "--model-spec",
            str(invalid),
            "--vocabulary",
            str(invalid),
            "--experiment-policy",
            str(invalid),
            "--experiment-policy-sha256",
            "2" * 64,
            "--tensors",
            str(invalid),
            "--output",
            str(output),
        ]
    )

    assert status == 2
    receipt = json.loads(output.read_text(encoding="utf-8"))
    assert receipt["status"] == "failed"
    assert receipt["error_code"] == "invalid_configuration"
    assert receipt["failure_details"] == []


def test_invalid_frozen_configuration_has_a_stable_failure_class() -> None:
    with pytest.raises(runtime.RuntimeBenchmarkError, match="configuration"):
        runtime.benchmark_checkpoint_runtime(
            checkpoint_path="missing-checkpoint.pt",
            expected_checkpoint_sha256="0" * 64,
            model_spec={
                # Model spec validation happens before loading.  This test only
                # asserts malformed runs never produce a success artifact.
            },
            tensor_inputs=[{"tensor_hash": "fixture"}],
            experiment_policy={},
            expected_experiment_policy_sha256="0" * 64,
        )

    receipt = runtime.runtime_failure_result(
        runtime.RuntimeBenchmarkError(
            "checkpoint load verification failed"
        ),
        expected_checkpoint_sha256="1" * 64,
        expected_experiment_policy_sha256="2" * 64,
    )
    assert receipt["status"] == "failed"
    assert receipt["error_code"] == "checkpoint_verification_failed"
    assert receipt["failure_details"] == []


@pytest.mark.skipif(not TORCH_AVAILABLE, reason="PyTorch unavailable")
def test_runtime_benchmark_loads_checkpoint_and_runs_real_cpu_inference(
    tmp_path: Path,
) -> None:
    from production.prediction.next_behavior_experiment_policy import (
        experiment_policy_sha256,
        load_experiment_policy,
    )
    from production.prediction.next_behavior_model import (
        build_model,
        build_model_spec,
        save_checkpoint,
    )
    from tests.test_next_behavior_model import _tensor, _vocabulary

    spec = build_model_spec(_vocabulary())
    checkpoint = tmp_path / "model.pt"
    receipt = save_checkpoint(
        checkpoint, build_model(spec, seed=17), spec=spec
    )
    policy = load_experiment_policy(
        "configs/next_behavior_experiment_policy.v1.json"
    )
    result = runtime.benchmark_checkpoint_runtime(
        checkpoint_path=checkpoint,
        expected_checkpoint_sha256=receipt["checkpoint_sha256"],
        model_spec=spec,
        tensor_inputs=[_tensor(spec)],
        experiment_policy=policy,
        expected_experiment_policy_sha256=experiment_policy_sha256(policy),
        warmup_iterations=2,
        measured_iterations=5,
    )

    assert result["measurement"] == (
        "real_cpu_checkpoint_load_and_forward_inference"
    )
    assert result["device"] == "cpu"
    assert result["measured_iterations"] == 5
    assert result["deterministic_replay"] is True
    assert result["latency_ms"]["p95"] > 0.0
    assert result["throughput_inferences_per_second"] > 0.0
    assert result["budget_evaluation"]["budgets"] == policy["runtime_budgets"]
