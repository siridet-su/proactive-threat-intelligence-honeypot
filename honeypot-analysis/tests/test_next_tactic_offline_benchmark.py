from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from production.prediction.external_vomm_artifact import build_external_vomm_artifact
from production.tools.next_tactic_offline_benchmark import (
    BenchmarkCase,
    ModelRun,
    Prediction,
    _make_neural_model,
    _neural_examples,
    _pad_batch,
    _record_for_case,
    evaluate_model,
    expected_calibration_error,
    first_order_model,
    majority_model,
    normalized_confusion,
    paired_comparison,
    run_benchmark,
    serialize_and_reload_neural_model,
    split_validation_sessions,
)


VOCABULARY = ["discovery", "execution", "persistence"]


def _case(identifier: str, actual: str, sequence: list[str], position: int = 0) -> BenchmarkCase:
    return BenchmarkCase(
        case_id=identifier,
        session_id=f"session-{identifier}",
        chronological_position=position,
        actual=actual,
        sequence=tuple(sequence),
        features={"tactic_sequence": sequence, "last_tactic": sequence[-1]},
    )


def _payload(identifier: str, split: str, tactics: list[str]) -> dict:
    return {
        "session_id": identifier,
        "split": split,
        "status": "closed",
        "is_ended": True,
        "tactics": tactics,
        "schema_version": "next_tactic_fixture.v1",
        "dataset_source": "fixture/offline-next-tactic-benchmark",
    }


def test_split_validation_roles_are_whole_session_deterministic_and_disjoint() -> None:
    rows = [_payload(f"validation-{index}", "calibration", ["discovery", "execution"]) for index in range(8)]

    selection, calibration, summary = split_validation_sessions(rows)

    assert [item["session_id"] for item in selection] == [f"validation-{index}" for index in range(4)]
    assert [item["session_id"] for item in calibration] == [f"validation-{index}" for index in range(4, 8)]
    assert summary["intersection_count"] == 0
    assert summary["selection"]["membership_sha256"] != summary["calibration"]["membership_sha256"]


def test_metrics_top3_mrr_abstention_and_confusion_are_correct() -> None:
    cases = [
        _case("one", "execution", ["discovery"]),
        _case("two", "persistence", ["execution"], 1),
        _case("three", "discovery", ["persistence"], 2),
    ]
    values = {
        "one": {"execution": 0.6, "discovery": 0.4},
        "two": {"execution": 0.6, "persistence": 0.3, "discovery": 0.1},
        "three": {},
    }
    model = ModelRun("fixture", "fixture", lambda case: Prediction(values[case.case_id]), {})

    result = evaluate_model(model, cases, VOCABULARY, bootstrap_iterations=0, seed=1)

    assert result["metrics"]["top1_accuracy"] == pytest.approx(1 / 3)
    assert result["metrics"]["top3_accuracy"] == pytest.approx(2 / 3)
    assert result["metrics"]["mean_reciprocal_rank"] == pytest.approx((1 + 1 / 2) / 3)
    assert result["metrics"]["coverage"] == pytest.approx(2 / 3)
    assert result["metrics"]["abstention_rate"] == pytest.approx(1 / 3)
    assert result["metrics"]["selective_top1_accuracy"] == pytest.approx(1 / 2)
    confusion = result["normalized_confusion_matrix"]
    assert confusion["discovery"]["<abstained>"] == 1.0
    assert sum(confusion["execution"].values()) == pytest.approx(1.0)


def test_first_order_and_majority_baselines_are_deterministic() -> None:
    sessions = [
        _payload("one", "train", ["discovery", "execution"]),
        _payload("two", "train", ["discovery", "execution"]),
        _payload("three", "train", ["discovery", "persistence"]),
    ]
    cases = [_case("x", "execution", ["discovery"])]
    first = first_order_model(sessions, VOCABULARY)
    majority = majority_model(cases, VOCABULARY)

    assert first.predictor(cases[0]).probabilities["execution"] == pytest.approx(2 / 3)
    assert majority.predictor(cases[0]).probabilities == {"discovery": 0.0, "execution": 1.0, "persistence": 0.0}


def test_paired_comparison_requires_same_cases_and_reports_all_outcomes() -> None:
    reference = [
        _record_for_case(_case("one", "execution", ["discovery"]), Prediction({"execution": 1.0}), VOCABULARY),
        _record_for_case(_case("two", "persistence", ["discovery"]), Prediction({"execution": 1.0}), VOCABULARY),
    ]
    candidate = [
        _record_for_case(_case("one", "execution", ["discovery"]), Prediction({"discovery": 1.0}), VOCABULARY),
        _record_for_case(_case("two", "persistence", ["discovery"]), Prediction({"persistence": 1.0}), VOCABULARY),
    ]

    paired = paired_comparison(reference, candidate)

    assert paired["outcomes"] == {"candidate_win": 1, "production_vomm_win": 1}
    with pytest.raises(ValueError, match="identical"):
        paired_comparison(reference, candidate[:1])


@pytest.mark.skipif(importlib.util.find_spec("torch") is None, reason="optional offline neural benchmark dependency")
def test_neural_input_alignment_causal_mask_and_serialization_roundtrip() -> None:
    import torch

    settings = {"embedding_dimension": 12, "hidden_dimension": 24, "layers": 1, "attention_heads": 3, "dropout": 0.0, "max_sequence_length": 8}
    cases = [_case("one", "execution", ["discovery"]), _case("two", "persistence", ["discovery", "execution"])]
    inputs, labels = _neural_examples(cases, VOCABULARY, 8)
    assert inputs == [[1], [1, 2]]
    assert labels == [1, 2]
    model = _make_neural_model("transformer", vocabulary_size=len(VOCABULARY), settings=settings, torch=torch)
    model.eval()
    tokens, lengths, _ = _pad_batch(torch, [[1, 2, 3], [1, 2]])
    changed = tokens.clone(); changed[0, 2] = 1
    with torch.no_grad():
        original_states = model.encode_states(tokens, lengths)
        changed_states = model.encode_states(changed, lengths)
    # Position one cannot see the later third token under a causal mask.
    assert torch.allclose(original_states[0, 0], changed_states[0, 0])
    payload, restored = serialize_and_reload_neural_model(model, kind="transformer", vocabulary_size=len(VOCABULARY), settings=settings)
    assert payload
    with torch.no_grad():
        assert torch.allclose(model(tokens, lengths), restored(tokens, lengths))


@pytest.mark.skipif(importlib.util.find_spec("torch") is None, reason="optional offline neural benchmark dependency")
def test_fixture_benchmark_keeps_manifest_bound_production_artifact_unchanged(tmp_path: Path) -> None:
    payloads = [
        _payload("train-a", "train", ["discovery", "execution"]),
        _payload("train-b", "train", ["discovery", "persistence"]),
        _payload("train-c", "train", ["execution", "persistence"]),
        _payload("train-d", "train", ["persistence", "execution"]),
        _payload("validation-a", "calibration", ["discovery", "execution"]),
        _payload("validation-b", "calibration", ["discovery", "persistence"]),
        _payload("validation-c", "calibration", ["execution", "persistence"]),
        _payload("validation-d", "calibration", ["persistence", "execution"]),
        _payload("test-a", "test", ["discovery", "execution"]),
        _payload("test-b", "test", ["discovery", "persistence"]),
        _payload("test-c", "test", ["execution", "persistence"]),
        _payload("test-d", "test", ["persistence", "execution"]),
    ]
    payload_path = tmp_path / "payload.jsonl"
    payload_path.write_text("".join(json.dumps(item) + "\n" for item in payloads), encoding="utf-8")
    artifact_path, manifest_path = tmp_path / "artifact.json", tmp_path / "manifest.json"
    built = build_external_vomm_artifact(
        payload_path=payload_path, artifact_path=artifact_path, manifest_path=manifest_path,
        artifact_version="fixture", source_start="2026-01-01", source_end="2026-01-02",
        preprocessing={"prefix_max_length": 3, "transition_smoothing": 0.05, "min_transition_count": 1},
        classification={"sha256": "fixture", "securebert_checkpoint_id": "fixture", "securebert_checkpoint_sha256": "fixture"},
        trust_policy={"sha256": "fixture"}, model_builder_commit="fixture",
    )
    policy_path = tmp_path / "policy.json"
    policy = json.loads(Path("configs/prediction_policy.trusted.json").read_text(encoding="utf-8"))["policy"]
    policy.update({"external_min_sessions": 1, "external_min_transition_count": 1, "min_transition_count": 1, "min_prefix_transition_count": 1, "min_technique_transition_count": 1, "min_tactic_transition_count": 1})
    policy_path.write_text(json.dumps({"policy": policy}), encoding="utf-8")
    before = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    args = type("Args", (), {"payload": str(payload_path), "artifact": str(artifact_path), "manifest": str(manifest_path), "policy": str(policy_path), "expected_artifact_sha256": built["artifact_sha256"], "expected_model_id": built["artifact"]["model_id"], "expected_manifest_id": built["manifest"]["manifest_id"], "seeds": [1, 2, 3, 4, 5], "bootstrap_iterations": 0})()

    result = run_benchmark(args)

    assert result["offline_only"] is True
    assert result["experimental_controls"]["test_used_for_training_or_selection"] is False
    assert hashlib.sha256(artifact_path.read_bytes()).hexdigest() == before
    assert set(result["models"]) == {"majority_class", "first_order_markov", "hard_backoff_vomm", "interpolated_vomm", "gru_aggregate", "transformer_aggregate"}
