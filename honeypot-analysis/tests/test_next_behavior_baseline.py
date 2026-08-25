from __future__ import annotations

import copy

import pytest

from production.reproduction.next_behavior import baseline as baseline_module
from production.reproduction.next_behavior.baseline import (
    NextBehaviorBaselineError,
    fit_corrected_target_baselines,
    fit_first_order_phase_state_markov,
    fit_hard_backoff_vomm,
    fit_interpolated_vomm,
    fit_majority_terminal_prevalence,
    predict_baseline,
    predict_many,
    require_valid_baseline,
)
from production.prediction.next_behavior_contract import (
    EXAMPLE_SCHEMA_VERSION,
    MODEL_INPUT_SCHEMA_VERSION,
    TARGET_CONTRACT_ID,
    TERMINAL_OUTCOME,
)


def _example(
    name: str,
    session: str,
    history: list[list[str]],
    target: list[str] | None,
) -> dict:
    return {
        "schema_version": EXAMPLE_SCHEMA_VERSION,
        "target_contract_id": TARGET_CONTRACT_ID,
        "example_id": f"example-{name}",
        "session_id": f"session-{session}",
        "source_member_id": "member-fixture",
        "prediction_phase_id": f"phase-{name}",
        "prediction_event_order": len(history),
        "model_input": {
            "schema_version": MODEL_INPUT_SCHEMA_VERSION,
            "target_contract_id": TARGET_CONTRACT_ID,
            "phase_sequence": [
                {
                    "tactics": sorted(tactics),
                    "techniques": [],
                    "repetition_bucket": "1",
                    "elapsed_time_bucket": "unknown",
                    "label_provenance_sources": [],
                    "label_confidence_buckets": [],
                    "label_agreement_statuses": [],
                    "audit_only_label_count": 0,
                    "evidence_refs": [],
                }
                for tactics in history
            ],
        },
        "target": (
            {
                "outcome_type": "session_end",
                "tactics": [],
                "techniques": [],
                "terminal_outcome": TERMINAL_OUTCOME,
                "target_evidence_refs": [],
            }
            if target is None
            else {
                "outcome_type": "next_behavior_phase",
                "tactics": sorted(target),
                "techniques": [],
                "terminal_outcome": "",
                "target_evidence_refs": [],
            }
        ),
    }


def _training() -> list[dict]:
    return [
        _example("a1", "a", [["discovery"]], ["execution", "persistence"]),
        _example(
            "a2",
            "a",
            [["discovery"], ["execution", "persistence"]],
            None,
        ),
        _example("b1", "b", [["discovery"]], ["execution", "persistence"]),
        _example(
            "b2",
            "b",
            [["discovery"], ["execution", "persistence"]],
            ["impact"],
        ),
        _example("c1", "c", [["reconnaissance"]], None),
    ]


def test_majority_baseline_models_exact_multilabel_states_and_terminal_prevalence() -> None:
    artifact = fit_majority_terminal_prevalence(_training())
    prediction = predict_baseline(
        artifact,
        _example("heldout", "heldout", [["collection"]], ["impact"]),
    )

    assert artifact["training_example_count"] == 5
    assert artifact["training_session_count"] == 3
    assert artifact["terminal_target_count"] == 2
    assert artifact["terminal_prevalence"] == pytest.approx(2 / 5)
    assert artifact["tactic_prevalence"] == pytest.approx(3 / 5)
    assert prediction["status"] == "predicted"
    assert prediction["predicted_tactics"] == ["execution", "persistence"]
    assert prediction["terminal_score"] == pytest.approx(2 / 5)
    assert prediction["tactic_scores"]["execution"] == pytest.approx(2 / 5)
    assert prediction["tactic_scores"]["persistence"] == pytest.approx(2 / 5)
    assert prediction["zero_order_used"] is True


def test_first_order_markov_abstains_on_unknown_state_without_hidden_fallback() -> None:
    artifact = fit_first_order_phase_state_markov(_training())
    known = predict_baseline(
        artifact,
        _example("known", "heldout", [["discovery"]], ["impact"]),
    )
    unknown = predict_baseline(
        artifact,
        _example("unknown", "heldout", [["collection"]], ["impact"]),
    )

    assert known["predicted_tactics"] == ["execution", "persistence"]
    assert known["used_context_lengths"] == [1]
    assert unknown["status"] == "abstained"
    assert unknown["reason"] == "unsupported_context"
    assert unknown["ranked_tactics"] == []
    assert unknown["predicted_terminal"] is None
    assert unknown["zero_order_used"] is False


def test_hard_backoff_uses_longest_supported_suffix_and_discloses_backoff() -> None:
    artifact = fit_hard_backoff_vomm(_training(), maximum_order=3)
    exact = predict_baseline(
        artifact,
        _example(
            "exact",
            "heldout",
            [["discovery"], ["execution", "persistence"]],
            ["impact"],
        ),
    )
    backed_off = predict_baseline(
        artifact,
        _example(
            "backoff",
            "heldout",
            [["collection"], ["discovery"]],
            ["impact"],
        ),
    )

    assert exact["used_context_lengths"] == [2]
    assert exact["terminal_score"] == pytest.approx(0.5)
    assert exact["predicted_tactics"] == ["impact"]
    assert backed_off["used_context_lengths"] == [1]
    assert backed_off["backoff_steps"] == 1
    assert backed_off["zero_order_used"] is False


def test_interpolated_vomm_combines_supported_suffixes_deterministically() -> None:
    artifact = fit_interpolated_vomm(
        _training(), maximum_order=2, interpolation_decay=0.5
    )
    example = _example(
        "interpolated",
        "heldout",
        [["discovery"], ["execution", "persistence"]],
        ["impact"],
    )
    first = predict_baseline(artifact, example)
    second = predict_baseline(copy.deepcopy(artifact), copy.deepcopy(example))

    assert first == second
    assert first["used_context_lengths"] == [2, 1]
    assert first["context_weights"] == pytest.approx({"1": 1 / 3, "2": 2 / 3})
    assert first["terminal_score"] == pytest.approx(2 / 3 * 0.5 + 1 / 3 * 0.5)
    assert first["tactic_scores"]["impact"] == pytest.approx(0.5)


def test_complete_baseline_set_uses_identical_membership_and_preserves_ids() -> None:
    examples = _training()
    artifacts = fit_corrected_target_baselines(examples, maximum_order=2)

    assert set(artifacts) == {
        "majority_terminal_prevalence",
        "first_order_phase_state_markov",
        "hard_backoff_vomm",
        "interpolated_vomm",
    }
    assert {
        tuple(artifact["training_example_ids"]) for artifact in artifacts.values()
    } == {tuple(sorted(item["example_id"] for item in examples))}
    predictions = predict_many(artifacts["hard_backoff_vomm"], examples)
    assert [item["example_id"] for item in predictions] == [
        item["example_id"] for item in examples
    ]
    assert [item["session_id"] for item in predictions] == [
        item["session_id"] for item in examples
    ]


def test_batch_prediction_validates_and_indexes_artifact_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = fit_hard_backoff_vomm(_training(), maximum_order=3)
    examples = _training() * 20
    examples = [
        {
            **copy.deepcopy(example),
            "example_id": f"{example['example_id']}-{index}",
        }
        for index, example in enumerate(examples)
    ]
    expected = [predict_baseline(artifact, example) for example in examples]
    original_validate = baseline_module.require_valid_baseline
    original_tables = baseline_module._artifact_tables
    calls = {"validation": 0, "tables": 0}

    def counted_validate(value: dict) -> dict:
        calls["validation"] += 1
        return original_validate(value)

    def counted_tables(value: dict) -> tuple:
        calls["tables"] += 1
        return original_tables(value)

    monkeypatch.setattr(
        baseline_module,
        "require_valid_baseline",
        counted_validate,
    )
    monkeypatch.setattr(baseline_module, "_artifact_tables", counted_tables)

    assert predict_many(artifact, examples) == expected
    assert calls == {"validation": 1, "tables": 1}


def test_artifacts_and_examples_fail_closed_on_contract_or_identity_changes() -> None:
    artifact = fit_hard_backoff_vomm(_training())
    tampered = copy.deepcopy(artifact)
    tampered["target_contract_id"] = "historical_single_tactic"

    with pytest.raises(NextBehaviorBaselineError, match="corrected target"):
        require_valid_baseline(tampered)

    old_target = _training()[0]
    old_target["target_contract_id"] = "historical_single_tactic"
    with pytest.raises(NextBehaviorBaselineError, match="corrected"):
        fit_hard_backoff_vomm([old_target])
