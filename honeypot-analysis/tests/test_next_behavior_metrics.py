from __future__ import annotations

import copy
import random
from collections import defaultdict

import pytest

from production.prediction import next_behavior_metrics as metrics_module
from production.prediction.next_behavior_contract import (
    EXAMPLE_SCHEMA_VERSION,
    TARGET_CONTRACT_ID,
    TERMINAL_OUTCOME,
)
from production.prediction.next_behavior_metrics import (
    NextBehaviorMetricsError,
    align_examples_and_predictions,
    evaluate_next_behavior_predictions,
    paired_model_comparison,
)


def _example(
    index: int,
    session: str,
    tactics: list[str] | None,
) -> dict:
    return {
        "schema_version": EXAMPLE_SCHEMA_VERSION,
        "target_contract_id": TARGET_CONTRACT_ID,
        "example_id": f"example-{index}",
        "session_id": f"session-{session}",
        "target": (
            {
                "outcome_type": "session_end",
                "tactics": [],
                "techniques": [],
                "terminal_outcome": TERMINAL_OUTCOME,
                "target_evidence_refs": [],
            }
            if tactics is None
            else {
                "outcome_type": "next_behavior_phase",
                "tactics": sorted(tactics),
                "techniques": [],
                "terminal_outcome": "",
                "target_evidence_refs": [],
            }
        ),
    }


def _prediction(
    example: dict,
    *,
    tactics: list[str] | None,
    ranking: list[str],
    status: str = "predicted",
) -> dict:
    return {
        "example_id": example["example_id"],
        "session_id": example["session_id"],
        "status": status,
        "predicted_terminal": (
            None if status == "abstained" else tactics is None
        ),
        "predicted_tactics": [] if tactics is None else sorted(tactics),
        "ranked_tactics": ranking,
    }


def _fixture() -> tuple[list[dict], list[dict]]:
    examples = [
        _example(1, "a", ["execution", "persistence"]),
        _example(2, "a", None),
        _example(3, "b", ["execution"]),
        _example(4, "c", ["discovery"]),
        _example(5, "d", None),
    ]
    predictions = [
        _prediction(
            examples[0],
            tactics=["execution"],
            ranking=["execution", "persistence", "discovery"],
        ),
        _prediction(examples[1], tactics=None, ranking=["execution"]),
        _prediction(
            examples[2],
            tactics=["execution", "discovery"],
            ranking=["discovery", "execution"],
        ),
        _prediction(
            examples[3],
            tactics=["discovery"],
            ranking=["persistence", "discovery"],
        ),
        _prediction(
            examples[4],
            tactics=[],
            ranking=[],
            status="abstained",
        ),
    ]
    return examples, predictions


def test_multilabel_per_class_micro_macro_weighted_and_reportability() -> None:
    examples, predictions = _fixture()
    result = evaluate_next_behavior_predictions(
        examples,
        predictions,
        tactic_vocabulary=["discovery", "execution", "persistence"],
        minimum_target_sessions=2,
        minimum_targets=2,
        bootstrap_samples=20,
        bootstrap_seed=5,
    )
    per_class = result["multilabel_tactics"]["per_class"]

    assert per_class["execution"] == {
        "tp": 2,
        "fp": 0,
        "fn": 0,
        "tn": 3,
        "support": 2,
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
        "specificity": 1.0,
        "accuracy": 1.0,
        "balanced_accuracy": 1.0,
        "target_count": 2,
        "target_session_count": 2,
        "reportable": True,
    }
    assert per_class["persistence"]["recall"] == 0.0
    assert per_class["persistence"]["target_session_count"] == 1
    assert per_class["persistence"]["reportable"] is False
    assert result["multilabel_tactics"]["reportable_classes"] == ["execution"]
    all_aggregate = result["multilabel_tactics"]["all_classes"]
    assert all_aggregate["micro"]["precision"] == pytest.approx(3 / 4)
    assert all_aggregate["micro"]["recall"] == pytest.approx(3 / 4)
    assert all_aggregate["weighted"]["f1"] == pytest.approx(2 / 3)


def test_terminal_discrimination_and_rank_metrics_use_correct_denominators() -> None:
    examples, predictions = _fixture()
    result = evaluate_next_behavior_predictions(
        examples,
        predictions,
        tactic_vocabulary=["discovery", "execution", "persistence"],
        minimum_target_sessions=1,
        minimum_targets=1,
        bootstrap_samples=20,
    )

    assert result["terminal"]["support"] == 2
    assert result["terminal"]["tp"] == 1
    assert result["terminal"]["fn"] == 1
    assert result["terminal"]["target_session_count"] == 2
    assert result["terminal"]["reportable"] is True
    assert result["tactic_vs_end"]["coverage"] == pytest.approx(4 / 5)
    assert result["tactic_vs_end"]["all_case_accuracy"] == pytest.approx(4 / 5)
    ranking = result["nonterminal_ranking"]
    assert ranking["nonterminal_target_count"] == 3
    assert ranking["top1_accuracy"] == pytest.approx(1 / 3)
    assert ranking["top3_accuracy"] == 1.0
    assert ranking["mrr"] == pytest.approx((1 + 0.5 + 0.5) / 3)


def test_reportability_requires_both_thirty_targets_and_thirty_sessions() -> None:
    examples = [
        _example(index, "same", ["execution"]) for index in range(1, 31)
    ]
    predictions = [
        _prediction(item, tactics=["execution"], ranking=["execution"])
        for item in examples
    ]
    repeated = evaluate_next_behavior_predictions(
        examples,
        predictions,
        tactic_vocabulary=["execution"],
        bootstrap_samples=5,
    )
    assert repeated["multilabel_tactics"]["per_class"]["execution"][
        "target_count"
    ] == 30
    assert repeated["multilabel_tactics"]["per_class"]["execution"][
        "target_session_count"
    ] == 1
    assert repeated["multilabel_tactics"]["reportable_classes"] == []

    independent_examples = [
        _example(index, str(index), ["execution"]) for index in range(1, 31)
    ]
    independent_predictions = [
        _prediction(item, tactics=["execution"], ranking=["execution"])
        for item in independent_examples
    ]
    independent = evaluate_next_behavior_predictions(
        independent_examples,
        independent_predictions,
        tactic_vocabulary=["execution"],
        bootstrap_samples=5,
    )
    assert independent["multilabel_tactics"]["reportable_classes"] == [
        "execution"
    ]


def test_cluster_bootstrap_is_deterministic_and_preserves_dependency_unit() -> None:
    examples, predictions = _fixture()
    arguments = {
        "tactic_vocabulary": ["discovery", "execution", "persistence"],
        "minimum_target_sessions": 1,
        "minimum_targets": 1,
        "bootstrap_samples": 50,
        "bootstrap_seed": 1234,
    }
    first = evaluate_next_behavior_predictions(examples, predictions, **arguments)
    second = evaluate_next_behavior_predictions(
        copy.deepcopy(examples), copy.deepcopy(predictions), **arguments
    )

    assert first["session_cluster_bootstrap"] == second[
        "session_cluster_bootstrap"
    ]
    assert first["session_cluster_bootstrap"]["unit"] == "session"
    assert first["session_cluster_bootstrap"]["session_count"] == 4
    assert first["session_clustered_aggregates"]["aggregation"] == (
        "equal_weight_per_session"
    )
    assert first["example_ids"] == [item["example_id"] for item in examples]


def test_sufficient_statistics_bootstrap_matches_reference_resampling() -> None:
    examples, predictions = _fixture()
    labels = ("discovery", "execution", "persistence")
    rows = align_examples_and_predictions(examples, predictions)
    aggregate_labels = metrics_module.multilabel_tactic_metrics(
        rows,
        tactic_vocabulary=labels,
        minimum_target_sessions=1,
        minimum_targets=1,
    )["reportable_classes"]

    reference = metrics_module.session_cluster_bootstrap(
        rows,
        lambda sample: metrics_module._point_metrics(
            sample,
            tactic_vocabulary=labels,
            minimum_target_sessions=1,
            minimum_targets=1,
            aggregate_labels=aggregate_labels,
        ),
        samples=40,
        seed=37,
    )
    optimized = metrics_module._clustered_point_bootstrap(
        rows,
        tactic_vocabulary=labels,
        aggregate_labels=aggregate_labels,
        samples=40,
        seed=37,
    )

    assert optimized == reference


def test_bootstrap_does_not_repeat_full_row_metric_scans(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    examples = [
        _example(index, str(index), ["execution"])
        for index in range(1, 101)
    ]
    predictions = [
        _prediction(item, tactics=["execution"], ranking=["execution"])
        for item in examples
    ]

    def forbidden(*_args: object, **_kwargs: object) -> dict:
        raise AssertionError("full row metric stack was rescanned")

    monkeypatch.setattr(metrics_module, "_point_metrics", forbidden)
    result = evaluate_next_behavior_predictions(
        examples,
        predictions,
        tactic_vocabulary=["execution"],
        minimum_target_sessions=1,
        minimum_targets=1,
        bootstrap_samples=100,
        bootstrap_seed=19,
    )

    assert result["session_cluster_bootstrap"]["samples"] == 100
    assert result["session_cluster_bootstrap"]["session_count"] == 100


def test_paired_comparison_uses_same_examples_sessions_and_bootstrap_draws() -> None:
    examples, imperfect = _fixture()
    perfect = [
        _prediction(
            item,
            tactics=None if item["target"]["outcome_type"] == "session_end" else item["target"]["tactics"],
            ranking=(
                []
                if item["target"]["outcome_type"] == "session_end"
                else list(item["target"]["tactics"])
            ),
        )
        for item in examples
    ]
    result = paired_model_comparison(
        examples,
        perfect,
        imperfect,
        model_a="perfect",
        model_b="imperfect",
        tactic_vocabulary=["discovery", "execution", "persistence"],
        minimum_target_sessions=1,
        minimum_targets=1,
        bootstrap_samples=40,
        bootstrap_seed=9,
    )

    assert result["paired_example_count"] == 5
    assert result["paired_session_count"] == 4
    assert result["difference_direction"] == "model_a_minus_model_b"
    assert result["metrics"]["macro_f1"]["difference"] > 0
    assert result["metrics"]["top1_accuracy"]["difference"] > 0
    assert result["metrics"]["terminal_f1"]["difference"] > 0
    assert result["example_ids"] == [item["example_id"] for item in examples]


def test_paired_sufficient_statistics_match_reference_draws() -> None:
    examples, imperfect = _fixture()
    perfect = [
        _prediction(
            item,
            tactics=(
                None
                if item["target"]["outcome_type"] == "session_end"
                else item["target"]["tactics"]
            ),
            ranking=(
                []
                if item["target"]["outcome_type"] == "session_end"
                else list(item["target"]["tactics"])
            ),
        )
        for item in examples
    ]
    labels = ("discovery", "execution", "persistence")
    rows_a = align_examples_and_predictions(examples, perfect)
    rows_b = align_examples_and_predictions(examples, imperfect)
    aggregate_labels = metrics_module.multilabel_tactic_metrics(
        rows_a,
        tactic_vocabulary=labels,
        minimum_target_sessions=1,
        minimum_targets=1,
    )["reportable_classes"]
    pairs_by_session: dict[str, list[tuple[dict, dict]]] = defaultdict(list)
    by_b = {row["example_id"]: row for row in rows_b}
    for row in rows_a:
        pairs_by_session[row["session_id"]].append(
            (row, by_b[row["example_id"]])
        )
    sessions = sorted(pairs_by_session)
    generator = random.Random(29)
    reference_draws: dict[str, list[float]] = {}
    for _ in range(30):
        sample_a: list[dict] = []
        sample_b: list[dict] = []
        for session_id in generator.choices(sessions, k=len(sessions)):
            for row_a, row_b in pairs_by_session[session_id]:
                sample_a.append(row_a)
                sample_b.append(row_b)
        values_a = metrics_module._point_metrics(
            sample_a,
            tactic_vocabulary=labels,
            minimum_target_sessions=1,
            minimum_targets=1,
            aggregate_labels=aggregate_labels,
        )
        values_b = metrics_module._point_metrics(
            sample_b,
            tactic_vocabulary=labels,
            minimum_target_sessions=1,
            minimum_targets=1,
            aggregate_labels=aggregate_labels,
        )
        for key in values_a:
            reference_draws.setdefault(key, []).append(
                values_a[key] - values_b[key]
            )

    optimized = paired_model_comparison(
        examples,
        perfect,
        imperfect,
        tactic_vocabulary=labels,
        minimum_target_sessions=1,
        minimum_targets=1,
        bootstrap_samples=30,
        bootstrap_seed=29,
    )
    for key, draws in reference_draws.items():
        assert optimized["metrics"][key]["lower"] == metrics_module._percentile(
            draws, 0.025
        )
        assert optimized["metrics"][key]["upper"] == metrics_module._percentile(
            draws, 0.975
        )


def test_alignment_rejects_missing_extra_or_reassigned_identifiers() -> None:
    examples, predictions = _fixture()
    with pytest.raises(NextBehaviorMetricsError, match="membership mismatch"):
        align_examples_and_predictions(examples, predictions[:-1])

    reassigned = copy.deepcopy(predictions)
    reassigned[0]["session_id"] = "session-other"
    with pytest.raises(NextBehaviorMetricsError, match="changed session"):
        align_examples_and_predictions(examples, reassigned)
