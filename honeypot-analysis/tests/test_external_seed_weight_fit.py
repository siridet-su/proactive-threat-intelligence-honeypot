from __future__ import annotations

from production.tools.external_seed_weight_fit import (
    _build_thesis_markdown_tables,
    _dataset_statistics,
    _evaluate_cases,
    _normalize_selected_weights,
    _scoped_payload,
    _split_eligible_sessions,
)


def _payload(session_id: str, tactics: list[str]) -> dict:
    return {
        "session_id": session_id,
        "status": "closed",
        "is_ended": True,
        "classification_events": [
            {
                "tactic": tactic,
                "ttp": f"T10{index}",
                "command": f"cmd-{index}",
                "confidence": 1.0,
            }
            for index, tactic in enumerate(tactics)
        ],
    }


def test_external_seed_weight_fit_split_is_deterministic_and_excludes_ineligible() -> None:
    payloads = [
        _payload(f"s{i}", ["execution", "persistence"])
        for i in range(6)
    ] + [
        _payload(f"d{i}", ["discovery", "command-and-control"])
        for i in range(6)
    ] + [
        _payload("single", ["discovery"])
    ]

    first = _split_eligible_sessions(payloads, seed=20260707, train_ratio=0.5, calibration_ratio=0.25)
    second = _split_eligible_sessions(payloads, seed=20260707, train_ratio=0.5, calibration_ratio=0.25)

    assert [item["session_id"] for item in first["train"]] == [item["session_id"] for item in second["train"]]
    assert len(first["ineligible"]) == 1
    assert len(first["train_eligible"]) == 6
    assert len(first["calibration"]) == 2
    assert len(first["test"]) == 4


def test_external_seed_weight_fit_helpers_scope_weights_and_metrics() -> None:
    scoped = _scoped_payload(
        _payload("mixed", ["discovery", "impact", "execution"]),
        {"discovery", "execution"},
    )
    assert [event["tactic"] for event in scoped["classification_events"]] == ["discovery", "execution"]

    weights = _normalize_selected_weights(
        {"weights": {"local_transition": 0.35, "external_seed_transition": 0.22, "ignored": 9.0}},
        ["local_transition", "external_seed_transition"],
    )
    assert round(sum(weights.values()), 6) == 1.0
    assert weights["local_transition"] > weights["external_seed_transition"]

    metrics = _evaluate_cases(
        [
            {"actual_next": "execution", "predicted": ["execution"], "rank": 1, "brier_score": 0.1},
            {"actual_next": "persistence", "predicted": ["execution", "persistence"], "rank": 2, "brier_score": 0.5},
        ]
    )
    assert metrics["top1_accuracy"] == 0.5
    assert metrics["top3_accuracy"] == 1.0
    assert metrics["brier_score"] == 0.3


def test_external_seed_weight_fit_dataset_stats_and_markdown_tables() -> None:
    payloads = [
        _payload("a", ["discovery", "discovery", "execution", "persistence"]),
        _payload("b", ["credential-access"]),
    ]

    stats = _dataset_statistics(payloads)

    assert stats["total_sessions"] == 2
    assert stats["sessions_with_at_least_one_tactic_transition"] == 1
    assert stats["compressed_transition_observations"] == 2
    assert stats["tactic_distribution"]["discovery"] == 1

    result = {
        "dataset_statistics": stats,
        "split": {
            "train_sessions_total": 1,
            "train_eligible_sessions": 1,
            "calibration_sessions": 1,
            "test_sessions": 1,
            "ineligible_sessions_assigned_to_train": 0,
        },
        "baseline_weights": {"local_transition": 1.0},
        "fit": {"fitted_weights": {"local_transition": 1.0}},
        "scorers": ["local_transition"],
        "heldout_comparison": {
            "baseline_current_weights": {
                "top1_accuracy": 0.5,
                "top3_accuracy": 1.0,
                "mean_reciprocal_rank": 0.75,
                "brier_score": 0.25,
                "coverage": 1.0,
                "total_cases": 2,
            },
            "fitted_weights": {
                "top1_accuracy": 1.0,
                "top3_accuracy": 1.0,
                "mean_reciprocal_rank": 1.0,
                "brier_score": 0.1,
                "coverage": 1.0,
                "total_cases": 2,
            },
        },
        "ablation": [
            {
                "label": "all_fitted_scorers",
                "metrics": {
                    "top1_accuracy": 1.0,
                    "top3_accuracy": 1.0,
                    "mean_reciprocal_rank": 1.0,
                    "brier_score": 0.1,
                },
            }
        ],
        "sensitivity_analysis": [
            {
                "perturbation": {
                    "relative_change": 0.1,
                    "scorer": "local_transition",
                    "direction": "up",
                },
                "metrics": {
                    "top1_accuracy": 1.0,
                    "top3_accuracy": 1.0,
                    "mean_reciprocal_rank": 1.0,
                    "brier_score": 0.11,
                },
                "delta_vs_fitted": {"brier_score_delta": 0.01},
            }
        ],
    }

    tables = _build_thesis_markdown_tables(result)

    assert "Metric | Current Selected Weights | Fitted Weights | Change" in tables["current_vs_fitted_performance"]
    assert "Dataset Statistics" not in tables["dataset_statistics"]
