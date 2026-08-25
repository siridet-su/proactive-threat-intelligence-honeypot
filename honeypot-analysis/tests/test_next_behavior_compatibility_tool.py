from __future__ import annotations

import copy

from production.prediction.next_behavior_contract import (
    TARGET_CONTRACT_ID,
    TACTIC_VOCABULARY,
)
from production.tools.evaluate_frozen_checkpoint_compatibility import (
    _comparison,
    _probability_metrics,
)


def _example() -> dict:
    return {
        "target_contract_id": TARGET_CONTRACT_ID,
        "example_id": "example-1",
        "session_id": "session-1",
        "target": {
            "outcome_type": "next_behavior_phase",
            "tactics": ["discovery"],
            "techniques": ["T1082"],
            "terminal_outcome": "",
            "target_evidence_refs": [],
        },
    }


def _prediction() -> dict:
    tactics = sorted(TACTIC_VOCABULARY)
    return {
        "example_id": "example-1",
        "session_id": "session-1",
        "status": "predicted",
        "ranked_tactics": [
            "discovery",
            *[item for item in tactics if item != "discovery"],
        ],
        "predicted_tactics": ["discovery"],
        "predicted_terminal": False,
        "_probabilities": {
            tactic: 0.99 if tactic == "discovery" else 0.01
            for tactic in tactics
        },
        "_terminal_probability": 0.01,
        "_tensor_hash": "tensor-a",
        "_prediction_event_order": 1,
    }


def test_probability_metrics_cover_set_ranking_and_calibration_inputs() -> None:
    metrics = _probability_metrics([_example()], [_prediction()])

    assert metrics["exact_set_accuracy"] == 1.0
    assert metrics["mean_jaccard"] == 1.0
    assert metrics["hamming_loss"] == 0.0
    assert 0.0 < metrics["brier_score"] < 0.001
    assert 0.0 < metrics["log_loss"] < 0.02
    assert 0.0 < metrics["expected_calibration_error_10_bin"] < 0.02


def test_prediction_comparison_reports_tensor_probability_and_decision_changes() -> None:
    first = _prediction()
    second = copy.deepcopy(first)
    second["_tensor_hash"] = "tensor-b"
    second["_probabilities"]["discovery"] = 0.1
    second["_probabilities"]["execution"] = 0.9
    second["ranked_tactics"] = [
        "execution",
        *[
            item
            for item in sorted(TACTIC_VOCABULARY)
            if item != "execution"
        ],
    ]
    second["predicted_tactics"] = ["execution"]

    result = _comparison([first], [second], same_identity=True)

    assert result["common_count"] == 1
    assert result["tensor_change_rate"] == 1.0
    assert result["prediction_change_rate"] == 1.0
    assert result["top1_change_rate"] == 1.0
    assert result["mean_probability_l1"] > 0.0
