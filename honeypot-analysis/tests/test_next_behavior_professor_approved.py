import copy

import pytest

from production.prediction.next_behavior_professor_approved import (
    ProfessorApprovedPocError,
    build_professor_approved_decision,
    rank_complete_selection_candidates,
    require_valid_professor_approved_decision,
)


HASH = "a" * 64


def _record(seed, macro, balanced, terminal, latency):
    return {
        "seed": seed,
        "status": "complete",
        "completion_marker_verified": True,
        "checkpoint": {"sha256": f"{seed:064x}"[-64:]},
        "candidate": {
            "eligible": False,
            "blockers": ["reportable_zero_recall:defense-evasion"],
            "selection_values": {
                "macro_f1": macro,
                "balanced_accuracy": balanced,
                "terminal_f1": terminal,
                "p95_single_case_cpu_latency_ms": latency,
            },
        },
    }


def _receipt():
    return {
        "status": "selection_blocked_pre_test",
        "test_opened": False,
        "seed_candidates": [
            _record(2, 0.6, 0.8, 0.5, 2.0),
            _record(1, 0.7, 0.7, 0.4, 3.0),
        ],
    }


def test_professor_approval_ranks_aggregate_candidate_without_changing_blocker():
    receipt = _receipt()
    ranked = rank_complete_selection_candidates(receipt)
    assert [item["seed"] for item in ranked] == [1, 2]
    decision = build_professor_approved_decision(
        receipt, selection_blocked_receipt_sha256=HASH, source_code_commit="b" * 40
    )
    assert decision["selection"]["selected_seed"] == 1
    assert decision["original_experiment"]["status"] == "BLOCKED_AT_SELECTION"
    assert decision["selection"]["ranked_seeds"][0]["original_eligible"] is False
    assert require_valid_professor_approved_decision(decision) == decision


def test_professor_approval_fails_closed_when_original_blocker_is_lost():
    receipt = _receipt()
    receipt["seed_candidates"][1]["candidate"]["blockers"] = []
    with pytest.raises(ProfessorApprovedPocError, match="defense-evasion"):
        build_professor_approved_decision(
            receipt, selection_blocked_receipt_sha256=HASH, source_code_commit="b" * 40
        )


def test_professor_approval_rejects_posthoc_tampering():
    decision = build_professor_approved_decision(
        _receipt(), selection_blocked_receipt_sha256=HASH, source_code_commit="b" * 40
    )
    changed = copy.deepcopy(decision)
    changed["selection"]["selected_seed"] = 2
    with pytest.raises(ProfessorApprovedPocError, match="selected seed"):
        require_valid_professor_approved_decision(changed)
