from __future__ import annotations

from tests.test_next_trusted_group_target import _group, _session

from production.reproduction.next_behavior.group_target_support import (
    attach_operational_observations,
    build_group_target_support_receipt,
    validate_group_target_support_receipt,
)


HASH = "a" * 64


def _passing_sessions(prefix: str) -> list[dict]:
    sessions = [
        _session(
            [
                _group(f"{prefix}-{index}-one", 1, 0, [("discovery", "T1082")]),
                _group(f"{prefix}-{index}-two", 2, 1000, [("execution", "T1059")]),
                _group(f"{prefix}-{index}-three", 3, 2000, [("discovery", "T1033")]),
            ]
        )
        for index in range(30)
    ]
    for index, session in enumerate(sessions):
        session["session_id"] = (
            "nbsession_"
            + __import__("hashlib").sha256(f"{prefix}:{index}".encode()).hexdigest()
        )
    return sessions


def _receipt(sessions) -> dict:
    return build_group_target_support_receipt(
        safe_sessions_by_role=sessions,
        target_policy_sha256=HASH,
        design_commit="b" * 40,
        design_tree="c" * 40,
        source_selection_sha256=HASH,
        successor_inventory_id="inventory",
        successor_inventory_sha256=HASH,
        classification_receipt_sha256=HASH,
        pseudonymization_key_id="next-behavior-hmac-aaaaaaaaaaaaaaaa",
        pseudonymization_key_fingerprint_sha256=HASH,
        historical_test_membership_receipt_sha256=HASH,
    )


def test_support_gate_passes_two_conditional_tactics_at_thirty_sessions() -> None:
    receipt = _receipt(
        {
            "train": _passing_sessions("train"),
            "selection": _passing_sessions("selection"),
            "calibration": _passing_sessions("calibration"),
        }
    )

    assert receipt["status"] == "support_gate_passed"
    assert receipt["gate"]["reportable_conditional_tactics"] == [
        "discovery",
        "execution",
    ]
    assert receipt["roles"]["train"]["total_targets"] == 90
    assert receipt["roles"]["train"]["continuation_targets"] == 60
    assert receipt["roles"]["train"]["terminal_targets"] == 30
    assert receipt["roles"]["train"]["next_tactic_counts"] == {
        "discovery": 30,
        "execution": 30,
    }
    assert validate_group_target_support_receipt(receipt) == []


def test_repeated_same_tactic_continuation_counts_as_a_real_target() -> None:
    one = _session(
        [
            _group("repeat-one", 1, 0, [("discovery", "T1082")]),
            _group("repeat-two", 2, 1000, [("discovery", "T1033")]),
        ]
    )
    role_sessions = {}
    for role in ("train", "selection", "calibration"):
        copied = __import__("copy").deepcopy(one)
        copied["session_id"] = (
            "nbsession_"
            + __import__("hashlib").sha256(role.encode()).hexdigest()
        )
        role_sessions[role] = [copied]
    receipt = _receipt(role_sessions)

    assert receipt["roles"]["train"]["repeated_same_tactic_set_continuations"] == 1
    assert receipt["roles"]["train"]["continuation_targets"] == 1
    assert receipt["status"] == "support_gate_failed"


def test_twenty_nine_distinct_sessions_fail_closed() -> None:
    receipt = _receipt(
        {
            "train": _passing_sessions("train")[:29],
            "selection": _passing_sessions("selection"),
            "calibration": _passing_sessions("calibration"),
        }
    )

    assert receipt["gate"]["binary_classes"]["train"]["session_end"]["passed"] is False
    assert receipt["gate"]["conditional_tactics"]["execution"]["reportable"] is False
    assert receipt["status"] == "support_gate_failed"


def test_test_role_is_rejected_before_aggregation() -> None:
    sessions = {
        "train": [],
        "selection": [],
        "calibration": [],
        "test": [],
    }

    try:
        _receipt(sessions)
    except ValueError as exc:
        assert "exactly train, selection, and calibration" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("test role was accepted")


def test_tampered_gate_and_boundary_are_rejected() -> None:
    receipt = _receipt(
        {
            "train": _passing_sessions("train"),
            "selection": _passing_sessions("selection"),
            "calibration": _passing_sessions("calibration"),
        }
    )
    receipt["gate"]["passed"] = False
    receipt["sealed_test_boundary"]["test_metrics_used"] = True

    errors = validate_group_target_support_receipt(receipt)

    assert "support gate cannot be recomputed" in errors
    assert "sealed-test boundary is invalid" in errors


def test_cross_role_session_overlap_fails_closed() -> None:
    train = _passing_sessions("shared")

    try:
        _receipt(
            {
                "train": train,
                "selection": train,
                "calibration": _passing_sessions("calibration"),
            }
        )
    except ValueError as exc:
        assert "memberships overlap" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("cross-role overlap was accepted")


def test_operational_measurements_do_not_change_semantic_support_identity() -> None:
    receipt = _receipt(
        {
            "train": _passing_sessions("train"),
            "selection": _passing_sessions("selection"),
            "calibration": _passing_sessions("calibration"),
        }
    )

    measured = attach_operational_observations(
        receipt,
        {"elapsed_seconds": "12.500000", "peak_rss_kib": 1234},
    )

    assert measured["semantic_support_sha256"] == receipt["semantic_support_sha256"]
    assert measured["receipt_id"] != receipt["receipt_id"]
    assert validate_group_target_support_receipt(measured) == []
