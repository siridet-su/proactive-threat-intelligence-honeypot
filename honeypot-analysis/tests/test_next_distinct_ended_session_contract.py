from __future__ import annotations

import production.api.monitor_web as monitor_web


SESSION_ID = "session_v1_ended_contract_0123456789abcdef"


def _projection(**overrides):
    value = {
        "ok": True,
        "prediction_status": "PREDICTED",
        "freshness": {"state": "FRESH", "history_manifest_match": True},
        "top1": "credential-access",
        "session_ended": False,
        "canonical_write_allowed": False,
    }
    value.update(overrides)
    return monitor_web._dashboard_next_distinct_projection(value, SESSION_ID)


def test_active_fresh_prediction_keeps_current_contract() -> None:
    result = _projection()

    assert result["state"] == "DATA"
    assert result["next_distinct_tactic"] == "credential-access"
    assert result["stored_next_distinct_tactic"] is None
    assert result["canonical_write_allowed"] is False


def test_ended_fresh_manifest_matched_prediction_is_historical_only() -> None:
    result = _projection(session_ended=True)

    assert result["state"] == "SESSION_ENDED"
    assert result["status"] == "SESSION_ENDED"
    assert result["availability"] == "SESSION_ENDED"
    assert result["next_distinct_tactic"] is None
    assert result["stored_next_distinct_tactic"] == "credential-access"
    assert "historical advisory" in result["prediction_status_reason"]


def test_ended_stale_prediction_fails_closed() -> None:
    result = _projection(
        prediction_status="STALE",
        freshness={"state": "STALE", "history_manifest_match": False},
        session_ended=True,
    )

    assert result["state"] == "SESSION_ENDED"
    assert result["next_distinct_tactic"] is None
    assert result["stored_next_distinct_tactic"] is None
    assert "stale or history-mismatched" in result["prediction_status_reason"]


def test_ended_manifest_mismatch_fails_closed() -> None:
    result = _projection(
        freshness={"state": "FRESH", "history_manifest_match": False},
        session_ended=True,
    )

    assert result["state"] == "SESSION_ENDED"
    assert result["next_distinct_tactic"] is None
    assert result["stored_next_distinct_tactic"] is None
    assert "no valid stored prediction" in result["prediction_status_reason"]


def test_ended_missing_top1_fails_closed() -> None:
    result = _projection(top1=None, session_ended=True)

    assert result["state"] == "SESSION_ENDED"
    assert result["next_distinct_tactic"] is None
    assert result["stored_next_distinct_tactic"] is None


def test_ended_missing_manifest_match_fails_closed() -> None:
    result = _projection(freshness={"state": "FRESH"}, session_ended=True)

    assert result["state"] == "SESSION_ENDED"
    assert result["stored_next_distinct_tactic"] is None
