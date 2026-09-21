from __future__ import annotations

import production.api.monitor_web as monitor_web
from production.prediction_next_distinct_poc import dashboard_adapter


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


def test_ended_final_manifest_matched_prediction_is_historical_only() -> None:
    result = _projection(
        freshness={"state": "FINAL", "history_manifest_match": True},
        session_ended=True,
    )

    assert result["state"] == "SESSION_ENDED"
    assert result["next_distinct_tactic"] is None
    assert result["stored_next_distinct_tactic"] == "credential-access"
    assert "historical advisory" in result["prediction_status_reason"]


def test_freshness_finalizes_only_ended_manifest_matched_records() -> None:
    manifest = {"history_manifest_sha256": "a" * 64}
    old_record = {
        "recorded_at": 1_000.0,
        "history_manifest_sha256": "a" * 64,
        "session_ended": True,
    }

    final = dashboard_adapter._freshness(old_record, manifest, 10_000.0, 3_600.0)
    assert final["state"] == "FINAL"
    assert final["history_manifest_match"] is True
    assert final["session_ended"] is True

    active = dashboard_adapter._freshness(
        {**old_record, "session_ended": False}, manifest, 10_000.0, 3_600.0
    )
    assert active["state"] == "STALE"

    mismatched = dashboard_adapter._freshness(
        {**old_record, "history_manifest_sha256": "b" * 64},
        manifest,
        10_000.0,
        3_600.0,
    )
    assert mismatched["state"] == "STALE"
    assert mismatched["history_manifest_match"] is False


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
