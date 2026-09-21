from __future__ import annotations

import json
from pathlib import Path

import production.api.monitor_web as monitor_web
from production.reporting.artifacts import _latest_ti_lookup_at, _report_prediction_context


class ReportStorage:
    def __init__(self, session_id: str, *, event_rows: list[dict] | None = None) -> None:
        self.session_id = session_id
        self.event_rows = list(event_rows or [])

    def list_rows_for_session(self, table: str, session_id: str, limit: int = 100):
        assert limit > 0
        if session_id != self.session_id:
            return []
        if table == "sessions":
            return [
                {
                    "session_id": session_id,
                    "payload_json": json.dumps(
                        {
                            "session_id": session_id,
                            "src_ip": "203.0.113.40",
                            "sensor_id": "pi5-cowrie-01",
                            "is_ended": True,
                            "command_count": 2,
                        }
                    ),
                }
            ]
        if table == "reports":
            return [
                {
                    "report_id": "report-session-download",
                    "session_id": session_id,
                    "created_at": "2026-09-17T07:00:00Z",
                    "payload_json": json.dumps(
                        {
                            "session_id": session_id,
                            "schema_version": "threat_hypothesis.v2",
                            "summary": "bounded report fixture",
                        }
                    ),
                }
            ]
        if table == "events":
            return self.event_rows
        return []


def _config(
    tmp_path: Path,
    session_id: str,
    *,
    event_rows: list[dict] | None = None,
) -> monitor_web.MonitorConfig:
    config = monitor_web.MonitorConfig(
        db_path="",
        database_url="sqlite:///:memory:",
        reports_dir=str(tmp_path / "reports"),
    )
    config._storage = ReportStorage(session_id, event_rows=event_rows)
    return config


def _next_distinct_projection(session_id: str, **overrides):
    projection = {
        "ok": True,
        "source": "NEXT_DISTINCT_POC",
        "dashboard_source": "NEXT_DISTINCT_POC",
        "session_id": session_id,
        "sequence_id": session_id,
        "session_ended": True,
        "state": "SESSION_ENDED",
        "prediction_status": "PREDICTED",
        "prediction_status_reason": "session ended; last fresh result is historical advisory only",
        "top1": "discovery",
        "top3": ["discovery", "execution", "credential-access"],
        "prediction": [
            {"tactic": "discovery", "score": 0.6},
            {"tactic": "execution", "score": 0.25},
            {"tactic": "credential-access", "score": 0.15},
        ],
        "freshness": {
            "state": "FRESH",
            "history_manifest_match": True,
            "generated_at": "2026-09-21T11:35:00Z",
        },
        "model": {
            "model_identifier": "next-distinct-test-model",
            "checkpoint_sha256": "a" * 64,
        },
    }
    projection.update(overrides)
    return projection


def test_session_report_pdf_uses_exact_stored_report_without_persistence(
    tmp_path: Path,
    monkeypatch,
) -> None:
    session_id = "session_v1_report_download"
    captured = {}

    expected_ti = {
        "ok": True,
        "status": "TI_PENDING",
        "session_id": session_id,
    }
    expected_ai = {
        "ok": True,
        "status": "unavailable",
        "session_id": session_id,
        "advisory": {},
    }
    expected_prediction = _next_distinct_projection(session_id)

    def render(
        report,
        session,
        *,
        artifact_version="",
        external_ti_projection=None,
        ai_advisory_projection=None,
        prediction_snapshot=None,
    ):
        captured["report"] = report
        captured["session"] = session
        captured["artifact_version"] = artifact_version
        captured["external_ti_projection"] = external_ti_projection
        captured["ai_advisory_projection"] = ai_advisory_projection
        captured["prediction_snapshot"] = prediction_snapshot
        return b"%PDF-1.7 bounded fixture"

    monkeypatch.setattr(monitor_web, "render_pdf_report_bytes", render)
    monkeypatch.setattr(
        monitor_web,
        "build_session_ti_projection",
        lambda storage, selected_session_id, config=None: expected_ti,
    )
    monkeypatch.setattr(
        monitor_web,
        "load_ai_advisory_detail",
        lambda config, selected_session_id, _storage=None: expected_ai,
    )
    monkeypatch.setattr(
        monitor_web,
        "load_next_distinct_prediction",
        lambda config, selected_session_id, _storage=None: expected_prediction,
    )
    pdf, error = monitor_web.load_session_report_pdf(_config(tmp_path, session_id), session_id)

    assert pdf == b"%PDF-1.7 bounded fixture"
    assert error == {}
    assert captured["report"]["schema_version"] == "threat_hypothesis.v2"
    assert captured["session"]["session_id"] == session_id
    assert captured["external_ti_projection"] == expected_ti
    assert captured["ai_advisory_projection"] == expected_ai
    prediction_snapshot = captured["prediction_snapshot"]
    assert prediction_snapshot["session_id"] == session_id
    assert prediction_snapshot["prediction_status"] == "HISTORICAL_ADVISORY"
    assert prediction_snapshot["prediction"] == [
        "discovery", "execution", "credential-access"
    ]
    assert prediction_snapshot["model_artifact_sha256"] == "a" * 64
    rendered_context = _report_prediction_context(prediction_snapshot, session_id)
    assert rendered_context["status"] == "HISTORICAL_ADVISORY"
    assert rendered_context["predictions"] == prediction_snapshot["prediction"]
    assert [item["label"] for item in rendered_context["ranking"]] == prediction_snapshot["prediction"]
    assert not (tmp_path / "reports").exists()


def test_report_next_distinct_context_rejects_cross_session_and_stale_labels() -> None:
    session_id = "session_v1_report_prediction"

    mismatched = _next_distinct_projection(
        "session_v1_other",
        sequence_id="session_v1_other",
    )
    assert monitor_web._report_next_distinct_snapshot(
        monitor_web._dashboard_next_distinct_projection(mismatched, session_id),
        session_id,
    ) is None

    stale = _next_distinct_projection(
        session_id,
        prediction_status="STALE",
        prediction_status_reason="stored result is stale",
        freshness={
            "state": "STALE",
            "history_manifest_match": True,
            "generated_at": "2026-09-20T00:00:00Z",
        },
    )
    stale_projection = monitor_web._dashboard_next_distinct_projection(stale, session_id)
    stale_snapshot = monitor_web._report_next_distinct_snapshot(stale_projection, session_id)
    assert stale_snapshot["prediction_status"] == "STALE"
    assert stale_snapshot["prediction"] == []
    assert stale_snapshot["final_ranking"] == []
    stale_context = _report_prediction_context(stale_snapshot, session_id)
    assert stale_context["predictions"] == []
    assert stale_context["ranking"] == []


def test_report_next_distinct_context_preserves_final_ended_advisory() -> None:
    session_id = "session_v1_final_ended_0123456789abcdef"
    final = _next_distinct_projection(
        session_id,
        session_ended=True,
        freshness={
            "state": "FINAL",
            "history_manifest_match": True,
            "age_seconds": 86_400.0,
        },
    )
    projection = monitor_web._dashboard_next_distinct_projection(final, session_id)
    snapshot = monitor_web._report_next_distinct_snapshot(projection, session_id)

    assert snapshot is not None
    assert snapshot["prediction_status"] == "HISTORICAL_ADVISORY"
    assert snapshot["prediction"][0] == projection["stored_next_distinct_tactic"]


def test_session_report_pdf_fails_context_closed_without_losing_report(
    tmp_path: Path,
    monkeypatch,
) -> None:
    session_id = "session_v1_report_context_failure"
    captured = {}

    monkeypatch.setattr(
        monitor_web,
        "build_session_ti_projection",
        lambda storage, selected_session_id, config=None: (_ for _ in ()).throw(RuntimeError("private detail")),
    )
    monkeypatch.setattr(
        monitor_web,
        "load_ai_advisory_detail",
        lambda config, selected_session_id, _storage=None: (_ for _ in ()).throw(RuntimeError("private detail")),
    )

    def render(report, session, **kwargs):
        captured.update(kwargs)
        return b"%PDF-1.7 bounded fixture"

    monkeypatch.setattr(monitor_web, "render_pdf_report_bytes", render)
    pdf, error = monitor_web.load_session_report_pdf(_config(tmp_path, session_id), session_id)

    assert pdf == b"%PDF-1.7 bounded fixture"
    assert error == {}
    assert captured["external_ti_projection"]["status"] == "TI_UNAVAILABLE"
    assert captured["external_ti_projection"]["error_code"] == "projection_unavailable"
    assert "error" not in captured["external_ti_projection"]
    assert captured["ai_advisory_projection"]["status"] == "unavailable"
    assert "error" not in captured["ai_advisory_projection"]


def test_session_report_pdf_fails_closed_without_exact_session_or_report(tmp_path: Path) -> None:
    config = _config(tmp_path, "session_v1_report_download")

    pdf, error = monitor_web.load_session_report_pdf(config, "../outside")
    assert pdf is None
    assert error["error_code"] == "malformed_session_id"

    pdf, error = monitor_web.load_session_report_pdf(config, "session_v1_missing")
    assert pdf is None
    assert error["error_code"] == "session_not_found"


def test_session_report_pdf_projects_authentication_metadata_without_passwords(
    tmp_path: Path,
    monkeypatch,
) -> None:
    session_id = "session_v1_report_authentication"
    password_sentinel = "report-password-must-never-be-rendered"
    storage = ReportStorage(
        session_id,
        event_rows=[
            {
                "event_id": "auth-success",
                "session_id": session_id,
                "eventid": "cowrie.login.success",
                "timestamp": "2026-09-17T07:01:00Z",
                "payload_json": json.dumps(
                    {
                        "eventid": "cowrie.login.success",
                        "session": session_id,
                        "timestamp": "2026-09-17T07:01:00Z",
                        "username": "observed-report-account",
                        "password": password_sentinel,
                    }
                ),
            }
        ],
    )
    config = _config(tmp_path, session_id)
    config._storage = storage
    captured = {}
    monkeypatch.setattr(
        monitor_web,
        "build_session_ti_projection",
        lambda _storage, selected_session_id, config=None: {
            "ok": True,
            "status": "TI_PENDING",
            "session_id": selected_session_id,
        },
    )
    monkeypatch.setattr(
        monitor_web,
        "load_ai_advisory_detail",
        lambda _config, selected_session_id, _storage=None: {
            "ok": True,
            "status": "unavailable",
            "session_id": selected_session_id,
        },
    )
    monkeypatch.setattr(
        monitor_web,
        "load_next_distinct_prediction",
        lambda *_args, **_kwargs: {},
    )

    def render(_report, session, **_kwargs):
        captured["session"] = session
        return b"%PDF-1.7 auth fixture"

    monkeypatch.setattr(monitor_web, "render_pdf_report_bytes", render)
    pdf, error = monitor_web.load_session_report_pdf(config, session_id)

    assert pdf == b"%PDF-1.7 auth fixture"
    assert error == {}
    assert captured["session"]["login_attempts"] == 1
    assert captured["session"]["login_success"] is True
    assert captured["session"]["observed_account_visibility"] == "AVAILABLE"
    assert captured["session"]["observed_account_identifier"] == "observed-report-account"
    assert password_sentinel not in json.dumps(captured["session"], sort_keys=True)


def test_latest_ti_lookup_uses_newest_provider_or_source_ip_cache_time() -> None:
    assert _latest_ti_lookup_at(
        {
            "freshness": {"latest_retrieved_at": "2026-09-21T11:00:00Z"},
            "external_ti_summary": {
                "source_ip_cache_latest_lookup_at": "2026-09-21T11:10:00Z"
            },
        }
    ) == "2026-09-21T11:10:00Z"
    assert _latest_ti_lookup_at(
        {
            "freshness": {"latest_retrieved_at": "2026-09-21T11:20:00Z"},
            "external_ti_summary": {
                "source_ip_cache_latest_lookup_at": "2026-09-21T11:10:00Z"
            },
        }
    ) == "2026-09-21T11:20:00Z"
    assert _latest_ti_lookup_at({"freshness": {}, "external_ti_summary": {}}) is None
