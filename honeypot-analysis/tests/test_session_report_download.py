from __future__ import annotations

import json
from pathlib import Path

import production.api.monitor_web as monitor_web


class ReportStorage:
    def __init__(self, session_id: str) -> None:
        self.session_id = session_id

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
        return []


def _config(tmp_path: Path, session_id: str) -> monitor_web.MonitorConfig:
    config = monitor_web.MonitorConfig(
        db_path="",
        database_url="sqlite:///:memory:",
        reports_dir=str(tmp_path / "reports"),
    )
    config._storage = ReportStorage(session_id)
    return config


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

    def render(
        report,
        session,
        *,
        artifact_version="",
        external_ti_projection=None,
        ai_advisory_projection=None,
    ):
        captured["report"] = report
        captured["session"] = session
        captured["artifact_version"] = artifact_version
        captured["external_ti_projection"] = external_ti_projection
        captured["ai_advisory_projection"] = ai_advisory_projection
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
    pdf, error = monitor_web.load_session_report_pdf(_config(tmp_path, session_id), session_id)

    assert pdf == b"%PDF-1.7 bounded fixture"
    assert error == {}
    assert captured["report"]["schema_version"] == "threat_hypothesis.v2"
    assert captured["session"]["session_id"] == session_id
    assert captured["external_ti_projection"] == expected_ti
    assert captured["ai_advisory_projection"] == expected_ai
    assert not (tmp_path / "reports").exists()


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
