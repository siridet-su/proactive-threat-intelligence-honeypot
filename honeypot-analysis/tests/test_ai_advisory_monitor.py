from __future__ import annotations

import http.client
import threading
from pathlib import Path

from production.api import monitor_web
from production.api.monitor_web import MonitorConfig, build_server, load_ai_advisory_detail
from production.utils.config import ProductionConfig


class _Storage:
    def get_current_report_for_session(self, session_id: str):
        assert session_id == "session-1"
        return {
            "report_id": "report_0123456789abcdef0123456789abcdef",
            "payload": {
                "assessment_id": "session_assessment_0123456789abcdef0123456789abcdef"
            },
        }

    def get_ai_advisory_for_report(self, report_id: str, assessment_id: str):
        assert report_id == "report_0123456789abcdef0123456789abcdef"
        assert assessment_id == "session_assessment_0123456789abcdef0123456789abcdef"
        return self.get_ai_advisory_for_session("session-1")

    def get_ai_advisory_outbox_for_report(self, report_id: str, assessment_id: str):
        del report_id, assessment_id
        return {"status": "succeeded"}

    def get_ai_advisory_for_session(self, session_id: str):
        assert session_id == "session-1"
        return {
            "advisory_id": "ai_advisory_0123456789abcdef0123456789abcdef",
            "report_id": "report_0123456789abcdef0123456789abcdef",
            "assessment_id": "session_assessment_0123456789abcdef0123456789abcdef",
            "status": "accepted",
            "payload": {
                "schema_version": "ai_advisory_record.v1",
                "status": "accepted",
                "authority": "non_authoritative_advisory_only",
                "validation": {"status": "accepted", "reason_code": ""},
                "rendered_advisory": {
                    "schema_version": "ai_advisory_rendered.v1",
                    "status": "rendered",
                    "paragraphs": [{"text": "Policy-authored deterministic text"}],
                },
                "shadow_candidates": {
                    "schema_version": "ai_shadow_candidate_set.v1",
                    "candidates": [
                        {
                            "candidate_id": "ai_candidate_0123456789abcdef0123456789abcdef",
                            "candidate_type": "possible_falsifiable_hypothesis",
                            "status": "unverified_ai_candidate",
                        }
                    ],
                },
                "safety": {
                    "requires_manual_approval": True,
                    "safe_to_auto_execute": False,
                },
                "provenance": {"projection_sha256": "a" * 64},
            },
            "metrics": {"validator_accepted": True},
        }


def test_additive_monitor_loader_keeps_ai_separate_and_non_authoritative() -> None:
    result = load_ai_advisory_detail(
        MonitorConfig(db_path=":memory:", reports_dir="reports"),
        "session-1",
        _storage=_Storage(),
    )
    assert result["ok"] is True
    assert result["advisory"]["authority"] == "non_authoritative_advisory_only"
    assert result["advisory"]["shadow_candidates"]["candidates"][0][
        "status"
    ] == "unverified_ai_candidate"
    assert "canonical_evidence" not in result["advisory"]
    assert "response_guidance_v3" not in result["advisory"]


class _StaleStorage(_Storage):
    def get_ai_advisory_for_report(self, report_id: str, assessment_id: str):
        del report_id, assessment_id
        return None

    def get_ai_advisory_outbox_for_report(self, report_id: str, assessment_id: str):
        del report_id, assessment_id
        return None


def test_monitor_never_displays_an_advisory_for_an_older_report() -> None:
    result = load_ai_advisory_detail(
        MonitorConfig(db_path=":memory:", reports_dir="reports"),
        "session-1",
        _storage=_StaleStorage(),
    )
    assert result["ok"] is True
    assert result["status"] == "superseded"
    assert result["advisory"] == {}
    assert result["report_id"] == "report_0123456789abcdef0123456789abcdef"


def test_monitor_asset_uses_separate_endpoint_labels_and_text_content() -> None:
    html = (
        Path(__file__).resolve().parents[1]
        / "production"
        / "api"
        / "static"
        / "monitor.html"
    ).read_text(encoding="utf-8")
    assert "/api/ai-advisory?session_id=" in html
    assert "AI-generated advisory — non-authoritative" in html
    assert "Graph-grounded AI advisory — non-authoritative" in html
    assert "Historical v1 shadow candidates — Unverified AI candidates" in html
    assert "existing deterministic object; non-authoritative" in html
    assert "rendered.sections" in html
    assert "item.textContent = String(paragraph?.text || '')" in html
    assert "renderAIAdvisoryPanel(aiResult)" in html


def test_live_monitor_auth_no_store_and_advisory_rendering(monkeypatch) -> None:
    safe_detail = {
        "ok": True,
        "session_id": "session-1",
        "advisory": {
            "authority": "non_authoritative_advisory_only",
            "rendered_advisory": {
                "paragraphs": [{"text": "Review existing finding IDs only."}],
            },
        },
    }
    monkeypatch.setattr(monitor_web, "load_ai_advisory_detail", lambda *args, **kwargs: safe_detail)
    production_config = ProductionConfig(
        dashboard_read_token="read-secret",
        dashboard_write_token="write-secret",
    )
    config = MonitorConfig(
        db_path=":memory:",
        reports_dir="reports",
        production_config=production_config,
    )
    server = build_server("127.0.0.1", 0, config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        connection = http.client.HTTPConnection(host, port, timeout=5)
        connection.request("GET", "/api/ai-advisory?session_id=session-1")
        unauthorized = connection.getresponse()
        unauthorized_body = unauthorized.read().decode("utf-8")
        assert unauthorized.status == 401
        assert unauthorized.getheader("Cache-Control") == "no-store"
        assert "Review existing finding IDs only" not in unauthorized_body
        connection.close()

        connection = http.client.HTTPConnection(host, port, timeout=5)
        connection.request(
            "GET",
            "/api/ai-advisory?session_id=session-1",
            headers={"Authorization": "Bearer read-secret"},
        )
        authorized = connection.getresponse()
        authorized_body = authorized.read().decode("utf-8")
        assert authorized.status == 200
        assert authorized.getheader("Cache-Control") == "no-store"
        assert "Review existing finding IDs only" in authorized_body
        assert "non_authoritative_advisory_only" in authorized_body
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
