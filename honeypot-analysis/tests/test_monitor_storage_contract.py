from __future__ import annotations

import io
import sqlite3
from pathlib import Path
from urllib.parse import urlencode

import pytest

import production.api.monitor_web as monitor_web
from production.storage import open_storage


class RecordingFeedbackStorage:
    """SQLite-shaped storage seam used to test both monitor write routes.

    The production path is SQLite-only.  This test double intentionally
    implements only the storage method the handlers need; it does not imply
    support for another database backend.
    """

    def __init__(self) -> None:
        self.feedback_payloads: list[dict] = []

    def record_analyst_feedback(self, payload: dict) -> str:
        self.feedback_payloads.append(dict(payload))
        return str(payload.get("feedback_id") or f"feedback-{len(self.feedback_payloads)}")


def test_unsupported_database_url_does_not_fall_back_to_db_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened: list[str] = []

    def unsupported(database_url: str):
        opened.append(database_url)
        raise RuntimeError("unsupported backend")

    def forbidden_sqlite(*args, **kwargs):
        raise AssertionError(f"unexpected SQLite fallback: {args!r} {kwargs!r}")

    monkeypatch.setattr(monitor_web, "open_storage", unsupported)
    monkeypatch.setattr(sqlite3, "connect", forbidden_sqlite)
    fallback_path = tmp_path / "split-brain.db"
    config = monitor_web.MonitorConfig(
        db_path=str(fallback_path),
        database_url="unsupported://database.internal/honeypot",
        reports_dir=str(tmp_path / "reports"),
    )

    snapshot = monitor_web.load_snapshot(config)

    assert snapshot["ok"] is False
    assert "storage open failed" in snapshot["error"]
    assert opened == ["unsupported://database.internal/honeypot"]
    assert not fallback_path.exists()


def test_both_feedback_http_paths_use_shared_feedback_writer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage = RecordingFeedbackStorage()
    monkeypatch.setattr(monitor_web, "open_storage", lambda _url: storage)
    monkeypatch.setattr(
        sqlite3,
        "connect",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError(f"unexpected SQLite feedback write: {args!r} {kwargs!r}")
        ),
    )
    database_path = tmp_path / "monitor.db"
    config = monitor_web.MonitorConfig(
        db_path=str(database_path),
        database_url=f"sqlite:///{database_path}",
        reports_dir=str(tmp_path / "reports"),
    )

    class StubHandler:
        monitor_config = config

        def __init__(self, path: str, body: bytes) -> None:
            self.path = path
            self.headers = {
                "Content-Length": str(len(body)),
                "Content-Type": (
                    "application/json"
                    if path == "/analyst-feedback"
                    else "application/x-www-form-urlencoded"
                ),
            }
            self.rfile = io.BytesIO(body)
            self.json_response = None
            self.redirect_location = ""
            self.error_response = None

        def _send_json(self, status, payload) -> None:
            self.json_response = (status, payload)

        def _redirect(self, location: str) -> None:
            self.redirect_location = location

        def _send(self, status, body, content_type) -> None:
            self.error_response = (status, body, content_type)

        def _require_feedback_write(self) -> bool:
            return True

    json_handler = StubHandler(
        "/analyst-feedback",
        (
            '{"session_id":"session-sqlite","snapshot_id":"snapshot-sqlite",'
            '"label":"useful"}'
        ).encode(),
    )
    monitor_web.MonitorHandler.do_POST(json_handler)

    form_handler = StubHandler(
        "/feedback",
        urlencode(
            {
                "session_id": "session-sqlite",
                "snapshot_id": "snapshot-sqlite",
                "label": "not_useful",
            }
        ).encode(),
    )
    monitor_web.MonitorHandler.do_POST(form_handler)

    assert json_handler.json_response is not None
    assert form_handler.redirect_location == "/?session_id=session-sqlite"
    assert form_handler.error_response is None
    assert [row["label"] for row in storage.feedback_payloads] == [
        "useful",
        "not_useful",
    ]


def test_explicit_legacy_db_path_remains_supported_through_storage_contract(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "legacy-monitor.db"
    storage = open_storage(f"sqlite:///{database_path}")
    storage.save_session(
        {
            "session_id": "legacy-sqlite-session",
            "src_ip": "8.8.4.4",
            "commands": ["id"],
            "tactics": ["discovery"],
            "is_ended": False,
        }
    )
    config = monitor_web.MonitorConfig(
        db_path=str(database_path),
        reports_dir=str(tmp_path / "reports"),
    )

    snapshot = monitor_web.load_snapshot(config)
    detail = monitor_web.load_session_detail(
        config,
        "legacy-sqlite-session",
    )

    assert snapshot["ok"] is True
    assert snapshot["selected"]["session_id"] == "legacy-sqlite-session"
    assert detail["ok"] is True
    assert detail["commands"] == ["id"]


@pytest.mark.parametrize("loader_name", ["load_session_detail", "load_dashboard_session_detail"])
def test_session_detail_distinguishes_immutable_report_from_late_ai_advisory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, loader_name: str,
) -> None:
    database_path = tmp_path / "ai-status.db"
    storage = open_storage(f"sqlite:///{database_path}")
    storage.save_session({"session_id": "late-ai-session", "src_ip": "8.8.4.4", "is_ended": True})
    config = monitor_web.MonitorConfig(db_path=str(database_path), reports_dir=str(tmp_path / "reports"))
    monkeypatch.setattr(monitor_web, "_complete_report_payload", lambda *_args: {
        "schema_version": "session_assessment.v4", "assessment_id": "assessment-1",
        "behavioral_findings": [], "hypothesis_sets": [],
    })
    monkeypatch.setattr(monitor_web, "_report_payload", lambda *_args: {
        "schema_version": "session_assessment.v4", "assessment_id": "assessment-1",
    })
    monkeypatch.setattr(monitor_web, "_report_summary", lambda *_args: {
        "ai_enriched": "false", "ai_enrichment_scope": "immutable_deterministic_assessment_at_generation",
    })
    monkeypatch.setattr(monitor_web, "load_ai_advisory_detail", lambda *_args, **_kwargs: {
        "ok": True, "status": "accepted",
    })

    detail = getattr(monitor_web, loader_name)(config, "late-ai-session")

    assert detail["ok"] is True
    assert detail["report_summary"]["ai_enriched"] == "false"
    assert detail["report_summary"]["current_ai_advisory_status"] == "accepted"
    assert detail["report_summary"]["current_ai_advisory_scope"] == "separate_late_bound_advisory"


def test_session_detail_command_count_comes_from_durable_event_rows(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "event-backed-monitor.db"
    storage = open_storage(f"sqlite:///{database_path}")
    storage.save_session(
        {
            "session_id": "event-backed-session",
            "src_ip": "203.0.113.20",
            "commands": [],
            "is_ended": True,
        }
    )
    event_ids = [
        "cowrie.session.connect",
        "cowrie.command.input",
        "cowrie.login.success",
        "cowrie.command.input",
        "cowrie.client.kex",
        "cowrie.command.input",
        "cowrie.login.success",
        "cowrie.session.closed",
    ]
    for index, eventid in enumerate(event_ids):
        storage.store_event(
            "sensor-monitor",
            {
                "eventid": eventid,
                "session": "event-backed-session",
                "src_ip": "203.0.113.20",
                "timestamp": f"2026-07-17T00:00:0{index}Z",
                "input": "id" if eventid == "cowrie.command.input" else "",
            },
        )

    config = monitor_web.MonitorConfig(
        db_path=str(database_path),
        reports_dir=str(tmp_path / "reports"),
    )
    detail = monitor_web.load_session_detail(config, "event-backed-session")

    assert detail["ok"] is True
    assert len(detail["events_table_rows"]) == 8
    assert detail["overview"]["command_count"] == 3


def test_session_detail_command_count_excludes_explicit_blank_input(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "blank-input-monitor.db"
    storage = open_storage(f"sqlite:///{database_path}")
    storage.save_session(
        {
            "session_id": "blank-input-session",
            "src_ip": "203.0.113.21",
            "commands": [],
            "is_ended": True,
        }
    )
    for index, command_input in enumerate(("id", "", "   ", "uname -a")):
        storage.store_event(
            "sensor-monitor",
            {
                "eventid": "cowrie.command.input",
                "session": "blank-input-session",
                "src_ip": "203.0.113.21",
                "timestamp": f"2026-07-17T00:00:0{index}Z",
                "input": command_input,
            },
        )

    config = monitor_web.MonitorConfig(
        db_path=str(database_path),
        reports_dir=str(tmp_path / "reports"),
    )
    detail = monitor_web.load_session_detail(config, "blank-input-session")

    assert detail["ok"] is True
    assert detail["overview"]["command_count"] == 2
