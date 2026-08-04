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
