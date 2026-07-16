from __future__ import annotations

import io
import sqlite3
from pathlib import Path
from urllib.parse import urlencode

import pytest

import production.api.monitor_web as monitor_web
from production.storage import open_storage


class FakeMonitorStorage:
    def __init__(self) -> None:
        session_payload = {
            "session_id": "session-mongo",
            "src_ip": "8.8.8.8",
            "commands": ["whoami"],
            "tactics": ["discovery"],
            "ttps": ["T1033"],
            "is_ended": False,
            "raw_events": [
                {
                    "eventid": "cowrie.command.input",
                    "session": "session-mongo",
                    "src_ip": "8.8.8.8",
                    "timestamp": "2026-07-16T10:00:00Z",
                    "input": "whoami",
                }
            ],
        }
        self.sessions = [
            {
                "session_id": "session-mongo",
                "src_ip": "8.8.8.8",
                "updated_at": "2026-07-16T10:00:02Z",
                "payload": session_payload,
            }
        ]
        self.tables = {
            "analysis_jobs": [
                {
                    "job_id": "job-mongo",
                    "session_id": "session-mongo",
                    "status": "succeeded",
                    "report_id": "report-mongo",
                    "updated_at": "2026-07-16T10:00:03Z",
                    "payload": {"session_id": "session-mongo"},
                }
            ],
            "reports": [
                {
                    "report_id": "report-mongo",
                    "session_id": "session-mongo",
                    "created_at": "2026-07-16T10:00:04Z",
                    "payload": {
                        "session_id": "session-mongo",
                        "summary": "backend-neutral report",
                    },
                }
            ],
            "events": [
                {
                    "event_id": "event-mongo",
                    "session_id": "session-mongo",
                    "sensor_id": "sensor-mongo",
                    "src_ip": "8.8.8.8",
                    "eventid": "cowrie.command.input",
                    "timestamp": "2026-07-16T10:00:00Z",
                    "received_at": "2026-07-16T10:00:01Z",
                    "payload": {
                        "eventid": "cowrie.command.input",
                        "session": "session-mongo",
                        "src_ip": "8.8.8.8",
                        "timestamp": "2026-07-16T10:00:00Z",
                        "input": "whoami",
                    },
                }
            ],
            "alerts": [],
            "prediction_snapshots": [
                {
                    "snapshot_id": "snapshot-mongo",
                    "session_id": "session-mongo",
                    "created_at": "2026-07-16T10:00:05Z",
                    "payload": {
                        "snapshot_id": "snapshot-mongo",
                        "session_id": "session-mongo",
                        "prediction": ["execution"],
                        "final_ranking": [
                            {
                                "tactic": "execution",
                                "score": 0.5,
                                "confidence": "medium",
                            }
                        ],
                    },
                }
            ],
            "analyst_feedback": [],
            "observable_sightings": [],
            "threat_hunt_jobs": [],
            "enrichment_jobs": [],
            "prediction_backtest_runs": [],
            "prediction_calibration_runs": [],
            "classification_review_labels": [],
        }
        self.session_queries: list[tuple[str, str, int]] = []
        self.feedback_payloads: list[dict] = []

    def list_session_rows(
        self,
        limit: int = 100,
        session_source: str | None = None,
        external_only: bool = False,
    ) -> list[dict]:
        del session_source, external_only
        return [dict(row) for row in self.sessions[:limit]]

    def list_rows(self, table: str, limit: int = 100) -> list[dict]:
        return [dict(row) for row in self.tables.get(table, [])[:limit]]

    def list_rows_for_session(
        self,
        table: str,
        session_id: str,
        limit: int = 100,
    ) -> list[dict]:
        self.session_queries.append((table, session_id, limit))
        if table == "sessions":
            rows = self.sessions
        else:
            rows = self.tables.get(table, [])
        return [
            dict(row)
            for row in rows
            if (
                row.get("session_id")
                or (row.get("payload") or {}).get("session_id")
                or (row.get("payload") or {}).get("session")
            )
            == session_id
        ][:limit]

    def get_session(self, session_id: str) -> dict | None:
        return next(
            (
                dict(row)
                for row in self.sessions
                if row.get("session_id") == session_id
            ),
            None,
        )

    def get_enrichment_record(
        self,
        observable_type: str,
        observable_value: str,
        allow_stale: bool = True,
    ) -> None:
        del observable_type, observable_value, allow_stale
        return None

    def load_enrichment_cache(
        self,
        observable_type: str = "ip",
        allow_stale: bool = True,
    ) -> dict:
        del observable_type, allow_stale
        return {}

    def list_session_links(self, session_id: str, limit: int = 100) -> list:
        del session_id, limit
        return []

    def list_session_campaigns(
        self,
        session_id: str,
        limit: int = 20,
    ) -> list:
        del session_id, limit
        return []

    def get_campaign(self, campaign_id: str) -> None:
        del campaign_id
        return None

    def record_analyst_feedback(self, payload: dict) -> str:
        self.feedback_payloads.append(dict(payload))
        feedback_id = str(payload.get("feedback_id") or "feedback-mongo")
        self.tables["analyst_feedback"].insert(
            0,
            {
                **payload,
                "feedback_id": feedback_id,
                "payload": dict(payload),
            },
        )
        return feedback_id


def _mongo_config(tmp_path: Path) -> monitor_web.MonitorConfig:
    return monitor_web.MonitorConfig(
        db_path=str(tmp_path / "must-not-be-opened.db"),
        database_url=(
            "mongodb://unit-user:unit-password@database.internal:27017/"
            "honeypot?authSource=admin"
        ),
        reports_dir=str(tmp_path / "reports"),
        enable_smb_decisions=False,
    )


def test_snapshot_detail_and_feedback_use_shared_storage_without_sqlite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage = FakeMonitorStorage()
    opened: list[str] = []

    def fake_open_storage(database_url: str) -> FakeMonitorStorage:
        opened.append(database_url)
        return storage

    def forbidden_sqlite(*args, **kwargs):
        raise AssertionError(f"sqlite3.connect must not be called: {args!r} {kwargs!r}")

    monkeypatch.setattr(monitor_web, "open_storage", fake_open_storage)
    monkeypatch.setattr(sqlite3, "connect", forbidden_sqlite)
    config = _mongo_config(tmp_path)

    snapshot = monitor_web.load_snapshot(config)
    detail = monitor_web.load_session_detail(config, "session-mongo")
    feedback_id = monitor_web.record_analyst_feedback(
        config,
        {
            "session_id": "session-mongo",
            "snapshot_id": "snapshot-mongo",
            "label": "useful",
            "notes": "stored through fake Mongo backend",
        },
    )

    assert snapshot["ok"] is True
    assert snapshot["summary"]["total_sessions"] == 1
    assert snapshot["selected"]["payload"]["commands"] == ["whoami"]
    assert snapshot["selected_detail"]["events_table_rows"][0]["payload"]["input"] == "whoami"
    assert detail["ok"] is True
    assert detail["latest_prediction_snapshot"]["payload"]["prediction"] == [
        "execution"
    ]
    assert feedback_id
    assert storage.feedback_payloads[-1]["source"] == "monitor_web"
    assert {query[0] for query in storage.session_queries} >= {
        "sessions",
        "events",
        "analysis_jobs",
        "reports",
        "prediction_snapshots",
        "analyst_feedback",
    }
    assert opened
    assert all(url.startswith("mongodb://") for url in opened)
    assert not Path(config.db_path).exists()


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
    storage = FakeMonitorStorage()
    monkeypatch.setattr(monitor_web, "open_storage", lambda _url: storage)
    monkeypatch.setattr(
        sqlite3,
        "connect",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError(f"unexpected SQLite feedback write: {args!r} {kwargs!r}")
        ),
    )
    config = _mongo_config(tmp_path)

    class StubHandler:
        monitor_config = config

        def __init__(self, path: str, body: bytes) -> None:
            self.path = path
            self.headers = {"Content-Length": str(len(body))}
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

    json_handler = StubHandler(
        "/analyst-feedback",
        (
            '{"session_id":"session-mongo","snapshot_id":"snapshot-mongo",'
            '"label":"useful"}'
        ).encode(),
    )
    monitor_web.MonitorHandler.do_POST(json_handler)

    form_handler = StubHandler(
        "/feedback",
        urlencode(
            {
                "session_id": "session-mongo",
                "snapshot_id": "snapshot-mongo",
                "label": "not_useful",
            }
        ).encode(),
    )
    monitor_web.MonitorHandler.do_POST(form_handler)

    assert json_handler.json_response is not None
    assert form_handler.redirect_location == "/?session_id=session-mongo"
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
        enable_smb_decisions=False,
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
