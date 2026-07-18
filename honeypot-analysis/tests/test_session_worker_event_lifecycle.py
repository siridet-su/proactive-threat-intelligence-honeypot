from __future__ import annotations

import base64
import json
import os
import sqlite3
import threading
from pathlib import Path

import pytest

from production.storage import open_storage
from production.utils.config import ProductionConfig
from production.workers.session_monitor import SessionMonitor
from production.workers.session_worker import SessionWorker


def _config(tmp_path: Path, *, batch_size: int = 10) -> ProductionConfig:
    keyring = tmp_path / "credential-hmac-keyring.json"
    if not keyring.exists():
        keyring.write_text(
            json.dumps(
                {
                    "schema_version": "credential_hmac_keyring.v1",
                    "active_key_id": "worker-test-key",
                    "keys": {
                        "worker-test-key": base64.b64encode(
                            b"worker-lifecycle-test-key-material"
                        ).decode("ascii")
                    },
                    "correlation_key_ids": [],
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        os.chmod(keyring, 0o600)
    return ProductionConfig(
        database_url=f"sqlite:///{tmp_path / 'state.db'}",
        worker_batch_size=batch_size,
        enable_feed_loading=False,
        enable_securebert=False,
        enable_enrichment_jobs=False,
        enable_session_ttp_correlation=False,
        enable_smb_decisions=False,
        analysis_skip_empty_sessions=False,
        credential_hmac_keyring_file=str(keyring),
        prediction_policy={"enabled": False},
        calibration_policy={"enabled": False},
        campaign_policy={"enabled": False},
        threat_hunt_policy={"enabled": False},
    )


def _event(session: str, eventid: str, index: int, **extra: object) -> dict:
    return {
        "eventid": eventid,
        "session": session,
        "src_ip": "203.0.113.27",
        "timestamp": f"2026-07-18T02:00:{index:02d}Z",
        **extra,
    }


def _event_row(storage: object, event_id: str) -> dict:
    rows = storage.list_rows("events", limit=100)
    return next(row for row in rows if row["event_id"] == event_id)


def test_worker_completes_claim_only_after_durable_session_save(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    storage = open_storage(config.database_url)
    event_id, _ = storage.store_event(
        "sensor-a",
        _event("session-a", "cowrie.session.connect", 0),
    )
    worker = SessionWorker(config)
    original_complete = worker.storage.complete_event

    def complete_after_session_save(*args: object, **kwargs: object) -> bool:
        saved = worker.storage.get_session("session-a")
        assert saved is not None
        effects = args[3]
        assert effects["event_applied"] is True
        assert effects["session_saved"] is True
        return original_complete(*args, **kwargs)

    monkeypatch.setattr(worker.storage, "complete_event", complete_after_session_save)
    try:
        assert worker.process_unprocessed() == 1
    finally:
        worker.close()

    row = _event_row(storage, event_id)
    effects = json.loads(row["effect_summary_json"])
    assert row["processed"] == 1
    assert row["processing_outcome"] == "succeeded"
    assert effects["event_applied"] is True
    assert effects["session_saved"] is True


def test_partial_write_failure_retries_without_duplicate_in_memory_state_or_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = _config(tmp_path, batch_size=1)
    storage = open_storage(config.database_url)
    event_id, _ = storage.store_event(
        "sensor-a",
        _event(
            "session-retry",
            "cowrie.command.input",
            0,
            input="whoami",
            success=1,
        ),
    )
    worker = SessionWorker(config)
    original_save = worker.storage.save_session
    marker = "mongodb://operator:do-not-store@example.invalid/db?token=secret"
    failures = 0

    def fail_once(payload: dict) -> None:
        nonlocal failures
        failures += 1
        if failures == 1:
            raise RuntimeError(marker)
        original_save(payload)

    monkeypatch.setattr(worker.storage, "save_session", fail_once)
    monkeypatch.setattr(worker, "_retry_delay_seconds", lambda _attempts: 0.0)
    try:
        assert worker.process_unprocessed() == 0
        assert worker.monitor.get_session("session-retry") is None
        retry_row = _event_row(storage, event_id)
        assert retry_row["processed"] == 0
        assert retry_row["processing_outcome"] == "retry_scheduled"
        assert retry_row["last_error_code"] == "event_processing_failed"
        assert retry_row["last_error_type"] == "RuntimeError"
        assert marker not in json.dumps(retry_row, sort_keys=True)

        assert worker.process_unprocessed() == 1
        state = worker.monitor.get_session("session-retry")
        assert state is not None
        assert state.commands == ["whoami"]
        assert len(state.raw_events) == 1
    finally:
        worker.close()

    assert marker not in capsys.readouterr().out
    saved = storage.get_session("session-retry")["payload"]
    assert saved["commands"] == ["whoami"]
    assert len(saved["raw_events"]) == 1
    assert _event_row(storage, event_id)["attempts"] == 2


def test_retried_close_event_restores_active_state_and_enqueues_one_analysis_job(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    storage = open_storage(config.database_url)
    storage.store_event("sensor-a", _event("session-close", "cowrie.session.connect", 0))
    storage.store_event(
        "sensor-a",
        _event(
            "session-close",
            "cowrie.command.input",
            1,
            input="id",
            success=1,
        ),
    )
    worker = SessionWorker(config)
    assert worker.process_unprocessed() == 2
    active = worker.monitor.get_session("session-close")
    assert active is not None and active.is_ended is False

    close_id, _ = storage.store_event(
        "sensor-a",
        _event("session-close", "cowrie.session.closed", 2, duration=5.0),
    )
    worker.config.worker_batch_size = 1
    original_enqueue = worker.storage.enqueue_analysis_job
    calls = 0

    def fail_before_enqueue(payload: dict) -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ConnectionError("temporary destination interruption")
        return original_enqueue(payload)

    monkeypatch.setattr(worker.storage, "enqueue_analysis_job", fail_before_enqueue)
    monkeypatch.setattr(worker, "_retry_delay_seconds", lambda _attempts: 0.0)
    try:
        assert worker.process_unprocessed() == 0
        restored = worker.monitor.get_session("session-close")
        assert restored is not None
        assert restored.is_ended is False
        assert len(restored.raw_events) == 2

        assert worker.process_unprocessed() == 1
        closed = worker.monitor.get_session("session-close")
        assert closed is not None
        assert closed.is_ended is True
        assert len(closed.raw_events) == 3
    finally:
        worker.close()

    assert _event_row(storage, close_id)["attempts"] == 2
    jobs = storage.list_rows("analysis_jobs", limit=20)
    assert len(jobs) == 1
    assert jobs[0]["session_id"] == "session-close"


def test_active_worker_lease_blocks_standby_until_release(tmp_path: Path) -> None:
    config = _config(tmp_path)
    storage = open_storage(config.database_url)
    first_id, _ = storage.store_event(
        "sensor-a",
        _event("session-one", "cowrie.session.connect", 0),
    )
    active = SessionWorker(config)
    standby = SessionWorker(config)
    try:
        assert active.process_unprocessed() == 1
        assert _event_row(storage, first_id)["processed"] == 1

        second_id, _ = storage.store_event(
            "sensor-a",
            _event("session-two", "cowrie.session.connect", 1),
        )
        assert standby.process_unprocessed() == 0
        assert _event_row(storage, second_id)["processed"] == 0

        active.close()
        assert standby.process_unprocessed() == 1
        assert _event_row(storage, second_id)["processed"] == 1
    finally:
        active.close()
        standby.close()


def test_concurrent_runtime_workers_cannot_apply_the_same_event(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path, batch_size=1)
    storage = open_storage(config.database_url)
    event_id, _ = storage.store_event(
        "sensor-a",
        _event("session-concurrent", "cowrie.session.connect", 0),
    )
    active = SessionWorker(config)
    standby = SessionWorker(config)
    entered = threading.Event()
    release = threading.Event()
    original_on_event = active.monitor.on_event
    result: list[int] = []

    def blocked_on_event(event: dict) -> list:
        entered.set()
        assert release.wait(timeout=5)
        return original_on_event(event)

    monkeypatch.setattr(active.monitor, "on_event", blocked_on_event)
    thread = threading.Thread(target=lambda: result.append(active.process_unprocessed()))
    thread.start()
    assert entered.wait(timeout=5)
    try:
        assert standby.process_unprocessed() == 0
        assert _event_row(storage, event_id)["processed"] == 0
    finally:
        release.set()
        thread.join(timeout=5)
        active.close()
        standby.close()
    assert not thread.is_alive()
    assert result == [1]
    assert _event_row(storage, event_id)["attempts"] == 1


def test_permanent_failure_is_dead_lettered_with_registered_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path, batch_size=1)
    config.event_max_attempts = 2
    storage = open_storage(config.database_url)
    event_id, _ = storage.store_event(
        "sensor-a",
        _event("session-dead-letter", "cowrie.session.connect", 0),
    )
    worker = SessionWorker(config)

    def unavailable(_payload: dict) -> None:
        raise ConnectionError("destination unavailable")

    monkeypatch.setattr(worker.storage, "save_session", unavailable)
    monkeypatch.setattr(worker, "_retry_delay_seconds", lambda _attempts: 0.0)
    try:
        assert worker.process_unprocessed() == 0
        assert worker.process_unprocessed() == 0
        assert worker.process_unprocessed() == 0
    finally:
        worker.close()

    row = _event_row(storage, event_id)
    assert row["processed"] == 1
    assert row["processing_outcome"] == "dead_letter"
    assert row["attempts"] == 2
    assert row["last_error_code"] == "event_processing_failed"
    assert row["last_error_type"] == "ConnectionError"
    assert worker.monitor.get_session("session-dead-letter") is None


def test_stale_crashed_claim_is_recovered_by_new_worker(tmp_path: Path) -> None:
    config = _config(tmp_path)
    storage = open_storage(config.database_url)
    event_id, _ = storage.store_event(
        "sensor-a",
        _event("session-crash", "cowrie.session.connect", 0),
    )
    crashed = SessionWorker(config)
    assert crashed._ensure_leadership()
    claimed = crashed.storage.claim_events(
        crashed.worker_owner,
        1,
        config.event_lease_seconds,
        max_attempts=config.event_max_attempts,
        leader_scope="session-worker",
        leader_token=crashed.worker_token,
    )
    assert [row["event_id"] for row in claimed] == [event_id]

    database_path = Path(config.database_url.removeprefix("sqlite:///"))
    with sqlite3.connect(database_path) as conn:
        conn.execute(
            "UPDATE events SET claim_expires_at = '2000-01-01T00:00:00+00:00' "
            "WHERE event_id = ?",
            (event_id,),
        )
        conn.execute(
            "UPDATE worker_leases SET expires_at = '2000-01-01T00:00:00+00:00' "
            "WHERE scope = 'session-worker'"
        )

    recovered = SessionWorker(config)
    try:
        assert recovered.process_unprocessed() == 1
    finally:
        crashed.close()
        recovered.close()
    row = _event_row(storage, event_id)
    assert row["processed"] == 1
    assert row["attempts"] == 2


def test_monitor_can_preserve_legacy_callback_containment_or_propagate() -> None:
    def fail(_state: object) -> None:
        raise RuntimeError("callback failed")

    close = _event("callback-session", "cowrie.session.closed", 0)
    SessionMonitor(on_session_end=fail).on_event(close)
    strict = SessionMonitor(on_session_end=fail, propagate_session_end_errors=True)
    with pytest.raises(RuntimeError, match="callback failed"):
        strict.on_event(close)
