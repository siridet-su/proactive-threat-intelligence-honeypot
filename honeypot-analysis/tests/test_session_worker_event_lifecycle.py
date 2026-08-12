from __future__ import annotations

import base64
import asyncio
import json
import os
import sqlite3
import threading
from pathlib import Path

import pytest

from production.storage import open_storage
from production.utils.config import ProductionConfig
from production.workers.session_monitor import SessionMonitor, SessionState
from production.workers.analysis_worker import AnalysisWorker
from production.workers.session_worker import SessionWorker, WorkerError


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
        analysis_skip_empty_sessions=False,
        credential_hmac_keyring_file=str(keyring),
        prediction_policy={"enabled": False},
        calibration_policy={"enabled": False},
        campaign_policy={"enabled": False},
        threat_hunt_policy={"enabled": False},
        reports_dir=str(tmp_path / "reports"),
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


def test_prediction_snapshot_never_persists_response_guidance_or_creates_alert(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The forecast persistence path cannot become a guidance authority."""

    class _Predictor:
        enabled = True

        def predict(self, _features: object, *, event_id: str = "") -> dict:
            return {
                "snapshot_id": "guidance-free-snapshot",
                "session_id": "guidance-free-session",
                "src_ip": "203.0.113.27",
                "event_id": event_id,
                "prediction": ["execution"],
                "final_ranking": [{"tactic": "execution", "score": 0.9}],
            }

    worker = SessionWorker(_config(tmp_path))
    worker.prediction_engine = _Predictor()
    monkeypatch.setattr(worker, "_apply_campaign_clustering", lambda *_args, **_kwargs: {})
    state = SessionState(
        session_id="guidance-free-session",
        src_ip="203.0.113.27",
        start_time="2026-07-27T00:00:00Z",
        commands=["whoami"],
    )
    try:
        assert worker._save_prediction_snapshot_unobserved(
            state,
            {"eventid": "cowrie.command.input", "input": "whoami"},
            event_id="event-guidance-free",
            evidence_cutoff={
                "schema_version": "prediction_evidence_cutoff.v1",
                "received_at": "2026-07-27T00:00:01.000000+00:00",
                "event_id": "event-guidance-free",
            },
        )
        saved = worker.storage.get_latest_prediction_snapshot("guidance-free-session")
        assert saved is not None
        payload = saved["payload"]
        assert "response_guidance" not in payload
        assert "response_guidance_v3" not in payload
        assert "smb_decision" not in payload
        assert "recommended_actions" not in payload
        assert payload["predictive_alert"]["status"] == "prohibited"
        assert worker.storage.list_rows("alerts", limit=20) == []
    finally:
        worker.close()


def test_invalid_v3_prediction_is_rejected_and_recorded_in_outbox(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _InvalidPredictor:
        enabled = True

        def predict(self, _features: object, *, event_id: str = "") -> dict:
            return {
                "schema_version": "prediction_snapshot.v3",
                "snapshot_id": "prediction_corrupt",
                "snapshot_sha256": "0" * 64,
                "session_id": "integrity-session",
                "session_status": "active",
                "event_id": event_id,
                "prediction_status": "predicted",
                "prediction": ["execution"],
            }

    worker = SessionWorker(_config(tmp_path))
    worker.prediction_engine = _InvalidPredictor()
    monkeypatch.setattr(
        worker,
        "_apply_campaign_clustering",
        lambda *_args, **_kwargs: {},
    )
    state = SessionState(
        session_id="integrity-session",
        src_ip="203.0.113.27",
        start_time="2026-07-27T00:00:00Z",
        commands=["whoami"],
    )
    try:
        assert worker._save_prediction_snapshot_unobserved(
            state,
            {"eventid": "cowrie.command.input", "input": "whoami"},
            event_id="event-integrity",
            evidence_cutoff={
                "schema_version": "prediction_evidence_cutoff.v1",
                "received_at": "2026-07-27T00:00:01.000000+00:00",
                "event_id": "event-integrity",
            },
        )
        row = worker.storage.list_rows("prediction_outbox", limit=1)[0]
        assert row["status"] == "dead_letter"
        assert row["last_error_code"] == "prediction_snapshot_integrity_error"
        assert worker.storage.list_rows("prediction_snapshots", limit=1) == []
    finally:
        worker.close()


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


class _RecoveryCoordinator:
    def __init__(self, **_kwargs: object) -> None:
        pass

    async def analyze(self, _ioc_bundle: object, _tactic_summary: object, sessions: object, **kwargs: object) -> dict:
        from production.reporting.session_assessment_v4 import (
            build_session_assessment_v4,
        )

        return build_session_assessment_v4(
            sessions,
            raw_events=kwargs.get("raw_events", []),
        )


def test_active_session_restart_preserves_ordered_analysis_and_prediction_history(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    config.prediction_policy = ProductionConfig().prediction_policy
    storage = open_storage(config.database_url)
    events = [
        _event("session-restart", "cowrie.session.connect", 0),
        _event(
            "session-restart",
            "cowrie.login.success",
            1,
            username="root",
            password="fixture-only-password",
        ),
        _event(
            "session-restart",
            "cowrie.command.input",
            2,
            input="whoami",
            success=1,
        ),
    ]
    first_event_ids = [storage.store_event("sensor-a", event)[0] for event in events]
    first = SessionWorker(config)
    try:
        assert first.process_unprocessed() == 3
        before = first.monitor.get_session("session-restart")
        assert before is not None
        assert before.commands == ["whoami"]
    finally:
        first.close()

    second_command_id, _ = storage.store_event(
        "sensor-a",
        _event(
            "session-restart",
            "cowrie.command.input",
            3,
            input="cat /etc/passwd",
            success=1,
        ),
    )
    close_id, _ = storage.store_event(
        "sensor-a",
        _event("session-restart", "cowrie.session.closed", 4, duration=12.0),
    )
    restarted = SessionWorker(config)
    try:
        assert restarted._ensure_leadership()
        recovered = restarted.monitor.get_session("session-restart")
        assert recovered is not None
        assert recovered.commands == ["whoami"]
        assert len(restarted._session_prediction_snapshots["session-restart"]) == 2
        assert restarted.process_unprocessed() == 2
    finally:
        restarted.close()

    final_payload = storage.get_session("session-restart")["payload"]
    assert final_payload["is_ended"] is True
    assert final_payload["last_applied_event_id"] == close_id
    assert final_payload["commands"] == ["whoami", "cat /etc/passwd"]
    assert len(final_payload["raw_events"]) == 5
    assert len(final_payload["classification_events"]) >= 2
    assert all(
        event.get("durable_evidence_order", {}).get("event_id")
        for event in final_payload["classification_events"]
    )
    trusted_ttps = {
        event.get("ttp")
        for event in final_payload["classification_events"]
        if event.get("evidence_tier") == "trusted_observation"
    }
    assert {"T1033", "T1087.001"} <= trusted_ttps

    snapshots = storage.list_rows_for_session(
        "prediction_snapshots",
        "session-restart",
        limit=20,
    )
    snapshot_event_ids = {row["event_id"] for row in snapshots}
    assert first_event_ids[1] in snapshot_event_ids
    assert first_event_ids[2] in snapshot_event_ids
    assert second_command_id in snapshot_event_ids
    assert close_id in snapshot_event_ids
    for row in snapshots:
        snapshot_payload = json.loads(row["payload_json"])
        cutoff = snapshot_payload["evidence_cutoff"]
        assert cutoff["event_id"] == row["event_id"]

    prediction_tasks = storage.list_rows("prediction_outbox", limit=20)
    assert prediction_tasks
    for row in prediction_tasks:
        task = json.loads(row["payload_json"])
        assert task["schema_version"] == "prediction_outbox_task.v2"
        assert task["evidence_cutoff"]["event_id"] == task["event_id"]

    jobs = storage.list_rows("analysis_jobs", limit=10)
    assert len(jobs) == 1
    queued_payload = json.loads(jobs[0]["payload_json"])
    assert queued_payload["commands"] == ["whoami", "cat /etc/passwd"]
    assert queued_payload["last_applied_event_id"] == close_id

    assert asyncio.run(
        AnalysisWorker(config).process_once(coordinator_class=_RecoveryCoordinator)
    ) == 1
    report = json.loads(storage.list_rows("reports", limit=1)[0]["payload_json"])
    assert report["session_id"] == "session-restart"
    assert report["schema_version"] == "session_assessment.v4"
    assert report["canonical_evidence"]["source_evidence_sha256"]


def test_restart_after_durable_session_save_does_not_reapply_event(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path, batch_size=1)
    storage = open_storage(config.database_url)
    event_id, _ = storage.store_event(
        "sensor-a",
        _event(
            "session-complete-crash",
            "cowrie.command.input",
            0,
            input="whoami",
            success=1,
        ),
    )
    crashed = SessionWorker(config)
    original_complete = crashed.storage.complete_event
    calls = 0

    def lose_completion_once(*args: object, **kwargs: object) -> bool:
        nonlocal calls
        calls += 1
        if calls == 1:
            return False
        return original_complete(*args, **kwargs)

    monkeypatch.setattr(crashed.storage, "complete_event", lose_completion_once)
    try:
        assert crashed.process_unprocessed() == 0
        durable = storage.get_session("session-complete-crash")["payload"]
        assert durable["last_applied_event_id"] == event_id
        assert durable["commands"] == ["whoami"]
    finally:
        crashed.close()

    database_path = Path(config.database_url.removeprefix("sqlite:///"))
    with sqlite3.connect(database_path) as conn:
        conn.execute(
            "UPDATE events SET next_retry_at = '2000-01-01T00:00:00+00:00' "
            "WHERE event_id = ?",
            (event_id,),
        )

    recovered = SessionWorker(config)
    try:
        assert recovered.process_unprocessed() == 1
        state = recovered.monitor.get_session("session-complete-crash")
        assert state is not None
        assert state.commands == ["whoami"]
        assert len(state.raw_events) == 1
    finally:
        recovered.close()
    assert _event_row(storage, event_id)["attempts"] == 2


def test_restart_resumes_already_persisted_close_without_duplicate_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    storage = open_storage(config.database_url)
    storage.store_event("sensor-a", _event("session-close-crash", "cowrie.session.connect", 0))
    storage.store_event(
        "sensor-a",
        _event(
            "session-close-crash",
            "cowrie.command.input",
            1,
            input="id",
            success=1,
        ),
    )
    crashed = SessionWorker(config)
    assert crashed.process_unprocessed() == 2
    close_id, _ = storage.store_event(
        "sensor-a",
        _event("session-close-crash", "cowrie.session.closed", 2, duration=3.0),
    )
    crashed.config.worker_batch_size = 1
    original_complete = crashed.storage.complete_event

    def lose_close_completion(*args: object, **kwargs: object) -> bool:
        if args[0] == close_id:
            return False
        return original_complete(*args, **kwargs)

    monkeypatch.setattr(crashed.storage, "complete_event", lose_close_completion)
    try:
        assert crashed.process_unprocessed() == 0
        persisted = storage.get_session("session-close-crash")["payload"]
        assert persisted["is_ended"] is True
        assert persisted["last_applied_event_id"] == close_id
        assert len(persisted["raw_events"]) == 3
    finally:
        crashed.close()

    database_path = Path(config.database_url.removeprefix("sqlite:///"))
    with sqlite3.connect(database_path) as conn:
        conn.execute(
            "UPDATE events SET next_retry_at = '2000-01-01T00:00:00+00:00' "
            "WHERE event_id = ?",
            (close_id,),
        )

    resumed = SessionWorker(config)
    try:
        assert resumed.process_unprocessed() == 1
    finally:
        resumed.close()
    final_payload = storage.get_session("session-close-crash")["payload"]
    assert final_payload["commands"] == ["id"]
    assert len(final_payload["raw_events"]) == 3
    assert len(storage.list_rows("analysis_jobs", limit=10)) == 1
    assert _event_row(storage, close_id)["attempts"] == 2


def test_active_session_recovery_limit_fails_closed_and_releases_leadership(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    storage = open_storage(config.database_url)
    for session_id in ("active-one", "active-two"):
        storage.save_session(
            {
                "session_id": session_id,
                "src_ip": "203.0.113.27",
                "start_time": "2026-07-18T02:00:00Z",
                "is_ended": False,
                "session_source": "production_live",
            }
        )
    config.active_session_recovery_limit = 1
    worker = SessionWorker(config)
    with pytest.raises(WorkerError, match="recovery limit exceeded"):
        worker.process_unprocessed()
    assert worker._leader_held is False


def test_legacy_rebuild_flag_only_loads_snapshots_and_never_marks_events(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    storage = open_storage(config.database_url)
    storage.save_session(
        {
            "session_id": "active-rebuild",
            "src_ip": "203.0.113.27",
            "start_time": "2026-07-18T02:00:00Z",
            "is_ended": False,
            "session_source": "production_live",
            "commands": ["whoami"],
            "raw_events": [_event("active-rebuild", "cowrie.command.input", 0)],
        }
    )
    queued_id, _ = storage.store_event(
        "sensor-a",
        _event("active-rebuild", "cowrie.command.input", 1, input="id", success=1),
    )
    worker = SessionWorker(config)
    try:
        assert worker.rebuild_from_events() == 1
        recovered = worker.monitor.get_session("active-rebuild")
        assert recovered is not None
        assert recovered.commands == ["whoami"]
        queued = _event_row(storage, queued_id)
        assert queued["processed"] == 0
        assert queued["attempts"] == 0
        assert queued["claim_token"] is None
    finally:
        worker.close()
