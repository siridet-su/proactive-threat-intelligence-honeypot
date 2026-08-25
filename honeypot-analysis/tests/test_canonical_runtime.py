from __future__ import annotations

import asyncio
import base64
import json
import os
from pathlib import Path

import pytest

from production.reporting.artifacts import (
    _artifact_version_id,
    validate_report_artifact_manifest,
)
from production.reporting.session_assessment_v4 import SessionAssessmentV4Error
from production.storage import StorageError, open_storage
from production.utils.config import ProductionConfig
from production.utils.serialization import stable_json
from production.workers.analysis_worker import (
    AnalysisWorker,
    reconstruct_canonical_session_events,
)
from production.workers.session_monitor import SessionMonitor
from production.workers.session_worker import SessionWorker, alert_payload


class _FailingCoordinator:
    def __init__(self, **_kwargs) -> None:
        pass

    async def analyze(self, *_args, **_kwargs):
        raise RuntimeError("controlled primary analysis failure")


def _config(tmp_path, *, history_limit: int = 3) -> ProductionConfig:
    keyring = tmp_path / "credential-keyring.json"
    keyring.write_text(
        json.dumps(
            {
                "schema_version": "credential_hmac_keyring.v1",
                "active_key_id": "phase7-key",
                "keys": {
                    "phase7-key": base64.b64encode(
                        b"phase7-canonical-runtime-test-key"
                    ).decode("ascii")
                },
                "correlation_key_ids": [],
            }
        ),
        encoding="utf-8",
    )
    os.chmod(keyring, 0o600)
    return ProductionConfig(
        database_url=f"sqlite:///{tmp_path / 'state.db'}",
        worker_batch_size=100,
        session_event_history_limit=history_limit,
        canonical_evidence_max_events=100,
        enable_feed_loading=False,
        enable_securebert=False,
        enable_enrichment_jobs=False,
        enable_session_ttp_correlation=False,
        analysis_skip_empty_sessions=False,
        analysis_max_attempts=1,
        analysis_batch_size=1,
        enable_artifacts=False,
        credential_hmac_keyring_file=str(keyring),
        prediction_policy={"enabled": False},
        calibration_policy={"enabled": False},
        campaign_policy={"enabled": False},
        threat_hunt_policy={"enabled": False},
    )


def _event(session_id: str, index: int, eventid: str, **extra) -> dict:
    return {
        "eventid": eventid,
        "session": session_id,
        "src_ip": "203.0.113.44",
        "timestamp": f"2026-07-29T01:00:{index:02d}Z",
        **extra,
    }


def test_large_session_report_uses_complete_durable_event_manifest(tmp_path) -> None:
    config = _config(tmp_path, history_limit=3)
    storage = open_storage(config.database_url)
    events = [_event("large-session", 0, "cowrie.session.connect")]
    events.extend(
        _event(
            "large-session",
            index,
            "cowrie.command.input",
            input=f"echo phase7-{index}",
            success=1,
        )
        for index in range(1, 11)
    )
    events.append(_event("large-session", 11, "cowrie.session.closed"))
    for event in events:
        storage.store_event("sensor-phase7", event)

    session_worker = SessionWorker(config)
    try:
        assert session_worker.process_unprocessed() == len(events)
    finally:
        session_worker.close()

    job_row = storage.list_rows("analysis_jobs", limit=1)[0]
    job_payload = json.loads(job_row["payload_json"])
    assert len(job_payload["raw_events"]) == config.session_event_history_limit
    assert job_payload["canonical_event_manifest"]["event_count"] == len(events)

    reconstructed = reconstruct_canonical_session_events(
        storage,
        job_payload,
        max_events=config.canonical_evidence_max_events,
    )
    assert len(reconstructed["raw_events"]) == len(events)
    assert reconstructed["raw_events"][-1]["eventid"] == "cowrie.session.closed"

    assert asyncio.run(AnalysisWorker(config).process_once()) == 1
    report = json.loads(storage.list_rows("reports", limit=1)[0]["payload_json"])
    assert report["schema_version"] == "session_assessment.v4"
    assert report["canonical_evidence"]["durable_event_manifest"] == (
        job_payload["canonical_event_manifest"]
    )
    assert report["provenance"]["durable_event_manifest"] == (
        job_payload["canonical_event_manifest"]
    )
    assert len(report["canonical_evidence"]["observations"]) == 10


def test_terminal_fallback_reconstructs_full_durable_session_before_artifacts(
    tmp_path,
) -> None:
    config = _config(tmp_path, history_limit=2)
    config.enable_artifacts = True
    config.reports_dir = str(tmp_path / "reports")
    storage = open_storage(config.database_url)
    events = [_event("fallback-large", 0, "cowrie.session.connect")]
    events.extend(
        _event(
            "fallback-large",
            index,
            "cowrie.command.input",
            input=f"printf fallback-{index}",
            success=1,
        )
        for index in range(1, 9)
    )
    events.append(_event("fallback-large", 9, "cowrie.session.closed"))
    for event in events:
        storage.store_event("sensor-phase7", event)
    session_worker = SessionWorker(config)
    try:
        assert session_worker.process_unprocessed() == len(events)
    finally:
        session_worker.close()

    queued = json.loads(storage.list_rows("analysis_jobs", limit=1)[0]["payload_json"])
    assert len(queued["raw_events"]) == 2
    assert len(queued["commands"]) == 2
    assert queued["canonical_event_manifest"]["event_count"] == len(events)

    assert asyncio.run(
        AnalysisWorker(config).process_once(coordinator_class=_FailingCoordinator)
    ) == 1
    report = json.loads(storage.list_rows("reports", limit=1)[0]["payload_json"])
    assert report["status"] == "observation_only_abstention"
    assert report["behavioral_findings"] == []
    assert report["hypothesis_sets"] == []
    assert report["canonical_evidence"]["durable_event_manifest"] == (
        queued["canonical_event_manifest"]
    )
    assert len(report["canonical_evidence"]["observations"]) == 8
    assert report["provenance"]["durable_event_manifest"] == (
        queued["canonical_event_manifest"]
    )
    assert validate_report_artifact_manifest(
        report["artifacts"]["integrity_manifest"]
    ) == []
    for artifact_path in report["artifacts"].values():
        assert Path(artifact_path).is_file()


def test_manifest_failure_creates_no_report_or_partial_artifact(tmp_path) -> None:
    config = _config(tmp_path)
    config.enable_artifacts = True
    config.reports_dir = str(tmp_path / "reports")
    storage = open_storage(config.database_url)
    events = [
        _event("fallback-mismatch", 0, "cowrie.session.connect"),
        _event(
            "fallback-mismatch",
            1,
            "cowrie.command.input",
            input="id",
            success=1,
        ),
        _event("fallback-mismatch", 2, "cowrie.session.closed"),
    ]
    event_ids = []
    for event in events:
        event_id, _ = storage.store_event("sensor-phase7", event)
        event_ids.append(event_id)
    session_worker = SessionWorker(config)
    try:
        assert session_worker.process_unprocessed() == len(events)
    finally:
        session_worker.close()

    with storage.connection() as connection:
        connection.execute(
            "UPDATE events SET payload_json=? WHERE event_id=?",
            ('{"eventid":"tampered","session":"fallback-mismatch"}', event_ids[1]),
        )

    assert asyncio.run(
        AnalysisWorker(config).process_once(coordinator_class=_FailingCoordinator)
    ) == 0
    assert storage.list_rows("reports") == []
    failed = storage.list_rows("analysis_jobs", limit=1)[0]
    assert failed["status"] == "failed"
    assert failed["last_error_code"] == "job_invalid"
    reports_dir = Path(config.reports_dir)
    assert not reports_dir.exists() or list(reports_dir.iterdir()) == []


def test_temporary_durable_storage_failure_retries_without_partial_report(
    tmp_path,
    monkeypatch,
) -> None:
    config = _config(tmp_path)
    config.analysis_max_attempts = 2
    config.enable_artifacts = True
    config.reports_dir = str(tmp_path / "reports")
    storage = open_storage(config.database_url)
    events = [
        _event("fallback-storage", 0, "cowrie.session.connect"),
        _event(
            "fallback-storage",
            1,
            "cowrie.command.input",
            input="whoami",
            success=1,
        ),
        _event("fallback-storage", 2, "cowrie.session.closed"),
    ]
    for event in events:
        storage.store_event("sensor-phase7", event)
    session_worker = SessionWorker(config)
    try:
        assert session_worker.process_unprocessed() == len(events)
    finally:
        session_worker.close()

    worker = AnalysisWorker(config)
    monkeypatch.setattr(
        worker.storage,
        "load_session_event_snapshot",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            StorageError("temporary database unavailable")
        ),
    )
    assert asyncio.run(
        worker.process_once(coordinator_class=_FailingCoordinator)
    ) == 0
    assert storage.list_rows("reports") == []
    retry = storage.list_rows("analysis_jobs", limit=1)[0]
    assert retry["status"] == "retry"
    assert retry["last_error_code"] == "analysis_failed"
    reports_dir = Path(config.reports_dir)
    assert not reports_dir.exists() or list(reports_dir.iterdir()) == []


def test_missing_durable_watermark_fails_without_report_or_artifacts(
    tmp_path,
) -> None:
    config = _config(tmp_path)
    config.enable_artifacts = True
    config.reports_dir = str(tmp_path / "reports")
    storage = open_storage(config.database_url)
    first = _event(
        "fallback-missing",
        0,
        "cowrie.command.input",
        input="id",
        success=1,
    )
    close = _event("fallback-missing", 1, "cowrie.session.closed")
    storage.store_event("sensor-phase7", first)
    close_id, _ = storage.store_event("sensor-phase7", close)
    snapshot = storage.load_session_event_snapshot(
        "fallback-missing", close_id, max_events=10
    )
    manifest = {
        key: snapshot[key]
        for key in (
            "schema_version",
            "session_id",
            "through_event_id",
            "event_count",
            "manifest_sha256",
        )
    }
    manifest["through_event_id"] = "event_missing_watermark"
    storage.enqueue_analysis_job(
        {
            "session_id": "fallback-missing",
            "commands": ["id"],
            "commands_success": ["id"],
            "commands_failed": [],
            "raw_events": [close],
            "canonical_event_manifest": manifest,
        }
    )

    assert asyncio.run(
        AnalysisWorker(config).process_once(coordinator_class=_FailingCoordinator)
    ) == 0
    assert storage.list_rows("reports") == []
    failed = storage.list_rows("analysis_jobs", limit=1)[0]
    assert failed["status"] == "failed"
    assert failed["last_error_code"] == "analysis_failed"
    reports_dir = Path(config.reports_dir)
    assert not reports_dir.exists() or list(reports_dir.iterdir()) == []


def test_duplicate_and_timestamp_reordered_events_reconstruct_once_in_durable_order(
    tmp_path,
) -> None:
    storage = open_storage(f"sqlite:///{tmp_path / 'ordered.db'}")
    first = _event(
        "durable-order",
        2,
        "cowrie.command.input",
        input="printf received-first",
        success=1,
    )
    second = _event(
        "durable-order",
        1,
        "cowrie.command.input",
        input="printf received-second",
        success=0,
    )
    first_id, first_inserted = storage.store_event("sensor-phase7", first)
    duplicate_id, duplicate_inserted = storage.store_event("sensor-phase7", first)
    second_id, second_inserted = storage.store_event("sensor-phase7", second)
    assert first_inserted is True
    assert duplicate_inserted is False
    assert duplicate_id == first_id
    assert second_inserted is True

    snapshot = storage.load_session_event_snapshot(
        "durable-order", second_id, max_events=10
    )
    assert snapshot["through_received_at"] == snapshot["event_entries"][-1][
        "received_at"
    ]
    assert all(entry["received_at"] for entry in snapshot["event_entries"])
    manifest = {
        key: snapshot[key]
        for key in (
            "schema_version",
            "session_id",
            "through_event_id",
            "event_count",
            "manifest_sha256",
        )
    }
    reconstructed = reconstruct_canonical_session_events(
        storage,
        {
            "session_id": "durable-order",
            "commands": ["bounded-wrong"],
            "commands_success": [],
            "commands_failed": [],
            "raw_events": [second],
            "canonical_event_manifest": manifest,
            "session_evidence_graph": {"graph_id": "bounded-stale"},
        },
        max_events=10,
    )
    assert reconstructed["commands"] == [
        "printf received-first",
        "printf received-second",
    ]
    assert reconstructed["commands_success"] == ["printf received-first"]
    assert reconstructed["commands_failed"] == ["printf received-second"]
    assert reconstructed["session_evidence_graph"] == {}
    assert len(reconstructed["raw_events"]) == 2


def test_reconstruction_exceeds_default_ten_thousand_event_history_bound(
    tmp_path,
) -> None:
    storage = open_storage(f"sqlite:///{tmp_path / 'large-storage.db'}")
    session_id = "large-default-bound"
    event_count = 10_001
    rows = []
    for index in range(event_count):
        event_id = f"large_event_{index:05d}"
        event = {
            "eventid": (
                "cowrie.session.closed"
                if index == event_count - 1
                else "cowrie.command.input"
            ),
            "session": session_id,
            "src_ip": "203.0.113.45",
            "timestamp": f"2026-07-29T02:00:{index % 60:02d}Z",
            "input": f"echo large-{index}",
        }
        rows.append(
            (
                event_id,
                "sensor-phase7",
                session_id,
                event["src_ip"],
                event["eventid"],
                event["timestamp"],
                stable_json(event),
                f"2026-07-29T03:00:00.{index:05d}+00:00",
            )
        )
    with storage.connection() as connection:
        connection.executemany(
            """
            INSERT INTO events
            (event_id, sensor_id, session_id, src_ip, eventid, timestamp,
             payload_json, received_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )

    snapshot = storage.load_session_event_snapshot(
        session_id,
        rows[-1][0],
        max_events=event_count,
    )
    assert snapshot["event_count"] == event_count
    assert len(snapshot["events"]) == event_count
    assert snapshot["events"][-1]["eventid"] == "cowrie.session.closed"
    assert len(snapshot["manifest_sha256"]) == 64

    expected = {
        key: snapshot[key]
        for key in (
            "schema_version",
            "session_id",
            "through_event_id",
            "event_count",
            "manifest_sha256",
        )
    }
    reconstructed = reconstruct_canonical_session_events(
        storage,
        {
            "session_id": session_id,
            "raw_events": snapshot["events"][-10_000:],
            "canonical_event_manifest": expected,
        },
        max_events=event_count,
    )
    assert len(reconstructed["raw_events"]) == event_count
    with pytest.raises(Exception, match="event limit"):
        storage.load_session_event_snapshot(
            session_id,
            rows[-1][0],
            max_events=10_000,
        )


def test_durable_evidence_manifest_mismatch_and_size_excess_fail_closed(
    tmp_path,
) -> None:
    config = _config(tmp_path)
    storage = open_storage(config.database_url)
    first_id, _ = storage.store_event(
        "sensor-phase7", _event("manifest-fail", 0, "cowrie.session.connect")
    )
    second_id, _ = storage.store_event(
        "sensor-phase7", _event("manifest-fail", 1, "cowrie.session.closed")
    )
    snapshot = storage.load_session_event_snapshot(
        "manifest-fail", first_id, max_events=2
    )
    expected = {
        key: snapshot[key]
        for key in (
            "schema_version",
            "session_id",
            "through_event_id",
            "event_count",
            "manifest_sha256",
        )
    }
    with storage.connection() as connection:
        connection.execute(
            "UPDATE events SET payload_json = ? WHERE event_id = ?",
            ('{"eventid":"tampered","session":"manifest-fail"}', first_id),
        )
    with pytest.raises(SessionAssessmentV4Error, match="does not match"):
        reconstruct_canonical_session_events(
            storage,
            {
                "session_id": "manifest-fail",
                "canonical_event_manifest": expected,
            },
            max_events=2,
        )
    with pytest.raises(Exception, match="event limit"):
        storage.load_session_event_snapshot(
            "manifest-fail", second_id, max_events=1
        )


def test_active_runtime_uses_canonical_classifier_and_durable_campaign_only(
    tmp_path,
) -> None:
    config = _config(tmp_path)
    worker = SessionWorker(config)
    try:
        assert worker.monitor.campaign_tracker is None
        classified = worker.classifier.classify("whoami")
        assert classified
        assert all(item["rule_policy_sha256"] for item in classified)
        assert all(item["rule_policy_path"] for item in classified)
    finally:
        worker.close()

    unavailable = SessionMonitor(
        classification_policy={"strategy": "notebook_merge"}
    )._classify_many_with_source("whoami")
    assert unavailable == [
        {
            "command": "whoami",
            "ttp": None,
            "tactic": "unknown",
            "source": "canonical_classifier_unavailable",
            "confidence": 0.0,
            "authority": "audit_only",
        }
    ]


def test_new_alert_report_and_artifact_identities_ignore_runtime_timestamps(
    tmp_path,
) -> None:
    first_alert = {
        "session_id": "identity-session",
        "severity": "HIGH",
        "reason": "observed threshold",
        "alert_key": "observed-rule",
        "timestamp": "2026-07-29T01:00:00Z",
    }
    second_alert = {
        **first_alert,
        "timestamp": "2026-07-29T01:05:00Z",
    }
    assert alert_payload(
        first_alert, triggering_event_id="event-stable"
    )["alert_id"] == alert_payload(
        second_alert, triggering_event_id="event-stable"
    )["alert_id"]

    report_one = {
        "schema_version": "session_assessment.v4",
        "assessment_id": "assessment_stable",
        "generated_at": "2026-07-29T01:00:00Z",
        "provenance": {"evidence_sha256": "a" * 64},
    }
    report_two = {
        **report_one,
        "generated_at": "2026-07-29T02:00:00Z",
    }
    session = {"session_id": "identity-session"}
    assert _artifact_version_id(report_one, session) == _artifact_version_id(
        report_two, session
    )

    report_ids = []
    for name, payload in (("one", report_one), ("two", report_two)):
        storage = open_storage(f"sqlite:///{tmp_path / f'{name}.db'}")
        storage.save_session(
            {
                "session_id": "identity-session",
                "src_ip": "203.0.113.44",
                "is_ended": True,
            }
        )
        job_id = storage.enqueue_analysis_job(
            {"session_id": "identity-session"}
        )
        job = storage.claim_analysis_jobs(name, 1, 60, 1)[0]
        report_ids.append(
            storage.complete_analysis_job(
                job_id,
                name,
                job["claim_token"],
                {**payload, "session_id": "identity-session"},
            )
        )
    assert report_ids[0] == report_ids[1]
