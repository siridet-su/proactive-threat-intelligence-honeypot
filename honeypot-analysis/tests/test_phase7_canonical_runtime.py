from __future__ import annotations

import asyncio
import base64
import json
import os

import pytest

from production.reporting.artifacts import _artifact_version_id
from production.reporting.session_assessment_v4 import SessionAssessmentV4Error
from production.storage import open_storage
from production.utils.config import ProductionConfig
from production.workers.analysis_worker import (
    AnalysisWorker,
    reconstruct_canonical_session_events,
)
from production.workers.session_monitor import SessionMonitor
from production.workers.session_worker import SessionWorker, alert_payload


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
