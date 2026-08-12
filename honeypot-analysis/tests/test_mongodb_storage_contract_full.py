from __future__ import annotations

import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor

import pytest

from production.prediction.evidence_cutoff import make_evidence_cutoff
from production.prediction.prediction_snapshot_contract import (
    PredictionSnapshotIntegrityError,
    finalize_prediction_snapshot,
)
from production.storage import (
    CanonicalEventRecord,
    MongoDBStorageBackend,
    StorageBackend,
    StorageError,
    install_mongodb_schema,
)


NOW = "2026-08-12T01:00:00.000000+00:00"


@pytest.fixture()
def full_mongo():
    uri = os.getenv("MONGODB_TEST_URI", "")
    if not uri:
        pytest.skip("MONGODB_TEST_URI is not configured for an isolated replica set")
    pymongo = pytest.importorskip("pymongo")
    client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=5_000)
    client.admin.command("ping")
    client.drop_database("honeypot_canonical_v1")
    install_mongodb_schema(client)
    storage = MongoDBStorageBackend(client=client)
    storage.initialize()
    try:
        yield storage
    finally:
        client.drop_database("honeypot_canonical_v1")
        client.close()


def _record(index: int = 0) -> CanonicalEventRecord:
    return CanonicalEventRecord.create(
        "sensor-a",
        {
            "eventid": "cowrie.command.input",
            "session": "sensor-a:session-a",
            "src_ip": "192.0.2.10",
            "timestamp": f"2026-08-12T00:00:0{index}Z",
            "input": "id",
        },
        received_at=f"2026-08-12T00:01:0{index}Z",
    )


def test_formal_contract_has_no_missing_or_placeholder_mongodb_method() -> None:
    required = {
        name
        for name, value in StorageBackend.__dict__.items()
        if callable(value) and not name.startswith("_")
    }
    missing = [name for name in required if not callable(getattr(MongoDBStorageBackend, name, None))]
    assert missing == []
    assert not any(
        "NotImplemented" in str(getattr(MongoDBStorageBackend, name))
        for name in required
    )


def test_event_claim_retry_fencing_and_completion(full_mongo) -> None:
    record = _record()
    full_mongo.store_canonical_event(record)
    claim = full_mongo.claim_events("worker-a", 1, 30, 3, now=NOW)[0]
    assert claim["event_id"] == record.event_id
    assert not full_mongo.complete_event(
        record.event_id, "worker-a", str(__import__("uuid").uuid4()), now=NOW
    )
    assert full_mongo.fail_event(
        record.event_id,
        "worker-a",
        claim["claim_token"],
        "temporary_failure",
        "TimeoutError",
        True,
        3,
        1,
        now=NOW,
    ) == "retry_scheduled"
    second = full_mongo.claim_events(
        "worker-b", 1, 30, 3, now="2026-08-12T01:00:02Z"
    )[0]
    assert full_mongo.complete_event(
        record.event_id,
        "worker-b",
        second["claim_token"],
        {"event_applied": True},
        now="2026-08-12T01:00:03Z",
    )
    assert full_mongo.get_event(record.event_id)["processed"] is True


def test_event_claim_preserves_per_session_head_of_line(full_mongo) -> None:
    first = _record(0)
    second = _record(1)
    other = CanonicalEventRecord.create(
        "sensor-b",
        {
            "eventid": "cowrie.command.input",
            "session": "sensor-b:session-a",
            "input": "whoami",
        },
        received_at="2026-08-12T00:01:00Z",
    )
    for record in (second, other, first):
        full_mongo.store_canonical_event(record)

    claimed = full_mongo.claim_events("worker-a", 3, 30, 3, now=NOW)
    assert {item["event_id"] for item in claimed} == {first.event_id, other.event_id}
    assert second.event_id not in {item["event_id"] for item in claimed}
    first_claim = next(item for item in claimed if item["event_id"] == first.event_id)
    assert full_mongo.complete_event(
        first.event_id, "worker-a", first_claim["claim_token"], now=NOW
    )
    next_claim = full_mongo.claim_events("worker-b", 1, 30, 3, now=NOW)
    assert [item["event_id"] for item in next_claim] == [second.event_id]


def test_event_terminal_failure_matches_sqlite_dead_letter_state(full_mongo) -> None:
    record = _record()
    full_mongo.store_canonical_event(record)
    claim = full_mongo.claim_events("worker-a", 1, 30, 1, now=NOW)[0]
    assert full_mongo.fail_event(
        record.event_id,
        "worker-a",
        claim["claim_token"],
        "event_processing_failed",
        "StorageError",
        False,
        1,
        0,
        now=NOW,
    ) == "dead_letter"
    failed = full_mongo.list_failed_events()
    assert [item["event_id"] for item in failed] == [record.event_id]
    assert failed[0]["processing_outcome"] == "dead_letter"


def test_duplicate_identity_binds_received_at_and_concurrent_exact_insert(full_mongo) -> None:
    record = _record()
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _index: full_mongo.store_canonical_event(record), range(8)))
    assert sum(inserted for _identity, inserted in results) == 1
    changed_order = CanonicalEventRecord.create(
        record.sensor_id,
        record.event,
        received_at="2026-08-12T00:02:00Z",
    )
    assert changed_order.event_id == record.event_id
    with pytest.raises(StorageError, match="conflicting duplicate"):
        full_mongo.store_canonical_event(changed_order)


def test_durable_prefix_limit_and_sensor_aware_session_identity(full_mongo) -> None:
    records = [_record(index) for index in range(3)]
    cross_sensor = CanonicalEventRecord.create(
        "sensor-b",
        {"eventid": "cowrie.command.input", "session": "sensor-b:session-a", "input": "id"},
        received_at="2026-08-12T00:01:00Z",
    )
    for record in (*records, cross_sensor):
        full_mongo.store_canonical_event(record)
    exact = full_mongo.load_session_event_snapshot(
        "sensor-a:session-a", records[-1].event_id, len(records)
    )
    assert exact["event_count"] == len(records)
    with pytest.raises(StorageError, match="exceeds configured event limit"):
        full_mongo.load_session_event_snapshot(
            "sensor-a:session-a", records[-1].event_id, len(records) - 1
        )
    assert full_mongo.load_session_event_snapshot(
        "sensor-b:session-a", cross_sensor.event_id, 1
    )["event_count"] == 1


def test_leader_lease_is_bound_to_claim_owner_and_active_claim(full_mongo) -> None:
    leader_token = "11111111-1111-4111-8111-111111111111"
    replacement_token = "22222222-2222-4222-8222-222222222222"
    assert full_mongo.acquire_worker_lease(
        "events", "worker-a", leader_token, 60, now=NOW
    )
    record = _record()
    full_mongo.store_canonical_event(record)
    claim = full_mongo.claim_events(
        "worker-a",
        1,
        30,
        3,
        now=NOW,
        leader_scope="events",
        leader_token=leader_token,
    )[0]
    assert not full_mongo.complete_event(
        record.event_id,
        "worker-b",
        claim["claim_token"],
        now=NOW,
        leader_scope="events",
        leader_token=leader_token,
    )
    full_mongo.database.worker_leases.update_one(
        {"_id": "events"},
        {"$set": {"expires_at": "2026-08-12T01:00:01.000000+00:00"}},
    )
    assert not full_mongo.acquire_worker_lease(
        "events",
        "worker-b",
        replacement_token,
        60,
        now="2026-08-12T01:00:02Z",
    )


def test_simultaneous_analysis_claim_is_single_owner(full_mongo) -> None:
    job_id = full_mongo.enqueue_analysis_job({"session_id": "sensor-a:session-a"})
    with ThreadPoolExecutor(max_workers=8) as pool:
        claimed = list(
            pool.map(
                lambda index: full_mongo.claim_analysis_jobs(
                    f"owner-{index}", 1, 30, 3, now=NOW
                ),
                range(8),
            )
        )
    rows = [row for batch in claimed for row in batch]
    assert len(rows) == 1
    assert rows[0]["job_id"] == job_id


def test_simultaneous_deterministic_auxiliary_enqueues_are_idempotent(full_mongo) -> None:
    with ThreadPoolExecutor(max_workers=8) as pool:
        enrichment = list(
            pool.map(
                lambda _: full_mongo.enqueue_enrichment_job(
                    "ip", "192.0.2.44", "sensor-a:session-a"
                ),
                range(8),
            )
        )
    assert len({job_id for job_id, _queued in enrichment}) == 1
    assert full_mongo.database.enrichment_jobs.count_documents({}) == 1

    with ThreadPoolExecutor(max_workers=8) as pool:
        hunts = list(
            pool.map(
                lambda _: full_mongo.enqueue_threat_hunt_job(
                    "sensor-a:session-a", "ip", "192.0.2.44"
                ),
                range(8),
            )
        )
    assert len({job_id for job_id, _queued in hunts}) == 1
    assert full_mongo.database.threat_hunt_jobs.count_documents({}) == 1


def test_analysis_publication_is_atomic_and_abort_leaves_no_partial_state(
    full_mongo, monkeypatch: pytest.MonkeyPatch
) -> None:
    full_mongo.save_session({"session_id": "sensor-a:session-a", "src_ip": "192.0.2.10"})
    job_id = full_mongo.enqueue_analysis_job({"session_id": "sensor-a:session-a"})
    claim = full_mongo.claim_analysis_jobs("analysis-a", 1, 60, 3, now=NOW)[0]
    report = {"schema_version": "legacy-report.v1", "session_id": "sensor-a:session-a", "findings": []}
    original = full_mongo._exact_insert

    def abort_after_report(collection, identity, document, **kwargs):
        inserted = original(collection, identity, document, **kwargs)
        if collection == "reports":
            raise RuntimeError("injected transaction abort")
        return inserted

    monkeypatch.setattr(full_mongo, "_exact_insert", abort_after_report)
    with pytest.raises(RuntimeError, match="injected transaction abort"):
        full_mongo.complete_analysis_job(
            job_id, "analysis-a", claim["claim_token"], report, now="2026-08-12T01:00:01Z"
        )
    assert full_mongo.database.reports.count_documents({}) == 0
    assert full_mongo.database.analysis_jobs.find_one({"_id": job_id})["status"] == "running"
    assert "report_id" not in full_mongo.get_session("sensor-a:session-a")["payload"]
    monkeypatch.setattr(full_mongo, "_exact_insert", original)
    report_id = full_mongo.complete_analysis_job(
        job_id, "analysis-a", claim["claim_token"], report, now="2026-08-12T01:00:01Z"
    )
    assert report_id
    assert full_mongo.get_report_by_id(report_id)["payload"] == report
    assert full_mongo.get_session("sensor-a:session-a")["payload"]["report_id"] == report_id


def test_ai_outbox_failure_cannot_rollback_deterministic_report(full_mongo, monkeypatch) -> None:
    record = _record(); full_mongo.store_canonical_event(record)
    full_mongo.save_session({"session_id": "sensor-a:session-a", "src_ip": "192.0.2.10"})
    job_id = full_mongo.enqueue_analysis_job({"session_id": "sensor-a:session-a"})
    claim = full_mongo.claim_analysis_jobs("analysis-a", 1, 60, 3, now=NOW)[0]
    report = {"schema_version": "session_assessment.v4", "assessment_id": "assessment-a", "session_id": "sensor-a:session-a", "canonical_evidence": {"session_id": "sensor-a:session-a"}}
    monkeypatch.setattr(full_mongo, "enqueue_ai_advisory_job", lambda *args, **kwargs: (_ for _ in ()).throw(ConnectionError("optional AI unavailable")))
    report_id = full_mongo.complete_analysis_job(job_id, "analysis-a", claim["claim_token"], report, enqueue_ai_advisory=True, ai_advisory_reconciliation_cutoff={"schema_version": "prediction_evidence_cutoff.v1", "received_at": "2026-08-11T00:00:00.000000+00:00", "event_id": "cutoff"}, now="2026-08-12T01:00:01Z")
    assert report_id
    assert full_mongo.get_report_by_id(report_id)["payload"] == report
    assert full_mongo.database.ai_advisory_outbox.count_documents({}) == 0


def test_ai_advisory_outbox_and_persistence_are_idempotent(full_mongo) -> None:
    record = _record(); full_mongo.store_canonical_event(record)
    full_mongo.save_session({"session_id": "sensor-a:session-a", "src_ip": "192.0.2.10"})
    job_id = full_mongo.enqueue_analysis_job({"session_id": "sensor-a:session-a"})
    claim = full_mongo.claim_analysis_jobs("analysis-a", 1, 60, 3, now=NOW)[0]
    report = {"schema_version": "session_assessment.v4", "assessment_id": "assessment-a", "session_id": "sensor-a:session-a", "canonical_evidence": {"session_id": "sensor-a:session-a"}}
    report_id = full_mongo.complete_analysis_job(job_id, "analysis-a", claim["claim_token"], report, now="2026-08-12T01:00:01Z")
    cutoff = {"schema_version": "prediction_evidence_cutoff.v1", "received_at": "2026-08-11T00:00:00.000000+00:00", "event_id": "cutoff"}
    ai_job = full_mongo.enqueue_ai_advisory_job(report_id, "sensor-a:session-a", "assessment-a", reconciliation_cutoff=cutoff)
    assert full_mongo.enqueue_ai_advisory_job(report_id, "sensor-a:session-a", "assessment-a", reconciliation_cutoff=cutoff) == ai_job
    claimed = full_mongo.claim_ai_advisory_jobs("ai-a", 1, 60, 3, now="2026-08-12T01:00:02Z")[0]
    record = {"advisory_id": "advisory-a", "cache_key": "cache-a", "report_id": report_id, "session_id": "sensor-a:session-a", "assessment_id": "assessment-a", "status": "accepted", "projection_sha256": "1" * 64, "request_sha256": "2" * 64, "response_sha256": "3" * 64, "provider_id": "fixture", "model_id": "fixture-model", "prompt_sha256": "4" * 64, "schema_sha256": "5" * 64, "policy_sha256": "6" * 64, "payload": {"authority": "non_authoritative"}, "metrics": {"latency_ms": 1}}
    assert full_mongo.complete_ai_advisory_job(ai_job, "ai-a", claimed["claim_token"], record, now="2026-08-12T01:00:03Z") == "advisory-a"
    assert full_mongo.get_ai_advisory_for_report(report_id, "assessment-a")["payload"]["authority"] == "non_authoritative"


def test_ai_reconciliation_cursor_advances_without_first_page_starvation(
    full_mongo,
) -> None:
    cutoff = {
        "schema_version": "prediction_evidence_cutoff.v1",
        "received_at": "2026-08-11T00:00:00.000000+00:00",
        "event_id": "cutoff",
    }
    for index in range(3):
        session_id = f"sensor-a:reconcile-{index}"
        record = CanonicalEventRecord.create(
            "sensor-a",
            {
                "eventid": "cowrie.command.input",
                "session": session_id,
                "input": "id",
            },
            received_at=f"2026-08-12T00:0{index}:00Z",
        )
        full_mongo.store_canonical_event(record)
        report_id = f"report-{index}"
        assessment_id = f"assessment-{index}"
        payload = {
            "schema_version": "session_assessment.v4",
            "assessment_id": assessment_id,
            "session_id": session_id,
        }
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        full_mongo.database.reports.insert_one(
            {
                "_id": report_id,
                "schema_version": "mongodb_report.v1",
                "report_id": report_id,
                "session_id": session_id,
                "assessment_id": assessment_id,
                "payload_json": payload_json,
                "payload_sha256": hashlib.sha256(payload_json.encode()).hexdigest(),
                "created_at": f"2026-08-12T01:0{index}:00.000000+00:00",
            }
        )

    results = [
        full_mongo.reconcile_ai_advisory_outbox(
            reconciliation_cutoff=cutoff, limit=1
        )
        for _ in range(4)
    ]
    assert results == [
        {"scanned": 1, "enqueued": 1, "ineligible": 0},
        {"scanned": 1, "enqueued": 1, "ineligible": 0},
        {"scanned": 1, "enqueued": 1, "ineligible": 0},
        {"scanned": 0, "enqueued": 0, "ineligible": 0},
    ]
    assert full_mongo.database.ai_advisory_outbox.count_documents({}) == 3

    cursor = full_mongo.database.reconciliation_cursors.find_one({})
    full_mongo.database.reconciliation_cursors.update_one(
        {"_id": cursor["_id"]}, {"$set": {"payload_sha256": "0" * 64}}
    )
    with pytest.raises(StorageError, match="cursor hash mismatch"):
        full_mongo.reconcile_ai_advisory_outbox(
            reconciliation_cutoff=cutoff, limit=1
        )


def test_prediction_outbox_snapshot_integrity_and_lifecycle(full_mongo) -> None:
    task = {"event_id": "event-p", "session_id": "sensor-a:session-a", "prediction_mode": "transformer_poc"}
    outbox_id = full_mongo.enqueue_prediction_outbox(task)
    claim = full_mongo.claim_prediction_outbox("prediction-a", 1, 30, 3, now=NOW)[0]
    snapshot = finalize_prediction_snapshot(
        {
            "schema_version": "prediction_snapshot.v3",
            "session_id": "sensor-a:session-a",
            "event_id": "event-p",
            "session_status": "active",
            "generated_at": "2026-08-12T01:00:01Z",
            "prediction_status": "predicted",
            "prediction": ["discovery"],
            "evidence_cutoff": make_evidence_cutoff("2026-08-12T01:00:00Z", "event-p"),
            "runtime": {"model_load_time_ms": 1.0, "inference_latency_ms": 2.0},
        }
    )
    snapshot_id = full_mongo.save_prediction_snapshot(snapshot)
    assert full_mongo.save_prediction_snapshot(dict(snapshot)) == snapshot_id
    changed = json.loads(json.dumps(snapshot)); changed["prediction"] = ["execution"]
    with pytest.raises(PredictionSnapshotIntegrityError):
        full_mongo.save_prediction_snapshot(changed)
    assert full_mongo.complete_prediction_outbox(outbox_id, "prediction-a", claim["claim_token"], snapshot_id, now="2026-08-12T01:00:02Z")
    assert full_mongo.get_current_prediction_snapshot("sensor-a:session-a")["snapshot_id"] == snapshot_id
    assert full_mongo.record_data_lifecycle_policy(policy_id="retention", policy_version="v1", policy_sha256="a" * 64, effective_path="configs/data.json")
    assert not full_mongo.record_data_lifecycle_policy(policy_id="retention", policy_version="v1", policy_sha256="a" * 64, effective_path="configs/data.json")


def test_enrichment_hunt_observable_campaign_feedback_and_webhook(full_mongo) -> None:
    job_id, queued = full_mongo.enqueue_enrichment_job("ip", "192.0.2.10", "sensor-a:session-a")
    assert queued
    claim = full_mongo.claim_enrichment_jobs("enrich-a", 1, 30, 3, now=NOW)[0]
    full_mongo.save_enrichment_record("ip", "192.0.2.10", {"asn": 64500}, {"provider": "fixture"}, "2026-08-13T00:00:00Z")
    assert full_mongo.complete_enrichment_job(job_id, "enrich-a", claim["claim_token"], now="2026-08-12T01:00:01Z")
    sighting_id = full_mongo.record_observable_sighting({"observable_type": "ip", "observable_value": "192.0.2.10", "session_id": "sensor-a:session-a", "event_id": "event-a"})
    assert sighting_id
    hunt_id, _ = full_mongo.enqueue_threat_hunt_job("sensor-a:session-a", "ip", "192.0.2.10")
    hunt = full_mongo.claim_threat_hunt_jobs("hunt-a", 1, 30, 3, now=NOW)[0]
    assert full_mongo.complete_threat_hunt_job(hunt_id, "hunt-a", hunt["claim_token"], {"matches": 1}, now="2026-08-12T01:00:01Z")
    campaign_id = full_mongo.save_campaign({"campaign_id": "campaign-a", "hassh_fingerprint": "hash-a"})
    assert full_mongo.find_matching_campaigns({"hassh_fingerprint": "hash-a"})[0]["campaign_id"] == campaign_id
    full_mongo.link_campaign_session(campaign_id, "sensor-a:session-a", ["hassh"], 1.0)
    assert full_mongo.count_campaign_sessions(campaign_id) == 1
    assert full_mongo.record_classification_review_label({"session_id": "sensor-a:session-a", "label": "reviewed"})
    alert_id = full_mongo.store_alert({"session_id": "sensor-a:session-a", "severity": "low"})
    delivery = full_mongo.claim_webhook_delivery({"alert_id": alert_id}, "b" * 64, "webhook-a", 30, 3, alert_id=alert_id, now=NOW)
    assert delivery
    assert full_mongo.complete_webhook_delivery(delivery["delivery_id"], "webhook-a", delivery["claim_token"], "delivered", response_status=204, now="2026-08-12T01:00:01Z")


def test_manifest_validator_rejects_sensitive_top_level_container(full_mongo) -> None:
    from pymongo.errors import WriteError

    with pytest.raises(WriteError):
        full_mongo.database.events.insert_one(
            {
                "_id": "bad",
                "schema_version": "mongodb_canonical_event.v1",
                "event_id": "bad",
                "sensor_id": "sensor-a",
                "session_id": "sensor-a:bad",
                "received_at": NOW,
                "payload_json": "{}",
                "payload_sha256": "0" * 64,
                "processed": False,
                "attempts": 0,
                "password": "must-not-persist",
            }
        )
