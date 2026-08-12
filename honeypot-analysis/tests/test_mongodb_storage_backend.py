from __future__ import annotations

import os
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from production.storage import (
    CanonicalEventRecord,
    MongoDBStorageBackend,
    StorageError,
    load_mongodb_runtime_identity,
    load_mongodb_schema_manifest,
    open_storage,
)
from tests.mongodb_test_support import (
    cleanup_canonical_test_database,
    prepare_canonical_test_database,
)


def _event(session_id: str, command: str, timestamp: str) -> dict:
    return {
        "eventid": "cowrie.command.input",
        "session": session_id,
        "src_ip": "192.0.2.10",
        "timestamp": timestamp,
        "input": command,
    }


def test_mongodb_manifest_freezes_namespace_order_durability_and_no_ttl() -> None:
    manifest = load_mongodb_schema_manifest()

    assert manifest.database == "honeypot_canonical_v1"
    assert manifest.document["canonical_event_order"] == ["received_at", "event_id"]
    assert manifest.document["write_concern"] == {"w": "majority", "j": True}
    assert manifest.document["read_concern"] == "majority"
    assert len(manifest.collections) >= 25
    assert all(
        collection["canonical_key"] in collection["required_fields"]
        for collection in manifest.collections
    )
    assert all(
        "expireAfterSeconds" not in index
        for collection in manifest.collections
        for index in collection["indexes"]
    )


def test_mongodb_runtime_identity_is_exact_and_least_privilege() -> None:
    identity = json.loads(
        Path("configs/mongodb_runtime_identity.v2.json").read_text(encoding="utf-8")
    )
    privileges = set(identity["custom_role"]["privileges"])
    prohibited_roles = set(identity["prohibited_roles"])
    prohibited_actions = set(identity["prohibited_actions"])

    assert identity["schema_version"] == "mongodb_runtime_identity.v2"
    assert identity["username"] == "10k"
    assert identity["authentication"] == "SCRAM-SHA-256"
    assert identity["database"] == "honeypot_canonical_v1"
    assert identity["cluster_scope"] == "epoch_receipt"
    assert identity["secret_material_present"] is False
    assert privileges == {
        "find", "insert", "update", "remove", "listCollections",
        "listIndexes", "collStats", "dbStats",
    }
    assert privileges.isdisjoint(prohibited_roles | prohibited_actions)
    assert "atlasAdmin" in prohibited_roles
    assert "createIndex" in prohibited_actions
    assert "bypassDocumentValidation" in prohibited_actions
    loaded = load_mongodb_runtime_identity()
    assert loaded.document == identity
    assert len(loaded.sha256) == 64


@pytest.fixture()
def mongo_storage():
    uri = os.getenv("MONGODB_TEST_URI", "")
    if not uri:
        pytest.skip("MONGODB_TEST_URI is not configured for an isolated replica set")
    pymongo = pytest.importorskip("pymongo")
    client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=5_000)
    client.admin.command("ping")
    prepare_canonical_test_database(client)
    storage = MongoDBStorageBackend(client=client)
    storage.initialize()
    try:
        yield storage
    finally:
        cleanup_canonical_test_database(client)
        client.close()


def test_mongodb_exact_duplicate_and_conflict_fail_closed(mongo_storage) -> None:
    record = CanonicalEventRecord.create(
        "sensor-a",
        _event("sensor-a:session-a", "id", "2026-08-12T00:00:00Z"),
        received_at="2026-08-12T01:00:00Z",
    )

    assert mongo_storage.store_canonical_event(record) == (record.event_id, True)
    assert mongo_storage.store_canonical_event(record) == (record.event_id, False)

    mongo_storage.database.events.update_one(
        {"_id": record.event_id}, {"$set": {"payload_json": "{}"}}
    )
    with pytest.raises(StorageError, match="conflicting duplicate"):
        mongo_storage.store_canonical_event(record)


def test_mongodb_concurrent_duplicate_is_idempotent(mongo_storage) -> None:
    record = CanonicalEventRecord.create(
        "sensor-a",
        _event("sensor-a:session-a", "id", "2026-08-12T00:00:00Z"),
        received_at="2026-08-12T01:00:00Z",
    )
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: mongo_storage.store_canonical_event(record), range(16)))

    assert sum(1 for _, inserted in results if inserted) == 1
    assert {event_id for event_id, _ in results} == {record.event_id}
    assert mongo_storage.database.events.count_documents({"_id": record.event_id}) == 1


def test_mongodb_order_watermark_limit_and_cross_sensor_identity(mongo_storage) -> None:
    later = CanonicalEventRecord.create(
        "sensor-a",
        _event("sensor-a:shared", "uname -a", "2026-08-12T00:00:02Z"),
        received_at="2026-08-12T01:00:02Z",
    )
    other_sensor = CanonicalEventRecord.create(
        "sensor-b",
        _event("sensor-b:shared", "whoami", "2026-08-12T00:00:01Z"),
        received_at="2026-08-12T01:00:01Z",
    )
    earlier = CanonicalEventRecord.create(
        "sensor-a",
        _event("sensor-a:shared", "id", "2026-08-12T00:00:00Z"),
        received_at="2026-08-12T01:00:00Z",
    )
    for record in (later, other_sensor, earlier):
        mongo_storage.store_canonical_event(record)

    assert [row["event_id"] for row in mongo_storage.fetch_events()] == [
        earlier.event_id,
        other_sensor.event_id,
        later.event_id,
    ]
    snapshot = mongo_storage.load_session_event_snapshot(
        "sensor-a:shared", later.event_id, 2
    )
    assert snapshot["event_count"] == 2
    assert [item["input"] for item in snapshot["events"]] == ["id", "uname -a"]
    with pytest.raises(StorageError, match="exceeds configured event limit"):
        mongo_storage.load_session_event_snapshot("sensor-a:shared", later.event_id, 1)


def test_sqlite_mongodb_event_prefix_parity(mongo_storage, tmp_path: Path) -> None:
    sqlite = open_storage(f"sqlite:///{tmp_path / 'parity.db'}")
    records = [
        CanonicalEventRecord.create(
            "sensor-a",
            _event("sensor-a:session-a", command, f"2026-08-12T00:00:0{index}Z"),
            received_at=f"2026-08-12T01:00:0{index}Z",
        )
        for index, command in enumerate(("id", "uname -a", "cat /etc/passwd"), 1)
    ]
    for record in reversed(records):
        assert sqlite.store_canonical_event(record) == (record.event_id, True)
        assert mongo_storage.store_canonical_event(record) == (record.event_id, True)

    sqlite_snapshot = sqlite.load_session_event_snapshot(
        "sensor-a:session-a", records[-1].event_id, 3
    )
    mongo_snapshot = mongo_storage.load_session_event_snapshot(
        "sensor-a:session-a", records[-1].event_id, 3
    )

    assert mongo_snapshot == sqlite_snapshot
    assert mongo_storage.store_canonical_event(records[0]) == (records[0].event_id, False)


def test_mongodb_worker_lease_fencing(mongo_storage) -> None:
    token_a = "11111111-1111-4111-8111-111111111111"
    token_b = "22222222-2222-4222-8222-222222222222"
    wrong_token = "33333333-3333-4333-8333-333333333333"
    assert mongo_storage.acquire_worker_lease(
        "session-worker", "owner-a", token_a, 30, now="2026-08-12T00:00:00Z"
    )
    assert not mongo_storage.acquire_worker_lease(
        "session-worker", "owner-b", token_b, 30, now="2026-08-12T00:00:01Z"
    )
    assert not mongo_storage.renew_worker_lease(
        "session-worker", "owner-a", wrong_token, 30, now="2026-08-12T00:00:02Z"
    )
    assert mongo_storage.renew_worker_lease(
        "session-worker", "owner-a", token_a, 30, now="2026-08-12T00:00:02Z"
    )
    assert mongo_storage.release_worker_lease(
        "session-worker", "owner-a", token_a, now="2026-08-12T00:00:03Z"
    )


def test_mongodb_session_revision_and_analysis_fields_are_preserved(mongo_storage) -> None:
    mongo_storage.save_session(
        {
            "session_id": "sensor-a:session-a",
            "src_ip": "192.0.2.10",
            "analysis_status": "succeeded",
            "report_id": "report-a",
        }
    )
    mongo_storage.save_session(
        {"session_id": "sensor-a:session-a", "src_ip": "192.0.2.10", "is_ended": True}
    )
    result = mongo_storage.get_session("sensor-a:session-a")

    assert result is not None
    assert result["revision"] == 2
    assert result["payload"]["analysis_status"] == "succeeded"
    assert result["payload"]["report_id"] == "report-a"
    assert result["ended"] is True
