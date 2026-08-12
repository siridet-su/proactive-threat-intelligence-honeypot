from __future__ import annotations

import os

import pytest

from production.storage import (
    CanonicalEventRecord,
    MongoDBStorageBackend,
    MongoSQLiteRollbackMirror,
    SQLiteMongoShadowOutbox,
    StorageError,
    install_mongodb_schema,
    open_storage,
)


@pytest.fixture()
def backends(tmp_path):
    uri = os.getenv("MONGODB_TEST_URI", "")
    if not uri:
        pytest.skip("MONGODB_TEST_URI is not configured for an isolated replica set")
    pymongo = pytest.importorskip("pymongo")
    client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=5_000)
    client.drop_database("honeypot_canonical_v1")
    install_mongodb_schema(client)
    mongo = MongoDBStorageBackend(client=client)
    mongo.initialize()
    sqlite = open_storage(f"sqlite:///{tmp_path / 'authority.db'}")
    try:
        yield sqlite, mongo
    finally:
        client.drop_database("honeypot_canonical_v1")
        client.close()


def _record(suffix: str = "a") -> CanonicalEventRecord:
    return CanonicalEventRecord.create(
        "sensor-a",
        {
            "eventid": "cowrie.command.input",
            "session": "sensor-a:session-a",
            "input": f"id {suffix}",
            "timestamp": "2026-08-12T00:00:00Z",
        },
        received_at="2026-08-12T00:01:00Z",
    )


def test_shadow_intent_is_atomic_retry_safe_and_verified(backends) -> None:
    sqlite, mongo = backends
    shadow = SQLiteMongoShadowOutbox(sqlite, mongo)
    shadow.initialize_extension()
    record = _record()
    event_id, inserted, shadow_id = shadow.store_event_with_shadow(record)
    assert inserted
    assert sqlite.get_event(event_id)["payload_json"] == record.payload_json
    assert mongo.get_event(event_id) is None
    assert shadow.replicate_one("shadow-a", now="2026-08-12T01:00:00+00:00") == "succeeded"
    assert mongo.get_event(event_id)["payload_json"] == record.payload_json
    assert shadow.store_event_with_shadow(record) == (event_id, False, shadow_id)
    assert shadow.replicate_one("shadow-a") == "idle"


def test_shadow_outage_retries_without_changing_sqlite(backends, monkeypatch) -> None:
    sqlite, mongo = backends
    shadow = SQLiteMongoShadowOutbox(sqlite, mongo); shadow.initialize_extension()
    record = _record("outage"); shadow.store_event_with_shadow(record)
    monkeypatch.setattr(mongo, "store_canonical_event", lambda value: (_ for _ in ()).throw(ConnectionError("offline")))
    assert shadow.replicate_one("shadow-a", now="2026-08-12T01:00:00+00:00") == "retry"
    assert sqlite.get_event(record.event_id)["payload_json"] == record.payload_json
    assert mongo.get_event(record.event_id) is None


def test_shadow_worker_crash_after_mongo_write_replays_idempotently(backends) -> None:
    sqlite, mongo = backends
    shadow = SQLiteMongoShadowOutbox(sqlite, mongo)
    shadow.initialize_extension()
    record = _record("crash-after-write")
    shadow.store_event_with_shadow(record)
    claim = shadow.claim_one(
        "shadow-a", 1, 5, now="2026-08-12T01:00:00+00:00"
    )
    assert claim is not None
    # Simulate a process death after the majority write but before the SQLite
    # shadow acknowledgement is committed.
    mongo.store_canonical_event(record)
    assert shadow.replicate_one(
        "shadow-b", now="2026-08-12T01:00:02+00:00"
    ) == "succeeded"
    assert mongo.database.events.count_documents({"_id": record.event_id}) == 1


@pytest.mark.parametrize("initial", ["neither", "mongo", "sqlite", "both"])
def test_rollback_mirror_repairs_missing_exact_copy_before_ack(backends, initial) -> None:
    sqlite, mongo = backends; record = _record(initial)
    if initial in {"mongo", "both"}: mongo.store_canonical_event(record)
    if initial in {"sqlite", "both"}: sqlite.store_canonical_event(record)
    result = MongoSQLiteRollbackMirror(mongo, sqlite).persist_for_ack(record)
    assert result["ack_eligible"] is True
    assert result["final_state"] == "both_exact"
    assert mongo.get_event(record.event_id)["payload_json"] == record.payload_json
    assert sqlite.get_event(record.event_id)["payload_json"] == record.payload_json


def test_rollback_mirror_conflict_fails_closed(backends) -> None:
    sqlite, mongo = backends; record = _record("conflict")
    mongo.store_canonical_event(record)
    mongo.database.events.update_one({"_id": record.event_id}, {"$set": {"payload_json": "{}"}})
    with pytest.raises(StorageError, match="conflicting MongoDB"):
        MongoSQLiteRollbackMirror(mongo, sqlite).persist_for_ack(record)
    assert sqlite.get_event(record.event_id) is None


def test_rollback_mirror_sqlite_conflict_fails_closed(backends) -> None:
    sqlite, mongo = backends
    record = _record("sqlite-conflict")
    sqlite.store_canonical_event(record)
    with sqlite.connection() as connection:
        connection.execute(
            "UPDATE events SET payload_json='{}' WHERE event_id=?",
            (record.event_id,),
        )
    with pytest.raises(StorageError, match="conflicting SQLite"):
        MongoSQLiteRollbackMirror(mongo, sqlite).persist_for_ack(record)
    assert mongo.get_event(record.event_id) is None
