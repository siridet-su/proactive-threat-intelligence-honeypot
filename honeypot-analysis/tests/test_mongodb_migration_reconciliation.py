from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from production.storage import CanonicalEventRecord, MongoDBStorageBackend, open_storage
from production.storage.backend import StorageError
from production.tools import mongodb_canonical_migration
from production.tools.mongodb_canonical_migration import (
    migrate_sqlite_backup,
    reconcile_sqlite_backup,
)
from tests.mongodb_test_support import cleanup_canonical_test_database, prepare_canonical_test_database


@pytest.fixture()
def migration_target():
    uri = os.getenv("MONGODB_TEST_URI", "")
    if not uri:
        pytest.skip("MONGODB_TEST_URI is not configured for an isolated replica set")
    pymongo = pytest.importorskip("pymongo")
    client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=5_000)
    prepare_canonical_test_database(client)
    storage = MongoDBStorageBackend(client=client); storage.initialize()
    try:
        yield storage
    finally:
        cleanup_canonical_test_database(client); client.close()


def _backup_fixture(tmp_path: Path) -> Path:
    live = tmp_path / "fixture-live.db"; backup = tmp_path / "fixture-backup.db"
    storage = open_storage(f"sqlite:///{live}")
    storage.initialize_ai_advisory_extension()
    record = CanonicalEventRecord.create(
        "sensor-a",
        {"eventid": "cowrie.command.input", "session": "sensor-a:session-a", "input": "id"},
        received_at="2026-08-12T00:00:00Z",
    )
    storage.store_canonical_event(record)
    storage.save_session({"session_id": "sensor-a:session-a", "src_ip": "192.0.2.10"})
    job_id = storage.enqueue_analysis_job({"session_id": "sensor-a:session-a"})
    claim = storage.claim_analysis_jobs("worker-a", 1, 30, 3, now="2026-08-12T01:00:00Z")[0]
    storage.complete_analysis_job(job_id, "worker-a", claim["claim_token"], {"schema_version": "legacy-report.v1", "session_id": "sensor-a:session-a", "findings": []}, now="2026-08-12T01:00:01Z")
    storage.enqueue_prediction_outbox({"event_id": record.event_id, "session_id": "sensor-a:session-a", "prediction_mode": "transformer_poc"})
    source = sqlite3.connect(live)
    destination = sqlite3.connect(backup)
    try:
        source.backup(destination)
    finally:
        destination.close(); source.close()
    return backup


def test_full_offline_migration_is_idempotent_and_reconciles(migration_target, tmp_path: Path) -> None:
    backup = _backup_fixture(tmp_path)
    first = migrate_sqlite_backup(backup, migration_target, destination_identity="local-rs0")
    assert first.inserted > 0
    assert first.receipt["conflicting_count"] == 0
    reconciliation = reconcile_sqlite_backup(backup, migration_target, destination_identity="local-rs0")
    assert reconciliation["matched"] is True
    assert reconciliation["mismatches"] == {}
    second = migrate_sqlite_backup(backup, migration_target, destination_identity="local-rs0")
    assert second.inserted == 0
    assert second.exact_existing == first.receipt["migrated_record_count"]
    assert second.receipt == first.receipt


def test_reconciliation_reports_mismatch_without_repair(migration_target, tmp_path: Path) -> None:
    backup = _backup_fixture(tmp_path)
    migrate_sqlite_backup(backup, migration_target, destination_identity="local-rs0")
    event = migration_target.database.events.find_one({})
    migration_target.database.events.update_one({"_id": event["_id"]}, {"$set": {"payload_sha256": "0" * 64}})
    receipt = reconcile_sqlite_backup(backup, migration_target, destination_identity="local-rs0")
    assert receipt["matched"] is False
    assert "events" in receipt["mismatches"]
    assert migration_target.database.events.find_one({"_id": event["_id"]})["payload_sha256"] == "0" * 64


def test_reconciliation_hashes_whole_state_and_destination_only_records(
    migration_target, tmp_path: Path
) -> None:
    backup = _backup_fixture(tmp_path)
    migrate_sqlite_backup(backup, migration_target, destination_identity="local-rs0")
    job = migration_target.database.analysis_jobs.find_one({})
    migration_target.database.analysis_jobs.update_one(
        {"_id": job["_id"]}, {"$set": {"status": "failed"}}
    )
    receipt = reconcile_sqlite_backup(
        backup, migration_target, destination_identity="local-rs0"
    )
    assert receipt["matched"] is False
    assert "analysis_jobs" in receipt["mismatches"]

    migration_target.database.analysis_jobs.update_one(
        {"_id": job["_id"]}, {"$set": {"status": job["status"]}}
    )
    migration_target.database.ai_advisories.insert_one(
        {
            "_id": "unexpected-advisory",
            "schema_version": "mongodb_ai_advisory.v1",
            "advisory_id": "unexpected-advisory",
            "cache_key": "unexpected-cache",
            "report_id": "report-x",
            "session_id": "sensor-x:session-x",
            "assessment_id": "assessment-x",
            "payload_json": "{}",
        }
    )
    receipt = reconcile_sqlite_backup(
        backup, migration_target, destination_identity="local-rs0"
    )
    assert receipt["matched"] is False
    assert "ai_advisories" in receipt["mismatches"]


def test_migration_rejects_source_that_changes_during_read(
    migration_target, tmp_path: Path, monkeypatch
) -> None:
    backup = _backup_fixture(tmp_path)
    actual = mongodb_canonical_migration._sha256_file(backup)
    observed = 0

    def changing_hash(path: Path) -> str:
        nonlocal observed
        observed += 1
        return actual if observed == 1 else "0" * 64

    monkeypatch.setattr(
        mongodb_canonical_migration, "_sha256_file", changing_hash
    )
    with pytest.raises(StorageError, match="changed while it was read"):
        migrate_sqlite_backup(
            backup, migration_target, destination_identity="local-rs0"
        )
