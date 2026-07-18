from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

import production.tools.migrate_sqlite_to_mongodb as migration_module
from production.storage.backend import SQLiteStorage
from production.storage.mongodb import MONGODB_SCHEMA_VERSION
from production.tools.migrate_sqlite_to_mongodb import (
    DEFAULT_MIGRATION_ID,
    EVENT_LIFECYCLE_SOURCE_FIELDS,
    MIGRATION_TABLES,
    SQLiteToMongoMigrator,
    open_readonly_sqlite,
)
from tests.test_mongodb_storage import FakeDatabase, make_storage


def _store_lifecycle_events(path: Path) -> tuple[SQLiteStorage, dict[str, str]]:
    storage = SQLiteStorage(f"sqlite:///{path}")
    storage.initialize()
    event_ids: dict[str, str] = {}
    for sequence, state in enumerate(
        (
            "pending",
            "claimed",
            "retry_scheduled",
            "succeeded",
            "dead_letter",
            "processed_legacy",
        ),
        start=1,
    ):
        event_id, created = storage.store_event(
            "pi-1",
            {
                "session": f"session-{state}",
                "src_ip": f"192.0.2.{sequence}",
                "eventid": "cowrie.command.input",
                "input": f"state-{state}",
            },
        )
        assert created is True
        event_ids[state] = event_id

    updates: dict[str, dict[str, Any]] = {
        "pending": {},
        "claimed": {
            "claim_owner": "worker-a",
            "claim_token": "11111111-1111-4111-8111-111111111111",
            "claim_leader_scope": "session-worker",
            "claim_leader_token": "22222222-2222-4222-8222-222222222222",
            "claim_expires_at": "2026-07-18T01:05:00+00:00",
            "attempts": 1,
        },
        "retry_scheduled": {
            "attempts": 2,
            "next_retry_at": "2026-07-18T01:10:00+00:00",
            "last_error_code": "session_processing_failed",
            "last_error_type": "StorageError",
            "last_error_at": "2026-07-18T01:00:00+00:00",
            "processing_outcome": "retry_scheduled",
        },
        "succeeded": {
            "processed": 1,
            "attempts": 1,
            "processing_outcome": "succeeded",
            "processed_at": "2026-07-18T01:00:00+00:00",
            "effect_summary_json": json.dumps(
                {"alerts_created": 1, "session_saved": True}, sort_keys=True
            ),
        },
        "dead_letter": {
            "processed": 1,
            "attempts": 5,
            "last_error_code": "event_lease_attempts_exhausted",
            "last_error_type": "LeaseExpired",
            "last_error_at": "2026-07-18T01:00:00+00:00",
            "processing_outcome": "dead_letter",
            "processed_at": "2026-07-18T01:00:00+00:00",
        },
        "processed_legacy": {
            "processed": 1,
            "attempts": 0,
        },
    }
    with storage.connection() as connection:
        for state, values in updates.items():
            if not values:
                continue
            assignments = ", ".join(f'"{field}" = ?' for field in values)
            connection.execute(
                f'UPDATE events SET {assignments} WHERE event_id = ?',
                (*values.values(), event_ids[state]),
            )
    return storage, event_ids


def _checkpoint_document(
    migrator: SQLiteToMongoMigrator,
    *,
    target_schema_version: Any,
    checkpoint_id: str | None = None,
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "_id": checkpoint_id or migrator._checkpoint_id("events"),
        "migration_id": migrator.migration_id,
        "target_schema_version": target_schema_version,
        "source_id": migrator.source.source_id,
        "source_size_bytes": migrator.source.size_bytes,
        "source_modified_ns": migrator.source.modified_ns,
        "source_wal_size_bytes": migrator.source.wal_size_bytes,
        "source_wal_modified_ns": migrator.source.wal_modified_ns,
        "table": "events",
        "last_rowid": 0,
        "processed": 0,
        "source_count": 1,
        "status": "running",
    }
    if target_schema_version is None:
        document.pop("target_schema_version")
    return document


def test_v2_report_checkpoints_and_event_lifecycle_values(tmp_path: Path) -> None:
    source_path = tmp_path / "lifecycle.db"
    _, event_ids = _store_lifecycle_events(source_path)
    original_bytes = source_path.read_bytes()
    target, database = make_storage()
    database["_storage_leases"].replace_one(
        {"_id": "existing-lease"},
        {
            "_id": "existing-lease",
            "scope": "unrelated-live-scope",
            "owner": "other-worker",
            "token": "33333333-3333-4333-8333-333333333333",
            "expires_at": "2026-07-18T02:00:00+00:00",
        },
        upsert=True,
    )

    report = SQLiteToMongoMigrator(
        source_path,
        target,
        batch_size=2,
        sample_size=1,
        tables=("events",),
    ).run()

    assert DEFAULT_MIGRATION_ID == "sqlite-to-mongodb-v2"
    assert report["ok"] is True
    assert report["target_schema_version"] == MONGODB_SCHEMA_VERSION
    assert report["migration_tables"] == ["events"]
    assert "worker_leases" not in MIGRATION_TABLES
    assert report["excluded_ephemeral_tables"] == [
        {
            "source_table": "worker_leases",
            "target_collection": "_storage_leases",
            "reason": (
                "ephemeral worker fencing state is deployment-local and must be "
                "reacquired after writers are quiesced; it is never migrated"
            ),
        }
    ]
    assert database["_storage_leases"].find_one({"_id": "existing-lease"}) is not None

    validation = report["tables"][0]["validation"]
    lifecycle = validation["event_lifecycle"]
    assert validation["event_source_preflight"] == {
        "performed": True,
        "table": "events",
        "source_count": 6,
        "rows_checked": 6,
        "conversion_rows_checked": 6,
        "states_checked": {
            "pending": 1,
            "claimed": 1,
            "retry_scheduled": 1,
            "succeeded": 1,
            "dead_letter": 1,
            "processed_legacy": 1,
        },
        "required_source_fields": list(EVENT_LIFECYCLE_SOURCE_FIELDS),
        "ok": True,
    }
    assert lifecycle["ok"] is True
    assert lifecycle["target_schema_version"] == MONGODB_SCHEMA_VERSION
    assert lifecycle["required_source_fields"] == list(EVENT_LIFECYCLE_SOURCE_FIELDS)
    assert lifecycle["states_checked"] == {
        "pending": 1,
        "claimed": 1,
        "retry_scheduled": 1,
        "succeeded": 1,
        "dead_letter": 1,
        "processed_legacy": 1,
    }

    documents = {
        state: database["events"].find_one({"event_id": event_id})
        for state, event_id in event_ids.items()
    }
    assert all(document is not None for document in documents.values())
    assert all(type(document["processed"]) is bool for document in documents.values())
    assert all(
        document["schema_version"] == MONGODB_SCHEMA_VERSION
        for document in documents.values()
    )
    assert documents["pending"]["effect_summary"] is None
    assert documents["succeeded"]["effect_summary"] == {
        "alerts_created": 1,
        "session_saved": True,
    }
    assert documents["processed_legacy"]["processed"] is True
    assert documents["processed_legacy"]["processing_outcome"] is None
    assert documents["processed_legacy"]["effect_summary"] is None
    assert documents["retry_scheduled"]["next_retry_at"] == "2026-07-18T01:10:00+00:00"
    assert documents["dead_letter"]["last_error_type"] == "LeaseExpired"

    checkpoint = database["_migration_checkpoints"].find_one(
        {"migration_id": DEFAULT_MIGRATION_ID, "table": "events"}
    )
    assert checkpoint["target_schema_version"] == MONGODB_SCHEMA_VERSION
    expected_identity = hashlib.sha256(
        (
            f"{DEFAULT_MIGRATION_ID}\0{MONGODB_SCHEMA_VERSION}\0"
            f"{report['source']['source_id']}\0events"
        ).encode("utf-8")
    ).hexdigest()
    assert checkpoint["_id"] == expected_identity
    assert source_path.read_bytes() == original_bytes


@pytest.mark.parametrize("checkpoint_schema", [None, 1])
def test_missing_or_v1_checkpoint_schema_refuses_resume(
    tmp_path: Path,
    checkpoint_schema: Any,
) -> None:
    source_path = tmp_path / "checkpoint-schema.db"
    storage = SQLiteStorage(f"sqlite:///{source_path}")
    storage.initialize()
    storage.store_event(
        "pi-1",
        {"session": "s", "src_ip": "192.0.2.10", "eventid": "cowrie.session.connect"},
    )
    target, database = make_storage()
    migrator = SQLiteToMongoMigrator(source_path, target, tables=("events",))
    stale = _checkpoint_document(
        migrator,
        target_schema_version=checkpoint_schema,
    )
    database["_migration_checkpoints"].replace_one(
        {"_id": stale["_id"]}, stale, upsert=True
    )

    report = migrator.run()

    assert report["ok"] is False
    assert report["tables"][0]["status"] == "failed"
    error = report["tables"][0]["failures"][0]["error"]
    assert "target schema" in error
    assert "--restart" in error
    assert "--migration-id" in error
    assert target.count_collection("events") == 0


def test_obsolete_checkpoint_identity_requires_explicit_restart(tmp_path: Path) -> None:
    source_path = tmp_path / "checkpoint-identity.db"
    storage = SQLiteStorage(f"sqlite:///{source_path}")
    storage.initialize()
    storage.store_event(
        "pi-1",
        {"session": "s", "src_ip": "192.0.2.11", "eventid": "cowrie.session.connect"},
    )
    target, database = make_storage()
    migrator = SQLiteToMongoMigrator(source_path, target, tables=("events",))
    old_identity = hashlib.sha256(
        f"{migrator.migration_id}\0{migrator.source.source_id}\0events".encode("utf-8")
    ).hexdigest()
    stale = _checkpoint_document(
        migrator,
        target_schema_version=MONGODB_SCHEMA_VERSION,
        checkpoint_id=old_identity,
    )
    database["_migration_checkpoints"].replace_one(
        {"_id": old_identity}, stale, upsert=True
    )

    refused = migrator.run()
    assert refused["ok"] is False
    error = refused["tables"][0]["failures"][0]["error"]
    assert "identity is obsolete" in error
    assert "--restart" in error
    assert "--migration-id" in error

    with open_readonly_sqlite(source_path) as connection:
        source_row = dict(
            connection.execute(
                "SELECT rowid AS __rowid__, * FROM events LIMIT 1"
            ).fetchone()
        )
    assert target.upsert_migrated_row("events", source_row)["outcome"] == "inserted"
    database["_storage_leases"].replace_one(
        {"_id": "must-survive"},
        {"_id": "must-survive", "scope": "must-survive"},
        upsert=True,
    )
    restarted = SQLiteToMongoMigrator(
        source_path,
        target,
        tables=("events",),
        restart=True,
    ).run()
    assert restarted["ok"] is True
    assert restarted["checkpoints_cleared"] == 1
    assert target.count_collection("events") == 1
    assert restarted["counters"]["skipped"] == 1
    assert database["_storage_leases"].find_one({"_id": "must-survive"}) == {
        "_id": "must-survive",
        "scope": "must-survive",
    }


def test_old_event_schema_is_rejected_before_converter_or_target_write(tmp_path: Path) -> None:
    source_path = tmp_path / "old-events.db"
    with sqlite3.connect(source_path) as connection:
        connection.execute(
            """
            CREATE TABLE events (
                event_id TEXT PRIMARY KEY,
                sensor_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                eventid TEXT NOT NULL,
                timestamp TEXT,
                payload_json TEXT NOT NULL,
                received_at TEXT NOT NULL,
                processed INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        connection.execute(
            """
            INSERT INTO events (
                event_id, sensor_id, session_id, src_ip, eventid,
                timestamp, payload_json, received_at, processed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "old-event",
                "pi-1",
                "old-session",
                "192.0.2.12",
                "cowrie.session.connect",
                None,
                json.dumps({"session": "old-session"}),
                "2026-07-18T01:00:00+00:00",
                0,
            ),
        )
    original_bytes = source_path.read_bytes()
    target, _ = make_storage()

    dry_run = SQLiteToMongoMigrator(
        source_path,
        None,
        tables=("events",),
        sample_size=0,
        dry_run=True,
    ).run()
    assert dry_run["ok"] is False
    assert dry_run["tables"][0]["status"] == "failed"
    dry_error = dry_run["tables"][0]["failures"][0]["error"]
    assert "source preflight" in dry_error
    assert "missing required columns" in dry_error

    report = SQLiteToMongoMigrator(
        source_path,
        target,
        tables=("events",),
        sample_size=1,
    ).run()

    assert report["ok"] is False
    assert report["tables"][0]["status"] == "failed"
    assert "missing required columns" in report["tables"][0]["failures"][0]["error"]
    assert target.count_collection("events") == 0
    assert source_path.read_bytes() == original_bytes


def test_invalid_source_state_is_fully_preflighted_before_target_write(tmp_path: Path) -> None:
    source_path = tmp_path / "invalid-state.db"
    storage = SQLiteStorage(f"sqlite:///{source_path}")
    storage.initialize()
    event_ids = []
    for sequence in range(3):
        event_id, _ = storage.store_event(
            "pi-1",
            {
                "session": f"s-{sequence}",
                "src_ip": f"192.0.2.{20 + sequence}",
                "eventid": "cowrie.command.input",
                "input": f"command-{sequence}",
            },
        )
        event_ids.append(event_id)
    with storage.connection() as connection:
        connection.execute(
            "UPDATE events SET attempts = 1, processing_outcome = 'retry_scheduled' "
            "WHERE event_id = ?",
            (event_ids[1],),
        )
    target, _ = make_storage()

    report = SQLiteToMongoMigrator(
        source_path,
        target,
        tables=("events",),
        sample_size=0,
    ).run()

    assert report["ok"] is False
    assert report["tables"][0]["status"] == "failed"
    error = report["tables"][0]["failures"][0]["error"]
    assert "source preflight failed" in error
    assert "field next_retry_at" in error
    assert "no checkpoints or destination documents were changed" in error
    assert target.count_collection("events") == 0


def _migration_document_count(database: FakeDatabase) -> int:
    # ``make_storage`` initializes one schema-metadata document before the
    # migrator exists. Exclude that baseline and count every collection the
    # migration can otherwise change, including its checkpoints.
    return sum(
        len(collection.documents)
        for name, collection in database.collections.items()
        if name != "_storage_metadata"
    )


@pytest.mark.parametrize(
    "state_values, expected_field",
    [
        (
            {
                "attempts": 1,
                "next_retry_at": "2026-07-18T01:10:00+00:00",
                "last_error_code": "token_FAKE_SECRET_SENTINEL",
                "last_error_type": "StorageError",
                "last_error_at": "2026-07-18T01:00:00+00:00",
                "processing_outcome": "retry_scheduled",
            },
            "last_error_code",
        ),
        (
            {
                "attempts": 1,
                "next_retry_at": "2026-07-18T01:10:00+00:00",
                "last_error_code": "temporary_failure",
                "last_error_type": "SecretBearingException",
                "last_error_at": "2026-07-18T01:00:00+00:00",
                "processing_outcome": "retry_scheduled",
            },
            "last_error_type",
        ),
        (
            {
                "processed": 1,
                "attempts": 1,
                "processing_outcome": "succeeded",
                "processed_at": "2026-07-18T01:00:00+00:00",
                "effect_summary_json": json.dumps({"api_key": 1}),
            },
            "effect_summary_json",
        ),
        (
            {
                "processed": 1,
                "attempts": 1,
                "processing_outcome": "succeeded",
                "processed_at": "2026-07-18T01:00:00+00:00",
                "effect_summary_json": json.dumps(
                    {"session_saved": "FAKE_SECRET_SENTINEL"}
                ),
            },
            "effect_summary_json",
        ),
    ],
    ids=(
        "unknown-error-code",
        "unknown-error-type",
        "unknown-effect-key",
        "secret-shaped-effect-value",
    ),
)
def test_runtime_policy_rejections_match_dry_run_and_write_nothing(
    tmp_path: Path,
    state_values: dict[str, Any],
    expected_field: str,
) -> None:
    source_path = tmp_path / "policy-rejection.db"
    storage = SQLiteStorage(f"sqlite:///{source_path}")
    storage.initialize()
    event_id, _ = storage.store_event(
        "pi-1",
        {"session": "s", "src_ip": "192.0.2.40", "eventid": "cowrie.command.input"},
    )
    with storage.connection() as connection:
        assignments = ", ".join(f'"{field}" = ?' for field in state_values)
        connection.execute(
            f"UPDATE events SET {assignments} WHERE event_id = ?",
            (*state_values.values(), event_id),
        )
    original_bytes = source_path.read_bytes()

    dry_report = SQLiteToMongoMigrator(
        source_path,
        None,
        tables=("events",),
        sample_size=0,
        dry_run=True,
    ).run()
    target, database = make_storage()
    real_report = SQLiteToMongoMigrator(
        source_path,
        target,
        tables=("events",),
        sample_size=0,
    ).run()

    dry_table = dry_report["tables"][0]
    real_table = real_report["tables"][0]
    assert dry_report["ok"] is False
    assert real_report["ok"] is False
    assert dry_table["status"] == real_table["status"] == "failed"
    dry_error = dry_table["failures"][0]["error"]
    real_error = real_table["failures"][0]["error"]
    assert dry_error == real_error
    assert f"field {expected_field}" in real_error
    assert "FAKE_SECRET_SENTINEL" not in json.dumps(real_report, sort_keys=True)
    assert _migration_document_count(database) == 0
    assert database["events"].documents == {}
    assert database["_migration_checkpoints"].documents == {}
    assert source_path.read_bytes() == original_bytes


def test_mixed_policy_invalid_batch_cannot_partially_write(tmp_path: Path) -> None:
    source_path = tmp_path / "mixed-policy-batch.db"
    storage = SQLiteStorage(f"sqlite:///{source_path}")
    storage.initialize()
    event_ids = []
    for sequence in range(3):
        event_id, _ = storage.store_event(
            "pi-1",
            {
                "session": f"mixed-{sequence}",
                "src_ip": f"192.0.2.{50 + sequence}",
                "eventid": "cowrie.command.input",
            },
        )
        event_ids.append(event_id)
    with storage.connection() as connection:
        connection.execute(
            "UPDATE events SET processed = 1, attempts = 1, "
            "processing_outcome = 'succeeded', processed_at = ?, "
            "effect_summary_json = ? WHERE event_id = ?",
            (
                "2026-07-18T01:00:00+00:00",
                json.dumps({"unexpected_secret_metadata": 1}),
                event_ids[1],
            ),
        )
    original_bytes = source_path.read_bytes()
    target, database = make_storage()

    report = SQLiteToMongoMigrator(
        source_path,
        target,
        tables=("events",),
        batch_size=1,
        sample_size=0,
    ).run()

    assert report["ok"] is False
    assert report["tables"][0]["processed_this_run"] == 0
    assert "runtime_effect_summary_policy" in report["tables"][0]["failures"][0]["error"]
    assert _migration_document_count(database) == 0
    assert database["events"].documents == {}
    assert database["_migration_checkpoints"].documents == {}
    assert source_path.read_bytes() == original_bytes


@pytest.mark.parametrize(
    "state_values",
    [
        {"claim_leader_scope": "stale-scope"},
        {
            "processed": 1,
            "processing_outcome": "succeeded",
            "processed_at": "2026-07-18T01:00:00+00:00",
            "claim_leader_scope": "stale-scope",
            "claim_leader_token": "44444444-4444-4444-8444-444444444444",
        },
    ],
    ids=("pending-partial-leader-binding", "terminal-stale-leader-binding"),
)
def test_stale_leader_bindings_fail_preflight_without_writes(
    tmp_path: Path,
    state_values: dict[str, Any],
) -> None:
    source_path = tmp_path / "stale-leader.db"
    storage = SQLiteStorage(f"sqlite:///{source_path}")
    storage.initialize()
    event_id, _ = storage.store_event(
        "pi-1",
        {"session": "s", "src_ip": "192.0.2.30", "eventid": "cowrie.session.connect"},
    )
    with storage.connection() as connection:
        assignments = ", ".join(f'"{field}" = ?' for field in state_values)
        connection.execute(
            f"UPDATE events SET {assignments} WHERE event_id = ?",
            (*state_values.values(), event_id),
        )
    target, _ = make_storage()

    report = SQLiteToMongoMigrator(
        source_path,
        target,
        tables=("events",),
    ).run()

    assert report["ok"] is False
    error = report["tables"][0]["failures"][0]["error"]
    assert "field claim_leader_scope" in error
    assert "must_be_clear_for_lifecycle_state" in error
    assert target.count_collection("events") == 0


def test_raw_boolean_tampering_is_not_hidden_by_row_round_trip(tmp_path: Path) -> None:
    source_path = tmp_path / "tampered-bool.db"
    storage = SQLiteStorage(f"sqlite:///{source_path}")
    storage.initialize()
    event_id, _ = storage.store_event(
        "pi-1",
        {"session": "s", "src_ip": "192.0.2.13", "eventid": "cowrie.session.connect"},
    )
    target, database = make_storage()
    migrator = SQLiteToMongoMigrator(
        source_path,
        target,
        tables=("events",),
        sample_size=1,
    )
    assert migrator.run()["ok"] is True
    database["events"].documents[event_id]["processed"] = 0

    with open_readonly_sqlite(source_path) as connection:
        source_row = dict(
            connection.execute(
                "SELECT rowid AS __rowid__, * FROM events WHERE event_id = ?",
                (event_id,),
            ).fetchone()
        )
    validation = migrator._validate_table("events", 1, [source_row])

    # The generic row conversion normalizes both BSON bool and integer 0 to
    # SQLite integer 0.  The independent raw-document check must still fail.
    assert validation["sample_hashes"][0]["match"] is True
    assert validation["sample_failures"] == []
    assert validation["event_lifecycle"]["ok"] is False
    assert {
        (failure["field"], failure["reason"])
        for failure in validation["event_lifecycle"]["failures"]
    } >= {("processed", "target_value_must_be_boolean")}


def test_restart_preserves_checkpoints_until_complete_preflight_succeeds(
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "restart-preflight.db"
    storage = SQLiteStorage(f"sqlite:///{source_path}")
    storage.initialize()
    event_id, _ = storage.store_event(
        "pi-1",
        {"session": "restart", "src_ip": "192.0.2.60", "eventid": "event"},
    )
    target, database = make_storage()
    initial = SQLiteToMongoMigrator(
        source_path,
        target,
        tables=("events",),
    ).run()
    assert initial["ok"] is True
    checkpoint_before = copy.deepcopy(
        database["_migration_checkpoints"].find_one(
            {"migration_id": DEFAULT_MIGRATION_ID, "table": "events"}
        )
    )
    event_before = copy.deepcopy(database["events"].documents[event_id])

    with storage.connection() as connection:
        connection.execute(
            "UPDATE events SET processed = 1, attempts = 1, "
            "processing_outcome = 'succeeded', processed_at = ?, "
            "effect_summary_json = ? WHERE event_id = ?",
            (
                "2026-07-18T01:00:00+00:00",
                json.dumps({"unapproved_restart_metadata": 1}),
                event_id,
            ),
        )
    source_before_restart = source_path.read_bytes()

    restarted = SQLiteToMongoMigrator(
        source_path,
        target,
        tables=("events",),
        restart=True,
    ).run()

    assert restarted["ok"] is False
    assert restarted["migration_completed"] is False
    assert restarted["checkpoints_cleared"] == 0
    assert database["_migration_checkpoints"].find_one(
        {"migration_id": DEFAULT_MIGRATION_ID, "table": "events"}
    ) == checkpoint_before
    assert database["events"].documents[event_id] == event_before
    assert source_path.read_bytes() == source_before_restart


def test_global_conversion_preflight_matches_dry_run_and_blocks_earlier_tables(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_path = tmp_path / "global-conversion-preflight.db"
    storage = SQLiteStorage(f"sqlite:///{source_path}")
    storage.initialize()
    storage.store_event(
        "pi-1",
        {"session": "event", "src_ip": "192.0.2.61", "eventid": "event"},
    )
    for sequence in range(2):
        storage.save_session(
            {
                "session_id": f"session-{sequence}",
                "src_ip": f"192.0.2.{62 + sequence}",
                "session_source": "production_live",
            }
        )
    source_before = source_path.read_bytes()
    original_converter = migration_module.document_from_sqlite_row

    def reject_second_session(table: str, row: dict[str, Any]) -> dict[str, Any]:
        if table == "sessions" and int(row.get("__rowid__", 0)) == 2:
            raise RuntimeError("FAKE_SECRET_SENTINEL must not enter reports")
        return original_converter(table, row)

    monkeypatch.setattr(
        migration_module,
        "document_from_sqlite_row",
        reject_second_session,
    )
    dry_report = SQLiteToMongoMigrator(
        source_path,
        None,
        tables=("events", "sessions"),
        batch_size=1,
        dry_run=True,
    ).run()
    target, database = make_storage()
    real_report = SQLiteToMongoMigrator(
        source_path,
        target,
        tables=("events", "sessions"),
        batch_size=1,
    ).run()

    assert dry_report["ok"] is real_report["ok"] is False
    assert dry_report["migration_completed"] is False
    assert real_report["migration_completed"] is False
    assert [item["status"] for item in real_report["tables"]] == [
        "not_started",
        "failed",
    ]
    dry_error = dry_report["tables"][1]["failures"][0]["error"]
    real_error = real_report["tables"][1]["failures"][0]["error"]
    assert dry_error == real_error
    assert "sessions source conversion preflight failed" in real_error
    assert "FAKE_SECRET_SENTINEL" not in json.dumps(real_report, sort_keys=True)
    assert _migration_document_count(database) == 0
    assert source_path.read_bytes() == source_before


def test_mid_batch_write_failure_is_auditable_and_safely_resumable(
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "write-failure-resume.db"
    storage = SQLiteStorage(f"sqlite:///{source_path}")
    storage.initialize()
    for sequence in range(3):
        storage.store_event(
            "pi-1",
            {
                "session": f"resume-{sequence}",
                "src_ip": f"192.0.2.{70 + sequence}",
                "eventid": "event",
            },
        )
    source_before = source_path.read_bytes()
    target, database = make_storage()
    original_upsert = target.upsert_migrated_row
    calls = 0

    def fail_second_upsert(table: str, row: dict[str, Any]) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("FAKE_SECRET_SENTINEL destination outage")
        return original_upsert(table, row)

    target.upsert_migrated_row = fail_second_upsert  # type: ignore[method-assign]
    failed = SQLiteToMongoMigrator(
        source_path,
        target,
        tables=("events",),
        batch_size=3,
    ).run()

    assert failed["ok"] is False
    assert failed["migration_completed"] is False
    assert failed["tables"][0]["status"] == "failed"
    assert failed["tables"][0]["last_rowid"] == 0
    assert failed["tables"][0]["processed_this_run"] == 0
    assert "failed to upsert events rowid 2" in failed["tables"][0]["failures"][0][
        "error"
    ]
    assert target.count_collection("events") == 1
    failed_checkpoint = database["_migration_checkpoints"].find_one(
        {"migration_id": DEFAULT_MIGRATION_ID, "table": "events"}
    )
    assert failed_checkpoint["status"] == "failed"
    assert failed_checkpoint["last_rowid"] == 0
    assert failed_checkpoint["processed"] == 0
    assert "FAKE_SECRET_SENTINEL" not in json.dumps(failed, sort_keys=True)

    target.upsert_migrated_row = original_upsert  # type: ignore[method-assign]
    resumed = SQLiteToMongoMigrator(
        source_path,
        target,
        tables=("events",),
        batch_size=3,
    ).run()

    assert resumed["ok"] is True
    assert resumed["migration_completed"] is True
    assert resumed["counters"]["skipped"] == 1
    assert resumed["counters"]["inserted"] == 2
    assert target.count_collection("events") == 3
    assert source_path.read_bytes() == source_before


def test_later_collection_write_failure_never_reports_global_completion(
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "later-collection-failure.db"
    storage = SQLiteStorage(f"sqlite:///{source_path}")
    storage.initialize()
    storage.store_event(
        "pi-1",
        {"session": "later", "src_ip": "192.0.2.80", "eventid": "event"},
    )
    storage.save_session(
        {
            "session_id": "later",
            "src_ip": "192.0.2.80",
            "session_source": "production_live",
        }
    )
    source_before = source_path.read_bytes()
    target, database = make_storage()
    original_upsert = target.upsert_migrated_row

    def fail_session_upsert(table: str, row: dict[str, Any]) -> dict[str, Any]:
        if table == "sessions":
            raise RuntimeError("FAKE_SECRET_SENTINEL later collection outage")
        return original_upsert(table, row)

    target.upsert_migrated_row = fail_session_upsert  # type: ignore[method-assign]
    report = SQLiteToMongoMigrator(
        source_path,
        target,
        tables=("events", "sessions"),
        batch_size=1,
    ).run()

    assert report["ok"] is False
    assert report["migration_completed"] is False
    assert [item["status"] for item in report["tables"]] == [
        "completed",
        "failed",
    ]
    assert target.count_collection("events") == 1
    assert target.count_collection("sessions") == 0
    assert database["_migration_checkpoints"].find_one(
        {"migration_id": DEFAULT_MIGRATION_ID, "table": "events"}
    )["status"] == "completed"
    assert database["_migration_checkpoints"].find_one(
        {"migration_id": DEFAULT_MIGRATION_ID, "table": "sessions"}
    )["status"] == "failed"
    assert "FAKE_SECRET_SENTINEL" not in json.dumps(report, sort_keys=True)
    assert source_path.read_bytes() == source_before
