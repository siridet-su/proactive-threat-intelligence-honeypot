"""Non-authoritative SQLite-to-MongoDB shadow replication primitives.

These helpers are intentionally not wired into production configuration.  The
authoritative SQLite event and its shadow intent are committed in one SQLite
transaction; a separate retry-safe replicator writes and verifies MongoDB.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from production.storage.backend import SQLiteStorage, StorageError
from production.storage.canonical_event import CanonicalEventRecord
from production.storage.mongodb_backend import MongoDBStorageBackend
from production.utils.serialization import stable_id, stable_json, utc_now


SHADOW_SCHEMA = "mongodb_shadow_outbox.v1"


def _future(now: str, seconds: float) -> str:
    parsed = datetime.fromisoformat(now.replace("Z", "+00:00"))
    return (parsed + timedelta(seconds=float(seconds))).isoformat()


def _record_payload(record: CanonicalEventRecord) -> Dict[str, Any]:
    record.verify()
    return {
        "schema_version": record.schema_version,
        "event_id": record.event_id,
        "sensor_id": record.sensor_id,
        "session_id": record.session_id,
        "received_at": record.received_at,
        "payload_json": record.payload_json,
        "payload_sha256": record.payload_sha256,
        "event": record.event,
    }


def _restore_record(payload: Dict[str, Any]) -> CanonicalEventRecord:
    record = CanonicalEventRecord(
        event_id=str(payload["event_id"]),
        sensor_id=str(payload["sensor_id"]),
        session_id=str(payload["session_id"]),
        received_at=str(payload["received_at"]),
        payload_json=str(payload["payload_json"]),
        payload_sha256=str(payload["payload_sha256"]),
        event=dict(payload["event"]),
        schema_version=str(payload["schema_version"]),
    )
    record.verify()
    return record


class SQLiteMongoShadowOutbox:
    def __init__(self, sqlite: SQLiteStorage, mongo: MongoDBStorageBackend) -> None:
        self.sqlite = sqlite
        self.mongo = mongo

    def initialize_extension(self) -> None:
        with self.sqlite.connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS mongodb_shadow_outbox (
                    shadow_id TEXT PRIMARY KEY,
                    schema_version TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    canonical_id TEXT NOT NULL,
                    manifest_sha256 TEXT NOT NULL,
                    status TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_retry_at TEXT,
                    claim_owner TEXT,
                    claim_token TEXT,
                    claim_expires_at TEXT,
                    discrepancy_code TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(operation, canonical_id, manifest_sha256)
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_mongodb_shadow_claimable
                ON mongodb_shadow_outbox(
                    status, next_retry_at, claim_expires_at, created_at, shadow_id
                )
                """
            )

    def store_event_with_shadow(
        self, record: CanonicalEventRecord
    ) -> tuple[str, bool, str]:
        record.verify()
        payload = _record_payload(record)
        payload_json = stable_json(payload)
        shadow_id = stable_id(
            "mongoshadow",
            {
                "operation": "store_canonical_event",
                "canonical_id": record.event_id,
                "manifest_sha256": self.mongo.manifest.sha256,
            },
        )
        current = utc_now()
        with self.sqlite.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO events
                (event_id, sensor_id, session_id, src_ip, eventid, timestamp,
                 payload_json, received_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.event_id,
                    record.sensor_id,
                    record.session_id,
                    str(record.event.get("src_ip", "unknown")),
                    str(record.event.get("eventid", "")),
                    record.event.get("timestamp"),
                    record.payload_json,
                    record.received_at,
                ),
            )
            inserted = cursor.rowcount == 1
            if not inserted:
                existing = conn.execute(
                    "SELECT sensor_id, session_id, payload_json, received_at "
                    "FROM events WHERE event_id=?",
                    (record.event_id,),
                ).fetchone()
                if existing is None or any(
                    existing[key] != expected
                    for key, expected in (
                        ("sensor_id", record.sensor_id),
                        ("session_id", record.session_id),
                        ("payload_json", record.payload_json),
                        ("received_at", record.received_at),
                    )
                ):
                    raise StorageError("conflicting duplicate canonical event ID")
            conn.execute(
                """
                INSERT OR IGNORE INTO mongodb_shadow_outbox
                (shadow_id, schema_version, operation, canonical_id,
                 manifest_sha256, status, payload_json, payload_sha256,
                 attempts, created_at, updated_at)
                VALUES (?, ?, 'store_canonical_event', ?, ?, 'queued', ?, ?, 0, ?, ?)
                """,
                (
                    shadow_id,
                    SHADOW_SCHEMA,
                    record.event_id,
                    self.mongo.manifest.sha256,
                    payload_json,
                    hashlib.sha256(payload_json.encode()).hexdigest(),
                    current,
                    current,
                ),
            )
        return record.event_id, inserted, shadow_id

    def claim_one(
        self,
        owner: str,
        lease_seconds: float,
        max_attempts: int,
        *,
        now: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        current = now or utc_now()
        with self.sqlite.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT * FROM mongodb_shadow_outbox
                WHERE attempts < ?
                  AND status IN ('queued', 'retry', 'running')
                  AND (next_retry_at IS NULL OR next_retry_at <= ?)
                  AND (status <> 'running' OR claim_expires_at IS NULL
                       OR claim_expires_at <= ?)
                ORDER BY created_at, shadow_id LIMIT 1
                """,
                (int(max_attempts), current, current),
            ).fetchone()
            if row is None:
                return None
            token = str(uuid.uuid4())
            cursor = conn.execute(
                """
                UPDATE mongodb_shadow_outbox
                SET status='running', attempts=attempts+1, claim_owner=?,
                    claim_token=?, claim_expires_at=?, next_retry_at=NULL,
                    updated_at=?
                WHERE shadow_id=? AND attempts=? AND status=?
                """,
                (
                    owner,
                    token,
                    _future(current, lease_seconds),
                    current,
                    row["shadow_id"],
                    row["attempts"],
                    row["status"],
                ),
            )
            if cursor.rowcount != 1:
                return None
            result = dict(row)
            result.update(
                {
                    "status": "running",
                    "attempts": int(row["attempts"]) + 1,
                    "claim_owner": owner,
                    "claim_token": token,
                }
            )
            return result

    def replicate_one(
        self,
        owner: str,
        *,
        lease_seconds: float = 30,
        max_attempts: int = 5,
        retry_delay_seconds: float = 1,
        now: Optional[str] = None,
    ) -> str:
        row = self.claim_one(owner, lease_seconds, max_attempts, now=now)
        if row is None:
            return "idle"
        current = now or utc_now()
        try:
            payload_json = str(row["payload_json"])
            if hashlib.sha256(payload_json.encode()).hexdigest() != row["payload_sha256"]:
                raise StorageError("shadow payload hash mismatch")
            record = _restore_record(json.loads(payload_json))
            self.mongo.store_canonical_event(record)
            persisted = self.mongo.get_event(record.event_id)
            if not _event_matches(record, persisted):
                raise StorageError("shadow destination verification mismatch")
        except Exception as exc:
            discrepancy = isinstance(exc, StorageError)
            with self.sqlite.connection() as conn:
                status = "discrepancy" if discrepancy or row["attempts"] >= max_attempts else "retry"
                conn.execute(
                    """
                    UPDATE mongodb_shadow_outbox
                    SET status=?, next_retry_at=?, discrepancy_code=?,
                        claim_owner=NULL, claim_token=NULL,
                        claim_expires_at=NULL, updated_at=?
                    WHERE shadow_id=? AND status='running'
                      AND claim_owner=? AND claim_token=?
                    """,
                    (
                        status,
                        None if status == "discrepancy" else _future(current, retry_delay_seconds),
                        "integrity_mismatch" if discrepancy else "destination_unavailable",
                        current,
                        row["shadow_id"],
                        owner,
                        row["claim_token"],
                    ),
                )
            return status
        with self.sqlite.connection() as conn:
            conn.execute(
                """
                UPDATE mongodb_shadow_outbox
                SET status='succeeded', next_retry_at=NULL,
                    discrepancy_code=NULL, claim_owner=NULL, claim_token=NULL,
                    claim_expires_at=NULL, updated_at=?
                WHERE shadow_id=? AND status='running'
                  AND claim_owner=? AND claim_token=?
                """,
                (current, row["shadow_id"], owner, row["claim_token"]),
            )
        return "succeeded"


def _event_matches(
    record: CanonicalEventRecord, persisted: Optional[Dict[str, Any]]
) -> bool:
    return bool(
        persisted
        and persisted.get("event_id") == record.event_id
        and persisted.get("sensor_id") == record.sensor_id
        and persisted.get("payload_json") == record.payload_json
        and persisted.get("received_at") == record.received_at
    )


class MongoSQLiteRollbackMirror:
    """Post-cutover dual-durable ACK state machine for the new epoch."""

    def __init__(self, mongo: MongoDBStorageBackend, sqlite: SQLiteStorage) -> None:
        self.mongo = mongo
        self.sqlite = sqlite

    def persist_for_ack(self, record: CanonicalEventRecord) -> Dict[str, Any]:
        record.verify()
        mongo = self.mongo.get_event(record.event_id)
        sqlite = self.sqlite.get_event(record.event_id)
        mongo_exact = _event_matches(record, mongo)
        sqlite_exact = _event_matches(record, sqlite)
        if mongo is not None and not mongo_exact:
            raise StorageError("conflicting MongoDB canonical event content")
        if sqlite is not None and not sqlite_exact:
            raise StorageError("conflicting SQLite canonical event content")
        initial = (
            "neither_exists"
            if mongo is None and sqlite is None
            else "mongo_only"
            if sqlite is None
            else "sqlite_only"
            if mongo is None
            else "both_exact"
        )
        if mongo is None:
            self.mongo.store_canonical_event(record)
        if sqlite is None:
            self.sqlite.store_canonical_event(record)
        mongo_after = self.mongo.get_event(record.event_id)
        sqlite_after = self.sqlite.get_event(record.event_id)
        if not _event_matches(record, mongo_after) or not _event_matches(record, sqlite_after):
            raise StorageError("rollback mirror exact verification failed")
        return {
            "schema_version": "mongodb_sqlite_ack.v1",
            "event_id": record.event_id,
            "initial_state": initial,
            "final_state": "both_exact",
            "ack_eligible": True,
        }
