"""Offline migration and reconciliation for a consistent SQLite backup.

The tool is not a cutover mechanism. It preserves application identifiers and
canonical JSON bytes, writes only to an already-installed MongoDB manifest,
and produces a content-addressed receipt. It never rewrites either side during
reconciliation.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, Mapping, Optional

from production.storage.backend import StorageError
from production.storage.mongodb_backend import MongoDBStorageBackend
from production.utils.serialization import stable_id, stable_json, utc_now


MIGRATION_RECEIPT_SCHEMA = "sqlite_to_mongodb_migration_receipt.v1"
RECONCILIATION_RECEIPT_SCHEMA = "sqlite_mongodb_reconciliation_receipt.v1"

TABLE_COLLECTION = {
    "events": "events",
    "sessions": "sessions",
    "analysis_jobs": "analysis_jobs",
    "reports": "reports",
    "alerts": "alerts",
    "prediction_outbox": "prediction_outbox",
    "prediction_snapshots": "prediction_snapshots",
    "prediction_backtest_runs": "prediction_backtest_runs",
    "prediction_calibration_runs": "prediction_calibration_runs",
    "ai_advisory_outbox": "ai_advisory_outbox",
    "ai_advisories": "ai_advisories",
    "enrichment_jobs": "enrichment_jobs",
    "enrichment_records": "enrichment_records",
    "threat_hunt_jobs": "threat_hunt_jobs",
    "observables": "observables",
    "observable_sightings": "observable_sightings",
    "webhook_deliveries": "webhook_deliveries",
    "session_links": "session_links",
    "campaigns": "campaigns",
    "campaign_sessions": "campaign_sessions",
    "analyst_feedback": "analyst_feedback",
    "classification_review_labels": "classification_review_labels",
    "feed_status": "feed_status",
    "data_lifecycle_policy_ledger": "lifecycle_ledger",
    "worker_leases": "worker_leases",
}
MIGRATED_COLLECTIONS = frozenset(
    {*TABLE_COLLECTION.values(), "canonical_assessments"}
)

IDENTITY_FIELD = {
    "events": "event_id",
    "sessions": "session_id",
    "analysis_jobs": "job_id",
    "reports": "report_id",
    "alerts": "alert_id",
    "prediction_outbox": "outbox_id",
    "prediction_snapshots": "snapshot_id",
    "prediction_backtest_runs": "run_id",
    "prediction_calibration_runs": "run_id",
    "ai_advisory_outbox": "job_id",
    "ai_advisories": "advisory_id",
    "enrichment_jobs": "job_id",
    "threat_hunt_jobs": "job_id",
    "observable_sightings": "sighting_id",
    "webhook_deliveries": "delivery_id",
    "session_links": "link_id",
    "campaigns": "campaign_id",
    "campaign_sessions": "link_id",
    "analyst_feedback": "feedback_id",
    "classification_review_labels": "label_id",
    "prediction_backtest_runs": "run_id",
    "prediction_calibration_runs": "run_id",
    "data_lifecycle_policy_ledger": "policy_sha256",
    "worker_leases": "scope",
}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode()).hexdigest()


def _open_backup(path: Path) -> sqlite3.Connection:
    resolved = path.resolve(strict=True)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise StorageError("SQLite migration source must be a regular non-symlink file")
    wal = Path(f"{resolved}-wal")
    if wal.exists() and wal.stat().st_size:
        raise StorageError("SQLite migration source has an uncheckpointed WAL")
    connection = sqlite3.connect(
        f"file:{resolved}?mode=ro&immutable=1", uri=True
    )
    connection.row_factory = sqlite3.Row
    if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
        connection.close()
        raise StorageError("SQLite migration source failed quick_check")
    return connection


def _table_names(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }


def _identity(table: str, row: Mapping[str, Any]) -> str:
    explicit = IDENTITY_FIELD.get(table)
    if explicit:
        return str(row[explicit])
    if table == "enrichment_records":
        return stable_id("enrichment", {"observable_type": row["observable_type"], "observable_value": row["observable_value"]})
    if table == "observables":
        return stable_id("observable", {"observable_type": row["observable_type"], "observable_value": row["observable_value"]})
    if table == "feed_status":
        return str(row["name"])
    raise StorageError(f"migration identity is undefined for {table}")


def _schema(collection: str) -> str:
    special = {
        "events": "mongodb_canonical_event.v1",
        "sessions": "mongodb_canonical_session.v1",
        "worker_leases": "mongodb_worker_lease.v1",
    }
    return special.get(collection, f"mongodb_{collection.rstrip('s')}.v1")


def _document(table: str, row: Mapping[str, Any]) -> Dict[str, Any]:
    collection = TABLE_COLLECTION[table]
    identity = _identity(table, row)
    document: Dict[str, Any] = {
        "_id": identity,
        "schema_version": _schema(collection),
        **dict(row),
    }
    aliases = {
        "events": ("event_id", identity),
        "sessions": ("session_id", identity),
        "analysis_jobs": ("job_id", identity),
        "prediction_outbox": ("outbox_id", identity),
        "ai_advisory_outbox": ("job_id", identity),
        "enrichment_jobs": ("job_id", identity),
        "threat_hunt_jobs": ("job_id", identity),
        "feed_status": ("feed_id", identity),
        "worker_leases": ("scope", identity),
    }
    if table in aliases:
        key, value = aliases[table]
        document[key] = value
    if table == "observables":
        document["observable_id"] = identity
    if table == "observable_sightings":
        document["observable_id"] = stable_id("observable", {"observable_type": row["observable_type"], "observable_value": row["observable_value"]})
    if table == "session_links":
        document["session_id"] = str(row["session_id_a"])
    if "payload_json" in document:
        document["payload_sha256"] = hashlib.sha256(str(document["payload_json"]).encode()).hexdigest()
    if table == "events":
        document["processed"] = bool(document.get("processed"))
        document["attempts"] = int(document.get("attempts") or 0)
    if table == "sessions":
        document["ended"] = bool(document.get("ended"))
        document["is_external_source"] = bool(document.get("is_external_source"))
    return document


def _canonical_assessment(report: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        payload = json.loads(str(report.get("payload_json") or "{}"))
    except json.JSONDecodeError as exc:
        raise StorageError("report payload is malformed") from exc
    assessment_id = str(payload.get("assessment_id") or "")
    if payload.get("schema_version") != "session_assessment.v4" or not assessment_id:
        return None
    return {
        "_id": assessment_id,
        "schema_version": "mongodb_canonical_assessment.v1",
        "assessment_id": assessment_id,
        "report_id": report["report_id"],
        "session_id": report["session_id"],
        "payload_json": report["payload_json"],
        "payload_sha256": hashlib.sha256(str(report["payload_json"]).encode()).hexdigest(),
        "created_at": report["created_at"],
    }


def iter_sqlite_documents(
    connection: sqlite3.Connection,
) -> Iterator[tuple[str, Dict[str, Any]]]:
    existing = _table_names(connection)
    for table, collection in TABLE_COLLECTION.items():
        if table not in existing:
            continue
        identity = IDENTITY_FIELD.get(table)
        order = identity or (
            "observable_type, observable_value"
            if table in {"enrichment_records", "observables"}
            else "name"
        )
        for raw in connection.execute(f"SELECT * FROM {table} ORDER BY {order}"):
            document = _document(table, dict(raw))
            yield collection, document
            if table == "reports":
                assessment = _canonical_assessment(document)
                if assessment:
                    yield "canonical_assessments", assessment


def _domain_manifest(
    documents: Iterable[tuple[str, Mapping[str, Any]]],
    *,
    include_empty: bool = False,
) -> Dict[str, Dict[str, Any]]:
    domains: Dict[str, tuple[int, Any]] = {}
    if include_empty:
        domains = {
            collection: (0, hashlib.sha256())
            for collection in MIGRATED_COLLECTIONS
        }
    for collection, document in documents:
        document_hash = _sha256_json(document)
        count, digest = domains.setdefault(collection, (0, hashlib.sha256()))
        entry = {
            "id": str(document["_id"]),
            "document_sha256": document_hash,
        }
        digest.update(stable_json(entry).encode("utf-8"))
        digest.update(b"\n")
        domains[collection] = (count + 1, digest)
    return {
        collection: {
            "count": count,
            "ordered_aggregate_sha256": digest.hexdigest(),
        }
        for collection, (count, digest) in sorted(domains.items())
    }


@dataclass(frozen=True)
class MigrationResult:
    receipt: Dict[str, Any]
    inserted: int
    exact_existing: int


def migrate_sqlite_backup(
    source_path: str | Path,
    destination: MongoDBStorageBackend,
    *,
    destination_identity: str,
    release_bindings: Optional[Dict[str, str]] = None,
) -> MigrationResult:
    from pymongo.errors import DuplicateKeyError

    source = Path(source_path)
    source_sha256 = _sha256_file(source)
    destination.verify_existing_schema()
    inserted = exact = rejected = conflicts = 0
    cutoff: Optional[Dict[str, str]] = None
    domain_counts: Dict[str, int] = {}
    domain_digests: Dict[str, Any] = {}

    def observe(collection: str, document: Mapping[str, Any]) -> None:
        entry = {
            "id": str(document["_id"]),
            "document_sha256": _sha256_json(document),
        }
        digest = domain_digests.setdefault(collection, hashlib.sha256())
        digest.update(stable_json(entry).encode("utf-8"))
        digest.update(b"\n")
        domain_counts[collection] = domain_counts.get(collection, 0) + 1

    with _open_backup(source) as connection:
        tables = _table_names(connection)
        schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        migrations = [dict(row) for row in connection.execute("SELECT * FROM schema_migrations ORDER BY version")] if "schema_migrations" in tables else []
        extensions = [dict(row) for row in connection.execute("SELECT * FROM schema_extensions ORDER BY extension_id")] if "schema_extensions" in tables else []
        for collection, document in iter_sqlite_documents(connection):
            observe(collection, document)
            if collection == "events":
                candidate = {
                    "schema_version": "prediction_evidence_cutoff.v1",
                    "received_at": str(document["received_at"]),
                    "event_id": str(document["event_id"]),
                }
                if cutoff is None or (
                    candidate["received_at"], candidate["event_id"]
                ) > (cutoff["received_at"], cutoff["event_id"]):
                    cutoff = candidate
            try:
                destination.database[collection].insert_one(document)
                inserted += 1
            except DuplicateKeyError:
                existing = destination.database[collection].find_one(
                    {"_id": document["_id"]}
                )
                if existing is None or stable_json(existing) != stable_json(document):
                    conflicts += 1
                    raise StorageError(
                        f"migration conflict in {collection}:{document['_id']}"
                    )
                exact += 1
            except Exception:
                rejected += 1
                raise
    if _sha256_file(source) != source_sha256:
        raise StorageError("SQLite migration source changed while it was read")
    domains = {
        collection: {
            "count": domain_counts[collection],
            "ordered_aggregate_sha256": domain_digests[collection].hexdigest(),
        }
        for collection in sorted(domain_counts)
    }
    migrated_record_count = sum(domain_counts.values())
    basis = {
        "schema_version": MIGRATION_RECEIPT_SCHEMA,
        "source_sqlite_sha256": source_sha256,
        "source_sqlite_schema_version": schema_version,
        "source_schema_migrations": migrations,
        "source_schema_extensions": extensions,
        "event_cutoff": cutoff,
        "release_bindings": dict(sorted((release_bindings or {}).items())),
        "destination_identity": str(destination_identity),
        "mongodb_manifest_sha256": destination.manifest.sha256,
        "migration_tool_revision": "mongodb_canonical_migration.v1",
        "domains": domains,
        "migrated_record_count": migrated_record_count,
        "exact_verified_count": migrated_record_count,
        "rejected_count": rejected,
        "conflicting_count": conflicts,
        "reconciliation": "pending",
    }
    receipt_id = stable_id("mongomigration", basis)
    receipt = {**basis, "receipt_id": receipt_id}
    payload_json = stable_json(receipt)
    receipt_document = {
            "_id": receipt_id,
            "schema_version": MIGRATION_RECEIPT_SCHEMA,
            "receipt_id": receipt_id,
            "payload_json": payload_json,
            "payload_sha256": hashlib.sha256(payload_json.encode()).hexdigest(),
            "created_at": utc_now(),
        }
    try:
        destination.database.migration_receipts.insert_one(receipt_document)
    except DuplicateKeyError:
        existing_receipt = destination.database.migration_receipts.find_one(
            {"_id": receipt_id}
        )
        if not existing_receipt or existing_receipt.get("payload_json") != payload_json:
            raise StorageError("migration receipt identity conflict")
    return MigrationResult(receipt=receipt, inserted=inserted, exact_existing=exact)


def reconcile_sqlite_backup(
    source_path: str | Path,
    destination: MongoDBStorageBackend,
    *,
    destination_identity: str,
) -> Dict[str, Any]:
    source = Path(source_path)
    with _open_backup(source) as connection:
        expected = _domain_manifest(
            iter_sqlite_documents(connection), include_empty=True
        )

    def observed_documents() -> Iterator[tuple[str, Mapping[str, Any]]]:
        for collection in sorted(MIGRATED_COLLECTIONS):
            for document in destination.database[collection].find({}).sort([("_id", 1)]):
                yield collection, document

    observed = _domain_manifest(observed_documents(), include_empty=True)
    mismatches = {
        collection: {"expected": expected.get(collection), "observed": observed.get(collection)}
        for collection in sorted(set(expected) | set(observed))
        if expected.get(collection) != observed.get(collection)
    }
    basis = {
        "schema_version": RECONCILIATION_RECEIPT_SCHEMA,
        "source_sqlite_sha256": _sha256_file(source),
        "destination_identity": str(destination_identity),
        "mongodb_manifest_sha256": destination.manifest.sha256,
        "expected_domains": expected,
        "observed_domains": observed,
        "mismatches": mismatches,
        "matched": not mismatches,
    }
    return {**basis, "receipt_id": stable_id("mongoreconcile", basis)}
