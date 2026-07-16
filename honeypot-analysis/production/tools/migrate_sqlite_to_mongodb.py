"""Repeatable, resumable SQLite-to-MongoDB migration.

The source SQLite database is always opened read-only and is never modified or
deleted.  MongoDB writes are idempotent replacements keyed by the same stable
domain identifiers used by the runtime adapter.  A checkpoint is advanced only
after every row in a batch has been upserted, so interrupted batches can be
replayed safely.

For a production cutover, quiesce writers or take a verified SQLite backup and
migrate that immutable copy.  Resume follows SQLite ``rowid`` progress; changes
to already-migrated rows require ``--restart`` (which clears checkpoints only,
not either database) so all source rows are reconciled again.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence
from urllib.parse import quote

from production.storage.mongodb import (
    ALLOWED_TABLES,
    MongoStorage,
    _safe_error,
    document_from_sqlite_row,
    row_from_document,
)
from production.utils.serialization import stable_json, utc_now


DEFAULT_MIGRATION_ID = "sqlite-to-mongodb-v1"
DEFAULT_BATCH_SIZE = 1000
DEFAULT_SAMPLE_SIZE = 3

# Preserve a predictable operational ordering even though MongoDB has no
# foreign-key requirement.
MIGRATION_TABLES: tuple[str, ...] = (
    "events",
    "sessions",
    "alerts",
    "analysis_jobs",
    "reports",
    "feed_status",
    "observables",
    "observable_sightings",
    "enrichment_records",
    "enrichment_jobs",
    "webhook_deliveries",
    "prediction_snapshots",
    "prediction_backtest_runs",
    "prediction_calibration_runs",
    "analyst_feedback",
    "classification_review_labels",
    "threat_hunt_jobs",
    "session_links",
    "campaigns",
    "campaign_sessions",
)


class MigrationError(RuntimeError):
    pass


@dataclass(frozen=True)
class SourceIdentity:
    source_id: str
    path: str
    size_bytes: int
    modified_ns: int
    wal_size_bytes: int
    wal_modified_ns: int

    @classmethod
    def from_path(cls, path: Path) -> "SourceIdentity":
        resolved = path.expanduser().resolve(strict=True)
        stat = resolved.stat()
        wal_path = Path(f"{resolved}-wal")
        wal_stat = wal_path.stat() if wal_path.exists() else None
        # SQLite may create a zero-byte WAL while a read-only connection is
        # opened.  It contains no source changes and must not invalidate an
        # otherwise resumable checkpoint.
        if wal_stat is not None and wal_stat.st_size == 0:
            wal_stat = None
        identity_payload = (
            f"{resolved}\0{stat.st_dev}\0{stat.st_ino}".encode("utf-8", errors="surrogatepass")
        )
        return cls(
            source_id=hashlib.sha256(identity_payload).hexdigest(),
            path=str(resolved),
            size_bytes=int(stat.st_size),
            modified_ns=int(stat.st_mtime_ns),
            wal_size_bytes=int(wal_stat.st_size) if wal_stat else 0,
            wal_modified_ns=int(wal_stat.st_mtime_ns) if wal_stat else -1,
        )

    def public_summary(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "path": self.path,
            "size_bytes": self.size_bytes,
            "modified_ns": self.modified_ns,
            "wal_size_bytes": self.wal_size_bytes,
            "wal_modified_ns": self.wal_modified_ns,
        }


def sqlite_path_from_value(value: str) -> Path:
    text = str(value or "").strip()
    if text.startswith("sqlite:///"):
        text = text.replace("sqlite:///", "", 1)
    if not text:
        raise MigrationError("SQLite source path must not be empty")
    path = Path(text).expanduser()
    if not path.exists():
        raise MigrationError(f"SQLite source does not exist: {path}")
    if not path.is_file():
        raise MigrationError(f"SQLite source is not a regular file: {path}")
    return path.resolve()


def open_readonly_sqlite(path: Path) -> sqlite3.Connection:
    uri = f"file:{quote(str(path), safe='/')}?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


def _table_exists(connection: sqlite3.Connection, table: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def _normalize_for_comparison(table: str, row: Mapping[str, Any]) -> Dict[str, Any]:
    return row_from_document(table, document_from_sqlite_row(table, row))


class SQLiteToMongoMigrator:
    def __init__(
        self,
        sqlite_path: Path,
        target: Optional[MongoStorage],
        *,
        migration_id: str = DEFAULT_MIGRATION_ID,
        batch_size: int = DEFAULT_BATCH_SIZE,
        sample_size: int = DEFAULT_SAMPLE_SIZE,
        tables: Sequence[str] = MIGRATION_TABLES,
        dry_run: bool = False,
        restart: bool = False,
        strict_counts: bool = True,
        continue_on_error: bool = False,
    ):
        self.sqlite_path = sqlite_path_from_value(str(sqlite_path))
        self.source = SourceIdentity.from_path(self.sqlite_path)
        self.target = target
        self.migration_id = str(migration_id or DEFAULT_MIGRATION_ID).strip()
        self.batch_size = max(int(batch_size), 1)
        self.sample_size = max(int(sample_size), 0)
        self.tables = tuple(tables)
        self.dry_run = bool(dry_run)
        self.restart = bool(restart)
        self.strict_counts = bool(strict_counts)
        self.continue_on_error = bool(continue_on_error)
        invalid = sorted(set(self.tables) - ALLOWED_TABLES)
        if invalid:
            raise MigrationError(f"unsupported migration tables: {', '.join(invalid)}")
        if not self.migration_id:
            raise MigrationError("migration_id must not be empty")
        if not self.dry_run and self.target is None:
            raise MigrationError("a MongoDB target is required unless --dry-run is used")

    @property
    def checkpoints(self) -> Any:
        if self.target is None:
            raise MigrationError("checkpoint access requires a MongoDB target")
        return self.target.database["_migration_checkpoints"]

    def _checkpoint_id(self, table: str) -> str:
        return hashlib.sha256(
            f"{self.migration_id}\0{self.source.source_id}\0{table}".encode("utf-8")
        ).hexdigest()

    def _load_checkpoint(self, table: str) -> Optional[Dict[str, Any]]:
        if self.dry_run or self.target is None:
            return None
        checkpoint = self.checkpoints.find_one({"_id": self._checkpoint_id(table)})
        if checkpoint is None:
            checkpoint = self.checkpoints.find_one(
                {"migration_id": self.migration_id, "table": table}
            )
        if checkpoint and checkpoint.get("source_id") != self.source.source_id:
            raise MigrationError(
                f"checkpoint source identity mismatch for table {table}; use --restart or a new migration id"
            )
        if checkpoint and (
            int(checkpoint.get("source_size_bytes") or -1) != self.source.size_bytes
            or int(checkpoint.get("source_modified_ns") or -1) != self.source.modified_ns
            or int(checkpoint.get("source_wal_size_bytes") or 0) != self.source.wal_size_bytes
            or int(checkpoint.get("source_wal_modified_ns") or -1)
            != self.source.wal_modified_ns
        ):
            raise MigrationError(
                f"SQLite source changed after the {table} checkpoint; use --restart to reconcile all rows"
            )
        return dict(checkpoint) if checkpoint else None

    def _save_checkpoint(
        self,
        table: str,
        *,
        last_rowid: int,
        processed: int,
        status: str,
        source_count: int,
        validation: Optional[Mapping[str, Any]] = None,
        error: str = "",
    ) -> None:
        if self.dry_run or self.target is None:
            return
        now = utc_now()
        checkpoint_id = self._checkpoint_id(table)
        document = {
            "_id": checkpoint_id,
            "migration_id": self.migration_id,
            "source_id": self.source.source_id,
            "source_size_bytes": self.source.size_bytes,
            "source_modified_ns": self.source.modified_ns,
            "source_wal_size_bytes": self.source.wal_size_bytes,
            "source_wal_modified_ns": self.source.wal_modified_ns,
            "table": table,
            "last_rowid": int(last_rowid),
            "processed": int(processed),
            "source_count": int(source_count),
            "status": status,
            "validation": dict(validation or {}),
            "error": str(error or "")[:2000],
            "updated_at": now,
        }
        existing = self.checkpoints.find_one({"_id": checkpoint_id})
        document["created_at"] = (
            existing.get("created_at") if existing else now
        )
        self.checkpoints.replace_one({"_id": checkpoint_id}, document, upsert=True)

    def _clear_checkpoints(self) -> int:
        if self.dry_run or self.target is None or not self.restart:
            return 0
        result = self.checkpoints.delete_many(
            {
                "migration_id": self.migration_id,
                "table": {"$in": list(self.tables)},
            }
        )
        return int(getattr(result, "deleted_count", 0) or 0)

    def _sample_rows(
        self,
        first_rows: Sequence[Mapping[str, Any]],
        last_rows: Sequence[Mapping[str, Any]],
    ) -> list[Dict[str, Any]]:
        selected: list[Dict[str, Any]] = []
        seen: set[int] = set()
        for row in [*first_rows, *last_rows]:
            rowid = int(row["__rowid__"])
            if rowid in seen:
                continue
            seen.add(rowid)
            selected.append(dict(row))
        return selected

    def _validate_table(
        self,
        table: str,
        source_count: int,
        samples: Sequence[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        if self.dry_run or self.target is None:
            return {
                "performed": False,
                "reason": "dry-run: no MongoDB writes or target validation",
                "source_count": source_count,
                "samples_checked": 0,
                "ok": True,
            }
        target_count = self.target.count_collection(table)
        if self.strict_counts:
            count_ok = target_count == source_count
        else:
            count_ok = target_count >= source_count
        sample_failures = []
        sample_hashes = []
        for source_row in samples:
            expected = _normalize_for_comparison(table, source_row)
            actual = self.target.get_migrated_row(table, source_row)
            expected_hash = hashlib.sha256(stable_json(expected).encode("utf-8")).hexdigest()
            actual_hash = (
                hashlib.sha256(stable_json(actual).encode("utf-8")).hexdigest()
                if actual is not None
                else ""
            )
            sample_hashes.append(
                {
                    "rowid": int(source_row["__rowid__"]),
                    "expected_sha256": expected_hash,
                    "actual_sha256": actual_hash,
                    "match": bool(actual is not None and expected_hash == actual_hash),
                }
            )
            if actual is None:
                sample_failures.append(
                    {"rowid": int(source_row["__rowid__"]), "reason": "missing_target_document"}
                )
                continue
            if actual_hash != expected_hash:
                sample_failures.append(
                    {"rowid": int(source_row["__rowid__"]), "reason": "content_mismatch"}
                )
        return {
            "performed": True,
            "source_count": source_count,
            "target_count": target_count,
            "strict_counts": self.strict_counts,
            "count_ok": count_ok,
            "samples_checked": len(samples),
            "sample_hashes": sample_hashes,
            "sample_failures": sample_failures,
            "ok": count_ok and not sample_failures,
        }

    def migrate_table(
        self,
        connection: sqlite3.Connection,
        table: str,
    ) -> Dict[str, Any]:
        if not _table_exists(connection, table):
            return {
                "table": table,
                "status": "absent",
                "source_count": 0,
                "processed_this_run": 0,
                "counters": {
                    "inserted": 0,
                    "updated": 0,
                    "skipped": 0,
                    "duplicate": 0,
                    "invalid": 0,
                    "failed": 0,
                },
                "message": "source table does not exist; target was not changed",
            }
        source_count = int(
            connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
        )
        checkpoint: Optional[Dict[str, Any]] = None
        checkpoint_loaded = False
        last_rowid = 0
        processed_total = 0
        processed_this_run = 0
        first_samples: list[Dict[str, Any]] = []
        last_samples: list[Dict[str, Any]] = []
        failures: list[Dict[str, Any]] = []
        counters = {
            "inserted": 0,
            "updated": 0,
            "skipped": 0,
            "duplicate": 0,
            "invalid": 0,
            "failed": 0,
        }
        try:
            checkpoint = self._load_checkpoint(table)
            checkpoint_loaded = True
            last_rowid = int(checkpoint.get("last_rowid") or 0) if checkpoint else 0
            processed_total = int(checkpoint.get("processed") or 0) if checkpoint else 0
            while True:
                rows = connection.execute(
                    f'''
                    SELECT rowid AS __rowid__, *
                    FROM "{table}"
                    WHERE rowid > ?
                    ORDER BY rowid
                    LIMIT ?
                    ''',
                    (last_rowid, self.batch_size),
                ).fetchall()
                if not rows:
                    break
                converted_batch = []
                for row in rows:
                    item = dict(row)
                    # Conversion is performed in dry-run too, so BSON/key/JSON
                    # failures are detected before any cutover.
                    try:
                        document_from_sqlite_row(table, item)
                    except Exception as exc:
                        counters["invalid"] += 1
                        raise MigrationError(
                            f"invalid {table} rowid {item.get('__rowid__')}: {_safe_error(exc)}"
                        ) from exc
                    converted_batch.append(item)
                if self.dry_run:
                    counters["skipped"] += len(converted_batch)
                else:
                    assert self.target is not None
                    for item in converted_batch:
                        try:
                            outcome = self.target.upsert_migrated_row(table, item)
                            outcome_name = str(outcome.get("outcome") or "updated")
                            if outcome_name not in {"inserted", "updated", "skipped"}:
                                outcome_name = "updated"
                            counters[outcome_name] += 1
                        except Exception as exc:
                            if getattr(exc, "code", None) == 11000 or "duplicate key" in str(exc).lower():
                                counters["duplicate"] += 1
                            else:
                                counters["failed"] += 1
                            raise MigrationError(
                                f"failed to upsert {table} rowid {item.get('__rowid__')}: {_safe_error(exc)}"
                            ) from exc
                for item in converted_batch:
                    if len(first_samples) < self.sample_size:
                        first_samples.append(item)
                    if self.sample_size:
                        last_samples.append(item)
                        if len(last_samples) > self.sample_size:
                            last_samples.pop(0)
                last_rowid = int(converted_batch[-1]["__rowid__"])
                processed_this_run += len(converted_batch)
                processed_total += len(converted_batch)
                self._save_checkpoint(
                    table,
                    last_rowid=last_rowid,
                    processed=processed_total,
                    status="running",
                    source_count=source_count,
                )
            samples = self._sample_rows(first_samples, last_samples)
            # A completed checkpoint can resume with no rows.  Re-read samples
            # deterministically so validation still occurs.
            if not samples and source_count and self.sample_size:
                first = connection.execute(
                    f'SELECT rowid AS __rowid__, * FROM "{table}" ORDER BY rowid LIMIT ?',
                    (self.sample_size,),
                ).fetchall()
                last = connection.execute(
                    f'SELECT rowid AS __rowid__, * FROM "{table}" ORDER BY rowid DESC LIMIT ?',
                    (self.sample_size,),
                ).fetchall()
                samples = self._sample_rows(
                    [dict(row) for row in first],
                    [dict(row) for row in reversed(last)],
                )
            validation = self._validate_table(table, source_count, samples)
            status = "completed" if validation["ok"] else "validation_failed"
            self._save_checkpoint(
                table,
                last_rowid=last_rowid,
                processed=processed_total,
                status=status,
                source_count=source_count,
                validation=validation,
            )
            return {
                "table": table,
                "status": status,
                "source_count": source_count,
                "checkpoint_start_rowid": int(checkpoint.get("last_rowid") or 0)
                if checkpoint
                else 0,
                "last_rowid": last_rowid,
                "processed_before_run": int(checkpoint.get("processed") or 0)
                if checkpoint
                else 0,
                "processed_this_run": processed_this_run,
                "validation": validation,
                "failures": failures,
                "counters": counters,
            }
        except Exception as exc:
            error = _safe_error(exc)
            failures.append({"last_rowid": last_rowid, "error": error})
            if checkpoint_loaded:
                self._save_checkpoint(
                    table,
                    last_rowid=last_rowid,
                    processed=processed_total,
                    status="failed",
                    source_count=source_count,
                    error=error,
                )
            return {
                "table": table,
                "status": "failed",
                "source_count": source_count,
                "last_rowid": last_rowid,
                "processed_this_run": processed_this_run,
                "failures": failures,
                "counters": counters,
            }

    def run(self) -> Dict[str, Any]:
        self.source = SourceIdentity.from_path(self.sqlite_path)
        source_at_start = self.source
        started_at = utc_now()
        checkpoints_cleared = self._clear_checkpoints()
        table_reports = []
        with open_readonly_sqlite(self.sqlite_path) as connection:
            # One read transaction gives counts, rows, and samples a consistent
            # view. It does not modify the SQLite source.
            connection.execute("BEGIN")
            quick_check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
            if quick_check.lower() != "ok":
                raise MigrationError(f"SQLite quick_check failed: {quick_check[:500]}")
            for table in self.tables:
                report = self.migrate_table(connection, table)
                table_reports.append(report)
                if report["status"] in {"failed", "validation_failed"} and not self.continue_on_error:
                    break
        failures = [
            {"table": item["table"], "status": item["status"], "failures": item.get("failures", [])}
            for item in table_reports
            if item["status"] in {"failed", "validation_failed"}
        ]
        source_after = SourceIdentity.from_path(self.sqlite_path)
        source_changed_during_run = (
            source_after.size_bytes != source_at_start.size_bytes
            or source_after.modified_ns != source_at_start.modified_ns
            or source_after.wal_size_bytes != source_at_start.wal_size_bytes
            or source_after.wal_modified_ns != source_at_start.wal_modified_ns
        )
        if source_changed_during_run:
            failures.append(
                {
                    "stage": "source_changed_during_run",
                    "status": "failed",
                    "error": (
                        "SQLite source size or modification time changed during migration; "
                        "restart is required to reconcile the consistent source snapshot"
                    ),
                }
            )
        aggregate_counters = {
            name: sum(
                int(item.get("counters", {}).get(name, 0))
                for item in table_reports
            )
            for name in ("inserted", "updated", "skipped", "duplicate", "invalid", "failed")
        }
        return {
            "migration_id": self.migration_id,
            "dry_run": self.dry_run,
            "restart": self.restart,
            "batch_size": self.batch_size,
            "sample_size": self.sample_size,
            "strict_counts": self.strict_counts,
            "source": self.source.public_summary(),
            "source_after": source_after.public_summary(),
            "source_changed_during_run": source_changed_during_run,
            "source_quick_check": "ok",
            "checkpoints_cleared": checkpoints_cleared,
            "started_at": started_at,
            "completed_at": utc_now(),
            "tables": table_reports,
            "counters": aggregate_counters,
            "failures": failures,
            "ok": not failures,
            "source_deleted": False,
        }


def _parse_tables(value: str) -> tuple[str, ...]:
    if not value.strip():
        return MIGRATION_TABLES
    tables = tuple(item.strip() for item in value.split(",") if item.strip())
    if not tables:
        raise argparse.ArgumentTypeError("at least one table is required")
    invalid = sorted(set(tables) - ALLOWED_TABLES)
    if invalid:
        raise argparse.ArgumentTypeError(f"unsupported tables: {', '.join(invalid)}")
    return tables


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Migrate SQLite honeypot data to MongoDB without modifying SQLite",
    )
    parser.add_argument(
        "--sqlite",
        required=True,
        help="SQLite path or sqlite:/// URL (opened read-only)",
    )
    parser.add_argument(
        "--mongodb-uri",
        default=os.getenv("MONGODB_URI", ""),
        help="MongoDB URI; defaults to MONGODB_URI (never printed)",
    )
    parser.add_argument(
        "--mongodb-database",
        default=os.getenv("MONGODB_DATABASE", ""),
        help="MongoDB database; defaults to MONGODB_DATABASE",
    )
    parser.add_argument("--migration-id", default=DEFAULT_MIGRATION_ID)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--sample-size", type=int, default=DEFAULT_SAMPLE_SIZE)
    parser.add_argument("--tables", type=_parse_tables, default=MIGRATION_TABLES)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate SQLite and BSON conversion without connecting to or writing MongoDB",
    )
    parser.add_argument(
        "--restart",
        action="store_true",
        help="clear matching migration checkpoints and reconcile every source row again",
    )
    parser.add_argument(
        "--allow-target-extras",
        action="store_true",
        help="accept target counts greater than source counts during validation",
    )
    parser.add_argument(
        "--continue-on-error",
        action="store_true",
        help="continue migrating later tables after a table failure",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.batch_size < 1:
        parser.error("--batch-size must be at least 1")
    if args.sample_size < 0:
        parser.error("--sample-size must not be negative")
    if not args.dry_run and (not args.mongodb_uri or not args.mongodb_database):
        parser.error(
            "--mongodb-uri and --mongodb-database are required unless --dry-run is used"
        )
    try:
        target = None
        if not args.dry_run:
            target = MongoStorage(args.mongodb_uri, args.mongodb_database)
            target.initialize()
            health = target.health_check()
            if not health.get("ok"):
                raise MigrationError(
                    f"MongoDB health check failed: {health.get('error', 'unknown error')}"
                )
        migrator = SQLiteToMongoMigrator(
            sqlite_path_from_value(args.sqlite),
            target,
            migration_id=args.migration_id,
            batch_size=args.batch_size,
            sample_size=args.sample_size,
            tables=args.tables,
            dry_run=args.dry_run,
            restart=args.restart,
            strict_counts=not args.allow_target_extras,
            continue_on_error=args.continue_on_error,
        )
        report = migrator.run()
    except Exception as exc:
        report = {
            "ok": False,
            "dry_run": bool(args.dry_run),
            "source_deleted": False,
            "failures": [{"stage": "startup", "error": _safe_error(exc)}],
        }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
