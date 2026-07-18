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

from production.storage.contract import (
    validate_event_effect_summary,
    validate_event_failure_fields,
)
from production.storage.mongodb import (
    ALLOWED_TABLES,
    MONGODB_SCHEMA_VERSION,
    MongoStorage,
    _safe_error,
    document_from_sqlite_row,
    from_bson_safe,
    row_from_document,
)
from production.utils.serialization import stable_json, utc_now


DEFAULT_MIGRATION_ID = "sqlite-to-mongodb-v2"
DEFAULT_BATCH_SIZE = 1000
DEFAULT_SAMPLE_SIZE = 3

# These are runtime fencing records, not durable domain state.  Carrying them
# across backends could make a new worker believe that an owner from the old
# deployment still has authority.  Cutovers must quiesce workers and let the
# destination acquire fresh leases instead.
EXCLUDED_EPHEMERAL_TABLES: tuple[Dict[str, str], ...] = (
    {
        "source_table": "worker_leases",
        "target_collection": "_storage_leases",
        "reason": (
            "ephemeral worker fencing state is deployment-local and must be "
            "reacquired after writers are quiesced; it is never migrated"
        ),
    },
)

EVENT_LIFECYCLE_SCALAR_FIELDS: tuple[str, ...] = (
    "claim_owner",
    "claim_token",
    "claim_leader_scope",
    "claim_leader_token",
    "claim_expires_at",
    "attempts",
    "next_retry_at",
    "last_error_code",
    "last_error_type",
    "last_error_at",
    "processing_outcome",
    "processed_at",
)
EVENT_LIFECYCLE_SOURCE_FIELDS: tuple[str, ...] = (
    "processed",
    *EVENT_LIFECYCLE_SCALAR_FIELDS,
    "effect_summary_json",
)

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


class MigrationSourceChangedError(MigrationError):
    """A stable operator-actionable checkpoint/source mismatch."""


class MigrationPreflightError(MigrationError):
    """A safe, field-only source validation failure raised before target writes."""

    def __init__(self, table: str, message: str):
        super().__init__(message)
        self.table = table


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
        self.target_schema_version = MONGODB_SCHEMA_VERSION
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
            (
                f"{self.migration_id}\0{self.target_schema_version}\0"
                f"{self.source.source_id}\0{table}"
            ).encode("utf-8")
        ).hexdigest()

    def _load_checkpoint(self, table: str) -> Optional[Dict[str, Any]]:
        if self.dry_run or self.target is None:
            return None
        expected_id = self._checkpoint_id(table)
        checkpoints = list(
            self.checkpoints.find(
                {"migration_id": self.migration_id, "table": table}
            )
        )
        checkpoint_by_id = self.checkpoints.find_one({"_id": expected_id})
        if checkpoint_by_id and not any(
            item.get("_id") == expected_id for item in checkpoints
        ):
            checkpoints.append(checkpoint_by_id)
        if len(checkpoints) > 1:
            raise MigrationSourceChangedError(
                f"multiple incompatible checkpoints exist for table {table}; "
                "rerun with --restart or choose a new --migration-id"
            )
        checkpoint = checkpoints[0] if checkpoints else None
        if checkpoint and (
            checkpoint.get("migration_id") != self.migration_id
            or checkpoint.get("table") != table
        ):
            raise MigrationSourceChangedError(
                f"checkpoint metadata is missing or incompatible for table {table}; "
                "rerun with --restart or choose a new --migration-id"
            )
        if checkpoint and checkpoint.get("_id") != expected_id:
            raise MigrationSourceChangedError(
                f"checkpoint identity is obsolete for table {table}; rerun with "
                "--restart or choose a new --migration-id"
            )
        if checkpoint and (
            type(checkpoint.get("target_schema_version")) is not int
            or checkpoint.get("target_schema_version") != self.target_schema_version
        ):
            raise MigrationSourceChangedError(
                f"checkpoint target schema is missing or incompatible for table {table}; "
                "rerun with --restart or choose a new --migration-id"
            )
        if checkpoint and checkpoint.get("source_id") != self.source.source_id:
            raise MigrationSourceChangedError(
                f"checkpoint source identity mismatch for table {table}; rerun with "
                "--restart or choose a new --migration-id"
            )
        if checkpoint and (
            int(checkpoint.get("source_size_bytes") or -1) != self.source.size_bytes
            or int(checkpoint.get("source_modified_ns") or -1) != self.source.modified_ns
            or int(checkpoint.get("source_wal_size_bytes") or 0) != self.source.wal_size_bytes
            or int(checkpoint.get("source_wal_modified_ns") or -1)
            != self.source.wal_modified_ns
        ):
            raise MigrationSourceChangedError(
                f"SQLite source changed after the {table} checkpoint; rerun with "
                "--restart or choose a new --migration-id"
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
            "target_schema_version": self.target_schema_version,
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
                "$or": [
                    {
                        "migration_id": self.migration_id,
                        "table": {"$in": list(self.tables)},
                    },
                    {
                        "_id": {
                            "$in": [self._checkpoint_id(table) for table in self.tables]
                        }
                    },
                ]
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

    def _event_lifecycle_samples(
        self,
        connection: sqlite3.Connection,
        samples: Sequence[Mapping[str, Any]],
    ) -> list[Dict[str, Any]]:
        """Add one deterministic sample for every lifecycle state present."""

        selected = [dict(row) for row in samples]
        seen = {int(row["__rowid__"]) for row in selected}
        columns = {
            str(row["name"])
            for row in connection.execute('PRAGMA table_info("events")').fetchall()
        }
        if not set(EVENT_LIFECYCLE_SOURCE_FIELDS).issubset(columns):
            if not selected:
                row = connection.execute(
                    'SELECT rowid AS __rowid__, * FROM "events" ORDER BY rowid LIMIT 1'
                ).fetchone()
                if row is not None:
                    selected.append(dict(row))
            return selected

        conditions = (
            (
                "pending",
                "processed = 0 AND COALESCE(processing_outcome, '') = '' "
                "AND COALESCE(claim_owner, '') = '' "
                "AND COALESCE(claim_token, '') = '' "
                "AND COALESCE(claim_expires_at, '') = ''",
            ),
            (
                "claimed",
                "processed = 0 AND COALESCE(processing_outcome, '') != 'retry_scheduled' "
                "AND (COALESCE(claim_owner, '') != '' OR COALESCE(claim_token, '') != '' "
                "OR COALESCE(claim_expires_at, '') != '')",
            ),
            ("retry_scheduled", "processed = 0 AND processing_outcome = 'retry_scheduled'"),
            ("succeeded", "processed != 0 AND processing_outcome = 'succeeded'"),
            ("dead_letter", "processed != 0 AND processing_outcome = 'dead_letter'"),
            (
                "processed_legacy",
                "processed != 0 AND COALESCE(processing_outcome, '') NOT IN "
                "('succeeded', 'dead_letter')",
            ),
        )
        present_states = {self._lifecycle_state(row) for row in selected}
        for state, condition in conditions:
            if state in present_states:
                continue
            row = connection.execute(
                f"SELECT rowid AS __rowid__, * FROM events WHERE {condition} "
                "ORDER BY rowid LIMIT 1"
            ).fetchone()
            if row is None or int(row["__rowid__"]) in seen:
                continue
            selected.append(dict(row))
            seen.add(int(row["__rowid__"]))
            present_states.add(state)
        return selected

    @staticmethod
    def _lifecycle_failure(
        source_row: Mapping[str, Any],
        field: str,
        reason: str,
        *,
        state: str = "",
    ) -> Dict[str, Any]:
        failure: Dict[str, Any] = {
            "rowid": int(source_row["__rowid__"]),
            "field": field,
            "reason": reason,
        }
        if state:
            failure["state"] = state
        return failure

    @staticmethod
    def _lifecycle_state(row: Mapping[str, Any]) -> str:
        processed = row.get("processed") in (True, 1)
        outcome = row.get("processing_outcome")
        if processed and outcome == "dead_letter":
            return "dead_letter"
        if processed and outcome == "succeeded":
            return "succeeded"
        if processed:
            return "processed_legacy"
        if outcome == "retry_scheduled":
            return "retry_scheduled"
        if row.get("claim_owner") or row.get("claim_token") or row.get("claim_expires_at"):
            return "claimed"
        return "pending"

    def _event_source_expectation(
        self,
        source_row: Mapping[str, Any],
    ) -> tuple[str, Dict[str, Any], list[Dict[str, Any]]]:
        state = self._lifecycle_state(source_row)
        failures: list[Dict[str, Any]] = []

        def fail(field: str, reason: str) -> None:
            failures.append(
                self._lifecycle_failure(source_row, field, reason, state=state)
            )

        for field in EVENT_LIFECYCLE_SOURCE_FIELDS:
            if field not in source_row:
                fail(field, "required_source_field_missing")

        processed = source_row.get("processed")
        if type(processed) is not int or processed not in (0, 1):
            fail("processed", "source_value_must_be_integer_zero_or_one")
        attempts = source_row.get("attempts")
        if type(attempts) is not int or attempts < 0:
            fail("attempts", "source_value_must_be_non_negative_integer")

        text_fields = tuple(
            field for field in EVENT_LIFECYCLE_SCALAR_FIELDS if field != "attempts"
        )
        for field in text_fields:
            value = source_row.get(field)
            if value is not None and not isinstance(value, str):
                fail(field, "source_value_must_be_text_or_null")

        raw_summary = source_row.get("effect_summary_json")
        summary: Any = None
        if raw_summary not in (None, ""):
            try:
                summary = json.loads(raw_summary) if isinstance(raw_summary, str) else None
            except (TypeError, ValueError):
                summary = None
            if not isinstance(summary, dict):
                fail("effect_summary_json", "source_value_must_be_json_object_or_null")
            else:
                try:
                    summary = validate_event_effect_summary(summary)
                except ValueError:
                    summary = None
                    fail(
                        "effect_summary_json",
                        "source_value_violates_runtime_effect_summary_policy",
                    )

        error_code = source_row.get("last_error_code")
        error_type = source_row.get("last_error_type")
        has_error_code = error_code not in (None, "")
        has_error_type = error_type not in (None, "")
        if has_error_code != has_error_type:
            fail(
                "last_error_code" if has_error_code else "last_error_type",
                "error_code_and_type_must_be_set_together",
            )
        elif has_error_code and has_error_type:
            try:
                validate_event_failure_fields(error_code, error_type)
            except ValueError as exc:
                field = (
                    "last_error_type"
                    if str(exc).startswith("error_type")
                    else "last_error_code"
                )
                fail(field, "source_value_not_in_runtime_failure_registry")

        def require_present(fields: Sequence[str]) -> None:
            for field in fields:
                if source_row.get(field) in (None, ""):
                    fail(field, "required_for_lifecycle_state")

        def require_absent(fields: Sequence[str]) -> None:
            for field in fields:
                if source_row.get(field) not in (None, ""):
                    fail(field, "must_be_clear_for_lifecycle_state")

        claim_core = ("claim_owner", "claim_token", "claim_expires_at")
        claims = (
            "claim_owner",
            "claim_token",
            "claim_leader_scope",
            "claim_leader_token",
            "claim_expires_at",
        )
        if state == "claimed":
            require_present(claim_core)
            if bool(source_row.get("claim_leader_scope")) != bool(
                source_row.get("claim_leader_token")
            ):
                fail("claim_leader_token", "leader_scope_and_token_must_be_set_together")
        elif state == "retry_scheduled":
            require_present(
                ("next_retry_at", "last_error_code", "last_error_type", "last_error_at")
            )
            require_absent(claims)
        elif state == "succeeded":
            require_present(("processed_at",))
            require_absent(claims)
        elif state == "dead_letter":
            require_present(
                ("processed_at", "last_error_code", "last_error_type", "last_error_at")
            )
            require_absent(claims)
        elif state in {"pending", "processed_legacy"}:
            require_absent(claims)

        expected = {field: source_row.get(field) for field in text_fields}
        expected.update(
            {
                "processed": bool(processed) if processed in (0, 1) else None,
                "attempts": attempts,
                "effect_summary": summary,
                "schema_version": self.target_schema_version,
            }
        )
        return state, expected, failures

    def _preflight_event_source(
        self,
        connection: sqlite3.Connection,
    ) -> Dict[str, Any]:
        """Validate every event lifecycle row before any domain upsert."""

        source_count = int(
            connection.execute('SELECT COUNT(*) FROM "events"').fetchone()[0]
        )
        columns = {
            str(row["name"])
            for row in connection.execute('PRAGMA table_info("events")').fetchall()
        }
        missing = sorted(set(EVENT_LIFECYCLE_SOURCE_FIELDS) - columns)
        if missing:
            raise MigrationPreflightError(
                "events",
                "event lifecycle source preflight found missing required columns: "
                f"{', '.join(missing)}; initialize or upgrade the SQLite source before "
                "retrying; no checkpoints or destination documents were changed"
            )

        cursor = connection.execute(
            'SELECT rowid AS __rowid__, * FROM "events" ORDER BY rowid'
        )
        rows_checked = 0
        states_checked: Dict[str, int] = {}
        fetch_size = min(max(self.batch_size, 1000), 10_000)
        while True:
            rows = cursor.fetchmany(fetch_size)
            if not rows:
                break
            for row in rows:
                source_row = dict(row)
                state, _, failures = self._event_source_expectation(source_row)
                rows_checked += 1
                states_checked[state] = states_checked.get(state, 0) + 1
                if failures:
                    first = failures[0]
                    raise MigrationPreflightError(
                        "events",
                        "event lifecycle source preflight failed at "
                        f"rowid {first['rowid']} field {first['field']}: {first['reason']}; "
                        "no checkpoints or destination documents were changed"
                    )
                try:
                    document_from_sqlite_row("events", source_row)
                except Exception as exc:
                    raise MigrationPreflightError(
                        "events",
                        "events source conversion preflight failed at "
                        f"rowid {source_row['__rowid__']}: {_safe_error(exc)}; "
                        "no checkpoints or destination documents were changed",
                    ) from exc
        return {
            "performed": True,
            "source_count": source_count,
            "rows_checked": rows_checked,
            "conversion_rows_checked": rows_checked,
            "states_checked": states_checked,
            "required_source_fields": list(EVENT_LIFECYCLE_SOURCE_FIELDS),
            "ok": True,
        }

    def _preflight_table_source(
        self,
        connection: sqlite3.Connection,
        table: str,
    ) -> Dict[str, Any]:
        """Convert every selected source row before any destination mutation."""

        if not _table_exists(connection, table):
            return {
                "table": table,
                "performed": False,
                "reason": "source table does not exist",
                "source_count": 0,
                "rows_checked": 0,
                "conversion_rows_checked": 0,
                "ok": True,
            }
        if table == "events":
            report = self._preflight_event_source(connection)
            report["table"] = table
            return report

        source_count = int(
            connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
        )
        cursor = connection.execute(
            f'SELECT rowid AS __rowid__, * FROM "{table}" ORDER BY rowid'
        )
        rows_checked = 0
        fetch_size = min(max(self.batch_size, 1000), 10_000)
        while True:
            rows = cursor.fetchmany(fetch_size)
            if not rows:
                break
            for row in rows:
                source_row = dict(row)
                rows_checked += 1
                try:
                    document_from_sqlite_row(table, source_row)
                except Exception as exc:
                    raise MigrationPreflightError(
                        table,
                        f"{table} source conversion preflight failed at "
                        f"rowid {source_row['__rowid__']}: {_safe_error(exc)}; "
                        "no checkpoints or destination documents were changed",
                    ) from exc
        return {
            "table": table,
            "performed": True,
            "source_count": source_count,
            "rows_checked": rows_checked,
            "conversion_rows_checked": rows_checked,
            "ok": True,
        }

    def _event_lifecycle_report(
        self,
        samples: Sequence[Mapping[str, Any]],
        *,
        validate_target: bool,
    ) -> Dict[str, Any]:
        """Validate v2 event fields independently of the migration converter."""

        failures: list[Dict[str, Any]] = []
        states_checked: Dict[str, int] = {}
        events = self.target.database["events"] if validate_target and self.target else None

        for source_row in samples:
            state, expected, source_failures = self._event_source_expectation(source_row)
            states_checked[state] = states_checked.get(state, 0) + 1
            failures.extend(source_failures)
            if events is None:
                continue
            event_id = source_row.get("event_id")
            actual = events.find_one({"event_id": event_id}) if event_id else None
            if actual is None:
                failures.append(
                    self._lifecycle_failure(
                        source_row, "event_id", "target_document_missing", state=state
                    )
                )
                continue

            for field, expected_value in expected.items():
                if field not in actual:
                    failures.append(
                        self._lifecycle_failure(
                            source_row, field, "required_target_field_missing", state=state
                        )
                    )
                    continue
                actual_value = actual.get(field)
                invalid_reason = ""
                if field == "processed":
                    if type(actual_value) is not bool:
                        invalid_reason = "target_value_must_be_boolean"
                elif field in {"attempts", "schema_version"}:
                    if type(actual_value) is not int:
                        invalid_reason = "target_value_must_be_integer"
                    elif field == "attempts" and actual_value < 0:
                        invalid_reason = "target_value_must_be_non_negative_integer"
                elif field == "effect_summary":
                    actual_value = from_bson_safe(actual_value)
                    if actual_value is not None and not isinstance(actual_value, dict):
                        invalid_reason = "target_value_must_be_object_or_null"
                elif actual_value is not None and not isinstance(actual_value, str):
                    invalid_reason = "target_value_must_be_text_or_null"
                if invalid_reason:
                    failures.append(
                        self._lifecycle_failure(
                            source_row, field, invalid_reason, state=state
                        )
                    )
                if actual_value != expected_value:
                    reason = (
                        "target_schema_version_mismatch"
                        if field == "schema_version"
                        else "source_target_value_mismatch"
                    )
                    failures.append(
                        self._lifecycle_failure(source_row, field, reason, state=state)
                    )

        return {
            "performed": True,
            "source_validation_performed": True,
            "target_validation_performed": validate_target,
            "target_schema_version": self.target_schema_version,
            "required_source_fields": list(EVENT_LIFECYCLE_SOURCE_FIELDS),
            "samples_checked": len(samples),
            "states_checked": states_checked,
            "failures": failures,
            "ok": not failures,
        }

    def _validate_event_lifecycle_source_samples(
        self,
        samples: Sequence[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        return self._event_lifecycle_report(samples, validate_target=False)

    def _validate_event_lifecycle_samples(
        self,
        samples: Sequence[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        # Generic hashes use the canonical converter.  This check reads raw
        # MongoDB documents and derives expectations directly from SQLite.
        return self._event_lifecycle_report(samples, validate_target=True)

    def _validate_table(
        self,
        table: str,
        source_count: int,
        samples: Sequence[Mapping[str, Any]],
        lifecycle_samples: Optional[Sequence[Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        if self.dry_run or self.target is None:
            event_lifecycle = (
                self._validate_event_lifecycle_source_samples(
                    lifecycle_samples if lifecycle_samples is not None else samples
                )
                if table == "events"
                else {
                    "performed": False,
                    "reason": "not an event collection",
                    "target_schema_version": self.target_schema_version,
                    "samples_checked": 0,
                    "states_checked": {},
                    "failures": [],
                    "ok": True,
                }
            )
            return {
                "performed": False,
                "reason": "dry-run: no MongoDB writes or target validation",
                "source_count": source_count,
                "samples_checked": 0,
                "event_lifecycle": event_lifecycle,
                "ok": event_lifecycle["ok"],
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
        event_lifecycle = (
            self._validate_event_lifecycle_samples(
                lifecycle_samples if lifecycle_samples is not None else samples
            )
            if table == "events"
            else {
                "performed": False,
                "reason": "not an event collection",
                "target_schema_version": self.target_schema_version,
                "samples_checked": 0,
                "states_checked": {},
                "failures": [],
                "ok": True,
            }
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
            "event_lifecycle": event_lifecycle,
            "ok": count_ok and not sample_failures and event_lifecycle["ok"],
        }

    def migrate_table(
        self,
        connection: sqlite3.Connection,
        table: str,
        *,
        source_preflight: Optional[Mapping[str, Any]] = None,
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
            # Direct callers receive the same all-row source validation as
            # ``run``. The normal run path supplies a report produced during
            # the global preflight that precedes restart checkpoint deletion.
            if source_preflight is None:
                source_preflight = self._preflight_table_source(connection, table)
            source_preflight = dict(source_preflight)
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
            lifecycle_samples: Sequence[Mapping[str, Any]] = samples
            if table == "events" and source_count:
                # Lifecycle validation is mandatory even when generic hashes
                # are disabled, and samples each state independently.
                lifecycle_samples = self._event_lifecycle_samples(connection, samples)
            validation = self._validate_table(
                table,
                source_count,
                samples,
                lifecycle_samples,
            )
            validation["source_preflight"] = source_preflight
            if table == "events":
                validation["event_source_preflight"] = source_preflight
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
            error = (
                str(exc)
                if isinstance(exc, MigrationError)
                else _safe_error(exc)
            )
            failures.append({"last_rowid": last_rowid, "error": error})
            # A source-policy rejection must be a read-only operation against
            # both databases. In particular, do not create a failed checkpoint
            # that would undermine the preflight's zero-destination-write
            # guarantee.
            if checkpoint_loaded and not isinstance(exc, MigrationPreflightError):
                try:
                    self._save_checkpoint(
                        table,
                        last_rowid=last_rowid,
                        processed=processed_total,
                        status="failed",
                        source_count=source_count,
                        error=error,
                    )
                except Exception as checkpoint_exc:
                    failures.append(
                        {
                            "stage": "failed_checkpoint_audit",
                            "last_rowid": last_rowid,
                            "error": _safe_error(checkpoint_exc),
                        }
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
        checkpoints_cleared = 0
        table_reports: list[Dict[str, Any]] = []
        source_preflight: Dict[str, Dict[str, Any]] = {}
        run_failures: list[Dict[str, Any]] = []
        counter_names = (
            "inserted",
            "updated",
            "skipped",
            "duplicate",
            "invalid",
            "failed",
        )

        def empty_counters() -> Dict[str, int]:
            return {name: 0 for name in counter_names}

        with open_readonly_sqlite(self.sqlite_path) as connection:
            # One read transaction gives counts, rows, and samples a consistent
            # view. It does not modify the SQLite source.
            connection.execute("BEGIN")
            quick_check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
            if quick_check.lower() != "ok":
                run_failures.append(
                    {
                        "stage": "source_quick_check",
                        "status": "failed",
                        "error": "SQLite quick_check failed; no destination state changed",
                    }
                )

            if not run_failures:
                # Validate every selected table before restart checkpoint
                # deletion or the first destination upsert. This gives dry-run
                # and real migration the same source acceptance boundary.
                for table in self.tables:
                    try:
                        source_preflight[table] = self._preflight_table_source(
                            connection,
                            table,
                        )
                    except MigrationPreflightError as exc:
                        source_count = (
                            int(
                                connection.execute(
                                    f'SELECT COUNT(*) FROM "{table}"'
                                ).fetchone()[0]
                            )
                            if _table_exists(connection, table)
                            else 0
                        )
                        source_preflight[table] = {
                            "table": table,
                            "performed": True,
                            "source_count": source_count,
                            "ok": False,
                            "error": str(exc),
                        }
                    except Exception as exc:
                        source_count = (
                            int(
                                connection.execute(
                                    f'SELECT COUNT(*) FROM "{table}"'
                                ).fetchone()[0]
                            )
                            if _table_exists(connection, table)
                            else 0
                        )
                        source_preflight[table] = {
                            "table": table,
                            "performed": True,
                            "source_count": source_count,
                            "ok": False,
                            "error": (
                                f"{table} source preflight failed: {_safe_error(exc)}; "
                                "no checkpoints or destination documents were changed"
                            ),
                        }

            preflight_failed = any(
                not report.get("ok", False) for report in source_preflight.values()
            )
            if preflight_failed:
                for table in self.tables:
                    preflight = source_preflight[table]
                    failed = not preflight.get("ok", False)
                    table_reports.append(
                        {
                            "table": table,
                            "status": "failed" if failed else "not_started",
                            "source_count": int(
                                preflight.get("source_count", 0) or 0
                            ),
                            "last_rowid": 0,
                            "processed_this_run": 0,
                            "source_preflight": preflight,
                            "failures": (
                                [{"last_rowid": 0, "error": preflight["error"]}]
                                if failed
                                else []
                            ),
                            "counters": empty_counters(),
                            "message": (
                                "migration was not started because selected source "
                                "preflight failed"
                            ),
                        }
                    )
            elif not run_failures:
                try:
                    # ``--restart`` is deliberately delayed until quick-check
                    # and every selected-table preflight have succeeded.
                    checkpoints_cleared = self._clear_checkpoints()
                except Exception as exc:
                    run_failures.append(
                        {
                            "stage": "restart_checkpoint_clear",
                            "status": "failed",
                            "error": _safe_error(exc),
                        }
                    )

                if not run_failures:
                    for table in self.tables:
                        report = self.migrate_table(
                            connection,
                            table,
                            source_preflight=source_preflight[table],
                        )
                        table_reports.append(report)
                        if (
                            report["status"] in {"failed", "validation_failed"}
                            and not self.continue_on_error
                        ):
                            break
        failures = [
            {"table": item["table"], "status": item["status"], "failures": item.get("failures", [])}
            for item in table_reports
            if item["status"] in {"failed", "validation_failed"}
        ]
        failures.extend(run_failures)
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
            for name in counter_names
        }
        migration_completed = bool(
            not failures
            and len(table_reports) == len(self.tables)
            and all(
                item.get("status") in {"completed", "absent"}
                for item in table_reports
            )
        )
        return {
            "migration_id": self.migration_id,
            "target_schema_version": self.target_schema_version,
            "dry_run": self.dry_run,
            "restart": self.restart,
            "batch_size": self.batch_size,
            "sample_size": self.sample_size,
            "strict_counts": self.strict_counts,
            "source": self.source.public_summary(),
            "source_after": source_after.public_summary(),
            "source_changed_during_run": source_changed_during_run,
            "source_quick_check": (
                "ok" if quick_check.lower() == "ok" else "failed"
            ),
            "source_preflight": [
                source_preflight[table]
                for table in self.tables
                if table in source_preflight
            ],
            "checkpoints_cleared": checkpoints_cleared,
            "started_at": started_at,
            "completed_at": utc_now(),
            "tables": table_reports,
            "migration_tables": list(self.tables),
            "excluded_ephemeral_tables": [
                dict(item) for item in EXCLUDED_EPHEMERAL_TABLES
            ],
            "counters": aggregate_counters,
            "failures": failures,
            "migration_completed": migration_completed,
            "ok": migration_completed,
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
