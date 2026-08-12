from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
import stat
import uuid
from collections.abc import Mapping
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from production.storage.contract import (
    DatabaseConfigurationError,
    DatabaseSettings,
    MONGODB_BACKEND,
    SQLITE_BACKEND,
    StorageBackend,
    JOB_QUEUE_TABLES,
    OPERATIONAL_COUNT_TABLES,
    OPERATIONAL_QUEUE_NAMES,
    SESSION_ANALYSIS_FIELDS,
    validate_event_effect_summary,
    validate_event_failure_fields,
    validate_job_failure_fields,
    validate_webhook_completion_fields,
)
from production.storage.canonical_event import CanonicalEventRecord
from production.storage.job_materialization import (
    materialize_ai_advisory_job_claim,
    materialize_analysis_job_claim,
)
from production.utils.serialization import stable_id, stable_json, utc_now
from production.prediction.evidence_cutoff import (
    evidence_cutoff_sort_key,
    require_valid_evidence_cutoff,
)
from production.prediction.prediction_snapshot_contract import (
    SNAPSHOT_SCHEMA_VERSION,
    PredictionSnapshotIntegrityError,
    canonical_prediction_content,
    require_valid_prediction_snapshot,
    validate_prediction_snapshot_integrity,
)
from production.utils.feedback import normalize_feedback_payload
from production.utils.sensitive_data import redact_error_for_log
from production.storage.session_provenance import (
    SESSION_SOURCE_PRODUCTION_LIVE,
    SESSION_SOURCE_UNKNOWN_LEGACY,
    is_external_source_ip,
    normalize_session_source,
)


class StorageError(RuntimeError):
    pass


SQLITE_SCHEMA_VERSION = 3
AI_ADVISORY_SCHEMA_EXTENSION_ID = "non_authoritative_ai_advisory.v1"
AI_ADVISORY_RECONCILIATION_CURSOR_SCHEMA = (
    "ai_advisory_reconciliation_cursor.v1"
)
AI_ADVISORY_RECONCILIATION_CURSOR_MAX_BYTES = 4096
AI_ADVISORY_SCHEMA_OBJECTS = frozenset(
    {
        "ai_advisory_outbox",
        "ai_advisories",
        "idx_ai_advisory_outbox_claimable",
        "idx_ai_advisory_outbox_session",
        "idx_ai_advisories_session",
        "idx_ai_advisories_report",
    }
)


def _ai_advisory_schema_statements() -> tuple[str, ...]:
    """Return the additive AI schema kept outside the rollback-sensitive version."""

    return (
        """
        CREATE TABLE IF NOT EXISTS ai_advisory_outbox (
            job_id TEXT PRIMARY KEY,
            report_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            assessment_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued',
            payload_json TEXT NOT NULL,
            advisory_id TEXT,
            error TEXT,
            attempts INTEGER NOT NULL DEFAULT 0,
            next_retry_at TEXT,
            claim_owner TEXT,
            claim_token TEXT,
            claim_expires_at TEXT,
            completion_code TEXT,
            last_error_code TEXT,
            last_error_type TEXT,
            last_error_at TEXT,
            completed_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE (report_id, assessment_id)
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_ai_advisory_outbox_claimable
        ON ai_advisory_outbox(
            status, next_retry_at, claim_expires_at, created_at, job_id
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_ai_advisory_outbox_session
        ON ai_advisory_outbox(session_id, created_at, job_id)
        """,
        """
        CREATE TABLE IF NOT EXISTS ai_advisories (
            advisory_id TEXT PRIMARY KEY,
            cache_key TEXT NOT NULL UNIQUE,
            report_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            assessment_id TEXT NOT NULL,
            status TEXT NOT NULL,
            projection_sha256 TEXT NOT NULL,
            request_sha256 TEXT NOT NULL,
            response_sha256 TEXT NOT NULL,
            provider_id TEXT NOT NULL,
            model_id TEXT NOT NULL,
            prompt_sha256 TEXT NOT NULL,
            schema_sha256 TEXT NOT NULL,
            policy_sha256 TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            metrics_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_ai_advisories_session
        ON ai_advisories(session_id, created_at, advisory_id)
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_ai_advisories_report
        ON ai_advisories(report_id, created_at, advisory_id)
        """,
    )


def _sqlite_migration_definitions() -> tuple[tuple[int, str, tuple[str, ...]], ...]:
    return (
        (1, "establish_versioned_schema_ledger", ()),
        (
            2,
            "durable_prediction_outbox",
            (
                """
                CREATE TABLE IF NOT EXISTS prediction_outbox (
                    outbox_id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'queued',
                    payload_json TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_retry_at TEXT,
                    claim_owner TEXT,
                    claim_token TEXT,
                    claim_expires_at TEXT,
                    snapshot_id TEXT,
                    last_error_code TEXT,
                    last_error_type TEXT,
                    last_error_at TEXT,
                    completed_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """,
                """
                CREATE INDEX IF NOT EXISTS idx_prediction_outbox_claimable
                ON prediction_outbox(
                    status, next_retry_at, claim_expires_at, created_at, outbox_id
                )
                """,
                """
                CREATE INDEX IF NOT EXISTS idx_prediction_outbox_session
                ON prediction_outbox(session_id, created_at, outbox_id)
                """,
            ),
        ),
        (
            3,
            "data_lifecycle_policy_ledger",
            (
                """
                CREATE TABLE IF NOT EXISTS data_lifecycle_policy_ledger (
                    policy_sha256 TEXT PRIMARY KEY,
                    policy_id TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    effective_path TEXT NOT NULL,
                    activated_at TEXT NOT NULL
                )
                """,
            ),
        ),
    )


def _sqlite_migration_checksum(
    version: int,
    name: str,
    statements: tuple[str, ...],
) -> str:
    return hashlib.sha256(
        stable_json(
            {
                "version": version,
                "name": name,
                "statements": statements,
            }
        ).encode("utf-8")
    ).hexdigest()


def _decode_json(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    return json.loads(value)


def _decode_event_payload(value: Any) -> tuple[Dict[str, Any], str]:
    try:
        decoded = _decode_json(value)
        if not isinstance(decoded, Mapping):
            raise ValueError("event payload must be a mapping")
        payload = dict(decoded)
        return payload, stable_json(payload)
    except Exception as exc:
        raise ValueError("event payload is not a valid JSON mapping") from exc


def _safe_event_payload(value: Any) -> tuple[Dict[str, Any], str]:
    try:
        return _decode_event_payload(value)
    except ValueError:
        return {}, "{}"


def _prediction_row_payload(row: Mapping[str, Any]) -> Dict[str, Any]:
    raw = row.get("payload")
    if isinstance(raw, Mapping):
        return dict(raw)
    try:
        decoded = json.loads(str(row.get("payload_json") or "{}"))
    except (TypeError, json.JSONDecodeError):
        return {}
    return dict(decoded) if isinstance(decoded, Mapping) else {}


def _prediction_row_order(
    row: Mapping[str, Any],
) -> tuple[int, str, str, str]:
    """Return canonical currentness order; invalid declared cutoffs sort last."""

    payload = _prediction_row_payload(row)
    if payload.get("schema_version") == SNAPSHOT_SCHEMA_VERSION:
        if validate_prediction_snapshot_integrity(payload):
            return (-1, "", "", str(row.get("snapshot_id") or ""))
        if str(row.get("snapshot_id") or "") != str(
            payload.get("snapshot_id") or ""
        ):
            return (-1, "", "", str(row.get("snapshot_id") or ""))
    if "evidence_cutoff" in payload:
        try:
            cutoff = require_valid_evidence_cutoff(payload["evidence_cutoff"])
            cutoff_key = evidence_cutoff_sort_key(cutoff)
        except ValueError:
            return (-1, "", "", str(row.get("snapshot_id") or ""))
        if (
            str(payload.get("event_id") or "") != cutoff["event_id"]
            or str(row.get("event_id") or "") != cutoff["event_id"]
        ):
            return (-1, "", "", str(row.get("snapshot_id") or ""))
        return (
            1,
            cutoff_key[0],
            cutoff_key[1],
            str(row.get("snapshot_id") or ""),
        )
    return (
        0,
        str(row.get("created_at") or ""),
        str(row.get("event_id") or ""),
        str(row.get("snapshot_id") or ""),
    )


def _apply_analysis_status(
    payload: Dict[str, Any],
    status: str,
    updated_at: str,
    *,
    job_id: str = "",
    report_id: str = "",
    error: str = "",
    skip_reason: str = "",
) -> Dict[str, Any]:
    updated = dict(payload)
    updated["analysis_status"] = status
    updated["analysis_updated_at"] = updated_at
    if job_id:
        updated["analysis_job_id"] = job_id
    if report_id:
        updated["report_id"] = report_id
    if error:
        updated["analysis_error"] = error
    else:
        updated.pop("analysis_error", None)
    if skip_reason:
        updated["analysis_skip_reason"] = skip_reason
    elif status != "skipped":
        updated.pop("analysis_skip_reason", None)
    return updated


def _parse_dt(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        text = str(value).replace("Z", "+00:00")
        parsed = datetime.fromisoformat(text)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _is_future(value: Any) -> bool:
    parsed = _parse_dt(value)
    return bool(parsed and parsed > datetime.now(timezone.utc))


def _retry_at(seconds: float) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=max(seconds, 0))).isoformat()


def _utc_timestamp(value: Any = None) -> str:
    if value is None:
        parsed = datetime.now(timezone.utc)
    elif isinstance(value, datetime):
        parsed = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    else:
        parsed = _parse_dt(value)
        if parsed is None:
            raise ValueError("now must be an ISO-8601 timestamp or datetime")
    return parsed.astimezone(timezone.utc).isoformat()


def _future_timestamp(now: str, seconds: float, *, field: str) -> str:
    try:
        duration = float(seconds)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be a positive number") from exc
    if not math.isfinite(duration) or duration <= 0:
        raise ValueError(f"{field} must be a positive number")
    parsed = _parse_dt(now)
    if parsed is None:  # pragma: no cover - _utc_timestamp guarantees this
        raise ValueError("now must be a valid timestamp")
    return (parsed + timedelta(seconds=duration)).isoformat()


def _required_identity(value: str, field: str) -> str:
    normalized = str(value or "").strip()
    if not normalized or len(normalized) > 256:
        raise ValueError(f"{field} must be non-empty and at most 256 characters")
    return normalized


def _uuid_token(value: str, field: str) -> str:
    normalized = _required_identity(value, field)
    try:
        return str(uuid.UUID(normalized))
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"{field} must be a UUID fencing token") from exc


def _claim_leader_binding_matches(
    row: Any,
    leader_scope: str,
    leader_token: str,
) -> bool:
    stored_scope = str(row["claim_leader_scope"] or "")
    stored_token = str(row["claim_leader_token"] or "")
    if not stored_scope and not stored_token:
        return not leader_scope and not leader_token
    return stored_scope == leader_scope and stored_token == leader_token


def _optional_utc_timestamp(value: Any) -> Optional[str]:
    return _utc_timestamp(value) if value else None


PRIORITY_RANK = {"low": 0, "normal": 1, "high": 2, "urgent": 3}

SESSION_SCOPED_TABLE_ORDER = {
    "events": "received_at",
    "sessions": "updated_at",
    "alerts": "created_at",
    "analysis_jobs": "updated_at",
    "reports": "created_at",
    "ai_advisory_outbox": "updated_at",
    "ai_advisories": "created_at",
    "enrichment_jobs": "updated_at",
    "prediction_snapshots": "created_at",
    "prediction_outbox": "updated_at",
    "analyst_feedback": "created_at",
    "classification_review_labels": "created_at",
    "observable_sightings": "created_at",
    "threat_hunt_jobs": "updated_at",
    "campaign_sessions": "created_at",
}


def _normalize_priority(priority: str) -> str:
    value = str(priority or "normal").strip().lower()
    return value if value in PRIORITY_RANK else "normal"


def _payload_session_source(session_payload: Dict[str, Any]) -> str:
    return normalize_session_source(session_payload.get("session_source"), SESSION_SOURCE_UNKNOWN_LEGACY)


class SQLiteStorage:
    """SQLite-backed pilot storage and durable queue.

    The schema mirrors the Postgres pilot schema closely enough for local tests and
    single-node deployments. Cloud SQL Postgres can use the SQL schema in
    `production/storage/postgres_schema.sql`.
    """

    def __init__(self, database_url: str = "sqlite:///production_state.db"):
        if not database_url.startswith("sqlite:///"):
            raise StorageError("SQLiteStorage requires sqlite:///DATABASE_PATH")
        self.path = Path(database_url.replace("sqlite:///", "", 1))
        if self.path.parent and str(self.path.parent) != ".":
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30.0)
        os.chmod(self.path, 0o600)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        conn = self.connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize(self) -> None:
        with self.connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    sensor_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    eventid TEXT NOT NULL,
                    timestamp TEXT,
                    payload_json TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    processed INTEGER NOT NULL DEFAULT 0,
                    claim_owner TEXT,
                    claim_token TEXT,
                    claim_leader_scope TEXT,
                    claim_leader_token TEXT,
                    claim_expires_at TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_retry_at TEXT,
                    last_error_code TEXT,
                    last_error_type TEXT,
                    last_error_at TEXT,
                    processing_outcome TEXT,
                    processed_at TEXT,
                    effect_summary_json TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_events_processed ON events(processed, received_at);
                CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);

                CREATE TABLE IF NOT EXISTS worker_leases (
                    scope TEXT PRIMARY KEY,
                    owner TEXT NOT NULL,
                    token TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    src_ip TEXT NOT NULL,
                    start_time TEXT,
                    ended INTEGER NOT NULL DEFAULT 0,
                    session_source TEXT NOT NULL DEFAULT 'unknown_legacy',
                    is_external_source INTEGER NOT NULL DEFAULT 0,
                    revision INTEGER NOT NULL DEFAULT 0,
                    payload_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    delivered INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS analysis_jobs (
                    job_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    report_id TEXT,
                    error TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_retry_at TEXT,
                    claim_owner TEXT,
                    claim_token TEXT,
                    claim_expires_at TEXT,
                    last_error_code TEXT,
                    last_error_type TEXT,
                    last_error_at TEXT,
                    completed_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS reports (
                    report_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS feed_status (
                    name TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS observables (
                    observable_type TEXT NOT NULL,
                    observable_value TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    sighting_count INTEGER NOT NULL DEFAULT 0,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY (observable_type, observable_value)
                );
                CREATE INDEX IF NOT EXISTS idx_observables_last_seen
                    ON observables(last_seen);

                CREATE TABLE IF NOT EXISTS observable_sightings (
                    sighting_id TEXT PRIMARY KEY,
                    observable_type TEXT NOT NULL,
                    observable_value TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    sensor_id TEXT,
                    src_ip TEXT,
                    event_id TEXT,
                    eventid TEXT,
                    role TEXT NOT NULL,
                    source TEXT NOT NULL,
                    timestamp TEXT,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_observable_sightings_observable
                    ON observable_sightings(observable_type, observable_value, created_at);
                CREATE INDEX IF NOT EXISTS idx_observable_sightings_session
                    ON observable_sightings(session_id, created_at);

                CREATE TABLE IF NOT EXISTS enrichment_records (
                    observable_type TEXT NOT NULL,
                    observable_value TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    provider_status_json TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    expires_at TEXT,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (observable_type, observable_value)
                );
                CREATE INDEX IF NOT EXISTS idx_enrichment_records_expires
                    ON enrichment_records(expires_at);

                CREATE TABLE IF NOT EXISTS enrichment_jobs (
                    job_id TEXT PRIMARY KEY,
                    observable_type TEXT NOT NULL,
                    observable_value TEXT NOT NULL,
                    session_id TEXT,
                    status TEXT NOT NULL,
                    priority TEXT NOT NULL DEFAULT 'normal',
                    priority_reason TEXT,
                    payload_json TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_retry_at TEXT,
                    claim_owner TEXT,
                    claim_token TEXT,
                    claim_expires_at TEXT,
                    last_error_code TEXT,
                    last_error_type TEXT,
                    last_error_at TEXT,
                    completed_at TEXT,
                    error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE (observable_type, observable_value)
                );
                CREATE INDEX IF NOT EXISTS idx_enrichment_jobs_status
                    ON enrichment_jobs(status, next_retry_at, created_at);

                CREATE TABLE IF NOT EXISTS webhook_deliveries (
                    delivery_id TEXT PRIMARY KEY,
                    alert_id TEXT,
                    report_id TEXT,
                    target_url_hash TEXT NOT NULL,
                    status TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    error_code TEXT,
                    next_retry_at TEXT,
                    claim_owner TEXT,
                    claim_token TEXT,
                    claim_expires_at TEXT,
                    response_status INTEGER,
                    response_body_sha256 TEXT,
                    response_body_bytes INTEGER NOT NULL DEFAULT 0,
                    response_body_truncated INTEGER NOT NULL DEFAULT 0,
                    completed_at TEXT,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS prediction_snapshots (
                    snapshot_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    session_status TEXT NOT NULL,
                    event_id TEXT,
                    features_hash TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_prediction_snapshots_session
                    ON prediction_snapshots(session_id, created_at);
                CREATE INDEX IF NOT EXISTS idx_prediction_snapshots_created
                    ON prediction_snapshots(created_at);

                CREATE TABLE IF NOT EXISTS prediction_backtest_runs (
                    run_id TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_prediction_backtest_runs_created
                    ON prediction_backtest_runs(created_at);

                CREATE TABLE IF NOT EXISTS prediction_calibration_runs (
                    run_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    applied INTEGER NOT NULL DEFAULT 0,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_prediction_calibration_runs_created
                    ON prediction_calibration_runs(created_at);

                CREATE TABLE IF NOT EXISTS analyst_feedback (
                    feedback_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    snapshot_id TEXT,
                    label TEXT NOT NULL,
                    feedback_type TEXT NOT NULL DEFAULT 'operator_usefulness',
                    operator_signal TEXT,
                    action_status TEXT,
                    label_authority TEXT,
                    evidence_confidence REAL,
                    evidence_origin TEXT NOT NULL DEFAULT 'live_cowrie',
                    weight_eligible INTEGER NOT NULL DEFAULT 0,
                    correct_next_tactic TEXT,
                    observed_prefix TEXT,
                    predicted_top_tactic TEXT,
                    predicted_ranking TEXT,
                    final_actual_next_tactic TEXT,
                    tactic_granularity TEXT NOT NULL DEFAULT 'tactic',
                    analyst_corrected_at TEXT,
                    notes TEXT,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_analyst_feedback_session
                    ON analyst_feedback(session_id, created_at);

                CREATE TABLE IF NOT EXISTS classification_review_labels (
                    label_id TEXT PRIMARY KEY,
                    review_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    command_index INTEGER NOT NULL DEFAULT 0,
                    command TEXT NOT NULL,
                    predicted_ttp TEXT,
                    predicted_tactic TEXT,
                    predicted_source TEXT,
                    predicted_confidence REAL,
                    reviewed_ttp TEXT,
                    reviewed_tactic TEXT,
                    reviewer TEXT,
                    notes TEXT,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_classification_review_session
                    ON classification_review_labels(session_id, created_at);
                CREATE INDEX IF NOT EXISTS idx_classification_review_review_id
                    ON classification_review_labels(review_id);

                CREATE TABLE IF NOT EXISTS threat_hunt_jobs (
                    job_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    observable_type TEXT NOT NULL,
                    observable_value TEXT NOT NULL,
                    trigger_reason TEXT,
                    status TEXT NOT NULL DEFAULT 'queued',
                    result_json TEXT,
                    payload_json TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_retry_at TEXT,
                    claim_owner TEXT,
                    claim_token TEXT,
                    claim_expires_at TEXT,
                    last_error_code TEXT,
                    last_error_type TEXT,
                    last_error_at TEXT,
                    completed_at TEXT,
                    error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE (session_id, observable_type, observable_value)
                );
                CREATE INDEX IF NOT EXISTS idx_threat_hunt_jobs_status
                    ON threat_hunt_jobs(status, created_at);
                CREATE INDEX IF NOT EXISTS idx_threat_hunt_jobs_observable
                    ON threat_hunt_jobs(observable_type, observable_value);

                CREATE TABLE IF NOT EXISTS session_links (
                    link_id TEXT PRIMARY KEY,
                    session_id_a TEXT NOT NULL,
                    session_id_b TEXT NOT NULL,
                    link_type TEXT NOT NULL,
                    observable_type TEXT,
                    observable_value TEXT,
                    confidence REAL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_session_links_session_a
                    ON session_links(session_id_a, created_at);
                CREATE INDEX IF NOT EXISTS idx_session_links_session_b
                    ON session_links(session_id_b, created_at);
                CREATE INDEX IF NOT EXISTS idx_session_links_observable
                    ON session_links(observable_type, observable_value);

                CREATE TABLE IF NOT EXISTS campaigns (
                    campaign_id TEXT PRIMARY KEY,
                    primary_fingerprint_type TEXT,
                    primary_fingerprint_value TEXT,
                    hassh_fingerprint TEXT,
                    ja3_fingerprint TEXT,
                    tactic_sequence_hash TEXT,
                    command_pattern_hash TEXT,
                    source_ip TEXT,
                    session_count INTEGER NOT NULL DEFAULT 0,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    confirmed_tactics_json TEXT NOT NULL,
                    max_confirmed_severity TEXT NOT NULL DEFAULT 'info',
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_campaigns_hassh
                    ON campaigns(hassh_fingerprint);
                CREATE INDEX IF NOT EXISTS idx_campaigns_ja3
                    ON campaigns(ja3_fingerprint);
                CREATE INDEX IF NOT EXISTS idx_campaigns_command_pattern
                    ON campaigns(command_pattern_hash);
                CREATE INDEX IF NOT EXISTS idx_campaigns_tactic_sequence
                    ON campaigns(tactic_sequence_hash);
                CREATE INDEX IF NOT EXISTS idx_campaigns_source_ip
                    ON campaigns(source_ip);

                CREATE TABLE IF NOT EXISTS campaign_sessions (
                    link_id TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    match_reasons_json TEXT NOT NULL,
                    confidence REAL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE (campaign_id, session_id)
                );
                CREATE INDEX IF NOT EXISTS idx_campaign_sessions_campaign
                    ON campaign_sessions(campaign_id, created_at);
                CREATE INDEX IF NOT EXISTS idx_campaign_sessions_session
                    ON campaign_sessions(session_id, created_at);
                """
            )
            self._ensure_sqlite_event_processing_columns(conn)
            self._ensure_sqlite_job_processing_columns(conn)
            self._ensure_sqlite_session_source_column(conn)
            self._ensure_sqlite_enrichment_priority_columns(conn)
            self._ensure_sqlite_webhook_delivery_columns(conn)
            self._run_sqlite_migrations(conn)
            # The AI advisory extension is optional and must never participate
            # in canonical storage readiness.  It is initialized explicitly by
            # the AI worker/activation preflight instead.

    def _run_sqlite_migrations(self, conn: sqlite3.Connection) -> None:
        """Apply additive, checksummed migrations in one transaction each."""

        check = conn.execute("PRAGMA quick_check").fetchone()
        if not check or str(check[0]).lower() != "ok":
            raise StorageError("SQLite quick_check failed before migration")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                checksum TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
            """
        )
        current_user_version = int(
            conn.execute("PRAGMA user_version").fetchone()[0]
        )
        if current_user_version > SQLITE_SCHEMA_VERSION:
            raise StorageError("SQLite schema is newer than this release")
        applied = {
            int(row["version"]): dict(row)
            for row in conn.execute(
                "SELECT version, name, checksum FROM schema_migrations"
            ).fetchall()
        }
        if any(version > SQLITE_SCHEMA_VERSION for version in applied):
            raise StorageError("SQLite migration ledger is newer than this release")
        for version, name, statements in _sqlite_migration_definitions():
            checksum = _sqlite_migration_checksum(version, name, statements)
            existing = applied.get(version)
            if existing:
                if (
                    existing.get("name") != name
                    or existing.get("checksum") != checksum
                ):
                    raise StorageError(
                        f"SQLite migration {version} checksum mismatch"
                    )
                continue
            conn.execute("SAVEPOINT sqlite_schema_migration")
            try:
                for statement in statements:
                    conn.execute(statement)
                conn.execute(
                    """
                    INSERT INTO schema_migrations
                    (version, name, checksum, applied_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (version, name, checksum, utc_now()),
                )
                conn.execute(f"PRAGMA user_version={version}")
                conn.execute("RELEASE SAVEPOINT sqlite_schema_migration")
            except Exception:
                conn.execute("ROLLBACK TO SAVEPOINT sqlite_schema_migration")
                conn.execute("RELEASE SAVEPOINT sqlite_schema_migration")
                raise
        final_check = conn.execute("PRAGMA quick_check").fetchone()
        if not final_check or str(final_check[0]).lower() != "ok":
            raise StorageError("SQLite quick_check failed after migration")

    def _ensure_ai_advisory_schema(self, conn: sqlite3.Connection) -> None:
        """Install a checksummed optional extension without breaking old releases.

        The previous verified runtime rejects a higher ``PRAGMA user_version``.
        Keeping this additive schema in a separate ledger means rollback code can
        continue to open the database and safely ignore the new tables.
        """

        statements = _ai_advisory_schema_statements()
        checksum = hashlib.sha256(
            stable_json(
                {
                    "extension_id": AI_ADVISORY_SCHEMA_EXTENSION_ID,
                    "statements": statements,
                }
            ).encode("utf-8")
        ).hexdigest()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_extensions (
                extension_id TEXT PRIMARY KEY,
                checksum TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
            """
        )
        existing = conn.execute(
            """
            SELECT checksum FROM schema_extensions WHERE extension_id = ?
            """,
            (AI_ADVISORY_SCHEMA_EXTENSION_ID,),
        ).fetchone()
        if existing:
            if str(existing["checksum"]) != checksum:
                raise StorageError("AI advisory schema extension checksum mismatch")
            self._verify_ai_advisory_schema_objects(conn)
            return

        conn.execute("SAVEPOINT ai_advisory_schema_extension")
        try:
            for statement in statements:
                conn.execute(statement)
            conn.execute(
                """
                INSERT INTO schema_extensions (extension_id, checksum, applied_at)
                VALUES (?, ?, ?)
                """,
                (AI_ADVISORY_SCHEMA_EXTENSION_ID, checksum, utc_now()),
            )
            conn.execute("RELEASE SAVEPOINT ai_advisory_schema_extension")
        except Exception:
            conn.execute("ROLLBACK TO SAVEPOINT ai_advisory_schema_extension")
            conn.execute("RELEASE SAVEPOINT ai_advisory_schema_extension")
            raise
        self._verify_ai_advisory_schema_objects(conn)
        final_check = conn.execute("PRAGMA quick_check").fetchone()
        if not final_check or str(final_check[0]).lower() != "ok":
            raise StorageError("SQLite quick_check failed after AI schema extension")

    def initialize_ai_advisory_extension(self) -> None:
        """Initialize the optional AI-only schema without coupling canonical startup."""

        with self.connection() as conn:
            self._ensure_ai_advisory_schema(conn)

    def verify_existing_schema(self) -> None:
        """Fail closed on an untrusted canonical schema without scanning data.

        This is the bounded readiness path for an optional worker joining an
        already initialized production database.  Canonical deployment and
        migration paths continue to use :meth:`initialize`, including its full
        integrity checks.
        """

        try:
            metadata = self.path.lstat()
        except FileNotFoundError as exc:
            raise StorageError("SQLite database does not exist") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise StorageError("SQLite database is not a regular file")
        if metadata.st_uid != os.geteuid():
            raise StorageError("SQLite database owner does not match the worker")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise StorageError("SQLite database permissions are unsafe")

        database_uri = f"{self.path.resolve().as_uri()}?mode=ro"
        conn = sqlite3.connect(database_uri, uri=True, timeout=5.0)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only=ON")
            user_version = int(conn.execute("PRAGMA user_version").fetchone()[0])
            if user_version != SQLITE_SCHEMA_VERSION:
                raise StorageError("SQLite schema version is not ready")
            required_tables = {
                "events",
                "sessions",
                "analysis_jobs",
                "reports",
                "schema_migrations",
            }
            present_tables = {
                str(item["name"])
                for item in conn.execute(
                    """
                    SELECT name FROM sqlite_master
                    WHERE type = 'table'
                      AND name IN (?, ?, ?, ?, ?)
                    """,
                    tuple(sorted(required_tables)),
                ).fetchall()
            }
            if present_tables != required_tables:
                raise StorageError("SQLite canonical schema is incomplete")
            applied = [
                (int(row["version"]), str(row["name"]), str(row["checksum"]))
                for row in conn.execute(
                    """
                    SELECT version, name, checksum FROM schema_migrations
                    ORDER BY version
                    """
                ).fetchall()
            ]
        finally:
            conn.close()

        expected = [
            (version, name, _sqlite_migration_checksum(version, name, statements))
            for version, name, statements in _sqlite_migration_definitions()
        ]
        if applied != expected:
            raise StorageError("SQLite migration ledger is not ready")

    @staticmethod
    def _verify_ai_advisory_schema_objects(conn: sqlite3.Connection) -> None:
        rows = conn.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type IN ('table', 'index')
              AND name IN (?, ?, ?, ?, ?, ?)
            """,
            tuple(sorted(AI_ADVISORY_SCHEMA_OBJECTS)),
        ).fetchall()
        present = {str(row["name"]) for row in rows}
        if present != set(AI_ADVISORY_SCHEMA_OBJECTS):
            raise StorageError("AI advisory schema extension is incomplete")

    def health_check(self) -> Dict[str, Any]:
        # Readiness must never acquire a schema-write transaction or repeat
        # migration work.  In particular, do not call ``self.connection()``
        # here: that normal operational path enforces file mode and write-side
        # PRAGMAs before yielding a connection.
        database_uri = f"{self.path.resolve().as_uri()}?mode=ro"
        conn = sqlite3.connect(database_uri, uri=True, timeout=5.0)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only=ON")
            user_version = int(conn.execute("PRAGMA user_version").fetchone()[0])
            required_tables = {
                "events",
                "sessions",
                "analysis_jobs",
                "reports",
                "schema_migrations",
            }
            present_tables = {
                str(item["name"])
                for item in conn.execute(
                    """
                    SELECT name FROM sqlite_master
                    WHERE type = 'table'
                      AND name IN (?, ?, ?, ?, ?)
                    """,
                    tuple(sorted(required_tables)),
                ).fetchall()
            }
            row = conn.execute("SELECT 1 AS ready").fetchone()
        finally:
            conn.close()
        return {
            "ok": bool(
                row
                and int(row["ready"]) == 1
                and user_version == SQLITE_SCHEMA_VERSION
                and present_tables == required_tables
            ),
            "backend": SQLITE_BACKEND,
        }

    def operational_metrics(self, *, now: Any = None) -> Dict[str, Any]:
        checked_at = _utc_timestamp(now)
        with self.connection() as conn:
            collection_counts = {
                table: int(
                    conn.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()[
                        "count"
                    ]
                )
                for table in OPERATIONAL_COUNT_TABLES
            }
            event_counts = {
                (str(row["processing_outcome"] or "pending")):
                int(row["count"])
                for row in conn.execute(
                    """
                    SELECT processing_outcome, COUNT(*) AS count
                    FROM events GROUP BY processing_outcome
                    """
                ).fetchall()
            }
            webhook_status = {
                str(row["status"]): int(row["count"])
                for row in conn.execute(
                    "SELECT status, COUNT(*) AS count FROM webhook_deliveries GROUP BY status"
                ).fetchall()
            }
            active_sessions = int(
                conn.execute(
                    "SELECT COUNT(*) AS count FROM sessions WHERE ended = 0"
                ).fetchone()["count"]
            )
        database_bytes = 0
        for candidate in (
            self.path,
            Path(f"{self.path}-wal"),
            Path(f"{self.path}-shm"),
        ):
            try:
                database_bytes += candidate.stat().st_size
            except FileNotFoundError:
                pass
        return {
            "backend": SQLITE_BACKEND,
            "backend_connectivity": self.health_check(),
            "database_bytes": database_bytes,
            "collection_counts": collection_counts,
            "event_processing_outcomes": event_counts,
            "active_sessions": active_sessions,
            "queues": {
                queue: self.job_queue_metrics(queue, now=checked_at)
                for queue in OPERATIONAL_QUEUE_NAMES
            },
            "webhook_delivery_status": webhook_status,
            "checked_at": checked_at,
        }

    def _ensure_sqlite_session_source_column(self, conn: sqlite3.Connection) -> None:
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(sessions)").fetchall()}
        if "session_source" not in columns:
            conn.execute("ALTER TABLE sessions ADD COLUMN session_source TEXT NOT NULL DEFAULT 'unknown_legacy'")
        if "is_external_source" not in columns:
            conn.execute("ALTER TABLE sessions ADD COLUMN is_external_source INTEGER NOT NULL DEFAULT 0")
        if "revision" not in columns:
            conn.execute("ALTER TABLE sessions ADD COLUMN revision INTEGER NOT NULL DEFAULT 0")
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_sessions_source_updated
                ON sessions(session_source, updated_at)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_sessions_source_external_updated
                ON sessions(session_source, is_external_source, updated_at)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_sessions_active_source_updated
                ON sessions(ended, session_source, updated_at)
            """
        )

    def _ensure_sqlite_event_processing_columns(self, conn: sqlite3.Connection) -> None:
        columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(events)").fetchall()
        }
        additions = {
            "claim_owner": "TEXT",
            "claim_token": "TEXT",
            "claim_leader_scope": "TEXT",
            "claim_leader_token": "TEXT",
            "claim_expires_at": "TEXT",
            "attempts": "INTEGER NOT NULL DEFAULT 0",
            "next_retry_at": "TEXT",
            "last_error_code": "TEXT",
            "last_error_type": "TEXT",
            "last_error_at": "TEXT",
            "processing_outcome": "TEXT",
            "processed_at": "TEXT",
            "effect_summary_json": "TEXT",
        }
        for name, declaration in additions.items():
            if name not in columns:
                conn.execute(f"ALTER TABLE events ADD COLUMN {name} {declaration}")
        # These indexes must be created only after legacy events tables have
        # acquired every referenced lifecycle column.
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_events_claimable
                ON events(processed, next_retry_at, claim_expires_at, attempts, received_at, event_id)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_events_failed
                ON events(processing_outcome, processed_at, event_id)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_events_session_queue
                ON events(session_id, processed, received_at, event_id)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_events_leader_claims
                ON events(claim_leader_scope, processed, claim_expires_at, claim_owner, claim_leader_token)
            """
        )

    def _ensure_sqlite_job_processing_columns(self, conn: sqlite3.Connection) -> None:
        additions = {
            "next_retry_at": "TEXT",
            "claim_owner": "TEXT",
            "claim_token": "TEXT",
            "claim_expires_at": "TEXT",
            "last_error_code": "TEXT",
            "last_error_type": "TEXT",
            "last_error_at": "TEXT",
            "completed_at": "TEXT",
        }
        for table in ("analysis_jobs", "enrichment_jobs", "threat_hunt_jobs"):
            columns = {
                row["name"]
                for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
            }
            for name, definition in additions.items():
                if name not in columns:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
            conn.execute(
                f"""
                CREATE INDEX IF NOT EXISTS idx_{table}_claimable
                    ON {table}(status, next_retry_at, claim_expires_at, created_at)
                """
            )

    def _ensure_sqlite_enrichment_priority_columns(self, conn: sqlite3.Connection) -> None:
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(enrichment_jobs)").fetchall()}
        if "priority" not in columns:
            conn.execute("ALTER TABLE enrichment_jobs ADD COLUMN priority TEXT NOT NULL DEFAULT 'normal'")
        if "priority_reason" not in columns:
            conn.execute("ALTER TABLE enrichment_jobs ADD COLUMN priority_reason TEXT")
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_enrichment_jobs_priority
                ON enrichment_jobs(status, priority, next_retry_at, created_at)
            """
        )

    def _ensure_sqlite_webhook_delivery_columns(self, conn: sqlite3.Connection) -> None:
        columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(webhook_deliveries)").fetchall()
        }
        additions = {
            "error_code": "TEXT",
            "next_retry_at": "TEXT",
            "claim_owner": "TEXT",
            "claim_token": "TEXT",
            "claim_expires_at": "TEXT",
            "response_status": "INTEGER",
            "response_body_sha256": "TEXT",
            "response_body_bytes": "INTEGER NOT NULL DEFAULT 0",
            "response_body_truncated": "INTEGER NOT NULL DEFAULT 0",
            "completed_at": "TEXT",
        }
        for name, declaration in additions.items():
            if name not in columns:
                conn.execute(
                    f"ALTER TABLE webhook_deliveries ADD COLUMN {name} {declaration}"
                )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_webhook_target_claimable
                ON webhook_deliveries(
                    target_url_hash, status, next_retry_at,
                    claim_expires_at, updated_at
                )
            """
        )

    def store_event(self, sensor_id: str, event: Dict[str, Any]) -> tuple[str, bool]:
        record = CanonicalEventRecord.create(sensor_id, event)
        try:
            return self.store_canonical_event(record)
        except StorageError:
            # A replay arriving through the legacy ingest method receives a
            # new local clock value. The first durable received_at remains
            # authoritative when the authenticated sensor and canonical event
            # bytes are exact; explicit CanonicalEventRecord writes bind and
            # verify received_at strictly for shadow/mirror operation.
            existing = self.get_event(record.event_id)
            if (
                existing is not None
                and existing.get("sensor_id") == record.sensor_id
                and existing.get("payload_json") == record.payload_json
            ):
                return record.event_id, False
            raise

    def store_canonical_event(
        self,
        record: CanonicalEventRecord,
    ) -> tuple[str, bool]:
        try:
            record.verify()
        except ValueError as exc:
            raise StorageError("canonical event record failed integrity validation") from exc
        with self.connection() as conn:
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO events
                (event_id, sensor_id, session_id, src_ip, eventid, timestamp, payload_json, received_at)
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
            inserted = cur.rowcount == 1
            if not inserted:
                existing = conn.execute(
                    """
                    SELECT sensor_id, session_id, received_at, payload_json
                    FROM events WHERE event_id = ?
                    """,
                    (record.event_id,),
                ).fetchone()
                if existing is None or (
                    existing["sensor_id"] != record.sensor_id
                    or existing["session_id"] != record.session_id
                    or existing["received_at"] != record.received_at
                    or existing["payload_json"] != record.payload_json
                ):
                    raise StorageError("conflicting duplicate canonical event ID")
            return record.event_id, inserted

    def fetch_unprocessed_events(self, limit: int) -> List[Dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT event_id, sensor_id, payload_json, processed, received_at
                FROM events
                WHERE processed = 0
                ORDER BY received_at, event_id
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "event_id": row["event_id"],
                "sensor_id": row["sensor_id"],
                "event": json.loads(row["payload_json"]),
                "payload_json": row["payload_json"],
                "processed": bool(row["processed"]),
                "received_at": row["received_at"],
            }
            for row in rows
        ]

    def get_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        identity = _required_identity(event_id, "event_id")
        with self.connection() as conn:
            row = conn.execute(
                "SELECT event_id, sensor_id, payload_json, processed, received_at "
                "FROM events WHERE event_id=? LIMIT 1",
                (identity,),
            ).fetchone()
        if row is None:
            return None
        return {
            "event_id": row["event_id"],
            "sensor_id": row["sensor_id"],
            "event": json.loads(row["payload_json"]),
            "payload_json": row["payload_json"],
            "processed": bool(row["processed"]),
            "received_at": row["received_at"],
        }

    def load_session_event_snapshot(
        self,
        session_id: str,
        through_event_id: str,
        max_events: int,
    ) -> Dict[str, Any]:
        """Load and bind the exact durable event prefix used by analysis."""

        selected_session = str(session_id or "").strip()
        watermark = str(through_event_id or "").strip()
        if not selected_session or not watermark:
            raise StorageError(
                "canonical session evidence requires session and event watermark"
            )
        if (
            isinstance(max_events, bool)
            or not isinstance(max_events, int)
            or max_events < 1
        ):
            raise ValueError("max_events must be a positive integer")

        events: List[Dict[str, Any]] = []
        entries: List[Dict[str, str]] = []
        found = False
        with self.connection() as conn:
            cursor = conn.execute(
                """
                SELECT event_id, payload_json
                FROM events
                WHERE session_id = ?
                ORDER BY received_at, event_id
                """,
                (selected_session,),
            )
            for row in cursor:
                if len(events) >= max_events:
                    raise StorageError(
                        "canonical session evidence exceeds configured event limit"
                    )
                try:
                    event = json.loads(row["payload_json"])
                except (TypeError, json.JSONDecodeError) as exc:
                    raise StorageError(
                        "canonical session evidence contains invalid JSON"
                    ) from exc
                if not isinstance(event, dict):
                    raise StorageError(
                        "canonical session evidence event must be an object"
                    )
                event_id = str(row["event_id"])
                events.append(event)
                entries.append(
                    {
                        "event_id": event_id,
                        "payload_sha256": hashlib.sha256(
                            row["payload_json"].encode("utf-8")
                        ).hexdigest(),
                    }
                )
                if event_id == watermark:
                    found = True
                    break
        if not found:
            raise StorageError(
                "canonical session evidence watermark is unavailable"
            )
        manifest_basis = {
            "schema_version": "durable_session_event_manifest.v1",
            "session_id": selected_session,
            "through_event_id": watermark,
            "event_entries": entries,
        }
        return {
            **manifest_basis,
            "event_count": len(events),
            "manifest_sha256": hashlib.sha256(
                stable_json(manifest_basis).encode("utf-8")
            ).hexdigest(),
            "events": events,
        }

    def claim_events(
        self,
        owner: str,
        limit: int,
        lease_seconds: float,
        max_attempts: int = 5,
        *,
        now: Any = None,
        leader_scope: str = "",
        leader_token: str = "",
    ) -> List[Dict[str, Any]]:
        claim_owner = _required_identity(owner, "owner")
        if bool(leader_scope) != bool(leader_token):
            raise ValueError("leader_scope and leader_token must be provided together")
        lease_scope = _required_identity(leader_scope, "leader_scope") if leader_scope else ""
        lease_token = _uuid_token(leader_token, "leader_token") if leader_token else ""
        try:
            claim_limit = max(0, int(limit))
            attempt_limit = int(max_attempts)
        except (TypeError, ValueError) as exc:
            raise ValueError("limit and max_attempts must be integers") from exc
        if attempt_limit <= 0:
            raise ValueError("max_attempts must be positive")
        current_time = _utc_timestamp(now)
        expires_at = _future_timestamp(
            current_time,
            lease_seconds,
            field="lease_seconds",
        )
        claimed: List[Dict[str, Any]] = []
        with self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if lease_scope:
                leader = conn.execute(
                    """
                    SELECT 1
                    FROM worker_leases
                    WHERE scope = ?
                      AND owner = ?
                      AND token = ?
                      AND expires_at >= ?
                    """,
                    (lease_scope, claim_owner, lease_token, expires_at),
                ).fetchone()
                if leader is None:
                    return []
            conn.execute(
                """
                UPDATE events
                SET processed = 1,
                    processing_outcome = 'dead_letter',
                    processed_at = ?,
                    next_retry_at = NULL,
                    last_error_code = 'event_lease_attempts_exhausted',
                    last_error_type = 'LeaseExpired',
                    last_error_at = ?,
                    claim_owner = NULL,
                    claim_token = NULL,
                    claim_leader_scope = NULL,
                    claim_leader_token = NULL,
                    claim_expires_at = NULL
                WHERE processed = 0
                  AND attempts >= ?
                  AND (next_retry_at IS NULL OR next_retry_at <= ?)
                  AND (
                      claim_token IS NULL
                      OR claim_expires_at IS NULL
                      OR claim_expires_at <= ?
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM events AS predecessor
                      WHERE predecessor.session_id = events.session_id
                        AND predecessor.processed = 0
                        AND (
                            predecessor.received_at < events.received_at
                            OR (
                                predecessor.received_at = events.received_at
                                AND predecessor.event_id < events.event_id
                            )
                        )
                  )
                """,
                (
                    current_time,
                    current_time,
                    attempt_limit,
                    current_time,
                    current_time,
                ),
            )
            if claim_limit == 0:
                return []
            invalid_budget = 1_000
            while len(claimed) < claim_limit and invalid_budget > 0:
                remaining = claim_limit - len(claimed)
                rows = conn.execute(
                    """
                    SELECT event_id, sensor_id, payload_json, received_at, attempts
                    FROM events AS candidate
                    WHERE candidate.processed = 0
                      AND candidate.attempts < ?
                      AND (candidate.next_retry_at IS NULL OR candidate.next_retry_at <= ?)
                      AND (
                          candidate.claim_token IS NULL
                          OR candidate.claim_expires_at IS NULL
                          OR candidate.claim_expires_at <= ?
                      )
                      AND NOT EXISTS (
                          SELECT 1
                          FROM events AS predecessor
                          WHERE predecessor.session_id = candidate.session_id
                            AND predecessor.processed = 0
                            AND (
                                predecessor.received_at < candidate.received_at
                                OR (
                                    predecessor.received_at = candidate.received_at
                                    AND predecessor.event_id < candidate.event_id
                                )
                            )
                      )
                    ORDER BY candidate.received_at, candidate.event_id
                    LIMIT ?
                    """,
                    (attempt_limit, current_time, current_time, remaining),
                ).fetchall()
                if not rows:
                    break
                progressed = False
                for row in rows:
                    try:
                        event_payload, payload_json = _decode_event_payload(
                            row["payload_json"]
                        )
                    except ValueError:
                        cursor = conn.execute(
                            """
                            UPDATE events
                            SET processed = 1,
                                processing_outcome = 'dead_letter',
                                processed_at = ?,
                                next_retry_at = NULL,
                                last_error_code = 'event_processing_invalid',
                                last_error_type = 'ValidationError',
                                last_error_at = ?,
                                effect_summary_json = NULL,
                                claim_owner = NULL,
                                claim_token = NULL,
                                claim_leader_scope = NULL,
                                claim_leader_token = NULL,
                                claim_expires_at = NULL
                            WHERE event_id = ? AND processed = 0
                            """,
                            (current_time, current_time, row["event_id"]),
                        )
                        if cursor.rowcount == 1:
                            invalid_budget -= 1
                            progressed = True
                        continue
                    token = str(uuid.uuid4())
                    cursor = conn.execute(
                        """
                        UPDATE events
                        SET claim_owner = ?,
                            claim_token = ?,
                            claim_leader_scope = ?,
                            claim_leader_token = ?,
                            claim_expires_at = ?,
                            attempts = attempts + 1,
                            processing_outcome = NULL,
                            effect_summary_json = NULL
                        WHERE event_id = ?
                          AND processed = 0
                          AND attempts < ?
                          AND (next_retry_at IS NULL OR next_retry_at <= ?)
                          AND (
                              claim_token IS NULL
                              OR claim_expires_at IS NULL
                              OR claim_expires_at <= ?
                          )
                        """,
                        (
                            claim_owner,
                            token,
                            lease_scope or None,
                            lease_token or None,
                            expires_at,
                            row["event_id"],
                            attempt_limit,
                            current_time,
                            current_time,
                        ),
                    )
                    if cursor.rowcount != 1:  # pragma: no cover - exclusive transaction
                        continue
                    progressed = True
                    claimed.append(
                        {
                            "event_id": row["event_id"],
                            "sensor_id": row["sensor_id"],
                            "event": event_payload,
                            "payload_json": payload_json,
                            "received_at": row["received_at"],
                            "claim_owner": claim_owner,
                            "claim_token": token,
                            "claim_leader_scope": lease_scope,
                            "claim_leader_token": lease_token,
                            "claim_expires_at": expires_at,
                            "attempts": int(row["attempts"] or 0) + 1,
                        }
                    )
                if not progressed:
                    break
        return claimed

    def renew_event_claim(
        self,
        event_id: str,
        owner: str,
        token: str,
        lease_seconds: float,
        *,
        now: Any = None,
        leader_scope: str = "",
        leader_token: str = "",
    ) -> bool:
        if bool(leader_scope) != bool(leader_token):
            raise ValueError("leader_scope and leader_token must be provided together")
        lease_scope = _required_identity(leader_scope, "leader_scope") if leader_scope else ""
        lease_token = _uuid_token(leader_token, "leader_token") if leader_token else ""
        event_identity = _required_identity(event_id, "event_id")
        event_claim_token = _uuid_token(token, "token")
        claim_owner = _required_identity(owner, "owner")
        current_time = _utc_timestamp(now)
        expires_at = _future_timestamp(
            current_time,
            lease_seconds,
            field="lease_seconds",
        )
        with self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            claim = conn.execute(
                """
                SELECT claim_leader_scope, claim_leader_token
                FROM events
                WHERE event_id = ?
                  AND processed = 0
                  AND claim_owner = ?
                  AND claim_token = ?
                  AND claim_expires_at > ?
                """,
                (event_identity, claim_owner, event_claim_token, current_time),
            ).fetchone()
            if claim is None or not _claim_leader_binding_matches(
                claim, lease_scope, lease_token
            ):
                return False
            if lease_scope:
                leader = conn.execute(
                    """
                    SELECT 1 FROM worker_leases
                    WHERE scope = ?
                      AND owner = ?
                      AND token = ?
                      AND expires_at >= ?
                    """,
                    (lease_scope, claim_owner, lease_token, expires_at),
                ).fetchone()
                if leader is None:
                    return False
            cursor = conn.execute(
                """
                UPDATE events
                SET claim_expires_at = ?
                WHERE event_id = ?
                  AND processed = 0
                  AND claim_owner = ?
                  AND claim_token = ?
                  AND claim_expires_at > ?
                """,
                (
                    expires_at,
                    event_identity,
                    claim_owner,
                    event_claim_token,
                    current_time,
                ),
            )
            return cursor.rowcount == 1

    def complete_event(
        self,
        event_id: str,
        owner: str,
        token: str,
        effect_summary: Optional[Dict[str, Any]] = None,
        *,
        now: Any = None,
        leader_scope: str = "",
        leader_token: str = "",
    ) -> bool:
        if bool(leader_scope) != bool(leader_token):
            raise ValueError("leader_scope and leader_token must be provided together")
        lease_scope = _required_identity(leader_scope, "leader_scope") if leader_scope else ""
        lease_token = _uuid_token(leader_token, "leader_token") if leader_token else ""
        claim_owner = _required_identity(owner, "owner")
        event_identity = _required_identity(event_id, "event_id")
        event_claim_token = _uuid_token(token, "token")
        current_time = _utc_timestamp(now)
        validated_effect_summary = validate_event_effect_summary(effect_summary)
        effect_summary_json = (
            stable_json(validated_effect_summary)
            if validated_effect_summary is not None
            else None
        )
        with self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            claim = conn.execute(
                """
                SELECT claim_leader_scope, claim_leader_token
                FROM events
                WHERE event_id = ?
                  AND processed = 0
                  AND claim_owner = ?
                  AND claim_token = ?
                  AND claim_expires_at > ?
                """,
                (event_identity, claim_owner, event_claim_token, current_time),
            ).fetchone()
            if claim is None or not _claim_leader_binding_matches(
                claim, lease_scope, lease_token
            ):
                return False
            if lease_scope:
                leader = conn.execute(
                    """
                    SELECT 1 FROM worker_leases
                    WHERE scope = ?
                      AND owner = ?
                      AND token = ?
                      AND expires_at > ?
                    """,
                    (lease_scope, claim_owner, lease_token, current_time),
                ).fetchone()
                if leader is None:
                    return False
            cursor = conn.execute(
                """
                UPDATE events
                SET processed = 1,
                    processing_outcome = 'succeeded',
                    processed_at = ?,
                    effect_summary_json = ?,
                    next_retry_at = NULL,
                    last_error_code = NULL,
                    last_error_type = NULL,
                    last_error_at = NULL,
                    claim_owner = NULL,
                    claim_token = NULL,
                    claim_leader_scope = NULL,
                    claim_leader_token = NULL,
                    claim_expires_at = NULL
                WHERE event_id = ?
                  AND processed = 0
                  AND claim_owner = ?
                  AND claim_token = ?
                  AND claim_expires_at > ?
                """,
                (
                    current_time,
                    effect_summary_json,
                    event_identity,
                    claim_owner,
                    event_claim_token,
                    current_time,
                ),
            )
            return cursor.rowcount == 1

    def fail_event(
        self,
        event_id: str,
        owner: str,
        token: str,
        error_code: str,
        error_type: str,
        retryable: bool,
        max_attempts: int,
        retry_delay_seconds: float,
        *,
        now: Any = None,
        leader_scope: str = "",
        leader_token: str = "",
    ) -> str:
        if bool(leader_scope) != bool(leader_token):
            raise ValueError("leader_scope and leader_token must be provided together")
        lease_scope = _required_identity(leader_scope, "leader_scope") if leader_scope else ""
        lease_token = _uuid_token(leader_token, "leader_token") if leader_token else ""
        event_identity = _required_identity(event_id, "event_id")
        claim_owner = _required_identity(owner, "owner")
        claim_token = _uuid_token(token, "token")
        stable_error_code, stable_error_type = validate_event_failure_fields(
            error_code,
            error_type,
        )
        try:
            attempt_limit = int(max_attempts)
            retry_delay = float(retry_delay_seconds)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "max_attempts must be an integer and retry_delay_seconds must be numeric"
            ) from exc
        if attempt_limit <= 0:
            raise ValueError("max_attempts must be positive")
        if not math.isfinite(retry_delay) or retry_delay < 0:
            raise ValueError("retry_delay_seconds must be non-negative")
        current_time = _utc_timestamp(now)
        parsed_now = _parse_dt(current_time)
        if parsed_now is None:  # pragma: no cover - _utc_timestamp guarantees this
            raise ValueError("now must be a valid timestamp")
        next_retry_at = (parsed_now + timedelta(seconds=retry_delay)).isoformat()
        with self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT attempts, claim_leader_scope, claim_leader_token
                FROM events
                WHERE event_id = ?
                  AND processed = 0
                  AND claim_owner = ?
                  AND claim_token = ?
                  AND claim_expires_at > ?
                """,
                (event_identity, claim_owner, claim_token, current_time),
            ).fetchone()
            if row is None or not _claim_leader_binding_matches(
                row, lease_scope, lease_token
            ):
                return "stale_claim"
            if lease_scope:
                leader = conn.execute(
                    """
                    SELECT 1 FROM worker_leases
                    WHERE scope = ?
                      AND owner = ?
                      AND token = ?
                      AND expires_at > ?
                    """,
                    (lease_scope, claim_owner, lease_token, current_time),
                ).fetchone()
                if leader is None:
                    return "stale_claim"
            if bool(retryable) and int(row["attempts"] or 0) < attempt_limit:
                conn.execute(
                    """
                    UPDATE events
                    SET processing_outcome = 'retry_scheduled',
                        next_retry_at = ?,
                        last_error_code = ?,
                        last_error_type = ?,
                        last_error_at = ?,
                        claim_owner = NULL,
                        claim_token = NULL,
                        claim_leader_scope = NULL,
                        claim_leader_token = NULL,
                        claim_expires_at = NULL
                    WHERE event_id = ?
                      AND processed = 0
                      AND claim_owner = ?
                      AND claim_token = ?
                      AND claim_expires_at > ?
                    """,
                    (
                        next_retry_at,
                        stable_error_code,
                        stable_error_type,
                        current_time,
                        event_identity,
                        claim_owner,
                        claim_token,
                        current_time,
                    ),
                )
                return "retry_scheduled"
            conn.execute(
                """
                UPDATE events
                SET processed = 1,
                    processing_outcome = 'dead_letter',
                    processed_at = ?,
                    next_retry_at = NULL,
                    last_error_code = ?,
                    last_error_type = ?,
                    last_error_at = ?,
                    claim_owner = NULL,
                    claim_token = NULL,
                    claim_leader_scope = NULL,
                    claim_leader_token = NULL,
                    claim_expires_at = NULL
                WHERE event_id = ?
                  AND processed = 0
                  AND claim_owner = ?
                  AND claim_token = ?
                  AND claim_expires_at > ?
                """,
                (
                    current_time,
                    stable_error_code,
                    stable_error_type,
                    current_time,
                    event_identity,
                    claim_owner,
                    claim_token,
                    current_time,
                ),
            )
            return "dead_letter"

    def release_event_claim(
        self,
        event_id: str,
        owner: str,
        token: str,
        *,
        now: Any = None,
        leader_scope: str = "",
        leader_token: str = "",
    ) -> bool:
        if bool(leader_scope) != bool(leader_token):
            raise ValueError("leader_scope and leader_token must be provided together")
        lease_scope = _required_identity(leader_scope, "leader_scope") if leader_scope else ""
        lease_token = _uuid_token(leader_token, "leader_token") if leader_token else ""
        claim_owner = _required_identity(owner, "owner")
        event_identity = _required_identity(event_id, "event_id")
        event_claim_token = _uuid_token(token, "token")
        current_time = _utc_timestamp(now)
        with self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            claim = conn.execute(
                """
                SELECT claim_leader_scope, claim_leader_token
                FROM events
                WHERE event_id = ?
                  AND processed = 0
                  AND claim_owner = ?
                  AND claim_token = ?
                  AND claim_expires_at > ?
                """,
                (event_identity, claim_owner, event_claim_token, current_time),
            ).fetchone()
            if claim is None or not _claim_leader_binding_matches(
                claim, lease_scope, lease_token
            ):
                return False
            if lease_scope:
                leader = conn.execute(
                    """
                    SELECT 1 FROM worker_leases
                    WHERE scope = ?
                      AND owner = ?
                      AND token = ?
                      AND expires_at > ?
                    """,
                    (lease_scope, claim_owner, lease_token, current_time),
                ).fetchone()
                if leader is None:
                    return False
            cursor = conn.execute(
                """
                UPDATE events
                SET claim_owner = NULL,
                    claim_token = NULL,
                    claim_leader_scope = NULL,
                    claim_leader_token = NULL,
                    claim_expires_at = NULL,
                    processing_outcome = NULL
                WHERE event_id = ?
                  AND processed = 0
                  AND claim_owner = ?
                  AND claim_token = ?
                  AND claim_expires_at > ?
                """,
                (
                    event_identity,
                    claim_owner,
                    event_claim_token,
                    current_time,
                ),
            )
            return cursor.rowcount == 1

    def list_failed_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        try:
            row_limit = max(0, int(limit))
        except (TypeError, ValueError) as exc:
            raise ValueError("limit must be an integer") from exc
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT event_id, sensor_id, payload_json, attempts,
                       last_error_code, last_error_type, last_error_at,
                       processing_outcome, processed_at
                FROM events
                WHERE processed = 1
                  AND processing_outcome = 'dead_letter'
                ORDER BY processed_at DESC, event_id
                LIMIT ?
                """,
                (row_limit,),
            ).fetchall()
        return [
            {
                "event_id": row["event_id"],
                "sensor_id": row["sensor_id"],
                "event": _safe_event_payload(row["payload_json"])[0],
                "payload_json": _safe_event_payload(row["payload_json"])[1],
                "attempts": int(row["attempts"] or 0),
                "last_error_code": row["last_error_code"],
                "last_error_type": row["last_error_type"],
                "last_error_at": row["last_error_at"],
                "processing_outcome": row["processing_outcome"],
                "processed_at": row["processed_at"],
            }
            for row in rows
        ]

    def acquire_worker_lease(
        self,
        scope: str,
        owner: str,
        token: str,
        lease_seconds: float,
        *,
        now: Any = None,
    ) -> bool:
        lease_scope = _required_identity(scope, "scope")
        lease_owner = _required_identity(owner, "owner")
        lease_token = _uuid_token(token, "token")
        current_time = _utc_timestamp(now)
        expires_at = _future_timestamp(
            current_time,
            lease_seconds,
            field="lease_seconds",
        )
        with self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT owner, token, expires_at FROM worker_leases WHERE scope = ?",
                (lease_scope,),
            ).fetchone()
            if row is not None and row["expires_at"] > current_time:
                if row["owner"] != lease_owner or row["token"] != lease_token:
                    return False
                conn.execute(
                    """
                    UPDATE worker_leases
                    SET expires_at = ?, updated_at = ?
                    WHERE scope = ? AND owner = ? AND token = ?
                    """,
                    (
                        expires_at,
                        current_time,
                        lease_scope,
                        lease_owner,
                        lease_token,
                    ),
                )
                return True
            conflicting_claim = conn.execute(
                """
                SELECT 1
                FROM events
                WHERE processed = 0
                  AND claim_leader_scope = ?
                  AND (
                      claim_owner <> ?
                      OR COALESCE(claim_leader_token, '') <> ?
                  )
                  AND claim_expires_at > ?
                LIMIT 1
                """,
                (lease_scope, lease_owner, lease_token, current_time),
            ).fetchone()
            if conflicting_claim is not None:
                return False
            if row is None:
                conn.execute(
                    """
                    INSERT INTO worker_leases(scope, owner, token, expires_at, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (lease_scope, lease_owner, lease_token, expires_at, current_time),
                )
                return True
            conn.execute(
                """
                UPDATE worker_leases
                SET owner = ?, token = ?, expires_at = ?, updated_at = ?
                WHERE scope = ?
                """,
                (lease_owner, lease_token, expires_at, current_time, lease_scope),
            )
            return True

    def renew_worker_lease(
        self,
        scope: str,
        owner: str,
        token: str,
        lease_seconds: float,
        *,
        now: Any = None,
    ) -> bool:
        current_time = _utc_timestamp(now)
        expires_at = _future_timestamp(
            current_time,
            lease_seconds,
            field="lease_seconds",
        )
        with self.connection() as conn:
            cursor = conn.execute(
                """
                UPDATE worker_leases
                SET expires_at = ?, updated_at = ?
                WHERE scope = ?
                  AND owner = ?
                  AND token = ?
                  AND expires_at > ?
                """,
                (
                    expires_at,
                    current_time,
                    _required_identity(scope, "scope"),
                    _required_identity(owner, "owner"),
                    _uuid_token(token, "token"),
                    current_time,
                ),
            )
            return cursor.rowcount == 1

    def release_worker_lease(
        self,
        scope: str,
        owner: str,
        token: str,
        *,
        now: Any = None,
    ) -> bool:
        current_time = _utc_timestamp(now)
        with self.connection() as conn:
            cursor = conn.execute(
                """
                DELETE FROM worker_leases
                WHERE scope = ?
                  AND owner = ?
                  AND token = ?
                  AND expires_at > ?
                """,
                (
                    _required_identity(scope, "scope"),
                    _required_identity(owner, "owner"),
                    _uuid_token(token, "token"),
                    current_time,
                ),
            )
            return cursor.rowcount == 1

    def fetch_events(self, limit: int = 1000, processed: Optional[bool] = None) -> List[Dict[str, Any]]:
        where = ""
        params: List[Any] = []
        if processed is not None:
            where = "WHERE processed = ?"
            params.append(1 if processed else 0)
        params.append(limit)
        with self.connection() as conn:
            rows = conn.execute(
                f"""
                SELECT event_id, sensor_id, payload_json, processed, received_at FROM events
                {where}
                ORDER BY received_at, event_id
                LIMIT ?
                """,
                params,
            ).fetchall()
        return [
            {
                "event_id": row["event_id"],
                "sensor_id": row["sensor_id"],
                "event": json.loads(row["payload_json"]),
                "payload_json": row["payload_json"],
                "processed": bool(row["processed"]),
                "received_at": row["received_at"],
            }
            for row in rows
        ]

    def mark_event_processed(self, event_id: str) -> None:
        now = utc_now()
        with self.connection() as conn:
            conn.execute(
                """
                UPDATE events
                SET processed = 1,
                    processing_outcome = 'succeeded',
                    processed_at = ?,
                    next_retry_at = NULL,
                    last_error_code = NULL,
                    last_error_type = NULL,
                    last_error_at = NULL,
                    effect_summary_json = NULL,
                    claim_owner = NULL,
                    claim_token = NULL,
                    claim_leader_scope = NULL,
                    claim_leader_token = NULL,
                    claim_expires_at = NULL
                WHERE event_id = ?
                """,
                (now, event_id),
            )

    def save_session(self, session_payload: Dict[str, Any]) -> None:
        now = utc_now()
        session_source = _payload_session_source(session_payload)
        session_payload = dict(session_payload)
        is_external_source = is_external_source_ip(session_payload.get("src_ip"))
        session_payload["session_source"] = session_source
        session_payload["is_external_source"] = is_external_source
        with self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT payload_json FROM sessions WHERE session_id = ? LIMIT 1",
                (session_payload.get("session_id", "unknown"),),
            ).fetchone()
            if existing:
                stored_payload = json.loads(existing["payload_json"] or "{}")
                for key in SESSION_ANALYSIS_FIELDS:
                    if key in stored_payload:
                        session_payload[key] = stored_payload[key]
                    else:
                        session_payload.pop(key, None)
            conn.execute(
                """
                INSERT INTO sessions
                    (session_id, src_ip, start_time, ended, session_source,
                     is_external_source, revision, payload_json, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    src_ip=excluded.src_ip,
                    start_time=excluded.start_time,
                    ended=excluded.ended,
                    session_source=excluded.session_source,
                    is_external_source=excluded.is_external_source,
                    revision=sessions.revision + 1,
                    payload_json=excluded.payload_json,
                    updated_at=excluded.updated_at
                """,
                (
                    session_payload.get("session_id", "unknown"),
                    session_payload.get("src_ip", "unknown"),
                    session_payload.get("start_time", ""),
                    1 if session_payload.get("is_ended") else 0,
                    session_source,
                    1 if is_external_source else 0,
                    stable_json(session_payload),
                    now,
                ),
            )

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        if not session_id:
            return None
        with self.connection() as conn:
            row = conn.execute(
                """
                SELECT * FROM sessions
                WHERE session_id = ?
                LIMIT 1
                """,
                (session_id,),
            ).fetchone()
        if not row:
            return None
        item = dict(row)
        item["payload"] = json.loads(item.get("payload_json") or "{}")
        return item

    def update_session_analysis_status(
        self,
        session_id: str,
        status: str,
        *,
        job_id: str = "",
        report_id: str = "",
        error: str = "",
        skip_reason: str = "",
    ) -> None:
        """Patch analysis status fields inside the stored session payload.

        Analysis jobs are the source of truth for worker state, but the monitor
        and dashboard also read session payload summaries. Keeping these fields
        current prevents closed sessions from looking permanently queued after a
        report has already been generated.
        """
        if not session_id:
            return
        now = utc_now()
        with self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT payload_json FROM sessions WHERE session_id = ? LIMIT 1",
                (session_id,),
            ).fetchone()
            if not row:
                return
            payload = _apply_analysis_status(
                json.loads(row["payload_json"] or "{}"),
                status,
                now,
                job_id=job_id,
                report_id=report_id,
                error=error,
                skip_reason=skip_reason,
            )
            conn.execute(
                """
                UPDATE sessions
                SET payload_json = ?, revision = revision + 1, updated_at = ?
                WHERE session_id = ?
                """,
                (stable_json(payload), now, session_id),
            )

    def store_alert(self, alert_payload: Dict[str, Any]) -> str:
        alert_id = alert_payload.get("alert_id") or stable_id("alert", alert_payload)
        now = utc_now()
        with self.connection() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO alerts
                (alert_id, session_id, severity, reason, payload_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    alert_id,
                    alert_payload.get("session_id", "unknown"),
                    alert_payload.get("severity", "UNKNOWN"),
                    alert_payload.get("reason", ""),
                    stable_json(alert_payload),
                    alert_payload.get("created_at", now),
                ),
            )
        return alert_id

    def enqueue_analysis_job(self, session_payload: Dict[str, Any]) -> str:
        job_id = stable_id("job", {"session_id": session_payload.get("session_id", "unknown")})
        now = utc_now()
        with self.connection() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO analysis_jobs
                (job_id, session_id, status, payload_json, created_at, updated_at)
                VALUES (?, ?, 'queued', ?, ?, ?)
                """,
                (
                    job_id,
                    session_payload.get("session_id", "unknown"),
                    stable_json(session_payload),
                    now,
                    now,
                ),
            )
        return job_id

    def claim_jobs(
        self,
        queue: str,
        owner: str,
        limit: int,
        lease_seconds: float,
        max_attempts: int,
        *,
        now: Any = None,
    ) -> List[Dict[str, Any]]:
        queue_name = str(queue or "").strip()
        if queue_name not in JOB_QUEUE_TABLES:
            raise ValueError("queue is not a registered durable job queue")
        table = JOB_QUEUE_TABLES[queue_name]
        claim_owner = _required_identity(owner, "owner")
        claim_limit = max(int(limit), 0)
        attempt_limit = int(max_attempts)
        if attempt_limit < 1:
            raise ValueError("max_attempts must be positive")
        current_time = _utc_timestamp(now)
        expires_at = _future_timestamp(current_time, lease_seconds, field="lease_seconds")
        order_by = (
            "CASE priority WHEN 'urgent' THEN 3 WHEN 'high' THEN 2 "
            "WHEN 'normal' THEN 1 ELSE 0 END DESC, created_at, job_id"
            if queue_name == "enrichment"
            else "created_at, job_id"
        )
        with self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                f"""
                UPDATE {table}
                SET status='failed',
                    error='job_attempts_exhausted:LeaseExpired',
                    last_error_code='job_attempts_exhausted',
                    last_error_type='LeaseExpired',
                    last_error_at=?,
                    next_retry_at=NULL,
                    claim_owner=NULL,
                    claim_token=NULL,
                    claim_expires_at=NULL,
                    completed_at=?,
                    updated_at=?
                WHERE attempts >= ?
                  AND status IN ('queued', 'retry', 'running')
                  AND (next_retry_at IS NULL OR next_retry_at <= ?)
                  AND (
                      status <> 'running'
                      OR claim_token IS NULL
                      OR claim_expires_at IS NULL
                      OR claim_expires_at <= ?
                  )
                """,
                (
                    current_time,
                    current_time,
                    current_time,
                    attempt_limit,
                    current_time,
                    current_time,
                ),
            )
            if claim_limit == 0:
                return []
            rows = conn.execute(
                f"""
                SELECT * FROM {table}
                WHERE attempts < ?
                  AND (next_retry_at IS NULL OR next_retry_at <= ?)
                  AND (
                      status IN ('queued', 'retry')
                      OR (
                          status = 'running'
                          AND (
                              claim_token IS NULL
                              OR claim_expires_at IS NULL
                              OR claim_expires_at <= ?
                          )
                      )
                  )
                ORDER BY {order_by}
                LIMIT ?
                """,
                (attempt_limit, current_time, current_time, claim_limit),
            ).fetchall()
            claimed: List[Dict[str, Any]] = []
            for row in rows:
                token = str(uuid.uuid4())
                cursor = conn.execute(
                    f"""
                    UPDATE {table}
                    SET status='running',
                        attempts=attempts+1,
                        next_retry_at=NULL,
                        claim_owner=?,
                        claim_token=?,
                        claim_expires_at=?,
                        completed_at=NULL,
                        updated_at=?
                    WHERE job_id=?
                      AND attempts < ?
                      AND (next_retry_at IS NULL OR next_retry_at <= ?)
                      AND (
                          status IN ('queued', 'retry')
                          OR (
                              status='running'
                              AND (
                                  claim_token IS NULL
                                  OR claim_expires_at IS NULL
                                  OR claim_expires_at <= ?
                              )
                          )
                      )
                    """,
                    (
                        claim_owner,
                        token,
                        expires_at,
                        current_time,
                        row["job_id"],
                        attempt_limit,
                        current_time,
                        current_time,
                    ),
                )
                if cursor.rowcount != 1:
                    continue
                item = dict(row)
                item.update(
                    {
                        "status": "running",
                        "attempts": int(row["attempts"] or 0) + 1,
                        "claim_owner": claim_owner,
                        "claim_token": token,
                        "claim_expires_at": expires_at,
                    }
                )
                claimed.append(item)
            return claimed

    def renew_job_claim(
        self,
        queue: str,
        job_id: str,
        owner: str,
        token: str,
        lease_seconds: float,
        *,
        now: Any = None,
    ) -> bool:
        queue_name = str(queue or "").strip()
        if queue_name not in JOB_QUEUE_TABLES:
            raise ValueError("queue is not a registered durable job queue")
        current_time = _utc_timestamp(now)
        expires_at = _future_timestamp(current_time, lease_seconds, field="lease_seconds")
        with self.connection() as conn:
            cursor = conn.execute(
                f"""
                UPDATE {JOB_QUEUE_TABLES[queue_name]}
                SET claim_expires_at=?, updated_at=?
                WHERE job_id=? AND status='running'
                  AND claim_owner=? AND claim_token=?
                  AND claim_expires_at > ?
                """,
                (
                    expires_at,
                    current_time,
                    _required_identity(job_id, "job_id"),
                    _required_identity(owner, "owner"),
                    _uuid_token(token, "token"),
                    current_time,
                ),
            )
            return cursor.rowcount == 1

    def fail_job(
        self,
        queue: str,
        job_id: str,
        owner: str,
        token: str,
        error_code: str,
        error_type: str,
        retryable: bool,
        max_attempts: int,
        retry_delay_seconds: float,
        *,
        now: Any = None,
    ) -> str:
        queue_name, stable_code, stable_type = validate_job_failure_fields(
            queue,
            error_code,
            error_type,
        )
        attempt_limit = int(max_attempts)
        delay = float(retry_delay_seconds)
        if attempt_limit < 1 or not math.isfinite(delay) or delay < 0:
            raise ValueError("job retry policy is invalid")
        current_time = _utc_timestamp(now)
        parsed_now = _parse_dt(current_time)
        if parsed_now is None:  # pragma: no cover
            raise ValueError("now must be a valid timestamp")
        next_retry = (parsed_now + timedelta(seconds=delay)).isoformat()
        table = JOB_QUEUE_TABLES[queue_name]
        with self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                f"""
                SELECT attempts FROM {table}
                WHERE job_id=? AND status='running'
                  AND claim_owner=? AND claim_token=?
                  AND claim_expires_at > ?
                """,
                (
                    _required_identity(job_id, "job_id"),
                    _required_identity(owner, "owner"),
                    _uuid_token(token, "token"),
                    current_time,
                ),
            ).fetchone()
            if row is None:
                return "stale_claim"
            retry = bool(retryable) and int(row["attempts"] or 0) < attempt_limit
            status = "retry" if retry else "failed"
            conn.execute(
                f"""
                UPDATE {table}
                SET status=?,
                    error=?,
                    next_retry_at=?,
                    last_error_code=?,
                    last_error_type=?,
                    last_error_at=?,
                    claim_owner=NULL,
                    claim_token=NULL,
                    claim_expires_at=NULL,
                    completed_at=?,
                    updated_at=?
                WHERE job_id=? AND status='running'
                  AND claim_owner=? AND claim_token=?
                  AND claim_expires_at > ?
                """,
                (
                    status,
                    f"{stable_code}:{stable_type}",
                    next_retry if retry else None,
                    stable_code,
                    stable_type,
                    current_time,
                    None if retry else current_time,
                    current_time,
                    job_id,
                    owner,
                    token,
                    current_time,
                ),
            )
            return "retry_scheduled" if retry else "failed"

    def release_job_claim(
        self,
        queue: str,
        job_id: str,
        owner: str,
        token: str,
        *,
        now: Any = None,
    ) -> bool:
        queue_name = str(queue or "").strip()
        if queue_name not in JOB_QUEUE_TABLES:
            raise ValueError("queue is not a registered durable job queue")
        current_time = _utc_timestamp(now)
        with self.connection() as conn:
            cursor = conn.execute(
                f"""
                UPDATE {JOB_QUEUE_TABLES[queue_name]}
                SET status='retry', next_retry_at=?, claim_owner=NULL,
                    claim_token=NULL, claim_expires_at=NULL, updated_at=?
                WHERE job_id=? AND status='running'
                  AND claim_owner=? AND claim_token=?
                  AND claim_expires_at > ?
                """,
                (current_time, current_time, job_id, owner, token, current_time),
            )
            return cursor.rowcount == 1

    def retry_failed_job(
        self,
        queue: str,
        job_id: str,
        *,
        now: Any = None,
    ) -> bool:
        queue_name = str(queue or "").strip()
        if queue_name not in JOB_QUEUE_TABLES:
            raise ValueError("queue is not a registered durable job queue")
        current_time = _utc_timestamp(now)
        with self.connection() as conn:
            cursor = conn.execute(
                f"""
                UPDATE {JOB_QUEUE_TABLES[queue_name]}
                SET status='retry', attempts=0, next_retry_at=?,
                    claim_owner=NULL, claim_token=NULL, claim_expires_at=NULL,
                    completed_at=NULL, updated_at=?
                WHERE job_id=? AND status='failed'
                """,
                (current_time, current_time, _required_identity(job_id, "job_id")),
            )
            return cursor.rowcount == 1

    def job_queue_metrics(self, queue: str, *, now: Any = None) -> Dict[str, Any]:
        queue_name = str(queue or "").strip()
        if queue_name not in JOB_QUEUE_TABLES:
            raise ValueError("queue is not a registered durable job queue")
        current_time = _utc_timestamp(now)
        table = JOB_QUEUE_TABLES[queue_name]
        with self.connection() as conn:
            counts = conn.execute(
                f"SELECT status, COUNT(*) AS count FROM {table} GROUP BY status"
            ).fetchall()
            ready = conn.execute(
                f"""
                SELECT COUNT(*) AS count, MIN(created_at) AS oldest
                FROM {table}
                WHERE status IN ('queued', 'retry')
                  AND (next_retry_at IS NULL OR next_retry_at <= ?)
                """,
                (current_time,),
            ).fetchone()
            stale = conn.execute(
                f"""
                SELECT COUNT(*) AS count FROM {table}
                WHERE status='running'
                  AND (claim_expires_at IS NULL OR claim_expires_at <= ?)
                """,
                (current_time,),
            ).fetchone()
        oldest = ready["oldest"] if ready else None
        oldest_dt = _parse_dt(oldest)
        current_dt = _parse_dt(current_time)
        age = (
            max((current_dt - oldest_dt).total_seconds(), 0.0)
            if current_dt is not None and oldest_dt is not None
            else None
        )
        return {
            "queue": queue_name,
            "status_counts": {row["status"]: int(row["count"]) for row in counts},
            "ready": int(ready["count"] if ready else 0),
            "stale_running": int(stale["count"] if stale else 0),
            "oldest_ready_at": oldest,
            "oldest_ready_age_seconds": age,
            "checked_at": current_time,
        }

    def claim_analysis_jobs(
        self,
        owner: str,
        limit: int,
        lease_seconds: float,
        max_attempts: int,
        *,
        now: Any = None,
    ) -> List[Dict[str, Any]]:
        rows = self.claim_jobs(
            "analysis", owner, limit, lease_seconds, max_attempts, now=now
        )
        return [materialize_analysis_job_claim(row) for row in rows]

    def complete_analysis_job(
        self,
        job_id: str,
        owner: str,
        token: str,
        report_payload: Dict[str, Any],
        enqueue_ai_advisory: bool = False,
        ai_advisory_max_queue_records: int = 10_000,
        ai_advisory_reconciliation_cutoff: Optional[Dict[str, str]] = None,
        *,
        now: Any = None,
    ) -> Optional[str]:
        assessment_id = str(report_payload.get("assessment_id") or "").strip()
        if (
            report_payload.get("schema_version") == "session_assessment.v4"
            and assessment_id
        ):
            report_id = stable_id(
                "report",
                {
                    "job_id": job_id,
                    "schema_version": "session_assessment.v4",
                    "assessment_id": assessment_id,
                },
            )
        else:
            # Preserve the historical identity algorithm for legacy payloads.
            report_id = stable_id(
                "report", {"job_id": job_id, "report": report_payload}
            )
        current_time = _utc_timestamp(now)
        canonical_evidence = report_payload.get("canonical_evidence")
        canonical_session_id = (
            canonical_evidence.get("session_id")
            if (
                report_payload.get("schema_version") == "session_assessment.v4"
                and isinstance(canonical_evidence, dict)
            )
            else ""
        )
        session_id = str(
            canonical_session_id
            or report_payload.get("session_id")
            or report_payload.get("data_provenance", {})
            .get("session", {})
            .get("session_id")
            or "unknown"
        ).strip()
        with self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            claim = conn.execute(
                """
                SELECT 1 FROM analysis_jobs
                WHERE job_id=? AND status='running' AND claim_owner=?
                  AND claim_token=? AND claim_expires_at > ?
                """,
                (job_id, owner, token, current_time),
            ).fetchone()
            if claim is None:
                return None
            conn.execute(
                """
                INSERT OR REPLACE INTO reports (report_id, session_id, payload_json, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (report_id, session_id, stable_json(report_payload), current_time),
            )
            cursor = conn.execute(
                """
                UPDATE analysis_jobs
                SET status='succeeded', report_id=?, error=NULL,
                    next_retry_at=NULL, claim_owner=NULL, claim_token=NULL,
                    claim_expires_at=NULL, completed_at=?, updated_at=?
                WHERE job_id=? AND status='running' AND claim_owner=?
                  AND claim_token=? AND claim_expires_at > ?
                """,
                (
                    report_id,
                    current_time,
                    current_time,
                    job_id,
                    owner,
                    token,
                    current_time,
                ),
            )
            if cursor.rowcount != 1:  # pragma: no cover - same transaction
                raise StorageError("analysis job claim changed during completion")
            session = conn.execute(
                "SELECT payload_json FROM sessions WHERE session_id=? LIMIT 1",
                (session_id,),
            ).fetchone()
            if session:
                payload = _apply_analysis_status(
                    json.loads(session["payload_json"] or "{}"),
                    "succeeded",
                    current_time,
                    report_id=report_id,
                )
                conn.execute(
                    """
                    UPDATE sessions
                    SET payload_json=?, revision=revision + 1, updated_at=?
                    WHERE session_id=?
                    """,
                    (stable_json(payload), current_time, session_id),
                )
        # Canonical completion is committed before optional AI work is touched.
        # This compatibility flag is best-effort; the AI worker also reconciles
        # committed reports so a crash or extension failure cannot lose work.
        if enqueue_ai_advisory:
            try:
                self.initialize_ai_advisory_extension()
                self.enqueue_ai_advisory_job(
                    report_id,
                    session_id,
                    assessment_id,
                    reconciliation_cutoff=(
                        ai_advisory_reconciliation_cutoff or {}
                    ),
                    max_queue_records=ai_advisory_max_queue_records,
                )
            except Exception:
                pass
        return report_id

    def enqueue_ai_advisory_job(
        self,
        report_id: str,
        session_id: str,
        assessment_id: str,
        *,
        reconciliation_cutoff: Dict[str, str],
        max_queue_records: int = 10_000,
        now: Any = None,
    ) -> Optional[str]:
        """Idempotently enqueue one committed report under a hard queue bound."""

        report_key = _required_identity(report_id, "report_id")
        session_key = _required_identity(session_id, "session_id")
        assessment_key = _required_identity(assessment_id, "assessment_id")
        cutoff = require_valid_evidence_cutoff(reconciliation_cutoff)
        queue_limit = int(max_queue_records)
        if queue_limit < 1:
            raise ValueError("max_queue_records must be positive")
        current_time = _utc_timestamp(now)
        ai_job_id = stable_id(
            "ai_advisory_job",
            {"report_id": report_key, "assessment_id": assessment_key},
        )
        task = {
            "schema_version": "ai_advisory_task.v1",
            "report_id": report_key,
            "session_id": session_key,
            "assessment_id": assessment_key,
        }
        with self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            report = conn.execute(
                "SELECT session_id, payload_json FROM reports WHERE report_id=? LIMIT 1",
                (report_key,),
            ).fetchone()
            if report is None or str(report["session_id"]) != session_key:
                raise StorageError("AI advisory enqueue requires a committed report")
            try:
                payload = json.loads(report["payload_json"] or "{}")
            except (TypeError, json.JSONDecodeError) as exc:
                raise StorageError("committed report is not valid JSON") from exc
            if (
                payload.get("schema_version") != "session_assessment.v4"
                or str(payload.get("assessment_id") or "") != assessment_key
            ):
                raise StorageError("AI advisory enqueue report identity is invalid")
            existing = conn.execute(
                "SELECT job_id FROM ai_advisory_outbox WHERE job_id=? LIMIT 1",
                (ai_job_id,),
            ).fetchone()
            if existing:
                return ai_job_id
            if not self._ai_advisory_first_event_after_cutoff(
                conn, session_key, cutoff
            ):
                return None
            queued = conn.execute(
                """
                SELECT COUNT(*) AS count FROM ai_advisory_outbox
                WHERE status IN ('queued', 'retry', 'running')
                """
            ).fetchone()
            if int(queued["count"] if queued else 0) >= queue_limit:
                return None
            conn.execute(
                """
                INSERT OR IGNORE INTO ai_advisory_outbox
                (job_id, report_id, session_id, assessment_id, status,
                 payload_json, attempts, created_at, updated_at)
                VALUES (?, ?, ?, ?, 'queued', ?, 0, ?, ?)
                """,
                (
                    ai_job_id,
                    report_key,
                    session_key,
                    assessment_key,
                    stable_json(task),
                    current_time,
                    current_time,
                ),
            )
        return ai_job_id

    def _ai_advisory_reconciliation_cursor_path(self) -> Path:
        return self.path.with_name(
            f"{self.path.name}.ai-advisory-reconciliation-cursor.json"
        )

    @staticmethod
    def _ai_advisory_reconciliation_cursor_payload(
        cutoff: Dict[str, str],
        report_row: Optional[sqlite3.Row],
    ) -> Dict[str, Any]:
        if report_row is None:
            rowid = 0
            report_id = ""
            created_at = ""
            payload_sha256 = ""
        else:
            rowid = int(report_row["report_rowid"])
            report_id = str(report_row["report_id"])
            created_at = str(report_row["created_at"])
            payload_sha256 = hashlib.sha256(
                str(report_row["payload_json"]).encode("utf-8")
            ).hexdigest()
        return {
            "schema_version": AI_ADVISORY_RECONCILIATION_CURSOR_SCHEMA,
            "reconciliation_cutoff": dict(cutoff),
            "last_report_rowid": rowid,
            "last_report_id": report_id,
            "last_report_created_at": created_at,
            "last_report_payload_sha256": payload_sha256,
        }

    def _write_ai_advisory_reconciliation_cursor(
        self, payload: Dict[str, Any]
    ) -> None:
        destination = self._ai_advisory_reconciliation_cursor_path()
        temporary = destination.with_name(
            f".{destination.name}.{uuid.uuid4().hex}.tmp"
        )
        encoded = (stable_json(payload) + "\n").encode("utf-8")
        if len(encoded) > AI_ADVISORY_RECONCILIATION_CURSOR_MAX_BYTES:
            raise StorageError("AI advisory reconciliation cursor is oversized")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor: Optional[int] = None
        try:
            descriptor = os.open(temporary, flags, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                descriptor = None
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
            directory_descriptor = os.open(
                destination.parent,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def _read_ai_advisory_reconciliation_cursor(
        self,
    ) -> Optional[Dict[str, Any]]:
        path = self._ai_advisory_reconciliation_cursor_path()
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            return None
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise StorageError(
                "AI advisory reconciliation cursor is not a regular file"
            )
        if metadata.st_uid != os.geteuid():
            raise StorageError("AI advisory reconciliation cursor owner is unsafe")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise StorageError(
                "AI advisory reconciliation cursor permissions are unsafe"
            )
        if metadata.st_size > AI_ADVISORY_RECONCILIATION_CURSOR_MAX_BYTES:
            raise StorageError("AI advisory reconciliation cursor is oversized")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            raw = os.read(
                descriptor, AI_ADVISORY_RECONCILIATION_CURSOR_MAX_BYTES + 1
            )
        finally:
            os.close(descriptor)
        if not raw or len(raw) > AI_ADVISORY_RECONCILIATION_CURSOR_MAX_BYTES:
            raise StorageError("AI advisory reconciliation cursor is invalid")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StorageError("AI advisory reconciliation cursor is invalid") from exc
        expected = {
            "schema_version",
            "reconciliation_cutoff",
            "last_report_rowid",
            "last_report_id",
            "last_report_created_at",
            "last_report_payload_sha256",
        }
        if not isinstance(payload, dict) or set(payload) != expected:
            raise StorageError("AI advisory reconciliation cursor is invalid")
        if (
            payload.get("schema_version")
            != AI_ADVISORY_RECONCILIATION_CURSOR_SCHEMA
        ):
            raise StorageError("AI advisory reconciliation cursor schema is invalid")
        rowid = payload.get("last_report_rowid")
        if isinstance(rowid, bool) or not isinstance(rowid, int) or rowid < 0:
            raise StorageError("AI advisory reconciliation cursor rowid is invalid")
        for field in (
            "last_report_id",
            "last_report_created_at",
            "last_report_payload_sha256",
        ):
            if not isinstance(payload.get(field), str):
                raise StorageError("AI advisory reconciliation cursor is invalid")
        if rowid == 0 and any(
            payload[field]
            for field in (
                "last_report_id",
                "last_report_created_at",
                "last_report_payload_sha256",
            )
        ):
            raise StorageError("AI advisory reconciliation cursor is invalid")
        if rowid > 0 and (
            not payload["last_report_id"]
            or not payload["last_report_created_at"]
            or len(payload["last_report_payload_sha256"]) != 64
        ):
            raise StorageError("AI advisory reconciliation cursor is invalid")
        return payload

    @staticmethod
    def _ai_advisory_first_event_after_cutoff(
        conn: sqlite3.Connection,
        session_id: str,
        cutoff: Dict[str, str],
    ) -> bool:
        first_event = conn.execute(
            """
            SELECT received_at, event_id
            FROM events
            WHERE session_id=?
            ORDER BY received_at, event_id
            LIMIT 1
            """,
            (session_id,),
        ).fetchone()
        if first_event is None:
            return False
        first_event_key = evidence_cutoff_sort_key(
            {
                "schema_version": cutoff["schema_version"],
                "received_at": first_event["received_at"],
                "event_id": first_event["event_id"],
            }
        )
        return first_event_key > evidence_cutoff_sort_key(cutoff)

    def _bootstrap_ai_advisory_reconciliation_cursor(
        self,
        conn: sqlite3.Connection,
        cutoff: Dict[str, str],
    ) -> Dict[str, Any]:
        post_cutoff_event = conn.execute(
            """
            SELECT 1
            FROM events
            WHERE processed IN (0, 1)
              AND received_at >= ?
              AND (
                  received_at > ?
                  OR (received_at = ? AND event_id > ?)
              )
            LIMIT 1
            """,
            (
                cutoff["received_at"],
                cutoff["received_at"],
                cutoff["received_at"],
                cutoff["event_id"],
            ),
        ).fetchone()
        report_row: Optional[sqlite3.Row] = None
        if post_cutoff_event is None:
            report_row = conn.execute(
                """
                SELECT rowid AS report_rowid, report_id, payload_json, created_at
                FROM reports
                ORDER BY rowid DESC
                LIMIT 1
                """
            ).fetchone()
        payload = self._ai_advisory_reconciliation_cursor_payload(
            cutoff, report_row
        )
        self._write_ai_advisory_reconciliation_cursor(payload)
        return payload

    def _validated_ai_advisory_reconciliation_rowid(
        self,
        conn: sqlite3.Connection,
        cursor: Dict[str, Any],
    ) -> int:
        rowid = int(cursor["last_report_rowid"])
        if rowid == 0:
            return 0
        current = conn.execute(
            """
            SELECT rowid AS report_rowid, report_id, payload_json, created_at
            FROM reports
            WHERE rowid=?
            """,
            (rowid,),
        ).fetchone()
        if current is not None:
            current_payload = self._ai_advisory_reconciliation_cursor_payload(
                dict(cursor["reconciliation_cutoff"]), current
            )
            if all(
                current_payload[field] == cursor[field]
                for field in (
                    "last_report_id",
                    "last_report_created_at",
                    "last_report_payload_sha256",
                )
            ):
                return rowid
            if str(current["report_id"]) == cursor["last_report_id"]:
                return max(rowid - 1, 0)
        moved = conn.execute(
            """
            SELECT rowid
            FROM reports
            WHERE report_id=? AND rowid>?
            LIMIT 1
            """,
            (cursor["last_report_id"], rowid),
        ).fetchone()
        if moved is not None:
            return rowid
        raise StorageError(
            "AI advisory reconciliation cursor no longer matches reports"
        )

    def reconcile_ai_advisory_outbox(
        self,
        *,
        reconciliation_cutoff: Dict[str, str],
        limit: int = 100,
        max_queue_records: int = 10_000,
    ) -> Dict[str, int]:
        """Recover post-commit enqueue gaps without touching canonical rows."""

        cutoff = require_valid_evidence_cutoff(reconciliation_cutoff)
        scan_limit = min(max(int(limit), 1), 10_000)
        with self.connection() as conn:
            cursor = self._read_ai_advisory_reconciliation_cursor()
            if cursor is None or cursor["reconciliation_cutoff"] != cutoff:
                cursor = self._bootstrap_ai_advisory_reconciliation_cursor(
                    conn, cutoff
                )
            last_report_rowid = self._validated_ai_advisory_reconciliation_rowid(
                conn, cursor
            )
            rows = conn.execute(
                """
                SELECT rowid AS report_rowid, report_id, session_id,
                       payload_json, created_at
                FROM reports
                WHERE rowid > ?
                ORDER BY rowid
                LIMIT ?
                """,
                (last_report_rowid, scan_limit),
            ).fetchall()
        enqueued = 0
        scanned = 0
        bounded = 0
        advanced_row: Optional[sqlite3.Row] = None
        for row in rows:
            try:
                payload = json.loads(row["payload_json"] or "{}")
            except (TypeError, json.JSONDecodeError):
                advanced_row = row
                continue
            if payload.get("schema_version") != "session_assessment.v4":
                advanced_row = row
                continue
            assessment_id = str(payload.get("assessment_id") or "").strip()
            if not assessment_id:
                advanced_row = row
                continue
            with self.connection() as conn:
                eligible = self._ai_advisory_first_event_after_cutoff(
                    conn, str(row["session_id"]), cutoff
                )
            if not eligible:
                advanced_row = row
                continue
            scanned += 1
            result = self.enqueue_ai_advisory_job(
                str(row["report_id"]),
                str(row["session_id"]),
                assessment_id,
                reconciliation_cutoff=cutoff,
                max_queue_records=max_queue_records,
            )
            if result is None:
                bounded += 1
                break
            enqueued += 1
            advanced_row = row
        if advanced_row is not None:
            self._write_ai_advisory_reconciliation_cursor(
                self._ai_advisory_reconciliation_cursor_payload(
                    cutoff, advanced_row
                )
            )
        return {"scanned": scanned, "enqueued": enqueued, "bounded": bounded}

    def claim_ai_advisory_jobs(
        self,
        owner: str,
        limit: int,
        lease_seconds: float,
        max_attempts: int,
        *,
        now: Any = None,
    ) -> List[Dict[str, Any]]:
        rows = self.claim_jobs(
            "ai_advisory",
            owner,
            limit,
            lease_seconds,
            max_attempts,
            now=now,
        )
        return [materialize_ai_advisory_job_claim(row) for row in rows]

    def get_report_by_id(self, report_id: str) -> Optional[Dict[str, Any]]:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM reports WHERE report_id=? LIMIT 1",
                (_required_identity(report_id, "report_id"),),
            ).fetchone()
        if row is None:
            return None
        item = dict(row)
        try:
            item["payload"] = json.loads(item.get("payload_json") or "{}")
        except (TypeError, json.JSONDecodeError) as exc:
            raise StorageError("stored report is not valid JSON") from exc
        return item

    def get_current_report_for_session(
        self, session_id: str
    ) -> Optional[Dict[str, Any]]:
        session_key = _required_identity(session_id, "session_id")
        with self.connection() as conn:
            session = conn.execute(
                "SELECT payload_json FROM sessions WHERE session_id=? LIMIT 1",
                (session_key,),
            ).fetchone()
            current_report_id = ""
            if session is not None:
                try:
                    session_payload = json.loads(session["payload_json"] or "{}")
                except (TypeError, json.JSONDecodeError) as exc:
                    raise StorageError("stored session is not valid JSON") from exc
                current_report_id = str(
                    session_payload.get("report_id") or ""
                ).strip()
            if current_report_id:
                row = conn.execute(
                    """
                    SELECT * FROM reports
                    WHERE report_id=? AND session_id=?
                    LIMIT 1
                    """,
                    (current_report_id, session_key),
                ).fetchone()
            else:
                # Compatibility for historical session rows created before the
                # report pointer was recorded.
                row = conn.execute(
                    """
                    SELECT * FROM reports
                    WHERE session_id=?
                    ORDER BY created_at DESC, report_id DESC
                    LIMIT 1
                    """,
                    (session_key,),
                ).fetchone()
        if row is None:
            return None
        item = dict(row)
        try:
            item["payload"] = json.loads(item.get("payload_json") or "{}")
        except (TypeError, json.JSONDecodeError) as exc:
            raise StorageError("stored report is not valid JSON") from exc
        return item

    def _decode_ai_advisory_row(self, row: Any) -> Optional[Dict[str, Any]]:
        if row is None:
            return None
        item = dict(row)
        try:
            item["payload"] = json.loads(item.get("payload_json") or "{}")
            item["metrics"] = json.loads(item.get("metrics_json") or "{}")
        except (TypeError, json.JSONDecodeError) as exc:
            raise StorageError("stored AI advisory is not valid JSON") from exc
        return item

    def get_ai_advisory_by_cache_key(
        self, cache_key: str
    ) -> Optional[Dict[str, Any]]:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM ai_advisories WHERE cache_key=? LIMIT 1",
                (_required_identity(cache_key, "cache_key"),),
            ).fetchone()
        return self._decode_ai_advisory_row(row)

    def get_ai_advisory_for_session(
        self, session_id: str
    ) -> Optional[Dict[str, Any]]:
        with self.connection() as conn:
            row = conn.execute(
                """
                SELECT * FROM ai_advisories
                WHERE session_id=?
                ORDER BY created_at DESC, advisory_id DESC
                LIMIT 1
                """,
                (_required_identity(session_id, "session_id"),),
            ).fetchone()
        return self._decode_ai_advisory_row(row)

    def get_ai_advisory_for_report(
        self, report_id: str, assessment_id: str
    ) -> Optional[Dict[str, Any]]:
        with self.connection() as conn:
            row = conn.execute(
                """
                SELECT * FROM ai_advisories
                WHERE report_id=? AND assessment_id=?
                ORDER BY created_at DESC, advisory_id DESC
                LIMIT 1
                """,
                (
                    _required_identity(report_id, "report_id"),
                    _required_identity(assessment_id, "assessment_id"),
                ),
            ).fetchone()
        return self._decode_ai_advisory_row(row)

    def get_ai_advisory_outbox_for_report(
        self, report_id: str, assessment_id: str
    ) -> Optional[Dict[str, Any]]:
        with self.connection() as conn:
            row = conn.execute(
                """
                SELECT * FROM ai_advisory_outbox
                WHERE report_id=? AND assessment_id=?
                LIMIT 1
                """,
                (
                    _required_identity(report_id, "report_id"),
                    _required_identity(assessment_id, "assessment_id"),
                ),
            ).fetchone()
        return dict(row) if row is not None else None

    def prune_ai_advisories(
        self,
        retention_days: int = 30,
        keep_latest_per_session: bool = False,
        *,
        max_records: int = 50_000,
        max_storage_bytes: int = 256 * 1024 * 1024,
        now: Any = None,
    ) -> Dict[str, Any]:
        """Strictly bound optional advisory rows by age, count, and bytes."""
        if (
            isinstance(retention_days, bool)
            or not isinstance(retention_days, int)
            or not 1 <= retention_days <= 3650
        ):
            raise ValueError("retention_days must be between 1 and 3650")
        if keep_latest_per_session:
            raise ValueError("keep_latest_per_session is incompatible with bounded retention")
        if isinstance(max_records, bool) or int(max_records) < 1:
            raise ValueError("max_records must be positive")
        if isinstance(max_storage_bytes, bool) or int(max_storage_bytes) < 1:
            raise ValueError("max_storage_bytes must be positive")
        current_time = _utc_timestamp(now)
        reference = _parse_dt(current_time)
        if reference is None:  # pragma: no cover - _utc_timestamp validates
            raise ValueError("retention reference is invalid")
        cutoff = (reference - timedelta(days=retention_days)).isoformat()
        with self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                "DELETE FROM ai_advisories WHERE created_at < ?",
                (cutoff,),
            )
            deleted_advisories = int(cursor.rowcount or 0)
            retained_rows = conn.execute(
                """
                SELECT advisory_id,
                       LENGTH(advisory_id) + LENGTH(cache_key) + LENGTH(report_id)
                       + LENGTH(session_id) + LENGTH(assessment_id) + LENGTH(status)
                       + LENGTH(projection_sha256) + LENGTH(request_sha256)
                       + LENGTH(response_sha256) + LENGTH(provider_id) + LENGTH(model_id)
                       + LENGTH(prompt_sha256) + LENGTH(schema_sha256)
                       + LENGTH(policy_sha256) + LENGTH(payload_json)
                       + LENGTH(metrics_json) + LENGTH(created_at) AS record_bytes
                FROM ai_advisories
                ORDER BY created_at DESC, advisory_id DESC
                """
            ).fetchall()
            used_records = 0
            used_bytes = 0
            overflow_ids: list[tuple[str]] = []
            for row in retained_rows:
                row_bytes = int(row["record_bytes"] or 0)
                if (
                    used_records >= int(max_records)
                    or used_bytes + row_bytes > int(max_storage_bytes)
                ):
                    overflow_ids.append((str(row["advisory_id"]),))
                    continue
                used_records += 1
                used_bytes += row_bytes
            if overflow_ids:
                conn.executemany(
                    "DELETE FROM ai_advisories WHERE advisory_id=?",
                    overflow_ids,
                )
                deleted_advisories += len(overflow_ids)
            cursor = conn.execute(
                """
                DELETE FROM ai_advisory_outbox
                WHERE status IN ('succeeded', 'failed')
                  AND updated_at < ?
                """,
                (cutoff,),
            )
            deleted_outbox = int(cursor.rowcount or 0)
        return {
            "retention_days": retention_days,
            "cutoff": cutoff,
            "keep_latest_per_session": False,
            "max_records": int(max_records),
            "max_storage_bytes": int(max_storage_bytes),
            "records_retained": used_records,
            "storage_bytes_retained": used_bytes,
            "advisories_deleted": deleted_advisories,
            "outbox_deleted": deleted_outbox,
        }

    def complete_ai_advisory_job(
        self,
        job_id: str,
        owner: str,
        token: str,
        advisory_record: Dict[str, Any],
        completion_code: str = "accepted",
        *,
        now: Any = None,
    ) -> Optional[str]:
        required = {
            "advisory_id",
            "cache_key",
            "report_id",
            "session_id",
            "assessment_id",
            "status",
            "projection_sha256",
            "request_sha256",
            "response_sha256",
            "provider_id",
            "model_id",
            "prompt_sha256",
            "schema_sha256",
            "policy_sha256",
            "payload",
            "metrics",
        }
        if set(advisory_record) != required:
            raise ValueError("AI advisory storage record has invalid keys")
        current_time = _utc_timestamp(now)
        advisory_id = _required_identity(
            advisory_record["advisory_id"], "advisory_id"
        )
        if completion_code not in {"accepted", "rejected", "cache_replayed"}:
            raise ValueError("AI advisory completion_code is invalid")
        with self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            claim = conn.execute(
                """
                SELECT report_id, session_id, assessment_id
                FROM ai_advisory_outbox
                WHERE job_id=? AND status='running' AND claim_owner=?
                  AND claim_token=? AND claim_expires_at > ?
                """,
                (job_id, owner, token, current_time),
            ).fetchone()
            if claim is None:
                return None
            for field in ("report_id", "session_id", "assessment_id"):
                if str(claim[field]) != str(advisory_record[field]):
                    raise StorageError("AI advisory record does not match its outbox claim")
            conn.execute(
                """
                INSERT OR IGNORE INTO ai_advisories
                (advisory_id, cache_key, report_id, session_id, assessment_id,
                 status, projection_sha256, request_sha256, response_sha256,
                 provider_id, model_id, prompt_sha256, schema_sha256,
                 policy_sha256, payload_json, metrics_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    advisory_id,
                    _required_identity(advisory_record["cache_key"], "cache_key"),
                    claim["report_id"],
                    claim["session_id"],
                    claim["assessment_id"],
                    _required_identity(advisory_record["status"], "status"),
                    _required_identity(advisory_record["projection_sha256"], "projection_sha256"),
                    _required_identity(advisory_record["request_sha256"], "request_sha256"),
                    _required_identity(advisory_record["response_sha256"], "response_sha256"),
                    _required_identity(advisory_record["provider_id"], "provider_id"),
                    str(advisory_record["model_id"] or ""),
                    _required_identity(advisory_record["prompt_sha256"], "prompt_sha256"),
                    _required_identity(advisory_record["schema_sha256"], "schema_sha256"),
                    _required_identity(advisory_record["policy_sha256"], "policy_sha256"),
                    stable_json(advisory_record["payload"]),
                    stable_json(advisory_record["metrics"]),
                    current_time,
                ),
            )
            existing = conn.execute(
                "SELECT advisory_id FROM ai_advisories WHERE cache_key=? LIMIT 1",
                (advisory_record["cache_key"],),
            ).fetchone()
            if existing is None:  # pragma: no cover - same transaction
                raise StorageError("AI advisory insert was not durable")
            persisted_id = str(existing["advisory_id"])
            cursor = conn.execute(
                """
                UPDATE ai_advisory_outbox
                SET status='succeeded', advisory_id=?, error=NULL,
                    next_retry_at=NULL, claim_owner=NULL, claim_token=NULL,
                    claim_expires_at=NULL, last_error_code=NULL,
                    last_error_type=NULL, last_error_at=NULL,
                    completion_code=?, completed_at=?, updated_at=?
                WHERE job_id=? AND status='running' AND claim_owner=?
                  AND claim_token=? AND claim_expires_at > ?
                """,
                (
                    persisted_id,
                    completion_code,
                    current_time,
                    current_time,
                    job_id,
                    owner,
                    token,
                    current_time,
                ),
            )
            if cursor.rowcount != 1:  # pragma: no cover - same transaction
                raise StorageError("AI advisory claim changed during completion")
        return persisted_id

    def fail_analysis_job(
        self,
        job_id: str,
        owner: str,
        token: str,
        error_code: str,
        error_type: str,
        retryable: bool,
        max_attempts: int,
        retry_delay_seconds: float,
        *,
        now: Any = None,
    ) -> str:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT session_id FROM analysis_jobs WHERE job_id=? LIMIT 1",
                (job_id,),
            ).fetchone()
        result = self.fail_job(
            "analysis",
            job_id,
            owner,
            token,
            error_code,
            error_type,
            retryable,
            max_attempts,
            retry_delay_seconds,
            now=now,
        )
        if row and result in {"retry_scheduled", "failed"}:
            status = "retry" if result == "retry_scheduled" else "failed"
            self.update_session_analysis_status(
                row["session_id"],
                status,
                error=f"{error_code}:{error_type}",
            )
        return result

    def skip_analysis_job(
        self,
        job_id: str,
        owner: str,
        token: str,
        reason: str,
        *,
        now: Any = None,
    ) -> bool:
        current_time = _utc_timestamp(now)
        with self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT session_id FROM analysis_jobs
                WHERE job_id=? AND status='running' AND claim_owner=?
                  AND claim_token=? AND claim_expires_at > ?
                LIMIT 1
                """,
                (job_id, owner, token, current_time),
            ).fetchone()
            if row is None:
                return False
            cursor = conn.execute(
                """
                UPDATE analysis_jobs
                SET status='skipped', error=?, next_retry_at=NULL,
                    claim_owner=NULL, claim_token=NULL, claim_expires_at=NULL,
                    completed_at=?, updated_at=?
                WHERE job_id=? AND status='running' AND claim_owner=?
                  AND claim_token=? AND claim_expires_at > ?
                """,
                (reason, current_time, current_time, job_id, owner, token, current_time),
            )
        if cursor.rowcount == 1:
            self.update_session_analysis_status(row["session_id"], "skipped", skip_reason=reason)
            return True
        return False

    def save_feed_status(self, status: Dict[str, Any]) -> None:
        now = utc_now()
        with self.connection() as conn:
            for name, payload in status.items():
                if name == "summary":
                    continue
                conn.execute(
                    """
                    INSERT INTO feed_status (name, payload_json, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(name) DO UPDATE SET
                        payload_json=excluded.payload_json,
                        updated_at=excluded.updated_at
                    """,
                    (name, stable_json(payload), now),
                )

    def get_enrichment_record(
        self,
        observable_type: str,
        observable_value: str,
        allow_stale: bool = True,
    ) -> Optional[Dict[str, Any]]:
        with self.connection() as conn:
            row = conn.execute(
                """
                SELECT * FROM enrichment_records
                WHERE observable_type = ? AND observable_value = ?
                """,
                (observable_type, observable_value),
            ).fetchone()
        if not row:
            return None
        record = dict(row)
        record["payload"] = json.loads(record["payload_json"])
        record["provider_status"] = json.loads(record["provider_status_json"])
        record["is_stale"] = not _is_future(record.get("expires_at"))
        if record["is_stale"] and not allow_stale:
            return None
        return record

    def load_enrichment_cache(self, observable_type: str = "ip", allow_stale: bool = True) -> Dict[str, Dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT observable_value, payload_json, expires_at
                FROM enrichment_records
                WHERE observable_type = ?
                """,
                (observable_type,),
            ).fetchall()
        cache: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            is_stale = not _is_future(row["expires_at"])
            if is_stale and not allow_stale:
                continue
            payload = json.loads(row["payload_json"])
            payload.setdefault(
                "enrichment_cache",
                {
                    "source": "storage",
                    "status": "stale" if is_stale else "fresh",
                    "expires_at": row["expires_at"],
                },
            )
            cache[row["observable_value"]] = payload
        return cache

    def save_enrichment_record(
        self,
        observable_type: str,
        observable_value: str,
        payload: Dict[str, Any],
        provider_status: Dict[str, Any],
        expires_at: Optional[str] = None,
    ) -> None:
        now = utc_now()
        previous = self.get_enrichment_record(observable_type, observable_value, allow_stale=True)
        first_seen = previous["first_seen"] if previous else now
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO enrichment_records
                (observable_type, observable_value, payload_json, provider_status_json,
                 first_seen, last_seen, expires_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(observable_type, observable_value) DO UPDATE SET
                    payload_json=excluded.payload_json,
                    provider_status_json=excluded.provider_status_json,
                    last_seen=excluded.last_seen,
                    expires_at=excluded.expires_at,
                    updated_at=excluded.updated_at
                """,
                (
                    observable_type,
                    observable_value,
                    stable_json(payload),
                    stable_json(provider_status),
                    first_seen,
                    now,
                    expires_at,
                    now,
                ),
            )

    def enqueue_enrichment_job(
        self,
        observable_type: str,
        observable_value: str,
        session_id: str = "",
        payload: Optional[Dict[str, Any]] = None,
        force: bool = False,
        priority: str = "normal",
        priority_reason: str = "",
    ) -> tuple[str, bool]:
        existing = self.get_enrichment_record(observable_type, observable_value, allow_stale=False)
        job_id = stable_id(
            "enrichjob",
            {"observable_type": observable_type, "observable_value": observable_value},
        )
        if existing and not force:
            return job_id, False
        now = utc_now()
        priority = _normalize_priority(priority)
        body = payload or {}
        body.setdefault("observable_type", observable_type)
        body.setdefault("observable_value", observable_value)
        if session_id:
            body.setdefault("session_id", session_id)
        if priority != "normal":
            body.setdefault("priority", priority)
        if priority_reason:
            body.setdefault("priority_reason", priority_reason)
        with self.connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO enrichment_jobs
                (job_id, observable_type, observable_value, session_id, status,
                 priority, priority_reason, payload_json, attempts, next_retry_at, error, created_at, updated_at)
                VALUES (?, ?, ?, ?, 'queued', ?, ?, ?, 0, NULL, NULL, ?, ?)
                ON CONFLICT(observable_type, observable_value) DO UPDATE SET
                    session_id=COALESCE(excluded.session_id, enrichment_jobs.session_id),
                    status=CASE
                        WHEN enrichment_jobs.status IN ('queued', 'running', 'retry') THEN enrichment_jobs.status
                        ELSE 'queued'
                    END,
                    priority=CASE
                        WHEN
                            (CASE excluded.priority WHEN 'urgent' THEN 3 WHEN 'high' THEN 2 WHEN 'normal' THEN 1 ELSE 0 END) >
                            (CASE enrichment_jobs.priority WHEN 'urgent' THEN 3 WHEN 'high' THEN 2 WHEN 'normal' THEN 1 ELSE 0 END)
                        THEN excluded.priority
                        ELSE enrichment_jobs.priority
                    END,
                    priority_reason=CASE
                        WHEN
                            (CASE excluded.priority WHEN 'urgent' THEN 3 WHEN 'high' THEN 2 WHEN 'normal' THEN 1 ELSE 0 END) >
                            (CASE enrichment_jobs.priority WHEN 'urgent' THEN 3 WHEN 'high' THEN 2 WHEN 'normal' THEN 1 ELSE 0 END)
                        THEN excluded.priority_reason
                        ELSE enrichment_jobs.priority_reason
                    END,
                    payload_json=excluded.payload_json,
                    next_retry_at=NULL,
                    error=NULL,
                    updated_at=excluded.updated_at
                """,
                (
                    job_id,
                    observable_type,
                    observable_value,
                    session_id or None,
                    priority,
                    priority_reason or None,
                    stable_json(body),
                    now,
                    now,
                ),
            )
        return job_id, cur.rowcount > 0

    def claim_enrichment_jobs(
        self,
        owner: str,
        limit: int,
        lease_seconds: float,
        max_attempts: int,
        *,
        now: Any = None,
    ) -> List[Dict[str, Any]]:
        rows = self.claim_jobs(
            "enrichment", owner, limit, lease_seconds, max_attempts, now=now
        )
        return [
            {
                "job_id": row["job_id"],
                "observable_type": row["observable_type"],
                "observable_value": row["observable_value"],
                "session_id": row["session_id"],
                "priority": row["priority"],
                "priority_reason": row["priority_reason"],
                "payload": json.loads(row["payload_json"]),
                "attempts": row["attempts"],
                "claim_owner": row["claim_owner"],
                "claim_token": row["claim_token"],
                "claim_expires_at": row["claim_expires_at"],
            }
            for row in rows
        ]

    def reprioritize_enrichment_jobs(
        self,
        observable_value: str,
        observable_type: str = "ip",
        priority: str = "urgent",
        reason: str = "",
        session_id: str = "",
    ) -> int:
        priority = _normalize_priority(priority)
        if not observable_value:
            return 0
        now = utc_now()
        with self.connection() as conn:
            cur = conn.execute(
                """
                UPDATE enrichment_jobs
                SET
                    priority=CASE
                        WHEN
                            (CASE ? WHEN 'urgent' THEN 3 WHEN 'high' THEN 2 WHEN 'normal' THEN 1 ELSE 0 END) >
                            (CASE priority WHEN 'urgent' THEN 3 WHEN 'high' THEN 2 WHEN 'normal' THEN 1 ELSE 0 END)
                        THEN ?
                        ELSE priority
                    END,
                    priority_reason=CASE
                        WHEN
                            (CASE ? WHEN 'urgent' THEN 3 WHEN 'high' THEN 2 WHEN 'normal' THEN 1 ELSE 0 END) >
                            (CASE priority WHEN 'urgent' THEN 3 WHEN 'high' THEN 2 WHEN 'normal' THEN 1 ELSE 0 END)
                        THEN ?
                        ELSE priority_reason
                    END,
                    session_id=COALESCE(NULLIF(?, ''), session_id),
                    next_retry_at=NULL,
                    updated_at=?
                WHERE observable_type=? AND observable_value=? AND status IN ('queued', 'retry')
                """,
                (
                    priority,
                    priority,
                    priority,
                    reason or None,
                    session_id,
                    now,
                    observable_type,
                    observable_value,
                ),
            )
        return int(cur.rowcount or 0)

    def complete_enrichment_job(
        self,
        job_id: str,
        owner: str,
        token: str,
        *,
        now: Any = None,
    ) -> bool:
        current_time = _utc_timestamp(now)
        with self.connection() as conn:
            cursor = conn.execute(
                """
                UPDATE enrichment_jobs
                SET status='succeeded', error=NULL, next_retry_at=NULL,
                    claim_owner=NULL, claim_token=NULL, claim_expires_at=NULL,
                    completed_at=?, updated_at=?
                WHERE job_id=? AND status='running' AND claim_owner=?
                  AND claim_token=? AND claim_expires_at > ?
                """,
                (current_time, current_time, job_id, owner, token, current_time),
            )
            return cursor.rowcount == 1

    def fail_enrichment_job(
        self,
        job_id: str,
        owner: str,
        token: str,
        error_code: str,
        error_type: str,
        retryable: bool,
        max_attempts: int,
        retry_delay_seconds: float,
        *,
        now: Any = None,
    ) -> str:
        return self.fail_job(
            "enrichment",
            job_id,
            owner,
            token,
            error_code,
            error_type,
            retryable,
            max_attempts,
            retry_delay_seconds,
            now=now,
        )

    def record_observable_sighting(self, sighting: Dict[str, Any]) -> str:
        observable_type = str(sighting.get("observable_type") or "").strip().lower()
        observable_value = str(sighting.get("observable_value") or "").strip()
        session_id = str(sighting.get("session_id") or "unknown")
        role = str(sighting.get("role") or "observed")
        source = str(sighting.get("source") or "unknown")
        event_id = str(sighting.get("event_id") or "")
        timestamp = str(sighting.get("timestamp") or "") or utc_now()
        if not observable_type or not observable_value:
            raise ValueError("observable sighting requires observable_type and observable_value")
        sighting_id = sighting.get("sighting_id") or stable_id(
            "sighting",
            {
                "observable_type": observable_type,
                "observable_value": observable_value,
                "session_id": session_id,
                "role": role,
                "source": source,
                "event_id": event_id,
                "eventid": sighting.get("eventid", ""),
            },
        )
        now = utc_now()
        payload = dict(sighting.get("payload") or {})
        payload.setdefault("observable_type", observable_type)
        payload.setdefault("observable_value", observable_value)
        payload.setdefault("role", role)
        payload.setdefault("source", source)
        with self.connection() as conn:
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO observable_sightings
                (sighting_id, observable_type, observable_value, session_id, sensor_id, src_ip,
                 event_id, eventid, role, source, timestamp, payload_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sighting_id,
                    observable_type,
                    observable_value,
                    session_id,
                    sighting.get("sensor_id", ""),
                    sighting.get("src_ip", ""),
                    event_id,
                    sighting.get("eventid", ""),
                    role,
                    source,
                    timestamp,
                    stable_json(payload),
                    now,
                ),
            )
            if cur.rowcount == 1:
                conn.execute(
                    """
                    INSERT INTO observables
                    (observable_type, observable_value, first_seen, last_seen, sighting_count, payload_json)
                    VALUES (?, ?, ?, ?, 1, ?)
                    ON CONFLICT(observable_type, observable_value) DO UPDATE SET
                        last_seen=CASE
                            WHEN excluded.last_seen > observables.last_seen THEN excluded.last_seen
                            ELSE observables.last_seen
                        END,
                        sighting_count=observables.sighting_count + 1,
                        payload_json=excluded.payload_json
                    """,
                    (
                        observable_type,
                        observable_value,
                        timestamp,
                        timestamp,
                        stable_json({"last_role": role, "last_source": source}),
                    ),
                )
        return sighting_id

    def enqueue_threat_hunt_job(
        self,
        session_id: str,
        observable_type: str,
        observable_value: str,
        trigger_reason: str = "",
        payload: Optional[Dict[str, Any]] = None,
    ) -> tuple[str, bool]:
        session_id = str(session_id or "unknown")
        observable_type = str(observable_type or "").strip().lower()
        observable_value = str(observable_value or "").strip()
        if not observable_type or not observable_value:
            raise ValueError("threat hunt job requires observable_type and observable_value")
        job_id = stable_id(
            "threathuntjob",
            {
                "session_id": session_id,
                "observable_type": observable_type,
                "observable_value": observable_value,
            },
        )
        now = utc_now()
        body = dict(payload or {})
        body.setdefault("session_id", session_id)
        body.setdefault("observable_type", observable_type)
        body.setdefault("observable_value", observable_value)
        body.setdefault("trigger_reason", trigger_reason)
        with self.connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO threat_hunt_jobs
                (job_id, session_id, observable_type, observable_value, trigger_reason,
                 status, result_json, payload_json, attempts, error, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 'queued', NULL, ?, 0, NULL, ?, ?)
                ON CONFLICT(session_id, observable_type, observable_value) DO UPDATE SET
                    status=CASE
                        WHEN threat_hunt_jobs.status IN ('queued', 'running', 'retry') THEN threat_hunt_jobs.status
                        ELSE 'queued'
                    END,
                    trigger_reason=excluded.trigger_reason,
                    payload_json=excluded.payload_json,
                    error=NULL,
                    updated_at=excluded.updated_at
                """,
                (
                    job_id,
                    session_id,
                    observable_type,
                    observable_value,
                    trigger_reason or None,
                    stable_json(body),
                    now,
                    now,
                ),
            )
        return job_id, cur.rowcount == 1

    def claim_threat_hunt_jobs(
        self,
        owner: str,
        limit: int,
        lease_seconds: float,
        max_attempts: int,
        *,
        now: Any = None,
    ) -> List[Dict[str, Any]]:
        rows = self.claim_jobs(
            "threat_hunt", owner, limit, lease_seconds, max_attempts, now=now
        )
        jobs = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.get("payload_json") or "{}")
            item["result"] = json.loads(item.get("result_json") or "{}") if item.get("result_json") else {}
            jobs.append(item)
        return jobs

    def complete_threat_hunt_job(
        self,
        job_id: str,
        owner: str,
        token: str,
        result: Dict[str, Any],
        *,
        now: Any = None,
    ) -> bool:
        current_time = _utc_timestamp(now)
        with self.connection() as conn:
            cursor = conn.execute(
                """
                UPDATE threat_hunt_jobs
                SET status='succeeded', result_json=?, error=NULL,
                    next_retry_at=NULL, claim_owner=NULL, claim_token=NULL,
                    claim_expires_at=NULL, completed_at=?, updated_at=?
                WHERE job_id=? AND status='running' AND claim_owner=?
                  AND claim_token=? AND claim_expires_at > ?
                """,
                (
                    stable_json(result),
                    current_time,
                    current_time,
                    job_id,
                    owner,
                    token,
                    current_time,
                ),
            )
            return cursor.rowcount == 1

    def fail_threat_hunt_job(
        self,
        job_id: str,
        owner: str,
        token: str,
        error_code: str,
        error_type: str,
        retryable: bool,
        max_attempts: int,
        retry_delay_seconds: float,
        *,
        now: Any = None,
    ) -> str:
        return self.fail_job(
            "threat_hunt",
            job_id,
            owner,
            token,
            error_code,
            error_type,
            retryable,
            max_attempts,
            retry_delay_seconds,
            now=now,
        )

    def find_sessions_by_observable(
        self,
        observable_type: str,
        observable_value: str,
        exclude_session_id: str = "",
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT
                    os.session_id,
                    COUNT(*) AS sighting_count,
                    MIN(COALESCE(os.timestamp, os.created_at)) AS first_seen,
                    MAX(COALESCE(os.timestamp, os.created_at)) AS last_seen,
                    GROUP_CONCAT(DISTINCT os.role) AS roles,
                    GROUP_CONCAT(DISTINCT os.source) AS sources,
                    s.src_ip AS src_ip,
                    s.ended AS ended,
                    s.updated_at AS updated_at,
                    s.payload_json AS payload_json
                FROM observable_sightings os
                LEFT JOIN sessions s ON s.session_id = os.session_id
                WHERE os.observable_type = ?
                  AND os.observable_value = ?
                  AND os.session_id <> ?
                GROUP BY os.session_id
                ORDER BY last_seen DESC
                LIMIT ?
                """,
                (observable_type, observable_value, exclude_session_id, limit),
            ).fetchall()
        output = []
        for row in rows:
            item = dict(row)
            item["ended"] = bool(item.get("ended"))
            item["payload"] = json.loads(item.get("payload_json") or "{}") if item.get("payload_json") else {}
            item.pop("payload_json", None)
            item["roles"] = [value for value in str(item.get("roles") or "").split(",") if value]
            item["sources"] = [value for value in str(item.get("sources") or "").split(",") if value]
            output.append(item)
        return output

    def save_session_link(self, link_payload: Dict[str, Any]) -> str:
        a = str(link_payload.get("session_id_a") or "").strip()
        b = str(link_payload.get("session_id_b") or "").strip()
        if not a or not b:
            raise ValueError("session link requires session_id_a and session_id_b")
        observable_type = str(link_payload.get("observable_type") or "").strip().lower()
        observable_value = str(link_payload.get("observable_value") or "").strip()
        link_type = str(link_payload.get("link_type") or "shared_observable").strip()
        canonical_sessions = sorted([a, b])
        link_id = link_payload.get("link_id") or stable_id(
            "sessionlink",
            {
                "sessions": canonical_sessions,
                "link_type": link_type,
                "observable_type": observable_type,
                "observable_value": observable_value,
            },
        )
        now = link_payload.get("created_at") or utc_now()
        payload = dict(link_payload)
        payload["link_id"] = link_id
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO session_links
                (link_id, session_id_a, session_id_b, link_type, observable_type,
                 observable_value, confidence, payload_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(link_id) DO UPDATE SET
                    session_id_a=excluded.session_id_a,
                    session_id_b=excluded.session_id_b,
                    link_type=excluded.link_type,
                    observable_type=excluded.observable_type,
                    observable_value=excluded.observable_value,
                    confidence=excluded.confidence,
                    payload_json=excluded.payload_json,
                    created_at=excluded.created_at
                """,
                (
                    link_id,
                    a,
                    b,
                    link_type,
                    observable_type or None,
                    observable_value or None,
                    float(link_payload.get("confidence") or 0.0),
                    stable_json(payload),
                    now,
                ),
            )
        return link_id

    def list_session_links(self, session_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM session_links
                WHERE session_id_a = ? OR session_id_b = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (session_id, session_id, limit),
            ).fetchall()
        output = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.get("payload_json") or "{}")
            output.append(item)
        return output

    def save_campaign(self, campaign: Dict[str, Any]) -> str:
        campaign_id = str(campaign.get("campaign_id") or "").strip()
        if not campaign_id:
            raise ValueError("campaign_id is required")
        now = utc_now()
        payload = dict(campaign)
        confirmed_tactics = payload.get("confirmed_tactics") or []
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO campaigns
                (campaign_id, primary_fingerprint_type, primary_fingerprint_value,
                 hassh_fingerprint, ja3_fingerprint, tactic_sequence_hash, command_pattern_hash,
                 source_ip, session_count, first_seen, last_seen, confirmed_tactics_json,
                 max_confirmed_severity, payload_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(campaign_id) DO UPDATE SET
                    primary_fingerprint_type=excluded.primary_fingerprint_type,
                    primary_fingerprint_value=excluded.primary_fingerprint_value,
                    hassh_fingerprint=COALESCE(NULLIF(excluded.hassh_fingerprint, ''), campaigns.hassh_fingerprint),
                    ja3_fingerprint=COALESCE(NULLIF(excluded.ja3_fingerprint, ''), campaigns.ja3_fingerprint),
                    tactic_sequence_hash=COALESCE(NULLIF(excluded.tactic_sequence_hash, ''), campaigns.tactic_sequence_hash),
                    command_pattern_hash=COALESCE(NULLIF(excluded.command_pattern_hash, ''), campaigns.command_pattern_hash),
                    source_ip=COALESCE(NULLIF(excluded.source_ip, ''), campaigns.source_ip),
                    session_count=excluded.session_count,
                    first_seen=CASE WHEN excluded.first_seen < campaigns.first_seen THEN excluded.first_seen ELSE campaigns.first_seen END,
                    last_seen=CASE WHEN excluded.last_seen > campaigns.last_seen THEN excluded.last_seen ELSE campaigns.last_seen END,
                    confirmed_tactics_json=excluded.confirmed_tactics_json,
                    max_confirmed_severity=excluded.max_confirmed_severity,
                    payload_json=excluded.payload_json,
                    updated_at=excluded.updated_at
                """,
                (
                    campaign_id,
                    campaign.get("primary_fingerprint_type") or "",
                    campaign.get("primary_fingerprint_value") or "",
                    campaign.get("hassh_fingerprint") or "",
                    campaign.get("ja3_fingerprint") or "",
                    campaign.get("tactic_sequence_hash") or "",
                    campaign.get("command_pattern_hash") or "",
                    campaign.get("source_ip") or "",
                    int(campaign.get("session_count") or 0),
                    campaign.get("first_seen") or now,
                    campaign.get("last_seen") or now,
                    stable_json(confirmed_tactics),
                    campaign.get("max_confirmed_severity") or "info",
                    stable_json(payload),
                    campaign.get("created_at") or now,
                    now,
                ),
            )
        return campaign_id

    def get_campaign(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        if not campaign_id:
            return None
        with self.connection() as conn:
            row = conn.execute("SELECT * FROM campaigns WHERE campaign_id = ? LIMIT 1", (campaign_id,)).fetchone()
        if not row:
            return None
        item = dict(row)
        item["payload"] = json.loads(item.get("payload_json") or "{}")
        item["confirmed_tactics"] = json.loads(item.get("confirmed_tactics_json") or "[]")
        return item

    def find_matching_campaigns(self, fingerprint: Dict[str, Any], limit: int = 20) -> List[Dict[str, Any]]:
        fields = [
            ("hassh_fingerprint", fingerprint.get("hassh_fingerprint")),
            ("ja3_fingerprint", fingerprint.get("ja3_fingerprint")),
            ("command_pattern_hash", fingerprint.get("command_pattern_hash")),
            ("tactic_sequence_hash", fingerprint.get("tactic_sequence_hash")),
            ("source_ip", fingerprint.get("src_ip")),
        ]
        conditions = []
        params: List[Any] = []
        for column, value in fields:
            text = str(value or "").strip()
            if text and text.lower() != "unknown":
                conditions.append(f"{column} = ?")
                params.append(text)
        if not conditions:
            return []
        params.append(limit)
        with self.connection() as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM campaigns
                WHERE {" OR ".join(conditions)}
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                params,
            ).fetchall()
        output = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.get("payload_json") or "{}")
            item["confirmed_tactics"] = json.loads(item.get("confirmed_tactics_json") or "[]")
            output.append(item)
        return output

    def link_campaign_session(
        self,
        campaign_id: str,
        session_id: str,
        match_reasons: Optional[List[str]] = None,
        confidence: float = 0.0,
        payload: Optional[Dict[str, Any]] = None,
    ) -> tuple[str, bool]:
        link_id = stable_id("campaignsession", {"campaign_id": campaign_id, "session_id": session_id})
        now = utc_now()
        body = dict(payload or {})
        body.setdefault("campaign_id", campaign_id)
        body.setdefault("session_id", session_id)
        reasons = list(match_reasons or [])
        with self.connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO campaign_sessions
                (link_id, campaign_id, session_id, match_reasons_json, confidence, payload_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(campaign_id, session_id) DO UPDATE SET
                    match_reasons_json=excluded.match_reasons_json,
                    confidence=excluded.confidence,
                    payload_json=excluded.payload_json
                """,
                (
                    link_id,
                    campaign_id,
                    session_id,
                    stable_json(reasons),
                    float(confidence or 0.0),
                    stable_json(body),
                    now,
                ),
            )
        return link_id, cur.rowcount == 1

    def count_campaign_sessions(self, campaign_id: str) -> int:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS count FROM campaign_sessions WHERE campaign_id = ?",
                (campaign_id,),
            ).fetchone()
        return int(row["count"] if row else 0)

    def list_campaign_sessions(self, campaign_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM campaign_sessions
                WHERE campaign_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (campaign_id, limit),
            ).fetchall()
        output = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.get("payload_json") or "{}")
            item["match_reasons"] = json.loads(item.get("match_reasons_json") or "[]")
            output.append(item)
        return output

    def list_session_campaigns(self, session_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT cs.*, c.payload_json AS campaign_payload_json, c.max_confirmed_severity, c.session_count
                FROM campaign_sessions cs
                LEFT JOIN campaigns c ON c.campaign_id = cs.campaign_id
                WHERE cs.session_id = ?
                ORDER BY cs.created_at DESC
                LIMIT ?
                """,
                (session_id, limit),
            ).fetchall()
        output = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.get("payload_json") or "{}")
            item["match_reasons"] = json.loads(item.get("match_reasons_json") or "[]")
            item["campaign_payload"] = json.loads(item.get("campaign_payload_json") or "{}")
            output.append(item)
        return output

    def enqueue_prediction_outbox(self, payload: Dict[str, Any]) -> str:
        event_identity = _required_identity(payload.get("event_id"), "event_id")
        session_identity = _required_identity(
            payload.get("session_id"), "session_id"
        )
        outbox_id = stable_id(
            "prediction_outbox",
            {
                "event_id": event_identity,
                "session_id": session_identity,
                "prediction_mode": payload.get("prediction_mode") or "",
            },
        )
        now = utc_now()
        with self.connection() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO prediction_outbox
                (outbox_id, event_id, session_id, status, payload_json,
                 attempts, created_at, updated_at)
                VALUES (?, ?, ?, 'queued', ?, 0, ?, ?)
                """,
                (
                    outbox_id,
                    event_identity,
                    session_identity,
                    stable_json(payload),
                    now,
                    now,
                ),
            )
        return outbox_id

    def record_data_lifecycle_policy(
        self,
        *,
        policy_id: str,
        policy_version: str,
        policy_sha256: str,
        effective_path: str,
        activated_at: Any = None,
    ) -> bool:
        digest = str(policy_sha256 or "").strip().lower()
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError("policy_sha256 must be a lowercase SHA-256 digest")
        with self.connection() as conn:
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO data_lifecycle_policy_ledger
                (policy_sha256, policy_id, policy_version, effective_path, activated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    digest,
                    _required_identity(policy_id, "policy_id"),
                    _required_identity(policy_version, "policy_version"),
                    _required_identity(effective_path, "effective_path"),
                    _utc_timestamp(activated_at),
                ),
            )
            return cursor.rowcount == 1

    def claim_prediction_outbox(
        self,
        owner: str,
        limit: int,
        lease_seconds: float,
        max_attempts: int,
        *,
        now: Any = None,
    ) -> List[Dict[str, Any]]:
        claim_owner = _required_identity(owner, "owner")
        claim_limit = max(0, int(limit))
        attempt_limit = int(max_attempts)
        if attempt_limit < 1:
            raise ValueError("max_attempts must be positive")
        current_time = _utc_timestamp(now)
        expires_at = _future_timestamp(
            current_time, lease_seconds, field="lease_seconds"
        )
        claimed: List[Dict[str, Any]] = []
        with self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                UPDATE prediction_outbox
                SET status='dead_letter',
                    last_error_code='prediction_attempts_exhausted',
                    last_error_type='RetryLimitExceeded',
                    last_error_at=?,
                    claim_owner=NULL,
                    claim_token=NULL,
                    claim_expires_at=NULL,
                    updated_at=?
                WHERE status IN ('queued', 'retry', 'in_progress')
                  AND attempts >= ?
                  AND (
                    status != 'in_progress'
                    OR claim_expires_at IS NULL
                    OR claim_expires_at <= ?
                  )
                """,
                (current_time, current_time, attempt_limit, current_time),
            )
            rows = conn.execute(
                """
                SELECT outbox_id, payload_json, attempts
                FROM prediction_outbox
                WHERE status IN ('queued', 'retry', 'in_progress')
                  AND attempts < ?
                  AND (next_retry_at IS NULL OR next_retry_at <= ?)
                  AND (
                    status != 'in_progress'
                    OR claim_expires_at IS NULL
                    OR claim_expires_at <= ?
                  )
                ORDER BY created_at, outbox_id
                LIMIT ?
                """,
                (attempt_limit, current_time, current_time, claim_limit),
            ).fetchall()
            for row in rows:
                token = str(uuid.uuid4())
                cursor = conn.execute(
                    """
                    UPDATE prediction_outbox
                    SET status='in_progress',
                        attempts=attempts + 1,
                        claim_owner=?,
                        claim_token=?,
                        claim_expires_at=?,
                        updated_at=?
                    WHERE outbox_id=?
                      AND attempts < ?
                      AND status IN ('queued', 'retry', 'in_progress')
                    """,
                    (
                        claim_owner,
                        token,
                        expires_at,
                        current_time,
                        row["outbox_id"],
                        attempt_limit,
                    ),
                )
                if cursor.rowcount != 1:
                    continue
                try:
                    task = json.loads(row["payload_json"])
                except (TypeError, json.JSONDecodeError):
                    conn.execute(
                        """
                        UPDATE prediction_outbox
                        SET status='dead_letter',
                            last_error_code='prediction_task_invalid',
                            last_error_type='ValidationError',
                            last_error_at=?,
                            claim_owner=NULL,
                            claim_token=NULL,
                            claim_expires_at=NULL,
                            updated_at=?
                        WHERE outbox_id=? AND claim_token=?
                        """,
                        (current_time, current_time, row["outbox_id"], token),
                    )
                    continue
                if not isinstance(task, dict):
                    conn.execute(
                        """
                        UPDATE prediction_outbox
                        SET status='dead_letter',
                            last_error_code='prediction_task_invalid',
                            last_error_type='ValidationError',
                            last_error_at=?,
                            claim_owner=NULL,
                            claim_token=NULL,
                            claim_expires_at=NULL,
                            updated_at=?
                        WHERE outbox_id=? AND claim_token=?
                        """,
                        (current_time, current_time, row["outbox_id"], token),
                    )
                    continue
                claimed.append(
                    {
                        "outbox_id": row["outbox_id"],
                        "task": task,
                        "attempts": int(row["attempts"] or 0) + 1,
                        "claim_owner": claim_owner,
                        "claim_token": token,
                        "claim_expires_at": expires_at,
                    }
                )
        return claimed

    def complete_prediction_outbox(
        self,
        outbox_id: str,
        owner: str,
        token: str,
        snapshot_id: str,
        *,
        now: Any = None,
    ) -> bool:
        current_time = _utc_timestamp(now)
        with self.connection() as conn:
            cursor = conn.execute(
                """
                UPDATE prediction_outbox
                SET status='completed',
                    snapshot_id=?,
                    next_retry_at=NULL,
                    claim_owner=NULL,
                    claim_token=NULL,
                    claim_expires_at=NULL,
                    last_error_code=NULL,
                    last_error_type=NULL,
                    last_error_at=NULL,
                    completed_at=?,
                    updated_at=?
                WHERE outbox_id=?
                  AND status='in_progress'
                  AND claim_owner=?
                  AND claim_token=?
                  AND claim_expires_at > ?
                """,
                (
                    _required_identity(snapshot_id, "snapshot_id"),
                    current_time,
                    current_time,
                    _required_identity(outbox_id, "outbox_id"),
                    _required_identity(owner, "owner"),
                    _uuid_token(token, "token"),
                    current_time,
                ),
            )
            return cursor.rowcount == 1

    def fail_prediction_outbox(
        self,
        outbox_id: str,
        owner: str,
        token: str,
        error_code: str,
        error_type: str,
        retryable: bool,
        max_attempts: int,
        retry_delay_seconds: float,
        *,
        now: Any = None,
    ) -> str:
        current_time = _utc_timestamp(now)
        retry_at = _future_timestamp(
            current_time,
            retry_delay_seconds,
            field="retry_delay_seconds",
        )
        with self.connection() as conn:
            row = conn.execute(
                """
                SELECT attempts FROM prediction_outbox
                WHERE outbox_id=?
                  AND status='in_progress'
                  AND claim_owner=?
                  AND claim_token=?
                  AND claim_expires_at > ?
                """,
                (
                    _required_identity(outbox_id, "outbox_id"),
                    _required_identity(owner, "owner"),
                    _uuid_token(token, "token"),
                    current_time,
                ),
            ).fetchone()
            if row is None:
                return "lost_claim"
            should_retry = (
                bool(retryable)
                and int(row["attempts"] or 0) < int(max_attempts)
            )
            status = "retry" if should_retry else "dead_letter"
            conn.execute(
                """
                UPDATE prediction_outbox
                SET status=?,
                    next_retry_at=?,
                    last_error_code=?,
                    last_error_type=?,
                    last_error_at=?,
                    claim_owner=NULL,
                    claim_token=NULL,
                    claim_expires_at=NULL,
                    updated_at=?
                WHERE outbox_id=?
                """,
                (
                    status,
                    retry_at if should_retry else None,
                    _required_identity(error_code, "error_code"),
                    _required_identity(error_type, "error_type"),
                    current_time,
                    current_time,
                    outbox_id,
                ),
            )
            return status

    def save_prediction_snapshot(self, snapshot: Dict[str, Any]) -> str:
        snapshot_id = snapshot.get("snapshot_id") or stable_id("predsnap", snapshot)
        now = snapshot.get("generated_at") or utc_now()
        is_v3 = snapshot.get("schema_version") == SNAPSHOT_SCHEMA_VERSION
        if is_v3:
            snapshot = require_valid_prediction_snapshot(snapshot)
            snapshot_id = snapshot["snapshot_id"]
        cutoff = snapshot.get("evidence_cutoff")
        if cutoff is not None:
            cutoff = require_valid_evidence_cutoff(cutoff)
            if str(snapshot.get("event_id") or "") != cutoff["event_id"]:
                raise StorageError(
                    "prediction event_id does not match its evidence cutoff"
                )
        with self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                """
                SELECT snapshot_id, payload_json
                FROM prediction_snapshots
                WHERE snapshot_id = ?
                LIMIT 1
                """,
                (snapshot_id,),
            ).fetchone()
            if existing is not None and is_v3:
                try:
                    existing_payload = json.loads(
                        str(existing["payload_json"] or "{}")
                    )
                except (TypeError, json.JSONDecodeError) as exc:
                    raise PredictionSnapshotIntegrityError(
                        "stored snapshot payload is malformed"
                    ) from exc
                if not isinstance(existing_payload, Mapping):
                    raise PredictionSnapshotIntegrityError(
                        "stored snapshot payload is not an object"
                    )
                require_valid_prediction_snapshot(existing_payload)
                if canonical_prediction_content(
                    existing_payload
                ) != canonical_prediction_content(snapshot):
                    raise PredictionSnapshotIntegrityError(
                        "snapshot_id already stores different canonical content"
                    )
                return snapshot_id
            if existing is not None:
                conn.execute(
                    """
                    UPDATE prediction_snapshots
                    SET session_id=?, src_ip=?, session_status=?, event_id=?,
                        features_hash=?, payload_json=?, created_at=?
                    WHERE snapshot_id=?
                    """,
                    (
                        snapshot.get("session_id", "unknown"),
                        snapshot.get("src_ip", "unknown"),
                        snapshot.get("session_status", "active"),
                        snapshot.get("event_id", ""),
                        snapshot.get("features_hash", ""),
                        stable_json(snapshot),
                        now,
                        snapshot_id,
                    ),
                )
                return snapshot_id
            conn.execute(
                """
                INSERT INTO prediction_snapshots
                (snapshot_id, session_id, src_ip, session_status, event_id, features_hash, payload_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    snapshot.get("session_id", "unknown"),
                    snapshot.get("src_ip", "unknown"),
                    snapshot.get("session_status", "active"),
                    snapshot.get("event_id", ""),
                    snapshot.get("features_hash", ""),
                    stable_json(snapshot),
                    now,
                ),
            )
        return snapshot_id

    def list_prediction_snapshots_for_session(
        self,
        session_id: str,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM prediction_snapshots
                WHERE session_id = ?
                """,
                (session_id,),
            ).fetchall()
        items: List[Dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["payload"] = _prediction_row_payload(item)
            item["integrity_errors"] = (
                validate_prediction_snapshot_integrity(item["payload"])
                if item["payload"].get("schema_version")
                == SNAPSHOT_SCHEMA_VERSION
                else []
            )
            items.append(item)
        items.sort(key=_prediction_row_order, reverse=True)
        return items[: max(0, int(limit))]

    def get_current_prediction_snapshot(
        self,
        session_id: str,
    ) -> Optional[Dict[str, Any]]:
        rows = self.list_prediction_snapshots_for_session(session_id, limit=1)
        if not rows or _prediction_row_order(rows[0])[0] < 0:
            return None
        return rows[0]

    def get_latest_prediction_snapshot(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Compatibility alias for the canonical evidence-current selector."""

        return self.get_current_prediction_snapshot(session_id)

    def get_prediction_snapshot(self, snapshot_id: str) -> Optional[Dict[str, Any]]:
        if not snapshot_id:
            return None
        with self.connection() as conn:
            row = conn.execute(
                """
                SELECT * FROM prediction_snapshots
                WHERE snapshot_id = ?
                LIMIT 1
                """,
                (snapshot_id,),
            ).fetchone()
        if not row:
            return None
        item = dict(row)
        item["payload"] = _prediction_row_payload(item)
        item["integrity_errors"] = (
            validate_prediction_snapshot_integrity(item["payload"])
            if item["payload"].get("schema_version") == SNAPSHOT_SCHEMA_VERSION
            else []
        )
        return item

    def prune_prediction_snapshots(
        self,
        retention_days: int = 90,
        keep_latest_per_session: bool = True,
        now: Optional[str] = None,
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        retention_days = max(int(retention_days), 0)
        reference = _parse_dt(now) or datetime.now(timezone.utc)
        cutoff = (reference - timedelta(days=retention_days)).isoformat()
        with self.connection() as conn:
            total_before = conn.execute("SELECT COUNT(*) FROM prediction_snapshots").fetchone()[0]
            old_count = int(
                conn.execute(
                    "SELECT COUNT(*) FROM prediction_snapshots WHERE created_at < ?",
                    (cutoff,),
                ).fetchone()[0]
            )
            feedback_protected = int(
                conn.execute(
                    """
                    SELECT COUNT(*) FROM prediction_snapshots AS ps
                    WHERE ps.created_at < ?
                      AND EXISTS (
                          SELECT 1 FROM analyst_feedback AS af
                          WHERE af.snapshot_id = ps.snapshot_id
                      )
                    """,
                    (cutoff,),
                ).fetchone()[0]
            )
            latest_protected = 0
            latest_clause = ""
            latest_params: tuple[str, ...] = ()
            if keep_latest_per_session:
                current_by_session: Dict[str, Dict[str, Any]] = {}
                for raw_row in conn.execute(
                    "SELECT * FROM prediction_snapshots"
                ).fetchall():
                    candidate = dict(raw_row)
                    candidate["payload"] = _prediction_row_payload(candidate)
                    if _prediction_row_order(candidate)[0] < 0:
                        continue
                    session_identity = str(candidate.get("session_id") or "")
                    current = current_by_session.get(session_identity)
                    if current is None or _prediction_row_order(
                        candidate
                    ) > _prediction_row_order(current):
                        current_by_session[session_identity] = candidate
                latest_params = tuple(
                    sorted(
                        str(row["snapshot_id"])
                        for row in current_by_session.values()
                    )
                )
                if latest_params:
                    placeholders = ",".join("?" for _ in latest_params)
                    latest_clause = (
                        f"AND snapshot_id NOT IN ({placeholders})"
                    )
                    latest_protected = int(
                        conn.execute(
                            f"""
                            SELECT COUNT(*) FROM prediction_snapshots
                            WHERE created_at < ?
                              AND snapshot_id IN ({placeholders})
                            """,
                            (cutoff, *latest_params),
                        ).fetchone()[0]
                    )
            eligibility_sql = f"""
                FROM prediction_snapshots
                WHERE created_at < ?
                  AND snapshot_id NOT IN (
                      SELECT COALESCE(snapshot_id, '')
                      FROM analyst_feedback
                      WHERE snapshot_id IS NOT NULL AND snapshot_id != ''
                  )
                  {latest_clause}
            """
            eligible = int(
                conn.execute(
                    f"SELECT COUNT(*) {eligibility_sql}",
                    (cutoff, *latest_params),
                ).fetchone()[0]
            )
            deleted = 0
            if not dry_run:
                cur = conn.execute(
                    f"""
                    DELETE FROM prediction_snapshots WHERE snapshot_id IN (
                        SELECT snapshot_id {eligibility_sql}
                    )
                    """,
                    (cutoff, *latest_params),
                )
                deleted = int(cur.rowcount if cur.rowcount is not None else 0)
            total_after = conn.execute("SELECT COUNT(*) FROM prediction_snapshots").fetchone()[0]
        return {
            "retention_days": retention_days,
            "cutoff": cutoff,
            "keep_latest_per_session": bool(keep_latest_per_session),
            "dry_run": bool(dry_run),
            "candidates_older_than_cutoff": old_count,
            "protected_by_feedback": feedback_protected,
            "protected_by_retention_marker": 0,
            "protected_as_latest": latest_protected,
            "eligible": eligible,
            "deleted": deleted,
            "before": int(total_before),
            "after": int(total_after),
        }

    def save_prediction_backtest_run(self, result: Dict[str, Any]) -> str:
        run_id = result.get("run_id") or stable_id("predbacktest", result)
        now = result.get("generated_at") or utc_now()
        payload = dict(result)
        payload["run_id"] = run_id
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO prediction_backtest_runs
                (run_id, payload_json, created_at)
                VALUES (?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    payload_json=excluded.payload_json,
                    created_at=excluded.created_at
                """,
                (run_id, stable_json(payload), now),
            )
        return run_id

    def save_prediction_calibration_run(self, result: Dict[str, Any]) -> str:
        run_id = result.get("run_id") or stable_id("predcalibration", result)
        now = result.get("generated_at") or utc_now()
        payload = dict(result)
        payload["run_id"] = run_id
        status = str(payload.get("status") or "unknown")
        applied = 1 if bool(payload.get("applied") or payload.get("apply")) else 0
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO prediction_calibration_runs
                (run_id, status, applied, payload_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    status=excluded.status,
                    applied=excluded.applied,
                    payload_json=excluded.payload_json,
                    created_at=excluded.created_at
                """,
                (run_id, status, applied, stable_json(payload), now),
            )
        return run_id

    def record_analyst_feedback(self, feedback: Dict[str, Any]) -> str:
        payload = normalize_feedback_payload(feedback)
        payload.setdefault("created_at", utc_now())
        payload["session_id"] = str(payload.get("session_id") or "").strip()
        payload["label"] = str(payload.get("label") or "").strip()
        payload["tactic_granularity"] = str(payload.get("tactic_granularity") or "tactic").strip() or "tactic"
        for key in ("observed_prefix", "predicted_ranking"):
            if isinstance(payload.get(key), (dict, list)):
                payload[key] = stable_json(payload[key])
        if not payload["session_id"]:
            raise ValueError("session_id is required")
        if not payload["label"]:
            raise ValueError("label is required")
        feedback_id = payload.get("feedback_id") or stable_id("feedback", payload)
        payload["feedback_id"] = feedback_id
        with self.connection() as conn:
            for column, ddl_type in (
                ("feedback_type", "TEXT NOT NULL DEFAULT 'operator_usefulness'"),
                ("operator_signal", "TEXT"),
                ("action_status", "TEXT"),
                ("label_authority", "TEXT"),
                ("evidence_confidence", "REAL"),
                ("evidence_origin", "TEXT NOT NULL DEFAULT 'live_cowrie'"),
                ("weight_eligible", "INTEGER NOT NULL DEFAULT 0"),
                ("observed_prefix", "TEXT"),
                ("predicted_top_tactic", "TEXT"),
                ("predicted_ranking", "TEXT"),
                ("final_actual_next_tactic", "TEXT"),
                ("tactic_granularity", "TEXT NOT NULL DEFAULT 'tactic'"),
                ("analyst_corrected_at", "TEXT"),
            ):
                try:
                    conn.execute(f"ALTER TABLE analyst_feedback ADD COLUMN {column} {ddl_type}")
                except sqlite3.OperationalError as exc:
                    if "duplicate column name" not in str(exc).lower():
                        raise
            conn.execute(
                """
                INSERT INTO analyst_feedback
                (feedback_id, session_id, snapshot_id, label, feedback_type,
                 operator_signal, action_status, label_authority, evidence_confidence,
                 evidence_origin, weight_eligible, correct_next_tactic,
                 observed_prefix, predicted_top_tactic, predicted_ranking,
                 final_actual_next_tactic, tactic_granularity, analyst_corrected_at,
                 notes, payload_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(feedback_id) DO UPDATE SET
                    session_id=excluded.session_id,
                    snapshot_id=excluded.snapshot_id,
                    label=excluded.label,
                    feedback_type=excluded.feedback_type,
                    operator_signal=excluded.operator_signal,
                    action_status=excluded.action_status,
                    label_authority=excluded.label_authority,
                    evidence_confidence=excluded.evidence_confidence,
                    evidence_origin=excluded.evidence_origin,
                    weight_eligible=excluded.weight_eligible,
                    correct_next_tactic=excluded.correct_next_tactic,
                    observed_prefix=excluded.observed_prefix,
                    predicted_top_tactic=excluded.predicted_top_tactic,
                    predicted_ranking=excluded.predicted_ranking,
                    final_actual_next_tactic=excluded.final_actual_next_tactic,
                    tactic_granularity=excluded.tactic_granularity,
                    analyst_corrected_at=excluded.analyst_corrected_at,
                    notes=excluded.notes,
                    payload_json=excluded.payload_json,
                    created_at=excluded.created_at
                """,
                (
                    feedback_id,
                    payload["session_id"],
                    payload.get("snapshot_id") or None,
                    payload["label"],
                    payload.get("feedback_type") or "operator_usefulness",
                    payload.get("operator_signal") or None,
                    payload.get("action_status") or None,
                    payload.get("label_authority") or None,
                    payload.get("evidence_confidence") if payload.get("evidence_confidence") not in ("", None) else None,
                    payload.get("evidence_origin") or "live_cowrie",
                    1 if bool(payload.get("weight_eligible")) else 0,
                    payload.get("correct_next_tactic") or None,
                    payload.get("observed_prefix") or None,
                    payload.get("predicted_top_tactic") or None,
                    payload.get("predicted_ranking") or None,
                    payload.get("final_actual_next_tactic") or None,
                    payload.get("tactic_granularity") or "tactic",
                    payload.get("analyst_corrected_at") or None,
                    payload.get("notes") or None,
                    stable_json(payload),
                    payload["created_at"],
                ),
            )
        return feedback_id

    def record_classification_review_label(self, label: Dict[str, Any]) -> str:
        payload = dict(label)
        payload.setdefault("created_at", utc_now())
        payload["session_id"] = str(payload.get("session_id") or "").strip()
        payload["command"] = str(payload.get("command") or "").strip()
        payload["review_id"] = str(payload.get("review_id") or stable_id("classreview", payload))
        payload["label_id"] = str(payload.get("label_id") or stable_id("classlabel", payload))
        if not payload["session_id"]:
            raise ValueError("session_id is required")
        if not payload["command"]:
            raise ValueError("command is required")
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO classification_review_labels
                (label_id, review_id, session_id, command_index, command,
                 predicted_ttp, predicted_tactic, predicted_source, predicted_confidence,
                 reviewed_ttp, reviewed_tactic, reviewer, notes, payload_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(label_id) DO UPDATE SET
                    review_id=excluded.review_id,
                    session_id=excluded.session_id,
                    command_index=excluded.command_index,
                    command=excluded.command,
                    predicted_ttp=excluded.predicted_ttp,
                    predicted_tactic=excluded.predicted_tactic,
                    predicted_source=excluded.predicted_source,
                    predicted_confidence=excluded.predicted_confidence,
                    reviewed_ttp=excluded.reviewed_ttp,
                    reviewed_tactic=excluded.reviewed_tactic,
                    reviewer=excluded.reviewer,
                    notes=excluded.notes,
                    payload_json=excluded.payload_json,
                    created_at=excluded.created_at
                """,
                (
                    payload["label_id"],
                    payload["review_id"],
                    payload["session_id"],
                    int(payload.get("command_index") or 0),
                    payload["command"],
                    payload.get("predicted_ttp") or None,
                    payload.get("predicted_tactic") or None,
                    payload.get("predicted_source") or None,
                    payload.get("predicted_confidence") if payload.get("predicted_confidence") not in ("", None) else None,
                    payload.get("reviewed_ttp") or payload.get("correct_ttp") or None,
                    payload.get("reviewed_tactic") or payload.get("correct_tactic") or None,
                    payload.get("reviewer") or None,
                    payload.get("notes") or None,
                    stable_json(payload),
                    payload["created_at"],
                ),
            )
        return payload["label_id"]

    def list_classification_review_labels(self, limit: int = 1000) -> List[Dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM classification_review_labels
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        output = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.get("payload_json") or "{}")
            output.append(item)
        return output

    def list_rows(self, table: str, limit: int = 100) -> List[Dict[str, Any]]:
        allowed = {"events", "sessions", "alerts", "analysis_jobs", "reports", "ai_advisory_outbox", "ai_advisories", "feed_status", "webhook_deliveries", "enrichment_records", "enrichment_jobs", "prediction_snapshots", "prediction_outbox", "prediction_backtest_runs", "prediction_calibration_runs", "analyst_feedback", "classification_review_labels", "observables", "observable_sightings", "threat_hunt_jobs", "session_links", "campaigns", "campaign_sessions"}
        if table not in allowed:
            raise ValueError(f"unsupported table: {table}")
        with self.connection() as conn:
            rows = conn.execute(f"SELECT * FROM {table} ORDER BY rowid DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def list_rows_for_session(
        self,
        table: str,
        session_id: str,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        if table not in SESSION_SCOPED_TABLE_ORDER:
            raise ValueError(f"unsupported session-scoped table: {table}")
        with self.connection() as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM {table}
                WHERE session_id = ?
                ORDER BY rowid DESC
                LIMIT ?
                """,
                (session_id, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_session_rows(
        self,
        limit: int = 100,
        session_source: str | None = SESSION_SOURCE_PRODUCTION_LIVE,
        external_only: bool = False,
    ) -> List[Dict[str, Any]]:
        source = normalize_session_source(session_source, "") if session_source else ""
        clauses = []
        params: List[Any] = []
        if source:
            clauses.append("session_source = ?")
            params.append(source)
        if external_only:
            clauses.append("is_external_source = 1")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with self.connection() as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM sessions
                {where}
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                params,
            ).fetchall()
        return [dict(row) for row in rows]

    def list_active_session_rows(
        self,
        limit: int = 10_000,
        session_source: str | None = SESSION_SOURCE_PRODUCTION_LIVE,
    ) -> List[Dict[str, Any]]:
        source = normalize_session_source(session_source, "") if session_source else ""
        clauses = ["ended = 0"]
        params: List[Any] = []
        if source:
            clauses.append("session_source = ?")
            params.append(source)
        params.append(max(int(limit), 0))
        with self.connection() as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM sessions
                WHERE {' AND '.join(clauses)}
                ORDER BY updated_at, session_id
                LIMIT ?
                """,
                params,
            ).fetchall()
        return [dict(row) for row in rows]

    def count_sessions(
        self,
        session_source: str | None = SESSION_SOURCE_PRODUCTION_LIVE,
        external_only: bool = False,
        ended_only: bool = False,
    ) -> int:
        source = normalize_session_source(session_source, "") if session_source else ""
        clauses = []
        params: List[Any] = []
        if source:
            clauses.append("session_source = ?")
            params.append(source)
        if external_only:
            clauses.append("is_external_source = 1")
        if ended_only:
            clauses.append("ended = 1")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.connection() as conn:
            row = conn.execute(
                f"SELECT COUNT(*) AS session_count FROM sessions {where}",
                params,
            ).fetchone()
        return int(row["session_count"] if row else 0)

    def pending_webhooks(
        self,
        limit: int = 100,
        *,
        target_url_hash: str = "",
        max_attempts: int = 5,
        now: Any = None,
    ) -> List[Dict[str, Any]]:
        if target_url_hash:
            target = _required_identity(target_url_hash, "target_url_hash")
            try:
                attempt_limit = int(max_attempts)
                row_limit = max(0, int(limit))
            except (TypeError, ValueError) as exc:
                raise ValueError("limit and max_attempts must be integers") from exc
            if attempt_limit < 1:
                raise ValueError("max_attempts must be positive")
            current_time = _utc_timestamp(now)
            with self.connection() as conn:
                rows = conn.execute(
                    """
                    SELECT alerts.alert_id, alerts.payload_json
                    FROM alerts
                    LEFT JOIN webhook_deliveries AS delivery
                      ON delivery.alert_id = alerts.alert_id
                     AND delivery.target_url_hash = ?
                    WHERE delivery.delivery_id IS NULL
                       OR (
                            delivery.status IN ('pending', 'retryable', 'failed', 'in_progress')
                            AND (
                                (
                                    delivery.attempts < ?
                                    AND (
                                        delivery.next_retry_at IS NULL
                                        OR delivery.next_retry_at <= ?
                                    )
                                )
                                OR (
                                    delivery.status = 'in_progress'
                                    AND delivery.attempts >= ?
                                )
                            )
                            AND (
                                delivery.claim_token IS NULL
                                OR delivery.claim_expires_at IS NULL
                                OR delivery.claim_expires_at <= ?
                            )
                       )
                    ORDER BY alerts.created_at, alerts.alert_id
                    LIMIT ?
                    """,
                    (
                        target,
                        attempt_limit,
                        current_time,
                        attempt_limit,
                        current_time,
                        row_limit,
                    ),
                ).fetchall()
            return [
                {
                    "alert_id": row["alert_id"],
                    "payload": json.loads(row["payload_json"]),
                }
                for row in rows
            ]
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT alert_id, payload_json FROM alerts
                WHERE delivered = 0
                ORDER BY created_at
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [{"alert_id": row["alert_id"], "payload": json.loads(row["payload_json"])} for row in rows]

    def get_webhook_delivery(self, delivery_id: str) -> Optional[Dict[str, Any]]:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM webhook_deliveries WHERE delivery_id = ?",
                (delivery_id,),
            ).fetchone()
        return dict(row) if row else None

    def claim_webhook_delivery(
        self,
        payload: Dict[str, Any],
        target_url_hash: str,
        owner: str,
        lease_seconds: float,
        max_attempts: int,
        *,
        alert_id: Optional[str] = None,
        report_id: Optional[str] = None,
        now: Any = None,
    ) -> Optional[Dict[str, Any]]:
        target = _required_identity(target_url_hash, "target_url_hash")
        claim_owner = _required_identity(owner, "owner")
        if not alert_id and not report_id:
            raise ValueError("alert_id or report_id is required")
        try:
            attempt_limit = int(max_attempts)
        except (TypeError, ValueError) as exc:
            raise ValueError("max_attempts must be an integer") from exc
        if attempt_limit < 1:
            raise ValueError("max_attempts must be positive")
        current_time = _utc_timestamp(now)
        expires_at = _future_timestamp(
            current_time, lease_seconds, field="lease_seconds"
        )
        delivery_id = stable_id(
            "delivery",
            {"alert_id": alert_id, "report_id": report_id, "target": target},
        )
        token = str(uuid.uuid4())
        payload_json = stable_json(payload)
        with self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                INSERT OR IGNORE INTO webhook_deliveries
                    (delivery_id, alert_id, report_id, target_url_hash, status,
                     attempts, payload_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, 'pending', 0, ?, ?, ?)
                """,
                (
                    delivery_id,
                    alert_id,
                    report_id,
                    target,
                    payload_json,
                    current_time,
                    current_time,
                ),
            )
            conn.execute(
                """
                UPDATE webhook_deliveries
                SET status = 'permanent_failure',
                    error_code = 'webhook_lease_attempts_exhausted',
                    last_error = 'delivery attempt budget exhausted after lease expiry',
                    completed_at = ?,
                    updated_at = ?,
                    next_retry_at = NULL,
                    claim_owner = NULL,
                    claim_token = NULL,
                    claim_expires_at = NULL
                WHERE delivery_id = ?
                  AND status = 'in_progress'
                  AND attempts >= ?
                  AND (claim_expires_at IS NULL OR claim_expires_at <= ?)
                """,
                (
                    current_time,
                    current_time,
                    delivery_id,
                    attempt_limit,
                    current_time,
                ),
            )
            cursor = conn.execute(
                """
                UPDATE webhook_deliveries
                SET status = 'in_progress',
                    attempts = attempts + 1,
                    payload_json = ?,
                    claim_owner = ?,
                    claim_token = ?,
                    claim_expires_at = ?,
                    next_retry_at = NULL,
                    error_code = NULL,
                    last_error = NULL,
                    completed_at = NULL,
                    updated_at = ?
                WHERE delivery_id = ?
                  AND status IN ('pending', 'retryable', 'failed', 'in_progress')
                  AND attempts < ?
                  AND (next_retry_at IS NULL OR next_retry_at <= ?)
                  AND (
                      claim_token IS NULL
                      OR claim_expires_at IS NULL
                      OR claim_expires_at <= ?
                  )
                """,
                (
                    payload_json,
                    claim_owner,
                    token,
                    expires_at,
                    current_time,
                    delivery_id,
                    attempt_limit,
                    current_time,
                    current_time,
                ),
            )
            if cursor.rowcount != 1:
                return None
            row = conn.execute(
                "SELECT * FROM webhook_deliveries WHERE delivery_id = ?",
                (delivery_id,),
            ).fetchone()
        if row is None:  # pragma: no cover - protected by the transaction
            return None
        result = dict(row)
        result["payload"] = json.loads(result["payload_json"])
        return result

    def complete_webhook_delivery(
        self,
        delivery_id: str,
        owner: str,
        token: str,
        status: str,
        *,
        error_code: str = "",
        error: str = "",
        response_status: Optional[int] = None,
        response_body_sha256: str = "",
        response_body_bytes: int = 0,
        response_body_truncated: bool = False,
        next_retry_at: Any = None,
        now: Any = None,
    ) -> bool:
        delivery = _required_identity(delivery_id, "delivery_id")
        claim_owner = _required_identity(owner, "owner")
        claim_token = _uuid_token(token, "token")
        (
            outcome,
            safe_error_code,
            safe_error,
            response_status,
            digest,
            body_bytes,
            response_body_truncated,
        ) = validate_webhook_completion_fields(
            status,
            error_code,
            error,
            response_status,
            response_body_sha256,
            response_body_bytes,
            response_body_truncated,
        )
        current_time = _utc_timestamp(now)
        retry_at = _optional_utc_timestamp(next_retry_at)
        if outcome == "retryable" and not retry_at:
            raise ValueError("retryable webhook completion requires next_retry_at")
        if outcome != "retryable" and retry_at:
            raise ValueError("next_retry_at is only valid for retryable completion")
        with self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                """
                UPDATE webhook_deliveries
                SET status = ?,
                    error_code = ?,
                    last_error = ?,
                    response_status = ?,
                    response_body_sha256 = ?,
                    response_body_bytes = ?,
                    response_body_truncated = ?,
                    next_retry_at = ?,
                    completed_at = CASE WHEN ? = 'retryable' THEN NULL ELSE ? END,
                    claim_owner = NULL,
                    claim_token = NULL,
                    claim_expires_at = NULL,
                    updated_at = ?
                WHERE delivery_id = ?
                  AND status = 'in_progress'
                  AND claim_owner = ?
                  AND claim_token = ?
                  AND claim_expires_at > ?
                """,
                (
                    outcome,
                    safe_error_code or None,
                    safe_error or None,
                    response_status,
                    digest or None,
                    body_bytes,
                    int(response_body_truncated),
                    retry_at,
                    outcome,
                    current_time,
                    current_time,
                    delivery,
                    claim_owner,
                    claim_token,
                    current_time,
                ),
            )
            return cursor.rowcount == 1

    def record_webhook_delivery(
        self,
        payload: Dict[str, Any],
        target_url_hash: str,
        status: str,
        error: str = "",
        alert_id: Optional[str] = None,
        report_id: Optional[str] = None,
    ) -> str:
        delivery_key = {"alert_id": alert_id, "report_id": report_id, "target": target_url_hash}
        if not alert_id and not report_id:
            delivery_key["payload"] = payload
        delivery_id = stable_id("delivery", delivery_key)
        now = utc_now()
        safe_error = redact_error_for_log(error) if error else ""
        with self.connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO webhook_deliveries
                (delivery_id, alert_id, report_id, target_url_hash, status, attempts, last_error, payload_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, COALESCE((SELECT attempts FROM webhook_deliveries WHERE delivery_id=?), 0) + 1, ?, ?, ?, ?)
                """,
                (delivery_id, alert_id, report_id, target_url_hash, status, delivery_id, safe_error, stable_json(payload), now, now),
            )
            if alert_id and status in {"succeeded", "delivered"}:
                conn.execute("UPDATE alerts SET delivered = 1 WHERE alert_id = ?", (alert_id,))
        return delivery_id


def safe_database_descriptor(
    database_url: str | DatabaseSettings,
) -> Dict[str, str]:
    """Return a log-safe database description without exposing credentials."""
    try:
        settings = (
            database_url
            if isinstance(database_url, DatabaseSettings)
            else DatabaseSettings.from_url(database_url)
        )
        return settings.safe_descriptor()
    except DatabaseConfigurationError as exc:
        raise StorageError(str(exc)) from exc


def open_storage(database: str | DatabaseSettings) -> StorageBackend:
    """Open the explicitly selected canonical adapter, failing closed."""
    try:
        settings = (
            database
            if isinstance(database, DatabaseSettings)
            else DatabaseSettings.from_url(database)
        )
    except DatabaseConfigurationError as exc:
        raise StorageError(str(exc)) from exc

    if settings.backend == MONGODB_BACKEND:
        from production.ai_advisory.security import read_mongodb_uri
        from production.storage.mongodb_backend import MongoDBStorageBackend
        from production.storage.mongodb_epoch import (
            MongoEpochStorage,
            load_storage_epoch,
            require_active_release,
            verify_runtime_deployment,
        )

        receipt = load_storage_epoch(settings.storage_epoch_receipt_path)
        require_active_release(receipt)
        mirror_identity = receipt["rollback_mirror"]
        if mirror_identity["path"] != settings.rollback_sqlite_database_path:
            raise StorageError("MongoDB rollback mirror path disagrees with epoch receipt")
        uri = read_mongodb_uri(settings.mongodb_uri_file, max_bytes=65_536)
        mongo = MongoDBStorageBackend(uri)
        mongo.initialize()
        verify_runtime_deployment(receipt, uri, mongo)
        mirror_path = Path(settings.rollback_sqlite_database_path)
        try:
            mirror_info = mirror_path.lstat()
        except OSError as exc:
            raise StorageError("MongoDB rollback mirror is not pre-created") from exc
        if mirror_path.is_symlink() or not mirror_path.is_file():
            raise StorageError("MongoDB rollback mirror must be a regular non-symlink file")
        if mirror_info.st_uid != os.geteuid() or mirror_info.st_mode & 0o077:
            raise StorageError("MongoDB rollback mirror must be service-owned mode 0600")
        mirror = SQLiteStorage(f"sqlite:///{settings.rollback_sqlite_database_path}")
        mirror.verify_existing_schema()
        return MongoEpochStorage(mongo, mirror, receipt)
    if settings.backend != SQLITE_BACKEND:
        raise StorageError(f"unsupported database backend: {settings.backend}")
    storage: StorageBackend = SQLiteStorage(settings.database_url)
    storage.initialize()
    return storage


def open_existing_storage(database: str | DatabaseSettings) -> StorageBackend:
    """Open a trusted existing database without migration or full data scans."""

    try:
        settings = (
            database
            if isinstance(database, DatabaseSettings)
            else DatabaseSettings.from_url(database)
        )
    except DatabaseConfigurationError as exc:
        raise StorageError(str(exc)) from exc

    if settings.backend == MONGODB_BACKEND:
        return open_storage(settings)
    if settings.backend != SQLITE_BACKEND:
        raise StorageError(f"unsupported database backend: {settings.backend}")
    database_path = Path(settings.database_url.replace("sqlite:///", "", 1))
    if not database_path.parent.exists():
        raise StorageError("SQLite database parent directory does not exist")
    storage: StorageBackend = SQLiteStorage(settings.database_url)
    storage.verify_existing_schema()
    return storage
