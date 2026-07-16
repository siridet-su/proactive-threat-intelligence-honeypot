from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from production.storage.contract import (
    DatabaseConfigurationError,
    DatabaseSettings,
    MONGODB_BACKEND,
    POSTGRESQL_BACKEND,
    SQLITE_BACKEND,
    StorageBackend,
)
from production.utils.serialization import event_id as make_event_id
from production.utils.serialization import stable_id, stable_json, utc_now
from production.utils.feedback import normalize_feedback_payload
from production.storage.session_provenance import (
    SESSION_SOURCE_PRODUCTION_LIVE,
    SESSION_SOURCE_UNKNOWN_LEGACY,
    is_external_source_ip,
    normalize_session_source,
)


class StorageError(RuntimeError):
    pass


def _decode_json(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    return json.loads(value)


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


PRIORITY_RANK = {"low": 0, "normal": 1, "high": 2, "urgent": 3}


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
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
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
                    processed INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_events_processed ON events(processed, received_at);
                CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);

                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    src_ip TEXT NOT NULL,
                    start_time TEXT,
                    ended INTEGER NOT NULL DEFAULT 0,
                    session_source TEXT NOT NULL DEFAULT 'unknown_legacy',
                    is_external_source INTEGER NOT NULL DEFAULT 0,
                    payload_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_sessions_source_updated
                    ON sessions(session_source, updated_at);
                CREATE INDEX IF NOT EXISTS idx_sessions_source_external_updated
                    ON sessions(session_source, is_external_source, updated_at);

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
            self._ensure_sqlite_session_source_column(conn)
            self._ensure_sqlite_enrichment_priority_columns(conn)

    def health_check(self) -> Dict[str, Any]:
        with self.connection() as conn:
            row = conn.execute("SELECT 1 AS ready").fetchone()
        return {
            "ok": bool(row and int(row["ready"]) == 1),
            "backend": SQLITE_BACKEND,
        }

    def _ensure_sqlite_session_source_column(self, conn: sqlite3.Connection) -> None:
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(sessions)").fetchall()}
        if "session_source" not in columns:
            conn.execute("ALTER TABLE sessions ADD COLUMN session_source TEXT NOT NULL DEFAULT 'unknown_legacy'")
        if "is_external_source" not in columns:
            conn.execute("ALTER TABLE sessions ADD COLUMN is_external_source INTEGER NOT NULL DEFAULT 0")
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

    def store_event(self, sensor_id: str, event: Dict[str, Any]) -> tuple[str, bool]:
        eid = make_event_id(sensor_id, event)
        now = utc_now()
        with self.connection() as conn:
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO events
                (event_id, sensor_id, session_id, src_ip, eventid, timestamp, payload_json, received_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    eid,
                    sensor_id,
                    str(event.get("session", "unknown")),
                    str(event.get("src_ip", "unknown")),
                    str(event.get("eventid", "")),
                    event.get("timestamp"),
                    stable_json(event),
                    now,
                ),
            )
            return eid, cur.rowcount == 1

    def fetch_unprocessed_events(self, limit: int) -> List[Dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT event_id, sensor_id, payload_json FROM events
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
            }
            for row in rows
        ]

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
                SELECT event_id, sensor_id, payload_json, processed FROM events
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
            }
            for row in rows
        ]

    def mark_event_processed(self, event_id: str) -> None:
        with self.connection() as conn:
            conn.execute("UPDATE events SET processed = 1 WHERE event_id = ?", (event_id,))

    def save_session(self, session_payload: Dict[str, Any]) -> None:
        now = utc_now()
        session_source = _payload_session_source(session_payload)
        session_payload = dict(session_payload)
        is_external_source = is_external_source_ip(session_payload.get("src_ip"))
        session_payload["session_source"] = session_source
        session_payload["is_external_source"] = is_external_source
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO sessions
                    (session_id, src_ip, start_time, ended, session_source, is_external_source, payload_json, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    src_ip=excluded.src_ip,
                    start_time=excluded.start_time,
                    ended=excluded.ended,
                    session_source=excluded.session_source,
                    is_external_source=excluded.is_external_source,
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
            row = conn.execute(
                "SELECT payload_json FROM sessions WHERE session_id = ? LIMIT 1",
                (session_id,),
            ).fetchone()
            if not row:
                return
            payload = json.loads(row["payload_json"] or "{}")
            payload["analysis_status"] = status
            payload["analysis_updated_at"] = now
            if report_id:
                payload["report_id"] = report_id
            if error:
                payload["analysis_error"] = error
            elif "analysis_error" in payload:
                payload.pop("analysis_error", None)
            if skip_reason:
                payload["analysis_skip_reason"] = skip_reason
            elif status != "skipped":
                payload.pop("analysis_skip_reason", None)
            conn.execute(
                """
                UPDATE sessions
                SET payload_json = ?, updated_at = ?
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

    def claim_analysis_jobs(self, limit: int) -> List[Dict[str, Any]]:
        now = utc_now()
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT job_id, session_id, payload_json, attempts FROM analysis_jobs
                WHERE status IN ('queued', 'retry')
                ORDER BY created_at, job_id
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            job_ids = [row["job_id"] for row in rows]
            for job_id in job_ids:
                conn.execute(
                    """
                    UPDATE analysis_jobs
                    SET status='running', attempts=attempts+1, updated_at=?
                    WHERE job_id=?
                    """,
                    (now, job_id),
                )
        return [
            {
                "job_id": row["job_id"],
                "session_id": row["session_id"],
                "session": json.loads(row["payload_json"]),
                "attempts": row["attempts"] + 1,
            }
            for row in rows
        ]

    def complete_analysis_job(self, job_id: str, report_payload: Dict[str, Any]) -> str:
        report_id = stable_id("report", {"job_id": job_id, "report": report_payload})
        now = utc_now()
        session_id = report_payload.get("session_id") or report_payload.get("data_provenance", {}).get("session", {}).get("session_id", "unknown")
        with self.connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO reports (report_id, session_id, payload_json, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (report_id, session_id, stable_json(report_payload), now),
            )
            conn.execute(
                """
                UPDATE analysis_jobs
                SET status='succeeded', report_id=?, error=NULL, updated_at=?
                WHERE job_id=?
                """,
                (report_id, now, job_id),
            )
        self.update_session_analysis_status(session_id, "succeeded", report_id=report_id)
        return report_id

    def fail_analysis_job(self, job_id: str, error: str, retry: bool = False) -> None:
        now = utc_now()
        status = "retry" if retry else "failed"
        with self.connection() as conn:
            row = conn.execute(
                "SELECT session_id FROM analysis_jobs WHERE job_id=? LIMIT 1",
                (job_id,),
            ).fetchone()
            conn.execute(
                "UPDATE analysis_jobs SET status=?, error=?, updated_at=? WHERE job_id=?",
                (status, error, now, job_id),
            )
        if row:
            self.update_session_analysis_status(row["session_id"], status, error=error)

    def skip_analysis_job(self, job_id: str, reason: str) -> None:
        now = utc_now()
        with self.connection() as conn:
            row = conn.execute(
                "SELECT session_id FROM analysis_jobs WHERE job_id=? LIMIT 1",
                (job_id,),
            ).fetchone()
            conn.execute(
                "UPDATE analysis_jobs SET status='skipped', error=?, updated_at=? WHERE job_id=?",
                (reason, now, job_id),
            )
        if row:
            self.update_session_analysis_status(row["session_id"], "skipped", skip_reason=reason)

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

    def claim_enrichment_jobs(self, limit: int) -> List[Dict[str, Any]]:
        now = utc_now()
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT job_id, observable_type, observable_value, session_id, priority, priority_reason, payload_json, attempts
                FROM enrichment_jobs
                WHERE status IN ('queued', 'retry')
                  AND (next_retry_at IS NULL OR next_retry_at <= ?)
                ORDER BY
                  CASE priority WHEN 'urgent' THEN 3 WHEN 'high' THEN 2 WHEN 'normal' THEN 1 ELSE 0 END DESC,
                  created_at,
                  job_id
                LIMIT ?
                """,
                (now, limit),
            ).fetchall()
            for row in rows:
                conn.execute(
                    """
                    UPDATE enrichment_jobs
                    SET status='running', attempts=attempts+1, updated_at=?
                    WHERE job_id=?
                    """,
                    (now, row["job_id"]),
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
                "attempts": row["attempts"] + 1,
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

    def complete_enrichment_job(self, job_id: str) -> None:
        now = utc_now()
        with self.connection() as conn:
            conn.execute(
                "UPDATE enrichment_jobs SET status='succeeded', error=NULL, next_retry_at=NULL, updated_at=? WHERE job_id=?",
                (now, job_id),
            )

    def fail_enrichment_job(self, job_id: str, error: str, retry: bool = False, retry_seconds: float = 300.0) -> None:
        now = utc_now()
        status = "retry" if retry else "failed"
        next_retry_at = _retry_at(retry_seconds) if retry else None
        with self.connection() as conn:
            conn.execute(
                """
                UPDATE enrichment_jobs
                SET status=?, error=?, next_retry_at=?, updated_at=?
                WHERE job_id=?
                """,
                (status, error, next_retry_at, now, job_id),
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

    def claim_threat_hunt_jobs(self, limit: int) -> List[Dict[str, Any]]:
        now = utc_now()
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM threat_hunt_jobs
                WHERE status IN ('queued', 'retry')
                ORDER BY created_at, job_id
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            for row in rows:
                conn.execute(
                    """
                    UPDATE threat_hunt_jobs
                    SET status='running', attempts=attempts+1, updated_at=?
                    WHERE job_id=?
                    """,
                    (now, row["job_id"]),
                )
        jobs = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.get("payload_json") or "{}")
            item["result"] = json.loads(item.get("result_json") or "{}") if item.get("result_json") else {}
            item["attempts"] = int(item.get("attempts") or 0) + 1
            jobs.append(item)
        return jobs

    def complete_threat_hunt_job(self, job_id: str, result: Dict[str, Any]) -> None:
        now = utc_now()
        with self.connection() as conn:
            conn.execute(
                """
                UPDATE threat_hunt_jobs
                SET status='succeeded', result_json=?, error=NULL, updated_at=?
                WHERE job_id=?
                """,
                (stable_json(result), now, job_id),
            )

    def fail_threat_hunt_job(self, job_id: str, error: str, retry: bool = False) -> None:
        now = utc_now()
        status = "retry" if retry else "failed"
        with self.connection() as conn:
            conn.execute(
                """
                UPDATE threat_hunt_jobs
                SET status=?, error=?, updated_at=?
                WHERE job_id=?
                """,
                (status, error, now, job_id),
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

    def save_prediction_snapshot(self, snapshot: Dict[str, Any]) -> str:
        snapshot_id = snapshot.get("snapshot_id") or stable_id("predsnap", snapshot)
        now = snapshot.get("generated_at") or utc_now()
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO prediction_snapshots
                (snapshot_id, session_id, src_ip, session_status, event_id, features_hash, payload_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(snapshot_id) DO UPDATE SET
                    session_id=excluded.session_id,
                    src_ip=excluded.src_ip,
                    session_status=excluded.session_status,
                    event_id=excluded.event_id,
                    features_hash=excluded.features_hash,
                    payload_json=excluded.payload_json,
                    created_at=excluded.created_at
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

    def get_latest_prediction_snapshot(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self.connection() as conn:
            row = conn.execute(
                """
                SELECT * FROM prediction_snapshots
                WHERE session_id = ?
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (session_id,),
            ).fetchone()
        if not row:
            return None
        item = dict(row)
        item["payload"] = json.loads(item.get("payload_json") or "{}")
        return item

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
        item["payload"] = json.loads(item.get("payload_json") or "{}")
        return item

    def prune_prediction_snapshots(
        self,
        retention_days: int = 90,
        keep_latest_per_session: bool = True,
        now: Optional[str] = None,
    ) -> Dict[str, Any]:
        retention_days = max(int(retention_days), 0)
        reference = _parse_dt(now) or datetime.now(timezone.utc)
        cutoff = (reference - timedelta(days=retention_days)).isoformat()
        with self.connection() as conn:
            total_before = conn.execute("SELECT COUNT(*) FROM prediction_snapshots").fetchone()[0]
            latest_clause = ""
            if keep_latest_per_session:
                latest_clause = """
                    AND snapshot_id NOT IN (
                        SELECT snapshot_id FROM prediction_snapshots AS latest
                        WHERE latest.created_at = (
                            SELECT MAX(inner_latest.created_at)
                            FROM prediction_snapshots AS inner_latest
                            WHERE inner_latest.session_id = latest.session_id
                        )
                    )
                """
            cur = conn.execute(
                f"""
                DELETE FROM prediction_snapshots
                WHERE created_at < ?
                  AND snapshot_id NOT IN (
                      SELECT COALESCE(snapshot_id, '')
                      FROM analyst_feedback
                      WHERE snapshot_id IS NOT NULL AND snapshot_id != ''
                  )
                  {latest_clause}
                """,
                (cutoff,),
            )
            deleted = int(cur.rowcount if cur.rowcount is not None else 0)
            total_after = conn.execute("SELECT COUNT(*) FROM prediction_snapshots").fetchone()[0]
        return {
            "retention_days": retention_days,
            "cutoff": cutoff,
            "keep_latest_per_session": bool(keep_latest_per_session),
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
        allowed = {"events", "sessions", "alerts", "analysis_jobs", "reports", "feed_status", "webhook_deliveries", "enrichment_records", "enrichment_jobs", "prediction_snapshots", "prediction_backtest_runs", "prediction_calibration_runs", "analyst_feedback", "classification_review_labels", "observables", "observable_sightings", "threat_hunt_jobs", "session_links", "campaigns", "campaign_sessions"}
        if table not in allowed:
            raise ValueError(f"unsupported table: {table}")
        with self.connection() as conn:
            rows = conn.execute(f"SELECT * FROM {table} ORDER BY rowid DESC LIMIT ?", (limit,)).fetchall()
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

    def pending_webhooks(self, limit: int = 100) -> List[Dict[str, Any]]:
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
        with self.connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO webhook_deliveries
                (delivery_id, alert_id, report_id, target_url_hash, status, attempts, last_error, payload_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, COALESCE((SELECT attempts FROM webhook_deliveries WHERE delivery_id=?), 0) + 1, ?, ?, ?, ?)
                """,
                (delivery_id, alert_id, report_id, target_url_hash, status, delivery_id, error, stable_json(payload), now, now),
            )
            if alert_id and status in {"succeeded", "delivered"}:
                conn.execute("UPDATE alerts SET delivered = 1 WHERE alert_id = ?", (alert_id,))
        return delivery_id


class PostgresStorage:
    """Cloud SQL/Postgres storage adapter.

    This adapter is optional at import time. Production images should install
    either `psycopg[binary]` or `psycopg2-binary`.
    """

    def __init__(self, database_url: str):
        self.database_url = database_url
        self._driver = None
        self._dict_row = None
        try:
            import psycopg
            from psycopg.rows import dict_row

            self._driver = psycopg
            self._dict_row = dict_row
            self._driver_name = "psycopg"
        except ImportError:
            try:
                import psycopg2
                from psycopg2.extras import RealDictCursor

                self._driver = psycopg2
                self._dict_row = RealDictCursor
                self._driver_name = "psycopg2"
            except ImportError as exc:
                raise StorageError(
                    "Postgres DATABASE_URL requires psycopg[binary] or psycopg2-binary in the runtime image."
                ) from exc

    def connect(self):
        if self._driver_name == "psycopg":
            return self._driver.connect(self.database_url, row_factory=self._dict_row)
        return self._driver.connect(self.database_url, cursor_factory=self._dict_row)

    @contextmanager
    def connection(self):
        conn = self.connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _execute(self, conn, sql: str, params: tuple = ()):
        if self._driver_name == "psycopg":
            return conn.execute(sql, params)
        cur = conn.cursor()
        cur.execute(sql, params)
        return cur

    def initialize(self) -> None:
        schema = Path(__file__).with_name("postgres_schema.sql").read_text(encoding="utf-8")
        statements = [stmt.strip() for stmt in schema.split(";") if stmt.strip()]
        with self.connection() as conn:
            for statement in statements:
                self._execute(conn, statement)

    def health_check(self) -> Dict[str, Any]:
        with self.connection() as conn:
            cur = self._execute(conn, "SELECT 1 AS ready")
            row = cur.fetchone()
        return {
            "ok": bool(row and int(row["ready"]) == 1),
            "backend": POSTGRESQL_BACKEND,
        }

    def store_event(self, sensor_id: str, event: Dict[str, Any]) -> tuple[str, bool]:
        eid = make_event_id(sensor_id, event)
        now = utc_now()
        with self.connection() as conn:
            cur = self._execute(
                conn,
                """
                INSERT INTO events
                (event_id, sensor_id, session_id, src_ip, eventid, timestamp, payload_json, received_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                ON CONFLICT(event_id) DO NOTHING
                RETURNING event_id
                """,
                (
                    eid,
                    sensor_id,
                    str(event.get("session", "unknown")),
                    str(event.get("src_ip", "unknown")),
                    str(event.get("eventid", "")),
                    event.get("timestamp"),
                    stable_json(event),
                    now,
                ),
            )
            inserted = cur.fetchone() is not None
        return eid, inserted

    def fetch_unprocessed_events(self, limit: int) -> List[Dict[str, Any]]:
        with self.connection() as conn:
            cur = self._execute(
                conn,
                """
                SELECT event_id, sensor_id, payload_json FROM events
                WHERE processed = false
                ORDER BY received_at, event_id
                LIMIT %s
                """,
                (limit,),
            )
            rows = cur.fetchall()
        return [
            {
                "event_id": row["event_id"],
                "sensor_id": row["sensor_id"],
                "event": _decode_json(row["payload_json"]),
                "payload_json": stable_json(_decode_json(row["payload_json"])),
            }
            for row in rows
        ]

    def fetch_events(self, limit: int = 1000, processed: Optional[bool] = None) -> List[Dict[str, Any]]:
        where = ""
        params: List[Any] = []
        if processed is not None:
            where = "WHERE processed = %s"
            params.append(processed)
        params.append(limit)
        with self.connection() as conn:
            cur = self._execute(
                conn,
                f"""
                SELECT event_id, sensor_id, payload_json, processed FROM events
                {where}
                ORDER BY received_at, event_id
                LIMIT %s
                """,
                tuple(params),
            )
            rows = cur.fetchall()
        return [
            {
                "event_id": row["event_id"],
                "sensor_id": row["sensor_id"],
                "event": _decode_json(row["payload_json"]),
                "payload_json": stable_json(_decode_json(row["payload_json"])),
                "processed": bool(row["processed"]),
            }
            for row in rows
        ]

    def mark_event_processed(self, event_id: str) -> None:
        with self.connection() as conn:
            self._execute(conn, "UPDATE events SET processed = true WHERE event_id = %s", (event_id,))

    def save_session(self, session_payload: Dict[str, Any]) -> None:
        now = utc_now()
        session_source = _payload_session_source(session_payload)
        session_payload = dict(session_payload)
        is_external_source = is_external_source_ip(session_payload.get("src_ip"))
        session_payload["session_source"] = session_source
        session_payload["is_external_source"] = is_external_source
        with self.connection() as conn:
            self._execute(
                conn,
                """
                INSERT INTO sessions
                    (session_id, src_ip, start_time, ended, session_source, is_external_source, payload_json, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                ON CONFLICT(session_id) DO UPDATE SET
                    src_ip=excluded.src_ip,
                    start_time=excluded.start_time,
                    ended=excluded.ended,
                    session_source=excluded.session_source,
                    is_external_source=excluded.is_external_source,
                    payload_json=excluded.payload_json,
                    updated_at=excluded.updated_at
                """,
                (
                    session_payload.get("session_id", "unknown"),
                    session_payload.get("src_ip", "unknown"),
                    session_payload.get("start_time") or None,
                    bool(session_payload.get("is_ended")),
                    session_source,
                    is_external_source,
                    stable_json(session_payload),
                    now,
                ),
            )

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        if not session_id:
            return None
        with self.connection() as conn:
            cur = self._execute(
                conn,
                """
                SELECT * FROM sessions
                WHERE session_id = %s
                LIMIT 1
                """,
                (session_id,),
            )
            row = cur.fetchone()
        if not row:
            return None
        item = dict(row)
        item["payload"] = _decode_json(item.get("payload_json") or "{}")
        return item

    def update_session_analysis_status(
        self,
        session_id: str,
        status: str,
        *,
        report_id: str = "",
        error: str = "",
        skip_reason: str = "",
    ) -> None:
        """Patch analysis status fields inside the stored session payload."""
        if not session_id:
            return
        now = utc_now()
        with self.connection() as conn:
            cur = self._execute(
                conn,
                "SELECT payload_json FROM sessions WHERE session_id = %s LIMIT 1",
                (session_id,),
            )
            row = cur.fetchone()
            if not row:
                return
            payload = _decode_json(row["payload_json"] or "{}")
            payload["analysis_status"] = status
            payload["analysis_updated_at"] = now
            if report_id:
                payload["report_id"] = report_id
            if error:
                payload["analysis_error"] = error
            else:
                payload.pop("analysis_error", None)
            if skip_reason:
                payload["analysis_skip_reason"] = skip_reason
            elif status != "skipped":
                payload.pop("analysis_skip_reason", None)
            self._execute(
                conn,
                """
                UPDATE sessions
                SET payload_json = %s::jsonb, updated_at = %s
                WHERE session_id = %s
                """,
                (stable_json(payload), now, session_id),
            )

    def store_alert(self, alert_payload: Dict[str, Any]) -> str:
        alert_id = alert_payload.get("alert_id") or stable_id("alert", alert_payload)
        now = utc_now()
        with self.connection() as conn:
            self._execute(
                conn,
                """
                INSERT INTO alerts
                (alert_id, session_id, severity, reason, payload_json, created_at)
                VALUES (%s, %s, %s, %s, %s::jsonb, %s)
                ON CONFLICT(alert_id) DO NOTHING
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
            self._execute(
                conn,
                """
                INSERT INTO analysis_jobs
                (job_id, session_id, status, payload_json, created_at, updated_at)
                VALUES (%s, %s, 'queued', %s::jsonb, %s, %s)
                ON CONFLICT(job_id) DO NOTHING
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

    def claim_analysis_jobs(self, limit: int) -> List[Dict[str, Any]]:
        now = utc_now()
        with self.connection() as conn:
            cur = self._execute(
                conn,
                """
                SELECT job_id, session_id, payload_json, attempts FROM analysis_jobs
                WHERE status IN ('queued', 'retry')
                ORDER BY created_at, job_id
                LIMIT %s
                FOR UPDATE SKIP LOCKED
                """,
                (limit,),
            )
            rows = cur.fetchall()
            for row in rows:
                self._execute(
                    conn,
                    """
                    UPDATE analysis_jobs
                    SET status='running', attempts=attempts+1, updated_at=%s
                    WHERE job_id=%s
                    """,
                    (now, row["job_id"]),
                )
        return [
            {
                "job_id": row["job_id"],
                "session_id": row["session_id"],
                "session": _decode_json(row["payload_json"]),
                "payload_json": stable_json(_decode_json(row["payload_json"])),
                "attempts": row["attempts"] + 1,
            }
            for row in rows
        ]

    def complete_analysis_job(self, job_id: str, report_payload: Dict[str, Any]) -> str:
        report_id = stable_id("report", {"job_id": job_id, "report": report_payload})
        now = utc_now()
        session_id = report_payload.get("session_id") or report_payload.get("data_provenance", {}).get("session", {}).get("session_id", "unknown")
        with self.connection() as conn:
            self._execute(
                conn,
                """
                INSERT INTO reports (report_id, session_id, payload_json, created_at)
                VALUES (%s, %s, %s::jsonb, %s)
                ON CONFLICT(report_id) DO UPDATE SET
                    session_id=excluded.session_id,
                    payload_json=excluded.payload_json,
                    created_at=excluded.created_at
                """,
                (report_id, session_id, stable_json(report_payload), now),
            )
            self._execute(
                conn,
                """
                UPDATE analysis_jobs
                SET status='succeeded', report_id=%s, error=NULL, updated_at=%s
                WHERE job_id=%s
                """,
                (report_id, now, job_id),
            )
        self.update_session_analysis_status(session_id, "succeeded", report_id=report_id)
        return report_id

    def fail_analysis_job(self, job_id: str, error: str, retry: bool = False) -> None:
        now = utc_now()
        status = "retry" if retry else "failed"
        with self.connection() as conn:
            cur = self._execute(
                conn,
                "SELECT session_id FROM analysis_jobs WHERE job_id=%s LIMIT 1",
                (job_id,),
            )
            row = cur.fetchone()
            self._execute(
                conn,
                "UPDATE analysis_jobs SET status=%s, error=%s, updated_at=%s WHERE job_id=%s",
                (status, error, now, job_id),
            )
        if row:
            self.update_session_analysis_status(row["session_id"], status, error=error)

    def skip_analysis_job(self, job_id: str, reason: str) -> None:
        now = utc_now()
        with self.connection() as conn:
            cur = self._execute(
                conn,
                "SELECT session_id FROM analysis_jobs WHERE job_id=%s LIMIT 1",
                (job_id,),
            )
            row = cur.fetchone()
            self._execute(
                conn,
                "UPDATE analysis_jobs SET status='skipped', error=%s, updated_at=%s WHERE job_id=%s",
                (reason, now, job_id),
            )
        if row:
            self.update_session_analysis_status(row["session_id"], "skipped", skip_reason=reason)

    def save_feed_status(self, status: Dict[str, Any]) -> None:
        now = utc_now()
        with self.connection() as conn:
            for name, payload in status.items():
                if name == "summary":
                    continue
                self._execute(
                    conn,
                    """
                    INSERT INTO feed_status (name, payload_json, updated_at)
                    VALUES (%s, %s::jsonb, %s)
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
            cur = self._execute(
                conn,
                """
                SELECT * FROM enrichment_records
                WHERE observable_type = %s AND observable_value = %s
                """,
                (observable_type, observable_value),
            )
            row = cur.fetchone()
        if not row:
            return None
        record = dict(row)
        record["payload"] = _decode_json(record["payload_json"])
        record["provider_status"] = _decode_json(record["provider_status_json"])
        record["is_stale"] = not _is_future(record.get("expires_at"))
        if record["is_stale"] and not allow_stale:
            return None
        return record

    def load_enrichment_cache(self, observable_type: str = "ip", allow_stale: bool = True) -> Dict[str, Dict[str, Any]]:
        with self.connection() as conn:
            cur = self._execute(
                conn,
                """
                SELECT observable_value, payload_json, expires_at
                FROM enrichment_records
                WHERE observable_type = %s
                """,
                (observable_type,),
            )
            rows = cur.fetchall()
        cache: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            is_stale = not _is_future(row["expires_at"])
            if is_stale and not allow_stale:
                continue
            payload = _decode_json(row["payload_json"])
            payload.setdefault(
                "enrichment_cache",
                {
                    "source": "storage",
                    "status": "stale" if is_stale else "fresh",
                    "expires_at": str(row["expires_at"]) if row["expires_at"] else None,
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
            self._execute(
                conn,
                """
                INSERT INTO enrichment_records
                (observable_type, observable_value, payload_json, provider_status_json,
                 first_seen, last_seen, expires_at, updated_at)
                VALUES (%s, %s, %s::jsonb, %s::jsonb, %s, %s, %s, %s)
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
            cur = self._execute(
                conn,
                """
                INSERT INTO enrichment_jobs
                (job_id, observable_type, observable_value, session_id, status,
                 priority, priority_reason, payload_json, attempts, next_retry_at, error, created_at, updated_at)
                VALUES (%s, %s, %s, %s, 'queued', %s, %s, %s::jsonb, 0, NULL, NULL, %s, %s)
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
                RETURNING job_id
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
            inserted = cur.fetchone() is not None
        return job_id, inserted

    def claim_enrichment_jobs(self, limit: int) -> List[Dict[str, Any]]:
        now = utc_now()
        with self.connection() as conn:
            cur = self._execute(
                conn,
                """
                SELECT job_id, observable_type, observable_value, session_id, priority, priority_reason, payload_json, attempts
                FROM enrichment_jobs
                WHERE status IN ('queued', 'retry')
                  AND (next_retry_at IS NULL OR next_retry_at <= %s)
                ORDER BY
                  CASE priority WHEN 'urgent' THEN 3 WHEN 'high' THEN 2 WHEN 'normal' THEN 1 ELSE 0 END DESC,
                  created_at,
                  job_id
                LIMIT %s
                FOR UPDATE SKIP LOCKED
                """,
                (now, limit),
            )
            rows = cur.fetchall()
            for row in rows:
                self._execute(
                    conn,
                    """
                    UPDATE enrichment_jobs
                    SET status='running', attempts=attempts+1, updated_at=%s
                    WHERE job_id=%s
                    """,
                    (now, row["job_id"]),
                )
        return [
            {
                "job_id": row["job_id"],
                "observable_type": row["observable_type"],
                "observable_value": row["observable_value"],
                "session_id": row["session_id"],
                "priority": row.get("priority") or "normal",
                "priority_reason": row.get("priority_reason") or "",
                "payload": _decode_json(row["payload_json"]),
                "attempts": row["attempts"] + 1,
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
            cur = self._execute(
                conn,
                """
                UPDATE enrichment_jobs
                SET
                    priority=CASE
                        WHEN
                            (CASE %s WHEN 'urgent' THEN 3 WHEN 'high' THEN 2 WHEN 'normal' THEN 1 ELSE 0 END) >
                            (CASE priority WHEN 'urgent' THEN 3 WHEN 'high' THEN 2 WHEN 'normal' THEN 1 ELSE 0 END)
                        THEN %s
                        ELSE priority
                    END,
                    priority_reason=CASE
                        WHEN
                            (CASE %s WHEN 'urgent' THEN 3 WHEN 'high' THEN 2 WHEN 'normal' THEN 1 ELSE 0 END) >
                            (CASE priority WHEN 'urgent' THEN 3 WHEN 'high' THEN 2 WHEN 'normal' THEN 1 ELSE 0 END)
                        THEN %s
                        ELSE priority_reason
                    END,
                    session_id=COALESCE(NULLIF(%s, ''), session_id),
                    next_retry_at=NULL,
                    updated_at=%s
                WHERE observable_type=%s AND observable_value=%s AND status IN ('queued', 'retry')
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
        return int(getattr(cur, "rowcount", 0) or 0)

    def complete_enrichment_job(self, job_id: str) -> None:
        now = utc_now()
        with self.connection() as conn:
            self._execute(
                conn,
                "UPDATE enrichment_jobs SET status='succeeded', error=NULL, next_retry_at=NULL, updated_at=%s WHERE job_id=%s",
                (now, job_id),
            )

    def fail_enrichment_job(self, job_id: str, error: str, retry: bool = False, retry_seconds: float = 300.0) -> None:
        now = utc_now()
        status = "retry" if retry else "failed"
        next_retry_at = _retry_at(retry_seconds) if retry else None
        with self.connection() as conn:
            self._execute(
                conn,
                """
                UPDATE enrichment_jobs
                SET status=%s, error=%s, next_retry_at=%s, updated_at=%s
                WHERE job_id=%s
                """,
                (status, error, next_retry_at, now, job_id),
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
            cur = self._execute(
                conn,
                """
                INSERT INTO observable_sightings
                (sighting_id, observable_type, observable_value, session_id, sensor_id, src_ip,
                 event_id, eventid, role, source, timestamp, payload_json, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                ON CONFLICT(sighting_id) DO NOTHING
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
                self._execute(
                    conn,
                    """
                    INSERT INTO observables
                    (observable_type, observable_value, first_seen, last_seen, sighting_count, payload_json)
                    VALUES (%s, %s, %s, %s, 1, %s::jsonb)
                    ON CONFLICT(observable_type, observable_value) DO UPDATE SET
                        last_seen=GREATEST(observables.last_seen, excluded.last_seen),
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
            cur = self._execute(
                conn,
                """
                INSERT INTO threat_hunt_jobs
                (job_id, session_id, observable_type, observable_value, trigger_reason,
                 status, result_json, payload_json, attempts, error, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, 'queued', NULL, %s::jsonb, 0, NULL, %s, %s)
                ON CONFLICT(session_id, observable_type, observable_value) DO UPDATE SET
                    status=CASE
                        WHEN threat_hunt_jobs.status IN ('queued', 'running', 'retry') THEN threat_hunt_jobs.status
                        ELSE 'queued'
                    END,
                    trigger_reason=excluded.trigger_reason,
                    payload_json=excluded.payload_json,
                    error=NULL,
                    updated_at=excluded.updated_at
                RETURNING job_id
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
            inserted = cur.fetchone() is not None
        return job_id, inserted

    def claim_threat_hunt_jobs(self, limit: int) -> List[Dict[str, Any]]:
        now = utc_now()
        with self.connection() as conn:
            cur = self._execute(
                conn,
                """
                SELECT * FROM threat_hunt_jobs
                WHERE status IN ('queued', 'retry')
                ORDER BY created_at, job_id
                LIMIT %s
                FOR UPDATE SKIP LOCKED
                """,
                (limit,),
            )
            rows = cur.fetchall()
            for row in rows:
                self._execute(
                    conn,
                    """
                    UPDATE threat_hunt_jobs
                    SET status='running', attempts=attempts+1, updated_at=%s
                    WHERE job_id=%s
                    """,
                    (now, row["job_id"]),
                )
        jobs = []
        for row in rows:
            item = dict(row)
            item["payload"] = _decode_json(item.get("payload_json") or "{}")
            item["result"] = _decode_json(item.get("result_json") or "{}") if item.get("result_json") else {}
            item["attempts"] = int(item.get("attempts") or 0) + 1
            jobs.append(item)
        return jobs

    def complete_threat_hunt_job(self, job_id: str, result: Dict[str, Any]) -> None:
        now = utc_now()
        with self.connection() as conn:
            self._execute(
                conn,
                """
                UPDATE threat_hunt_jobs
                SET status='succeeded', result_json=%s::jsonb, error=NULL, updated_at=%s
                WHERE job_id=%s
                """,
                (stable_json(result), now, job_id),
            )

    def fail_threat_hunt_job(self, job_id: str, error: str, retry: bool = False) -> None:
        now = utc_now()
        status = "retry" if retry else "failed"
        with self.connection() as conn:
            self._execute(
                conn,
                """
                UPDATE threat_hunt_jobs
                SET status=%s, error=%s, updated_at=%s
                WHERE job_id=%s
                """,
                (status, error, now, job_id),
            )

    def find_sessions_by_observable(
        self,
        observable_type: str,
        observable_value: str,
        exclude_session_id: str = "",
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        with self.connection() as conn:
            cur = self._execute(
                conn,
                """
                SELECT
                    os.session_id,
                    COUNT(*) AS sighting_count,
                    MIN(COALESCE(os.timestamp, os.created_at)) AS first_seen,
                    MAX(COALESCE(os.timestamp, os.created_at)) AS last_seen,
                    STRING_AGG(DISTINCT os.role, ',') AS roles,
                    STRING_AGG(DISTINCT os.source, ',') AS sources,
                    s.src_ip AS src_ip,
                    s.ended AS ended,
                    s.updated_at AS updated_at,
                    s.payload_json AS payload_json
                FROM observable_sightings os
                LEFT JOIN sessions s ON s.session_id = os.session_id
                WHERE os.observable_type = %s
                  AND os.observable_value = %s
                  AND os.session_id <> %s
                GROUP BY os.session_id, s.src_ip, s.ended, s.updated_at, s.payload_json
                ORDER BY last_seen DESC
                LIMIT %s
                """,
                (observable_type, observable_value, exclude_session_id, limit),
            )
            rows = cur.fetchall()
        output = []
        for row in rows:
            item = dict(row)
            item["ended"] = bool(item.get("ended"))
            item["payload"] = _decode_json(item.get("payload_json") or "{}") if item.get("payload_json") else {}
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
        link_id = link_payload.get("link_id") or stable_id(
            "sessionlink",
            {
                "sessions": sorted([a, b]),
                "link_type": link_type,
                "observable_type": observable_type,
                "observable_value": observable_value,
            },
        )
        now = link_payload.get("created_at") or utc_now()
        payload = dict(link_payload)
        payload["link_id"] = link_id
        with self.connection() as conn:
            self._execute(
                conn,
                """
                INSERT INTO session_links
                (link_id, session_id_a, session_id_b, link_type, observable_type,
                 observable_value, confidence, payload_json, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
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
            cur = self._execute(
                conn,
                """
                SELECT * FROM session_links
                WHERE session_id_a = %s OR session_id_b = %s
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (session_id, session_id, limit),
            )
            rows = cur.fetchall()
        output = []
        for row in rows:
            item = dict(row)
            item["payload"] = _decode_json(item.get("payload_json") or "{}")
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
            self._execute(
                conn,
                """
                INSERT INTO campaigns
                (campaign_id, primary_fingerprint_type, primary_fingerprint_value,
                 hassh_fingerprint, ja3_fingerprint, tactic_sequence_hash, command_pattern_hash,
                 source_ip, session_count, first_seen, last_seen, confirmed_tactics_json,
                 max_confirmed_severity, payload_json, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s::jsonb, %s, %s)
                ON CONFLICT(campaign_id) DO UPDATE SET
                    primary_fingerprint_type=excluded.primary_fingerprint_type,
                    primary_fingerprint_value=excluded.primary_fingerprint_value,
                    hassh_fingerprint=COALESCE(NULLIF(excluded.hassh_fingerprint, ''), campaigns.hassh_fingerprint),
                    ja3_fingerprint=COALESCE(NULLIF(excluded.ja3_fingerprint, ''), campaigns.ja3_fingerprint),
                    tactic_sequence_hash=COALESCE(NULLIF(excluded.tactic_sequence_hash, ''), campaigns.tactic_sequence_hash),
                    command_pattern_hash=COALESCE(NULLIF(excluded.command_pattern_hash, ''), campaigns.command_pattern_hash),
                    source_ip=COALESCE(NULLIF(excluded.source_ip, ''), campaigns.source_ip),
                    session_count=excluded.session_count,
                    first_seen=LEAST(excluded.first_seen, campaigns.first_seen),
                    last_seen=GREATEST(excluded.last_seen, campaigns.last_seen),
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
            cur = self._execute(conn, "SELECT * FROM campaigns WHERE campaign_id = %s LIMIT 1", (campaign_id,))
            row = cur.fetchone()
        if not row:
            return None
        item = dict(row)
        item["payload"] = _decode_json(item.get("payload_json") or "{}")
        item["confirmed_tactics"] = _decode_json(item.get("confirmed_tactics_json") or "[]")
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
                conditions.append(f"{column} = %s")
                params.append(text)
        if not conditions:
            return []
        params.append(limit)
        with self.connection() as conn:
            cur = self._execute(
                conn,
                f"""
                SELECT * FROM campaigns
                WHERE {" OR ".join(conditions)}
                ORDER BY updated_at DESC
                LIMIT %s
                """,
                tuple(params),
            )
            rows = cur.fetchall()
        output = []
        for row in rows:
            item = dict(row)
            item["payload"] = _decode_json(item.get("payload_json") or "{}")
            item["confirmed_tactics"] = _decode_json(item.get("confirmed_tactics_json") or "[]")
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
            cur = self._execute(
                conn,
                """
                INSERT INTO campaign_sessions
                (link_id, campaign_id, session_id, match_reasons_json, confidence, payload_json, created_at)
                VALUES (%s, %s, %s, %s::jsonb, %s, %s::jsonb, %s)
                ON CONFLICT(campaign_id, session_id) DO UPDATE SET
                    match_reasons_json=excluded.match_reasons_json,
                    confidence=excluded.confidence,
                    payload_json=excluded.payload_json
                RETURNING link_id
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
            inserted = cur.fetchone() is not None
        return link_id, inserted

    def count_campaign_sessions(self, campaign_id: str) -> int:
        with self.connection() as conn:
            cur = self._execute(
                conn,
                "SELECT COUNT(*) AS count FROM campaign_sessions WHERE campaign_id = %s",
                (campaign_id,),
            )
            row = cur.fetchone()
        return int(row["count"] if row else 0)

    def list_campaign_sessions(self, campaign_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        with self.connection() as conn:
            cur = self._execute(
                conn,
                """
                SELECT * FROM campaign_sessions
                WHERE campaign_id = %s
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (campaign_id, limit),
            )
            rows = cur.fetchall()
        output = []
        for row in rows:
            item = dict(row)
            item["payload"] = _decode_json(item.get("payload_json") or "{}")
            item["match_reasons"] = _decode_json(item.get("match_reasons_json") or "[]")
            output.append(item)
        return output

    def list_session_campaigns(self, session_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        with self.connection() as conn:
            cur = self._execute(
                conn,
                """
                SELECT cs.*, c.payload_json AS campaign_payload_json, c.max_confirmed_severity, c.session_count
                FROM campaign_sessions cs
                LEFT JOIN campaigns c ON c.campaign_id = cs.campaign_id
                WHERE cs.session_id = %s
                ORDER BY cs.created_at DESC
                LIMIT %s
                """,
                (session_id, limit),
            )
            rows = cur.fetchall()
        output = []
        for row in rows:
            item = dict(row)
            item["payload"] = _decode_json(item.get("payload_json") or "{}")
            item["match_reasons"] = _decode_json(item.get("match_reasons_json") or "[]")
            item["campaign_payload"] = _decode_json(item.get("campaign_payload_json") or "{}")
            output.append(item)
        return output

    def save_prediction_snapshot(self, snapshot: Dict[str, Any]) -> str:
        snapshot_id = snapshot.get("snapshot_id") or stable_id("predsnap", snapshot)
        now = snapshot.get("generated_at") or utc_now()
        with self.connection() as conn:
            self._execute(
                conn,
                """
                INSERT INTO prediction_snapshots
                (snapshot_id, session_id, src_ip, session_status, event_id, features_hash, payload_json, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                ON CONFLICT(snapshot_id) DO UPDATE SET
                    session_id=excluded.session_id,
                    src_ip=excluded.src_ip,
                    session_status=excluded.session_status,
                    event_id=excluded.event_id,
                    features_hash=excluded.features_hash,
                    payload_json=excluded.payload_json,
                    created_at=excluded.created_at
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

    def get_latest_prediction_snapshot(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self.connection() as conn:
            cur = self._execute(
                conn,
                """
                SELECT * FROM prediction_snapshots
                WHERE session_id = %s
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (session_id,),
            )
            row = cur.fetchone()
        if not row:
            return None
        item = dict(row)
        item["payload"] = _decode_json(item.get("payload_json") or "{}")
        return item

    def get_prediction_snapshot(self, snapshot_id: str) -> Optional[Dict[str, Any]]:
        if not snapshot_id:
            return None
        with self.connection() as conn:
            cur = self._execute(
                conn,
                """
                SELECT * FROM prediction_snapshots
                WHERE snapshot_id = %s
                LIMIT 1
                """,
                (snapshot_id,),
            )
            row = cur.fetchone()
        if not row:
            return None
        item = dict(row)
        item["payload"] = _decode_json(item.get("payload_json") or "{}")
        return item

    def prune_prediction_snapshots(
        self,
        retention_days: int = 90,
        keep_latest_per_session: bool = True,
        now: Optional[str] = None,
    ) -> Dict[str, Any]:
        retention_days = max(int(retention_days), 0)
        reference = _parse_dt(now) or datetime.now(timezone.utc)
        cutoff = (reference - timedelta(days=retention_days)).isoformat()
        with self.connection() as conn:
            total_cur = self._execute(conn, "SELECT COUNT(*) AS count FROM prediction_snapshots")
            total_before = int(total_cur.fetchone()["count"])
            latest_clause = ""
            if keep_latest_per_session:
                latest_clause = """
                    AND ps.snapshot_id NOT IN (
                        SELECT DISTINCT ON (session_id) snapshot_id
                        FROM prediction_snapshots
                        ORDER BY session_id, created_at DESC, snapshot_id DESC
                    )
                """
            cur = self._execute(
                conn,
                f"""
                DELETE FROM prediction_snapshots AS ps
                WHERE ps.created_at < %s
                  AND NOT EXISTS (
                      SELECT 1
                      FROM analyst_feedback AS af
                      WHERE af.snapshot_id = ps.snapshot_id
                  )
                  {latest_clause}
                """,
                (cutoff,),
            )
            deleted = int(getattr(cur, "rowcount", 0) or 0)
            after_cur = self._execute(conn, "SELECT COUNT(*) AS count FROM prediction_snapshots")
            total_after = int(after_cur.fetchone()["count"])
        return {
            "retention_days": retention_days,
            "cutoff": cutoff,
            "keep_latest_per_session": bool(keep_latest_per_session),
            "deleted": deleted,
            "before": total_before,
            "after": total_after,
        }

    def save_prediction_backtest_run(self, result: Dict[str, Any]) -> str:
        run_id = result.get("run_id") or stable_id("predbacktest", result)
        now = result.get("generated_at") or utc_now()
        payload = dict(result)
        payload["run_id"] = run_id
        with self.connection() as conn:
            self._execute(
                conn,
                """
                INSERT INTO prediction_backtest_runs
                (run_id, payload_json, created_at)
                VALUES (%s, %s::jsonb, %s)
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
        applied = bool(payload.get("applied") or payload.get("apply"))
        with self.connection() as conn:
            self._execute(
                conn,
                """
                INSERT INTO prediction_calibration_runs
                (run_id, status, applied, payload_json, created_at)
                VALUES (%s, %s, %s, %s::jsonb, %s)
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
                ("evidence_confidence", "DOUBLE PRECISION"),
                ("evidence_origin", "TEXT NOT NULL DEFAULT 'live_cowrie'"),
                ("weight_eligible", "BOOLEAN NOT NULL DEFAULT false"),
                ("observed_prefix", "TEXT"),
                ("predicted_top_tactic", "TEXT"),
                ("predicted_ranking", "TEXT"),
                ("final_actual_next_tactic", "TEXT"),
                ("tactic_granularity", "TEXT NOT NULL DEFAULT 'tactic'"),
                ("analyst_corrected_at", "TIMESTAMPTZ"),
            ):
                self._execute(conn, f"ALTER TABLE analyst_feedback ADD COLUMN IF NOT EXISTS {column} {ddl_type}")
            self._execute(
                conn,
                """
                INSERT INTO analyst_feedback
                (feedback_id, session_id, snapshot_id, label, feedback_type,
                 operator_signal, action_status, label_authority, evidence_confidence,
                 evidence_origin, weight_eligible, correct_next_tactic,
                 observed_prefix, predicted_top_tactic, predicted_ranking,
                 final_actual_next_tactic, tactic_granularity, analyst_corrected_at,
                 notes, payload_json, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
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
                    bool(payload.get("weight_eligible")),
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
        predicted_confidence = payload.get("predicted_confidence")
        if predicted_confidence in ("", None):
            predicted_confidence = None
        with self.connection() as conn:
            self._execute(
                conn,
                """
                INSERT INTO classification_review_labels
                (label_id, review_id, session_id, command_index, command,
                 predicted_ttp, predicted_tactic, predicted_source, predicted_confidence,
                 reviewed_ttp, reviewed_tactic, reviewer, notes, payload_json, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
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
                    predicted_confidence,
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
            cur = self._execute(
                conn,
                """
                SELECT * FROM classification_review_labels
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (limit,),
            )
            rows = cur.fetchall()
        output = []
        for row in rows:
            item = dict(row)
            item["payload"] = _decode_json(item.get("payload_json") or "{}")
            output.append(item)
        return output

    def list_rows(self, table: str, limit: int = 100) -> List[Dict[str, Any]]:
        allowed = {"events", "sessions", "alerts", "analysis_jobs", "reports", "feed_status", "webhook_deliveries", "enrichment_records", "enrichment_jobs", "prediction_snapshots", "prediction_backtest_runs", "prediction_calibration_runs", "analyst_feedback", "classification_review_labels", "observables", "observable_sightings", "threat_hunt_jobs", "session_links", "campaigns", "campaign_sessions"}
        if table not in allowed:
            raise ValueError(f"unsupported table: {table}")
        order_by = {
            "events": "received_at",
            "sessions": "updated_at",
            "alerts": "created_at",
            "analysis_jobs": "updated_at",
            "reports": "created_at",
            "feed_status": "updated_at",
            "webhook_deliveries": "updated_at",
            "enrichment_records": "updated_at",
            "enrichment_jobs": "updated_at",
            "prediction_snapshots": "created_at",
            "prediction_backtest_runs": "created_at",
            "prediction_calibration_runs": "created_at",
            "analyst_feedback": "created_at",
            "classification_review_labels": "created_at",
            "observables": "last_seen",
            "observable_sightings": "created_at",
            "threat_hunt_jobs": "updated_at",
            "session_links": "created_at",
            "campaigns": "updated_at",
            "campaign_sessions": "created_at",
        }[table]
        with self.connection() as conn:
            cur = self._execute(conn, f"SELECT * FROM {table} ORDER BY {order_by} DESC LIMIT %s", (limit,))
            return [dict(row) for row in cur.fetchall()]

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
            clauses.append("session_source = %s")
            params.append(source)
        if external_only:
            clauses.append("is_external_source = true")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with self.connection() as conn:
            cur = self._execute(
                conn,
                f"""
                SELECT * FROM sessions
                {where}
                ORDER BY updated_at DESC
                LIMIT %s
                """,
                tuple(params),
            )
            return [dict(row) for row in cur.fetchall()]

    def pending_webhooks(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self.connection() as conn:
            cur = self._execute(
                conn,
                """
                SELECT alert_id, payload_json FROM alerts
                WHERE delivered = false
                ORDER BY created_at
                LIMIT %s
                """,
                (limit,),
            )
            rows = cur.fetchall()
        return [{"alert_id": row["alert_id"], "payload": _decode_json(row["payload_json"])} for row in rows]

    def get_webhook_delivery(self, delivery_id: str) -> Optional[Dict[str, Any]]:
        with self.connection() as conn:
            cur = self._execute(
                conn,
                "SELECT * FROM webhook_deliveries WHERE delivery_id = %s",
                (delivery_id,),
            )
            row = cur.fetchone()
        return dict(row) if row else None

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
        with self.connection() as conn:
            self._execute(
                conn,
                """
                INSERT INTO webhook_deliveries
                (delivery_id, alert_id, report_id, target_url_hash, status, attempts, last_error, payload_json, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, COALESCE((SELECT attempts FROM webhook_deliveries WHERE delivery_id=%s), 0) + 1, %s, %s::jsonb, %s, %s)
                ON CONFLICT(delivery_id) DO UPDATE SET
                    status=excluded.status,
                    attempts=webhook_deliveries.attempts + 1,
                    last_error=excluded.last_error,
                    payload_json=excluded.payload_json,
                    updated_at=excluded.updated_at
                """,
                (delivery_id, alert_id, report_id, target_url_hash, status, delivery_id, error, stable_json(payload), now, now),
            )
            if alert_id and status in {"succeeded", "delivered"}:
                self._execute(conn, "UPDATE alerts SET delivered = true WHERE alert_id = %s", (alert_id,))
        return delivery_id


def safe_database_descriptor(database_url: str) -> Dict[str, str]:
    """Return a log-safe database description for a legacy runtime URL."""
    try:
        return DatabaseSettings.from_url(database_url).safe_descriptor()
    except DatabaseConfigurationError as exc:
        raise StorageError(str(exc)) from exc


def open_storage(database: str | DatabaseSettings) -> StorageBackend:
    """Open and initialize the explicitly selected storage adapter.

    String URLs remain supported for compatibility. New configuration should
    resolve to :class:`DatabaseSettings` first so backend-specific values are
    validated before an adapter is imported or a connection is attempted.
    """
    try:
        settings = (
            database
            if isinstance(database, DatabaseSettings)
            else DatabaseSettings.from_url(database)
        )
    except DatabaseConfigurationError as exc:
        raise StorageError(str(exc)) from exc

    if settings.backend == SQLITE_BACKEND:
        storage: StorageBackend = SQLiteStorage(settings.database_url)
    elif settings.backend == MONGODB_BACKEND:
        try:
            from production.storage.mongodb import MongoStorage

            storage = MongoStorage(
                settings.mongodb_uri or settings.database_url,
                settings.mongodb_database,
            )
        except ImportError as exc:
            raise StorageError(
                "MongoDB backend requested but its adapter or dependency is unavailable"
            ) from exc
    elif settings.backend == POSTGRESQL_BACKEND:
        storage = PostgresStorage(settings.database_url)
    else:  # DatabaseSettings validation makes this defensive branch unreachable.
        raise StorageError(f"unsupported database backend: {settings.backend}")

    try:
        storage.initialize()
    except ImportError as exc:
        if settings.backend == MONGODB_BACKEND:
            raise StorageError(
                "MongoDB backend requested but its adapter or dependency is unavailable"
            ) from exc
        raise
    return storage
