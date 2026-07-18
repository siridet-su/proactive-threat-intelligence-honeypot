from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from production.storage.session_provenance import SESSION_SOURCE_PRODUCTION_LIVE


SQLITE_BACKEND = "sqlite"
MONGODB_BACKEND = "mongodb"
POSTGRESQL_BACKEND = "postgresql"
SUPPORTED_DATABASE_BACKENDS = {
    SQLITE_BACKEND,
    MONGODB_BACKEND,
    POSTGRESQL_BACKEND,
}
MONGODB_SCHEMES = {"mongodb", "mongodb+srv"}
POSTGRESQL_SCHEMES = {"postgres", "postgresql"}
DEFAULT_SQLITE_DATABASE_PATH = "production_state.db"

EVENT_FAILURE_CODES = frozenset(
    {
        "database_unavailable",
        "event_lease_attempts_exhausted",
        "event_processing_dependency",
        "event_processing_failed",
        "event_processing_invalid",
        "event_processing_timeout",
        "invalid_event",
        "session_processing_failed",
        "stale_leader",
        "stale_worker",
        "temporary_dependency",
        "temporary_failure",
    }
)
EVENT_FAILURE_TYPES = frozenset(
    {
        "BaseException",
        "ConnectionError",
        "DependencyUnavailable",
        "Exception",
        "FileExistsError",
        "FileNotFoundError",
        "ImportError",
        "IsADirectoryError",
        "LeadershipLost",
        "LeaseExpired",
        "NotADirectoryError",
        "OSError",
        "PermissionError",
        "RuntimeError",
        "StorageError",
        "TimeoutError",
        "TypeError",
        "ValidationError",
        "ValueError",
        "WorkerError",
    }
)

JOB_QUEUE_TABLES = {
    "analysis": "analysis_jobs",
    "enrichment": "enrichment_jobs",
    "threat_hunt": "threat_hunt_jobs",
}
JOB_FAILURE_CODES = frozenset(
    {
        "analysis_failed",
        "enrichment_failed",
        "job_attempts_exhausted",
        "job_dependency_unavailable",
        "job_invalid",
        "job_processing_failed",
        "job_timeout",
        "threat_hunt_failed",
    }
)

SESSION_ANALYSIS_FIELDS = frozenset(
    {
        "analysis_status",
        "analysis_updated_at",
        "analysis_job_id",
        "analysis_error",
        "analysis_skip_reason",
        "report_id",
    }
)

EVENT_EFFECT_SUMMARY_KEYS = frozenset(
    {
        "analysis_job_enqueued",
        "alerts_created",
        "campaign_updated",
        "enrichment_jobs_enqueued",
        "event_applied",
        "observable_sightings_recorded",
        "prediction_saved",
        "session_closed",
        "session_saved",
        "threat_hunt_jobs_enqueued",
    }
)
MAX_EVENT_EFFECT_COUNT = 1_000_000


def validate_event_failure_fields(error_code: str, error_type: str) -> tuple[str, str]:
    """Accept only developer-defined event failure identifiers.

    These fields are persisted and operator-visible. An explicit registry keeps
    attacker-controlled exception text or secret-shaped identifiers out of the
    durable queue without creating another plaintext redaction system.
    """

    code = str(error_code or "").strip()
    failure_type = str(error_type or "").strip()
    if code not in EVENT_FAILURE_CODES:
        raise ValueError("error_code is not a registered event failure code")
    if failure_type not in EVENT_FAILURE_TYPES:
        raise ValueError("error_type is not a registered event failure type")
    return code, failure_type


def validate_event_effect_summary(
    effect_summary: Any,
) -> Optional[Dict[str, bool | int]]:
    """Validate the small, non-sensitive event-processing effect schema."""

    if effect_summary is None:
        return None
    if not isinstance(effect_summary, Mapping):
        raise ValueError("effect_summary must be a mapping or null")
    normalized: Dict[str, bool | int] = {}
    for key, value in effect_summary.items():
        if key not in EVENT_EFFECT_SUMMARY_KEYS:
            raise ValueError("effect_summary contains an unsupported key")
        if type(value) is bool:
            normalized[key] = value
            continue
        if type(value) is not int or value < 0 or value > MAX_EVENT_EFFECT_COUNT:
            raise ValueError(
                "effect_summary values must be booleans or bounded non-negative integers"
            )
        normalized[key] = value
    return normalized


def validate_job_failure_fields(
    queue: str,
    error_code: str,
    error_type: str,
) -> tuple[str, str, str]:
    queue_name = str(queue or "").strip()
    if queue_name not in JOB_QUEUE_TABLES:
        raise ValueError("queue is not a registered durable job queue")
    code = str(error_code or "").strip()
    failure_type = str(error_type or "").strip()
    if code not in JOB_FAILURE_CODES:
        raise ValueError("error_code is not a registered job failure code")
    if failure_type not in EVENT_FAILURE_TYPES:
        raise ValueError("error_type is not a registered job failure type")
    return queue_name, code, failure_type


class DatabaseConfigurationError(ValueError):
    """Raised when database selection is missing, conflicting, or unsupported."""


def _normalize_backend(value: str) -> str:
    backend = str(value or "").strip().lower()
    if backend == "postgres":
        return POSTGRESQL_BACKEND
    return backend


def _backend_from_url(database_url: str) -> str:
    value = str(database_url or "").strip()
    if value.startswith("sqlite:///"):
        return SQLITE_BACKEND
    scheme = urlsplit(value).scheme.lower()
    if scheme in MONGODB_SCHEMES:
        return MONGODB_BACKEND
    if scheme in POSTGRESQL_SCHEMES:
        return POSTGRESQL_BACKEND
    if not scheme:
        raise DatabaseConfigurationError(
            "legacy database_url must be a supported URL; plain filesystem paths are not accepted"
        )
    raise DatabaseConfigurationError(
        f"unsupported database URL scheme {scheme!r}; select sqlite or mongodb explicitly"
    )


def _sqlite_path_from_url(database_url: str) -> str:
    if not database_url.startswith("sqlite:///"):
        raise DatabaseConfigurationError("SQLite database_url must use sqlite:///DATABASE_PATH")
    path = database_url.replace("sqlite:///", "", 1)
    if not path:
        raise DatabaseConfigurationError("SQLite database path must not be empty")
    return path


def _mongodb_database_from_uri(uri: str) -> str:
    parsed = urlsplit(uri)
    path = unquote(parsed.path.lstrip("/"))
    if not path:
        return ""
    if "/" in path:
        raise DatabaseConfigurationError("MongoDB URI must contain at most one database name")
    return path


def _mongodb_uri_with_database(uri: str, database: str) -> str:
    parsed = urlsplit(uri)
    if parsed.scheme.lower() not in MONGODB_SCHEMES or not parsed.netloc:
        raise DatabaseConfigurationError(
            "MONGODB_URI must use mongodb:// or mongodb+srv:// and include a host"
        )
    uri_database = _mongodb_database_from_uri(uri)
    if uri_database and uri_database != database:
        raise DatabaseConfigurationError(
            "MONGODB_URI database name conflicts with MONGODB_DATABASE"
        )
    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            f"/{quote(database, safe='')}",
            parsed.query,
            parsed.fragment,
        )
    )


def _safe_endpoint(database_url: str) -> str:
    parsed = urlsplit(database_url)
    # Removing everything through the final @ strips URI user information even
    # when a password contains a percent-encoded @. Query parameters are omitted.
    return parsed.netloc.rsplit("@", 1)[-1]


@dataclass(frozen=True)
class DatabaseSettings:
    """Validated, backend-neutral database connection settings."""

    backend: str
    database_url: str
    sqlite_database_path: str = ""
    mongodb_uri: str = ""
    mongodb_database: str = ""

    @classmethod
    def from_values(
        cls,
        *,
        database_backend: str = "",
        database_url: str = "",
        sqlite_database_path: str = "",
        mongodb_uri: str = "",
        mongodb_database: str = "",
    ) -> "DatabaseSettings":
        backend = _normalize_backend(database_backend)
        legacy_url = str(database_url or "").strip()
        sqlite_path = str(sqlite_database_path or "").strip()
        mongo_uri = str(mongodb_uri or "").strip()
        mongo_database = str(mongodb_database or "").strip()

        url_backend = _backend_from_url(legacy_url) if legacy_url else ""
        if backend and backend not in SUPPORTED_DATABASE_BACKENDS:
            raise DatabaseConfigurationError(
                f"unsupported database backend {backend!r}; expected sqlite or mongodb"
            )
        if backend and url_backend and backend != url_backend:
            raise DatabaseConfigurationError(
                "database_backend conflicts with legacy database_url backend"
            )
        selected_backend = backend or url_backend or SQLITE_BACKEND

        if selected_backend == SQLITE_BACKEND:
            legacy_path = _sqlite_path_from_url(legacy_url) if legacy_url else ""
            if legacy_path and sqlite_path and legacy_path != sqlite_path:
                raise DatabaseConfigurationError(
                    "SQLITE_DATABASE_PATH conflicts with legacy sqlite database_url"
                )
            selected_path = sqlite_path or legacy_path or DEFAULT_SQLITE_DATABASE_PATH
            return cls(
                backend=SQLITE_BACKEND,
                database_url=f"sqlite:///{selected_path}",
                sqlite_database_path=selected_path,
                mongodb_uri=mongo_uri,
                mongodb_database=mongo_database,
            )

        if selected_backend == MONGODB_BACKEND:
            legacy_mongo_uri = legacy_url if url_backend == MONGODB_BACKEND else ""
            selected_uri = mongo_uri or legacy_mongo_uri
            if not selected_uri:
                raise DatabaseConfigurationError(
                    "DATABASE_BACKEND=mongodb requires MONGODB_URI"
                )
            uri_database = _mongodb_database_from_uri(selected_uri)
            legacy_database = (
                _mongodb_database_from_uri(legacy_mongo_uri)
                if legacy_mongo_uri
                else ""
            )
            selected_database = mongo_database or uri_database or legacy_database
            if not selected_database:
                raise DatabaseConfigurationError(
                    "DATABASE_BACKEND=mongodb requires MONGODB_DATABASE"
                )
            canonical_url = _mongodb_uri_with_database(selected_uri, selected_database)
            if legacy_mongo_uri:
                canonical_legacy = _mongodb_uri_with_database(
                    legacy_mongo_uri,
                    selected_database,
                )
                if mongo_uri and canonical_legacy != canonical_url:
                    raise DatabaseConfigurationError(
                        "MONGODB_URI conflicts with legacy mongodb database_url"
                    )
            return cls(
                backend=MONGODB_BACKEND,
                database_url=canonical_url,
                mongodb_uri=selected_uri,
                mongodb_database=selected_database,
                sqlite_database_path=sqlite_path,
            )

        if not legacy_url:
            raise DatabaseConfigurationError(
                "legacy PostgreSQL compatibility requires a postgresql:// database_url"
            )
        return cls(
            backend=POSTGRESQL_BACKEND,
            database_url=legacy_url,
            sqlite_database_path=sqlite_path,
            mongodb_uri=mongo_uri,
            mongodb_database=mongo_database,
        )

    @classmethod
    def from_url(cls, database_url: str) -> "DatabaseSettings":
        return cls.from_values(database_url=database_url)

    def safe_descriptor(self) -> Dict[str, str]:
        """Return connection identity without credentials or query parameters."""
        if self.backend == SQLITE_BACKEND:
            return {
                "backend": SQLITE_BACKEND,
                "database_path": self.sqlite_database_path,
            }
        parsed = urlsplit(self.database_url)
        database = unquote(parsed.path.lstrip("/"))
        return {
            "backend": self.backend,
            "endpoint": _safe_endpoint(self.database_url),
            "database": database,
        }


def safe_database_label(database: str | DatabaseSettings) -> str:
    """Return a compact connection label that cannot contain URI credentials.

    This is intended for persisted provenance and human-readable diagnostics.
    It deliberately omits connection options and URI fragments as well as user
    information.  Callers that need structured logging should prefer
    :meth:`DatabaseSettings.safe_descriptor`.
    """

    settings = (
        database
        if isinstance(database, DatabaseSettings)
        else DatabaseSettings.from_url(database)
    )
    descriptor = settings.safe_descriptor()
    if settings.backend == SQLITE_BACKEND:
        return f"sqlite:///{descriptor['database_path']}"
    endpoint = descriptor.get("endpoint") or "private"
    database_name = descriptor.get("database") or "default"
    configured_scheme = urlsplit(settings.database_url).scheme.lower()
    label_scheme = (
        configured_scheme
        if configured_scheme in MONGODB_SCHEMES | POSTGRESQL_SCHEMES
        else settings.backend
    )
    return f"{label_scheme}://{endpoint}/{database_name}"


@runtime_checkable
class StorageBackend(Protocol):
    """Logical persistence contract shared by runtime services and tools."""

    def initialize(self) -> None: ...

    def health_check(self) -> Dict[str, Any]: ...

    def store_event(
        self,
        sensor_id: str,
        event: Dict[str, Any],
    ) -> tuple[str, bool]: ...

    def fetch_unprocessed_events(self, limit: int) -> List[Dict[str, Any]]: ...

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
    ) -> List[Dict[str, Any]]: ...

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
    ) -> bool: ...

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
    ) -> bool: ...

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
    ) -> str: ...

    def release_event_claim(
        self,
        event_id: str,
        owner: str,
        token: str,
        *,
        now: Any = None,
        leader_scope: str = "",
        leader_token: str = "",
    ) -> bool: ...

    def list_failed_events(self, limit: int = 100) -> List[Dict[str, Any]]: ...

    def acquire_worker_lease(
        self,
        scope: str,
        owner: str,
        token: str,
        lease_seconds: float,
        *,
        now: Any = None,
    ) -> bool: ...

    def renew_worker_lease(
        self,
        scope: str,
        owner: str,
        token: str,
        lease_seconds: float,
        *,
        now: Any = None,
    ) -> bool: ...

    def release_worker_lease(
        self,
        scope: str,
        owner: str,
        token: str,
        *,
        now: Any = None,
    ) -> bool: ...

    def fetch_events(
        self,
        limit: int = 1000,
        processed: Optional[bool] = None,
    ) -> List[Dict[str, Any]]: ...

    def mark_event_processed(self, event_id: str) -> None: ...

    def save_session(self, session_payload: Dict[str, Any]) -> None: ...

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]: ...

    def update_session_analysis_status(
        self,
        session_id: str,
        status: str,
        *,
        job_id: str = "",
        report_id: str = "",
        error: str = "",
        skip_reason: str = "",
    ) -> None: ...

    def store_alert(self, alert_payload: Dict[str, Any]) -> str: ...

    def enqueue_analysis_job(self, session_payload: Dict[str, Any]) -> str: ...

    def claim_jobs(
        self,
        queue: str,
        owner: str,
        limit: int,
        lease_seconds: float,
        max_attempts: int,
        *,
        now: Any = None,
    ) -> List[Dict[str, Any]]: ...

    def renew_job_claim(
        self,
        queue: str,
        job_id: str,
        owner: str,
        token: str,
        lease_seconds: float,
        *,
        now: Any = None,
    ) -> bool: ...

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
    ) -> str: ...

    def release_job_claim(
        self,
        queue: str,
        job_id: str,
        owner: str,
        token: str,
        *,
        now: Any = None,
    ) -> bool: ...

    def retry_failed_job(
        self,
        queue: str,
        job_id: str,
        *,
        now: Any = None,
    ) -> bool: ...

    def job_queue_metrics(self, queue: str, *, now: Any = None) -> Dict[str, Any]: ...

    def claim_analysis_jobs(
        self,
        owner: str,
        limit: int,
        lease_seconds: float,
        max_attempts: int,
        *,
        now: Any = None,
    ) -> List[Dict[str, Any]]: ...

    def complete_analysis_job(
        self,
        job_id: str,
        owner: str,
        token: str,
        report_payload: Dict[str, Any],
        *,
        now: Any = None,
    ) -> Optional[str]: ...

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
    ) -> str: ...

    def skip_analysis_job(
        self,
        job_id: str,
        owner: str,
        token: str,
        reason: str,
        *,
        now: Any = None,
    ) -> bool: ...

    def save_feed_status(self, status: Dict[str, Any]) -> None: ...

    def get_enrichment_record(
        self,
        observable_type: str,
        observable_value: str,
        allow_stale: bool = True,
    ) -> Optional[Dict[str, Any]]: ...

    def load_enrichment_cache(
        self,
        observable_type: str = "ip",
        allow_stale: bool = True,
    ) -> Dict[str, Dict[str, Any]]: ...

    def save_enrichment_record(
        self,
        observable_type: str,
        observable_value: str,
        payload: Dict[str, Any],
        provider_status: Dict[str, Any],
        expires_at: Optional[str] = None,
    ) -> None: ...

    def enqueue_enrichment_job(
        self,
        observable_type: str,
        observable_value: str,
        session_id: str = "",
        payload: Optional[Dict[str, Any]] = None,
        force: bool = False,
        priority: str = "normal",
        priority_reason: str = "",
    ) -> tuple[str, bool]: ...

    def claim_enrichment_jobs(
        self,
        owner: str,
        limit: int,
        lease_seconds: float,
        max_attempts: int,
        *,
        now: Any = None,
    ) -> List[Dict[str, Any]]: ...

    def reprioritize_enrichment_jobs(
        self,
        observable_value: str,
        observable_type: str = "ip",
        priority: str = "urgent",
        reason: str = "",
        session_id: str = "",
    ) -> int: ...

    def complete_enrichment_job(
        self,
        job_id: str,
        owner: str,
        token: str,
        *,
        now: Any = None,
    ) -> bool: ...

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
    ) -> str: ...

    def record_observable_sighting(self, sighting: Dict[str, Any]) -> str: ...

    def enqueue_threat_hunt_job(
        self,
        session_id: str,
        observable_type: str,
        observable_value: str,
        trigger_reason: str = "",
        payload: Optional[Dict[str, Any]] = None,
    ) -> tuple[str, bool]: ...

    def claim_threat_hunt_jobs(
        self,
        owner: str,
        limit: int,
        lease_seconds: float,
        max_attempts: int,
        *,
        now: Any = None,
    ) -> List[Dict[str, Any]]: ...

    def complete_threat_hunt_job(
        self,
        job_id: str,
        owner: str,
        token: str,
        result: Dict[str, Any],
        *,
        now: Any = None,
    ) -> bool: ...

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
    ) -> str: ...

    def find_sessions_by_observable(
        self,
        observable_type: str,
        observable_value: str,
        exclude_session_id: str = "",
        limit: int = 100,
    ) -> List[Dict[str, Any]]: ...

    def save_session_link(self, link_payload: Dict[str, Any]) -> str: ...

    def list_session_links(
        self,
        session_id: str,
        limit: int = 100,
    ) -> List[Dict[str, Any]]: ...

    def save_campaign(self, campaign: Dict[str, Any]) -> str: ...

    def get_campaign(self, campaign_id: str) -> Optional[Dict[str, Any]]: ...

    def find_matching_campaigns(
        self,
        fingerprint: Dict[str, Any],
        limit: int = 20,
    ) -> List[Dict[str, Any]]: ...

    def link_campaign_session(
        self,
        campaign_id: str,
        session_id: str,
        match_reasons: Optional[List[str]] = None,
        confidence: float = 0.0,
        payload: Optional[Dict[str, Any]] = None,
    ) -> tuple[str, bool]: ...

    def count_campaign_sessions(self, campaign_id: str) -> int: ...

    def list_campaign_sessions(
        self,
        campaign_id: str,
        limit: int = 100,
    ) -> List[Dict[str, Any]]: ...

    def list_session_campaigns(
        self,
        session_id: str,
        limit: int = 20,
    ) -> List[Dict[str, Any]]: ...

    def save_prediction_snapshot(self, snapshot: Dict[str, Any]) -> str: ...

    def get_latest_prediction_snapshot(
        self,
        session_id: str,
    ) -> Optional[Dict[str, Any]]: ...

    def get_prediction_snapshot(
        self,
        snapshot_id: str,
    ) -> Optional[Dict[str, Any]]: ...

    def prune_prediction_snapshots(
        self,
        retention_days: int = 90,
        keep_latest_per_session: bool = True,
        now: Optional[str] = None,
    ) -> Dict[str, Any]: ...

    def save_prediction_backtest_run(self, result: Dict[str, Any]) -> str: ...

    def save_prediction_calibration_run(self, result: Dict[str, Any]) -> str: ...

    def record_analyst_feedback(self, feedback: Dict[str, Any]) -> str: ...

    def record_classification_review_label(self, label: Dict[str, Any]) -> str: ...

    def list_classification_review_labels(
        self,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]: ...

    def list_rows(self, table: str, limit: int = 100) -> List[Dict[str, Any]]: ...

    def list_rows_for_session(
        self,
        table: str,
        session_id: str,
        limit: int = 100,
    ) -> List[Dict[str, Any]]: ...

    def list_session_rows(
        self,
        limit: int = 100,
        session_source: str | None = SESSION_SOURCE_PRODUCTION_LIVE,
        external_only: bool = False,
    ) -> List[Dict[str, Any]]: ...

    def list_active_session_rows(
        self,
        limit: int = 10_000,
        session_source: str | None = SESSION_SOURCE_PRODUCTION_LIVE,
    ) -> List[Dict[str, Any]]: ...

    def count_sessions(
        self,
        session_source: str | None = SESSION_SOURCE_PRODUCTION_LIVE,
        external_only: bool = False,
        ended_only: bool = False,
    ) -> int: ...

    def pending_webhooks(self, limit: int = 100) -> List[Dict[str, Any]]: ...

    def get_webhook_delivery(
        self,
        delivery_id: str,
    ) -> Optional[Dict[str, Any]]: ...

    def record_webhook_delivery(
        self,
        payload: Dict[str, Any],
        target_url_hash: str,
        status: str,
        error: str = "",
        alert_id: Optional[str] = None,
        report_id: Optional[str] = None,
    ) -> str: ...
