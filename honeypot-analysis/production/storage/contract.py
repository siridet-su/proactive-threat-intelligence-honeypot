from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from production.storage.session_provenance import SESSION_SOURCE_PRODUCTION_LIVE
from production.storage.canonical_event import CanonicalEventRecord
from production.utils.sensitive_data import redact_error_for_log


SQLITE_BACKEND = "sqlite"
MONGODB_BACKEND = "mongodb"
SUPPORTED_DATABASE_BACKENDS = {SQLITE_BACKEND, MONGODB_BACKEND}
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
    "ai_advisory": "ai_advisory_outbox",
    "enrichment": "enrichment_jobs",
    "threat_hunt": "threat_hunt_jobs",
}

# Preserve the existing operational-metrics API shape. The optional AI queue
# has a separate research metrics endpoint and must not alter canonical health
# responses merely because its durable extension is installed.
OPERATIONAL_QUEUE_NAMES = ("analysis", "enrichment", "threat_hunt")

OPERATIONAL_COUNT_TABLES = (
    "events",
    "sessions",
    "alerts",
    "analysis_jobs",
    "reports",
    "enrichment_records",
    "enrichment_jobs",
    "prediction_snapshots",
    "prediction_outbox",
    "threat_hunt_jobs",
    "webhook_deliveries",
)
JOB_FAILURE_CODES = frozenset(
    {
        "analysis_failed",
        "ai_advisory_failed",
        "ai_job_invalid",
        "ai_output_invalid",
        "ai_provider_unavailable",
        "enrichment_failed",
        "job_attempts_exhausted",
        "job_dependency_unavailable",
        "job_invalid",
        "job_processing_failed",
        "job_timeout",
        "threat_hunt_failed",
    }
)

WEBHOOK_COMPLETION_STATUSES = frozenset(
    {"delivered", "retryable", "permanent_failure"}
)
WEBHOOK_FAILURE_CODES = frozenset(
    {
        "webhook_attempts_exhausted",
        "webhook_dns_no_addresses",
        "webhook_dns_unavailable",
        "webhook_endpoint_internal",
        "webhook_endpoint_unsafe",
        "webhook_lease_attempts_exhausted",
        "webhook_request_invalid",
        "webhook_transport_error",
        *(f"webhook_http_{status}" for status in range(100, 600)),
    }
)
MAX_WEBHOOK_RESPONSE_BYTES = 65_536

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
        "prediction_outbox_enqueued",
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


def validate_webhook_completion_fields(
    status: str,
    error_code: str,
    error: str,
    response_status: Optional[int],
    response_body_sha256: str,
    response_body_bytes: int,
    response_body_truncated: bool,
) -> tuple[str, str, str, Optional[int], str, int, bool]:
    """Validate the bounded, secret-free webhook completion schema."""

    outcome = str(status or "").strip().lower()
    if outcome not in WEBHOOK_COMPLETION_STATUSES:
        raise ValueError("unsupported webhook completion status")
    code = str(error_code or "").strip()
    if outcome == "delivered":
        if code or error:
            raise ValueError("delivered webhook completion cannot contain an error")
        safe_error = ""
    else:
        if code not in WEBHOOK_FAILURE_CODES:
            raise ValueError("error_code is not a registered webhook failure code")
        raw_error = str(error or "").strip()
        expected_http_error = (
            f"HTTP {response_status}" if response_status is not None else ""
        )
        safe_error = (
            raw_error
            if raw_error == expected_http_error and code == f"webhook_http_{response_status}"
            else redact_error_for_log(raw_error)
        )
    normalized_status: Optional[int] = None
    if response_status is not None:
        normalized_status = int(response_status)
        if not 100 <= normalized_status <= 599:
            raise ValueError("response_status must be an HTTP status")
        if outcome == "delivered" and not 200 <= normalized_status < 300:
            raise ValueError("delivered webhook response_status must be successful")
    body_bytes = int(response_body_bytes)
    if not 0 <= body_bytes <= MAX_WEBHOOK_RESPONSE_BYTES:
        raise ValueError("response_body_bytes exceeds the bounded capture limit")
    digest = str(response_body_sha256 or "")
    if digest and (
        len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise ValueError("response_body_sha256 must be a lowercase SHA-256 digest")
    if body_bytes and not digest:
        raise ValueError("captured response bytes require a SHA-256 digest")
    if not isinstance(response_body_truncated, bool):
        raise ValueError("response_body_truncated must be boolean")
    return (
        outcome,
        code,
        safe_error,
        normalized_status,
        digest,
        body_bytes,
        response_body_truncated,
    )


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
    return str(value or "").strip().lower()


def _backend_from_url(database_url: str) -> str:
    value = str(database_url or "").strip()
    if value.startswith("sqlite:///"):
        return SQLITE_BACKEND
    if value.startswith(("mongodb://", "mongodb+srv://")):
        return MONGODB_BACKEND
    if "://" not in value:
        raise DatabaseConfigurationError(
            "database_url must use sqlite:///DATABASE_PATH; plain paths are not accepted"
        )
    raise DatabaseConfigurationError(
        "unsupported database URL; expected sqlite or MongoDB"
    )


def _sqlite_path_from_url(database_url: str) -> str:
    if not database_url.startswith("sqlite:///"):
        raise DatabaseConfigurationError("SQLite database_url must use sqlite:///DATABASE_PATH")
    path = database_url.replace("sqlite:///", "", 1)
    if not path:
        raise DatabaseConfigurationError("SQLite database path must not be empty")
    return path


@dataclass(frozen=True)
class DatabaseSettings:
    """Validated canonical storage settings with secret-safe descriptors."""

    backend: str
    database_url: str
    sqlite_database_path: str = ""
    mongodb_uri_file: str = ""
    rollback_sqlite_database_path: str = ""
    storage_epoch_receipt_path: str = ""

    @classmethod
    def from_values(
        cls,
        *,
        database_backend: str = "",
        database_url: str = "",
        sqlite_database_path: str = "",
        mongodb_uri_file: str = "",
        rollback_sqlite_database_path: str = "",
        storage_epoch_receipt_path: str = "",
    ) -> "DatabaseSettings":
        backend = _normalize_backend(database_backend)
        legacy_url = str(database_url or "").strip()
        sqlite_path = str(sqlite_database_path or "").strip()

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

        legacy_path = (
            _sqlite_path_from_url(legacy_url)
            if legacy_url and url_backend == SQLITE_BACKEND
            else ""
        )
        if legacy_path and sqlite_path and legacy_path != sqlite_path:
            raise DatabaseConfigurationError(
                "SQLITE_DATABASE_PATH conflicts with legacy sqlite database_url"
            )
        if selected_backend == MONGODB_BACKEND:
            uri_file = str(mongodb_uri_file or "").strip()
            mirror_path = str(rollback_sqlite_database_path or "").strip()
            receipt_path = str(storage_epoch_receipt_path or "").strip()
            if legacy_url:
                raise DatabaseConfigurationError(
                    "MongoDB credentials must use MONGODB_URI_FILE, not database_url"
                )
            if not uri_file or not mirror_path or not receipt_path:
                raise DatabaseConfigurationError(
                    "MongoDB requires URI, rollback mirror, and storage epoch receipt files"
                )
            if not all(Path(value).is_absolute() for value in (uri_file, mirror_path, receipt_path)):
                raise DatabaseConfigurationError("MongoDB runtime paths must be absolute")
            return cls(
                backend=MONGODB_BACKEND,
                database_url="",
                mongodb_uri_file=uri_file,
                rollback_sqlite_database_path=mirror_path,
                storage_epoch_receipt_path=receipt_path,
            )
        selected_path = sqlite_path or legacy_path or DEFAULT_SQLITE_DATABASE_PATH
        return cls(
            backend=SQLITE_BACKEND,
            database_url=f"sqlite:///{selected_path}",
            sqlite_database_path=selected_path,
        )

    @classmethod
    def from_url(cls, database_url: str) -> "DatabaseSettings":
        return cls.from_values(database_url=database_url)

    def safe_descriptor(self) -> Dict[str, str]:
        """Return the non-secret SQLite connection identity."""
        if self.backend == MONGODB_BACKEND:
            return {
                "backend": MONGODB_BACKEND,
                "database": "honeypot_canonical_v1",
                "rollback_database_path": self.rollback_sqlite_database_path,
                "storage_epoch_receipt_path": self.storage_epoch_receipt_path,
            }
        return {"backend": SQLITE_BACKEND, "database_path": self.sqlite_database_path}


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
    if settings.backend == MONGODB_BACKEND:
        return "mongodb://honeypot_canonical_v1"
    return f"sqlite:///{descriptor['database_path']}"


@runtime_checkable
class StorageBackend(Protocol):
    """Logical persistence contract shared by runtime services and tools.

    Implementations preserve deterministic application identities and
    canonical JSON bytes. Inserts are idempotent only for identical canonical
    content; identity conflicts fail closed. Claims atomically increment the
    attempt count and issue fenced, expiring tokens. Multi-record publication
    is transactional and returned collections use explicit application order,
    never SQLite rowid, MongoDB ObjectId, or backend-natural order.
    """

    def initialize(self) -> None: ...

    def health_check(self) -> Dict[str, Any]: ...

    def operational_metrics(self, *, now: Any = None) -> Dict[str, Any]: ...

    def store_event(
        self,
        sensor_id: str,
        event: Dict[str, Any],
    ) -> tuple[str, bool]: ...

    def store_canonical_event(
        self,
        record: CanonicalEventRecord,
    ) -> tuple[str, bool]: ...

    def verify_existing_schema(self) -> None: ...

    def fetch_unprocessed_events(self, limit: int) -> List[Dict[str, Any]]: ...

    def get_event(self, event_id: str) -> Optional[Dict[str, Any]]: ...

    def load_session_event_snapshot(
        self,
        session_id: str,
        through_event_id: str,
        max_events: int,
    ) -> Dict[str, Any]: ...

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
        enqueue_ai_advisory: bool = False,
        ai_advisory_max_queue_records: int = 10_000,
        ai_advisory_reconciliation_cutoff: Optional[Dict[str, str]] = None,
        *,
        now: Any = None,
    ) -> Optional[str]: ...

    def claim_ai_advisory_jobs(
        self,
        owner: str,
        limit: int,
        lease_seconds: float,
        max_attempts: int,
        *,
        now: Any = None,
    ) -> List[Dict[str, Any]]: ...

    def initialize_ai_advisory_extension(self) -> None: ...

    def enqueue_ai_advisory_job(
        self,
        report_id: str,
        session_id: str,
        assessment_id: str,
        *,
        reconciliation_cutoff: Dict[str, str],
        max_queue_records: int = 10_000,
        now: Any = None,
    ) -> Optional[str]: ...

    def reconcile_ai_advisory_outbox(
        self,
        *,
        reconciliation_cutoff: Dict[str, str],
        limit: int = 100,
        max_queue_records: int = 10_000,
    ) -> Dict[str, int]: ...

    def get_report_by_id(self, report_id: str) -> Optional[Dict[str, Any]]: ...

    def get_current_report_for_session(
        self, session_id: str
    ) -> Optional[Dict[str, Any]]: ...

    def get_ai_advisory_by_cache_key(
        self, cache_key: str
    ) -> Optional[Dict[str, Any]]: ...

    def get_ai_advisory_for_session(
        self, session_id: str
    ) -> Optional[Dict[str, Any]]: ...

    def get_ai_advisory_for_report(
        self, report_id: str, assessment_id: str
    ) -> Optional[Dict[str, Any]]: ...

    def get_ai_advisory_outbox_for_report(
        self, report_id: str, assessment_id: str
    ) -> Optional[Dict[str, Any]]: ...

    def prune_ai_advisories(
        self,
        retention_days: int = 30,
        keep_latest_per_session: bool = False,
        *,
        max_records: int = 50_000,
        max_storage_bytes: int = 256 * 1024 * 1024,
        now: Any = None,
    ) -> Dict[str, Any]: ...

    def complete_ai_advisory_job(
        self,
        job_id: str,
        owner: str,
        token: str,
        advisory_record: Dict[str, Any],
        completion_code: str = "accepted",
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

    def list_enrichment_records_for_observables(
        self,
        observables: Any,
        allow_stale: bool = True,
    ) -> List[Dict[str, Any]]: ...

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

    def enqueue_prediction_outbox(self, payload: Dict[str, Any]) -> str: ...

    def claim_prediction_outbox(
        self,
        owner: str,
        limit: int,
        lease_seconds: float,
        max_attempts: int,
        *,
        now: Any = None,
    ) -> List[Dict[str, Any]]: ...

    def complete_prediction_outbox(
        self,
        outbox_id: str,
        owner: str,
        token: str,
        snapshot_id: str,
        *,
        now: Any = None,
    ) -> bool: ...

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
    ) -> str: ...

    def record_data_lifecycle_policy(
        self,
        *,
        policy_id: str,
        policy_version: str,
        policy_sha256: str,
        effective_path: str,
        activated_at: Any = None,
    ) -> bool: ...

    def get_latest_prediction_snapshot(
        self,
        session_id: str,
    ) -> Optional[Dict[str, Any]]: ...

    def get_current_prediction_snapshot(
        self,
        session_id: str,
    ) -> Optional[Dict[str, Any]]: ...

    def list_prediction_snapshots_for_session(
        self,
        session_id: str,
        limit: int = 100,
    ) -> List[Dict[str, Any]]: ...

    def list_dashboard_session_detail_prediction_snapshots(
        self,
        session_id: str,
        limit: int = 50,
    ) -> List[Dict[str, Any]]: ...

    def get_prediction_snapshot(
        self,
        snapshot_id: str,
    ) -> Optional[Dict[str, Any]]: ...

    def prune_prediction_snapshots(
        self,
        retention_days: int = 90,
        keep_latest_per_session: bool = True,
        now: Optional[str] = None,
        dry_run: bool = True,
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

    def pending_webhooks(
        self,
        limit: int = 100,
        *,
        target_url_hash: str = "",
        max_attempts: int = 5,
        now: Any = None,
    ) -> List[Dict[str, Any]]: ...

    def get_webhook_delivery(
        self,
        delivery_id: str,
    ) -> Optional[Dict[str, Any]]: ...

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
    ) -> Optional[Dict[str, Any]]: ...

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
    ) -> bool: ...

    def record_webhook_delivery(
        self,
        payload: Dict[str, Any],
        target_url_hash: str,
        status: str,
        error: str = "",
        alert_id: Optional[str] = None,
        report_id: Optional[str] = None,
    ) -> str: ...
