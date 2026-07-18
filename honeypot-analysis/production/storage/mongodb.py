"""MongoDB storage adapter for the production honeypot pipeline.

The adapter intentionally preserves the row-oriented outward contract used by
``SQLiteStorage``.  Payloads are stored as native BSON documents internally,
while ``list_rows`` and the dedicated getters expose deterministic
``*_json`` strings so existing workers can switch backends without special
case parsing.

``pymongo`` is an optional runtime import: SQLite-only installations can import
the storage package without installing it.  Constructing a real MongoDB
adapter without the driver raises an actionable ``StorageError``.  Tests and
embedding applications may inject a database-compatible object.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import math
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Dict, Iterator, List, Mapping, Optional, Sequence
from uuid import UUID, uuid4

from production.storage.backend import StorageError
from production.storage.contract import (
    validate_event_effect_summary,
    validate_event_failure_fields,
)
from production.storage.session_provenance import (
    SESSION_SOURCE_PRODUCTION_LIVE,
    is_external_source_ip,
    normalize_session_source,
)
from production.utils.feedback import normalize_feedback_payload
from production.utils.sensitive_data import redact_exception_for_log
from production.utils.serialization import event_id as make_event_id
from production.utils.serialization import stable_id, stable_json, utc_now

try:  # Optional so SQLite deployments do not require the MongoDB driver.
    from pymongo import ASCENDING, DESCENDING, MongoClient, ReturnDocument
except ImportError:  # pragma: no cover - constants are exercised via fakes.
    ASCENDING = 1
    DESCENDING = -1
    MongoClient = None  # type: ignore[assignment]

    class ReturnDocument:  # type: ignore[no-redef]
        BEFORE = False
        AFTER = True


MONGODB_DRIVER_AVAILABLE = MongoClient is not None
MONGODB_SCHEMA_VERSION = 2


def mongodb_dependency_diagnostic() -> Dict[str, Any]:
    """Return an explicit, secret-free MongoDB dependency diagnostic."""

    return {
        "driver": "pymongo",
        "available": MONGODB_DRIVER_AVAILABLE,
        "required_spec": "pymongo>=4.6,<5",
        "message": (
            "pymongo is available"
            if MONGODB_DRIVER_AVAILABLE
            else "MongoDB backend unavailable: install pymongo>=4.6,<5"
        ),
    }


def _parse_dt(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


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


def _retry_timestamp(now: str, seconds: float) -> str:
    try:
        duration = float(seconds)
    except (TypeError, ValueError) as exc:
        raise ValueError("retry_delay_seconds must be a non-negative number") from exc
    if not math.isfinite(duration) or duration < 0:
        raise ValueError("retry_delay_seconds must be a non-negative number")
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
        return str(UUID(normalized))
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"{field} must be a UUID fencing token") from exc


def _positive_attempt_limit(value: int) -> int:
    try:
        normalized = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("max_attempts must be a positive integer") from exc
    if normalized <= 0:
        raise ValueError("max_attempts must be positive")
    return normalized


PRIORITY_RANK = {"low": 0, "normal": 1, "high": 2, "urgent": 3}


def _normalize_priority(priority: str) -> str:
    value = str(priority or "normal").strip().lower()
    return value if value in PRIORITY_RANK else "normal"


def _safe_error(exc: BaseException) -> str:
    """Return a stable driver error category without request details."""

    return redact_exception_for_log(exc)


def _encode_key(value: Any) -> str:
    """Reversibly escape MongoDB-prohibited payload keys."""

    key = (
        str(value)
        .replace("%", "%25")
        .replace("\x00", "%00")
        .replace(".", "%2E")
    )
    if key.startswith("$"):
        key = "%24" + key[1:]
    return key


def _decode_key(value: Any) -> str:
    key = str(value)
    if key.startswith("%24"):
        key = "$" + key[3:]
    return key.replace("%00", "\x00").replace("%2E", ".").replace("%25", "%")


def _looks_like_object_id(value: Any) -> bool:
    cls = value.__class__
    return cls.__name__ == "ObjectId" and cls.__module__.startswith("bson")


def to_bson_safe(value: Any) -> Any:
    """Convert arbitrary JSON-like input into a MongoDB-safe value.

    Cowrie input is attacker-controlled.  In particular, mapping keys may start
    with ``$`` or contain ``.``; those keys are escaped reversibly rather than
    rejected or silently dropped.
    """

    if dataclasses.is_dataclass(value):
        return to_bson_safe(dataclasses.asdict(value))
    if isinstance(value, Mapping):
        return {_encode_key(key): to_bson_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [to_bson_safe(item) for item in value]
    if isinstance(value, datetime):
        parsed = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat()
    if isinstance(value, (UUID, Decimal)):
        return str(value)
    if isinstance(value, bytes):
        return "base64:" + base64.b64encode(value).decode("ascii")
    if _looks_like_object_id(value):
        return str(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def from_bson_safe(value: Any) -> Any:
    """Convert BSON values to deterministic API/JSON-safe Python values."""

    if isinstance(value, Mapping):
        return {_decode_key(key): from_bson_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [from_bson_safe(item) for item in value]
    if isinstance(value, datetime):
        parsed = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if _looks_like_object_id(value):
        return str(value)
    return value


JSON_FIELDS: Dict[str, Dict[str, str]] = {
    "events": {"payload_json": "payload"},
    "sessions": {"payload_json": "payload"},
    "alerts": {"payload_json": "payload"},
    "analysis_jobs": {"payload_json": "payload"},
    "reports": {"payload_json": "payload"},
    "feed_status": {"payload_json": "payload"},
    "observables": {"payload_json": "payload"},
    "observable_sightings": {"payload_json": "payload"},
    "enrichment_records": {
        "payload_json": "payload",
        "provider_status_json": "provider_status",
    },
    "enrichment_jobs": {"payload_json": "payload"},
    "webhook_deliveries": {"payload_json": "payload"},
    "prediction_snapshots": {"payload_json": "payload"},
    "prediction_backtest_runs": {"payload_json": "payload"},
    "prediction_calibration_runs": {"payload_json": "payload"},
    "analyst_feedback": {"payload_json": "payload"},
    "classification_review_labels": {"payload_json": "payload"},
    "threat_hunt_jobs": {
        "payload_json": "payload",
        "result_json": "result",
    },
    "session_links": {"payload_json": "payload"},
    "campaigns": {
        "payload_json": "payload",
        "confirmed_tactics_json": "confirmed_tactics",
    },
    "campaign_sessions": {
        "payload_json": "payload",
        "match_reasons_json": "match_reasons",
    },
}

TABLE_ID_FIELDS: Dict[str, Sequence[str]] = {
    "events": ("event_id",),
    "sessions": ("session_id",),
    "alerts": ("alert_id",),
    "analysis_jobs": ("job_id",),
    "reports": ("report_id",),
    "feed_status": ("name",),
    "observables": ("observable_type", "observable_value"),
    "observable_sightings": ("sighting_id",),
    "enrichment_records": ("observable_type", "observable_value"),
    "enrichment_jobs": ("job_id",),
    "webhook_deliveries": ("delivery_id",),
    "prediction_snapshots": ("snapshot_id",),
    "prediction_backtest_runs": ("run_id",),
    "prediction_calibration_runs": ("run_id",),
    "analyst_feedback": ("feedback_id",),
    "classification_review_labels": ("label_id",),
    "threat_hunt_jobs": ("job_id",),
    "session_links": ("link_id",),
    "campaigns": ("campaign_id",),
    "campaign_sessions": ("link_id",),
}

TABLE_ORDER_FIELDS: Dict[str, str] = {
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
}

ALLOWED_TABLES = frozenset(TABLE_ID_FIELDS)
SESSION_SCOPED_TABLES = frozenset(
    {
        "events",
        "sessions",
        "alerts",
        "analysis_jobs",
        "reports",
        "enrichment_jobs",
        "prediction_snapshots",
        "analyst_feedback",
        "classification_review_labels",
        "observable_sightings",
        "threat_hunt_jobs",
        "campaign_sessions",
    }
)


@dataclasses.dataclass(frozen=True)
class IndexDefinition:
    keys: Sequence[tuple[str, int]]
    name: str
    unique: bool = False


INDEX_DEFINITIONS: Dict[str, Sequence[IndexDefinition]] = {
    "events": (
        IndexDefinition((("event_id", ASCENDING),), "uq_events_event_id", True),
        IndexDefinition((("processed", ASCENDING), ("received_at", ASCENDING)), "idx_events_processed_received"),
        IndexDefinition((("session_id", ASCENDING),), "idx_events_session"),
        IndexDefinition(
            (
                ("processed", ASCENDING),
                ("next_retry_at", ASCENDING),
                ("claim_expires_at", ASCENDING),
                ("attempts", ASCENDING),
                ("received_at", ASCENDING),
                ("event_id", ASCENDING),
            ),
            "idx_events_claimable",
        ),
        IndexDefinition(
            (("processed", ASCENDING), ("next_retry_at", ASCENDING), ("received_at", ASCENDING)),
            "idx_events_retry",
        ),
        IndexDefinition(
            (("processing_outcome", ASCENDING), ("processed_at", DESCENDING), ("event_id", ASCENDING)),
            "idx_events_failed",
        ),
        IndexDefinition(
            (
                ("session_id", ASCENDING),
                ("processed", ASCENDING),
                ("received_at", ASCENDING),
                ("event_id", ASCENDING),
            ),
            "idx_events_session_queue",
        ),
        IndexDefinition(
            (
                ("processed", ASCENDING),
                ("claim_leader_scope", ASCENDING),
                ("claim_expires_at", ASCENDING),
                ("claim_leader_token", ASCENDING),
                ("claim_owner", ASCENDING),
            ),
            "idx_events_leader_fence",
        ),
    ),
    "sessions": (
        IndexDefinition((("session_id", ASCENDING),), "uq_sessions_session_id", True),
        IndexDefinition((("session_source", ASCENDING), ("updated_at", DESCENDING)), "idx_sessions_source_updated"),
        IndexDefinition(
            (("ended", ASCENDING), ("session_source", ASCENDING), ("updated_at", ASCENDING)),
            "idx_sessions_active_source_updated",
        ),
        IndexDefinition(
            (("session_source", ASCENDING), ("is_external_source", ASCENDING), ("updated_at", DESCENDING)),
            "idx_sessions_source_external_updated",
        ),
    ),
    "alerts": (
        IndexDefinition((("alert_id", ASCENDING),), "uq_alerts_alert_id", True),
        IndexDefinition((("delivered", ASCENDING), ("created_at", ASCENDING)), "idx_alerts_delivery_queue"),
        IndexDefinition((("session_id", ASCENDING), ("created_at", DESCENDING)), "idx_alerts_session"),
    ),
    "analysis_jobs": (
        IndexDefinition((("job_id", ASCENDING),), "uq_analysis_jobs_job_id", True),
        IndexDefinition((("status", ASCENDING), ("created_at", ASCENDING), ("job_id", ASCENDING)), "idx_analysis_claim"),
        IndexDefinition((("session_id", ASCENDING),), "idx_analysis_session"),
    ),
    "reports": (
        IndexDefinition((("report_id", ASCENDING),), "uq_reports_report_id", True),
        IndexDefinition((("session_id", ASCENDING), ("created_at", DESCENDING)), "idx_reports_session"),
    ),
    "feed_status": (IndexDefinition((("name", ASCENDING),), "uq_feed_status_name", True),),
    "observables": (
        IndexDefinition(
            (("observable_type", ASCENDING), ("observable_value", ASCENDING)),
            "uq_observables_type_value",
            True,
        ),
        IndexDefinition((("last_seen", DESCENDING),), "idx_observables_last_seen"),
    ),
    "observable_sightings": (
        IndexDefinition((("sighting_id", ASCENDING),), "uq_observable_sightings_id", True),
        IndexDefinition(
            (("observable_type", ASCENDING), ("observable_value", ASCENDING), ("created_at", DESCENDING)),
            "idx_observable_sightings_observable",
        ),
        IndexDefinition((("session_id", ASCENDING), ("created_at", DESCENDING)), "idx_observable_sightings_session"),
    ),
    "enrichment_records": (
        IndexDefinition(
            (("observable_type", ASCENDING), ("observable_value", ASCENDING)),
            "uq_enrichment_records_type_value",
            True,
        ),
        IndexDefinition((("expires_at", ASCENDING),), "idx_enrichment_records_expires"),
    ),
    "enrichment_jobs": (
        IndexDefinition((("job_id", ASCENDING),), "uq_enrichment_jobs_job_id", True),
        IndexDefinition(
            (("observable_type", ASCENDING), ("observable_value", ASCENDING)),
            "uq_enrichment_jobs_type_value",
            True,
        ),
        IndexDefinition(
            (
                ("status", ASCENDING),
                ("priority_rank", DESCENDING),
                ("next_retry_at", ASCENDING),
                ("created_at", ASCENDING),
            ),
            "idx_enrichment_claim",
        ),
    ),
    "webhook_deliveries": (
        IndexDefinition((("delivery_id", ASCENDING),), "uq_webhook_deliveries_id", True),
        IndexDefinition((("alert_id", ASCENDING),), "idx_webhook_alert"),
        IndexDefinition((("report_id", ASCENDING),), "idx_webhook_report"),
    ),
    "prediction_snapshots": (
        IndexDefinition((("snapshot_id", ASCENDING),), "uq_prediction_snapshots_id", True),
        IndexDefinition((("session_id", ASCENDING), ("created_at", DESCENDING)), "idx_prediction_session"),
        IndexDefinition((("created_at", DESCENDING),), "idx_prediction_created"),
    ),
    "prediction_backtest_runs": (
        IndexDefinition((("run_id", ASCENDING),), "uq_prediction_backtest_runs_id", True),
        IndexDefinition((("created_at", DESCENDING),), "idx_prediction_backtest_created"),
    ),
    "prediction_calibration_runs": (
        IndexDefinition((("run_id", ASCENDING),), "uq_prediction_calibration_runs_id", True),
        IndexDefinition((("created_at", DESCENDING),), "idx_prediction_calibration_created"),
    ),
    "analyst_feedback": (
        IndexDefinition((("feedback_id", ASCENDING),), "uq_analyst_feedback_id", True),
        IndexDefinition((("session_id", ASCENDING), ("created_at", DESCENDING)), "idx_analyst_feedback_session"),
        IndexDefinition((("snapshot_id", ASCENDING),), "idx_analyst_feedback_snapshot"),
    ),
    "classification_review_labels": (
        IndexDefinition((("label_id", ASCENDING),), "uq_classification_review_labels_id", True),
        IndexDefinition((("session_id", ASCENDING), ("created_at", DESCENDING)), "idx_classification_review_session"),
        IndexDefinition((("review_id", ASCENDING),), "idx_classification_review_review"),
    ),
    "threat_hunt_jobs": (
        IndexDefinition((("job_id", ASCENDING),), "uq_threat_hunt_jobs_id", True),
        IndexDefinition(
            (("session_id", ASCENDING), ("observable_type", ASCENDING), ("observable_value", ASCENDING)),
            "uq_threat_hunt_jobs_session_observable",
            True,
        ),
        IndexDefinition((("status", ASCENDING), ("created_at", ASCENDING), ("job_id", ASCENDING)), "idx_threat_hunt_claim"),
        IndexDefinition((("observable_type", ASCENDING), ("observable_value", ASCENDING)), "idx_threat_hunt_observable"),
    ),
    "session_links": (
        IndexDefinition((("link_id", ASCENDING),), "uq_session_links_id", True),
        IndexDefinition((("session_id_a", ASCENDING), ("created_at", DESCENDING)), "idx_session_links_a"),
        IndexDefinition((("session_id_b", ASCENDING), ("created_at", DESCENDING)), "idx_session_links_b"),
        IndexDefinition((("observable_type", ASCENDING), ("observable_value", ASCENDING)), "idx_session_links_observable"),
    ),
    "campaigns": (
        IndexDefinition((("campaign_id", ASCENDING),), "uq_campaigns_id", True),
        IndexDefinition((("hassh_fingerprint", ASCENDING),), "idx_campaigns_hassh"),
        IndexDefinition((("ja3_fingerprint", ASCENDING),), "idx_campaigns_ja3"),
        IndexDefinition((("command_pattern_hash", ASCENDING),), "idx_campaigns_command_pattern"),
        IndexDefinition((("tactic_sequence_hash", ASCENDING),), "idx_campaigns_tactic_sequence"),
        IndexDefinition((("source_ip", ASCENDING),), "idx_campaigns_source_ip"),
    ),
    "campaign_sessions": (
        IndexDefinition((("link_id", ASCENDING),), "uq_campaign_sessions_id", True),
        IndexDefinition((("campaign_id", ASCENDING), ("session_id", ASCENDING)), "uq_campaign_sessions_pair", True),
        IndexDefinition((("campaign_id", ASCENDING), ("created_at", DESCENDING)), "idx_campaign_sessions_campaign"),
        IndexDefinition((("session_id", ASCENDING), ("created_at", DESCENDING)), "idx_campaign_sessions_session"),
    ),
}


STORAGE_LEASE_INDEX_DEFINITIONS: Sequence[IndexDefinition] = (
    IndexDefinition((("scope", ASCENDING),), "uq_storage_leases_scope", True),
    IndexDefinition((("expires_at", ASCENDING),), "idx_storage_leases_expiry"),
)

MONGODB_FENCED_TRANSACTION_ATTEMPTS = 3
MONGODB_EVENT_SCAN_LIMIT = 1000


def _has_transaction_error_label(exc: BaseException, label: str) -> bool:
    checker = getattr(exc, "has_error_label", None)
    if not callable(checker):
        return False
    try:
        return bool(checker(label))
    except Exception:
        return False


def _domain_id(table: str, document: Mapping[str, Any]) -> str:
    fields = TABLE_ID_FIELDS[table]
    values = [str(document.get(field) or "") for field in fields]
    if len(values) == 1 and values[0]:
        return values[0]
    return stable_id(table.rstrip("s") or "document", dict(zip(fields, values)))


def _decode_json_field(value: Any, default: Any) -> Any:
    if value is None or value == "":
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(str(value))
    except (TypeError, ValueError):
        return default


def document_from_sqlite_row(table: str, row: Mapping[str, Any]) -> Dict[str, Any]:
    """Convert one SQLite row into the canonical MongoDB document model."""

    if table not in ALLOWED_TABLES:
        raise ValueError(f"unsupported table: {table}")
    document = {str(key): value for key, value in row.items() if key != "__rowid__"}
    for json_column, native_field in JSON_FIELDS.get(table, {}).items():
        if json_column in document:
            default: Any = [] if native_field in {"confirmed_tactics", "match_reasons"} else {}
            document[native_field] = _decode_json_field(document.pop(json_column), default)
    if table == "enrichment_jobs":
        priority = _normalize_priority(str(document.get("priority") or "normal"))
        document["priority"] = priority
        document["priority_rank"] = PRIORITY_RANK[priority]
    if table == "events":
        if "effect_summary_json" in document:
            raw_summary = document.pop("effect_summary_json")
            document["effect_summary"] = (
                None if raw_summary in (None, "") else _decode_json_field(raw_summary, {})
            )
        # SQLite exposes booleans as integers.  Normalize them here because
        # MongoDB distinguishes BSON booleans from numbers in query matching.
        document["processed"] = bool(document.get("processed", False))
        if "attempts" in document:
            document["attempts"] = int(document.get("attempts") or 0)
    document["schema_version"] = MONGODB_SCHEMA_VERSION
    document["_id"] = _domain_id(table, document)
    return to_bson_safe(document)


def row_from_document(table: str, document: Mapping[str, Any]) -> Dict[str, Any]:
    """Convert a native MongoDB document to the SQLite-compatible row shape."""

    item = from_bson_safe(document)
    if not isinstance(item, dict):
        return {}
    item = dict(item)
    item.pop("_id", None)
    item.pop("priority_rank", None)
    for json_column, native_field in JSON_FIELDS.get(table, {}).items():
        native = item.pop(native_field, [] if native_field in {"confirmed_tactics", "match_reasons"} else {})
        item[json_column] = stable_json(native)
    if table == "events":
        native_summary = item.pop("effect_summary", None)
        item["effect_summary_json"] = (
            None if native_summary is None else stable_json(native_summary)
        )
        if "processed" in item:
            item["processed"] = int(bool(item["processed"]))
    return item


class MongoStorage:
    """MongoDB implementation of the production storage contract."""

    def __init__(
        self,
        mongodb_uri: str,
        database_name: str = "",
        *,
        client: Any = None,
        database: Any = None,
        connect_timeout_ms: int = 5000,
    ):
        if not str(mongodb_uri or "").startswith(("mongodb://", "mongodb+srv://")):
            raise StorageError("MongoDBStorage requires a mongodb:// or mongodb+srv:// URI")
        self.mongodb_uri = str(mongodb_uri)
        self.database_name = str(database_name or "").strip()
        self._injected_database = database is not None

        if database is not None:
            self.client = client
            self.database = database
            if not self.database_name:
                self.database_name = str(getattr(database, "name", "") or "injected")
            return

        if client is None:
            if MongoClient is None:
                raise StorageError(mongodb_dependency_diagnostic()["message"])
            try:
                client = MongoClient(
                    self.mongodb_uri,
                    serverSelectionTimeoutMS=max(int(connect_timeout_ms), 1),
                    appname="honeypot-analysis",
                )
            except Exception as exc:
                raise StorageError(f"unable to create MongoDB client: {_safe_error(exc)}") from exc
        self.client = client
        if self.database_name:
            self.database = client[self.database_name]
        else:
            try:
                self.database = client.get_default_database()
                self.database_name = str(getattr(self.database, "name", "") or "")
            except Exception as exc:
                raise StorageError(
                    "MongoDB database name is required when the URI has no default database"
                ) from exc
        if not self.database_name:
            raise StorageError("MongoDB database name must not be empty")

    def connect(self) -> Any:
        return self.database

    @contextmanager
    def connection(self) -> Iterator[Any]:
        yield self.database

    def _run_fenced_transaction(self, operation: Any) -> Any:
        """Run one leader-fenced operation in a bounded Mongo transaction."""

        start_session = getattr(self.client, "start_session", None)
        if not callable(start_session):
            raise StorageError(
                "MongoDB leader fencing requires transaction-capable sessions"
            )

        last_error: Optional[BaseException] = None
        for transaction_attempt in range(MONGODB_FENCED_TRANSACTION_ATTEMPTS):
            try:
                with start_session() as session:
                    session.start_transaction()
                    try:
                        result = operation(session)
                    except Exception:
                        if bool(getattr(session, "in_transaction", False)):
                            session.abort_transaction()
                        raise

                    for commit_attempt in range(MONGODB_FENCED_TRANSACTION_ATTEMPTS):
                        try:
                            session.commit_transaction()
                            return result
                        except Exception as exc:
                            last_error = exc
                            if (
                                _has_transaction_error_label(
                                    exc,
                                    "UnknownTransactionCommitResult",
                                )
                                and commit_attempt
                                < MONGODB_FENCED_TRANSACTION_ATTEMPTS - 1
                            ):
                                continue
                            raise
            except Exception as exc:
                last_error = exc
                if (
                    _has_transaction_error_label(exc, "TransientTransactionError")
                    and transaction_attempt < MONGODB_FENCED_TRANSACTION_ATTEMPTS - 1
                ):
                    continue
                raise StorageError(
                    f"MongoDB fenced transaction failed: {_safe_error(exc)}"
                ) from exc

        # The loop always returns or raises; this keeps the failure mode stable
        # if a nonstandard driver violates that expectation.
        raise StorageError(
            "MongoDB fenced transaction failed: "
            + (_safe_error(last_error) if last_error else "operation_failed")
        )

    def _collection(self, table: str) -> Any:
        if table not in ALLOWED_TABLES:
            raise ValueError(f"unsupported table: {table}")
        return self.database[table]

    def initialize(self) -> None:
        try:
            for table, definitions in INDEX_DEFINITIONS.items():
                collection = self._collection(table)
                for definition in definitions:
                    collection.create_index(
                        list(definition.keys),
                        name=definition.name,
                        unique=definition.unique,
                    )
            self.database["_migration_checkpoints"].create_index(
                [("migration_id", ASCENDING), ("table", ASCENDING)],
                name="uq_migration_checkpoint",
                unique=True,
            )
            lease_collection = self.database["_storage_leases"]
            for definition in STORAGE_LEASE_INDEX_DEFINITIONS:
                lease_collection.create_index(
                    list(definition.keys),
                    name=definition.name,
                    unique=definition.unique,
                )
            # Publish the schema version only after every required index has
            # been created successfully.  A partial initialization must never
            # advertise itself as a usable v2 backend.
            self.database["_storage_metadata"].replace_one(
                {"_id": "schema"},
                {
                    "_id": "schema",
                    "backend": "mongodb",
                    "schema_version": MONGODB_SCHEMA_VERSION,
                    "updated_at": utc_now(),
                },
                upsert=True,
            )
        except Exception as exc:
            raise StorageError(f"MongoDB initialization failed: {_safe_error(exc)}") from exc

    def health_check(self) -> Dict[str, Any]:
        diagnostic = mongodb_dependency_diagnostic()
        result: Dict[str, Any] = {
            "backend": "mongodb",
            "database": self.database_name,
            "driver_available": diagnostic["available"] or self._injected_database,
            "ok": False,
            "status": "error",
        }
        try:
            if self.client is not None and getattr(self.client, "admin", None) is not None:
                self.client.admin.command("ping")
            elif hasattr(self.database, "command"):
                self.database.command("ping")
            else:
                self.database["_storage_metadata"].find_one({"_id": "schema"})
            result["ok"] = True
            result["status"] = "ok"
        except Exception as exc:
            result["error"] = _safe_error(exc)
        return result

    def _insert_once(self, table: str, document: Mapping[str, Any]) -> bool:
        versioned = dict(document)
        versioned.setdefault("schema_version", MONGODB_SCHEMA_VERSION)
        encoded = to_bson_safe(versioned)
        result = self._collection(table).update_one(
            {"_id": encoded["_id"]},
            {"$setOnInsert": encoded},
            upsert=True,
        )
        return getattr(result, "upserted_id", None) is not None

    def _replace(self, table: str, document: Mapping[str, Any]) -> None:
        versioned = dict(document)
        versioned.setdefault("schema_version", MONGODB_SCHEMA_VERSION)
        encoded = to_bson_safe(versioned)
        self._collection(table).replace_one({"_id": encoded["_id"]}, encoded, upsert=True)

    def _find(self, table: str, query: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        document = self._collection(table).find_one(dict(query))
        if document is None:
            return None
        decoded = from_bson_safe(document)
        return dict(decoded) if isinstance(decoded, Mapping) else None

    def store_event(self, sensor_id: str, event: Dict[str, Any]) -> tuple[str, bool]:
        event_key = make_event_id(sensor_id, event)
        document = {
            "_id": event_key,
            "event_id": event_key,
            "sensor_id": sensor_id,
            "session_id": str(event.get("session", "unknown")),
            "src_ip": str(event.get("src_ip", "unknown")),
            "eventid": str(event.get("eventid", "")),
            "timestamp": event.get("timestamp"),
            "payload": dict(event),
            "received_at": utc_now(),
            "processed": False,
            "attempts": 0,
        }
        return event_key, self._insert_once("events", document)

    def fetch_unprocessed_events(self, limit: int) -> List[Dict[str, Any]]:
        cursor = self._collection("events").find({"processed": {"$in": [False, 0]}}).sort(
            [("received_at", ASCENDING), ("event_id", ASCENDING)]
        ).limit(max(int(limit), 0))
        output = []
        for raw in cursor:
            item = from_bson_safe(raw)
            payload = dict(item.get("payload") or {})
            output.append(
                {
                    "event_id": item["event_id"],
                    "sensor_id": item["sensor_id"],
                    "event": payload,
                    "payload_json": stable_json(payload),
                }
            )
        return output

    @staticmethod
    def _event_due_and_unleased_query(now: str) -> Dict[str, Any]:
        return {
            "$and": [
                {
                    "$or": [
                        {"next_retry_at": None},
                        {"next_retry_at": {"$exists": False}},
                        {"next_retry_at": {"$lte": now}},
                    ]
                },
                {
                    "$or": [
                        {"claim_expires_at": None},
                        {"claim_expires_at": {"$exists": False}},
                        {"claim_expires_at": {"$lte": now}},
                    ]
                },
            ]
        }

    def _leader_allows_event_claim(
        self,
        scope: str,
        owner: str,
        token: str,
        event_claim_expires_at: str,
        *,
        session: Any = None,
        touch: bool = False,
    ) -> bool:
        query = {
            "_id": scope,
            "scope": scope,
            "owner": owner,
            "token": token,
            "expires_at": {"$gte": event_claim_expires_at},
        }
        collection = self.database["_storage_leases"]
        if touch:
            return collection.find_one_and_update(
                query,
                {"$inc": {"fence_revision": 1}},
                return_document=ReturnDocument.AFTER,
                session=session,
            ) is not None
        return collection.find_one(query, session=session) is not None

    def _leader_is_active(
        self,
        scope: str,
        owner: str,
        token: str,
        now: str,
        *,
        session: Any = None,
        touch: bool = False,
    ) -> bool:
        query = {
            "_id": scope,
            "scope": scope,
            "owner": owner,
            "token": token,
            "expires_at": {"$gt": now},
        }
        collection = self.database["_storage_leases"]
        if touch:
            return collection.find_one_and_update(
                query,
                {"$inc": {"fence_revision": 1}},
                return_document=ReturnDocument.AFTER,
                session=session,
            ) is not None
        return collection.find_one(query, session=session) is not None

    def _event_claim_leader_guard(
        self,
        event_id: str,
        owner: str,
        claim_token: str,
        now: str,
        leader_scope: str,
        leader_token: str,
        *,
        required_leader_expiry: str = "",
        session: Any = None,
    ) -> Optional[Dict[str, Any]]:
        """Return the CAS binding filter for an authorized active claim.

        Schema-v1 and explicitly ungated claims have no stored leader binding
        and remain compatible with ungated lifecycle calls.  Once a claim is
        bound, however, omitting or changing its leader context fails closed.
        """

        if bool(leader_scope) != bool(leader_token):
            raise ValueError("leader_scope and leader_token must be provided together")
        requested_scope = (
            _required_identity(leader_scope, "leader_scope") if leader_scope else ""
        )
        requested_token = (
            _uuid_token(leader_token, "leader_token") if leader_token else ""
        )
        claim = self._collection("events").find_one(
            {
                "event_id": event_id,
                "processed": {"$in": [False, 0]},
                "claim_owner": owner,
                "claim_token": claim_token,
                "claim_expires_at": {"$gt": now},
            },
            session=session,
        )
        if claim is None:
            return None

        stored_scope = str(claim.get("claim_leader_scope") or "").strip()
        stored_token = str(claim.get("claim_leader_token") or "").strip()
        if bool(stored_scope) != bool(stored_token):
            return None
        if stored_scope:
            if requested_scope != stored_scope or requested_token != stored_token:
                return None
            effective_scope = stored_scope
            effective_token = stored_token
            binding_filter: Dict[str, Any] = {
                "claim_leader_scope": stored_scope,
                "claim_leader_token": stored_token,
            }
        else:
            if requested_scope or requested_token:
                return None
            effective_scope = requested_scope
            effective_token = requested_token
            binding_filter = {
                "$and": [
                    {
                        "$or": [
                            {"claim_leader_scope": {"$exists": False}},
                            {"claim_leader_scope": None},
                            {"claim_leader_scope": ""},
                        ]
                    },
                    {
                        "$or": [
                            {"claim_leader_token": {"$exists": False}},
                            {"claim_leader_token": None},
                            {"claim_leader_token": ""},
                        ]
                    },
                ]
            }

        if effective_scope:
            leader_ok = (
                self._leader_allows_event_claim(
                    effective_scope,
                    owner,
                    effective_token,
                    required_leader_expiry,
                    session=session,
                    touch=session is not None,
                )
                if required_leader_expiry
                else self._leader_is_active(
                    effective_scope,
                    owner,
                    effective_token,
                    now,
                    session=session,
                    touch=session is not None,
                )
            )
            if not leader_ok:
                return None
        return binding_filter

    def _claim_has_stored_leader_binding(
        self,
        event_id: str,
        owner: str,
        claim_token: str,
    ) -> bool:
        claim = self._collection("events").find_one(
            {
                "event_id": event_id,
                "processed": {"$in": [False, 0]},
                "claim_owner": owner,
                "claim_token": claim_token,
            }
        )
        return bool(
            claim
            and (
                claim.get("claim_leader_scope")
                or claim.get("claim_leader_token")
            )
        )

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
        if bool(leader_scope) != bool(leader_token):
            raise ValueError("leader_scope and leader_token must be provided together")
        if leader_scope:
            return self._run_fenced_transaction(
                lambda session: self._claim_events_once(
                    owner,
                    limit,
                    lease_seconds,
                    max_attempts,
                    now=now,
                    leader_scope=leader_scope,
                    leader_token=leader_token,
                    session=session,
                )
            )
        return self._claim_events_once(
            owner,
            limit,
            lease_seconds,
            max_attempts,
            now=now,
        )

    def _claim_events_once(
        self,
        owner: str,
        limit: int,
        lease_seconds: float,
        max_attempts: int = 5,
        *,
        now: Any = None,
        leader_scope: str = "",
        leader_token: str = "",
        session: Any = None,
    ) -> List[Dict[str, Any]]:
        owner = _required_identity(owner, "owner")
        try:
            requested = max(int(limit), 0)
        except (TypeError, ValueError) as exc:
            raise ValueError("limit must be an integer") from exc
        attempt_limit = _positive_attempt_limit(max_attempts)
        claimed_at = _utc_timestamp(now)
        claim_expires_at = _future_timestamp(
            claimed_at,
            lease_seconds,
            field="lease_seconds",
        )
        if bool(leader_scope) != bool(leader_token):
            raise ValueError("leader_scope and leader_token must be provided together")
        if leader_scope:
            leader_scope = _required_identity(leader_scope, "leader_scope")
            leader_token = _uuid_token(leader_token, "leader_token")

        collection = self._collection("events")
        due_and_unleased = self._event_due_and_unleased_query(claimed_at)
        base_query: Dict[str, Any] = {
            "processed": {"$in": [False, 0]},
            **due_and_unleased,
        }

        if leader_scope and not self._leader_allows_event_claim(
            leader_scope,
            owner,
            leader_token,
            claim_expires_at,
            session=session,
            touch=session is not None,
        ):
            return []

        def is_session_head(candidate: Mapping[str, Any]) -> bool:
            head = collection.find_one(
                {
                    "session_id": candidate.get("session_id"),
                    "processed": {"$in": [False, 0]},
                },
                sort=[("received_at", ASCENDING), ("event_id", ASCENDING)],
                session=session,
            )
            return bool(head and head.get("_id") == candidate.get("_id"))

        # Rows that have exhausted their attempt budget cannot be claimed
        # again.  Transition them atomically so operators can see the terminal
        # failure even when they originated as schema-v1 documents.
        maintenance_count = 0
        while maintenance_count < MONGODB_EVENT_SCAN_LIMIT:
            progressed = False
            exhausted_cursor = collection.find(
                {**base_query, "attempts": {"$gte": attempt_limit}},
                session=session,
            ).sort([("received_at", ASCENDING), ("event_id", ASCENDING)]).limit(
                MONGODB_EVENT_SCAN_LIMIT - maintenance_count
            )
            for candidate in exhausted_cursor:
                if leader_scope and not self._leader_allows_event_claim(
                    leader_scope,
                    owner,
                    leader_token,
                    claim_expires_at,
                    session=session,
                    touch=session is not None,
                ):
                    return []
                if not is_session_head(candidate):
                    continue
                exhausted = collection.find_one_and_update(
                    {
                        "_id": candidate["_id"],
                        **base_query,
                        "attempts": {"$gte": attempt_limit},
                    },
                    {
                        "$set": {
                            "processed": True,
                            "processing_outcome": "dead_letter",
                            "processed_at": claimed_at,
                            "last_error_code": "event_lease_attempts_exhausted",
                            "last_error_type": "LeaseExpired",
                            "last_error_at": claimed_at,
                            "schema_version": MONGODB_SCHEMA_VERSION,
                        },
                        "$unset": {
                            "claim_owner": "",
                            "claim_token": "",
                            "claim_expires_at": "",
                            "claimed_at": "",
                            "claim_leader_scope": "",
                            "claim_leader_token": "",
                            "next_retry_at": "",
                            "effect_summary": "",
                        },
                    },
                    return_document=ReturnDocument.AFTER,
                    session=session,
                )
                if exhausted is not None:
                    progressed = True
                    maintenance_count += 1
                    if maintenance_count >= MONGODB_EVENT_SCAN_LIMIT:
                        break
            if not progressed:
                break

        output: List[Dict[str, Any]] = []
        eligible_query = {
            **base_query,
            "$and": [
                *base_query["$and"],
                {
                    "$or": [
                        {"attempts": {"$exists": False}},
                        {"attempts": {"$lt": attempt_limit}},
                    ]
                },
            ],
        }
        candidates = collection.find(eligible_query, session=session).sort(
            [("received_at", ASCENDING), ("event_id", ASCENDING)]
        ).limit(MONGODB_EVENT_SCAN_LIMIT)
        invalid_event_update = {
            "$set": {
                "processed": True,
                "processing_outcome": "dead_letter",
                "processed_at": claimed_at,
                "last_error_code": "event_processing_invalid",
                "last_error_type": "ValidationError",
                "last_error_at": claimed_at,
                "schema_version": MONGODB_SCHEMA_VERSION,
            },
            "$unset": {
                "claim_owner": "",
                "claim_token": "",
                "claim_expires_at": "",
                "claimed_at": "",
                "claim_leader_scope": "",
                "claim_leader_token": "",
                "next_retry_at": "",
                "effect_summary": "",
            },
        }
        for candidate in candidates:
            if len(output) >= requested:
                break
            if leader_scope and not self._leader_allows_event_claim(
                leader_scope,
                owner,
                leader_token,
                claim_expires_at,
                session=session,
                touch=session is not None,
            ):
                break
            if not is_session_head(candidate):
                continue
            if not isinstance(candidate.get("payload"), Mapping):
                collection.find_one_and_update(
                    {"_id": candidate["_id"], **eligible_query},
                    invalid_event_update,
                    return_document=ReturnDocument.AFTER,
                    session=session,
                )
                continue
            claim_token = str(uuid4())
            claim_set: Dict[str, Any] = {
                "claim_owner": owner,
                "claim_token": claim_token,
                "claim_expires_at": claim_expires_at,
                "claimed_at": claimed_at,
                "schema_version": MONGODB_SCHEMA_VERSION,
            }
            claim_unset: Dict[str, Any] = {
                "processing_outcome": "",
                "effect_summary": "",
            }
            if leader_scope:
                claim_set["claim_leader_scope"] = leader_scope
                claim_set["claim_leader_token"] = leader_token
            else:
                claim_unset["claim_leader_scope"] = ""
                claim_unset["claim_leader_token"] = ""
            raw = collection.find_one_and_update(
                {
                    "_id": candidate["_id"],
                    **eligible_query,
                },
                {
                    "$set": claim_set,
                    "$unset": claim_unset,
                    "$inc": {"attempts": 1},
                },
                sort=[("received_at", ASCENDING), ("event_id", ASCENDING)],
                return_document=ReturnDocument.AFTER,
                session=session,
            )
            if raw is None:
                # Another claimant may have won this exact document between
                # the head check and CAS.  Other sessions can still progress.
                continue
            item = from_bson_safe(raw)
            payload_value = item.get("payload")
            if not isinstance(payload_value, Mapping):
                collection.update_one(
                    {
                        "event_id": item["event_id"],
                        "processed": {"$in": [False, 0]},
                        "claim_owner": owner,
                        "claim_token": claim_token,
                    },
                    invalid_event_update,
                    session=session,
                )
                continue
            payload = dict(payload_value)
            output.append(
                {
                    "event_id": item["event_id"],
                    "sensor_id": item["sensor_id"],
                    "event": payload,
                    "payload_json": stable_json(payload),
                    "claim_owner": item["claim_owner"],
                    "claim_token": item["claim_token"],
                    "claim_expires_at": item["claim_expires_at"],
                    "claim_leader_scope": str(item.get("claim_leader_scope") or ""),
                    "claim_leader_token": str(item.get("claim_leader_token") or ""),
                    "attempts": int(item.get("attempts") or 0),
                }
            )
        return output

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
        event_identity = _required_identity(event_id, "event_id")
        claim_owner = _required_identity(owner, "owner")
        claim_token = _uuid_token(token, "token")
        if bool(leader_scope) != bool(leader_token):
            raise ValueError("leader_scope and leader_token must be provided together")
        validation_now = _utc_timestamp(now)
        _future_timestamp(validation_now, lease_seconds, field="lease_seconds")
        requires_transaction = bool(leader_scope) or self._claim_has_stored_leader_binding(
            event_identity,
            claim_owner,
            claim_token,
        )
        operation = lambda session: self._renew_event_claim_once(
            event_identity,
            claim_owner,
            claim_token,
            lease_seconds,
            now=now,
            leader_scope=leader_scope,
            leader_token=leader_token,
            session=session,
        )
        return (
            self._run_fenced_transaction(operation)
            if requires_transaction
            else operation(None)
        )

    def _renew_event_claim_once(
        self,
        event_id: str,
        owner: str,
        token: str,
        lease_seconds: float,
        *,
        now: Any = None,
        leader_scope: str = "",
        leader_token: str = "",
        session: Any = None,
    ) -> bool:
        event_id = _required_identity(event_id, "event_id")
        owner = _required_identity(owner, "owner")
        token = _uuid_token(token, "token")
        renewed_at = _utc_timestamp(now)
        expires_at = _future_timestamp(renewed_at, lease_seconds, field="lease_seconds")
        if bool(leader_scope) != bool(leader_token):
            raise ValueError("leader_scope and leader_token must be provided together")
        if leader_scope:
            leader_scope = _required_identity(leader_scope, "leader_scope")
            leader_token = _uuid_token(leader_token, "leader_token")
        binding_filter = self._event_claim_leader_guard(
            event_id,
            owner,
            token,
            renewed_at,
            leader_scope,
            leader_token,
            required_leader_expiry=expires_at,
            session=session,
        )
        if binding_filter is None:
            return False
        set_values: Dict[str, Any] = {
            "claim_expires_at": expires_at,
            "claimed_at": renewed_at,
            "schema_version": MONGODB_SCHEMA_VERSION,
        }
        if leader_scope:
            set_values["claim_leader_scope"] = leader_scope
            set_values["claim_leader_token"] = leader_token
        result = self._collection("events").update_one(
            {
                "event_id": event_id,
                "processed": {"$in": [False, 0]},
                "claim_owner": owner,
                "claim_token": token,
                "claim_expires_at": {"$gt": renewed_at},
                **binding_filter,
            },
            {"$set": set_values},
            session=session,
        )
        return bool(getattr(result, "matched_count", 0))

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
        event_identity = _required_identity(event_id, "event_id")
        claim_owner = _required_identity(owner, "owner")
        claim_token = _uuid_token(token, "token")
        if bool(leader_scope) != bool(leader_token):
            raise ValueError("leader_scope and leader_token must be provided together")
        validate_event_effect_summary(effect_summary)
        requires_transaction = bool(leader_scope) or self._claim_has_stored_leader_binding(
            event_identity,
            claim_owner,
            claim_token,
        )
        operation = lambda session: self._complete_event_once(
            event_identity,
            claim_owner,
            claim_token,
            effect_summary,
            now=now,
            leader_scope=leader_scope,
            leader_token=leader_token,
            session=session,
        )
        return (
            self._run_fenced_transaction(operation)
            if requires_transaction
            else operation(None)
        )

    def _complete_event_once(
        self,
        event_id: str,
        owner: str,
        token: str,
        effect_summary: Optional[Dict[str, Any]] = None,
        *,
        now: Any = None,
        leader_scope: str = "",
        leader_token: str = "",
        session: Any = None,
    ) -> bool:
        event_id = _required_identity(event_id, "event_id")
        owner = _required_identity(owner, "owner")
        token = _uuid_token(token, "token")
        completed_at = _utc_timestamp(now)
        validated_effect_summary = validate_event_effect_summary(effect_summary)
        binding_filter = self._event_claim_leader_guard(
            event_id,
            owner,
            token,
            completed_at,
            leader_scope,
            leader_token,
            session=session,
        )
        if binding_filter is None:
            return False
        result = self._collection("events").update_one(
            {
                "event_id": event_id,
                "processed": {"$in": [False, 0]},
                "claim_owner": owner,
                "claim_token": token,
                "claim_expires_at": {"$gt": completed_at},
                **binding_filter,
            },
            {
                "$set": to_bson_safe(
                    {
                        "processed": True,
                        "processing_outcome": "succeeded",
                        "processed_at": completed_at,
                        "effect_summary": validated_effect_summary,
                        "schema_version": MONGODB_SCHEMA_VERSION,
                    }
                ),
                "$unset": {
                    "claim_owner": "",
                    "claim_token": "",
                    "claim_expires_at": "",
                    "claimed_at": "",
                    "claim_leader_scope": "",
                    "claim_leader_token": "",
                    "next_retry_at": "",
                    "last_error_code": "",
                    "last_error_type": "",
                    "last_error_at": "",
                },
            },
            session=session,
        )
        return bool(getattr(result, "matched_count", 0))

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
        event_identity = _required_identity(event_id, "event_id")
        claim_owner = _required_identity(owner, "owner")
        claim_token = _uuid_token(token, "token")
        if bool(leader_scope) != bool(leader_token):
            raise ValueError("leader_scope and leader_token must be provided together")
        validate_event_failure_fields(error_code, error_type)
        _positive_attempt_limit(max_attempts)
        validation_now = _utc_timestamp(now)
        _retry_timestamp(validation_now, retry_delay_seconds)
        requires_transaction = bool(leader_scope) or self._claim_has_stored_leader_binding(
            event_identity,
            claim_owner,
            claim_token,
        )
        operation = lambda session: self._fail_event_once(
            event_identity,
            claim_owner,
            claim_token,
            error_code,
            error_type,
            retryable,
            max_attempts,
            retry_delay_seconds,
            now=now,
            leader_scope=leader_scope,
            leader_token=leader_token,
            session=session,
        )
        return (
            self._run_fenced_transaction(operation)
            if requires_transaction
            else operation(None)
        )

    def _fail_event_once(
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
        session: Any = None,
    ) -> str:
        event_id = _required_identity(event_id, "event_id")
        owner = _required_identity(owner, "owner")
        token = _uuid_token(token, "token")
        error_code, error_type = validate_event_failure_fields(error_code, error_type)
        attempt_limit = _positive_attempt_limit(max_attempts)
        failed_at = _utc_timestamp(now)
        next_retry_at = _retry_timestamp(failed_at, retry_delay_seconds)
        binding_filter = self._event_claim_leader_guard(
            event_id,
            owner,
            token,
            failed_at,
            leader_scope,
            leader_token,
            session=session,
        )
        if binding_filter is None:
            return "stale_claim"
        active_claim = {
            "event_id": event_id,
            "processed": {"$in": [False, 0]},
            "claim_owner": owner,
            "claim_token": token,
            "claim_expires_at": {"$gt": failed_at},
            **binding_filter,
        }
        collection = self._collection("events")
        if retryable:
            retry_result = collection.update_one(
                {**active_claim, "attempts": {"$lt": attempt_limit}},
                {
                    "$set": {
                        "next_retry_at": next_retry_at,
                        "last_error_code": error_code,
                        "last_error_type": error_type,
                        "last_error_at": failed_at,
                        "processing_outcome": "retry_scheduled",
                        "schema_version": MONGODB_SCHEMA_VERSION,
                    },
                    "$unset": {
                        "claim_owner": "",
                        "claim_token": "",
                        "claim_expires_at": "",
                        "claimed_at": "",
                        "claim_leader_scope": "",
                        "claim_leader_token": "",
                    },
                },
                session=session,
            )
            if getattr(retry_result, "matched_count", 0):
                return "retry_scheduled"

        dead_letter_result = collection.update_one(
            active_claim,
            {
                "$set": {
                    "processed": True,
                    "processing_outcome": "dead_letter",
                    "processed_at": failed_at,
                    "last_error_code": error_code,
                    "last_error_type": error_type,
                    "last_error_at": failed_at,
                    "schema_version": MONGODB_SCHEMA_VERSION,
                },
                "$unset": {
                    "claim_owner": "",
                    "claim_token": "",
                    "claim_expires_at": "",
                    "claimed_at": "",
                    "claim_leader_scope": "",
                    "claim_leader_token": "",
                    "next_retry_at": "",
                    "effect_summary": "",
                },
            },
            session=session,
        )
        return (
            "dead_letter"
            if getattr(dead_letter_result, "matched_count", 0)
            else "stale_claim"
        )

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
        event_identity = _required_identity(event_id, "event_id")
        claim_owner = _required_identity(owner, "owner")
        claim_token = _uuid_token(token, "token")
        if bool(leader_scope) != bool(leader_token):
            raise ValueError("leader_scope and leader_token must be provided together")
        requires_transaction = bool(leader_scope) or self._claim_has_stored_leader_binding(
            event_identity,
            claim_owner,
            claim_token,
        )
        operation = lambda session: self._release_event_claim_once(
            event_identity,
            claim_owner,
            claim_token,
            now=now,
            leader_scope=leader_scope,
            leader_token=leader_token,
            session=session,
        )
        return (
            self._run_fenced_transaction(operation)
            if requires_transaction
            else operation(None)
        )

    def _release_event_claim_once(
        self,
        event_id: str,
        owner: str,
        token: str,
        *,
        now: Any = None,
        leader_scope: str = "",
        leader_token: str = "",
        session: Any = None,
    ) -> bool:
        event_id = _required_identity(event_id, "event_id")
        owner = _required_identity(owner, "owner")
        token = _uuid_token(token, "token")
        released_at = _utc_timestamp(now)
        binding_filter = self._event_claim_leader_guard(
            event_id,
            owner,
            token,
            released_at,
            leader_scope,
            leader_token,
            session=session,
        )
        if binding_filter is None:
            return False
        result = self._collection("events").update_one(
            {
                "event_id": event_id,
                "processed": {"$in": [False, 0]},
                "claim_owner": owner,
                "claim_token": token,
                "claim_expires_at": {"$gt": released_at},
                **binding_filter,
            },
            {
                "$set": {"schema_version": MONGODB_SCHEMA_VERSION},
                "$unset": {
                    "claim_owner": "",
                    "claim_token": "",
                    "claim_expires_at": "",
                    "claimed_at": "",
                    "claim_leader_scope": "",
                    "claim_leader_token": "",
                    "processing_outcome": "",
                },
            },
            session=session,
        )
        return bool(getattr(result, "matched_count", 0))

    def list_failed_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        cursor = self._collection("events").find(
            {
                "processed": {"$in": [True, 1]},
                "processing_outcome": "dead_letter",
            }
        ).sort([("processed_at", DESCENDING), ("event_id", ASCENDING)]).limit(
            max(int(limit), 0)
        )
        output: List[Dict[str, Any]] = []
        for raw in cursor:
            item = from_bson_safe(raw)
            payload_value = item.get("payload")
            payload = dict(payload_value) if isinstance(payload_value, Mapping) else {}
            output.append(
                {
                    "event_id": item["event_id"],
                    "sensor_id": item["sensor_id"],
                    "event": payload,
                    "payload_json": stable_json(payload),
                    "attempts": int(item.get("attempts") or 0),
                    "last_error_code": item.get("last_error_code"),
                    "last_error_type": item.get("last_error_type"),
                    "last_error_at": item.get("last_error_at"),
                    "processing_outcome": item.get("processing_outcome"),
                    "processed_at": item.get("processed_at"),
                }
            )
        return output

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
        _required_identity(owner, "owner")
        _uuid_token(token, "token")
        validation_now = _utc_timestamp(now)
        _future_timestamp(validation_now, lease_seconds, field="lease_seconds")
        self._ensure_worker_lease_placeholder(lease_scope)
        return self._run_fenced_transaction(
            lambda session: self._acquire_worker_lease_once(
                lease_scope,
                owner,
                token,
                lease_seconds,
                now=now,
                session=session,
            )
        )

    def _ensure_worker_lease_placeholder(self, scope: str) -> None:
        collection = self.database["_storage_leases"]
        try:
            collection.update_one(
                {"_id": scope},
                {
                    "$setOnInsert": {
                        "_id": scope,
                        "scope": scope,
                        "schema_version": MONGODB_SCHEMA_VERSION,
                    }
                },
                upsert=True,
            )
        except Exception as exc:
            if (
                exc.__class__.__name__ != "DuplicateKeyError"
                or collection.find_one({"_id": scope, "scope": scope}) is None
            ):
                raise

    def _acquire_worker_lease_once(
        self,
        scope: str,
        owner: str,
        token: str,
        lease_seconds: float,
        *,
        now: Any = None,
        session: Any = None,
    ) -> bool:
        scope = _required_identity(scope, "scope")
        owner = _required_identity(owner, "owner")
        token = _uuid_token(token, "token")
        acquired_at = _utc_timestamp(now)
        expires_at = _future_timestamp(acquired_at, lease_seconds, field="lease_seconds")
        collection = self.database["_storage_leases"]
        existing_lease = collection.find_one({"_id": scope}, session=session)
        same_lease = bool(
            existing_lease
            and existing_lease.get("owner") == owner
            and existing_lease.get("token") == token
        )
        if not same_lease:
            active_foreign_claim = self._collection("events").find_one(
                {
                    "processed": {"$in": [False, 0]},
                    "claim_leader_scope": scope,
                    "claim_expires_at": {"$gt": acquired_at},
                    "$or": [
                        {"claim_leader_token": {"$ne": token}},
                        {"claim_owner": {"$ne": owner}},
                    ],
                },
                session=session,
            )
            if active_foreign_claim is not None:
                return False
        raw = collection.find_one_and_update(
            {
                "_id": scope,
                "$or": [
                    {"expires_at": {"$lte": acquired_at}},
                    {"expires_at": None},
                    {"expires_at": {"$exists": False}},
                    {"owner": owner, "token": token},
                ],
            },
            {
                "$set": {
                    "scope": scope,
                    "owner": owner,
                    "token": token,
                    "expires_at": expires_at,
                    "updated_at": acquired_at,
                    "schema_version": MONGODB_SCHEMA_VERSION,
                }
            },
            return_document=ReturnDocument.AFTER,
            session=session,
        )
        return raw is not None

    def renew_worker_lease(
        self,
        scope: str,
        owner: str,
        token: str,
        lease_seconds: float,
        *,
        now: Any = None,
    ) -> bool:
        _required_identity(scope, "scope")
        _required_identity(owner, "owner")
        _uuid_token(token, "token")
        validation_now = _utc_timestamp(now)
        _future_timestamp(validation_now, lease_seconds, field="lease_seconds")
        return self._run_fenced_transaction(
            lambda session: self._renew_worker_lease_once(
                scope,
                owner,
                token,
                lease_seconds,
                now=now,
                session=session,
            )
        )

    def _renew_worker_lease_once(
        self,
        scope: str,
        owner: str,
        token: str,
        lease_seconds: float,
        *,
        now: Any = None,
        session: Any = None,
    ) -> bool:
        scope = _required_identity(scope, "scope")
        owner = _required_identity(owner, "owner")
        token = _uuid_token(token, "token")
        renewed_at = _utc_timestamp(now)
        expires_at = _future_timestamp(renewed_at, lease_seconds, field="lease_seconds")
        result = self.database["_storage_leases"].update_one(
            {
                "_id": scope,
                "owner": owner,
                "token": token,
                "expires_at": {"$gt": renewed_at},
            },
            {"$set": {"expires_at": expires_at, "updated_at": renewed_at}},
            session=session,
        )
        return bool(getattr(result, "matched_count", 0))

    def release_worker_lease(
        self,
        scope: str,
        owner: str,
        token: str,
        *,
        now: Any = None,
    ) -> bool:
        _required_identity(scope, "scope")
        _required_identity(owner, "owner")
        _uuid_token(token, "token")
        _utc_timestamp(now)
        return self._run_fenced_transaction(
            lambda session: self._release_worker_lease_once(
                scope,
                owner,
                token,
                now=now,
                session=session,
            )
        )

    def _release_worker_lease_once(
        self,
        scope: str,
        owner: str,
        token: str,
        *,
        now: Any = None,
        session: Any = None,
    ) -> bool:
        scope = _required_identity(scope, "scope")
        owner = _required_identity(owner, "owner")
        token = _uuid_token(token, "token")
        released_at = _utc_timestamp(now)
        result = self.database["_storage_leases"].delete_one(
            {
                "_id": scope,
                "owner": owner,
                "token": token,
                "expires_at": {"$gt": released_at},
            },
            session=session,
        )
        return bool(getattr(result, "deleted_count", 0))

    def fetch_events(self, limit: int = 1000, processed: Optional[bool] = None) -> List[Dict[str, Any]]:
        query: Dict[str, Any] = {}
        if processed is not None:
            query["processed"] = {"$in": [bool(processed), int(bool(processed))]}
        cursor = self._collection("events").find(query).sort(
            [("received_at", ASCENDING), ("event_id", ASCENDING)]
        ).limit(max(int(limit), 0))
        output = []
        for raw in cursor:
            item = from_bson_safe(raw)
            payload = dict(item.get("payload") or {})
            output.append(
                {
                    "event_id": item["event_id"],
                    "sensor_id": item["sensor_id"],
                    "event": payload,
                    "payload_json": stable_json(payload),
                    "processed": bool(item.get("processed")),
                }
            )
        return output

    def mark_event_processed(self, event_id: str) -> None:
        self._collection("events").update_one(
            {"event_id": event_id},
            {
                "$set": {
                    "processed": True,
                    "processing_outcome": "succeeded",
                    "processed_at": utc_now(),
                    "effect_summary": None,
                    "schema_version": MONGODB_SCHEMA_VERSION,
                },
                "$unset": {
                    "claim_owner": "",
                    "claim_token": "",
                    "claim_expires_at": "",
                    "claimed_at": "",
                    "claim_leader_scope": "",
                    "claim_leader_token": "",
                    "next_retry_at": "",
                    "last_error_code": "",
                    "last_error_type": "",
                    "last_error_at": "",
                },
            },
        )

    def save_session(self, session_payload: Dict[str, Any]) -> None:
        payload = dict(session_payload)
        session_source = normalize_session_source(
            payload.get("session_source"),
            "unknown_legacy",
        )
        external = is_external_source_ip(payload.get("src_ip"))
        payload["session_source"] = session_source
        payload["is_external_source"] = external
        session_id = str(payload.get("session_id") or "unknown")
        self._replace(
            "sessions",
            {
                "_id": session_id,
                "session_id": session_id,
                "src_ip": payload.get("src_ip", "unknown"),
                "start_time": payload.get("start_time", ""),
                "ended": bool(payload.get("is_ended")),
                "session_source": session_source,
                "is_external_source": external,
                "payload": payload,
                "updated_at": utc_now(),
            },
        )

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        if not session_id:
            return None
        document = self._find("sessions", {"session_id": session_id})
        if not document:
            return None
        row = row_from_document("sessions", document)
        row["payload"] = dict(document.get("payload") or {})
        return row

    def update_session_analysis_status(
        self,
        session_id: str,
        status: str,
        *,
        report_id: str = "",
        error: str = "",
        skip_reason: str = "",
    ) -> None:
        if not session_id:
            return
        now = utc_now()
        set_values: Dict[str, Any] = {
            "payload.analysis_status": status,
            "payload.analysis_updated_at": now,
            "updated_at": now,
        }
        unset_values: Dict[str, Any] = {}
        if report_id:
            set_values["payload.report_id"] = report_id
        if error:
            set_values["payload.analysis_error"] = error
        else:
            unset_values["payload.analysis_error"] = ""
        if skip_reason:
            set_values["payload.analysis_skip_reason"] = skip_reason
        elif status != "skipped":
            unset_values["payload.analysis_skip_reason"] = ""
        # The keys here are intentional MongoDB dotted update paths.  Encode
        # their values, not the controlled path names themselves.
        update: Dict[str, Any] = {
            "$set": {key: to_bson_safe(value) for key, value in set_values.items()}
        }
        if unset_values:
            update["$unset"] = unset_values
        self._collection("sessions").update_one({"session_id": session_id}, update)

    def store_alert(self, alert_payload: Dict[str, Any]) -> str:
        alert_id = str(alert_payload.get("alert_id") or stable_id("alert", alert_payload))
        now = utc_now()
        self._insert_once(
            "alerts",
            {
                "_id": alert_id,
                "alert_id": alert_id,
                "session_id": alert_payload.get("session_id", "unknown"),
                "severity": alert_payload.get("severity", "UNKNOWN"),
                "reason": alert_payload.get("reason", ""),
                "payload": dict(alert_payload),
                "created_at": alert_payload.get("created_at", now),
                "delivered": False,
            },
        )
        return alert_id

    def enqueue_analysis_job(self, session_payload: Dict[str, Any]) -> str:
        job_id = stable_id("job", {"session_id": session_payload.get("session_id", "unknown")})
        now = utc_now()
        self._insert_once(
            "analysis_jobs",
            {
                "_id": job_id,
                "job_id": job_id,
                "session_id": session_payload.get("session_id", "unknown"),
                "status": "queued",
                "payload": dict(session_payload),
                "report_id": None,
                "error": None,
                "attempts": 0,
                "created_at": now,
                "updated_at": now,
            },
        )
        return job_id

    def claim_analysis_jobs(self, limit: int) -> List[Dict[str, Any]]:
        output = []
        for _ in range(max(int(limit), 0)):
            now = utc_now()
            raw = self._collection("analysis_jobs").find_one_and_update(
                {"status": {"$in": ["queued", "retry"]}},
                {"$set": {"status": "running", "updated_at": now}, "$inc": {"attempts": 1}},
                sort=[("created_at", ASCENDING), ("job_id", ASCENDING)],
                return_document=ReturnDocument.AFTER,
            )
            if raw is None:
                break
            item = from_bson_safe(raw)
            output.append(
                {
                    "job_id": item["job_id"],
                    "session_id": item["session_id"],
                    "session": dict(item.get("payload") or {}),
                    "attempts": int(item.get("attempts") or 0),
                }
            )
        return output

    def complete_analysis_job(self, job_id: str, report_payload: Dict[str, Any]) -> str:
        report_id = stable_id("report", {"job_id": job_id, "report": report_payload})
        now = utc_now()
        session_id = report_payload.get("session_id") or report_payload.get("data_provenance", {}).get(
            "session", {}
        ).get("session_id", "unknown")
        self._replace(
            "reports",
            {
                "_id": report_id,
                "report_id": report_id,
                "session_id": session_id,
                "payload": dict(report_payload),
                "created_at": now,
            },
        )
        self._collection("analysis_jobs").update_one(
            {"job_id": job_id},
            {"$set": {"status": "succeeded", "report_id": report_id, "error": None, "updated_at": now}},
        )
        self.update_session_analysis_status(str(session_id), "succeeded", report_id=report_id)
        return report_id

    def fail_analysis_job(self, job_id: str, error: str, retry: bool = False) -> None:
        status = "retry" if retry else "failed"
        raw = self._collection("analysis_jobs").find_one_and_update(
            {"job_id": job_id},
            {"$set": {"status": status, "error": error, "updated_at": utc_now()}},
            return_document=ReturnDocument.AFTER,
        )
        if raw:
            self.update_session_analysis_status(str(raw.get("session_id") or ""), status, error=error)

    def skip_analysis_job(self, job_id: str, reason: str) -> None:
        raw = self._collection("analysis_jobs").find_one_and_update(
            {"job_id": job_id},
            {"$set": {"status": "skipped", "error": reason, "updated_at": utc_now()}},
            return_document=ReturnDocument.AFTER,
        )
        if raw:
            self.update_session_analysis_status(
                str(raw.get("session_id") or ""),
                "skipped",
                skip_reason=reason,
            )

    def save_feed_status(self, status: Dict[str, Any]) -> None:
        now = utc_now()
        for name, payload in status.items():
            if name == "summary":
                continue
            self._replace(
                "feed_status",
                {"_id": str(name), "name": str(name), "payload": payload, "updated_at": now},
            )

    def get_enrichment_record(
        self,
        observable_type: str,
        observable_value: str,
        allow_stale: bool = True,
    ) -> Optional[Dict[str, Any]]:
        document = self._find(
            "enrichment_records",
            {"observable_type": observable_type, "observable_value": observable_value},
        )
        if not document:
            return None
        row = row_from_document("enrichment_records", document)
        row["payload"] = dict(document.get("payload") or {})
        row["provider_status"] = dict(document.get("provider_status") or {})
        row["is_stale"] = not _is_future(document.get("expires_at"))
        if row["is_stale"] and not allow_stale:
            return None
        return row

    def load_enrichment_cache(
        self,
        observable_type: str = "ip",
        allow_stale: bool = True,
    ) -> Dict[str, Dict[str, Any]]:
        cache: Dict[str, Dict[str, Any]] = {}
        for raw in self._collection("enrichment_records").find({"observable_type": observable_type}):
            item = from_bson_safe(raw)
            stale = not _is_future(item.get("expires_at"))
            if stale and not allow_stale:
                continue
            payload = dict(item.get("payload") or {})
            payload.setdefault(
                "enrichment_cache",
                {
                    "source": "storage",
                    "status": "stale" if stale else "fresh",
                    "expires_at": item.get("expires_at"),
                },
            )
            cache[str(item.get("observable_value") or "")] = payload
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
        key = stable_id(
            "enrichment",
            {"observable_type": observable_type, "observable_value": observable_value},
        )
        self._collection("enrichment_records").update_one(
            {"observable_type": observable_type, "observable_value": observable_value},
            {
                "$set": to_bson_safe(
                    {
                        "payload": payload,
                        "provider_status": provider_status,
                        "last_seen": now,
                        "expires_at": expires_at,
                        "updated_at": now,
                    }
                ),
                "$setOnInsert": {
                    "_id": key,
                    "observable_type": observable_type,
                    "observable_value": observable_value,
                    "first_seen": now,
                    "schema_version": MONGODB_SCHEMA_VERSION,
                },
            },
            upsert=True,
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
        rank = PRIORITY_RANK[priority]
        body = dict(payload or {})
        body.setdefault("observable_type", observable_type)
        body.setdefault("observable_value", observable_value)
        if session_id:
            body.setdefault("session_id", session_id)
        if priority != "normal":
            body.setdefault("priority", priority)
        if priority_reason:
            body.setdefault("priority_reason", priority_reason)
        collection = self._collection("enrichment_jobs")
        result = collection.update_one(
            {"observable_type": observable_type, "observable_value": observable_value},
            {
                "$setOnInsert": to_bson_safe(
                    {
                        "_id": job_id,
                        "job_id": job_id,
                        "observable_type": observable_type,
                        "observable_value": observable_value,
                        "session_id": session_id or None,
                        "status": "queued",
                        "priority": priority,
                        "priority_rank": rank,
                        "priority_reason": priority_reason or None,
                        "payload": body,
                        "attempts": 0,
                        "next_retry_at": None,
                        "error": None,
                        "created_at": now,
                        "updated_at": now,
                        "schema_version": MONGODB_SCHEMA_VERSION,
                    }
                )
            },
            upsert=True,
        )
        inserted = getattr(result, "upserted_id", None) is not None
        if not inserted:
            reset_values: Dict[str, Any] = {
                "payload": body,
                "next_retry_at": None,
                "error": None,
                "updated_at": now,
            }
            if session_id:
                reset_values["session_id"] = session_id
            collection.update_one(
                {
                    "observable_type": observable_type,
                    "observable_value": observable_value,
                    "status": {"$nin": ["queued", "running", "retry"]},
                },
                {"$set": {"status": "queued"}},
            )
            collection.update_one(
                {
                    "observable_type": observable_type,
                    "observable_value": observable_value,
                    "priority_rank": {"$lt": rank},
                },
                {
                    "$set": {
                        "priority": priority,
                        "priority_rank": rank,
                        "priority_reason": priority_reason or None,
                    }
                },
            )
            update_result = collection.update_one(
                {"observable_type": observable_type, "observable_value": observable_value},
                {"$set": to_bson_safe(reset_values)},
            )
            return job_id, bool(getattr(update_result, "matched_count", 0))
        return job_id, True

    def claim_enrichment_jobs(self, limit: int) -> List[Dict[str, Any]]:
        output = []
        for _ in range(max(int(limit), 0)):
            now = utc_now()
            raw = self._collection("enrichment_jobs").find_one_and_update(
                {
                    "status": {"$in": ["queued", "retry"]},
                    "$or": [
                        {"next_retry_at": None},
                        {"next_retry_at": {"$exists": False}},
                        {"next_retry_at": {"$lte": now}},
                    ],
                },
                {"$set": {"status": "running", "updated_at": now}, "$inc": {"attempts": 1}},
                sort=[
                    ("priority_rank", DESCENDING),
                    ("created_at", ASCENDING),
                    ("job_id", ASCENDING),
                ],
                return_document=ReturnDocument.AFTER,
            )
            if raw is None:
                break
            item = from_bson_safe(raw)
            output.append(
                {
                    "job_id": item["job_id"],
                    "observable_type": item["observable_type"],
                    "observable_value": item["observable_value"],
                    "session_id": item.get("session_id"),
                    "priority": item.get("priority", "normal"),
                    "priority_reason": item.get("priority_reason"),
                    "payload": dict(item.get("payload") or {}),
                    "attempts": int(item.get("attempts") or 0),
                }
            )
        return output

    def reprioritize_enrichment_jobs(
        self,
        observable_value: str,
        observable_type: str = "ip",
        priority: str = "urgent",
        reason: str = "",
        session_id: str = "",
    ) -> int:
        if not observable_value:
            return 0
        priority = _normalize_priority(priority)
        rank = PRIORITY_RANK[priority]
        values: Dict[str, Any] = {
            "priority": priority,
            "priority_rank": rank,
            "priority_reason": reason or None,
            "next_retry_at": None,
            "updated_at": utc_now(),
        }
        if session_id:
            values["session_id"] = session_id
        result = self._collection("enrichment_jobs").update_one(
            {
                "observable_type": observable_type,
                "observable_value": observable_value,
                "status": {"$in": ["queued", "retry"]},
                "priority_rank": {"$lt": rank},
            },
            {"$set": values},
        )
        if not getattr(result, "matched_count", 0):
            result = self._collection("enrichment_jobs").update_one(
                {
                    "observable_type": observable_type,
                    "observable_value": observable_value,
                    "status": {"$in": ["queued", "retry"]},
                },
                {
                    "$set": {
                        **({"session_id": session_id} if session_id else {}),
                        "next_retry_at": None,
                        "updated_at": utc_now(),
                    }
                },
            )
        return int(getattr(result, "matched_count", 0) or 0)

    def complete_enrichment_job(self, job_id: str) -> None:
        self._collection("enrichment_jobs").update_one(
            {"job_id": job_id},
            {
                "$set": {
                    "status": "succeeded",
                    "error": None,
                    "next_retry_at": None,
                    "updated_at": utc_now(),
                }
            },
        )

    def fail_enrichment_job(
        self,
        job_id: str,
        error: str,
        retry: bool = False,
        retry_seconds: float = 300.0,
    ) -> None:
        self._collection("enrichment_jobs").update_one(
            {"job_id": job_id},
            {
                "$set": {
                    "status": "retry" if retry else "failed",
                    "error": error,
                    "next_retry_at": _retry_at(retry_seconds) if retry else None,
                    "updated_at": utc_now(),
                }
            },
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
        sighting_id = str(
            sighting.get("sighting_id")
            or stable_id(
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
        )
        now = utc_now()
        payload = dict(sighting.get("payload") or {})
        payload.setdefault("observable_type", observable_type)
        payload.setdefault("observable_value", observable_value)
        payload.setdefault("role", role)
        payload.setdefault("source", source)
        inserted = self._insert_once(
            "observable_sightings",
            {
                "_id": sighting_id,
                "sighting_id": sighting_id,
                "observable_type": observable_type,
                "observable_value": observable_value,
                "session_id": session_id,
                "sensor_id": sighting.get("sensor_id", ""),
                "src_ip": sighting.get("src_ip", ""),
                "event_id": event_id,
                "eventid": sighting.get("eventid", ""),
                "role": role,
                "source": source,
                "timestamp": timestamp,
                "payload": payload,
                "created_at": now,
            },
        )
        if inserted:
            observable_id = stable_id(
                "observable",
                {"observable_type": observable_type, "observable_value": observable_value},
            )
            self._collection("observables").update_one(
                {"observable_type": observable_type, "observable_value": observable_value},
                {
                    "$set": to_bson_safe(
                        {
                            "payload": {"last_role": role, "last_source": source},
                        }
                    ),
                    "$setOnInsert": {
                        "_id": observable_id,
                        "observable_type": observable_type,
                        "observable_value": observable_value,
                        "first_seen": timestamp,
                        "schema_version": MONGODB_SCHEMA_VERSION,
                    },
                    "$max": {"last_seen": timestamp},
                    "$inc": {"sighting_count": 1},
                },
                upsert=True,
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
        collection = self._collection("threat_hunt_jobs")
        result = collection.update_one(
            {
                "session_id": session_id,
                "observable_type": observable_type,
                "observable_value": observable_value,
            },
            {
                "$setOnInsert": to_bson_safe(
                    {
                        "_id": job_id,
                        "job_id": job_id,
                        "session_id": session_id,
                        "observable_type": observable_type,
                        "observable_value": observable_value,
                        "trigger_reason": trigger_reason or None,
                        "status": "queued",
                        "result": None,
                        "payload": body,
                        "attempts": 0,
                        "error": None,
                        "created_at": now,
                        "updated_at": now,
                        "schema_version": MONGODB_SCHEMA_VERSION,
                    }
                )
            },
            upsert=True,
        )
        inserted = getattr(result, "upserted_id", None) is not None
        if not inserted:
            collection.update_one(
                {
                    "session_id": session_id,
                    "observable_type": observable_type,
                    "observable_value": observable_value,
                    "status": {"$nin": ["queued", "running", "retry"]},
                },
                {"$set": {"status": "queued"}},
            )
            collection.update_one(
                {
                    "session_id": session_id,
                    "observable_type": observable_type,
                    "observable_value": observable_value,
                },
                {
                    "$set": to_bson_safe(
                        {
                            "trigger_reason": trigger_reason or None,
                            "payload": body,
                            "error": None,
                            "updated_at": now,
                        }
                    )
                },
            )
        return job_id, inserted

    def claim_threat_hunt_jobs(self, limit: int) -> List[Dict[str, Any]]:
        output = []
        for _ in range(max(int(limit), 0)):
            raw = self._collection("threat_hunt_jobs").find_one_and_update(
                {"status": {"$in": ["queued", "retry"]}},
                {"$set": {"status": "running", "updated_at": utc_now()}, "$inc": {"attempts": 1}},
                sort=[("created_at", ASCENDING), ("job_id", ASCENDING)],
                return_document=ReturnDocument.AFTER,
            )
            if raw is None:
                break
            item = from_bson_safe(raw)
            item["payload"] = dict(item.get("payload") or {})
            item["result"] = dict(item.get("result") or {})
            output.append(dict(item))
        return output

    def complete_threat_hunt_job(self, job_id: str, result: Dict[str, Any]) -> None:
        self._collection("threat_hunt_jobs").update_one(
            {"job_id": job_id},
            {
                "$set": to_bson_safe(
                    {
                        "status": "succeeded",
                        "result": result,
                        "error": None,
                        "updated_at": utc_now(),
                    }
                )
            },
        )

    def fail_threat_hunt_job(self, job_id: str, error: str, retry: bool = False) -> None:
        self._collection("threat_hunt_jobs").update_one(
            {"job_id": job_id},
            {
                "$set": {
                    "status": "retry" if retry else "failed",
                    "error": error,
                    "updated_at": utc_now(),
                }
            },
        )

    def find_sessions_by_observable(
        self,
        observable_type: str,
        observable_value: str,
        exclude_session_id: str = "",
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        groups: Dict[str, Dict[str, Any]] = {}
        cursor = self._collection("observable_sightings").find(
            {
                "observable_type": observable_type,
                "observable_value": observable_value,
                "session_id": {"$ne": exclude_session_id},
            }
        )
        for raw in cursor:
            item = from_bson_safe(raw)
            session_id = str(item.get("session_id") or "unknown")
            seen = str(item.get("timestamp") or item.get("created_at") or "")
            group = groups.setdefault(
                session_id,
                {
                    "session_id": session_id,
                    "sighting_count": 0,
                    "first_seen": seen,
                    "last_seen": seen,
                    "roles": set(),
                    "sources": set(),
                },
            )
            group["sighting_count"] += 1
            group["first_seen"] = min(str(group["first_seen"]), seen)
            group["last_seen"] = max(str(group["last_seen"]), seen)
            group["roles"].add(str(item.get("role") or ""))
            group["sources"].add(str(item.get("source") or ""))
        ordered = sorted(groups.values(), key=lambda item: item["last_seen"], reverse=True)[: max(int(limit), 0)]
        output = []
        for group in ordered:
            session = self._find("sessions", {"session_id": group["session_id"]}) or {}
            output.append(
                {
                    **group,
                    "roles": sorted(value for value in group["roles"] if value),
                    "sources": sorted(value for value in group["sources"] if value),
                    "src_ip": session.get("src_ip"),
                    "ended": bool(session.get("ended")),
                    "updated_at": session.get("updated_at"),
                    "payload": dict(session.get("payload") or {}),
                }
            )
        return output

    def save_session_link(self, link_payload: Dict[str, Any]) -> str:
        a = str(link_payload.get("session_id_a") or "").strip()
        b = str(link_payload.get("session_id_b") or "").strip()
        if not a or not b:
            raise ValueError("session link requires session_id_a and session_id_b")
        observable_type = str(link_payload.get("observable_type") or "").strip().lower()
        observable_value = str(link_payload.get("observable_value") or "").strip()
        link_type = str(link_payload.get("link_type") or "shared_observable").strip()
        link_id = str(
            link_payload.get("link_id")
            or stable_id(
                "sessionlink",
                {
                    "sessions": sorted([a, b]),
                    "link_type": link_type,
                    "observable_type": observable_type,
                    "observable_value": observable_value,
                },
            )
        )
        payload = dict(link_payload)
        payload["link_id"] = link_id
        self._replace(
            "session_links",
            {
                "_id": link_id,
                "link_id": link_id,
                "session_id_a": a,
                "session_id_b": b,
                "link_type": link_type,
                "observable_type": observable_type or None,
                "observable_value": observable_value or None,
                "confidence": float(link_payload.get("confidence") or 0.0),
                "payload": payload,
                "created_at": link_payload.get("created_at") or utc_now(),
            },
        )
        return link_id

    def list_session_links(self, session_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        cursor = self._collection("session_links").find(
            {"$or": [{"session_id_a": session_id}, {"session_id_b": session_id}]}
        ).sort([("created_at", DESCENDING)]).limit(max(int(limit), 0))
        output = []
        for raw in cursor:
            item = from_bson_safe(raw)
            row = row_from_document("session_links", item)
            row["payload"] = dict(item.get("payload") or {})
            output.append(row)
        return output

    def save_campaign(self, campaign: Dict[str, Any]) -> str:
        campaign_id = str(campaign.get("campaign_id") or "").strip()
        if not campaign_id:
            raise ValueError("campaign_id is required")
        now = utc_now()
        first_seen = campaign.get("first_seen") or now
        last_seen = campaign.get("last_seen") or now
        values: Dict[str, Any] = {
            "primary_fingerprint_type": campaign.get("primary_fingerprint_type") or "",
            "primary_fingerprint_value": campaign.get("primary_fingerprint_value") or "",
            "session_count": int(campaign.get("session_count") or 0),
            "confirmed_tactics": list(campaign.get("confirmed_tactics") or []),
            "max_confirmed_severity": campaign.get("max_confirmed_severity") or "info",
            "payload": dict(campaign),
            "updated_at": now,
        }
        for key in (
            "hassh_fingerprint",
            "ja3_fingerprint",
            "tactic_sequence_hash",
            "command_pattern_hash",
            "source_ip",
        ):
            if str(campaign.get(key) or "").strip():
                values[key] = campaign[key]
        self._collection("campaigns").update_one(
            {"campaign_id": campaign_id},
            {
                "$set": to_bson_safe(values),
                "$setOnInsert": {
                    "_id": campaign_id,
                    "campaign_id": campaign_id,
                    "created_at": campaign.get("created_at") or now,
                    "schema_version": MONGODB_SCHEMA_VERSION,
                },
                "$min": {"first_seen": first_seen},
                "$max": {"last_seen": last_seen},
            },
            upsert=True,
        )
        return campaign_id

    def get_campaign(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        if not campaign_id:
            return None
        document = self._find("campaigns", {"campaign_id": campaign_id})
        if not document:
            return None
        row = row_from_document("campaigns", document)
        row["payload"] = dict(document.get("payload") or {})
        row["confirmed_tactics"] = list(document.get("confirmed_tactics") or [])
        return row

    def find_matching_campaigns(
        self,
        fingerprint: Dict[str, Any],
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        fields = (
            ("hassh_fingerprint", fingerprint.get("hassh_fingerprint")),
            ("ja3_fingerprint", fingerprint.get("ja3_fingerprint")),
            ("command_pattern_hash", fingerprint.get("command_pattern_hash")),
            ("tactic_sequence_hash", fingerprint.get("tactic_sequence_hash")),
            ("source_ip", fingerprint.get("src_ip")),
        )
        conditions = [
            {field: str(value).strip()}
            for field, value in fields
            if str(value or "").strip() and str(value).strip().lower() != "unknown"
        ]
        if not conditions:
            return []
        cursor = self._collection("campaigns").find({"$or": conditions}).sort(
            [("updated_at", DESCENDING)]
        ).limit(max(int(limit), 0))
        output = []
        for raw in cursor:
            item = from_bson_safe(raw)
            row = row_from_document("campaigns", item)
            row["payload"] = dict(item.get("payload") or {})
            row["confirmed_tactics"] = list(item.get("confirmed_tactics") or [])
            output.append(row)
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
        result = self._collection("campaign_sessions").update_one(
            {"campaign_id": campaign_id, "session_id": session_id},
            {
                "$set": to_bson_safe(
                    {
                        "match_reasons": list(match_reasons or []),
                        "confidence": float(confidence or 0.0),
                        "payload": body,
                    }
                ),
                "$setOnInsert": {
                    "_id": link_id,
                    "link_id": link_id,
                    "campaign_id": campaign_id,
                    "session_id": session_id,
                    "created_at": now,
                    "schema_version": MONGODB_SCHEMA_VERSION,
                },
            },
            upsert=True,
        )
        return link_id, getattr(result, "upserted_id", None) is not None

    def count_campaign_sessions(self, campaign_id: str) -> int:
        return int(self._collection("campaign_sessions").count_documents({"campaign_id": campaign_id}))

    def list_campaign_sessions(self, campaign_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        cursor = self._collection("campaign_sessions").find({"campaign_id": campaign_id}).sort(
            [("created_at", DESCENDING)]
        ).limit(max(int(limit), 0))
        output = []
        for raw in cursor:
            item = from_bson_safe(raw)
            row = row_from_document("campaign_sessions", item)
            row["payload"] = dict(item.get("payload") or {})
            row["match_reasons"] = list(item.get("match_reasons") or [])
            output.append(row)
        return output

    def list_session_campaigns(self, session_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        cursor = self._collection("campaign_sessions").find({"session_id": session_id}).sort(
            [("created_at", DESCENDING)]
        ).limit(max(int(limit), 0))
        output = []
        for raw in cursor:
            item = from_bson_safe(raw)
            row = row_from_document("campaign_sessions", item)
            campaign = self._find("campaigns", {"campaign_id": item.get("campaign_id")}) or {}
            row["payload"] = dict(item.get("payload") or {})
            row["match_reasons"] = list(item.get("match_reasons") or [])
            row["campaign_payload"] = dict(campaign.get("payload") or {})
            row["campaign_payload_json"] = stable_json(row["campaign_payload"])
            row["max_confirmed_severity"] = campaign.get("max_confirmed_severity")
            row["session_count"] = campaign.get("session_count")
            output.append(row)
        return output

    def save_prediction_snapshot(self, snapshot: Dict[str, Any]) -> str:
        snapshot_id = str(snapshot.get("snapshot_id") or stable_id("predsnap", snapshot))
        self._replace(
            "prediction_snapshots",
            {
                "_id": snapshot_id,
                "snapshot_id": snapshot_id,
                "session_id": snapshot.get("session_id", "unknown"),
                "src_ip": snapshot.get("src_ip", "unknown"),
                "session_status": snapshot.get("session_status", "active"),
                "event_id": snapshot.get("event_id", ""),
                "features_hash": snapshot.get("features_hash", ""),
                "payload": dict(snapshot),
                "created_at": snapshot.get("generated_at") or utc_now(),
            },
        )
        return snapshot_id

    def get_latest_prediction_snapshot(self, session_id: str) -> Optional[Dict[str, Any]]:
        raw = self._collection("prediction_snapshots").find_one(
            {"session_id": session_id},
            sort=[("created_at", DESCENDING)],
        )
        if raw is None:
            return None
        item = from_bson_safe(raw)
        row = row_from_document("prediction_snapshots", item)
        row["payload"] = dict(item.get("payload") or {})
        return row

    def get_prediction_snapshot(self, snapshot_id: str) -> Optional[Dict[str, Any]]:
        if not snapshot_id:
            return None
        item = self._find("prediction_snapshots", {"snapshot_id": snapshot_id})
        if not item:
            return None
        row = row_from_document("prediction_snapshots", item)
        row["payload"] = dict(item.get("payload") or {})
        return row

    def prune_prediction_snapshots(
        self,
        retention_days: int = 90,
        keep_latest_per_session: bool = True,
        now: Optional[str] = None,
    ) -> Dict[str, Any]:
        retention_days = max(int(retention_days), 0)
        reference = _parse_dt(now) or datetime.now(timezone.utc)
        cutoff = (reference - timedelta(days=retention_days)).isoformat()
        collection = self._collection("prediction_snapshots")
        total_before = int(collection.count_documents({}))
        protected = {
            str(item.get("snapshot_id"))
            for item in self._collection("analyst_feedback").find(
                {"snapshot_id": {"$nin": [None, ""]}}
            )
            if item.get("snapshot_id")
        }
        seen_sessions: set[str] = set()
        if keep_latest_per_session:
            for raw in collection.find({}).sort(
                [("session_id", ASCENDING), ("created_at", DESCENDING)]
            ):
                session_id = str(raw.get("session_id") or "")
                snapshot_id = str(raw.get("snapshot_id") or "")
                if session_id not in seen_sessions:
                    seen_sessions.add(session_id)
                    protected.add(snapshot_id)
        delete_ids = [
            raw["_id"]
            for raw in collection.find({"created_at": {"$lt": cutoff}})
            if str(raw.get("snapshot_id") or "") not in protected
        ]
        result = collection.delete_many({"_id": {"$in": delete_ids}}) if delete_ids else None
        deleted = int(getattr(result, "deleted_count", 0) if result is not None else 0)
        total_after = int(collection.count_documents({}))
        return {
            "retention_days": retention_days,
            "cutoff": cutoff,
            "keep_latest_per_session": bool(keep_latest_per_session),
            "deleted": deleted,
            "before": total_before,
            "after": total_after,
        }

    def save_prediction_backtest_run(self, result: Dict[str, Any]) -> str:
        run_id = str(result.get("run_id") or stable_id("predbacktest", result))
        payload = dict(result)
        payload["run_id"] = run_id
        self._replace(
            "prediction_backtest_runs",
            {
                "_id": run_id,
                "run_id": run_id,
                "payload": payload,
                "created_at": result.get("generated_at") or utc_now(),
            },
        )
        return run_id

    def save_prediction_calibration_run(self, result: Dict[str, Any]) -> str:
        run_id = str(result.get("run_id") or stable_id("predcalibration", result))
        payload = dict(result)
        payload["run_id"] = run_id
        self._replace(
            "prediction_calibration_runs",
            {
                "_id": run_id,
                "run_id": run_id,
                "status": str(payload.get("status") or "unknown"),
                "applied": bool(payload.get("applied") or payload.get("apply")),
                "payload": payload,
                "created_at": result.get("generated_at") or utc_now(),
            },
        )
        return run_id

    def record_analyst_feedback(self, feedback: Dict[str, Any]) -> str:
        payload = normalize_feedback_payload(feedback)
        payload.setdefault("created_at", utc_now())
        payload["session_id"] = str(payload.get("session_id") or "").strip()
        payload["label"] = str(payload.get("label") or "").strip()
        payload["tactic_granularity"] = (
            str(payload.get("tactic_granularity") or "tactic").strip() or "tactic"
        )
        for key in ("observed_prefix", "predicted_ranking"):
            if isinstance(payload.get(key), (dict, list)):
                payload[key] = stable_json(payload[key])
        if not payload["session_id"]:
            raise ValueError("session_id is required")
        if not payload["label"]:
            raise ValueError("label is required")
        feedback_id = str(payload.get("feedback_id") or stable_id("feedback", payload))
        payload["feedback_id"] = feedback_id
        document = {
            "_id": feedback_id,
            "feedback_id": feedback_id,
            "session_id": payload["session_id"],
            "snapshot_id": payload.get("snapshot_id") or None,
            "label": payload["label"],
            "feedback_type": payload.get("feedback_type") or "operator_usefulness",
            "operator_signal": payload.get("operator_signal") or None,
            "action_status": payload.get("action_status") or None,
            "label_authority": payload.get("label_authority") or None,
            "evidence_confidence": (
                payload.get("evidence_confidence")
                if payload.get("evidence_confidence") not in ("", None)
                else None
            ),
            "evidence_origin": payload.get("evidence_origin") or "live_cowrie",
            "weight_eligible": bool(payload.get("weight_eligible")),
            "correct_next_tactic": payload.get("correct_next_tactic") or None,
            "observed_prefix": payload.get("observed_prefix") or None,
            "predicted_top_tactic": payload.get("predicted_top_tactic") or None,
            "predicted_ranking": payload.get("predicted_ranking") or None,
            "final_actual_next_tactic": payload.get("final_actual_next_tactic") or None,
            "tactic_granularity": payload.get("tactic_granularity") or "tactic",
            "analyst_corrected_at": payload.get("analyst_corrected_at") or None,
            "notes": payload.get("notes") or None,
            "payload": payload,
            "created_at": payload["created_at"],
        }
        self._replace("analyst_feedback", document)
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
        self._replace(
            "classification_review_labels",
            {
                "_id": payload["label_id"],
                "label_id": payload["label_id"],
                "review_id": payload["review_id"],
                "session_id": payload["session_id"],
                "command_index": int(payload.get("command_index") or 0),
                "command": payload["command"],
                "predicted_ttp": payload.get("predicted_ttp") or None,
                "predicted_tactic": payload.get("predicted_tactic") or None,
                "predicted_source": payload.get("predicted_source") or None,
                "predicted_confidence": (
                    payload.get("predicted_confidence")
                    if payload.get("predicted_confidence") not in ("", None)
                    else None
                ),
                "reviewed_ttp": payload.get("reviewed_ttp") or payload.get("correct_ttp") or None,
                "reviewed_tactic": payload.get("reviewed_tactic") or payload.get("correct_tactic") or None,
                "reviewer": payload.get("reviewer") or None,
                "notes": payload.get("notes") or None,
                "payload": payload,
                "created_at": payload["created_at"],
            },
        )
        return payload["label_id"]

    def list_classification_review_labels(self, limit: int = 1000) -> List[Dict[str, Any]]:
        cursor = self._collection("classification_review_labels").find({}).sort(
            [("created_at", DESCENDING)]
        ).limit(max(int(limit), 0))
        output = []
        for raw in cursor:
            item = from_bson_safe(raw)
            row = row_from_document("classification_review_labels", item)
            row["payload"] = dict(item.get("payload") or {})
            output.append(row)
        return output

    def list_rows(self, table: str, limit: int = 100) -> List[Dict[str, Any]]:
        if table not in ALLOWED_TABLES:
            raise ValueError(f"unsupported table: {table}")
        order = TABLE_ORDER_FIELDS[table]
        cursor = self._collection(table).find({}).sort(
            [(order, DESCENDING), ("_id", DESCENDING)]
        ).limit(max(int(limit), 0))
        return [row_from_document(table, raw) for raw in cursor]

    def list_rows_for_session(
        self,
        table: str,
        session_id: str,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        if table not in SESSION_SCOPED_TABLES:
            raise ValueError(f"unsupported session-scoped table: {table}")
        order = TABLE_ORDER_FIELDS[table]
        cursor = self._collection(table).find({"session_id": session_id}).sort(
            [(order, DESCENDING), ("_id", DESCENDING)]
        ).limit(max(int(limit), 0))
        return [row_from_document(table, raw) for raw in cursor]

    def list_session_rows(
        self,
        limit: int = 100,
        session_source: str | None = SESSION_SOURCE_PRODUCTION_LIVE,
        external_only: bool = False,
    ) -> List[Dict[str, Any]]:
        query: Dict[str, Any] = {}
        source = normalize_session_source(session_source, "") if session_source else ""
        if source:
            query["session_source"] = source
        if external_only:
            query["is_external_source"] = True
        cursor = self._collection("sessions").find(query).sort(
            [("updated_at", DESCENDING)]
        ).limit(max(int(limit), 0))
        return [row_from_document("sessions", raw) for raw in cursor]

    def list_active_session_rows(
        self,
        limit: int = 10_000,
        session_source: str | None = SESSION_SOURCE_PRODUCTION_LIVE,
    ) -> List[Dict[str, Any]]:
        row_limit = max(int(limit), 0)
        if row_limit == 0:
            return []
        query: Dict[str, Any] = {"ended": False}
        source = normalize_session_source(session_source, "") if session_source else ""
        if source:
            query["session_source"] = source
        cursor = self._collection("sessions").find(query).sort(
            [("updated_at", ASCENDING), ("session_id", ASCENDING)]
        ).limit(row_limit)
        return [row_from_document("sessions", raw) for raw in cursor]

    def count_sessions(
        self,
        session_source: str | None = SESSION_SOURCE_PRODUCTION_LIVE,
        external_only: bool = False,
        ended_only: bool = False,
    ) -> int:
        query: Dict[str, Any] = {}
        source = normalize_session_source(session_source, "") if session_source else ""
        if source:
            query["session_source"] = source
        if external_only:
            query["is_external_source"] = True
        if ended_only:
            query["ended"] = True
        return int(self._collection("sessions").count_documents(query))

    def pending_webhooks(self, limit: int = 100) -> List[Dict[str, Any]]:
        cursor = self._collection("alerts").find({"delivered": False}).sort(
            [("created_at", ASCENDING)]
        ).limit(max(int(limit), 0))
        return [
            {
                "alert_id": item["alert_id"],
                "payload": dict(from_bson_safe(item).get("payload") or {}),
            }
            for item in cursor
        ]

    def get_webhook_delivery(self, delivery_id: str) -> Optional[Dict[str, Any]]:
        document = self._find("webhook_deliveries", {"delivery_id": delivery_id})
        return row_from_document("webhook_deliveries", document) if document else None

    def record_webhook_delivery(
        self,
        payload: Dict[str, Any],
        target_url_hash: str,
        status: str,
        error: str = "",
        alert_id: Optional[str] = None,
        report_id: Optional[str] = None,
    ) -> str:
        delivery_key: Dict[str, Any] = {
            "alert_id": alert_id,
            "report_id": report_id,
            "target": target_url_hash,
        }
        if not alert_id and not report_id:
            delivery_key["payload"] = payload
        delivery_id = stable_id("delivery", delivery_key)
        now = utc_now()
        self._collection("webhook_deliveries").update_one(
            {"delivery_id": delivery_id},
            {
                "$set": to_bson_safe(
                    {
                        "alert_id": alert_id,
                        "report_id": report_id,
                        "target_url_hash": target_url_hash,
                        "status": status,
                        "last_error": error,
                        "payload": payload,
                        "updated_at": now,
                    }
                ),
                "$setOnInsert": {
                    "_id": delivery_id,
                    "delivery_id": delivery_id,
                    "created_at": now,
                    "schema_version": MONGODB_SCHEMA_VERSION,
                },
                "$inc": {"attempts": 1},
            },
            upsert=True,
        )
        if alert_id and status in {"succeeded", "delivered"}:
            self._collection("alerts").update_one(
                {"alert_id": alert_id},
                {"$set": {"delivered": True}},
            )
        return delivery_id

    # Migration-facing helpers intentionally remain small and deterministic.
    def upsert_migrated_row(self, table: str, row: Mapping[str, Any]) -> Dict[str, str]:
        document = document_from_sqlite_row(table, row)
        collection = self._collection(table)
        existing = collection.find_one({"_id": document["_id"]})
        if existing is None:
            collection.replace_one({"_id": document["_id"]}, document, upsert=True)
            outcome = "inserted"
        elif stable_json(from_bson_safe(existing)) == stable_json(from_bson_safe(document)):
            outcome = "skipped"
        else:
            collection.replace_one({"_id": document["_id"]}, document, upsert=True)
            outcome = "updated"
        return {"id": str(document["_id"]), "outcome": outcome}

    def count_collection(self, table: str) -> int:
        return int(self._collection(table).count_documents({}))

    def get_migrated_row(self, table: str, row: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        expected = document_from_sqlite_row(table, row)
        found = self._collection(table).find_one({"_id": expected["_id"]})
        return row_from_document(table, found) if found else None


# Compatibility spelling retained for code and documentation that explicitly
# use "MongoDB" in the adapter name.
MongoDBStorage = MongoStorage


__all__ = [
    "ALLOWED_TABLES",
    "INDEX_DEFINITIONS",
    "JSON_FIELDS",
    "MONGODB_DRIVER_AVAILABLE",
    "MONGODB_SCHEMA_VERSION",
    "MongoDBStorage",
    "MongoStorage",
    "SESSION_SCOPED_TABLES",
    "STORAGE_LEASE_INDEX_DEFINITIONS",
    "document_from_sqlite_row",
    "from_bson_safe",
    "mongodb_dependency_diagnostic",
    "row_from_document",
    "to_bson_safe",
]
