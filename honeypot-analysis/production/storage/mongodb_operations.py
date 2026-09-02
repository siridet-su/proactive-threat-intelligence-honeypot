"""MongoDB implementations of the canonical runtime storage contract.

The mixin keeps the adapter itself small while making the operational contract
reviewable by domain.  It never installs collections or indexes: schema
administration is deliberately separated from the runtime identity.
"""

from __future__ import annotations

import hashlib
import json
import math
import uuid
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

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
from production.storage.backend import StorageError
from production.storage.job_materialization import (
    materialize_ai_advisory_job_claim,
    materialize_analysis_job_claim,
)
from production.storage.contract import (
    JOB_QUEUE_TABLES,
    SESSION_ANALYSIS_FIELDS,
    validate_event_effect_summary,
    validate_event_failure_fields,
    validate_job_failure_fields,
    validate_webhook_completion_fields,
)
from production.storage.session_provenance import (
    SESSION_SOURCE_PRODUCTION_LIVE,
    is_external_source_ip,
    normalize_session_source,
)
from production.utils.feedback import normalize_feedback_payload
from production.utils.sensitive_data import redact_error_for_log
from production.utils.serialization import stable_id, stable_json, utc_now


QUEUE_COLLECTIONS = dict(JOB_QUEUE_TABLES)
QUEUE_COLLECTIONS["prediction"] = "prediction_outbox"
_PRIORITY_RANK = {"low": 0, "normal": 1, "high": 2, "urgent": 3}
_SESSION_TABLES = {
    "sessions",
    "events",
    "reports",
    "alerts",
    "analysis_jobs",
    "prediction_snapshots",
    "prediction_outbox",
    "enrichment_jobs",
    "threat_hunt_jobs",
    "observable_sightings",
    "session_links",
    "campaign_sessions",
    "analyst_feedback",
    "classification_review_labels",
    "ai_advisory_outbox",
    "ai_advisories",
}

# Dashboard detail reads are deliberately projected to the durable identity,
# ordering, state, and payload fields needed by the public monitor projection.
# Keeping this allowlist here prevents a session detail request from becoming
# an arbitrary collection/document read while still preserving the existing
# legacy callers of list_rows_for_session.
_SESSION_DETAIL_PROJECTION = {
    "_id": 1,
    "schema_version": 1,
    "session_id": 1,
    "event_id": 1,
    "eventid": 1,
    "sensor_id": 1,
    "sensor": 1,
    "src_ip": 1,
    "timestamp": 1,
    "received_at": 1,
    "start_time": 1,
    "updated_at": 1,
    "created_at": 1,
    "ended": 1,
    "is_ended": 1,
    "session_source": 1,
    "is_external_source": 1,
    "revision": 1,
    "status": 1,
    "error": 1,
    "report_id": 1,
    "assessment_id": 1,
    "job_id": 1,
    "alert_id": 1,
    "snapshot_id": 1,
    "features_hash": 1,
    "processed": 1,
    "command_event": 1,
    "severity": 1,
    "reason": 1,
    "observable_type": 1,
    "observable_value": 1,
    "sighting_id": 1,
    "link_id": 1,
    "campaign_id": 1,
    "priority": 1,
    "delivered": 1,
    "expires_at": 1,
    "next_retry_at": 1,
    "payload_json": 1,
    "result_json": 1,
    "provider_status_json": 1,
    "confirmed_tactics_json": 1,
    "match_reasons_json": 1,
}

_SESSION_DETAIL_MONGO_SORTS = {
    "events": [("received_at", 1), ("event_id", 1)],
    "analysis_jobs": [("updated_at", -1), ("job_id", 1)],
    "reports": [("created_at", -1), ("report_id", 1)],
}

_SESSION_DETAIL_PREDICTION_SCAN_LIMIT = 500


def _utc(value: Any = None) -> str:
    if value is None:
        parsed = datetime.now(timezone.utc)
    elif isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("timestamp must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat()


def _future(value: str, seconds: float, field: str = "lease_seconds") -> str:
    try:
        duration = float(seconds)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be numeric") from exc
    if not math.isfinite(duration) or duration <= 0:
        raise ValueError(f"{field} must be positive")
    return (
        datetime.fromisoformat(value) + timedelta(seconds=duration)
    ).isoformat()


def _retry_at(value: str, seconds: float) -> str:
    try:
        duration = float(seconds)
    except (TypeError, ValueError) as exc:
        raise ValueError("retry_delay_seconds must be numeric") from exc
    if not math.isfinite(duration) or duration < 0:
        raise ValueError("retry_delay_seconds must be non-negative")
    return (
        datetime.fromisoformat(value) + timedelta(seconds=duration)
    ).isoformat()


def _required(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field} must be non-empty")
    return text


def _token(value: Any, field: str = "token") -> str:
    text = _required(value, field)
    try:
        return str(uuid.UUID(text))
    except ValueError as exc:
        raise ValueError(f"{field} must be a UUID") from exc


def _payload(document: Mapping[str, Any], field: str = "payload_json") -> Dict[str, Any]:
    try:
        value = json.loads(str(document.get(field) or "{}"))
    except (TypeError, json.JSONDecodeError) as exc:
        raise StorageError(f"{field} is malformed") from exc
    if not isinstance(value, dict):
        raise StorageError(f"{field} must contain an object")
    return value


def _row(document: Optional[Mapping[str, Any]]) -> Optional[Dict[str, Any]]:
    if document is None:
        return None
    return {key: value for key, value in document.items() if key != "_id"}


def _analysis_payload(
    payload: Mapping[str, Any],
    status: str,
    now: str,
    *,
    job_id: str = "",
    report_id: str = "",
    error: str = "",
    skip_reason: str = "",
) -> Dict[str, Any]:
    result = dict(payload)
    result["analysis_status"] = status
    result["analysis_updated_at"] = now
    values = {
        "analysis_job_id": job_id,
        "report_id": report_id,
        "analysis_error": error,
        "analysis_skip_reason": skip_reason,
    }
    for key, value in values.items():
        if value:
            result[key] = value
        elif key in result:
            result.pop(key, None)
    return result


class MongoDBRuntimeOperations:
    """Complete document implementation for the formal runtime operations."""

    database: Any

    @staticmethod
    def _return_document_after() -> Any:
        from pymongo import ReturnDocument

        return ReturnDocument.AFTER

    def _transaction(self, callback: Any) -> Any:
        """Run a retry-safe callback in one majority transaction."""

        with self.client.start_session() as session:
            return session.with_transaction(callback)

    def _exact_insert(
        self,
        collection: str,
        identity: str,
        document: Dict[str, Any],
        *,
        compare: tuple[str, ...],
        session: Any = None,
    ) -> bool:
        from pymongo.errors import DuplicateKeyError

        try:
            self.database[collection].insert_one(document, session=session)
            return True
        except DuplicateKeyError:
            existing = self.database[collection].find_one(
                {"_id": identity}, session=session
            )
            if not existing or any(existing.get(key) != document.get(key) for key in compare):
                raise StorageError(f"conflicting duplicate {collection} identity")
            return False

    def _leader_matches(
        self,
        scope: str,
        owner: str,
        token: str,
        required_until: str,
    ) -> bool:
        if not scope and not token:
            return True
        if not scope or not token:
            raise ValueError("leader_scope and leader_token must be supplied together")
        return self.database.worker_leases.count_documents(
            {
                "_id": _required(scope, "leader_scope"),
                "owner": _required(owner, "owner"),
                "token": _token(token, "leader_token"),
                "expires_at": {"$gte": required_until},
            },
            limit=1,
        ) == 1

    @staticmethod
    def _claimable_event_match(current: str, attempt_limit: int) -> Dict[str, Any]:
        return {
            "processed": False,
            "attempts": {"$lt": attempt_limit},
            "$and": [
                {
                    "$or": [
                        {"next_retry_at": None},
                        {"next_retry_at": {"$lte": current}},
                    ]
                },
                {
                    "$or": [
                        {"claim_token": None},
                        {"claim_expires_at": None},
                        {"claim_expires_at": {"$lte": current}},
                    ]
                },
            ],
        }

    def _head_event_ids(
        self,
        match: Dict[str, Any],
        *,
        limit: Optional[int] = None,
    ) -> List[str]:
        """Return deterministic session heads satisfying ``match``.

        The first reduction deliberately considers every unprocessed event,
        including one that is delayed or currently leased.  Grouping the
        earliest row for each session before applying ``match`` is equivalent
        to SQLite's correlated ``NOT EXISTS`` head-of-line guard, while
        avoiding a correlated self lookup over the complete claimable
        backlog.  The subsequent update remains a compare-and-set operation,
        so two workers may observe a candidate but only one can claim it.
        """

        pipeline: List[Dict[str, Any]] = [
            {"$match": {"processed": False}},
            {
                "$sort": {
                    "session_id": 1,
                    "received_at": 1,
                    "event_id": 1,
                }
            },
            {
                "$group": {
                    "_id": "$session_id",
                    "head": {"$first": "$$ROOT"},
                }
            },
            {"$replaceRoot": {"newRoot": "$head"}},
            {"$match": match},
            {"$sort": {"received_at": 1, "event_id": 1}},
            {"$project": {"_id": 1}},
        ]
        if limit is not None:
            pipeline.append({"$limit": max(0, int(limit))})
        return [str(item["_id"]) for item in self.database.events.aggregate(pipeline)]

    # Event queue ---------------------------------------------------------

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
        current = _utc(now)
        claim_owner = _required(owner, "owner")
        attempt_limit = int(max_attempts)
        if attempt_limit < 1:
            raise ValueError("max_attempts must be positive")
        expires = _future(current, lease_seconds)
        if not self._leader_matches(
            leader_scope, claim_owner, leader_token, expires
        ):
            return []

        exhausted_match = {
            "processed": False,
            "attempts": {"$gte": attempt_limit},
            "$and": [
                {
                    "$or": [
                        {"next_retry_at": None},
                        {"next_retry_at": {"$lte": current}},
                    ]
                },
                {
                    "$or": [
                        {"claim_token": None},
                        {"claim_expires_at": None},
                        {"claim_expires_at": {"$lte": current}},
                    ]
                },
            ],
        }
        for event_id in self._head_event_ids(exhausted_match):
            self.database.events.update_one(
                {"_id": event_id, **exhausted_match},
                {
                    "$set": {
                        "processed": True,
                        "processing_outcome": "dead_letter",
                        "last_error_code": "event_lease_attempts_exhausted",
                        "last_error_type": "LeaseExpired",
                        "last_error_at": current,
                        "processed_at": current,
                        "updated_at": current,
                    },
                    "$unset": {
                        "claim_owner": "",
                        "claim_token": "",
                        "claim_leader_scope": "",
                        "claim_leader_token": "",
                        "claim_expires_at": "",
                        "next_retry_at": "",
                    },
                },
            )

        claimed: List[Dict[str, Any]] = []
        invalid_budget = 1_000
        claim_limit = max(0, int(limit))
        while len(claimed) < claim_limit and invalid_budget > 0:
            candidates = self._head_event_ids(
                self._claimable_event_match(current, attempt_limit),
                limit=claim_limit - len(claimed),
            )
            if not candidates:
                break
            progressed = False
            for event_id in candidates:
                if len(claimed) >= claim_limit:
                    break
                token = str(uuid.uuid4())
                document = self.database.events.find_one_and_update(
                    {
                        "_id": event_id,
                        **self._claimable_event_match(current, attempt_limit),
                    },
                    {
                        "$set": {
                            "claim_owner": claim_owner,
                            "claim_token": token,
                            "claim_expires_at": expires,
                            "claim_leader_scope": leader_scope or None,
                            "claim_leader_token": leader_token or None,
                            "updated_at": current,
                        },
                        "$unset": {
                            "processing_outcome": "",
                            "effect_summary_json": "",
                        },
                        "$inc": {"attempts": 1},
                    },
                    return_document=self._return_document_after(),
                )
                if document is None:
                    continue
                progressed = True
                try:
                    item = self._event_result(document)
                except StorageError:
                    self.database.events.update_one(
                        {
                            "_id": event_id,
                            "processed": False,
                            "claim_owner": claim_owner,
                            "claim_token": token,
                        },
                        {
                            "$set": {
                                "processed": True,
                                "processing_outcome": "dead_letter",
                                "processed_at": current,
                                "last_error_code": "event_processing_invalid",
                                "last_error_type": "ValidationError",
                                "last_error_at": current,
                                "updated_at": current,
                            },
                            "$unset": {
                                "claim_owner": "",
                                "claim_token": "",
                                "claim_leader_scope": "",
                                "claim_leader_token": "",
                                "claim_expires_at": "",
                                "next_retry_at": "",
                                "effect_summary_json": "",
                            },
                        },
                    )
                    invalid_budget -= 1
                    continue
                item.update(
                    {
                        key: document.get(key)
                        for key in (
                            "attempts",
                            "claim_owner",
                            "claim_token",
                            "claim_expires_at",
                            "claim_leader_scope",
                            "claim_leader_token",
                        )
                    }
                )
                claimed.append(item)
            if not progressed:
                break
        return claimed

    def renew_event_claim(self, event_id: str, owner: str, token: str, lease_seconds: float, *, now: Any = None, leader_scope: str = "", leader_token: str = "") -> bool:
        current = _utc(now)
        expires = _future(current, lease_seconds)
        if not self._leader_matches(leader_scope, owner, leader_token, expires):
            return False
        result = self.database.events.update_one(
            {"_id": _required(event_id, "event_id"), "processed": False, "claim_owner": _required(owner, "owner"), "claim_token": _token(token), "claim_expires_at": {"$gt": current}, "claim_leader_scope": leader_scope or None, "claim_leader_token": leader_token or None},
            {"$set": {"claim_expires_at": expires, "updated_at": current}},
        )
        return result.modified_count == 1

    def complete_event(self, event_id: str, owner: str, token: str, effect_summary: Optional[Dict[str, Any]] = None, *, now: Any = None, leader_scope: str = "", leader_token: str = "") -> bool:
        current = _utc(now)
        if not self._leader_matches(leader_scope, owner, leader_token, current):
            return False
        summary = validate_event_effect_summary(effect_summary)
        result = self.database.events.update_one(
            {"_id": _required(event_id, "event_id"), "processed": False, "claim_owner": _required(owner, "owner"), "claim_token": _token(token), "claim_expires_at": {"$gt": current}, "claim_leader_scope": leader_scope or None, "claim_leader_token": leader_token or None},
            {"$set": {"processed": True, "processing_outcome": "succeeded", "processed_at": current, "effect_summary_json": stable_json(summary) if summary is not None else None, "updated_at": current}, "$unset": {"claim_owner": "", "claim_token": "", "claim_leader_scope": "", "claim_leader_token": "", "claim_expires_at": "", "next_retry_at": "", "last_error_code": "", "last_error_type": "", "last_error_at": ""}},
        )
        return result.modified_count == 1

    def fail_event(self, event_id: str, owner: str, token: str, error_code: str, error_type: str, retryable: bool, max_attempts: int, retry_delay_seconds: float, *, now: Any = None, leader_scope: str = "", leader_token: str = "") -> str:
        code, kind = validate_event_failure_fields(error_code, error_type)
        current = _utc(now)
        if not self._leader_matches(leader_scope, owner, leader_token, current):
            return "stale_claim"
        query = {"_id": _required(event_id, "event_id"), "processed": False, "claim_owner": _required(owner, "owner"), "claim_token": _token(token), "claim_expires_at": {"$gt": current}, "claim_leader_scope": leader_scope or None, "claim_leader_token": leader_token or None}
        row = self.database.events.find_one(query, {"attempts": 1})
        if row is None:
            return "stale_claim"
        retry = bool(retryable) and int(row.get("attempts", 0)) < int(max_attempts)
        set_fields = {"processing_outcome": "retry_scheduled" if retry else "dead_letter", "last_error_code": code, "last_error_type": kind, "last_error_at": current, "updated_at": current, "next_retry_at": _retry_at(current, retry_delay_seconds) if retry else None, "processed_at": None if retry else current, "processed": not retry}
        result = self.database.events.update_one(query, {"$set": set_fields, "$unset": {"claim_owner": "", "claim_token": "", "claim_leader_scope": "", "claim_leader_token": "", "claim_expires_at": ""}})
        if result.modified_count != 1:
            return "stale_claim"
        return "retry_scheduled" if retry else "dead_letter"

    def release_event_claim(self, event_id: str, owner: str, token: str, *, now: Any = None, leader_scope: str = "", leader_token: str = "") -> bool:
        current = _utc(now)
        if not self._leader_matches(leader_scope, owner, leader_token, current):
            return False
        result = self.database.events.update_one(
            {"_id": _required(event_id, "event_id"), "processed": False, "claim_owner": _required(owner, "owner"), "claim_token": _token(token), "claim_expires_at": {"$gt": current}, "claim_leader_scope": leader_scope or None, "claim_leader_token": leader_token or None},
            {"$set": {"updated_at": current}, "$unset": {"claim_owner": "", "claim_token": "", "claim_leader_scope": "", "claim_leader_token": "", "claim_expires_at": "", "processing_outcome": ""}},
        )
        return result.modified_count == 1

    def list_failed_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        return [self._event_result(item) | {key: item.get(key) for key in ("attempts", "last_error_code", "last_error_type", "last_error_at", "processing_outcome", "processed_at")} for item in self.database.events.find({"processed": True, "processing_outcome": "dead_letter"}).sort([("processed_at", -1), ("event_id", 1)]).limit(max(0, int(limit)))]

    # Generic durable queues ---------------------------------------------

    def _queue_collection(self, queue: str) -> Any:
        name = str(queue or "").strip()
        if name not in QUEUE_COLLECTIONS:
            raise ValueError("queue is not a registered durable job queue")
        return self.database[QUEUE_COLLECTIONS[name]]

    def claim_jobs(self, queue: str, owner: str, limit: int, lease_seconds: float, max_attempts: int, *, now: Any = None) -> List[Dict[str, Any]]:
        queue_name = str(queue or "").strip()
        collection = self._queue_collection(queue_name)
        claim_owner = _required(owner, "owner")
        attempt_limit = int(max_attempts)
        if attempt_limit < 1:
            raise ValueError("max_attempts must be positive")
        current = _utc(now)
        expires = _future(current, lease_seconds)
        collection.update_many(
            {"attempts": {"$gte": attempt_limit}, "status": {"$in": ["queued", "retry", "running"]}, "$and": [{"$or": [{"next_retry_at": None}, {"next_retry_at": {"$lte": current}}]}, {"$or": [{"status": {"$ne": "running"}}, {"claim_token": None}, {"claim_expires_at": None}, {"claim_expires_at": {"$lte": current}}]}]},
            {"$set": {"status": "failed", "error": "job_attempts_exhausted:LeaseExpired", "last_error_code": "job_attempts_exhausted", "last_error_type": "LeaseExpired", "last_error_at": current, "completed_at": current, "updated_at": current}, "$unset": {"next_retry_at": "", "claim_owner": "", "claim_token": "", "claim_expires_at": ""}},
        )
        claimed: List[Dict[str, Any]] = []
        sort = [("priority_rank", -1), ("created_at", 1), ("job_id", 1)] if queue_name == "enrichment" else [("created_at", 1), ("job_id", 1)]
        for _ in range(max(0, int(limit))):
            token = str(uuid.uuid4())
            item = collection.find_one_and_update(
                {"attempts": {"$lt": attempt_limit}, "$and": [{"$or": [{"next_retry_at": None}, {"next_retry_at": {"$lte": current}}]}, {"$or": [{"status": {"$in": ["queued", "retry"]}}, {"status": "running", "$or": [{"claim_token": None}, {"claim_expires_at": None}, {"claim_expires_at": {"$lte": current}}]}]}]},
                {"$set": {"status": "running", "claim_owner": claim_owner, "claim_token": token, "claim_expires_at": expires, "updated_at": current}, "$unset": {"next_retry_at": "", "completed_at": ""}, "$inc": {"attempts": 1}},
                sort=sort,
                return_document=self._return_document_after(),
            )
            if item is None:
                break
            claimed.append(_row(item) or {})
        return claimed

    def renew_job_claim(self, queue: str, job_id: str, owner: str, token: str, lease_seconds: float, *, now: Any = None) -> bool:
        current = _utc(now)
        result = self._queue_collection(queue).update_one(
            {"_id": _required(job_id, "job_id"), "status": "running", "claim_owner": _required(owner, "owner"), "claim_token": _token(token), "claim_expires_at": {"$gt": current}},
            {"$set": {"claim_expires_at": _future(current, lease_seconds), "updated_at": current}},
        )
        return result.modified_count == 1

    def fail_job(self, queue: str, job_id: str, owner: str, token: str, error_code: str, error_type: str, retryable: bool, max_attempts: int, retry_delay_seconds: float, *, now: Any = None) -> str:
        queue_name, code, kind = validate_job_failure_fields(queue, error_code, error_type)
        collection = self._queue_collection(queue_name)
        current = _utc(now)
        query = {"_id": _required(job_id, "job_id"), "status": "running", "claim_owner": _required(owner, "owner"), "claim_token": _token(token), "claim_expires_at": {"$gt": current}}
        item = collection.find_one(query, {"attempts": 1})
        if item is None:
            return "stale_claim"
        retry = bool(retryable) and int(item.get("attempts", 0)) < int(max_attempts)
        result = collection.update_one(query, {"$set": {"status": "retry" if retry else "failed", "error": f"{code}:{kind}", "next_retry_at": _retry_at(current, retry_delay_seconds) if retry else None, "last_error_code": code, "last_error_type": kind, "last_error_at": current, "completed_at": None if retry else current, "updated_at": current}, "$unset": {"claim_owner": "", "claim_token": "", "claim_expires_at": ""}})
        return ("retry_scheduled" if retry else "failed") if result.modified_count == 1 else "stale_claim"

    def release_job_claim(self, queue: str, job_id: str, owner: str, token: str, *, now: Any = None) -> bool:
        current = _utc(now)
        result = self._queue_collection(queue).update_one({"_id": _required(job_id, "job_id"), "status": "running", "claim_owner": _required(owner, "owner"), "claim_token": _token(token), "claim_expires_at": {"$gt": current}}, {"$set": {"status": "retry", "next_retry_at": current, "updated_at": current}, "$unset": {"claim_owner": "", "claim_token": "", "claim_expires_at": ""}})
        return result.modified_count == 1

    def retry_failed_job(self, queue: str, job_id: str, *, now: Any = None) -> bool:
        current = _utc(now)
        result = self._queue_collection(queue).update_one({"_id": _required(job_id, "job_id"), "status": "failed"}, {"$set": {"status": "retry", "attempts": 0, "next_retry_at": current, "updated_at": current}, "$unset": {"claim_owner": "", "claim_token": "", "claim_expires_at": "", "completed_at": ""}})
        return result.modified_count == 1

    def job_queue_metrics(self, queue: str, *, now: Any = None) -> Dict[str, Any]:
        current = _utc(now)
        collection = self._queue_collection(queue)
        counts = {item["_id"]: item["count"] for item in collection.aggregate([{"$group": {"_id": "$status", "count": {"$sum": 1}}}])}
        ready_query = {"status": {"$in": ["queued", "retry"]}, "$or": [{"next_retry_at": None}, {"next_retry_at": {"$lte": current}}]}
        oldest = collection.find_one(ready_query, sort=[("created_at", 1)], projection={"created_at": 1})
        oldest_at = oldest.get("created_at") if oldest else None
        age = max((datetime.fromisoformat(current) - datetime.fromisoformat(oldest_at)).total_seconds(), 0.0) if oldest_at else None
        return {"queue": str(queue), "status_counts": counts, "ready": collection.count_documents(ready_query), "stale_running": collection.count_documents({"status": "running", "$or": [{"claim_expires_at": None}, {"claim_expires_at": {"$lte": current}}]}), "oldest_ready_at": oldest_at, "oldest_ready_age_seconds": age, "checked_at": current}

    # Sessions, analysis, and reports ------------------------------------

    def update_session_analysis_status(self, session_id: str, status: str, *, job_id: str = "", report_id: str = "", error: str = "", skip_reason: str = "") -> None:
        identity = str(session_id or "")
        if not identity:
            return
        current = _utc()
        for _ in range(8):
            row = self.database.sessions.find_one({"_id": identity}, {"payload_json": 1, "revision": 1})
            if row is None:
                return
            payload = _analysis_payload(_payload(row), status, current, job_id=job_id, report_id=report_id, error=error, skip_reason=skip_reason)
            result = self.database.sessions.update_one(
                {"_id": identity, "revision": int(row.get("revision", 0))},
                {"$set": {"payload_json": stable_json(payload), "updated_at": current}, "$inc": {"revision": 1}},
            )
            if result.modified_count == 1:
                return
        raise StorageError("session revision changed repeatedly")

    def store_alert(self, alert_payload: Dict[str, Any]) -> str:
        payload_json = stable_json(alert_payload)
        alert_id = str(alert_payload.get("alert_id") or stable_id("alert", alert_payload))
        document = {"_id": alert_id, "schema_version": "mongodb_alert.v1", "alert_id": alert_id, "session_id": str(alert_payload.get("session_id", "unknown")), "severity": str(alert_payload.get("severity", "UNKNOWN")), "reason": str(alert_payload.get("reason", "")), "payload_json": payload_json, "payload_sha256": hashlib.sha256(payload_json.encode()).hexdigest(), "created_at": str(alert_payload.get("created_at") or utc_now()), "delivered": False}
        self._exact_insert("alerts", alert_id, document, compare=("payload_json",))
        return alert_id

    def enqueue_analysis_job(self, session_payload: Dict[str, Any]) -> str:
        session_id = str(session_payload.get("session_id", "unknown"))
        job_id = stable_id("job", {"session_id": session_id})
        current = utc_now()
        payload_json = stable_json(session_payload)
        document = {"_id": job_id, "schema_version": "mongodb_analysis_job.v1", "job_id": job_id, "session_id": session_id, "status": "queued", "payload_json": payload_json, "payload_sha256": hashlib.sha256(payload_json.encode()).hexdigest(), "attempts": 0, "created_at": current, "updated_at": current, "next_retry_at": None, "claim_owner": None, "claim_token": None, "claim_expires_at": None}
        self._exact_insert("analysis_jobs", job_id, document, compare=("session_id", "payload_json"))
        return job_id

    def claim_analysis_jobs(self, owner: str, limit: int, lease_seconds: float, max_attempts: int, *, now: Any = None) -> List[Dict[str, Any]]:
        rows = self.claim_jobs(
            "analysis", owner, limit, lease_seconds, max_attempts, now=now
        )
        return [materialize_analysis_job_claim(row) for row in rows]

    @staticmethod
    def _report_identity(job_id: str, report_payload: Dict[str, Any]) -> tuple[str, str, str]:
        assessment_id = str(report_payload.get("assessment_id") or "").strip()
        if report_payload.get("schema_version") == "session_assessment.v4" and assessment_id:
            report_id = stable_id("report", {"job_id": job_id, "schema_version": "session_assessment.v4", "assessment_id": assessment_id})
        else:
            report_id = stable_id("report", {"job_id": job_id, "report": report_payload})
        evidence = report_payload.get("canonical_evidence")
        canonical_session = evidence.get("session_id") if report_payload.get("schema_version") == "session_assessment.v4" and isinstance(evidence, dict) else ""
        session_id = str(canonical_session or report_payload.get("session_id") or (report_payload.get("data_provenance") or {}).get("session", {}).get("session_id") or "unknown").strip()
        return report_id, session_id, assessment_id

    def complete_analysis_job(self, job_id: str, owner: str, token: str, report_payload: Dict[str, Any], enqueue_ai_advisory: bool = False, ai_advisory_max_queue_records: int = 10_000, ai_advisory_reconciliation_cutoff: Optional[Dict[str, str]] = None, *, now: Any = None) -> Optional[str]:
        current = _utc(now)
        job_key = _required(job_id, "job_id")
        claim_owner = _required(owner, "owner")
        claim_token = _token(token)
        report_id, session_id, assessment_id = self._report_identity(job_key, report_payload)
        report_json = stable_json(report_payload)

        def publish(session: Any) -> Optional[str]:
            claim = self.database.analysis_jobs.find_one({"_id": job_key, "status": "running", "claim_owner": claim_owner, "claim_token": claim_token, "claim_expires_at": {"$gt": current}}, session=session)
            if claim is None:
                return None
            report = {"_id": report_id, "schema_version": "mongodb_report.v1", "report_id": report_id, "session_id": session_id, "assessment_id": assessment_id, "payload_json": report_json, "payload_sha256": hashlib.sha256(report_json.encode()).hexdigest(), "created_at": current}
            self._exact_insert("reports", report_id, report, compare=("session_id", "payload_json", "payload_sha256"), session=session)
            if assessment_id:
                assessment = dict(report)
                assessment.update({"_id": assessment_id, "schema_version": "mongodb_canonical_assessment.v1", "assessment_id": assessment_id})
                self._exact_insert("canonical_assessments", assessment_id, assessment, compare=("session_id", "payload_json", "payload_sha256"), session=session)
            result = self.database.analysis_jobs.update_one({"_id": job_key, "status": "running", "claim_owner": claim_owner, "claim_token": claim_token, "claim_expires_at": {"$gt": current}}, {"$set": {"status": "succeeded", "report_id": report_id, "error": None, "completed_at": current, "updated_at": current}, "$unset": {"next_retry_at": "", "claim_owner": "", "claim_token": "", "claim_expires_at": ""}}, session=session)
            if result.modified_count != 1:
                raise StorageError("analysis job claim changed during completion")
            stored = self.database.sessions.find_one({"_id": session_id}, {"payload_json": 1}, session=session)
            if stored:
                payload = _analysis_payload(_payload(stored), "succeeded", current, report_id=report_id)
                self.database.sessions.update_one({"_id": session_id}, {"$set": {"payload_json": stable_json(payload), "current_report_id": report_id, "updated_at": current}, "$inc": {"revision": 1}}, session=session)
            return report_id

        persisted = self._transaction(publish)
        if persisted and enqueue_ai_advisory:
            try:
                self.enqueue_ai_advisory_job(report_id, session_id, assessment_id, reconciliation_cutoff=ai_advisory_reconciliation_cutoff or {}, max_queue_records=ai_advisory_max_queue_records)
            except Exception:
                pass
        return persisted

    def fail_analysis_job(self, job_id: str, owner: str, token: str, error_code: str, error_type: str, retryable: bool, max_attempts: int, retry_delay_seconds: float, *, now: Any = None) -> str:
        row = self.database.analysis_jobs.find_one({"_id": job_id}, {"session_id": 1})
        result = self.fail_job("analysis", job_id, owner, token, error_code, error_type, retryable, max_attempts, retry_delay_seconds, now=now)
        if row and result in {"retry_scheduled", "failed"}:
            self.update_session_analysis_status(str(row["session_id"]), "retry" if result == "retry_scheduled" else "failed", error=f"{error_code}:{error_type}")
        return result

    def skip_analysis_job(self, job_id: str, owner: str, token: str, reason: str, *, now: Any = None) -> bool:
        current = _utc(now)
        query = {"_id": _required(job_id, "job_id"), "status": "running", "claim_owner": _required(owner, "owner"), "claim_token": _token(token), "claim_expires_at": {"$gt": current}}
        row = self.database.analysis_jobs.find_one(query, {"session_id": 1})
        if row is None:
            return False
        result = self.database.analysis_jobs.update_one(query, {"$set": {"status": "skipped", "error": str(reason), "completed_at": current, "updated_at": current}, "$unset": {"next_retry_at": "", "claim_owner": "", "claim_token": "", "claim_expires_at": ""}})
        if result.modified_count == 1:
            self.update_session_analysis_status(str(row["session_id"]), "skipped", skip_reason=str(reason))
            return True
        return False

    def get_report_by_id(self, report_id: str) -> Optional[Dict[str, Any]]:
        item = _row(self.database.reports.find_one({"_id": str(report_id)}))
        if item is not None:
            item["payload"] = _payload(item)
        return item

    def get_current_report_for_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        session = self.database.sessions.find_one({"_id": str(session_id)}, {"current_report_id": 1, "payload_json": 1})
        pointer = str(session.get("current_report_id") or "") if session else ""
        if not pointer and session:
            pointer = str(_payload(session).get("report_id") or "")
        if pointer:
            report = self.get_report_by_id(pointer)
            if report:
                return report
        document = self.database.reports.find_one({"session_id": str(session_id)}, sort=[("created_at", -1), ("report_id", 1)])
        item = _row(document)
        if item is not None:
            item["payload"] = _payload(item)
        return item

    # Optional AI advisory ------------------------------------------------

    def initialize_ai_advisory_extension(self) -> None:
        self.verify_existing_schema()

    def _session_after_cutoff(self, session_id: str, cutoff: Dict[str, str]) -> bool:
        first = self.database.events.find_one({"session_id": session_id}, sort=[("received_at", 1), ("event_id", 1)], projection={"received_at": 1, "event_id": 1})
        if first is None:
            return False
        return evidence_cutoff_sort_key({"schema_version": cutoff["schema_version"], "received_at": first["received_at"], "event_id": first["event_id"]}) > evidence_cutoff_sort_key(cutoff)

    def enqueue_ai_advisory_job(self, report_id: str, session_id: str, assessment_id: str, *, reconciliation_cutoff: Dict[str, str], max_queue_records: int = 10_000, now: Any = None) -> Optional[str]:
        report_key, session_key, assessment_key = (_required(report_id, "report_id"), _required(session_id, "session_id"), _required(assessment_id, "assessment_id"))
        cutoff = require_valid_evidence_cutoff(reconciliation_cutoff)
        report = self.database.reports.find_one({"_id": report_key})
        if report is None or report.get("session_id") != session_key:
            raise StorageError("AI advisory enqueue requires a committed report")
        payload = _payload(report)
        if payload.get("schema_version") != "session_assessment.v4" or str(payload.get("assessment_id") or "") != assessment_key:
            raise StorageError("AI advisory enqueue report identity is invalid")
        if not self._session_after_cutoff(session_key, cutoff):
            return None
        job_id = stable_id("ai_advisory_job", {"report_id": report_key, "assessment_id": assessment_key})
        existing = self.database.ai_advisory_outbox.find_one({"_id": job_id})
        if existing:
            if existing.get("report_id") != report_key or existing.get("assessment_id") != assessment_key:
                raise StorageError("conflicting AI advisory job identity")
            return job_id
        if self.database.ai_advisory_outbox.count_documents({"status": {"$in": ["queued", "retry", "running"]}}) >= int(max_queue_records):
            return None
        current = _utc(now)
        task = {"schema_version": "ai_advisory_task.v1", "report_id": report_key, "session_id": session_key, "assessment_id": assessment_key}
        document = {"_id": job_id, "schema_version": "mongodb_ai_advisory_job.v1", "job_id": job_id, "report_id": report_key, "session_id": session_key, "assessment_id": assessment_key, "status": "queued", "payload_json": stable_json(task), "attempts": 0, "created_at": current, "updated_at": current, "next_retry_at": None, "claim_owner": None, "claim_token": None, "claim_expires_at": None}
        self._exact_insert("ai_advisory_outbox", job_id, document, compare=("report_id", "assessment_id", "payload_json"))
        return job_id

    def reconcile_ai_advisory_outbox(self, *, reconciliation_cutoff: Dict[str, str], limit: int = 100, max_queue_records: int = 10_000) -> Dict[str, int]:
        cutoff = require_valid_evidence_cutoff(reconciliation_cutoff)
        scan_limit = max(0, int(limit))
        cursor_scope = stable_id("ai_advisory_reconciliation", cutoff)
        stored_cursor = self.database.reconciliation_cursors.find_one(
            {"_id": cursor_scope}
        )
        last_created_at = ""
        last_report_id = ""
        if stored_cursor is not None:
            payload_json = str(stored_cursor.get("payload_json") or "")
            if hashlib.sha256(payload_json.encode("utf-8")).hexdigest() != str(
                stored_cursor.get("payload_sha256") or ""
            ):
                raise StorageError("AI reconciliation cursor hash mismatch")
            cursor_payload = _payload(stored_cursor)
            if (
                cursor_payload.get("schema_version")
                != "mongodb_ai_reconciliation_cursor.v1"
                or cursor_payload.get("cutoff") != cutoff
            ):
                raise StorageError("AI reconciliation cursor identity mismatch")
            last_created_at = str(cursor_payload.get("last_created_at") or "")
            last_report_id = str(cursor_payload.get("last_report_id") or "")

        query: Dict[str, Any] = {"assessment_id": {"$nin": [None, ""]}}
        if last_created_at:
            query["$or"] = [
                {"created_at": {"$gt": last_created_at}},
                {
                    "created_at": last_created_at,
                    "report_id": {"$gt": last_report_id},
                },
            ]
        scanned = enqueued = ineligible = 0
        cursor = self.database.reports.find(query).sort(
            [("created_at", 1), ("report_id", 1)]
        ).limit(scan_limit)
        advanced_created_at = last_created_at
        advanced_report_id = last_report_id
        for report in cursor:
            scanned += 1
            advanced_created_at = str(report.get("created_at") or "")
            advanced_report_id = str(report.get("report_id") or "")
            if self.database.ai_advisory_outbox.count_documents({"report_id": report["report_id"], "assessment_id": report["assessment_id"]}, limit=1):
                continue
            if not self._session_after_cutoff(str(report["session_id"]), cutoff):
                ineligible += 1
                continue
            if self.enqueue_ai_advisory_job(report["report_id"], report["session_id"], report["assessment_id"], reconciliation_cutoff=cutoff, max_queue_records=max_queue_records):
                enqueued += 1
        if scanned:
            cursor_payload = {
                "schema_version": "mongodb_ai_reconciliation_cursor.v1",
                "scope": cursor_scope,
                "cutoff": cutoff,
                "last_created_at": advanced_created_at,
                "last_report_id": advanced_report_id,
            }
            payload_json = stable_json(cursor_payload)
            self.database.reconciliation_cursors.replace_one(
                {"_id": cursor_scope},
                {
                    "_id": cursor_scope,
                    "schema_version": "mongodb_reconciliation_cursor.v1",
                    "scope": cursor_scope,
                    "payload_json": payload_json,
                    "payload_sha256": hashlib.sha256(
                        payload_json.encode("utf-8")
                    ).hexdigest(),
                    "updated_at": utc_now(),
                },
                upsert=True,
            )
        return {"scanned": scanned, "enqueued": enqueued, "ineligible": ineligible}

    def claim_ai_advisory_jobs(self, owner: str, limit: int, lease_seconds: float, max_attempts: int, *, now: Any = None) -> List[Dict[str, Any]]:
        rows = self.claim_jobs(
            "ai_advisory", owner, limit, lease_seconds, max_attempts, now=now
        )
        return [materialize_ai_advisory_job_claim(row) for row in rows]

    def _advisory_result(self, document: Optional[Mapping[str, Any]]) -> Optional[Dict[str, Any]]:
        item = _row(document)
        if item is not None:
            item["payload"] = _payload(item)
            item["metrics"] = _payload(item, "metrics_json")
        return item

    def get_ai_advisory_by_cache_key(self, cache_key: str) -> Optional[Dict[str, Any]]:
        return self._advisory_result(self.database.ai_advisories.find_one({"cache_key": str(cache_key)}))

    def get_ai_advisory_for_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        return self._advisory_result(self.database.ai_advisories.find_one({"session_id": str(session_id)}, sort=[("created_at", -1), ("advisory_id", 1)]))

    def get_ai_advisory_for_report(self, report_id: str, assessment_id: str) -> Optional[Dict[str, Any]]:
        return self._advisory_result(self.database.ai_advisories.find_one({"report_id": str(report_id), "assessment_id": str(assessment_id)}))

    def get_ai_advisory_outbox_for_report(self, report_id: str, assessment_id: str) -> Optional[Dict[str, Any]]:
        return _row(self.database.ai_advisory_outbox.find_one({"report_id": str(report_id), "assessment_id": str(assessment_id)}))

    def complete_ai_advisory_job(self, job_id: str, owner: str, token: str, advisory_record: Dict[str, Any], completion_code: str = "accepted", *, now: Any = None) -> Optional[str]:
        required = {"advisory_id", "cache_key", "report_id", "session_id", "assessment_id", "status", "projection_sha256", "request_sha256", "response_sha256", "provider_id", "model_id", "prompt_sha256", "schema_sha256", "policy_sha256", "payload", "metrics"}
        if set(advisory_record) != required:
            raise ValueError("AI advisory storage record has invalid keys")
        if completion_code not in {"accepted", "rejected", "cache_replayed"}:
            raise ValueError("AI advisory completion_code is invalid")
        current = _utc(now)

        def complete(session: Any) -> Optional[str]:
            query = {"_id": job_id, "status": "running", "claim_owner": owner, "claim_token": token, "claim_expires_at": {"$gt": current}}
            claim = self.database.ai_advisory_outbox.find_one(query, session=session)
            if claim is None:
                return None
            for field in ("report_id", "session_id", "assessment_id"):
                if str(claim[field]) != str(advisory_record[field]):
                    raise StorageError("AI advisory record does not match its outbox claim")
            advisory_id = _required(advisory_record["advisory_id"], "advisory_id")
            payload_json, metrics_json = stable_json(advisory_record["payload"]), stable_json(advisory_record["metrics"])
            document = {"_id": advisory_id, "schema_version": "mongodb_ai_advisory.v1", **{key: str(advisory_record[key] or "") for key in required - {"payload", "metrics"}}, "advisory_id": advisory_id, "payload_json": payload_json, "payload_sha256": hashlib.sha256(payload_json.encode()).hexdigest(), "metrics_json": metrics_json, "created_at": current}
            try:
                self._exact_insert("ai_advisories", advisory_id, document, compare=("cache_key", "report_id", "assessment_id", "payload_json", "metrics_json"), session=session)
            except StorageError:
                by_cache = self.database.ai_advisories.find_one({"cache_key": advisory_record["cache_key"]}, session=session)
                if not by_cache or by_cache.get("payload_json") != payload_json:
                    raise
                advisory_id = str(by_cache["advisory_id"])
            result = self.database.ai_advisory_outbox.update_one(query, {"$set": {"status": "succeeded", "advisory_id": advisory_id, "completion_code": completion_code, "completed_at": current, "updated_at": current}, "$unset": {"error": "", "next_retry_at": "", "claim_owner": "", "claim_token": "", "claim_expires_at": "", "last_error_code": "", "last_error_type": "", "last_error_at": ""}}, session=session)
            if result.modified_count != 1:
                raise StorageError("AI advisory claim changed during completion")
            return advisory_id

        return self._transaction(complete)

    def prune_ai_advisories(self, retention_days: int = 30, keep_latest_per_session: bool = False, *, max_records: int = 50_000, max_storage_bytes: int = 256 * 1024 * 1024, now: Any = None) -> Dict[str, Any]:
        current = datetime.fromisoformat(_utc(now))
        cutoff = (current - timedelta(days=max(0, int(retention_days)))).isoformat(timespec="microseconds")
        rows = list(self.database.ai_advisories.find({}, {"_id": 1, "session_id": 1, "created_at": 1, "payload_json": 1, "metrics_json": 1}).sort([("created_at", -1), ("advisory_id", 1)]))
        keep = set()
        if keep_latest_per_session:
            for row in rows:
                keep.add(row["_id"]) if row.get("session_id") not in {self.database.ai_advisories.find_one({"_id": identity}, {"session_id": 1}).get("session_id") for identity in keep} else None
        total_bytes = sum(len(str(row.get("payload_json", "")).encode()) + len(str(row.get("metrics_json", "")).encode()) for row in rows)
        delete: List[str] = []
        for index, row in enumerate(rows):
            size = len(str(row.get("payload_json", "")).encode()) + len(str(row.get("metrics_json", "")).encode())
            if row["_id"] not in keep and (str(row.get("created_at") or "") < cutoff or index >= int(max_records) or total_bytes > int(max_storage_bytes)):
                delete.append(row["_id"])
                total_bytes -= size
        if delete:
            self.database.ai_advisories.delete_many({"_id": {"$in": delete}})
        return {"deleted": len(delete), "remaining": len(rows) - len(delete), "remaining_bytes": total_bytes, "cutoff": cutoff}

    # Enrichment, observables, hunts, links, and campaigns ----------------

    def save_feed_status(self, status: Dict[str, Any]) -> None:
        current = utc_now()
        for name, payload in status.items():
            if name == "summary":
                continue
            body = stable_json(payload)
            self.database.feed_status.replace_one({"_id": str(name)}, {"_id": str(name), "schema_version": "mongodb_feed_status.v1", "feed_id": str(name), "payload_json": body, "payload_sha256": hashlib.sha256(body.encode()).hexdigest(), "updated_at": current}, upsert=True)

    @staticmethod
    def _decode_enrichment_record(
        document: Optional[Mapping[str, Any]],
        allow_stale: bool,
    ) -> Optional[Dict[str, Any]]:
        item = _row(document)
        if item is None:
            return None
        item["payload"] = _payload(item)
        item["provider_status"] = _payload(item, "provider_status_json")
        expires = str(item.get("expires_at") or "")
        item["is_stale"] = not expires or expires <= _utc()
        return None if item["is_stale"] and not allow_stale else item

    def get_enrichment_record(self, observable_type: str, observable_value: str, allow_stale: bool = True) -> Optional[Dict[str, Any]]:
        document = self.database.enrichment_records.find_one(
            {"_id": stable_id("enrichment", {"observable_type": observable_type, "observable_value": observable_value})},
            _SESSION_DETAIL_PROJECTION,
        )
        return self._decode_enrichment_record(document, allow_stale)

    def list_enrichment_records_for_observables(
        self,
        observables: Any,
        allow_stale: bool = True,
    ) -> List[Dict[str, Any]]:
        identities = [
            stable_id(
                "enrichment",
                {"observable_type": str(observable_type), "observable_value": str(observable_value)},
            )
            for observable_type, observable_value in observables
            if str(observable_type) and str(observable_value)
        ]
        if not identities:
            return []
        documents = self.database.enrichment_records.find(
            {"_id": {"$in": identities}},
            _SESSION_DETAIL_PROJECTION,
        )
        records = []
        for document in documents:
            record = self._decode_enrichment_record(document, allow_stale)
            if record is not None:
                records.append(record)
        return records

    def load_enrichment_cache(self, observable_type: str = "ip", allow_stale: bool = True) -> Dict[str, Dict[str, Any]]:
        # The cache is a bounded read model.  Decode the already-selected
        # documents in one query; do not re-fetch every record by identity.
        output: Dict[str, Dict[str, Any]] = {}
        documents = self.database.enrichment_records.find(
            {"observable_type": observable_type},
            _SESSION_DETAIL_PROJECTION,
        )
        for document in documents:
            record = self._decode_enrichment_record(document, allow_stale)
            if record is None:
                continue
            payload = record["payload"]
            payload.setdefault("enrichment_cache", {"source": "storage", "status": "stale" if record["is_stale"] else "fresh", "expires_at": record.get("expires_at")})
            output[str(document["observable_value"])] = payload
        return output

    def save_enrichment_record(self, observable_type: str, observable_value: str, payload: Dict[str, Any], provider_status: Dict[str, Any], expires_at: Optional[str] = None) -> None:
        identity = stable_id("enrichment", {"observable_type": observable_type, "observable_value": observable_value})
        current = utc_now()
        old = self.database.enrichment_records.find_one({"_id": identity}, {"first_seen": 1})
        body, provider = stable_json(payload), stable_json(provider_status)
        self.database.enrichment_records.replace_one({"_id": identity}, {"_id": identity, "schema_version": "mongodb_enrichment_record.v1", "observable_type": observable_type, "observable_value": observable_value, "payload_json": body, "payload_sha256": hashlib.sha256(body.encode()).hexdigest(), "provider_status_json": provider, "first_seen": old.get("first_seen") if old else current, "last_seen": current, "expires_at": expires_at, "updated_at": current}, upsert=True)

    @staticmethod
    def _priority(value: str) -> str:
        selected = str(value or "normal").strip().lower()
        if selected not in _PRIORITY_RANK:
            raise ValueError("unsupported enrichment priority")
        return selected

    def enqueue_enrichment_job(self, observable_type: str, observable_value: str, session_id: str = "", payload: Optional[Dict[str, Any]] = None, force: bool = False, priority: str = "normal", priority_reason: str = "") -> tuple[str, bool]:
        from pymongo.errors import DuplicateKeyError

        job_id = stable_id("enrichjob", {"observable_type": observable_type, "observable_value": observable_value})
        if self.get_enrichment_record(observable_type, observable_value, allow_stale=False) and not force:
            return job_id, False
        selected = self._priority(priority)
        body = dict(payload or {})
        body.setdefault("observable_type", observable_type)
        body.setdefault("observable_value", observable_value)
        if session_id:
            body.setdefault("session_id", session_id)
        current = utc_now()
        existing = self.database.enrichment_jobs.find_one({"_id": job_id})
        if existing:
            update = {"payload_json": stable_json(body), "session_id": session_id or existing.get("session_id"), "updated_at": current, "error": None, "next_retry_at": None}
            if _PRIORITY_RANK[selected] > _PRIORITY_RANK.get(str(existing.get("priority")), 0):
                update.update({"priority": selected, "priority_rank": _PRIORITY_RANK[selected], "priority_reason": priority_reason or None})
            if existing.get("status") not in {"queued", "running", "retry"}:
                update["status"] = "queued"
            self.database.enrichment_jobs.update_one({"_id": job_id}, {"$set": update})
            return job_id, True
        document = {"_id": job_id, "schema_version": "mongodb_enrichment_job.v1", "job_id": job_id, "observable_type": observable_type, "observable_value": observable_value, "session_id": session_id or None, "status": "queued", "priority": selected, "priority_rank": _PRIORITY_RANK[selected], "priority_reason": priority_reason or None, "payload_json": stable_json(body), "attempts": 0, "next_retry_at": None, "error": None, "created_at": current, "updated_at": current}
        try:
            self.database.enrichment_jobs.insert_one(document)
        except DuplicateKeyError:
            # Another writer won the deterministic first-insert race. Re-enter
            # the existing-record path so priority/requeue semantics are the
            # same as a non-concurrent duplicate enqueue.
            return self.enqueue_enrichment_job(
                observable_type,
                observable_value,
                session_id,
                payload,
                force,
                priority,
                priority_reason,
            )
        return job_id, True

    def claim_enrichment_jobs(self, owner: str, limit: int, lease_seconds: float, max_attempts: int, *, now: Any = None) -> List[Dict[str, Any]]:
        output = []
        for row in self.claim_jobs("enrichment", owner, limit, lease_seconds, max_attempts, now=now):
            output.append({"job_id": row["job_id"], "observable_type": row["observable_type"], "observable_value": row["observable_value"], "session_id": row.get("session_id"), "priority": row.get("priority"), "priority_reason": row.get("priority_reason"), "payload": _payload(row), "attempts": row["attempts"], "claim_owner": row["claim_owner"], "claim_token": row["claim_token"], "claim_expires_at": row["claim_expires_at"]})
        return output

    def reprioritize_enrichment_jobs(self, observable_value: str, observable_type: str = "ip", priority: str = "urgent", reason: str = "", session_id: str = "") -> int:
        if not observable_value:
            return 0
        selected = self._priority(priority)
        query = {"observable_type": observable_type, "observable_value": observable_value, "status": {"$in": ["queued", "retry"]}, "priority_rank": {"$lt": _PRIORITY_RANK[selected]}}
        update: Dict[str, Any] = {"priority": selected, "priority_rank": _PRIORITY_RANK[selected], "priority_reason": reason or None, "next_retry_at": None, "updated_at": utc_now()}
        if session_id:
            update["session_id"] = session_id
        return self.database.enrichment_jobs.update_many(query, {"$set": update}).modified_count

    def _complete_queue_job(self, queue: str, job_id: str, owner: str, token: str, *, now: Any = None, extra: Optional[Dict[str, Any]] = None) -> bool:
        current = _utc(now)
        fields = {"status": "succeeded", "error": None, "completed_at": current, "updated_at": current, **(extra or {})}
        result = self._queue_collection(queue).update_one({"_id": _required(job_id, "job_id"), "status": "running", "claim_owner": _required(owner, "owner"), "claim_token": _token(token), "claim_expires_at": {"$gt": current}}, {"$set": fields, "$unset": {"next_retry_at": "", "claim_owner": "", "claim_token": "", "claim_expires_at": ""}})
        return result.modified_count == 1

    def complete_enrichment_job(self, job_id: str, owner: str, token: str, *, now: Any = None) -> bool:
        return self._complete_queue_job("enrichment", job_id, owner, token, now=now)

    def fail_enrichment_job(self, job_id: str, owner: str, token: str, error_code: str, error_type: str, retryable: bool, max_attempts: int, retry_delay_seconds: float, *, now: Any = None) -> str:
        return self.fail_job("enrichment", job_id, owner, token, error_code, error_type, retryable, max_attempts, retry_delay_seconds, now=now)

    def record_observable_sighting(self, sighting: Dict[str, Any]) -> str:
        observable_type = _required(str(sighting.get("observable_type") or "").lower(), "observable_type")
        observable_value = _required(sighting.get("observable_value"), "observable_value")
        session_id, role, source = str(sighting.get("session_id") or "unknown"), str(sighting.get("role") or "observed"), str(sighting.get("source") or "unknown")
        event_id = str(sighting.get("event_id") or "")
        identity = str(sighting.get("sighting_id") or stable_id("sighting", {"observable_type": observable_type, "observable_value": observable_value, "session_id": session_id, "role": role, "source": source, "event_id": event_id, "eventid": sighting.get("eventid", "")}))
        timestamp = str(sighting.get("timestamp") or utc_now())
        payload = dict(sighting.get("payload") or {})
        payload.update({"observable_type": observable_type, "observable_value": observable_value, "role": role, "source": source})

        def write(session: Any) -> str:
            document = {"_id": identity, "schema_version": "mongodb_observable_sighting.v1", "sighting_id": identity, "observable_id": stable_id("observable", {"observable_type": observable_type, "observable_value": observable_value}), "observable_type": observable_type, "observable_value": observable_value, "session_id": session_id, "sensor_id": str(sighting.get("sensor_id") or ""), "src_ip": str(sighting.get("src_ip") or ""), "event_id": event_id, "eventid": str(sighting.get("eventid") or ""), "role": role, "source": source, "timestamp": timestamp, "payload_json": stable_json(payload), "created_at": utc_now()}
            inserted = self._exact_insert("observable_sightings", identity, document, compare=("observable_type", "observable_value", "session_id", "role", "source", "event_id", "payload_json"), session=session)
            if inserted:
                self.database.observables.update_one({"_id": document["observable_id"]}, {"$setOnInsert": {"schema_version": "mongodb_observable.v1", "observable_id": document["observable_id"], "observable_type": observable_type, "observable_value": observable_value, "first_seen": timestamp}, "$set": {"last_seen": timestamp, "payload_json": stable_json({"last_role": role, "last_source": source})}, "$inc": {"sighting_count": 1}}, upsert=True, session=session)
            return identity
        return self._transaction(write)

    def enqueue_threat_hunt_job(self, session_id: str, observable_type: str, observable_value: str, trigger_reason: str = "", payload: Optional[Dict[str, Any]] = None) -> tuple[str, bool]:
        from pymongo.errors import DuplicateKeyError

        session_id, observable_type, observable_value = str(session_id or "unknown"), _required(str(observable_type or "").lower(), "observable_type"), _required(observable_value, "observable_value")
        identity = stable_id("threathuntjob", {"session_id": session_id, "observable_type": observable_type, "observable_value": observable_value})
        body = dict(payload or {})
        body.update({"session_id": session_id, "observable_type": observable_type, "observable_value": observable_value, "trigger_reason": trigger_reason})
        current = utc_now()
        existing = self.database.threat_hunt_jobs.find_one({"_id": identity})
        if existing:
            update = {"trigger_reason": trigger_reason or None, "payload_json": stable_json(body), "error": None, "updated_at": current}
            if existing.get("status") not in {"queued", "running", "retry"}:
                update["status"] = "queued"
            self.database.threat_hunt_jobs.update_one({"_id": identity}, {"$set": update})
            return identity, True
        try:
            self.database.threat_hunt_jobs.insert_one({"_id": identity, "schema_version": "mongodb_threat_hunt_job.v1", "job_id": identity, "session_id": session_id, "observable_type": observable_type, "observable_value": observable_value, "trigger_reason": trigger_reason or None, "status": "queued", "result_json": None, "payload_json": stable_json(body), "attempts": 0, "error": None, "created_at": current, "updated_at": current})
        except DuplicateKeyError:
            # Resolve a simultaneous deterministic enqueue through the same
            # update path used for an ordinary idempotent replay.
            return self.enqueue_threat_hunt_job(
                session_id,
                observable_type,
                observable_value,
                trigger_reason,
                payload,
            )
        return identity, True

    def claim_threat_hunt_jobs(self, owner: str, limit: int, lease_seconds: float, max_attempts: int, *, now: Any = None) -> List[Dict[str, Any]]:
        jobs = self.claim_jobs("threat_hunt", owner, limit, lease_seconds, max_attempts, now=now)
        for job in jobs:
            job["payload"] = _payload(job)
            job["result"] = _payload(job, "result_json") if job.get("result_json") else {}
        return jobs

    def complete_threat_hunt_job(self, job_id: str, owner: str, token: str, result: Dict[str, Any], *, now: Any = None) -> bool:
        return self._complete_queue_job("threat_hunt", job_id, owner, token, now=now, extra={"result_json": stable_json(result)})

    def fail_threat_hunt_job(self, job_id: str, owner: str, token: str, error_code: str, error_type: str, retryable: bool, max_attempts: int, retry_delay_seconds: float, *, now: Any = None) -> str:
        return self.fail_job("threat_hunt", job_id, owner, token, error_code, error_type, retryable, max_attempts, retry_delay_seconds, now=now)

    def find_sessions_by_observable(self, observable_type: str, observable_value: str, exclude_session_id: str = "", limit: int = 100) -> List[Dict[str, Any]]:
        groups: Dict[str, List[Dict[str, Any]]] = {}
        for row in self.database.observable_sightings.find({"observable_type": observable_type, "observable_value": observable_value, "session_id": {"$ne": exclude_session_id}}).sort([("timestamp", -1)]):
            groups.setdefault(str(row["session_id"]), []).append(row)
        output = []
        for session_id, rows in groups.items():
            session = self.database.sessions.find_one({"_id": session_id}) or {}
            times = [str(item.get("timestamp") or item.get("created_at") or "") for item in rows]
            output.append({"session_id": session_id, "sighting_count": len(rows), "first_seen": min(times), "last_seen": max(times), "roles": sorted({str(item.get("role") or "") for item in rows if item.get("role")}), "sources": sorted({str(item.get("source") or "") for item in rows if item.get("source")}), "src_ip": session.get("src_ip"), "ended": bool(session.get("ended")), "updated_at": session.get("updated_at"), "payload": _payload(session) if session else {}})
        return sorted(output, key=lambda item: (str(item["last_seen"]), item["session_id"]), reverse=True)[: max(0, int(limit))]

    def save_session_link(self, link_payload: Dict[str, Any]) -> str:
        a, b = _required(link_payload.get("session_id_a"), "session_id_a"), _required(link_payload.get("session_id_b"), "session_id_b")
        link_type, observable_type, observable_value = str(link_payload.get("link_type") or "shared_observable"), str(link_payload.get("observable_type") or "").lower(), str(link_payload.get("observable_value") or "")
        identity = str(link_payload.get("link_id") or stable_id("sessionlink", {"sessions": sorted([a, b]), "link_type": link_type, "observable_type": observable_type, "observable_value": observable_value}))
        payload = dict(link_payload); payload["link_id"] = identity
        document = {"_id": identity, "schema_version": "mongodb_session_link.v1", "link_id": identity, "session_id": a, "session_id_a": a, "session_id_b": b, "link_type": link_type, "observable_type": observable_type or None, "observable_value": observable_value or None, "confidence": float(link_payload.get("confidence") or 0.0), "payload_json": stable_json(payload), "created_at": str(link_payload.get("created_at") or utc_now())}
        existing = self.database.session_links.find_one({"_id": identity})
        if existing and any(existing.get(key) != document.get(key) for key in ("session_id_a", "session_id_b", "link_type", "observable_type", "observable_value")):
            raise StorageError("conflicting session link identity")
        self.database.session_links.replace_one({"_id": identity}, document, upsert=True)
        return identity

    def list_session_links(self, session_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        output = []
        for document in self.database.session_links.find({"$or": [{"session_id_a": session_id}, {"session_id_b": session_id}]}).sort([("created_at", -1), ("link_id", 1)]).limit(max(0, int(limit))):
            item = _row(document) or {}; item["payload"] = _payload(item); output.append(item)
        return output

    def save_campaign(self, campaign: Dict[str, Any]) -> str:
        identity = _required(campaign.get("campaign_id"), "campaign_id")
        current = utc_now(); payload = dict(campaign)
        document = {"_id": identity, "schema_version": "mongodb_campaign.v1", "campaign_id": identity, **{key: campaign.get(key) or "" for key in ("primary_fingerprint_type", "primary_fingerprint_value", "hassh_fingerprint", "ja3_fingerprint", "tactic_sequence_hash", "command_pattern_hash", "source_ip")}, "session_count": int(campaign.get("session_count") or 0), "first_seen": campaign.get("first_seen") or current, "last_seen": campaign.get("last_seen") or current, "confirmed_tactics_json": stable_json(campaign.get("confirmed_tactics") or []), "max_confirmed_severity": campaign.get("max_confirmed_severity") or "info", "payload_json": stable_json(payload), "created_at": campaign.get("created_at") or current, "updated_at": current}
        old = self.database.campaigns.find_one({"_id": identity})
        if old:
            document["created_at"] = old.get("created_at", document["created_at"])
            document["first_seen"] = min(str(old.get("first_seen") or document["first_seen"]), str(document["first_seen"]))
            document["last_seen"] = max(str(old.get("last_seen") or document["last_seen"]), str(document["last_seen"]))
        self.database.campaigns.replace_one({"_id": identity}, document, upsert=True)
        return identity

    def get_campaign(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        item = _row(self.database.campaigns.find_one({"_id": str(campaign_id)}))
        if item is not None:
            item["payload"] = _payload(item); item["confirmed_tactics"] = json.loads(str(item.get("confirmed_tactics_json") or "[]"))
        return item

    def find_matching_campaigns(self, fingerprint: Dict[str, Any], limit: int = 20) -> List[Dict[str, Any]]:
        clauses = []
        for field, source in (("hassh_fingerprint", "hassh_fingerprint"), ("ja3_fingerprint", "ja3_fingerprint"), ("command_pattern_hash", "command_pattern_hash"), ("tactic_sequence_hash", "tactic_sequence_hash"), ("source_ip", "src_ip")):
            value = str(fingerprint.get(source) or "").strip()
            if value and value.lower() != "unknown": clauses.append({field: value})
        if not clauses: return []
        return [self.get_campaign(document["campaign_id"]) for document in self.database.campaigns.find({"$or": clauses}).sort([("updated_at", -1), ("campaign_id", 1)]).limit(max(0, int(limit)))]

    def link_campaign_session(self, campaign_id: str, session_id: str, match_reasons: Optional[List[str]] = None, confidence: float = 0.0, payload: Optional[Dict[str, Any]] = None) -> tuple[str, bool]:
        identity = stable_id("campaignsession", {"campaign_id": campaign_id, "session_id": session_id})
        body = dict(payload or {}); body.update({"campaign_id": campaign_id, "session_id": session_id})
        document = {"_id": identity, "schema_version": "mongodb_campaign_session.v1", "link_id": identity, "campaign_id": campaign_id, "session_id": session_id, "match_reasons_json": stable_json(list(match_reasons or [])), "confidence": float(confidence or 0.0), "payload_json": stable_json(body), "created_at": utc_now()}
        self.database.campaign_sessions.update_one(
            {"_id": identity},
            {
                "$setOnInsert": {
                    "schema_version": document["schema_version"],
                    "link_id": identity,
                    "campaign_id": campaign_id,
                    "session_id": session_id,
                    "created_at": document["created_at"],
                },
                "$set": {
                    "match_reasons_json": document["match_reasons_json"],
                    "confidence": document["confidence"],
                    "payload_json": document["payload_json"],
                },
            },
            upsert=True,
        )
        return identity, True

    def count_campaign_sessions(self, campaign_id: str) -> int:
        return self.database.campaign_sessions.count_documents({"campaign_id": campaign_id})

    def _campaign_links(self, query: Dict[str, Any], limit: int) -> List[Dict[str, Any]]:
        output = []
        for document in self.database.campaign_sessions.find(query).sort([("created_at", -1), ("link_id", 1)]).limit(max(0, int(limit))):
            item = _row(document) or {}; item["payload"] = _payload(item); item["match_reasons"] = json.loads(str(item.get("match_reasons_json") or "[]")); output.append(item)
        return output

    def list_campaign_sessions(self, campaign_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        return self._campaign_links({"campaign_id": campaign_id}, limit)

    def list_session_campaigns(self, session_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        output = self._campaign_links({"session_id": session_id}, limit)
        for item in output:
            campaign = self.get_campaign(item["campaign_id"]); item["campaign_payload"] = campaign["payload"] if campaign else {}; item["max_confirmed_severity"] = campaign.get("max_confirmed_severity") if campaign else None; item["session_count"] = campaign.get("session_count") if campaign else None
        return output

    # Prediction ----------------------------------------------------------

    def enqueue_prediction_outbox(self, payload: Dict[str, Any]) -> str:
        event_id, session_id = _required(payload.get("event_id"), "event_id"), _required(payload.get("session_id"), "session_id")
        identity = stable_id("prediction_outbox", {"event_id": event_id, "session_id": session_id, "prediction_mode": payload.get("prediction_mode") or ""})
        current = utc_now(); body = stable_json(payload)
        document = {"_id": identity, "schema_version": "mongodb_prediction_outbox.v1", "outbox_id": identity, "job_id": identity, "event_id": event_id, "session_id": session_id, "status": "queued", "payload_json": body, "payload_sha256": hashlib.sha256(body.encode()).hexdigest(), "attempts": 0, "created_at": current, "updated_at": current, "next_retry_at": None, "claim_owner": None, "claim_token": None, "claim_expires_at": None}
        self._exact_insert("prediction_outbox", identity, document, compare=("event_id", "session_id", "payload_json"))
        return identity

    def claim_prediction_outbox(self, owner: str, limit: int, lease_seconds: float, max_attempts: int, *, now: Any = None) -> List[Dict[str, Any]]:
        collection = self.database.prediction_outbox; current = _utc(now); attempt_limit = int(max_attempts)
        if attempt_limit < 1: raise ValueError("max_attempts must be positive")
        collection.update_many({"attempts": {"$gte": attempt_limit}, "status": {"$in": ["queued", "retry", "in_progress"]}, "$or": [{"status": {"$ne": "in_progress"}}, {"claim_expires_at": None}, {"claim_expires_at": {"$lte": current}}]}, {"$set": {"status": "dead_letter", "last_error_code": "prediction_attempts_exhausted", "last_error_type": "RetryLimitExceeded", "last_error_at": current, "updated_at": current}, "$unset": {"claim_owner": "", "claim_token": "", "claim_expires_at": ""}})
        output = []
        for _ in range(max(0, int(limit))):
            token = str(uuid.uuid4())
            row = collection.find_one_and_update({"attempts": {"$lt": attempt_limit}, "$and": [{"status": {"$in": ["queued", "retry", "in_progress"]}}, {"$or": [{"next_retry_at": None}, {"next_retry_at": {"$lte": current}}]}, {"$or": [{"status": {"$ne": "in_progress"}}, {"claim_expires_at": None}, {"claim_expires_at": {"$lte": current}}]}]}, {"$set": {"status": "in_progress", "claim_owner": _required(owner, "owner"), "claim_token": token, "claim_expires_at": _future(current, lease_seconds), "updated_at": current}, "$inc": {"attempts": 1}}, sort=[("created_at", 1), ("outbox_id", 1)], return_document=self._return_document_after())
            if row is None: break
            try: task = _payload(row)
            except StorageError:
                collection.update_one({"_id": row["_id"], "claim_token": token}, {"$set": {"status": "dead_letter", "last_error_code": "prediction_task_invalid", "last_error_type": "ValidationError", "last_error_at": current, "updated_at": current}, "$unset": {"claim_owner": "", "claim_token": "", "claim_expires_at": ""}}); continue
            output.append({"outbox_id": row["outbox_id"], "task": task, "attempts": int(row.get("attempts", 0)), "claim_owner": row["claim_owner"], "claim_token": token, "claim_expires_at": row["claim_expires_at"]})
        return output

    def complete_prediction_outbox(self, outbox_id: str, owner: str, token: str, snapshot_id: str, *, now: Any = None) -> bool:
        current = _utc(now)
        result = self.database.prediction_outbox.update_one({"_id": _required(outbox_id, "outbox_id"), "status": "in_progress", "claim_owner": _required(owner, "owner"), "claim_token": _token(token), "claim_expires_at": {"$gt": current}}, {"$set": {"status": "completed", "snapshot_id": _required(snapshot_id, "snapshot_id"), "completed_at": current, "updated_at": current}, "$unset": {"next_retry_at": "", "claim_owner": "", "claim_token": "", "claim_expires_at": "", "last_error_code": "", "last_error_type": "", "last_error_at": ""}})
        return result.modified_count == 1

    def fail_prediction_outbox(self, outbox_id: str, owner: str, token: str, error_code: str, error_type: str, retryable: bool, max_attempts: int, retry_delay_seconds: float, *, now: Any = None) -> str:
        current = _utc(now); query = {"_id": _required(outbox_id, "outbox_id"), "status": "in_progress", "claim_owner": _required(owner, "owner"), "claim_token": _token(token), "claim_expires_at": {"$gt": current}}
        row = self.database.prediction_outbox.find_one(query, {"attempts": 1})
        if row is None: return "lost_claim"
        retry = bool(retryable) and int(row.get("attempts", 0)) < int(max_attempts); status = "retry" if retry else "dead_letter"
        result = self.database.prediction_outbox.update_one(query, {"$set": {"status": status, "next_retry_at": _retry_at(current, retry_delay_seconds) if retry else None, "last_error_code": _required(error_code, "error_code"), "last_error_type": _required(error_type, "error_type"), "last_error_at": current, "updated_at": current}, "$unset": {"claim_owner": "", "claim_token": "", "claim_expires_at": ""}})
        return status if result.modified_count == 1 else "lost_claim"

    def save_prediction_snapshot(self, snapshot: Dict[str, Any]) -> str:
        identity = str(snapshot.get("snapshot_id") or stable_id("predsnap", snapshot)); is_v3 = snapshot.get("schema_version") == SNAPSHOT_SCHEMA_VERSION
        normalized = require_valid_prediction_snapshot(snapshot) if is_v3 else dict(snapshot); identity = str(normalized.get("snapshot_id") or identity)
        cutoff = normalized.get("evidence_cutoff")
        if cutoff is not None:
            cutoff = require_valid_evidence_cutoff(cutoff)
            if str(normalized.get("event_id") or "") != cutoff["event_id"]: raise StorageError("prediction event_id does not match its evidence cutoff")
        body = stable_json(normalized); existing = self.database.prediction_snapshots.find_one({"_id": identity})
        if existing:
            old = _payload(existing)
            if is_v3:
                require_valid_prediction_snapshot(old)
                if canonical_prediction_content(old) != canonical_prediction_content(normalized): raise PredictionSnapshotIntegrityError("snapshot_id already stores different canonical content")
                return identity
        document = {"_id": identity, "schema_version": "mongodb_prediction_snapshot.v1", "snapshot_id": identity, "session_id": str(normalized.get("session_id", "unknown")), "src_ip": str(normalized.get("src_ip", "unknown")), "session_status": str(normalized.get("session_status", "active")), "event_id": str(normalized.get("event_id", "")), "features_hash": str(normalized.get("features_hash", "")), "payload_json": body, "payload_sha256": hashlib.sha256(body.encode()).hexdigest(), "created_at": str(normalized.get("generated_at") or utc_now())}
        if existing and existing.get("payload_json") != body and is_v3: raise PredictionSnapshotIntegrityError("snapshot identity conflict")
        self.database.prediction_snapshots.replace_one({"_id": identity}, document, upsert=True)
        return identity

    @staticmethod
    def _prediction_order(item: Mapping[str, Any]) -> tuple[Any, ...]:
        payload = item.get("payload") if isinstance(item.get("payload"), Mapping) else {}
        cutoff = payload.get("evidence_cutoff") if isinstance(payload, Mapping) else None
        if isinstance(cutoff, Mapping):
            try: return (1, *evidence_cutoff_sort_key(cutoff), str(item.get("snapshot_id") or ""))
            except Exception: pass
        return (0, str(item.get("created_at") or ""), str(item.get("snapshot_id") or ""))

    def list_prediction_snapshots_for_session(self, session_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        output = []
        for document in self.database.prediction_snapshots.find(
            {"session_id": session_id},
            _SESSION_DETAIL_PROJECTION,
        ):
            item = _row(document) or {}; item["payload"] = _payload(item); item["integrity_errors"] = validate_prediction_snapshot_integrity(item["payload"]) if item["payload"].get("schema_version") == SNAPSHOT_SCHEMA_VERSION else []; output.append(item)
        output.sort(key=self._prediction_order, reverse=True); return output[: max(0, int(limit))]

    def list_dashboard_session_detail_prediction_snapshots(self, session_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Return a bounded, indexed session-detail snapshot window.

        The worker-facing history method above intentionally preserves the full
        evidence-order semantics. Dashboard detail only needs a bounded recent
        window, so use the existing session/created_at index before applying
        the canonical evidence ordering to that fixed window.
        """
        bounded_limit = min(max(0, int(limit)), 50)
        if bounded_limit == 0:
            return []
        cursor = self.database.prediction_snapshots.find(
            {"session_id": session_id},
            _SESSION_DETAIL_PROJECTION,
        ).sort([("created_at", -1), ("snapshot_id", 1)]).limit(
            _SESSION_DETAIL_PREDICTION_SCAN_LIMIT
        )
        output = []
        for document in cursor:
            item = _row(document) or {}; item["payload"] = _payload(item); item["integrity_errors"] = validate_prediction_snapshot_integrity(item["payload"]) if item["payload"].get("schema_version") == SNAPSHOT_SCHEMA_VERSION else []; output.append(item)
        output.sort(key=self._prediction_order, reverse=True)
        return output[:bounded_limit]

    def get_current_prediction_snapshot(self, session_id: str) -> Optional[Dict[str, Any]]:
        rows = self.list_prediction_snapshots_for_session(session_id, 1); return rows[0] if rows and self._prediction_order(rows[0])[0] >= 0 else None

    def get_latest_prediction_snapshot(self, session_id: str) -> Optional[Dict[str, Any]]:
        return self.get_current_prediction_snapshot(session_id)

    def get_prediction_snapshot(self, snapshot_id: str) -> Optional[Dict[str, Any]]:
        item = _row(self.database.prediction_snapshots.find_one({"_id": str(snapshot_id)}))
        if item is not None: item["payload"] = _payload(item); item["integrity_errors"] = validate_prediction_snapshot_integrity(item["payload"]) if item["payload"].get("schema_version") == SNAPSHOT_SCHEMA_VERSION else []
        return item

    def prune_prediction_snapshots(self, retention_days: int = 90, keep_latest_per_session: bool = True, now: Optional[str] = None, dry_run: bool = True) -> Dict[str, Any]:
        current = datetime.fromisoformat(_utc(now)); cutoff = (current - timedelta(days=max(0, int(retention_days)))).isoformat(timespec="microseconds")
        rows = list(self.database.prediction_snapshots.find({}).sort([("created_at", -1), ("snapshot_id", 1)])); keep = set()
        if keep_latest_per_session:
            sessions = set()
            for row in rows:
                if row.get("session_id") not in sessions: keep.add(row["_id"]); sessions.add(row.get("session_id"))
        delete = [row["_id"] for row in rows if row["_id"] not in keep and str(row.get("created_at") or "") < cutoff]
        if delete and not dry_run: self.database.prediction_snapshots.delete_many({"_id": {"$in": delete}})
        return {"dry_run": bool(dry_run), "cutoff": cutoff, "candidate_count": len(delete), "deleted_count": 0 if dry_run else len(delete), "kept_latest_count": len(keep), "total_count": len(rows)}

    def _save_run(self, collection: str, prefix: str, result: Dict[str, Any]) -> str:
        identity = str(result.get("run_id") or stable_id(prefix, result)); body = stable_json(result)
        document = {"_id": identity, "schema_version": f"mongodb_{collection[:-1]}.v1", "run_id": identity, "payload_json": body, "payload_sha256": hashlib.sha256(body.encode()).hexdigest(), "created_at": str(result.get("created_at") or utc_now())}
        self._exact_insert(collection, identity, document, compare=("payload_json",)); return identity

    def save_prediction_backtest_run(self, result: Dict[str, Any]) -> str:
        return self._save_run("prediction_backtest_runs", "predbacktest", result)

    def save_prediction_calibration_run(self, result: Dict[str, Any]) -> str:
        return self._save_run("prediction_calibration_runs", "predcal", result)

    def record_data_lifecycle_policy(self, *, policy_id: str, policy_version: str, policy_sha256: str, effective_path: str, activated_at: Any = None) -> bool:
        digest = str(policy_sha256 or "").strip().lower()
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest): raise ValueError("policy_sha256 must be a lowercase SHA-256 digest")
        document = {"_id": digest, "schema_version": "mongodb_lifecycle_ledger.v1", "policy_sha256": digest, "policy_id": _required(policy_id, "policy_id"), "policy_version": _required(policy_version, "policy_version"), "effective_path": _required(effective_path, "effective_path"), "activated_at": _utc(activated_at)}
        return self._exact_insert("lifecycle_ledger", digest, document, compare=("policy_id", "policy_version"))

    # Feedback, review, and bounded read projections ---------------------

    def record_analyst_feedback(self, feedback: Dict[str, Any]) -> str:
        normalized = normalize_feedback_payload(feedback)
        identity = str(normalized.get("feedback_id") or stable_id("feedback", normalized)); body = stable_json(normalized)
        document = {"_id": identity, "schema_version": "mongodb_analyst_feedback.v1", "feedback_id": identity, "session_id": str(normalized.get("session_id") or "unknown"), "payload_json": body, "payload_sha256": hashlib.sha256(body.encode()).hexdigest(), "created_at": str(normalized.get("created_at") or utc_now())}
        self._exact_insert("analyst_feedback", identity, document, compare=("session_id", "payload_json")); return identity

    def record_classification_review_label(self, label: Dict[str, Any]) -> str:
        identity = str(label.get("label_id") or stable_id("classlabel", label)); body = stable_json(label)
        document = {"_id": identity, "schema_version": "mongodb_classification_review_label.v1", "label_id": identity, "session_id": str(label.get("session_id") or "unknown"), "payload_json": body, "payload_sha256": hashlib.sha256(body.encode()).hexdigest(), "created_at": str(label.get("created_at") or utc_now())}
        self._exact_insert("classification_review_labels", identity, document, compare=("session_id", "payload_json")); return identity

    def list_classification_review_labels(self, limit: int = 1000) -> List[Dict[str, Any]]:
        return [(_row(item) or {}) | {"payload": _payload(item)} for item in self.database.classification_review_labels.find({}).sort([("created_at", -1), ("label_id", 1)]).limit(max(0, int(limit)))]

    def list_rows(self, table: str, limit: int = 100) -> List[Dict[str, Any]]:
        allowed = {item["name"] for item in self.manifest.collections}
        if table not in allowed: raise ValueError("unsupported collection")
        return [_row(item) or {} for item in self.database[table].find({}).sort([("_id", 1)]).limit(max(0, int(limit)))]

    def list_rows_for_session(self, table: str, session_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        if table not in _SESSION_TABLES: raise ValueError("unsupported session-scoped table")
        query = {"_id": session_id} if table == "sessions" else {"session_id": session_id}
        cursor = self.database[table].find(query, _SESSION_DETAIL_PROJECTION)
        sort_order = _SESSION_DETAIL_MONGO_SORTS.get(
            table,
            [("created_at", -1), ("_id", 1)],
        )
        if table != "sessions":
            cursor = cursor.sort(sort_order)
        rows = [_row(item) or {} for item in cursor.limit(max(0, int(limit)))]
        return rows

    def list_session_rows(self, limit: int = 100, session_source: str | None = SESSION_SOURCE_PRODUCTION_LIVE, external_only: bool = False) -> List[Dict[str, Any]]:
        query: Dict[str, Any] = {}
        if session_source is not None: query["session_source"] = normalize_session_source(session_source)
        if external_only: query["is_external_source"] = True
        return [_row(item) or {} for item in self.database.sessions.find(query).sort([("updated_at", -1), ("session_id", 1)]).limit(max(0, int(limit)))]

    def list_active_session_rows(self, limit: int = 10_000, session_source: str | None = SESSION_SOURCE_PRODUCTION_LIVE) -> List[Dict[str, Any]]:
        query: Dict[str, Any] = {"ended": False}
        if session_source is not None: query["session_source"] = normalize_session_source(session_source)
        return [_row(item) or {} for item in self.database.sessions.find(query).sort([("updated_at", 1), ("session_id", 1)]).limit(max(0, int(limit)))]

    def count_sessions(self, session_source: str | None = SESSION_SOURCE_PRODUCTION_LIVE, external_only: bool = False, ended_only: bool = False) -> int:
        query: Dict[str, Any] = {}
        if session_source is not None: query["session_source"] = normalize_session_source(session_source)
        if external_only: query["is_external_source"] = True
        if ended_only: query["ended"] = True
        return self.database.sessions.count_documents(query)

    # Webhook delivery ----------------------------------------------------

    def pending_webhooks(self, limit: int = 100, *, target_url_hash: str = "", max_attempts: int = 5, now: Any = None) -> List[Dict[str, Any]]:
        current = _utc(now); output = []
        for alert in self.database.alerts.find({}).sort([("created_at", 1), ("alert_id", 1)]):
            if target_url_hash:
                identity = stable_id("delivery", {"alert_id": alert["alert_id"], "report_id": None, "target": target_url_hash})
                delivery = self.database.webhook_deliveries.find_one({"_id": identity})
                if delivery and not (delivery.get("status") in {"pending", "retryable", "failed", "in_progress"} and (int(delivery.get("attempts", 0)) < int(max_attempts) or delivery.get("status") == "in_progress") and (delivery.get("next_retry_at") is None or delivery.get("next_retry_at") <= current) and (delivery.get("claim_token") is None or delivery.get("claim_expires_at") is None or delivery.get("claim_expires_at") <= current)):
                    continue
            elif alert.get("delivered"):
                continue
            output.append({"alert_id": alert["alert_id"], "payload": _payload(alert)})
            if len(output) >= max(0, int(limit)): break
        return output

    def get_webhook_delivery(self, delivery_id: str) -> Optional[Dict[str, Any]]:
        return _row(self.database.webhook_deliveries.find_one({"_id": str(delivery_id)}))

    def claim_webhook_delivery(self, payload: Dict[str, Any], target_url_hash: str, owner: str, lease_seconds: float, max_attempts: int, *, alert_id: Optional[str] = None, report_id: Optional[str] = None, now: Any = None) -> Optional[Dict[str, Any]]:
        target, claim_owner = _required(target_url_hash, "target_url_hash"), _required(owner, "owner")
        if not alert_id and not report_id: raise ValueError("alert_id or report_id is required")
        attempt_limit = int(max_attempts)
        if attempt_limit < 1: raise ValueError("max_attempts must be positive")
        current = _utc(now); identity = stable_id("delivery", {"alert_id": alert_id, "report_id": report_id, "target": target}); body = stable_json(payload)
        self.database.webhook_deliveries.update_one({"_id": identity}, {"$setOnInsert": {"schema_version": "mongodb_webhook_delivery.v1", "delivery_id": identity, "alert_id": alert_id, "report_id": report_id, "target_url_hash": target, "status": "pending", "attempts": 0, "payload_json": body, "created_at": current, "updated_at": current}}, upsert=True)
        self.database.webhook_deliveries.update_one({"_id": identity, "status": "in_progress", "attempts": {"$gte": attempt_limit}, "$or": [{"claim_expires_at": None}, {"claim_expires_at": {"$lte": current}}]}, {"$set": {"status": "permanent_failure", "error_code": "webhook_lease_attempts_exhausted", "last_error": "delivery attempt budget exhausted after lease expiry", "completed_at": current, "updated_at": current}, "$unset": {"next_retry_at": "", "claim_owner": "", "claim_token": "", "claim_expires_at": ""}})
        token = str(uuid.uuid4())
        row = self.database.webhook_deliveries.find_one_and_update({"_id": identity, "status": {"$in": ["pending", "retryable", "failed", "in_progress"]}, "attempts": {"$lt": attempt_limit}, "$and": [{"$or": [{"next_retry_at": None}, {"next_retry_at": {"$lte": current}}]}, {"$or": [{"claim_token": None}, {"claim_expires_at": None}, {"claim_expires_at": {"$lte": current}}]}]}, {"$set": {"status": "in_progress", "payload_json": body, "claim_owner": claim_owner, "claim_token": token, "claim_expires_at": _future(current, lease_seconds), "updated_at": current}, "$unset": {"next_retry_at": "", "error_code": "", "last_error": "", "completed_at": ""}, "$inc": {"attempts": 1}}, return_document=self._return_document_after())
        result = _row(row)
        if result is not None: result["payload"] = _payload(result)
        return result

    def complete_webhook_delivery(self, delivery_id: str, owner: str, token: str, status: str, *, error_code: str = "", error: str = "", response_status: Optional[int] = None, response_body_sha256: str = "", response_body_bytes: int = 0, response_body_truncated: bool = False, next_retry_at: Any = None, now: Any = None) -> bool:
        outcome, code, safe_error, response_status, digest, body_bytes, truncated = validate_webhook_completion_fields(status, error_code, error, response_status, response_body_sha256, response_body_bytes, response_body_truncated)
        retry_at = _utc(next_retry_at) if next_retry_at is not None else None
        if outcome == "retryable" and retry_at is None: raise ValueError("retryable webhook completion requires next_retry_at")
        if outcome != "retryable" and retry_at is not None: raise ValueError("next_retry_at is only valid for retryable completion")
        current = _utc(now)
        result = self.database.webhook_deliveries.update_one({"_id": _required(delivery_id, "delivery_id"), "status": "in_progress", "claim_owner": _required(owner, "owner"), "claim_token": _token(token), "claim_expires_at": {"$gt": current}}, {"$set": {"status": outcome, "error_code": code or None, "last_error": safe_error or None, "response_status": response_status, "response_body_sha256": digest or None, "response_body_bytes": body_bytes, "response_body_truncated": bool(truncated), "next_retry_at": retry_at, "completed_at": None if outcome == "retryable" else current, "updated_at": current}, "$unset": {"claim_owner": "", "claim_token": "", "claim_expires_at": ""}})
        if result.modified_count == 1 and outcome == "delivered":
            delivery = self.database.webhook_deliveries.find_one({"_id": delivery_id}, {"alert_id": 1})
            if delivery and delivery.get("alert_id"): self.database.alerts.update_one({"_id": delivery["alert_id"]}, {"$set": {"delivered": True}})
        return result.modified_count == 1

    def record_webhook_delivery(self, payload: Dict[str, Any], target_url_hash: str, status: str, error: str = "", alert_id: Optional[str] = None, report_id: Optional[str] = None) -> str:
        key: Dict[str, Any] = {"alert_id": alert_id, "report_id": report_id, "target": target_url_hash}
        if not alert_id and not report_id: key["payload"] = payload
        identity = stable_id("delivery", key); current = utc_now(); old = self.database.webhook_deliveries.find_one({"_id": identity}, {"attempts": 1, "created_at": 1})
        self.database.webhook_deliveries.replace_one({"_id": identity}, {"_id": identity, "schema_version": "mongodb_webhook_delivery.v1", "delivery_id": identity, "alert_id": alert_id, "report_id": report_id, "target_url_hash": target_url_hash, "status": status, "attempts": int(old.get("attempts", 0) if old else 0) + 1, "last_error": redact_error_for_log(error) if error else "", "payload_json": stable_json(payload), "created_at": old.get("created_at") if old else current, "updated_at": current}, upsert=True)
        if alert_id and status in {"succeeded", "delivered"}: self.database.alerts.update_one({"_id": alert_id}, {"$set": {"delivered": True}})
        return identity
