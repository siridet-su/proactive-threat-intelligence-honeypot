"""Read-only capacity-aware retention planning."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence

from .cold_archive import canonical_ejson_dumps, mongo_capacity_status
from .retention_policy import (
    CollectionPolicy,
    RetentionConfig,
    capacity_state,
    capacity_state_with_hysteresis,
    lifecycle_document_is_safe,
    lifecycle_query,
    required_reclaim_bytes,
    target_ratio_for_state,
)


class RetentionPlanningError(RuntimeError):
    pass


def _id_token(value: Any) -> str:
    try:
        return canonical_ejson_dumps(value)
    except Exception:
        return repr(value)


def _id_hash(value: Any) -> str:
    return hashlib.sha256(_id_token(value).encode("utf-8")).hexdigest()[:16]


def _document_size(document: Mapping[str, Any]) -> tuple[int, str]:
    try:
        from bson import BSON  # type: ignore[import-not-found]

        return len(BSON.encode(dict(document))), "bson_document_bytes"
    except Exception:
        return len((canonical_ejson_dumps(document) + "\n").encode("utf-8")), "canonical_ejson_bytes_fallback"


def _timestamp_text(value: Any) -> str | None:
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _safe_float(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True)
class RetentionPlan:
    payload: Mapping[str, Any]
    selected: tuple[Mapping[str, Any], ...]
    selected_by_collection: Mapping[str, tuple[Mapping[str, Any], ...]]

    @property
    def status(self) -> str:
        return str(self.payload["status"])

    @property
    def run_id(self) -> str:
        return str(self.payload["run_id"])

    def as_dict(self) -> dict[str, Any]:
        return dict(self.payload)


def _collection_plan(
    collection: Any,
    policy: CollectionPolicy,
    *,
    now: datetime,
    max_scan_documents: int,
) -> tuple[dict[str, Any], list[Mapping[str, Any]]]:
    base = {
        "collection": policy.collection,
        "classification": policy.classification,
        "archive_eligible": policy.archive_eligible,
        "auto_archive_eligible": policy.auto_archive_eligible,
        "purge_eligible": policy.purge_eligible,
        "auto_purge_eligible": policy.auto_purge_eligible,
        "primary_time_field": policy.primary_time_field,
        "hot_window_days": policy.hot_window_days,
        "required_terminal_fields": list(policy.required_terminal_fields),
        "dependencies": list(policy.dependencies),
        "manual_review_required": policy.manual_review_required,
        "source_match_count": 0,
        "scanned_count": 0,
        "eligible_count": 0,
        "estimated_eligible_bytes": 0,
        "estimated_bytes_method": None,
        "oldest_eligible_timestamp": None,
        "newest_eligible_timestamp": None,
        "bounded_scan": True,
        "status": "NOT_ELIGIBLE",
        "reason": None,
    }
    if not policy.archive_eligible:
        base["reason"] = "POLICY_NOT_ARCHIVE_ELIGIBLE"
        return base, []
    if not policy.primary_time_field or policy.hot_window_days is None:
        base["status"] = "REVIEW_REQUIRED"
        base["reason"] = "TYPE_CORRECT_TIME_FIELD_OR_HOT_WINDOW_UNAVAILABLE"
        return base, []
    cutoff = now - timedelta(days=policy.hot_window_days)
    query = lifecycle_query(policy, cutoff=cutoff)
    if query is None:
        base["status"] = "REVIEW_REQUIRED"
        base["reason"] = "LIFECYCLE_QUERY_UNRESOLVED"
        return base, []
    # Receipts are JSON, while the live predicate contains a BSON datetime.
    # Keep the executable predicate separate and store canonical EJSON in the
    # plan so hashing and durable receipt writes remain deterministic.
    base["selection_query"] = json.loads(canonical_ejson_dumps(query))
    source_count = int(collection.count_documents(query))
    base["source_match_count"] = source_count
    if not policy.auto_archive_eligible:
        base["status"] = "MANUAL_REVIEW_ONLY"
        base["reason"] = "AUTOMATIC_ARCHIVE_DISABLED_BY_COLLECTION_POLICY"
        return base, []
    cursor = collection.find(query).sort(
        [[policy.primary_time_field, 1], ["_id", 1]]
    )
    candidates: list[Mapping[str, Any]] = []
    estimated_bytes = 0
    method: str | None = None
    oldest: str | None = None
    newest: str | None = None
    for document in cursor:
        if len(candidates) >= max_scan_documents:
            break
        if not isinstance(document, Mapping) or "_id" not in document:
            raise RetentionPlanningError(f"{policy.collection} returned a document without _id")
        base["scanned_count"] += 1
        if not lifecycle_document_is_safe(policy, document):
            continue
        size, method = _document_size(document)
        timestamp = _timestamp_text(document.get(policy.primary_time_field))
        if oldest is None:
            oldest = timestamp
        newest = timestamp
        estimated_bytes += size
        candidates.append(
            {
                "collection": policy.collection,
                "document": document,
                "document_id": document["_id"],
                "document_id_hash_prefix": _id_hash(document["_id"]),
                "timestamp": timestamp,
                "estimated_bytes": size,
            }
        )
    base["eligible_count"] = len(candidates)
    base["estimated_eligible_bytes"] = estimated_bytes
    base["estimated_bytes_method"] = method
    base["oldest_eligible_timestamp"] = oldest
    base["newest_eligible_timestamp"] = newest
    base["bounded_scan"] = source_count <= max_scan_documents
    base["status"] = "ELIGIBLE" if candidates else "NO_ELIGIBLE_RECORDS"
    if source_count > max_scan_documents:
        base["reason"] = "SCAN_BOUND_REACHED"
    return base, candidates


def _run_id(config: RetentionConfig, payload: Mapping[str, Any]) -> str:
    seed = {
        "policy_sha256": config.policy_sha256,
        "target": config.target.as_dict(),
        "state": payload.get("capacity_state"),
        "required_reclaim_bytes": payload.get("required_reclaim_bytes"),
        "selected": [
            {
                "collection": item.get("collection"),
                "document_id_hash_prefix": item.get("document_id_hash_prefix"),
                "estimated_bytes": item.get("estimated_bytes"),
                "timestamp": item.get("timestamp"),
            }
            for item in payload.get("selection_preview", [])
        ],
    }
    return "retention_" + hashlib.sha256(
        json.dumps(seed, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:40]


def plan_retention(
    database: Any,
    config: RetentionConfig,
    *,
    now: datetime | None = None,
    capacity: Mapping[str, Any] | None = None,
    collection_names: Sequence[str] | None = None,
    previous_capacity_state: str | None = None,
) -> RetentionPlan:
    """Produce a bounded, non-destructive retention plan."""

    observed_at = now or datetime.now(timezone.utc)
    if observed_at.tzinfo is None:
        observed_at = observed_at.replace(tzinfo=timezone.utc)
    if capacity is None:
        capacity_payload = mongo_capacity_status(
            database,
            tier_limit_bytes=config.capacity.quota_bytes,
            policy_thresholds={
                "warning": config.capacity.warning_ratio,
                "critical": config.capacity.high_ratio,
                "emergency": config.capacity.critical_ratio,
            },
        )
    else:
        capacity_payload = dict(capacity)
    has_logical_metric = any(
        key in capacity_payload
        for key in ("logical_data_plus_index_bytes", "data_bytes", "index_bytes")
    )
    logical_bytes = int(
        capacity_payload.get(
            "logical_data_plus_index_bytes",
            int(capacity_payload.get("data_bytes", 0)) + int(capacity_payload.get("index_bytes", 0)),
        )
    )
    quota_bytes = int(capacity_payload.get("tier_limit_bytes") or config.capacity.quota_bytes)
    used_ratio = _safe_float(capacity_payload.get("used_ratio"))
    if used_ratio is None and quota_bytes and has_logical_metric:
        used_ratio = logical_bytes / quota_bytes
    instantaneous_state = capacity_state(used_ratio, config.capacity)
    state = capacity_state_with_hysteresis(
        used_ratio,
        config.capacity,
        previous_state=previous_capacity_state,
    )
    capacity_unresolved = used_ratio is None
    target_ratio = target_ratio_for_state(state, config.capacity)
    required_bytes = required_reclaim_bytes(logical_bytes, quota_bytes, state, config.capacity)
    bounded_required_bytes = min(required_bytes, config.capacity.max_logical_bytes_per_cycle)
    names = list(collection_names or sorted(database.list_collection_names()))
    raw_collection_plans: list[dict[str, Any]] = []
    all_candidates: list[Mapping[str, Any]] = []
    max_scan = max(
        config.capacity.max_documents_per_cycle,
        config.capacity.max_documents_per_cycle * 2,
    )
    for name in names:
        policy = config.policy_for(name)
        if policy is None:
            raw_collection_plans.append(
                {
                    "collection": name,
                    "status": "REVIEW_REQUIRED",
                    "reason": "COLLECTION_POLICY_UNRESOLVED",
                    "archive_eligible": False,
                    "auto_archive_eligible": False,
                    "purge_eligible": False,
                    "auto_purge_eligible": False,
                }
            )
            continue
        item, candidates = _collection_plan(
            database[name],
            policy,
            now=observed_at,
            max_scan_documents=max_scan,
        )
        raw_collection_plans.append(item)
        all_candidates.extend(candidates)
    all_candidates.sort(
        key=lambda item: (
            str(item.get("timestamp") or "9999-12-31T23:59:59+00:00"),
            str(item.get("collection")),
            _id_token(item.get("document_id")),
        )
    )
    max_documents = min(
        config.capacity.max_documents_per_cycle,
        config.capacity.max_batches_per_run * config.capacity.batch_size_documents,
    )
    selected: list[Mapping[str, Any]] = []
    selected_bytes = 0
    if not capacity_unresolved and state in {"HIGH", "CRITICAL"} and bounded_required_bytes > 0:
        for candidate in all_candidates:
            if len(selected) >= max_documents:
                break
            if selected_bytes >= bounded_required_bytes:
                break
            if selected_bytes + int(candidate["estimated_bytes"]) > config.capacity.max_logical_bytes_per_cycle:
                break
            selected.append(candidate)
            selected_bytes += int(candidate["estimated_bytes"])
    selection_preview = [
        {
            "collection": item["collection"],
            "document_id_hash_prefix": item["document_id_hash_prefix"],
            "timestamp": item["timestamp"],
            "estimated_bytes": item["estimated_bytes"],
        }
        for item in selected
    ]
    selected_by_collection: dict[str, list[Mapping[str, Any]]] = {}
    for item in selected:
        selected_by_collection.setdefault(str(item["collection"]), []).append(item)
    collection_payload_by_name = {str(item["collection"]): item for item in raw_collection_plans}
    for name, items in selected_by_collection.items():
        collection_payload_by_name[name]["recommended_document_count"] = len(items)
        collection_payload_by_name[name]["recommended_archive_bytes"] = sum(
            int(item["estimated_bytes"]) for item in items
        )
    for item in raw_collection_plans:
        item.setdefault("recommended_document_count", 0)
        item.setdefault("recommended_archive_bytes", 0)
    projected_logical = max(0, logical_bytes - selected_bytes)
    projected_ratio = projected_logical / quota_bytes if quota_bytes else None
    payload: dict[str, Any] = {
        "schema_version": "mongo_pi_retention_plan.v1",
        "status": (
            "CAPACITY_UNRESOLVED"
            if capacity_unresolved
            else "NO_ACTION"
            if state == "NORMAL"
            else "PLAN_ONLY"
            if state == "WARNING"
            else "ACTIONABLE_PLAN"
            if selected
            else "NO_ELIGIBLE_DATA"
        ),
        "observed_at_utc": observed_at.astimezone(timezone.utc).isoformat(),
        "target": config.target.as_dict(),
        "policy_id": config.policy_id,
        "policy_sha256": config.policy_sha256,
        "capacity_state": state,
        "instantaneous_capacity_state": instantaneous_state,
        "previous_capacity_state": previous_capacity_state,
        "hysteresis": {
            "recovery_target_ratio": config.capacity.recovery_target_ratio,
            "rearm_condition": "used_ratio <= recovery_target_ratio after HIGH/CRITICAL action",
        },
        "current_used_ratio": round(used_ratio, 8) if used_ratio is not None else None,
        "capacity_unresolved": capacity_unresolved,
        "current_logical_data_plus_index_bytes": logical_bytes,
        "tier_limit_bytes": quota_bytes,
        "current_headroom_bytes": quota_bytes - logical_bytes,
        "threshold_crossed": (
            None
            if state == "NORMAL"
            else config.capacity.warning_ratio
            if state == "WARNING"
            else config.capacity.high_ratio
            if state == "HIGH"
            else config.capacity.critical_ratio
        ),
        "target_utilization_ratio": target_ratio,
        "required_reclaim_bytes": required_bytes,
        "bounded_reclaim_bytes": bounded_required_bytes,
        "estimated_selected_archive_bytes": selected_bytes,
        "recommended_document_count": len(selected),
        "projected_logical_data_plus_index_bytes": projected_logical,
        "projected_used_ratio": round(projected_ratio, 8) if projected_ratio is not None else None,
        "limits": config.capacity.as_dict(),
        "capacity_before": dict(capacity_payload),
        "selection_order": "oldest_first_by_type_correct_time_then_collection_then_canonical_id",
        "selection_is_deterministic": True,
        "lifecycle_requires_age_and_terminal_state": True,
        "collection_plans": raw_collection_plans,
        "selection_preview": selection_preview,
        "automatic_purge": config.automatic_purge,
        "mutations_performed": False,
    }
    payload["run_id"] = _run_id(config, payload)
    return RetentionPlan(
        payload=payload,
        selected=tuple(selected),
        selected_by_collection={
            name: tuple(items) for name, items in selected_by_collection.items()
        },
    )


__all__ = ["RetentionPlan", "RetentionPlanningError", "plan_retention"]
