"""Deterministic coverage accounting for bounded typed semantic analysis."""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

from production.utils.serialization import stable_json


SCHEMA_VERSION = "typed_semantic_coverage.v1"
SUPPORTED_COVERAGE_STATUSES = frozenset({"full", "unavailable"})
DEFAULT_LIMITS = {
    "max_facts": 2048,
    "max_entities": 8192,
    "max_relationships": 8192,
    "max_chains": 2048,
    "max_command_length": 8192,
    "max_total_command_bytes": 1_048_576,
}


def _sha(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def semantic_observation_counts(observed: Mapping[str, Any]) -> dict[str, int]:
    commands = [
        item
        for item in observed.get("ordered_command_observations") or []
        if isinstance(item, Mapping)
    ]
    transfers = [
        item
        for item in observed.get("transfer_event_observations") or []
        if isinstance(item, Mapping)
    ]
    return {
        "durable_event_count": len(
            (observed.get("durable_event_manifest") or {}).get("event_entries")
            or []
        ),
        "command_observation_count": len(commands),
        "transfer_observation_count": len(transfers),
        "eligible_semantic_observation_count": len(commands) + len(transfers),
        "total_command_bytes": sum(
            len(str(item.get("command") or "").encode("utf-8"))
            for item in commands
        ),
    }


def build_semantic_coverage(
    observed: Mapping[str, Any],
    *,
    limits: Mapping[str, Any] | None = None,
    typed_analyzed_count: int | None = None,
    typed_metrics: Mapping[str, Any] | None = None,
    status: str = "full",
    reason_code: str = "",
    limit_reached: str = "",
) -> dict[str, Any]:
    """Build a content-addressed, non-silent coverage record."""

    effective_limits = {
        key: int(value)
        for key, value in (limits or DEFAULT_LIMITS).items()
        if key in DEFAULT_LIMITS
    }
    effective_limits = {**DEFAULT_LIMITS, **effective_limits}
    counts = semantic_observation_counts(observed)
    eligible = counts["eligible_semantic_observation_count"]
    analyzed = eligible if typed_analyzed_count is None else max(
        0, min(int(typed_analyzed_count), eligible)
    )
    omitted = max(eligible - analyzed, 0)
    # ``partial`` was reserved by the reviewed v1 design for a future
    # versioned streaming/chunking contract.  A v1 builder must never emit it
    # because doing so would make a bounded prefix look like a supported
    # semantic result.  Keep the rejection here (rather than silently
    # coercing) so callers cannot accidentally change the contract.
    if status not in SUPPORTED_COVERAGE_STATUSES:
        raise ValueError("invalid semantic coverage status")
    if status == "unavailable" and typed_analyzed_count is None:
        analyzed = 0
        omitted = eligible
    if status == "full" and omitted:
        raise ValueError("full semantic coverage cannot omit observations")
    if status == "unavailable" and analyzed:
        raise ValueError("unavailable semantic coverage cannot analyze observations")
    result = {
        "schema_version": SCHEMA_VERSION,
        **counts,
        "typed_analyzed_count": analyzed,
        "omitted_count": omitted,
        "typed_fact_count": max(
            0, int((typed_metrics or {}).get("fact_count") or 0)
        ),
        "typed_entity_count": max(
            0, int((typed_metrics or {}).get("entity_count") or 0)
        ),
        "typed_relationship_count": max(
            0, int((typed_metrics or {}).get("relationship_count") or 0)
        ),
        "typed_chain_count": max(
            0, int((typed_metrics or {}).get("chain_count") or 0)
        ),
        "coverage_status": status,
        "configured_limits": effective_limits,
        "limit_reached": str(limit_reached or ""),
        "reason_code": str(reason_code or ""),
        "silent_truncation": False,
    }
    result["coverage_sha256"] = _sha(result)
    return result


def validate_semantic_coverage(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return ["semantic coverage must be an object"]
    errors: list[str] = []
    if value.get("schema_version") != SCHEMA_VERSION:
        errors.append("semantic coverage schema is invalid")
    if value.get("coverage_status") not in SUPPORTED_COVERAGE_STATUSES:
        errors.append("semantic coverage status is invalid")
    if value.get("silent_truncation") is not False:
        errors.append("semantic coverage must prohibit silent truncation")
    for key in (
        "durable_event_count",
        "command_observation_count",
        "transfer_observation_count",
        "eligible_semantic_observation_count",
        "typed_analyzed_count",
        "omitted_count",
        "typed_fact_count",
        "typed_entity_count",
        "typed_relationship_count",
        "typed_chain_count",
    ):
        if isinstance(value.get(key), bool) or not isinstance(value.get(key), int):
            errors.append(f"semantic coverage {key} is invalid")
    if value.get("typed_analyzed_count", 0) + value.get("omitted_count", 0) != value.get(
        "eligible_semantic_observation_count", -1
    ):
        errors.append("semantic coverage counts do not reconcile")
    if value.get("coverage_status") == "full" and value.get("omitted_count") != 0:
        errors.append("full semantic coverage cannot omit observations")
    if value.get("coverage_status") == "unavailable" and value.get("typed_analyzed_count") != 0:
        errors.append("unavailable semantic coverage cannot analyze observations")
    digest = value.get("coverage_sha256")
    if not isinstance(digest, str) or len(digest) != 64:
        errors.append("semantic coverage hash is invalid")
    else:
        copied = dict(value)
        copied.pop("coverage_sha256", None)
        if _sha(copied) != digest:
            errors.append("semantic coverage hash mismatch")
    return errors
