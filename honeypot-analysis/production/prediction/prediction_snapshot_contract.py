"""Lightweight content-addressed contract for advisory prediction snapshots."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from typing import Any, Mapping

from production.prediction.evidence_cutoff import validate_evidence_cutoff
from production.utils.serialization import stable_id, stable_json


SNAPSHOT_SCHEMA_VERSION = "prediction_snapshot.v3"


class PredictionSnapshotIntegrityError(ValueError):
    """Raised when a v3 snapshot violates its immutable identity contract."""


def _clean(value: Any) -> str:
    return str(value or "").strip()


def prediction_snapshot_hash_input(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Return immutable prediction content used for IDs and verification."""

    value = deepcopy(dict(snapshot))
    value.pop("snapshot_id", None)
    value.pop("snapshot_sha256", None)
    value.pop("generated_at", None)
    runtime = value.get("runtime")
    if isinstance(runtime, dict):
        runtime.pop("model_load_time_ms", None)
        runtime.pop("inference_latency_ms", None)
    return value


def finalize_prediction_snapshot(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Attach a retry-stable ID and SHA-256 after canonical fields exist."""

    value = deepcopy(dict(snapshot))
    hash_input = prediction_snapshot_hash_input(value)
    digest = hashlib.sha256(stable_json(hash_input).encode("utf-8")).hexdigest()
    value["snapshot_sha256"] = digest
    value["snapshot_id"] = stable_id(
        "prediction",
        {"schema_version": value.get("schema_version"), "sha256": digest},
    )
    return value


def validate_prediction_snapshot_integrity(
    snapshot: Mapping[str, Any],
) -> list[str]:
    """Validate v3 content identity and any additive durable cutoff."""

    if not isinstance(snapshot, Mapping):
        return ["prediction snapshot must be an object"]
    errors: list[str] = []
    if snapshot.get("schema_version") != SNAPSHOT_SCHEMA_VERSION:
        errors.append(f"schema_version must be {SNAPSHOT_SCHEMA_VERSION}")
        return errors
    expected = finalize_prediction_snapshot(snapshot)
    if _clean(snapshot.get("snapshot_sha256")).lower() != expected[
        "snapshot_sha256"
    ]:
        errors.append("snapshot_sha256 mismatch")
    if _clean(snapshot.get("snapshot_id")) != expected["snapshot_id"]:
        errors.append("snapshot_id mismatch")
    if "evidence_cutoff" in snapshot:
        cutoff_errors = validate_evidence_cutoff(snapshot.get("evidence_cutoff"))
        errors.extend(cutoff_errors)
        cutoff = snapshot.get("evidence_cutoff")
        if isinstance(cutoff, Mapping) and _clean(
            snapshot.get("event_id")
        ) != _clean(cutoff.get("event_id")):
            errors.append("event_id does not match evidence_cutoff.event_id")
    return errors


def require_valid_prediction_snapshot(
    snapshot: Mapping[str, Any],
) -> dict[str, Any]:
    errors = validate_prediction_snapshot_integrity(snapshot)
    if errors:
        raise PredictionSnapshotIntegrityError("; ".join(errors))
    return deepcopy(dict(snapshot))


def canonical_prediction_content(snapshot: Mapping[str, Any]) -> str:
    """Return exact canonical bytes compared for an idempotent retry."""

    return stable_json(prediction_snapshot_hash_input(snapshot))
