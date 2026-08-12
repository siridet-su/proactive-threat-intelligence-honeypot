"""Lightweight content-addressed contract for advisory prediction snapshots."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from typing import Any, Mapping

from production.prediction.evidence_cutoff import validate_evidence_cutoff
from production.utils.serialization import stable_id, stable_json


SNAPSHOT_SCHEMA_VERSION = "prediction_snapshot.v4"
LEGACY_SNAPSHOT_SCHEMA_VERSION = "prediction_snapshot.v3"
INTEGRITY_BOUND_SNAPSHOT_SCHEMA_VERSIONS = frozenset(
    {SNAPSHOT_SCHEMA_VERSION, LEGACY_SNAPSHOT_SCHEMA_VERSION}
)


class PredictionSnapshotIntegrityError(ValueError):
    """Raised when a current snapshot violates its immutable identity contract."""


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
    """Validate v4 content identity and its durable prediction boundary."""

    if not isinstance(snapshot, Mapping):
        return ["prediction snapshot must be an object"]
    errors: list[str] = []
    schema_version = snapshot.get("schema_version")
    if schema_version not in INTEGRITY_BOUND_SNAPSHOT_SCHEMA_VERSIONS:
        errors.append(
            f"schema_version must be {SNAPSHOT_SCHEMA_VERSION} or "
            f"{LEGACY_SNAPSHOT_SCHEMA_VERSION}"
        )
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
    if (
        schema_version == SNAPSHOT_SCHEMA_VERSION
        and snapshot.get("prediction_status") == "predicted"
    ):
        history = snapshot.get("prediction_history")
        if not isinstance(history, Mapping):
            errors.append("predicted snapshot requires prediction_history")
        else:
            if history.get("schema_version") != "prediction_trusted_history_manifest.v3":
                errors.append("prediction_history schema is invalid")
            if history.get("target_contract_id") != "next_distinct_trusted_behavior_phase_or_session_end.v2":
                errors.append("prediction_history target contract is invalid")
            digest = _clean(history.get("history_manifest_sha256")).lower()
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                errors.append("prediction_history manifest hash is invalid")
            hashes = history.get("ordered_phase_sha256")
            if not isinstance(hashes, list) or not hashes or any(
                len(_clean(item)) != 64 for item in hashes
            ):
                errors.append("prediction_history phase hashes are invalid")
            if history.get("evidence_cutoff") != snapshot.get("evidence_cutoff"):
                errors.append("prediction_history cutoff does not match snapshot cutoff")
    return errors


def is_integrity_bound_prediction_snapshot(snapshot: Mapping[str, Any]) -> bool:
    """Return whether the snapshot uses a content-addressed readable contract."""

    return snapshot.get("schema_version") in INTEGRITY_BOUND_SNAPSHOT_SCHEMA_VERSIONS


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
