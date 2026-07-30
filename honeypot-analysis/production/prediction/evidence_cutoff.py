"""Durable evidence-cutoff contract for advisory prediction snapshots."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Mapping


EVIDENCE_CUTOFF_SCHEMA_VERSION = "prediction_evidence_cutoff.v1"
_FIELDS = frozenset({"schema_version", "received_at", "event_id"})


class PredictionEvidenceCutoffError(ValueError):
    """Raised when a durable prediction cutoff is malformed."""


def _canonical_received_at(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        raise PredictionEvidenceCutoffError("evidence cutoff received_at is required")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PredictionEvidenceCutoffError(
            "evidence cutoff received_at is invalid"
        ) from exc
    if parsed.tzinfo is None:
        raise PredictionEvidenceCutoffError(
            "evidence cutoff received_at must include a timezone"
        )
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds")


def make_evidence_cutoff(received_at: Any, event_id: Any) -> dict[str, str]:
    """Return the canonical, privacy-safe durable prefix identity."""

    event_identity = str(event_id or "").strip()
    if not event_identity:
        raise PredictionEvidenceCutoffError("evidence cutoff event_id is required")
    return {
        "schema_version": EVIDENCE_CUTOFF_SCHEMA_VERSION,
        "received_at": _canonical_received_at(received_at),
        "event_id": event_identity,
    }


def validate_evidence_cutoff(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return ["evidence_cutoff must be an object"]
    errors = [
        f"evidence_cutoff.{field} is not defined by the contract"
        for field in sorted(set(value) - _FIELDS)
    ]
    if value.get("schema_version") != EVIDENCE_CUTOFF_SCHEMA_VERSION:
        errors.append(
            "evidence_cutoff.schema_version must be "
            f"{EVIDENCE_CUTOFF_SCHEMA_VERSION}"
        )
    try:
        canonical = make_evidence_cutoff(
            value.get("received_at"), value.get("event_id")
        )
    except PredictionEvidenceCutoffError as exc:
        errors.append(str(exc))
    else:
        if dict(value) != canonical:
            errors.append("evidence_cutoff is not canonical")
    return errors


def require_valid_evidence_cutoff(value: Any) -> dict[str, str]:
    errors = validate_evidence_cutoff(value)
    if errors:
        raise PredictionEvidenceCutoffError("; ".join(errors))
    return deepcopy(dict(value))


def evidence_cutoff_sort_key(value: Any) -> tuple[str, str]:
    cutoff = require_valid_evidence_cutoff(value)
    return cutoff["received_at"], cutoff["event_id"]
