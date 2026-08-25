from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict

from production.utils.sensitive_data import sanitize_cowrie_event_for_persistence
from production.utils.serialization import event_id as make_event_id
from production.utils.serialization import stable_json, utc_now


CANONICAL_EVENT_RECORD_SCHEMA = "canonical_event_record.v1"


def _canonical_utc_timestamp(value: str) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        raise ValueError("received_at must be a non-empty UTC timestamp")
    try:
        parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("received_at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("received_at must include a UTC offset")
    # Match prediction_evidence_cutoff.v1 exactly.  received_at participates in
    # durable-prefix ordering, so every backend must persist the same canonical
    # UTC representation rather than choosing its own equivalent spelling.
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds")


@dataclass(frozen=True)
class CanonicalEventRecord:
    """Backend-neutral immutable event bytes and deterministic identities.

    A record is constructed once at the authenticated ingest boundary and may
    then be written to multiple durable adapters without allowing either
    database clock or serializer to change canonical ordering or identity.
    """

    event_id: str
    sensor_id: str
    session_id: str
    received_at: str
    payload_json: str
    payload_sha256: str
    event: Dict[str, Any]
    schema_version: str = CANONICAL_EVENT_RECORD_SCHEMA

    @classmethod
    def create(
        cls,
        sensor_id: str,
        event: Dict[str, Any],
        *,
        received_at: str | None = None,
    ) -> "CanonicalEventRecord":
        canonical_sensor = str(sensor_id or "").strip()
        if not canonical_sensor:
            raise ValueError("sensor_id must be non-empty")
        if not isinstance(event, dict):
            raise ValueError("event must be a mapping")
        persisted_event = sanitize_cowrie_event_for_persistence(event)
        session_id = persisted_event.get("session")
        if not isinstance(session_id, str) or not session_id.strip():
            raise ValueError("canonical event session must be a non-empty string")
        if session_id != session_id.strip():
            raise ValueError("canonical event session must not contain whitespace")
        payload_json = stable_json(persisted_event)
        return cls(
            event_id=make_event_id(canonical_sensor, persisted_event),
            sensor_id=canonical_sensor,
            session_id=session_id,
            received_at=_canonical_utc_timestamp(received_at or utc_now()),
            payload_json=payload_json,
            payload_sha256=hashlib.sha256(payload_json.encode("utf-8")).hexdigest(),
            event=persisted_event,
        )

    def verify(self) -> None:
        if self.schema_version != CANONICAL_EVENT_RECORD_SCHEMA:
            raise ValueError("unsupported canonical event record schema")
        rebuilt = self.create(
            self.sensor_id,
            self.event,
            received_at=self.received_at,
        )
        if rebuilt != self:
            raise ValueError("canonical event record integrity mismatch")
