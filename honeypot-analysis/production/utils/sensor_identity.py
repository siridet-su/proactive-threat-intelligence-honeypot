"""Authenticated sensor/session identity binding for ingested Cowrie events."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping


IDENTITY_SCHEMA = "authenticated_sensor_session.v1"
MAX_SENSOR_SESSION_CHARS = 256
CANONICAL_SESSION_PREFIX = "session_v1_"


def validate_sensor_session_id(value: Any) -> str:
    """Return a bounded sensor-local Cowrie session ID or raise ``ValueError``."""

    if not isinstance(value, str):
        raise ValueError("session must be a string")
    if not value:
        raise ValueError("session is required")
    if value != value.strip():
        raise ValueError("session must not contain surrounding whitespace")
    if len(value) > MAX_SENSOR_SESSION_CHARS:
        raise ValueError(
            f"session must not exceed {MAX_SENSOR_SESSION_CHARS} characters"
        )
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError("session must not contain control characters")
    return value


def canonical_session_id(sensor_id: str, sensor_session_id: str) -> str:
    """Return a stable opaque identity namespaced by authenticated sensor."""

    selected_sensor = str(sensor_id or "")
    if not selected_sensor:
        raise ValueError("authenticated sensor identity is required")
    selected_session = validate_sensor_session_id(sensor_session_id)
    material = json.dumps(
        {
            "schema_version": IDENTITY_SCHEMA,
            "sensor_id": selected_sensor,
            "sensor_session_id": selected_session,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return CANONICAL_SESSION_PREFIX + hashlib.sha256(material).hexdigest()[:32]


def bind_authenticated_sensor_identity(
    event: Mapping[str, Any],
    sensor_id: str,
) -> dict[str, Any]:
    """Replace untrusted identity fields with authenticated canonical values."""

    if not isinstance(event, Mapping):
        raise ValueError("event must be an object")
    sensor_session_id = validate_sensor_session_id(event.get("session"))
    selected_sensor = str(sensor_id or "")
    session_id = canonical_session_id(selected_sensor, sensor_session_id)
    bound = dict(event)
    bound["session"] = session_id
    # Cowrie traditionally emits ``sensor`` while the ingest envelope uses
    # ``sensor_id``.  Both persisted spellings are owned by authentication.
    bound["sensor"] = selected_sensor
    bound["sensor_id"] = selected_sensor
    bound["_honeypot_identity"] = {
        "schema_version": IDENTITY_SCHEMA,
        "sensor_id": selected_sensor,
        "sensor_session_id": sensor_session_id,
        "canonical_session_id": session_id,
    }
    return bound
