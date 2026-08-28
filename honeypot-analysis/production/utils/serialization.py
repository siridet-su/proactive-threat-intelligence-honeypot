from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import math
from collections.abc import Mapping
from datetime import date, datetime, timezone
from decimal import Decimal
from enum import Enum
from pathlib import PurePath
from typing import Any, Dict, Iterable, List
from uuid import UUID

try:  # BSON is optional for SQLite-only deployments.
    from bson import ObjectId as _BsonObjectId
except ImportError:  # pragma: no cover - exercised when pymongo is not installed.
    _BsonObjectId = None  # type: ignore[assignment]


MAX_JSON_NESTING_DEPTH = 100


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _looks_like_object_id(value: Any) -> bool:
    if _BsonObjectId is not None and isinstance(value, _BsonObjectId):
        return True
    cls = value.__class__
    return cls.__name__ == "ObjectId" and cls.__module__.startswith("bson")


def _unsupported_type(value: Any, path: str) -> TypeError:
    value_type = value.__class__
    return TypeError(
        "unsupported JSON value at "
        f"{path}: {value_type.__module__}.{value_type.__qualname__}"
    )


def _datetime_text(value: datetime) -> str:
    normalized = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    return normalized.astimezone(timezone.utc).isoformat()


def _mapping_key(key: Any, path: str) -> str:
    if isinstance(key, str):
        return key
    if key is None:
        return "None"
    if isinstance(key, bool):
        return str(key)
    if isinstance(key, int):
        return str(key)
    if isinstance(key, float):
        if not math.isfinite(key):
            raise ValueError(f"non-finite mapping key at {path}")
        return str(key)
    if isinstance(key, datetime):
        return _datetime_text(key)
    if isinstance(key, date):
        return key.isoformat()
    if isinstance(key, UUID):
        return str(key)
    if isinstance(key, Decimal):
        return str(key)
    if isinstance(key, PurePath):
        return str(key)
    if isinstance(key, bytes):
        return "base64:" + base64.b64encode(key).decode("ascii")
    if _looks_like_object_id(key):
        return str(key)
    if isinstance(key, Enum):
        return _mapping_key(key.value, path)
    raise _unsupported_type(key, path)


def _to_jsonable(
    value: Any,
    *,
    path: str,
    depth: int,
    active_container_ids: set[int],
) -> Any:
    if depth > MAX_JSON_NESTING_DEPTH:
        raise ValueError(f"maximum JSON nesting depth exceeded at {path}")

    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"non-finite float at {path}")
        return value
    if isinstance(value, datetime):
        return _datetime_text(value)
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, PurePath):
        return str(value)
    if isinstance(value, bytes):
        return "base64:" + base64.b64encode(value).decode("ascii")
    if isinstance(value, (bytearray, memoryview)):
        encoded = base64.b64encode(bytes(value)).decode("ascii")
        return "base64:" + encoded
    if _looks_like_object_id(value):
        return str(value)
    if isinstance(value, Enum):
        return _to_jsonable(
            value.value,
            path=path,
            depth=depth,
            active_container_ids=active_container_ids,
        )

    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        identity = id(value)
        if identity in active_container_ids:
            raise ValueError(f"cyclic reference at {path}")
        active_container_ids.add(identity)
        try:
            return {
                field.name: _to_jsonable(
                    getattr(value, field.name),
                    path=f"{path}.{field.name}",
                    depth=depth + 1,
                    active_container_ids=active_container_ids,
                )
                for field in dataclasses.fields(value)
            }
        finally:
            active_container_ids.remove(identity)

    if isinstance(value, Mapping):
        identity = id(value)
        if identity in active_container_ids:
            raise ValueError(f"cyclic reference at {path}")
        active_container_ids.add(identity)
        try:
            result: Dict[str, Any] = {}
            for key, item in value.items():
                normalized_key = _mapping_key(key, f"{path}.<key>")
                if normalized_key in result:
                    raise ValueError(
                        "mapping key collision after JSON normalization at "
                        f"{path}: {normalized_key!r}"
                    )
                result[normalized_key] = _to_jsonable(
                    item,
                    path=f"{path}.{normalized_key}",
                    depth=depth + 1,
                    active_container_ids=active_container_ids,
                )
            return result
        finally:
            active_container_ids.remove(identity)

    if isinstance(value, (list, tuple)):
        identity = id(value)
        if identity in active_container_ids:
            raise ValueError(f"cyclic reference at {path}")
        active_container_ids.add(identity)
        try:
            return [
                _to_jsonable(
                    item,
                    path=f"{path}[{index}]",
                    depth=depth + 1,
                    active_container_ids=active_container_ids,
                )
                for index, item in enumerate(value)
            ]
        finally:
            active_container_ids.remove(identity)

    if isinstance(value, (set, frozenset)):
        identity = id(value)
        if identity in active_container_ids:
            raise ValueError(f"cyclic reference at {path}")
        active_container_ids.add(identity)
        try:
            converted = [
                _to_jsonable(
                    item,
                    path=f"{path}[set-item]",
                    depth=depth + 1,
                    active_container_ids=active_container_ids,
                )
                for item in value
            ]
        finally:
            active_container_ids.remove(identity)
        return sorted(
            converted,
            key=lambda item: json.dumps(
                item,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ),
        )

    raise _unsupported_type(value, path)


def to_jsonable(value: Any) -> Any:
    """Convert supported Python/backend values to deterministic JSON data.

    Unsupported values, cycles, non-finite floats and normalized mapping-key
    collisions raise explicit exceptions.  This prevents callers from silently
    invoking arbitrary ``__str__`` implementations or losing data through an
    unrestricted ``default=str`` fallback.
    """

    return _to_jsonable(
        value,
        path="$",
        depth=0,
        active_container_ids=set(),
    )


def stable_json(value: Any) -> str:
    return json.dumps(
        to_jsonable(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def html_script_json(value: Any) -> str:
    """Serialize JSON for direct embedding in an HTML ``script`` element.

    JSON itself does not escape ``<``.  Without this additional encoding, an
    attacker-controlled ``</script>`` string can terminate the surrounding
    element and create stored script injection in an operator interface.
    """

    return (
        stable_json(value)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def stable_id(prefix: str, value: Any) -> str:
    digest = hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()
    return f"{prefix}_{digest[:32]}"


def event_id(sensor_id: str, event: Dict[str, Any]) -> str:
    return stable_id("evt", {"sensor_id": sensor_id, "event": event})


def session_to_payload(state: Any) -> Dict[str, Any]:
    payload = to_jsonable(state)
    if not isinstance(payload, dict):
        raise TypeError("session state must serialize to a JSON object")
    payload.setdefault("session_id", getattr(state, "session_id", "unknown"))
    payload.setdefault("src_ip", getattr(state, "src_ip", "unknown"))
    payload.setdefault("is_ended", getattr(state, "is_ended", False))
    return payload


def _clean_command_list(values: Iterable[Any]) -> List[str]:
    return [str(value or "").strip() for value in values or [] if str(value or "").strip()]


def command_observation_provenance(
    commands: Iterable[Any],
    commands_success: Iterable[Any] | None = None,
    commands_failed: Iterable[Any] | None = None,
) -> Dict[str, Any]:
    """Describe command input and explicit command-outcome evidence.

    Cowrie reliably emits ``cowrie.command.input`` when an interactive command
    is entered. It does not always emit an explicit success/failure outcome for
    that command. Reports should therefore distinguish "command was observed"
    from "command outcome was observed" instead of silently counting unknown
    outcomes as failures.
    """
    observed = _clean_command_list(commands)
    success = _clean_command_list(commands_success)
    failed = _clean_command_list(commands_failed)
    explicit_outcomes = len(success) + len(failed)
    unknown = max(len(observed) - explicit_outcomes, 0)
    has_explicit_outcome = explicit_outcomes > 0
    return {
        "command_count": len(observed),
        "command_input_count": len(observed),
        "successful_command_count": len(success) if has_explicit_outcome else None,
        "failed_command_count": len(failed) if has_explicit_outcome else None,
        "unknown_command_outcome_count": unknown,
        "command_outcome_observed": has_explicit_outcome,
        "command_outcome_semantics": (
            "command_input_count counts Cowrie command.input events. "
            "successful_command_count and failed_command_count are only populated "
            "when Cowrie provides explicit command success/failure metadata."
        ),
    }
