"""Versioned, privacy-bounded adapter for the CyberLab Cowrie export.

CyberLab is an external-domain source and is intentionally kept out of the
internal Zenodo adapter.  Its daily members are gzip-compressed JSON arrays;
each array item is a one-key mapping from a session identifier to that
session's event list.  This module parses one session object at a time, keeps
the source order as durable evidence order, and exposes two boundaries:

``iter_cyberlab_private_sessions``
    An ephemeral, source-faithful event stream for the existing classifier.
    It contains command text and must never be persisted or published.

``iter_cyberlab_sessions``
    A privacy-safe canonical session representation.  Commands are represented
    only by HMAC evidence references and lengths; identifiers and source
    metadata are domain-separated and provenance-bound.

No success/failure event is paired with a command here.  CyberLab's export
does not contain a command-event identifier linking those records, so the
outcome is retained as contextual evidence and remains non-authoritative.
"""

from __future__ import annotations

import gzip
import hashlib
import hmac
import json
import re
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, Mapping, Sequence, TextIO

from production.reproduction.next_behavior.corpus import (
    PSEUDONYMIZATION_SCHEME,
    pseudonymous_id,
)
from production.utils.serialization import stable_id, stable_json


ADAPTER_SCHEMA_VERSION = "cyberlab_cowrie_adapter.v1"
ADAPTER_RECEIPT_SCHEMA_VERSION = "cyberlab_external_adapter_receipt.v1"
SOURCE_SCHEMA_VERSION = "cyberlab_session_array.v1"
CANONICAL_SESSION_SCHEMA_VERSION = "cyberlab_canonical_session.v1"
PRIVATE_SESSION_SCHEMA_VERSION = "cyberlab_private_session.v1"
HIGH_INTERACTION_SENSOR = "ubuntu_basic_pool"
ZENODO_RECORD_ID = 3687527
ZENODO_DOI = "10.5281/zenodo.3687527"

SUPPORTED_EVENT_TYPES = frozenset(
    {
        "cowrie.command.input",
        "cowrie.command.success",
        "cowrie.command.failed",
        "cowrie.session.closed",
    }
)
_COMMAND_TYPES = frozenset({"cowrie.command.input"})
_OUTCOME_TYPES = frozenset(
    {"cowrie.command.success", "cowrie.command.failed"}
)
_CLOSE_TYPE = "cowrie.session.closed"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MD5 = re.compile(r"^md5:[0-9a-f]{32}$")
_DATE = re.compile(r"^20[0-9]{2}-[01][0-9]-[0-3][0-9]$")
_SAFE_KEY_ID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


class CyberLabAdapterError(ValueError):
    """Raised when an external record cannot be normalized safely."""


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _sha256(value: Any) -> bool:
    return bool(_SHA256.fullmatch(_clean(value).lower()))


def _parse_timestamp(value: Any) -> tuple[str, datetime]:
    text = _clean(value)
    if not text:
        raise CyberLabAdapterError("timestamp is required")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CyberLabAdapterError("timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise CyberLabAdapterError("timestamp must include a timezone")
    utc = parsed.astimezone(timezone.utc)
    return utc.isoformat(timespec="microseconds").replace("+00:00", "Z"), utc


def _message_command(message: Any, prefix: str) -> str:
    text = _clean(message)
    if text.startswith(prefix):
        command = text[len(prefix):].strip()
        if command:
            return command
    return ""


def _event_fingerprint(event: Mapping[str, Any]) -> str:
    """Fingerprint only source fields needed for duplicate/conflict checks."""

    value = {
        "eventid": _clean(event.get("eventid")),
        "session_id": _clean(event.get("session_id")),
        "timestamp": _clean(event.get("timestamp")),
        "message": _clean(event.get("message")),
        "protocol": _clean(event.get("protocol")).lower(),
        "sensor": _clean(event.get("sensor")),
        "event_payload": event.get("event_payload"),
    }
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def _safe_digest(value: str, *, key: bytes, kind: str = "evidence") -> str:
    return pseudonymous_id(kind, value, key=key)


def validate_adapter_provenance(value: Any) -> list[str]:
    """Validate the provenance tuple required for every external session."""

    if not isinstance(value, Mapping):
        return ["adapter provenance must be an object"]
    required = {
        "adapter_schema_version",
        "source_schema_version",
        "zenodo_record_id",
        "doi",
        "source_filename",
        "source_member_date",
        "source_sha256",
        "source_checksum_md5",
        "sensor",
        "adapter_sha256",
        "sanitizer_version",
        "classification_policy_sha256",
        "trust_policy_sha256",
    }
    optional = {
        "pseudonymization_scheme",
        "pseudonymization_key_id",
        "source_member_filename",
    }
    errors = [
        f"provenance.{key} is not defined by the contract"
        for key in sorted(set(value) - required - optional)
    ]
    missing = required - set(value)
    errors.extend(f"provenance.{key} is required" for key in sorted(missing))
    if value.get("adapter_schema_version") != ADAPTER_SCHEMA_VERSION:
        errors.append("provenance.adapter_schema_version is invalid")
    if value.get("source_schema_version") != SOURCE_SCHEMA_VERSION:
        errors.append("provenance.source_schema_version is invalid")
    if value.get("zenodo_record_id") != ZENODO_RECORD_ID:
        errors.append("provenance.zenodo_record_id is not the frozen record")
    if value.get("doi") != ZENODO_DOI:
        errors.append("provenance.doi is not the frozen DOI")
    filename = _clean(value.get("source_filename"))
    if not filename.endswith(".json.gz") or "/" in filename or "\\" in filename:
        errors.append("provenance.source_filename is unsafe")
    if not _DATE.fullmatch(_clean(value.get("source_member_date"))):
        errors.append("provenance.source_member_date is invalid")
    if not _sha256(value.get("source_sha256")):
        errors.append("provenance.source_sha256 must be SHA-256")
    if not _MD5.fullmatch(_clean(value.get("source_checksum_md5")).lower()):
        errors.append("provenance.source_checksum_md5 must be an MD5 receipt")
    if value.get("sensor") != HIGH_INTERACTION_SENSOR:
        errors.append("provenance.sensor must be ubuntu_basic_pool")
    for field in (
        "adapter_sha256",
        "classification_policy_sha256",
        "trust_policy_sha256",
    ):
        if not _sha256(value.get(field)):
            errors.append(f"provenance.{field} must be SHA-256")
    if not _clean(value.get("sanitizer_version")):
        errors.append("provenance.sanitizer_version is required")
    if "pseudonymization_scheme" in value and value.get(
        "pseudonymization_scheme"
    ) != PSEUDONYMIZATION_SCHEME:
        errors.append("provenance.pseudonymization_scheme is invalid")
    if "pseudonymization_key_id" in value and not _SAFE_KEY_ID.fullmatch(
        _clean(value.get("pseudonymization_key_id"))
    ):
        errors.append("provenance.pseudonymization_key_id is invalid")
    if "source_member_filename" in value:
        source_member = _clean(value.get("source_member_filename"))
        if not source_member.endswith(".json.gz") or "/" in source_member:
            errors.append("provenance.source_member_filename is unsafe")
    return errors


def require_adapter_provenance(value: Any) -> Dict[str, Any]:
    errors = validate_adapter_provenance(value)
    if errors:
        raise CyberLabAdapterError("; ".join(errors))
    return dict(value)


def validate_adapter_policy(value: Any) -> list[str]:
    """Validate the tracked JSON contract without inspecting source data."""

    if not isinstance(value, Mapping):
        return ["CyberLab adapter policy must be an object"]
    errors: list[str] = []
    if value.get("schema_version") != ADAPTER_SCHEMA_VERSION:
        errors.append("schema_version is invalid")
    source = value.get("source")
    if not isinstance(source, Mapping):
        errors.append("source must be an object")
    else:
        if source.get("zenodo_record_id") != ZENODO_RECORD_ID:
            errors.append("source.zenodo_record_id is invalid")
        if source.get("doi") != ZENODO_DOI:
            errors.append("source.doi is invalid")
        if source.get("source_schema_version") != SOURCE_SCHEMA_VERSION:
            errors.append("source.source_schema_version is invalid")
        if source.get("official_checksum_domain") != "md5":
            errors.append("source.official_checksum_domain is invalid")
    session = value.get("session_contract")
    if not isinstance(session, Mapping):
        errors.append("session_contract must be an object")
    else:
        required_fields = session.get("required_event_fields")
        if required_fields != ["session_id", "eventid", "timestamp", "sensor"]:
            errors.append("session_contract.required_event_fields is invalid")
        if session.get("close_event") != _CLOSE_TYPE:
            errors.append("session_contract.close_event is invalid")
        if session.get("missing_close") != "active/unresolved; no fabricated terminal target":
            errors.append("session_contract.missing_close is invalid")
    policy = value.get("high_interaction_policy")
    if not isinstance(policy, Mapping) or policy.get("required_value") != HIGH_INTERACTION_SENSOR:
        errors.append("high_interaction_policy is invalid")
    commands = value.get("command_events")
    expected_commands = {
        "input": "cowrie.command.input",
        "success": "cowrie.command.success",
        "failed": "cowrie.command.failed",
    }
    if not isinstance(commands, Mapping) or any(
        commands.get(key) != expected for key, expected in expected_commands.items()
    ):
        errors.append("command_events mapping is invalid")
    return errors


def require_valid_adapter_policy(value: Any) -> Dict[str, Any]:
    errors = validate_adapter_policy(value)
    if errors:
        raise CyberLabAdapterError("; ".join(errors))
    return dict(value)


def validate_adapter_receipt(
    value: Any,
    *,
    repository_root: Path | None = None,
) -> list[str]:
    """Validate and, when requested, recompute the frozen adapter inputs."""

    if not isinstance(value, Mapping):
        return ["adapter receipt must be an object"]
    required = {
        "schema_version",
        "adapter_schema_version",
        "source_policy_path",
        "adapter_path",
        "documentation_path",
        "fixture_path",
        "source_policy_sha256",
        "adapter_sha256",
        "documentation_sha256",
        "fixture_sha256",
        "test_result",
        "real_external_data_accessed",
        "sealed_test_accessed",
        "receipt_id",
    }
    errors = [
        f"receipt.{key} is not defined by the contract"
        for key in sorted(set(value) - required)
    ]
    errors.extend(
        f"receipt.{key} is required" for key in sorted(required - set(value))
    )
    if value.get("schema_version") != ADAPTER_RECEIPT_SCHEMA_VERSION:
        errors.append("receipt schema_version is invalid")
    if value.get("adapter_schema_version") != ADAPTER_SCHEMA_VERSION:
        errors.append("receipt adapter_schema_version is invalid")
    for field in (
        "source_policy_sha256",
        "adapter_sha256",
        "documentation_sha256",
        "fixture_sha256",
    ):
        if not _sha256(value.get(field)):
            errors.append(f"receipt.{field} must be SHA-256")
    if value.get("test_result") != "10 passed":
        errors.append("receipt.test_result is not the reviewed result")
    if value.get("real_external_data_accessed") is not False:
        errors.append("receipt must record no real external data access")
    if value.get("sealed_test_accessed") is not False:
        errors.append("receipt must record no sealed-test access")
    identity = dict(value)
    receipt_id = identity.pop("receipt_id", None)
    if stable_id("cyberlabadapterreceipt", identity) != receipt_id:
        errors.append("receipt_id does not match receipt content")
    if repository_root is not None:
        for field in (
            "source_policy_path",
            "adapter_path",
            "documentation_path",
            "fixture_path",
        ):
            path = repository_root / _clean(value.get(field))
            if not path.is_file() or path.is_symlink():
                errors.append(f"receipt.{field} is not a regular repository file")
                continue
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            hash_field = {
                "source_policy_path": "source_policy_sha256",
                "adapter_path": "adapter_sha256",
                "documentation_path": "documentation_sha256",
                "fixture_path": "fixture_sha256",
            }[field]
            if digest != value.get(hash_field):
                errors.append(f"receipt.{hash_field} does not match repository bytes")
    return errors


def require_valid_adapter_receipt(
    value: Any,
    *,
    repository_root: Path | None = None,
) -> Dict[str, Any]:
    errors = validate_adapter_receipt(value, repository_root=repository_root)
    if errors:
        raise CyberLabAdapterError("; ".join(errors))
    return dict(value)


def _iter_json_array(stream: TextIO, *, chunk_size: int = 64 * 1024) -> Iterator[Any]:
    """Yield top-level JSON-array items without loading the array."""

    decoder = json.JSONDecoder()
    buffer = ""
    eof = False
    started = False
    finished = False

    def refill() -> None:
        nonlocal buffer, eof
        if eof:
            return
        piece = stream.read(chunk_size)
        if piece == "":
            eof = True
        else:
            buffer += piece

    while True:
        while not buffer and not eof:
            refill()
        if not started:
            while buffer and buffer[0].isspace():
                buffer = buffer[1:]
            if not buffer:
                raise CyberLabAdapterError("top-level JSON array is missing")
            if buffer[0] != "[":
                raise CyberLabAdapterError("CyberLab member must be a JSON array")
            buffer = buffer[1:]
            started = True
        while True:
            while buffer and buffer[0].isspace():
                buffer = buffer[1:]
            if not buffer and not eof:
                refill()
                continue
            if not buffer:
                raise CyberLabAdapterError("truncated top-level JSON array")
            if buffer[0] == "]":
                buffer = buffer[1:]
                finished = True
                break
            try:
                item, end = decoder.raw_decode(buffer)
            except json.JSONDecodeError:
                if eof:
                    raise CyberLabAdapterError("malformed top-level JSON item")
                refill()
                continue
            buffer = buffer[end:]
            yield item
            while buffer and buffer[0].isspace():
                buffer = buffer[1:]
            if buffer and buffer[0] == ",":
                buffer = buffer[1:]
                continue
            if buffer and buffer[0] == "]":
                buffer = buffer[1:]
                finished = True
                break
            if not buffer and not eof:
                refill()
                while buffer and buffer[0].isspace():
                    buffer = buffer[1:]
                if buffer and buffer[0] == ",":
                    buffer = buffer[1:]
                    continue
                if buffer and buffer[0] == "]":
                    buffer = buffer[1:]
                    finished = True
                    break
                if not buffer and eof:
                    raise CyberLabAdapterError("truncated top-level JSON array")
                raise CyberLabAdapterError("array item separator is invalid")
            raise CyberLabAdapterError("array item separator is invalid")
        if finished:
            break
    if buffer.strip():
        raise CyberLabAdapterError("trailing content follows top-level array")
    while not eof:
        refill()
    if buffer.strip():
        raise CyberLabAdapterError("trailing content follows top-level array")


def _session_item(item: Any) -> tuple[str, list[dict[str, Any]]]:
    if not isinstance(item, Mapping) or len(item) != 1:
        raise CyberLabAdapterError("each array item must map one session ID to events")
    raw_id, raw_events = next(iter(item.items()))
    session_id = _clean(raw_id)
    if not session_id or not isinstance(raw_events, list):
        raise CyberLabAdapterError("session ID and event array are required")
    if not raw_events:
        raise CyberLabAdapterError("session event array must not be empty")
    events: list[dict[str, Any]] = []
    for event in raw_events:
        if not isinstance(event, Mapping):
            raise CyberLabAdapterError("session event must be an object")
        current = dict(event)
        if _clean(current.get("session_id")) != session_id:
            raise CyberLabAdapterError("event session_id disagrees with array key")
        events.append(current)
    return session_id, events


def _normalize_raw_event(
    event: Mapping[str, Any],
    *,
    raw_session_id: str,
    source_member: Mapping[str, Any],
    event_order: int,
) -> dict[str, Any]:
    event_type = _clean(event.get("eventid"))
    if not event_type:
        raise CyberLabAdapterError("eventid is required")
    timestamp, _ = _parse_timestamp(event.get("timestamp"))
    sensor = _clean(event.get("sensor"))
    if not sensor:
        raise CyberLabAdapterError("sensor is required")
    protocol = _clean(event.get("protocol")).lower()
    if protocol and protocol not in {"ssh", "telnet"}:
        raise CyberLabAdapterError("unsupported protocol value")
    message = event.get("message")
    if message is not None and not isinstance(message, str):
        raise CyberLabAdapterError("message must be a string or null")
    command = ""
    outcome = "unknown"
    association = "not_applicable"
    if event_type == "cowrie.command.input":
        command = _clean(event.get("input")) or _message_command(message, "CMD: ")
        if not command:
            raise CyberLabAdapterError("command.input has no exact command text")
    elif event_type == "cowrie.command.success":
        outcome = "success"
        association = "unpaired_contextual"
        command = _message_command(message, "Command found: ")
    elif event_type == "cowrie.command.failed":
        outcome = "failed"
        association = "unpaired_contextual"
        command = _message_command(message, "Command not found: ")
    elif event_type == _CLOSE_TYPE:
        outcome = "session_closed"
    event_key = (event_type, timestamp, raw_session_id)
    return {
        "event_key": event_key,
        "event_id": _clean(event.get("event_id")) or stable_id(
            "cyberlabevent",
            {
                "source_member": _clean(source_member.get("filename")),
                "session_id": raw_session_id,
                "event_type": event_type,
                "timestamp": timestamp,
                "fingerprint": _event_fingerprint(
                    {
                        **event,
                        "session_id": raw_session_id,
                    }
                ),
            },
        ),
        "source_member": _clean(source_member.get("filename")),
        "source_member_date": _clean(source_member.get("collection_date")),
        "event_order": event_order,
        "source_event_order": event_order,
        "event_time": timestamp,
        "event_type": event_type,
        "protocol": protocol,
        "sensor": sensor,
        "command": command,
        "command_digest": hashlib.sha256(command.encode("utf-8")).hexdigest()
        if command
        else "",
        "outcome": outcome,
        "outcome_association": association,
    }


def _raw_session(
    raw_session_id: str,
    events: Sequence[dict[str, Any]],
    *,
    source_member: Mapping[str, Any],
) -> dict[str, Any]:
    protocols = {event["protocol"] for event in events if event["protocol"]}
    if len(protocols) > 1:
        raise CyberLabAdapterError("session has conflicting protocol values")
    protocol = next(iter(protocols), "unknown")
    sensors = {event["sensor"] for event in events}
    if len(sensors) != 1:
        eligibility = "mixed_sensor"
    elif next(iter(sensors)) != HIGH_INTERACTION_SENSOR:
        eligibility = "wrong_sensor"
    else:
        eligibility = "eligible"
    ordered = sorted(
        events,
        key=lambda event: (
            event["event_time"],
            int(event.get("source_event_order", event["event_order"])),
            event["event_id"],
        ),
    )
    ordered = [
        {**event, "event_order": index}
        for index, event in enumerate(ordered)
    ]
    closed = any(event["event_type"] == _CLOSE_TYPE for event in ordered)
    return {
        "schema_version": PRIVATE_SESSION_SCHEMA_VERSION,
        "raw_session_id": raw_session_id,
        "source_members": [_clean(source_member.get("filename"))],
        "source_member_dates": [_clean(source_member.get("collection_date"))],
        "protocol": protocol,
        "status": "closed" if closed else "active",
        "termination_status": "explicit_closed" if closed else "unresolved",
        "high_interaction_eligibility": eligibility,
        "events": ordered,
        "cross_file": False,
    }


def _deduplicate_events(events: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    exact: dict[str, dict[str, Any]] = {}
    by_key: dict[tuple[Any, ...], str] = {}
    for event in events:
        # Source member/order/derived IDs are intentionally excluded so an
        # exact event repeated at a daily-file boundary is idempotently
        # deduplicated.  The semantic payload remains conflict-bound.
        fingerprint = hashlib.sha256(
            stable_json(
                {
                    "event_key": tuple(event["event_key"]),
                    "event_time": event["event_time"],
                    "event_type": event["event_type"],
                    "protocol": event["protocol"],
                    "sensor": event["sensor"],
                    "command_digest": event["command_digest"],
                    "outcome": event["outcome"],
                    "outcome_association": event["outcome_association"],
                }
            ).encode("utf-8")
        ).hexdigest()
        key = tuple(event["event_key"])
        prior = by_key.get(key)
        if prior is not None and prior != fingerprint:
            raise CyberLabAdapterError("conflicting duplicate event")
        by_key[key] = fingerprint
        exact[fingerprint] = event
    return sorted(
        exact.values(),
        key=lambda event: (
            event["event_time"],
            event.get("source_event_order", event["event_order"]),
            event["event_id"],
        ),
    )


def merge_cyberlab_private_sessions(
    sessions: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Merge repeated/cross-file private sessions without losing provenance."""

    merged: OrderedDict[str, dict[str, Any]] = OrderedDict()
    for value in sessions:
        if not isinstance(value, Mapping):
            raise CyberLabAdapterError("private session must be an object")
        raw_id = _clean(value.get("raw_session_id"))
        if not raw_id:
            raise CyberLabAdapterError("private session identity is required")
        current = merged.get(raw_id)
        if current is None:
            current = dict(value)
            current["source_members"] = list(value.get("source_members") or [])
            current["source_member_dates"] = list(value.get("source_member_dates") or [])
            current["events"] = list(value.get("events") or [])
            merged[raw_id] = current
            continue
        current["source_members"] = sorted(
            set(current["source_members"]) | set(value.get("source_members") or [])
        )
        current["source_member_dates"] = sorted(
            set(current["source_member_dates"])
            | set(value.get("source_member_dates") or [])
        )
        current["events"] = _deduplicate_events(
            [*current["events"], *(value.get("events") or [])]
        )
        current["events"] = [
            {**event, "event_order": index}
            for index, event in enumerate(current["events"])
        ]
        current["cross_file"] = len(current["source_members"]) > 1
        current["status"] = (
            "closed"
            if any(event["event_type"] == _CLOSE_TYPE for event in current["events"])
            else "active"
        )
        current["termination_status"] = (
            "explicit_closed" if current["status"] == "closed" else "unresolved"
        )
        sensors = {event["sensor"] for event in current["events"]}
        current["high_interaction_eligibility"] = (
            "eligible"
            if sensors == {HIGH_INTERACTION_SENSOR}
            else "mixed_sensor"
            if HIGH_INTERACTION_SENSOR in sensors
            else "wrong_sensor"
        )
    return list(merged.values())


def _safe_session(
    private: Mapping[str, Any],
    *,
    provenance: Mapping[str, Any],
    source_member: Mapping[str, Any],
    key: bytes,
    key_id: str,
) -> dict[str, Any]:
    raw_id = _clean(private.get("raw_session_id"))
    source_members = list(private.get("source_members") or [])
    if not raw_id or not source_members:
        raise CyberLabAdapterError("private session identity/provenance is required")
    if len(source_members) != 1:
        raise CyberLabAdapterError(
            "cross-file sessions require a reviewed multi-member safe receipt"
        )
    safe_events = []
    for event in private.get("events") or []:
        safe_event = {
            "event_id": _safe_digest(
                f"{raw_id}:{event['event_id']}", key=key
            ),
            "event_order": int(event["event_order"]),
            "event_time": event["event_time"],
            "event_type": event["event_type"],
            "protocol": event["protocol"],
            "sensor": event["sensor"],
            "outcome": event["outcome"],
            "outcome_association": event["outcome_association"],
        }
        if event.get("command_digest"):
            safe_event["command_evidence_ref"] = _safe_digest(
                f"{raw_id}:{event['event_id']}:{event['command_digest']}",
                key=key,
            )
            safe_event["command_length"] = len(event.get("command") or "")
        safe_events.append(safe_event)
    safe = {
        "schema_version": CANONICAL_SESSION_SCHEMA_VERSION,
        "session_id": pseudonymous_id("session", raw_id, key=key),
        "source_member_ids": [
            pseudonymous_id("member", member, key=key)
            for member in source_members
        ],
        "source_member_sha256": _clean(provenance["source_sha256"]).lower(),
        "source_member_dates": sorted(set(private.get("source_member_dates") or [])),
        "protocol": _clean(private.get("protocol")).lower(),
        "status": _clean(private.get("status")),
        "termination_status": _clean(private.get("termination_status")),
        "high_interaction_eligibility": _clean(
            private.get("high_interaction_eligibility")
        ),
        "cross_file": bool(private.get("cross_file")),
        "events": safe_events,
        "provenance": {
            **dict(provenance),
            "pseudonymization_scheme": PSEUDONYMIZATION_SCHEME,
            "pseudonymization_key_id": key_id,
            "source_member_filename": _clean(source_member.get("filename")),
        },
    }
    return safe


def validate_cyberlab_session(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return ["CyberLab canonical session must be an object"]
    required = {
        "schema_version",
        "session_id",
        "source_member_ids",
        "source_member_sha256",
        "source_member_dates",
        "protocol",
        "status",
        "termination_status",
        "high_interaction_eligibility",
        "cross_file",
        "events",
        "provenance",
    }
    errors = [
        f"session.{key} is not defined by the contract"
        for key in sorted(set(value) - required)
    ]
    if value.get("schema_version") != CANONICAL_SESSION_SCHEMA_VERSION:
        errors.append("session schema_version is invalid")
    if not _clean(value.get("session_id")).startswith("nbsession_"):
        errors.append("session_id must be pseudonymous")
    member_ids = value.get("source_member_ids")
    if not isinstance(member_ids, list) or not member_ids or not all(
        _clean(item).startswith("nbmember_") for item in member_ids
    ):
        errors.append("source_member_ids must be non-empty pseudonymous IDs")
    if not _sha256(value.get("source_member_sha256")):
        errors.append("source_member_sha256 must be SHA-256")
    if not isinstance(value.get("source_member_dates"), list) or not value.get(
        "source_member_dates"
    ):
        errors.append("source_member_dates must be non-empty")
    if value.get("protocol") not in {"ssh", "telnet", "unknown"}:
        errors.append("protocol is invalid")
    if value.get("status") not in {"active", "closed"}:
        errors.append("status is invalid")
    if value.get("termination_status") not in {"explicit_closed", "unresolved"}:
        errors.append("termination_status is invalid")
    if value.get("termination_status") == "explicit_closed" and value.get("status") != "closed":
        errors.append("explicit_closed requires closed status")
    if value.get("termination_status") == "unresolved" and value.get("status") != "active":
        errors.append("unresolved requires active status")
    if value.get("high_interaction_eligibility") not in {
        "eligible",
        "wrong_sensor",
        "mixed_sensor",
    }:
        errors.append("high_interaction_eligibility is invalid")
    if type(value.get("cross_file")) is not bool:
        errors.append("cross_file must be boolean")
    events = value.get("events")
    if not isinstance(events, list) or not events:
        errors.append("events must be non-empty")
    else:
        orders = []
        for index, event in enumerate(events):
            if not isinstance(event, Mapping):
                errors.append(f"events[{index}] must be an object")
                continue
            allowed_event_fields = {
                "event_id",
                "event_order",
                "event_time",
                "event_type",
                "protocol",
                "sensor",
                "outcome",
                "outcome_association",
                "command_evidence_ref",
                "command_length",
            }
            errors.extend(
                f"events[{index}].{field} is not defined by the contract"
                for field in sorted(set(event) - allowed_event_fields)
            )
            for field in ("event_id", "event_time", "event_type", "sensor"):
                if not _clean(event.get(field)):
                    errors.append(f"events[{index}].{field} is required")
            if isinstance(event.get("event_order"), bool) or not isinstance(
                event.get("event_order"), int
            ):
                errors.append(f"events[{index}].event_order is invalid")
            else:
                orders.append(event["event_order"])
            try:
                _parse_timestamp(event.get("event_time"))
            except CyberLabAdapterError:
                errors.append(f"events[{index}].event_time is invalid")
            if event.get("outcome_association") == "unpaired_contextual" and event.get(
                "event_type"
            ) not in _OUTCOME_TYPES:
                errors.append(f"events[{index}] has invalid outcome association")
            if "command_evidence_ref" in event and not _clean(
                event.get("command_evidence_ref")
            ).startswith("nbevidence_"):
                errors.append(f"events[{index}].command_evidence_ref is invalid")
            if "command_length" in event and (
                isinstance(event.get("command_length"), bool)
                or not isinstance(event.get("command_length"), int)
                or event.get("command_length") < 1
            ):
                errors.append(f"events[{index}].command_length is invalid")
            if "command" in event or "message" in event or "src_ip" in event:
                errors.append(f"events[{index}] contains private source data")
        if orders != sorted(orders):
            errors.append("events are not in canonical order")
    errors.extend(
        f"provenance.{error}"
        for error in validate_adapter_provenance(value.get("provenance"))
    )
    return errors


def require_valid_cyberlab_session(value: Any) -> dict[str, Any]:
    errors = validate_cyberlab_session(value)
    if errors:
        raise CyberLabAdapterError("; ".join(errors))
    return dict(value)


def high_interaction_decision(private_session: Mapping[str, Any]) -> dict[str, Any]:
    """Return the label-blind sensor decision and nothing behavior-derived."""

    decision = _clean(private_session.get("high_interaction_eligibility"))
    if decision == "eligible":
        return {"eligible": True, "reason": "sensor_exact_match"}
    if decision == "mixed_sensor":
        return {"eligible": False, "reason": "mixed_sensor_values"}
    return {"eligible": False, "reason": "sensor_not_ubuntu_basic_pool"}


class CyberLabAdapter:
    """Parse one external member with explicit private/safe boundaries."""

    def __init__(
        self,
        *,
        source_member: Mapping[str, Any],
        provenance: Mapping[str, Any],
        pseudonymization_key: bytes,
        pseudonymization_key_id: str,
        maximum_events_per_session: int = 100_000,
    ) -> None:
        if not isinstance(pseudonymization_key, bytes) or len(pseudonymization_key) < 32:
            raise CyberLabAdapterError("pseudonymization key must contain 32 bytes")
        if not _SAFE_KEY_ID.fullmatch(_clean(pseudonymization_key_id)):
            raise CyberLabAdapterError("pseudonymization key ID is invalid")
        if not isinstance(maximum_events_per_session, int) or isinstance(
            maximum_events_per_session, bool
        ) or maximum_events_per_session < 1:
            raise CyberLabAdapterError("maximum_events_per_session is invalid")
        filename = _clean(source_member.get("filename"))
        date = _clean(source_member.get("collection_date"))
        if not filename.endswith(".json.gz") or "/" in filename:
            raise CyberLabAdapterError("source member filename is invalid")
        if not _DATE.fullmatch(date):
            raise CyberLabAdapterError("source member date is invalid")
        if not _sha256(source_member.get("sha256")):
            raise CyberLabAdapterError("source member SHA-256 is required")
        self.source_member = dict(source_member)
        self.provenance = require_adapter_provenance(provenance)
        if self.provenance["source_filename"] != filename:
            raise CyberLabAdapterError("provenance filename disagrees with source member")
        if self.provenance["source_member_date"] != date:
            raise CyberLabAdapterError("provenance date disagrees with source member")
        if self.provenance["source_sha256"] != _clean(source_member["sha256"]).lower():
            raise CyberLabAdapterError("provenance source hash disagrees with source member")
        self.key = pseudonymization_key
        self.key_id = _clean(pseudonymization_key_id)
        self.maximum_events_per_session = maximum_events_per_session

    def iter_private_sessions(self, path: Path | str) -> Iterator[dict[str, Any]]:
        source_path = Path(path)
        try:
            handle = gzip.open(source_path, "rt", encoding="utf-8", errors="strict")
        except OSError as exc:
            raise CyberLabAdapterError("cannot open CyberLab gzip member") from exc
        with handle:
            for item in _iter_json_array(handle):
                raw_id, raw_events = _session_item(item)
                if len(raw_events) > self.maximum_events_per_session:
                    raise CyberLabAdapterError("session event limit exceeded")
                normalized = [
                    _normalize_raw_event(
                        event,
                        raw_session_id=raw_id,
                        source_member=self.source_member,
                        event_order=index,
                    )
                    for index, event in enumerate(raw_events)
                ]
                yield _raw_session(
                    raw_id,
                    _deduplicate_events(normalized),
                    source_member=self.source_member,
                )

    def iter_sessions(self, path: Path | str) -> Iterator[dict[str, Any]]:
        """Yield privacy-safe sessions; repeated IDs are merged by the caller."""

        for private in self.iter_private_sessions(path):
            safe = _safe_session(
                private,
                provenance=self.provenance,
                source_member=self.source_member,
                key=self.key,
                key_id=self.key_id,
            )
            require_valid_cyberlab_session(safe)
            yield safe

    def build_private_classifier_events(
        self,
        private_session: Mapping[str, Any],
    ) -> list[dict[str, Any]]:
        """Return ephemeral SessionMonitor-shaped events for one private session.

        Outcome records deliberately carry no ``input`` field: the source does
        not provide an exact command-event relationship.  The existing monitor
        therefore retains them as contextual events and cannot promote them to
        command-success semantics.
        """

        if _clean(private_session.get("schema_version")) != PRIVATE_SESSION_SCHEMA_VERSION:
            raise CyberLabAdapterError("private session schema_version is invalid")
        events: list[dict[str, Any]] = []
        for event in private_session.get("events") or []:
            item = {
                "session": private_session["raw_session_id"],
                "session_id": private_session["raw_session_id"],
                "eventid": event["event_type"],
                "timestamp": event["event_time"],
                "protocol": event["protocol"],
                "sensor": event["sensor"],
                "cyberlab_outcome_association": event["outcome_association"],
            }
            if event["event_type"] == "cowrie.command.input":
                item["input"] = event["command"]
            events.append(item)
        return events


def iter_cyberlab_private_sessions(
    path: Path | str,
    *,
    source_member: Mapping[str, Any],
    provenance: Mapping[str, Any],
    pseudonymization_key: bytes,
    pseudonymization_key_id: str,
) -> Iterator[dict[str, Any]]:
    return CyberLabAdapter(
        source_member=source_member,
        provenance=provenance,
        pseudonymization_key=pseudonymization_key,
        pseudonymization_key_id=pseudonymization_key_id,
    ).iter_private_sessions(path)


def iter_cyberlab_sessions(
    path: Path | str,
    *,
    source_member: Mapping[str, Any],
    provenance: Mapping[str, Any],
    pseudonymization_key: bytes,
    pseudonymization_key_id: str,
) -> Iterator[dict[str, Any]]:
    return CyberLabAdapter(
        source_member=source_member,
        provenance=provenance,
        pseudonymization_key=pseudonymization_key,
        pseudonymization_key_id=pseudonymization_key_id,
    ).iter_sessions(path)


__all__ = [
    "ADAPTER_SCHEMA_VERSION",
    "ADAPTER_RECEIPT_SCHEMA_VERSION",
    "CANONICAL_SESSION_SCHEMA_VERSION",
    "CyberLabAdapter",
    "CyberLabAdapterError",
    "HIGH_INTERACTION_SENSOR",
    "PRIVATE_SESSION_SCHEMA_VERSION",
    "SOURCE_SCHEMA_VERSION",
    "ZENODO_DOI",
    "ZENODO_RECORD_ID",
    "high_interaction_decision",
    "iter_cyberlab_private_sessions",
    "iter_cyberlab_sessions",
    "merge_cyberlab_private_sessions",
    "require_adapter_provenance",
    "require_valid_adapter_policy",
    "require_valid_adapter_receipt",
    "require_valid_cyberlab_session",
    "validate_adapter_policy",
    "validate_adapter_receipt",
    "validate_adapter_provenance",
    "validate_cyberlab_session",
]
