"""Multi-member safe reconstruction for the CyberLab external adapter.

This is a successor contract to ``cyberlab_canonical_session.v1``.  The v1
adapter intentionally rejects a cross-file session at its single-member safe
boundary.  This module adds only the missing, content-addressed receipt and
does not change parsing, classification, trust, or target semantics.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence

from production.reproduction.cyberlab_adapter import (
    CyberLabAdapterError,
    HIGH_INTERACTION_SENSOR,
    _DATE,
    _MD5,
    _SHA256,
    _clean,
    _parse_timestamp,
    _safe_digest,
    merge_cyberlab_private_sessions,
    require_adapter_provenance,
    validate_adapter_provenance,
)
from production.reproduction.next_behavior.corpus import PSEUDONYMIZATION_SCHEME
from production.utils.serialization import stable_id, stable_json


MULTIMEMBER_RECEIPT_SCHEMA_VERSION = "cyberlab_multi_member_safe_receipt.v1"
MULTIMEMBER_SESSION_SCHEMA_VERSION = "cyberlab_canonical_session.v2"


def _member_receipt(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise CyberLabAdapterError("source member receipt must be an object")
    required = {
        "filename",
        "collection_date",
        "chronological_order",
        "size_bytes",
        "sha256",
        "checksum_md5",
    }
    if set(value) != required:
        raise CyberLabAdapterError("source member receipt fields are invalid")
    filename = _clean(value.get("filename"))
    if not filename.endswith(".json.gz") or "/" in filename or "\\" in filename:
        raise CyberLabAdapterError("source member filename is unsafe")
    if not _DATE.fullmatch(_clean(value.get("collection_date"))):
        raise CyberLabAdapterError("source member collection date is invalid")
    for field in ("chronological_order", "size_bytes"):
        item = value.get(field)
        if isinstance(item, bool) or not isinstance(item, int) or item < 1:
            raise CyberLabAdapterError(f"source member {field} is invalid")
    if not _SHA256.fullmatch(_clean(value.get("sha256")).lower()):
        raise CyberLabAdapterError("source member SHA-256 is invalid")
    if not _MD5.fullmatch(_clean(value.get("checksum_md5")).lower()):
        raise CyberLabAdapterError("source member MD5 is invalid")
    return {
        "filename": filename,
        "collection_date": _clean(value["collection_date"]),
        "chronological_order": value["chronological_order"],
        "size_bytes": value["size_bytes"],
        "sha256": _clean(value["sha256"]).lower(),
        "checksum_md5": _clean(value["checksum_md5"]).lower(),
    }


def _member_receipts_hash(receipts: Sequence[Mapping[str, Any]]) -> str:
    return hashlib.sha256(
        stable_json(list(receipts)).encode("utf-8")
    ).hexdigest()


def _safe_events(private_session: Mapping[str, Any], key: bytes) -> list[dict[str, Any]]:
    raw_session_id = _clean(private_session.get("raw_session_id"))
    events: list[dict[str, Any]] = []
    seen_keys: set[tuple[Any, ...]] = set()
    for event in private_session.get("events") or []:
        key_value = tuple(event.get("event_key") or ())
        if not key_value:
            raise CyberLabAdapterError("event key is required for reconstruction")
        if key_value in seen_keys:
            raise CyberLabAdapterError("duplicate event survived reconstruction")
        seen_keys.add(key_value)
        safe = {
            "event_id": _safe_digest(
                f"{raw_session_id}:{event['event_id']}", key=key
            ),
            "event_order": int(event["event_order"]),
            "event_time": event["event_time"],
            "event_type": event["event_type"],
            "protocol": event["protocol"],
            "sensor": event["sensor"],
            "outcome": event["outcome"],
            "outcome_association": event["outcome_association"],
        }
        command_digest = _clean(event.get("command_digest"))
        if command_digest:
            safe["command_evidence_ref"] = _safe_digest(
                f"{raw_session_id}:{event['event_id']}:{command_digest}",
                key=key,
            )
            safe["command_length"] = len(event.get("command") or "")
        events.append(safe)
    if not events:
        raise CyberLabAdapterError("reconstructed session has no events")
    return events


def build_multi_member_safe_receipt(
    private_session: Mapping[str, Any],
    member_receipts: Sequence[Mapping[str, Any]],
    *,
    provenance: Mapping[str, Any],
    pseudonymization_key: bytes,
    pseudonymization_key_id: str,
) -> dict[str, Any]:
    """Build a deterministic safe receipt for one merged session."""

    if not isinstance(pseudonymization_key, bytes) or len(pseudonymization_key) < 32:
        raise CyberLabAdapterError("pseudonymization key must contain 32 bytes")
    if not _clean(private_session.get("raw_session_id")):
        raise CyberLabAdapterError("private session identity is required")
    if not isinstance(member_receipts, Sequence) or not member_receipts:
        raise CyberLabAdapterError("member receipts are required")
    receipts = [_member_receipt(item) for item in member_receipts]
    receipts.sort(key=lambda item: item["chronological_order"])
    if len({item["filename"] for item in receipts}) != len(receipts):
        raise CyberLabAdapterError("source member receipts are duplicated")
    orders = [item["chronological_order"] for item in receipts]
    if orders != list(range(orders[0], orders[0] + len(orders))):
        raise CyberLabAdapterError("source member chronological order is not contiguous")
    source_members = sorted(_clean(item) for item in private_session.get("source_members") or [])
    receipt_names = sorted(item["filename"] for item in receipts)
    if source_members != receipt_names:
        raise CyberLabAdapterError("private/source-member receipt identities differ")
    checked_provenance = require_adapter_provenance(provenance)
    if checked_provenance["source_filename"] not in receipt_names:
        raise CyberLabAdapterError("provenance source member is not in reconstruction")
    if checked_provenance["source_sha256"] != next(
        item["sha256"] for item in receipts
        if item["filename"] == checked_provenance["source_filename"]
    ):
        raise CyberLabAdapterError("provenance source hash is not receipt-bound")
    if not private_session.get("cross_file") and len(receipts) > 1:
        raise CyberLabAdapterError("multi-member receipt requires a cross-file session")
    status = _clean(private_session.get("status"))
    termination = _clean(private_session.get("termination_status"))
    if (status, termination) not in {
        ("active", "unresolved"),
        ("closed", "explicit_closed"),
    }:
        raise CyberLabAdapterError("session termination state is invalid")
    safe_session = {
        "schema_version": MULTIMEMBER_SESSION_SCHEMA_VERSION,
        "session_id": _safe_digest(
            _clean(private_session["raw_session_id"]),
            key=pseudonymization_key,
            kind="session",
        ),
        "source_member_ids": [
            _safe_digest(item["filename"], key=pseudonymization_key, kind="member")
            for item in receipts
        ],
        "source_member_receipt_refs": [
            {
                "filename": item["filename"],
                "member_id": _safe_digest(
                    item["filename"], key=pseudonymization_key, kind="member"
                ),
                "collection_date": item["collection_date"],
                "chronological_order": item["chronological_order"],
                "size_bytes": item["size_bytes"],
                "sha256": item["sha256"],
                "checksum_md5": item["checksum_md5"],
            }
            for item in receipts
        ],
        "source_member_receipts_sha256": _member_receipts_hash(receipts),
        "protocol": _clean(private_session.get("protocol")).lower(),
        "status": status,
        "termination_status": termination,
        "high_interaction_eligibility": _clean(
            private_session.get("high_interaction_eligibility")
        ),
        "cross_file": len(receipts) > 1,
        "events": _safe_events(private_session, pseudonymization_key),
        "provenance": {
            **checked_provenance,
            "pseudonymization_scheme": PSEUDONYMIZATION_SCHEME,
            "pseudonymization_key_id": _clean(pseudonymization_key_id),
            "reconstruction_schema_version": MULTIMEMBER_RECEIPT_SCHEMA_VERSION,
        },
    }
    session_sha256 = hashlib.sha256(stable_json(safe_session).encode()).hexdigest()
    receipt = {
        "schema_version": MULTIMEMBER_RECEIPT_SCHEMA_VERSION,
        "status": "safe_session_reconstructed",
        "session": safe_session,
        "session_sha256": session_sha256,
        "source_member_receipts_sha256": safe_session[
            "source_member_receipts_sha256"
        ],
        "replay_identity": stable_id(
            "cyberlabmultimemberreplay",
            {
                "session_sha256": session_sha256,
                "source_member_receipts_sha256": safe_session[
                    "source_member_receipts_sha256"
                ],
                "adapter_schema_version": checked_provenance[
                    "adapter_schema_version"
                ],
            },
        ),
        "interruption_safe": True,
    }
    receipt["receipt_id"] = stable_id(
        "cyberlabmultimemberreceipt",
        {key: value for key, value in receipt.items() if key != "receipt_id"},
    )
    return receipt


def validate_multi_member_safe_receipt(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return ["multi-member receipt must be an object"]
    allowed_receipt_fields = {
        "schema_version",
        "status",
        "session",
        "session_sha256",
        "source_member_receipts_sha256",
        "replay_identity",
        "interruption_safe",
        "receipt_id",
    }
    errors: list[str] = [
        f"receipt.{field} is not defined by the contract"
        for field in sorted(set(value) - allowed_receipt_fields)
    ]
    if value.get("schema_version") != MULTIMEMBER_RECEIPT_SCHEMA_VERSION:
        errors.append("multi-member receipt schema_version is invalid")
    if value.get("status") != "safe_session_reconstructed":
        errors.append("multi-member receipt status is invalid")
    if value.get("interruption_safe") is not True:
        errors.append("multi-member receipt must be interruption-safe")
    session = value.get("session")
    if not isinstance(session, Mapping):
        errors.append("multi-member session is required")
        return errors
    allowed_session_fields = {
        "schema_version",
        "session_id",
        "source_member_ids",
        "source_member_receipt_refs",
        "source_member_receipts_sha256",
        "protocol",
        "status",
        "termination_status",
        "high_interaction_eligibility",
        "cross_file",
        "events",
        "provenance",
    }
    errors.extend(
        f"session.{field} is not defined by the contract"
        for field in sorted(set(session) - allowed_session_fields)
    )
    if session.get("schema_version") != MULTIMEMBER_SESSION_SCHEMA_VERSION:
        errors.append("multi-member session schema_version is invalid")
    if session.get("cross_file") is not True:
        errors.append("multi-member session must be cross_file")
    if session.get("status") not in {"active", "closed"}:
        errors.append("multi-member session status is invalid")
    if session.get("termination_status") not in {"unresolved", "explicit_closed"}:
        errors.append("multi-member session termination status is invalid")
    if session.get("status") == "active" and session.get("termination_status") != "unresolved":
        errors.append("active session must be unresolved")
    if session.get("status") == "closed" and session.get("termination_status") != "explicit_closed":
        errors.append("closed session must be explicitly closed")
    if session.get("protocol") not in {"ssh", "telnet", "unknown"}:
        errors.append("multi-member session protocol is invalid")
    if session.get("high_interaction_eligibility") not in {
        "eligible",
        "wrong_sensor",
        "mixed_sensor",
    }:
        errors.append("multi-member high-interaction eligibility is invalid")
    if not _clean(session.get("session_id")):
        errors.append("multi-member session ID is required")
    source_ids = session.get("source_member_ids")
    if not isinstance(source_ids, list):
        errors.append("source member IDs are required")
    member_refs = session.get("source_member_receipt_refs")
    if not isinstance(member_refs, list) or len(member_refs) < 2:
        errors.append("at least two member receipt refs are required")
    else:
        normalized = []
        for index, item in enumerate(member_refs):
            try:
                if set(item) != {
                    "filename",
                    "member_id",
                    "collection_date",
                    "chronological_order",
                    "size_bytes",
                    "sha256",
                    "checksum_md5",
                }:
                    errors.append("member receipt ref fields are invalid")
                normalized.append(
                    _member_receipt(
                        {
                            key: item[key]
                            for key in (
                                "filename",
                                "collection_date",
                                "chronological_order",
                                "size_bytes",
                                "sha256",
                                "checksum_md5",
                            )
                        }
                    )
                )
                if not isinstance(source_ids, list) or index >= len(source_ids):
                    errors.append("source member ID count does not match receipts")
                elif _clean(item["member_id"]) != _clean(source_ids[index]):
                    errors.append("member receipt ref member_id does not resolve")
            except (KeyError, TypeError, IndexError, AttributeError):
                errors.append("member receipt ref is malformed")
        if not errors:
            normalized.sort(key=lambda item: item["chronological_order"])
            orders = [item["chronological_order"] for item in normalized]
            if orders != list(range(orders[0], orders[0] + len(orders))):
                errors.append("source member chronological order is not contiguous")
            if _member_receipts_hash(normalized) != session.get(
                "source_member_receipts_sha256"
            ):
                errors.append("source member receipt hash is invalid")
            if value.get("source_member_receipts_sha256") != session.get(
                "source_member_receipts_sha256"
            ):
                errors.append("top-level source member receipt hash is invalid")
            if len(session.get("source_member_ids") or []) != len(normalized):
                errors.append("source member ID count does not match receipts")
    provenance = session.get("provenance")
    base_provenance = (
        {
            key: item
            for key, item in provenance.items()
            if key != "reconstruction_schema_version"
        }
        if isinstance(provenance, Mapping)
        else provenance
    )
    errors.extend(
        f"provenance.{error}"
        for error in validate_adapter_provenance(base_provenance)
    )
    if isinstance(provenance, Mapping):
        if provenance.get("pseudonymization_scheme") != PSEUDONYMIZATION_SCHEME:
            errors.append("provenance pseudonymization scheme is invalid")
        if not _clean(provenance.get("pseudonymization_key_id")):
            errors.append("provenance pseudonymization key ID is required")
        if provenance.get("reconstruction_schema_version") != MULTIMEMBER_RECEIPT_SCHEMA_VERSION:
            errors.append("provenance reconstruction schema version is invalid")
    events = session.get("events")
    if not isinstance(events, list) or not events:
        errors.append("multi-member events are required")
    else:
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
        orders = []
        for event in events:
            if not isinstance(event, Mapping):
                errors.append("multi-member event is malformed")
                continue
            errors.extend(
                f"multi-member event field {field} is not defined by the contract"
                for field in sorted(set(event) - allowed_event_fields)
            )
            if not _clean(event.get("event_id")) or not _clean(event.get("event_type")):
                errors.append("multi-member event identity/type is required")
            order = event.get("event_order")
            if isinstance(order, bool) or not isinstance(order, int) or order < 0:
                errors.append("multi-member event order is invalid")
            else:
                orders.append(order)
            try:
                _parse_timestamp(event.get("event_time"))
            except CyberLabAdapterError:
                errors.append("multi-member event time is invalid")
            if any(
                field in event for field in ("command", "message", "src_ip", "source_ip")
            ):
                errors.append("multi-member event contains private source data")
        if orders != list(range(len(orders))):
            errors.append("multi-member events are not in canonical order")
    if not _SHA256.fullmatch(_clean(value.get("session_sha256"))):
        errors.append("session_sha256 is invalid")
    elif hashlib.sha256(stable_json(session).encode()).hexdigest() != value.get(
        "session_sha256"
    ):
        errors.append("session_sha256 does not match session content")
    expected_replay = stable_id(
        "cyberlabmultimemberreplay",
        {
            "session_sha256": value.get("session_sha256"),
            "source_member_receipts_sha256": session.get(
                "source_member_receipts_sha256"
            ),
            "adapter_schema_version": (session.get("provenance") or {}).get(
                "adapter_schema_version"
            ),
        },
    )
    if value.get("replay_identity") != expected_replay:
        errors.append("replay_identity does not match receipt content")
    expected_id = stable_id(
        "cyberlabmultimemberreceipt",
        {key: item for key, item in value.items() if key != "receipt_id"},
    )
    if value.get("receipt_id") != expected_id:
        errors.append("receipt_id does not match receipt content")
    return errors


def require_valid_multi_member_safe_receipt(value: Any) -> dict[str, Any]:
    errors = validate_multi_member_safe_receipt(value)
    if errors:
        raise CyberLabAdapterError("; ".join(errors))
    return dict(value)


def publish_multi_member_receipt(path: Path, receipt: Mapping[str, Any]) -> str:
    """Publish once, fsync, and never overwrite a different receipt."""

    checked = require_valid_multi_member_safe_receipt(receipt)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(checked, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode()
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CyberLabAdapterError("existing receipt is unreadable") from exc
        if existing != checked:
            raise CyberLabAdapterError("refusing to overwrite a different receipt")
        return "already_published"
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise CyberLabAdapterError("receipt publication raced with another writer") from exc
        return "published"
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


__all__ = [
    "MULTIMEMBER_RECEIPT_SCHEMA_VERSION",
    "MULTIMEMBER_SESSION_SCHEMA_VERSION",
    "build_multi_member_safe_receipt",
    "merge_cyberlab_private_sessions",
    "publish_multi_member_receipt",
    "require_valid_multi_member_safe_receipt",
    "validate_multi_member_safe_receipt",
]
