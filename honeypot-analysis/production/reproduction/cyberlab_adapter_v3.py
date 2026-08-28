"""CyberLab adapter v3: explicit missing-command quarantine barriers.

v2 correctly moved sensor eligibility before semantic parsing, but an eligible
session with a missing command-input payload must not be repaired by silently
dropping the event.  v3 quarantines only that narrowly defined missing-evidence
case.  The quarantine is not a classifier event or label and becomes a causal
barrier.  Segment construction keeps trusted groups on either side separate;
earlier segments are active/unresolved and only the final segment inherits an
explicit ``cowrie.session.closed`` terminal state.

All other v2/v1 validation, duplicate handling, privacy, and provenance rules
remain strict and unchanged.  The private event shape remains compatible with
the reviewed v1 base contract; v3 is a separately versioned adapter boundary.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections import OrderedDict
from pathlib import Path
from typing import Any, Iterator, Mapping

from production.reproduction.cyberlab_adapter import (
    ADAPTER_SCHEMA_VERSION as V1_ADAPTER_SCHEMA_VERSION,
    CyberLabAdapterError,
    HIGH_INTERACTION_SENSOR,
    PRIVATE_SESSION_SCHEMA_VERSION,
    _CLOSE_TYPE,
    _DATE,
    _deduplicate_events,
    _event_fingerprint,
    _iter_json_array,
    _normalize_raw_event,
    _raw_session,
    _safe_digest,
    _session_item,
    _clean,
    _parse_timestamp,
    _SAFE_KEY_ID,
    _sha256,
    _safe_session,
    require_adapter_provenance,
    require_valid_cyberlab_session,
)
from production.reproduction.cyberlab_adapter_v2 import (
    ELIGIBLE_REASON,
    MIXED_OR_MISSING_SENSOR_REASON,
    MIXED_SENSOR_REASON,
    MISSING_SENSOR_REASON,
    WRONG_SENSOR_REASON,
    _sensor_preflight,
    high_interaction_decision as _v2_high_interaction_decision,
    merge_cyberlab_private_sessions as _v2_merge,
)
from production.utils.serialization import stable_id, stable_json


ADAPTER_SCHEMA_VERSION = "cyberlab_cowrie_adapter.v3"
ADAPTER_RECEIPT_SCHEMA_VERSION = "cyberlab_external_adapter_receipt.v3"
SOURCE_SCHEMA_VERSION = "cyberlab_session_array.v1"
QUARANTINE_SCHEMA_VERSION = "cyberlab_missing_evidence_quarantine.v1"
QUARANTINE_REASON = "missing_command_text"
SEGMENT_SCHEMA_VERSION = "cyberlab_causal_segment.v1"

_POLICY_FIELDS = {
    "schema_version", "previous_adapter_schema_version", "private_session_schema_version",
    "source", "eligibility_ordering", "quarantine_contract", "session_contract", "privacy", "provenance",
}
_RECEIPT_FIELDS = {
    "schema_version", "adapter_schema_version", "previous_adapter_schema_version",
    "source_policy_path", "adapter_path", "documentation_path", "fixture_path",
    "previous_receipt_path", "source_policy_sha256", "adapter_sha256", "documentation_sha256",
    "fixture_sha256", "previous_receipt_sha256", "test_result", "real_external_data_accessed",
    "sealed_test_accessed", "quarantine_contract", "receipt_id",
}


def _missing_command(event: Mapping[str, Any]) -> bool:
    """Match exactly the v1 missing-command condition, without broadening it."""

    message = event.get("message")
    command = _clean(event.get("input"))
    if command:
        return False
    if isinstance(message, str):
        payload = message.strip()
        return not (payload.startswith("CMD: ") and payload[5:].strip())
    return True


def _quarantine_record(
    event: Mapping[str, Any],
    *,
    raw_session_id: str,
    source_member: Mapping[str, Any],
    event_order: int,
) -> dict[str, Any]:
    """Create private-only missing-evidence metadata after strict base checks."""

    # _normalize_raw_event has already verified timestamp/sensor/protocol and
    # failed only because command text was absent.  Recompute the canonical
    # timestamp and identity without retaining source command/message fields.
    timestamp, _ = _parse_timestamp(event.get("timestamp"))
    event_key = ("cowrie.command.input", timestamp, raw_session_id)
    event_id = stable_id(
        "cyberlabevent",
        {
            "source_member": _clean(source_member.get("filename")),
            "session_id": raw_session_id,
            "event_type": "cowrie.command.input",
            "timestamp": timestamp,
            "fingerprint": _event_fingerprint({**event, "session_id": raw_session_id}),
        },
    )
    return {
        "schema_version": QUARANTINE_SCHEMA_VERSION,
        "event_id": event_id,
        "event_key": event_key,
        "source_member": _clean(source_member.get("filename")),
        "source_member_date": _clean(source_member.get("collection_date")),
        "source_event_order": event_order,
        "event_order": event_order,
        "event_time": timestamp,
        "event_type": "cowrie.command.input",
        "sensor": HIGH_INTERACTION_SENSOR,
        "reason_code": QUARANTINE_REASON,
        "barrier": True,
        "source_fingerprint": _event_fingerprint({**event, "session_id": raw_session_id}),
    }


def _quarantine_identity(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        stable_json(
            {
                "event_key": tuple(value.get("event_key") or ()),
                "event_time": value.get("event_time"),
                "event_type": value.get("event_type"),
                "sensor": value.get("sensor"),
                "reason_code": value.get("reason_code"),
                "source_fingerprint": value.get("source_fingerprint"),
            }
        ).encode("utf-8")
    ).hexdigest()


def _deduplicate_quarantines(
    quarantines: list[Mapping[str, Any]], normalized: list[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    by_key: dict[tuple[Any, ...], str] = {}
    by_identity: dict[str, dict[str, Any]] = {}
    normalized_keys = {tuple(event.get("event_key") or ()) for event in normalized}
    for item in quarantines:
        key = tuple(item.get("event_key") or ())
        if not key:
            raise CyberLabAdapterError("quarantine event key is required")
        if key in normalized_keys:
            raise CyberLabAdapterError("conflicting duplicate event")
        identity = _quarantine_identity(item)
        prior = by_key.get(key)
        if prior is not None and prior != identity:
            raise CyberLabAdapterError("conflicting duplicate event")
        by_key[key] = identity
        by_identity[identity] = dict(item)
    return sorted(
        by_identity.values(),
        key=lambda item: (
            item["event_time"], int(item.get("source_event_order", item["event_order"])), item["event_id"]
        ),
    )


def _raw_session_v3(
    raw_session_id: str,
    events: list[dict[str, Any]],
    quarantines: list[Mapping[str, Any]],
    *,
    source_member: Mapping[str, Any],
) -> dict[str, Any]:
    private = _raw_session(raw_session_id, _deduplicate_events(events), source_member=source_member)
    checked_quarantines = _deduplicate_quarantines(quarantines, private["events"])
    if checked_quarantines:
        private["quarantine_events"] = checked_quarantines
        private["quarantine_barrier_count"] = len(checked_quarantines)
    return private


def _merge_eligible(records: list[Mapping[str, Any]]) -> dict[str, Any]:
    base_records = []
    quarantines: list[Mapping[str, Any]] = []
    for record in records:
        current = dict(record)
        current.pop("quarantine_events", None)
        current.pop("quarantine_barrier_count", None)
        base_records.append(current)
        quarantines.extend(record.get("quarantine_events") or [])
    merged = _v2_merge(base_records)
    if len(merged) != 1:
        raise CyberLabAdapterError("eligible session merge identity is not unique")
    current = merged[0]
    checked = _deduplicate_quarantines(quarantines, current.get("events") or [])
    if checked:
        current["quarantine_events"] = checked
        current["quarantine_barrier_count"] = len(checked)
    return current


def merge_cyberlab_private_sessions(sessions: Any) -> list[dict[str, Any]]:
    """Merge v3 records while retaining quarantine barriers and exclusions."""

    grouped: OrderedDict[str, list[Mapping[str, Any]]] = OrderedDict()
    for value in sessions:
        if not isinstance(value, Mapping):
            raise CyberLabAdapterError("private session must be an object")
        raw_id = _clean(value.get("raw_session_id"))
        if not raw_id:
            raise CyberLabAdapterError("private session identity is required")
        grouped.setdefault(raw_id, []).append(value)
    output: list[dict[str, Any]] = []
    for records in grouped.values():
        if any("eligibility_reason" in item for item in records):
            output.extend(_v2_merge(records))
        else:
            output.append(_merge_eligible(records))
    return output


def _event_source_order(event: Mapping[str, Any]) -> int:
    return int(event.get("source_event_order", event.get("event_order", 0)))


def split_private_session_at_quarantine(private: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return causal segments; no target can cross a quarantined event."""

    barriers = sorted(
        private.get("quarantine_events") or [],
        key=lambda item: (_event_source_order(item), item["event_time"], item["event_id"]),
    )
    if not barriers:
        return [dict(private)]
    events = sorted(
        private.get("events") or [],
        key=lambda item: (_event_source_order(item), item["event_time"], item["event_id"]),
    )
    buckets: list[list[dict[str, Any]]] = [[] for _ in range(len(barriers) + 1)]
    for event in events:
        segment = sum(
            _event_source_order(event) > _event_source_order(barrier)
            for barrier in barriers
        )
        buckets[segment].append(dict(event))
    nonempty = [index for index, bucket in enumerate(buckets) if bucket]
    segments: list[dict[str, Any]] = []
    final_nonempty = nonempty[-1] if nonempty else -1
    for index, bucket in enumerate(buckets):
        if not bucket:
            continue
        segment = copy.deepcopy(dict(private))
        segment["schema_version"] = SEGMENT_SCHEMA_VERSION
        segment["raw_session_id"] = f"{_clean(private['raw_session_id'])}:quarantine-segment:{index}"
        segment["events"] = [
            {**event, "event_order": position} for position, event in enumerate(bucket)
        ]
        segment["segment_index"] = index
        segment["segment_count"] = len(nonempty)
        segment["quarantine_barrier_before"] = index > 0
        # A prior segment has no durable close authority.  Only the final
        # segment can inherit explicit session.closed from the source session.
        if index != final_nonempty:
            segment["status"] = "active"
            segment["termination_status"] = "unresolved"
        segment.pop("quarantine_events", None)
        segment.pop("quarantine_barrier_count", None)
        segments.append(segment)
    return segments


class CyberLabAdapter:
    """v3 adapter with sensor-first validation and missing-evidence barriers."""

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
        if not isinstance(maximum_events_per_session, int) or isinstance(maximum_events_per_session, bool) or maximum_events_per_session < 1:
            raise CyberLabAdapterError("maximum_events_per_session is invalid")
        filename = _clean(source_member.get("filename"))
        date = _clean(source_member.get("collection_date"))
        if not filename.endswith(".json.gz") or "/" in filename or "\\" in filename:
            raise CyberLabAdapterError("source member filename is invalid")
        if not _DATE.fullmatch(date):
            raise CyberLabAdapterError("source member date is invalid")
        if not _sha256(source_member.get("sha256")):
            raise CyberLabAdapterError("source member SHA-256 is required")
        checked = require_adapter_provenance(provenance)
        if checked["adapter_schema_version"] != V1_ADAPTER_SCHEMA_VERSION:
            raise CyberLabAdapterError("v3 adapter requires the v1 private provenance base")
        if checked["source_filename"] != filename or checked["source_member_date"] != date:
            raise CyberLabAdapterError("provenance source member identity disagrees")
        if checked["source_sha256"] != _clean(source_member["sha256"]).lower():
            raise CyberLabAdapterError("provenance source hash disagrees with source member")
        self.source_member = dict(source_member)
        self.provenance = checked
        self.key = pseudonymization_key
        self.key_id = _clean(pseudonymization_key_id)
        self.maximum_events_per_session = maximum_events_per_session

    def iter_private_sessions(self, path: Path | str) -> Iterator[dict[str, Any]]:
        try:
            handle = __import__("gzip").open(Path(path), "rt", encoding="utf-8", errors="strict")
        except OSError as exc:
            raise CyberLabAdapterError("cannot open CyberLab gzip member") from exc
        with handle:
            for item in _iter_json_array(handle):
                raw_id, raw_events = _session_item(item)
                eligible, reason = _sensor_preflight(raw_events)
                if not eligible:
                    # v2 owns the metadata-only exclusion representation.
                    from production.reproduction.cyberlab_adapter_v2 import _excluded_private_session
                    yield _excluded_private_session(raw_id, raw_events, source_member=self.source_member, reason=reason)
                    continue
                if len(raw_events) > self.maximum_events_per_session:
                    raise CyberLabAdapterError("session event limit exceeded")
                normalized: list[dict[str, Any]] = []
                quarantines: list[Mapping[str, Any]] = []
                for index, event in enumerate(raw_events):
                    if _clean(event.get("eventid")) == "cowrie.command.input" and _missing_command(event):
                        try:
                            _normalize_raw_event(event, raw_session_id=raw_id, source_member=self.source_member, event_order=index)
                        except CyberLabAdapterError as exc:
                            if str(exc) != "command.input has no exact command text":
                                raise
                            quarantines.append(_quarantine_record(event, raw_session_id=raw_id, source_member=self.source_member, event_order=index))
                            continue
                    normalized.append(_normalize_raw_event(event, raw_session_id=raw_id, source_member=self.source_member, event_order=index))
                yield _raw_session_v3(raw_id, normalized, quarantines, source_member=self.source_member)

    def iter_segment_private_sessions(self, path: Path | str) -> Iterator[dict[str, Any]]:
        for private in self.iter_private_sessions(path):
            if _clean(private.get("eligibility_reason")):
                yield private
            else:
                yield from split_private_session_at_quarantine(private)

    def iter_sessions(self, path: Path | str) -> Iterator[dict[str, Any]]:
        for private in self.iter_segment_private_sessions(path):
            if not _v2_high_interaction_decision(private)["eligible"]:
                continue
            safe = _safe_session(private, provenance=self.provenance, source_member=self.source_member, key=self.key, key_id=self.key_id)
            require_valid_cyberlab_session(safe)
            yield safe

    def build_private_classifier_events(self, private_session: Mapping[str, Any]) -> list[dict[str, Any]]:
        if _clean(private_session.get("schema_version")) not in {PRIVATE_SESSION_SCHEMA_VERSION, SEGMENT_SCHEMA_VERSION}:
            raise CyberLabAdapterError("private session schema_version is invalid")
        if not _v2_high_interaction_decision(private_session)["eligible"]:
            raise CyberLabAdapterError("ineligible session cannot enter classifier stream")
        events = []
        for event in private_session.get("events") or []:
            item = {
                "session": private_session["raw_session_id"], "session_id": private_session["raw_session_id"],
                "eventid": event["event_type"], "timestamp": event["event_time"], "protocol": event["protocol"],
                "sensor": event["sensor"], "cyberlab_outcome_association": event["outcome_association"],
            }
            if event["event_type"] == "cowrie.command.input":
                item["input"] = event["command"]
            events.append(item)
        return events


def validate_adapter_policy(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return ["CyberLab v3 adapter policy must be an object"]
    errors = [f"policy.{key} is not defined" for key in sorted(set(value) - _POLICY_FIELDS)]
    errors.extend(f"policy.{key} is required" for key in sorted(_POLICY_FIELDS - set(value)))
    if value.get("schema_version") != ADAPTER_SCHEMA_VERSION:
        errors.append("policy.schema_version is invalid")
    if value.get("previous_adapter_schema_version") != "cyberlab_cowrie_adapter.v2":
        errors.append("policy.previous_adapter_schema_version is invalid")
    if value.get("private_session_schema_version") != PRIVATE_SESSION_SCHEMA_VERSION:
        errors.append("policy.private_session_schema_version is invalid")
    source = value.get("source")
    if not isinstance(source, Mapping) or source.get("zenodo_record_id") != 3687527 or source.get("doi") != "10.5281/zenodo.3687527":
        errors.append("policy.source is invalid")
    ordering = value.get("eligibility_ordering")
    if not isinstance(ordering, Mapping) or ordering.get("required_sensor") != HIGH_INTERACTION_SENSOR or ordering.get("stage") != "before_event_semantic_validation":
        errors.append("policy.eligibility_ordering is invalid")
    quarantine = value.get("quarantine_contract")
    expected = {
        "schema_version": QUARANTINE_SCHEMA_VERSION,
        "missing_command_reason": QUARANTINE_REASON,
        "trusted_label_emitted": False,
        "attack_label_emitted": False,
        "transition_across_barrier": False,
        "segment_status_before_barrier": "active_unresolved",
        "terminal_authority": _CLOSE_TYPE,
    }
    if quarantine != expected:
        errors.append("policy.quarantine_contract is invalid")
    return errors


def require_valid_adapter_policy(value: Any) -> dict[str, Any]:
    errors = validate_adapter_policy(value)
    if errors:
        raise CyberLabAdapterError("; ".join(errors))
    return dict(value)


def validate_adapter_receipt(value: Any, *, repository_root: Path | None = None) -> list[str]:
    if not isinstance(value, Mapping):
        return ["CyberLab v3 adapter receipt must be an object"]
    errors = [f"receipt.{key} is not defined" for key in sorted(set(value) - _RECEIPT_FIELDS)]
    errors.extend(f"receipt.{key} is required" for key in sorted(_RECEIPT_FIELDS - set(value)))
    if value.get("schema_version") != ADAPTER_RECEIPT_SCHEMA_VERSION:
        errors.append("receipt.schema_version is invalid")
    if value.get("adapter_schema_version") != ADAPTER_SCHEMA_VERSION:
        errors.append("receipt.adapter_schema_version is invalid")
    if value.get("previous_adapter_schema_version") != "cyberlab_cowrie_adapter.v2":
        errors.append("receipt.previous_adapter_schema_version is invalid")
    for field in ("source_policy_sha256", "adapter_sha256", "documentation_sha256", "fixture_sha256", "previous_receipt_sha256"):
        if not _sha256(value.get(field)):
            errors.append(f"receipt.{field} must be SHA-256")
    expected = {
        "schema_version": QUARANTINE_SCHEMA_VERSION, "missing_command_reason": QUARANTINE_REASON,
        "trusted_label_emitted": False, "attack_label_emitted": False,
        "transition_across_barrier": False, "segment_status_before_barrier": "active_unresolved", "terminal_authority": _CLOSE_TYPE,
    }
    if value.get("quarantine_contract") != expected:
        errors.append("receipt.quarantine_contract is invalid")
    if value.get("test_result") != "36 passed":
        errors.append("receipt.test_result is not the reviewed result")
    if value.get("real_external_data_accessed") is not False or value.get("sealed_test_accessed") is not False:
        errors.append("receipt access flags are invalid")
    identity = dict(value)
    receipt_id = identity.pop("receipt_id", None)
    if stable_id("cyberlabadapterreceiptv3", identity) != receipt_id:
        errors.append("receipt_id does not match receipt content")
    if repository_root is not None:
        bindings = {
            "source_policy_path": "source_policy_sha256", "adapter_path": "adapter_sha256",
            "documentation_path": "documentation_sha256", "fixture_path": "fixture_sha256", "previous_receipt_path": "previous_receipt_sha256",
        }
        for path_field, hash_field in bindings.items():
            path = repository_root / _clean(value.get(path_field))
            if path.is_symlink() or not path.is_file():
                errors.append(f"receipt.{path_field} is not a regular repository file")
            elif hashlib.sha256(path.read_bytes()).hexdigest() != value.get(hash_field):
                errors.append(f"receipt.{hash_field} does not match repository bytes")
    return errors


def require_valid_adapter_receipt(value: Any, *, repository_root: Path | None = None) -> dict[str, Any]:
    errors = validate_adapter_receipt(value, repository_root=repository_root)
    if errors:
        raise CyberLabAdapterError("; ".join(errors))
    return dict(value)


__all__ = [
    "ADAPTER_RECEIPT_SCHEMA_VERSION", "ADAPTER_SCHEMA_VERSION", "CyberLabAdapter", "CyberLabAdapterError",
    "QUARANTINE_REASON", "QUARANTINE_SCHEMA_VERSION", "SEGMENT_SCHEMA_VERSION",
    "high_interaction_decision", "merge_cyberlab_private_sessions", "require_valid_adapter_policy",
    "require_valid_adapter_receipt", "split_private_session_at_quarantine", "validate_adapter_policy", "validate_adapter_receipt",
]


def high_interaction_decision(private_session: Mapping[str, Any]) -> dict[str, Any]:
    return _v2_high_interaction_decision(private_session)
