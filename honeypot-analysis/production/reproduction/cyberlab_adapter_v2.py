"""CyberLab adapter v2 with a metadata-first eligibility boundary.

The frozen v1 adapter normalizes every event before it evaluates the
``sensor`` policy.  CyberLab contains an ineligible session with a malformed
command event, so that order makes a source/configuration exclusion depend on
command parsing.  v2 changes only that ordering: the raw session shape and
sensor values are checked first, and strict v1 event normalization is still
used for every session whose sensor is exactly ``ubuntu_basic_pool``.

The private event/session shape deliberately remains
``cyberlab_private_session.v1``.  This keeps the reviewed multi-member and
privacy boundaries byte-compatible; the adapter boundary and receipt are the
new v2 identity.  Ineligible records contain no normalized events and are
never sent to the classifier or safe-session builder.
"""

from __future__ import annotations

from collections import OrderedDict
import hashlib
import json
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
    _message_command,
    _normalize_raw_event,
    _raw_session,
    _safe_digest,
    _session_item,
    _clean,
    _parse_timestamp,
    _SAFE_KEY_ID,
    _sha256,
    high_interaction_decision as _v1_high_interaction_decision,
    merge_cyberlab_private_sessions as _v1_merge,
    require_adapter_provenance,
    require_valid_adapter_receipt as require_valid_v1_receipt,
    validate_adapter_receipt as validate_v1_receipt,
)
from production.utils.serialization import stable_id


ADAPTER_SCHEMA_VERSION = "cyberlab_cowrie_adapter.v2"
ADAPTER_RECEIPT_SCHEMA_VERSION = "cyberlab_external_adapter_receipt.v2"
SOURCE_SCHEMA_VERSION = "cyberlab_session_array.v1"
ZENODO_RECORD_ID = 3687527
ZENODO_DOI = "10.5281/zenodo.3687527"

ELIGIBLE_REASON = "sensor_exact_match"
WRONG_SENSOR_REASON = "sensor_not_ubuntu_basic_pool"
MIXED_SENSOR_REASON = "mixed_sensor_values"
MISSING_SENSOR_REASON = "missing_sensor_value"
MIXED_OR_MISSING_SENSOR_REASON = "mixed_or_missing_sensor_values"

_V2_POLICY_FIELDS = {
    "schema_version",
    "previous_adapter_schema_version",
    "private_session_schema_version",
    "source",
    "eligibility_ordering",
    "session_contract",
    "privacy",
    "provenance",
}
_V2_RECEIPT_FIELDS = {
    "schema_version",
    "adapter_schema_version",
    "previous_adapter_schema_version",
    "private_session_schema_version",
    "source_policy_path",
    "adapter_path",
    "documentation_path",
    "fixture_path",
    "previous_receipt_path",
    "source_policy_sha256",
    "adapter_sha256",
    "documentation_sha256",
    "fixture_sha256",
    "previous_receipt_sha256",
    "test_result",
    "real_external_data_accessed",
    "sealed_test_accessed",
    "eligibility_ordering",
    "receipt_id",
}


def validate_adapter_policy(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return ["CyberLab v2 adapter policy must be an object"]
    errors = [f"policy.{key} is not defined" for key in sorted(set(value) - _V2_POLICY_FIELDS)]
    errors.extend(f"policy.{key} is required" for key in sorted(_V2_POLICY_FIELDS - set(value)))
    if value.get("schema_version") != ADAPTER_SCHEMA_VERSION:
        errors.append("policy.schema_version is invalid")
    if value.get("previous_adapter_schema_version") != V1_ADAPTER_SCHEMA_VERSION:
        errors.append("policy.previous_adapter_schema_version is invalid")
    if value.get("private_session_schema_version") != PRIVATE_SESSION_SCHEMA_VERSION:
        errors.append("policy.private_session_schema_version is invalid")
    source = value.get("source")
    if not isinstance(source, Mapping):
        errors.append("policy.source is required")
    else:
        if source.get("zenodo_record_id") != ZENODO_RECORD_ID:
            errors.append("policy.source.zenodo_record_id is invalid")
        if source.get("doi") != ZENODO_DOI:
            errors.append("policy.source.doi is invalid")
        if source.get("source_schema_version") != SOURCE_SCHEMA_VERSION:
            errors.append("policy.source.source_schema_version is invalid")
        if source.get("official_checksum_domain") != "md5":
            errors.append("policy.source.official_checksum_domain is invalid")
    ordering = value.get("eligibility_ordering")
    expected_ordering = {
        "stage": "before_event_semantic_validation",
        "metadata_fields": ["sensor"],
        "required_sensor": HIGH_INTERACTION_SENSOR,
        "wrong_sensor": "exclude_without_command_validation",
        "mixed_or_missing_sensor": "exclude_without_command_validation",
        "eligible_session": "run_v1_strict_event_validation",
        "eligible_malformed_event": "fail_closed",
        "command_content_used_for_eligibility": False,
        "labels_or_tactics_used_for_eligibility": False,
    }
    if ordering != expected_ordering:
        errors.append("policy.eligibility_ordering is invalid")
    return errors


def require_valid_adapter_policy(value: Any) -> dict[str, Any]:
    errors = validate_adapter_policy(value)
    if errors:
        raise CyberLabAdapterError("; ".join(errors))
    return dict(value)


def _regular_bound_file(root: Path, value: Any) -> tuple[Path | None, str | None]:
    relative = _clean(value)
    path = root / relative
    if not relative or path.is_symlink() or not path.is_file():
        return None, "path is not a regular repository file"
    return path, None


def validate_adapter_receipt(value: Any, *, repository_root: Path | None = None) -> list[str]:
    if not isinstance(value, Mapping):
        return ["CyberLab v2 adapter receipt must be an object"]
    errors = [f"receipt.{key} is not defined" for key in sorted(set(value) - _V2_RECEIPT_FIELDS)]
    errors.extend(f"receipt.{key} is required" for key in sorted(_V2_RECEIPT_FIELDS - set(value)))
    if value.get("schema_version") != ADAPTER_RECEIPT_SCHEMA_VERSION:
        errors.append("receipt.schema_version is invalid")
    if value.get("adapter_schema_version") != ADAPTER_SCHEMA_VERSION:
        errors.append("receipt.adapter_schema_version is invalid")
    if value.get("previous_adapter_schema_version") != V1_ADAPTER_SCHEMA_VERSION:
        errors.append("receipt.previous_adapter_schema_version is invalid")
    if value.get("private_session_schema_version") != PRIVATE_SESSION_SCHEMA_VERSION:
        errors.append("receipt.private_session_schema_version is invalid")
    for field in (
        "source_policy_sha256", "adapter_sha256", "documentation_sha256",
        "fixture_sha256", "previous_receipt_sha256",
    ):
        if not _sha256(value.get(field)):
            errors.append(f"receipt.{field} must be SHA-256")
    if value.get("test_result") != "24 passed":
        errors.append("receipt.test_result is not the reviewed result")
    if value.get("real_external_data_accessed") is not False:
        errors.append("receipt must record no real external data access")
    if value.get("sealed_test_accessed") is not False:
        errors.append("receipt must record no sealed-test access")
    expected_ordering = {
        "stage": "before_event_semantic_validation",
        "metadata_fields": ["sensor"],
        "required_sensor": HIGH_INTERACTION_SENSOR,
        "wrong_sensor": "exclude_without_command_validation",
        "mixed_or_missing_sensor": "exclude_without_command_validation",
        "eligible_session": "run_v1_strict_event_validation",
        "eligible_malformed_event": "fail_closed",
        "command_content_used_for_eligibility": False,
        "labels_or_tactics_used_for_eligibility": False,
    }
    if value.get("eligibility_ordering") != expected_ordering:
        errors.append("receipt.eligibility_ordering is invalid")
    identity = dict(value)
    receipt_id = identity.pop("receipt_id", None)
    if stable_id("cyberlabadapterreceiptv2", identity) != receipt_id:
        errors.append("receipt_id does not match receipt content")
    if repository_root is not None:
        bindings = {
            "source_policy_path": "source_policy_sha256",
            "adapter_path": "adapter_sha256",
            "documentation_path": "documentation_sha256",
            "fixture_path": "fixture_sha256",
            "previous_receipt_path": "previous_receipt_sha256",
        }
        for path_field, hash_field in bindings.items():
            path, problem = _regular_bound_file(repository_root, value.get(path_field))
            if problem:
                errors.append(f"receipt.{path_field} {problem}")
                continue
            assert path is not None
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != value.get(hash_field):
                errors.append(f"receipt.{hash_field} does not match repository bytes")
        previous_path = repository_root / _clean(value.get("previous_receipt_path"))
        if previous_path.is_file() and not previous_path.is_symlink():
            try:
                previous = json.loads(previous_path.read_text(encoding="utf-8"))
                errors.extend(
                    f"previous receipt: {error}"
                    for error in validate_v1_receipt(previous, repository_root=repository_root)
                )
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                errors.append(f"previous receipt cannot be read: {exc}")
    return errors


def require_valid_adapter_receipt(value: Any, *, repository_root: Path | None = None) -> dict[str, Any]:
    errors = validate_adapter_receipt(value, repository_root=repository_root)
    if errors:
        raise CyberLabAdapterError("; ".join(errors))
    return dict(value)


def _sensor_preflight(events: list[dict[str, Any]]) -> tuple[bool, str]:
    """Return the label-blind sensor decision before command validation."""

    missing = any(not _clean(event.get("sensor")) for event in events)
    sensors = {_clean(event.get("sensor")) for event in events if _clean(event.get("sensor"))}
    if missing and len(sensors) > 1:
        return False, MIXED_OR_MISSING_SENSOR_REASON
    if missing:
        return False, MISSING_SENSOR_REASON
    if len(sensors) != 1:
        return False, MIXED_SENSOR_REASON
    if next(iter(sensors)) != HIGH_INTERACTION_SENSOR:
        return False, WRONG_SENSOR_REASON
    return True, ELIGIBLE_REASON


def _excluded_private_session(
    raw_session_id: str,
    raw_events: list[dict[str, Any]],
    *,
    source_member: Mapping[str, Any],
    reason: str,
) -> dict[str, Any]:
    """Build an exclusion record without parsing command/timestamp semantics."""

    closed = any(_clean(event.get("eventid")) == _CLOSE_TYPE for event in raw_events)
    filename = _clean(source_member.get("filename"))
    date = _clean(source_member.get("collection_date"))
    return {
        "schema_version": PRIVATE_SESSION_SCHEMA_VERSION,
        "raw_session_id": raw_session_id,
        "source_members": [filename],
        "source_member_dates": [date],
        "protocol": "unknown",
        "status": "closed" if closed else "active",
        "termination_status": "explicit_closed" if closed else "unresolved",
        "high_interaction_eligibility": "mixed_sensor" if reason != WRONG_SENSOR_REASON else "wrong_sensor",
        "events": [],
        "cross_file": False,
        "eligibility_reason": reason,
        "raw_event_count": len(raw_events),
        "excluded_event_count": len(raw_events),
    }


def _merge_exclusions(records: list[Mapping[str, Any]]) -> dict[str, Any]:
    """Merge metadata-only exclusions and retain the strongest fail-closed reason."""

    raw_id = _clean(records[0].get("raw_session_id"))
    members = sorted({
        _clean(member)
        for record in records
        for member in record.get("source_members") or []
    })
    dates = sorted({
        _clean(date)
        for record in records
        for date in record.get("source_member_dates") or []
    })
    reasons = {
        _clean(record.get("eligibility_reason")) for record in records
    }
    if MIXED_OR_MISSING_SENSOR_REASON in reasons:
        reason = MIXED_OR_MISSING_SENSOR_REASON
    elif any(reason in reasons for reason in (MIXED_SENSOR_REASON, MISSING_SENSOR_REASON)):
        reason = MIXED_SENSOR_REASON
    elif len(reasons) > 1 or ELIGIBLE_REASON in reasons:
        reason = MIXED_SENSOR_REASON
    else:
        reason = WRONG_SENSOR_REASON
    closed = any(record.get("status") == "closed" for record in records)
    return {
        "schema_version": PRIVATE_SESSION_SCHEMA_VERSION,
        "raw_session_id": raw_id,
        "source_members": members,
        "source_member_dates": dates,
        "protocol": "unknown",
        "status": "closed" if closed else "active",
        "termination_status": "explicit_closed" if closed else "unresolved",
        "high_interaction_eligibility": "mixed_sensor" if reason != WRONG_SENSOR_REASON else "wrong_sensor",
        "events": [],
        "cross_file": len(members) > 1,
        "eligibility_reason": reason,
        "raw_event_count": sum(int(record.get("raw_event_count", 0)) for record in records),
        "excluded_event_count": sum(int(record.get("excluded_event_count", 0)) for record in records),
    }


def merge_cyberlab_private_sessions(sessions: Any) -> list[dict[str, Any]]:
    """Merge v2 records without allowing an excluded member to be bypassed."""

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
        if any("eligibility_reason" in record for record in records):
            output.append(_merge_exclusions(records))
        else:
            output.extend(_v1_merge(records))
    return output


def high_interaction_decision(private_session: Mapping[str, Any]) -> dict[str, Any]:
    reason = _clean(private_session.get("eligibility_reason"))
    if reason == ELIGIBLE_REASON:
        return {"eligible": True, "reason": reason}
    if reason:
        return {"eligible": False, "reason": reason}
    # Eligible v1-compatible records have no v2 metadata field.  This fallback
    # remains sensor-only and preserves the old decision API.
    return _v1_high_interaction_decision(private_session)


class CyberLabAdapter:
    """Metadata-first adapter; eligible normalization is exactly the v1 path."""

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
        # The v1 private/multi-member receipt remains the compatibility base.
        checked = require_adapter_provenance(provenance)
        if checked["adapter_schema_version"] != V1_ADAPTER_SCHEMA_VERSION:
            raise CyberLabAdapterError("v2 adapter requires the v1 private provenance base")
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
        source_path = Path(path)
        try:
            handle = __import__("gzip").open(source_path, "rt", encoding="utf-8", errors="strict")
        except OSError as exc:
            raise CyberLabAdapterError("cannot open CyberLab gzip member") from exc
        with handle:
            for item in _iter_json_array(handle):
                raw_id, raw_events = _session_item(item)
                eligible, reason = _sensor_preflight(raw_events)
                if not eligible:
                    yield _excluded_private_session(
                        raw_id, raw_events, source_member=self.source_member, reason=reason
                    )
                    continue
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
        from production.reproduction.cyberlab_adapter import _safe_session

        for private in self.iter_private_sessions(path):
            if not high_interaction_decision(private)["eligible"]:
                continue
            safe = _safe_session(
                private,
                provenance=self.provenance,
                source_member=self.source_member,
                key=self.key,
                key_id=self.key_id,
            )
            from production.reproduction.cyberlab_adapter import require_valid_cyberlab_session

            require_valid_cyberlab_session(safe)
            yield safe

    def build_private_classifier_events(self, private_session: Mapping[str, Any]) -> list[dict[str, Any]]:
        if _clean(private_session.get("schema_version")) != PRIVATE_SESSION_SCHEMA_VERSION:
            raise CyberLabAdapterError("private session schema_version is invalid")
        if not high_interaction_decision(private_session)["eligible"]:
            raise CyberLabAdapterError("ineligible session cannot enter classifier stream")
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


def iter_cyberlab_private_sessions(path: Path | str, *, source_member: Mapping[str, Any], provenance: Mapping[str, Any], pseudonymization_key: bytes, pseudonymization_key_id: str) -> Iterator[dict[str, Any]]:
    return CyberLabAdapter(source_member=source_member, provenance=provenance, pseudonymization_key=pseudonymization_key, pseudonymization_key_id=pseudonymization_key_id).iter_private_sessions(path)


def iter_cyberlab_sessions(path: Path | str, *, source_member: Mapping[str, Any], provenance: Mapping[str, Any], pseudonymization_key: bytes, pseudonymization_key_id: str) -> Iterator[dict[str, Any]]:
    return CyberLabAdapter(source_member=source_member, provenance=provenance, pseudonymization_key=pseudonymization_key, pseudonymization_key_id=pseudonymization_key_id).iter_sessions(path)


__all__ = [
    "ADAPTER_RECEIPT_SCHEMA_VERSION",
    "ADAPTER_SCHEMA_VERSION",
    "CyberLabAdapter",
    "CyberLabAdapterError",
    "ELIGIBLE_REASON",
    "HIGH_INTERACTION_SENSOR",
    "MIXED_SENSOR_REASON",
    "MISSING_SENSOR_REASON",
    "WRONG_SENSOR_REASON",
    "high_interaction_decision",
    "iter_cyberlab_private_sessions",
    "iter_cyberlab_sessions",
    "merge_cyberlab_private_sessions",
    "require_valid_adapter_policy",
    "require_valid_adapter_receipt",
    "validate_adapter_policy",
    "validate_adapter_receipt",
]
