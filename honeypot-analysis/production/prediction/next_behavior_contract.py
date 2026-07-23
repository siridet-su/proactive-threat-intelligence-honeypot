"""Versioned data contract for the final next-behavior experiment.

This module is deliberately independent from the active v2 prediction engine.
It defines a privacy-safe, causally ordered representation that can be shared
by future offline training and shadow inference without changing production
authority.
"""

from __future__ import annotations

from copy import deepcopy
from math import isfinite
from typing import Any, Dict, Iterable, List, Mapping

SESSION_SCHEMA_VERSION = "next_behavior_session.v1"
PHASE_SCHEMA_VERSION = "next_behavior_phase.v1"
EXAMPLE_SCHEMA_VERSION = "next_behavior_example.v1"
MODEL_INPUT_SCHEMA_VERSION = "next_behavior_model_input.v1"
TARGET_CONTRACT_ID = "next_distinct_command_behavior_phase_or_session_end.v1"
TERMINAL_OUTCOME = "session_end_no_further_trusted_behavior"

TRUSTED_LABEL_SOURCES = frozenset(
    {
        "reviewed_rule",
        "rule_model_agreement",
        "securebert",
    }
)
TRUSTED_TIER = "trusted_observation"
AUDIT_ONLY_TIERS = frozenset({"audit_only_candidate", "excluded"})
CONFIDENCE_BUCKETS = frozenset({"high", "medium", "not_applicable"})
LOGIN_OUTCOMES = frozenset({"success", "failed", "unknown"})
COMMAND_COUNT_BUCKETS = frozenset({"0", "1", "2-5", "6-20", "21+"})
SESSION_AGE_BUCKETS = frozenset(
    {"under_10s", "10_to_60s", "1_to_5m", "over_5m", "unknown"}
)
REPETITION_BUCKETS = frozenset({"1", "2", "3-5", "6+"})
ELAPSED_TIME_BUCKETS = frozenset(
    {"unknown", "under_1s", "1_to_10s", "10_to_60s", "over_60s"}
)

_FORBIDDEN_SAFE_FIELDS = frozenset(
    {
        "command",
        "commands",
        "raw_command",
        "raw_commands",
        "input",
        "password",
        "passwd",
        "src_ip",
        "source_ip",
        "username",
    }
)

_SESSION_FIELDS = frozenset(
    {
        "schema_version",
        "session_id",
        "source_member_id",
        "source_member_sha256",
        "protocol",
        "status",
        "configuration_id",
        "template_family_id",
        "observation_groups",
    }
)
_GROUP_FIELDS = frozenset(
    {
        "group_id",
        "event_order",
        "relative_time_ms",
        "tactics",
        "techniques",
        "evidence_refs",
        "label_provenance",
        "audit_only_labels",
        "session_context",
    }
)
_CONTEXT_FIELDS = frozenset(
    {
        "login_outcome",
        "command_count_bucket",
        "session_age_bucket",
        "confirmed_transfer_observed",
    }
)
_PROVENANCE_FIELDS = frozenset(
    {
        "tactic",
        "technique",
        "source",
        "trust_tier",
        "policy_sha256",
        "checkpoint_sha256",
        "confidence",
        "confidence_bucket",
        "agreement_status",
        "evidence_ref",
    }
)
_AUDIT_PROVENANCE_FIELDS = _PROVENANCE_FIELDS | frozenset({"exclusion_reason"})

LEGACY_LABEL_SOURCE_MAP = {
    "rule": "reviewed_rule",
    "both": "rule_model_agreement",
    "model": "securebert",
}


class NextBehaviorContractError(ValueError):
    """Raised when a v1 next-behavior record violates the frozen contract."""


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _unique_sorted(values: Iterable[Any]) -> List[str]:
    return sorted({_clean(value) for value in values if _clean(value)})


def _is_sha256(value: Any) -> bool:
    text = _clean(value).lower()
    return len(text) == 64 and all(character in "0123456789abcdef" for character in text)


def _strict_string_list(value: Any) -> List[str] | None:
    if not isinstance(value, list):
        return None
    output: List[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            return None
        text = item.strip()
        if text not in output:
            output.append(text)
    return output


def _unexpected_fields(
    value: Mapping[str, Any],
    allowed: frozenset[str],
    path: str,
) -> List[str]:
    return [
        f"{path}.{key} is not defined by the contract"
        for key in sorted(value)
        if key not in allowed
    ]


def _forbidden_paths(value: Any, path: str = "$") -> List[str]:
    errors: List[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = _clean(key)
            child_path = f"{path}.{key_text}"
            if key_text.lower() in _FORBIDDEN_SAFE_FIELDS:
                errors.append(f"{child_path} is forbidden in the privacy-safe contract")
            errors.extend(_forbidden_paths(item, child_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            errors.extend(_forbidden_paths(item, f"{path}[{index}]"))
    return errors


def _validate_context(value: Any, path: str) -> List[str]:
    if not isinstance(value, dict):
        return [f"{path} must be an object"]
    errors = _unexpected_fields(value, _CONTEXT_FIELDS, path)
    if _clean(value.get("login_outcome")) not in LOGIN_OUTCOMES:
        errors.append(f"{path}.login_outcome is invalid")
    if _clean(value.get("command_count_bucket")) not in COMMAND_COUNT_BUCKETS:
        errors.append(f"{path}.command_count_bucket is invalid")
    if _clean(value.get("session_age_bucket")) not in SESSION_AGE_BUCKETS:
        errors.append(f"{path}.session_age_bucket is invalid")
    if type(value.get("confirmed_transfer_observed")) is not bool:
        errors.append(f"{path}.confirmed_transfer_observed must be boolean")
    return errors


def _validate_provenance(
    value: Any,
    path: str,
    *,
    audit_only: bool = False,
) -> List[str]:
    if not isinstance(value, dict):
        return [f"{path} must be an object"]
    allowed_fields = (
        _AUDIT_PROVENANCE_FIELDS if audit_only else _PROVENANCE_FIELDS
    )
    errors = _unexpected_fields(value, allowed_fields, path)
    source = _clean(value.get("source"))
    trust_tier = _clean(value.get("trust_tier"))
    if audit_only:
        if source not in TRUSTED_LABEL_SOURCES:
            errors.append(f"{path}.source is not an approved classifier source")
        if trust_tier not in AUDIT_ONLY_TIERS:
            errors.append(f"{path}.trust_tier is not an audit-only tier")
        if not _clean(value.get("exclusion_reason")):
            errors.append(f"{path}.exclusion_reason is required")
    else:
        if source not in TRUSTED_LABEL_SOURCES:
            errors.append(f"{path}.source is not approved for trusted targets")
        if trust_tier != TRUSTED_TIER:
            errors.append(f"{path}.trust_tier must be {TRUSTED_TIER}")
    if not _is_sha256(value.get("policy_sha256")):
        errors.append(f"{path}.policy_sha256 must be a SHA-256 digest")
    if source in {"securebert", "rule_model_agreement"} and not _is_sha256(
        value.get("checkpoint_sha256")
    ):
        errors.append(f"{path}.checkpoint_sha256 is required for model-derived labels")
    bucket = _clean(value.get("confidence_bucket"))
    if bucket not in CONFIDENCE_BUCKETS:
        errors.append(f"{path}.confidence_bucket is invalid")
    confidence = value.get("confidence")
    if confidence is None:
        if bucket != "not_applicable":
            errors.append(f"{path}.confidence may be null only when not_applicable")
    else:
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            errors.append(f"{path}.confidence must be numeric or null")
        else:
            number = float(confidence)
            if not isfinite(number) or not 0.0 <= number <= 1.0:
                errors.append(f"{path}.confidence must be in [0, 1]")
    if not _clean(value.get("tactic")):
        errors.append(f"{path}.tactic is required")
    if not _clean(value.get("technique")):
        errors.append(f"{path}.technique is required")
    if not _clean(value.get("agreement_status")):
        errors.append(f"{path}.agreement_status is required")
    if not _clean(value.get("evidence_ref")):
        errors.append(f"{path}.evidence_ref is required")
    return errors


def normalize_label_source(source: Any) -> str:
    """Map reviewed historical source names to the frozen v1 vocabulary.

    Builders must call this explicitly while creating a new record. Validators
    intentionally reject legacy aliases so stored records cannot be ambiguous.
    """

    text = _clean(source).lower()
    return LEGACY_LABEL_SOURCE_MAP.get(text, text)


def validate_next_behavior_session(value: Any) -> List[str]:
    """Return stable validation errors for a privacy-safe session record."""

    if not isinstance(value, dict):
        return ["session record must be an object"]
    errors = _unexpected_fields(value, _SESSION_FIELDS, "$")
    errors.extend(_forbidden_paths(value))
    if value.get("schema_version") != SESSION_SCHEMA_VERSION:
        errors.append(f"schema_version must be {SESSION_SCHEMA_VERSION}")
    if not _clean(value.get("session_id")):
        errors.append("session_id is required")
    if _clean(value.get("status")) not in {"active", "closed"}:
        errors.append("status must be active or closed")
    if _clean(value.get("protocol")) != "ssh":
        errors.append("protocol must be ssh")
    if not _clean(value.get("source_member_id")):
        errors.append("source_member_id is required")
    if not _is_sha256(value.get("source_member_sha256")):
        errors.append("source_member_sha256 must be a SHA-256 digest")

    groups = value.get("observation_groups")
    if not isinstance(groups, list) or not groups:
        errors.append("observation_groups must be a non-empty array")
        return errors

    previous_order = -1
    previous_time: float | None = None
    seen_group_ids: set[str] = set()
    for index, group in enumerate(groups):
        path = f"observation_groups[{index}]"
        if not isinstance(group, dict):
            errors.append(f"{path} must be an object")
            continue
        errors.extend(_unexpected_fields(group, _GROUP_FIELDS, path))
        group_id = _clean(group.get("group_id"))
        if not group_id:
            errors.append(f"{path}.group_id is required")
        elif group_id in seen_group_ids:
            errors.append(f"{path}.group_id is duplicated")
        else:
            seen_group_ids.add(group_id)
        raw_order = group.get("event_order")
        if isinstance(raw_order, bool) or not isinstance(raw_order, int):
            errors.append(f"{path}.event_order must be an integer")
            order = previous_order
        else:
            order = raw_order
        if order < 1 or order <= previous_order:
            errors.append(f"{path}.event_order must be positive and strictly increasing")
        previous_order = order
        relative_time = group.get("relative_time_ms")
        if relative_time is not None:
            if isinstance(relative_time, bool) or not isinstance(
                relative_time, (int, float)
            ):
                errors.append(f"{path}.relative_time_ms must be numeric or null")
            else:
                relative_number = float(relative_time)
                if not isfinite(relative_number) or relative_number < 0:
                    errors.append(f"{path}.relative_time_ms must be non-negative")
                if previous_time is not None and relative_number < previous_time:
                    errors.append(f"{path}.relative_time_ms must be non-decreasing")
                if isfinite(relative_number):
                    previous_time = relative_number
        tactics = _strict_string_list(group.get("tactics"))
        if tactics is None or not tactics:
            errors.append(f"{path}.tactics must be a non-empty string array")
        techniques = _strict_string_list(group.get("techniques"))
        if techniques is None:
            errors.append(f"{path}.techniques must be a string array")
        refs = _strict_string_list(group.get("evidence_refs"))
        if refs is None or not refs:
            errors.append(f"{path}.evidence_refs must be a non-empty string array")
            refs = []
        provenance = group.get("label_provenance")
        if not isinstance(provenance, list) or not provenance:
            errors.append(f"{path}.label_provenance must be a non-empty array")
        else:
            for provenance_index, item in enumerate(provenance):
                errors.extend(
                    _validate_provenance(item, f"{path}.label_provenance[{provenance_index}]")
                )
                if isinstance(item, dict):
                    evidence_ref = _clean(item.get("evidence_ref"))
                    if evidence_ref and evidence_ref not in refs:
                        errors.append(
                            f"{path}.label_provenance[{provenance_index}].evidence_ref "
                            "is absent from evidence_refs"
                        )
                    tactic = _clean(item.get("tactic"))
                    if tactic and tactic not in (tactics or []):
                        errors.append(
                            f"{path}.label_provenance[{provenance_index}].tactic "
                            "is absent from tactics"
                        )
                    technique = _clean(item.get("technique"))
                    if technique and technique not in (techniques or []):
                        errors.append(
                            f"{path}.label_provenance[{provenance_index}].technique "
                            "is absent from techniques"
                        )
        audit_labels = group.get("audit_only_labels", [])
        if not isinstance(audit_labels, list):
            errors.append(f"{path}.audit_only_labels must be an array")
        else:
            for audit_index, item in enumerate(audit_labels):
                errors.extend(
                    _validate_provenance(
                        item,
                        f"{path}.audit_only_labels[{audit_index}]",
                        audit_only=True,
                    )
                )
        errors.extend(_validate_context(group.get("session_context"), f"{path}.session_context"))
    return errors


def require_valid_next_behavior_session(value: Any) -> Dict[str, Any]:
    errors = validate_next_behavior_session(value)
    if errors:
        raise NextBehaviorContractError("; ".join(errors))
    return deepcopy(value)
