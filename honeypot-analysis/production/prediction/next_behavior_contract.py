"""Versioned data contract for the final next-behavior experiment.

This module is deliberately independent from the active v2 prediction engine.
It defines a privacy-safe, causally ordered representation that can be shared
by future offline training and shadow inference without changing production
authority.
"""

from __future__ import annotations

import re
from copy import deepcopy
from math import isfinite
from typing import Any, Dict, Iterable, List, Mapping

from production.prediction.trusted_history import (
    validate_prediction_trusted_history_manifest,
)

SESSION_SCHEMA_VERSION = "next_behavior_session.v2"
PHASE_SCHEMA_VERSION = "next_behavior_phase.v2"
EXAMPLE_SCHEMA_VERSION = "next_behavior_example.v2"
MODEL_INPUT_SCHEMA_VERSION = "next_behavior_input.v2"
TARGET_CONTRACT_ID = "next_distinct_trusted_behavior_phase_or_session_end.v2"
LEGACY_SESSION_SCHEMA_VERSION = "next_behavior_session.v1"
LEGACY_PHASE_SCHEMA_VERSION = "next_behavior_phase.v1"
LEGACY_EXAMPLE_SCHEMA_VERSION = "next_behavior_example.v1"
LEGACY_MODEL_INPUT_SCHEMA_VERSION = "next_behavior_input.v1"
LEGACY_TARGET_CONTRACT_ID = "next_distinct_command_behavior_phase_or_session_end.v1"
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
CONFIDENCE_BUCKETS = frozenset({"high", "medium", "low", "not_applicable"})
AGREEMENT_STATUSES = frozenset(
    {"rule_only", "model_only", "agreed", "disagreed", "unreviewed", "emergency"}
)
AUDIT_REASON_CODES = frozenset(
    {
        "below_trusted_threshold",
        "unresolved_conflict",
        "emergency_rule",
        "unreviewed_rule",
        "opaque_model_probe",
        "malformed_label",
        "missing_provenance",
        "model_only_not_observed_evidence",
        "manifest_aggregate_audit_only",
    }
)
TACTIC_VOCABULARY = frozenset(
    {
        "reconnaissance",
        "resource-development",
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "discovery",
        "lateral-movement",
        "collection",
        "command-and-control",
        "exfiltration",
        "impact",
    }
)
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
        "pseudonymization_key_id",
        "audit_summary",
        "observation_groups",
        "prediction_trusted_history_manifest",
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
        "trust_policy_sha256",
        "checkpoint_sha256",
        "confidence",
        "confidence_bucket",
        "agreement_status",
        "evidence_ref",
    }
)
_AUDIT_PROVENANCE_FIELDS = _PROVENANCE_FIELDS | frozenset({"exclusion_reason"})
_AUDIT_SUMMARY_FIELDS = frozenset({"total", "by_reason"})

LEGACY_LABEL_SOURCE_MAP = {
    "rule": "reviewed_rule",
    "both": "rule_model_agreement",
    "model": "securebert",
}
_TECHNIQUE_ID = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")
_PSEUDONYMOUS_ID = re.compile(
    r"^nb(?P<kind>member|session|group|evidence|configuration|template_family)_"
    r"[0-9a-f]{64}$"
)


class NextBehaviorContractError(ValueError):
    """Raised when a current next-behavior record violates its contract."""


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _unique_sorted(values: Iterable[Any]) -> List[str]:
    return sorted({_clean(value) for value in values if _clean(value)})


def _is_sha256(value: Any) -> bool:
    text = _clean(value).lower()
    return len(text) == 64 and all(character in "0123456789abcdef" for character in text)


def _is_pseudonymous_id(value: Any, kind: str) -> bool:
    match = _PSEUDONYMOUS_ID.fullmatch(_clean(value))
    return bool(match and match.group("kind") == kind)


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
    if not _is_sha256(value.get("trust_policy_sha256")):
        errors.append(f"{path}.trust_policy_sha256 must be a SHA-256 digest")
    if source in {"securebert", "rule_model_agreement"} and not _is_sha256(
        value.get("checkpoint_sha256")
    ):
        errors.append(f"{path}.checkpoint_sha256 is required for model-derived labels")
    bucket = _clean(value.get("confidence_bucket"))
    if bucket not in CONFIDENCE_BUCKETS:
        errors.append(f"{path}.confidence_bucket is invalid")
    if not audit_only and bucket == "low":
        errors.append(f"{path}.low confidence cannot be trusted target evidence")
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
    elif _clean(value.get("tactic")).lower() not in TACTIC_VOCABULARY:
        errors.append(f"{path}.tactic is outside the frozen vocabulary")
    if not _TECHNIQUE_ID.fullmatch(_clean(value.get("technique")).upper()):
        errors.append(f"{path}.technique is not an ATT&CK technique identifier")
    if _clean(value.get("agreement_status")) not in AGREEMENT_STATUSES:
        errors.append(f"{path}.agreement_status is invalid")
    if not _is_pseudonymous_id(value.get("evidence_ref"), "evidence"):
        errors.append(f"{path}.evidence_ref must be a pseudonymous evidence ID")
    if audit_only and _clean(value.get("exclusion_reason")) not in AUDIT_REASON_CODES:
        errors.append(f"{path}.exclusion_reason is not a registered reason code")
    return errors


def normalize_label_source(source: Any) -> str:
    """Map reviewed historical source names to the frozen v1 vocabulary.

    Builders must call this explicitly while creating a new record. Validators
    intentionally reject legacy aliases so stored records cannot be ambiguous.
    """

    text = _clean(source).lower()
    return LEGACY_LABEL_SOURCE_MAP.get(text, text)


def _validate_audit_summary(value: Any, path: str) -> List[str]:
    if not isinstance(value, dict):
        return [f"{path} must be an object"]
    errors = _unexpected_fields(value, _AUDIT_SUMMARY_FIELDS, path)
    total = value.get("total")
    if isinstance(total, bool) or not isinstance(total, int) or total < 0:
        errors.append(f"{path}.total must be a non-negative integer")
    by_reason = value.get("by_reason")
    if not isinstance(by_reason, dict):
        errors.append(f"{path}.by_reason must be an object")
        return errors
    calculated = 0
    for reason, count in by_reason.items():
        if reason not in AUDIT_REASON_CODES:
            errors.append(f"{path}.by_reason.{reason} is not a registered reason")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            errors.append(
                f"{path}.by_reason.{reason} must be a non-negative integer"
            )
        else:
            calculated += count
    if isinstance(total, int) and not isinstance(total, bool) and calculated != total:
        errors.append(f"{path}.total does not equal by_reason counts")
    return errors


def validate_next_behavior_session(value: Any) -> List[str]:
    """Return stable validation errors for a privacy-safe session record."""

    if not isinstance(value, dict):
        return ["session record must be an object"]
    errors = _unexpected_fields(value, _SESSION_FIELDS, "$")
    errors.extend(_forbidden_paths(value))
    if value.get("schema_version") not in {
        SESSION_SCHEMA_VERSION,
        LEGACY_SESSION_SCHEMA_VERSION,
    }:
        errors.append(
            f"schema_version must be {SESSION_SCHEMA_VERSION} or "
            f"{LEGACY_SESSION_SCHEMA_VERSION}"
        )
    if not _is_pseudonymous_id(value.get("session_id"), "session"):
        errors.append("session_id must be a pseudonymous session ID")
    if _clean(value.get("status")) not in {"active", "closed"}:
        errors.append("status must be active or closed")
    if _clean(value.get("protocol")) != "ssh":
        errors.append("protocol must be ssh")
    if not _is_pseudonymous_id(value.get("source_member_id"), "member"):
        errors.append("source_member_id must be a pseudonymous member ID")
    if not _is_sha256(value.get("source_member_sha256")):
        errors.append("source_member_sha256 must be a SHA-256 digest")
    for optional_id, kind in (
        ("configuration_id", "configuration"),
        ("template_family_id", "template_family"),
    ):
        if optional_id in value and not _is_pseudonymous_id(
            value.get(optional_id), kind
        ):
            errors.append(f"{optional_id} must be a pseudonymous {kind} ID")
    if "pseudonymization_key_id" in value and not _clean(
        value.get("pseudonymization_key_id")
    ):
        errors.append("pseudonymization_key_id must be non-empty when present")
    if "audit_summary" in value:
        errors.extend(_validate_audit_summary(value["audit_summary"], "audit_summary"))
    if "prediction_trusted_history_manifest" in value:
        history = value.get("prediction_trusted_history_manifest")
        if not isinstance(history, dict):
            errors.append("prediction_trusted_history_manifest must be an object")
        else:
            if history.get("schema_version") not in {
                "prediction_trusted_history_manifest.v1",
                "prediction_trusted_history_manifest.v2",
                "prediction_trusted_history_manifest.v3",
            }:
                errors.append("prediction_trusted_history_manifest schema is invalid")
            phases = history.get("ordered_trusted_phases")
            if not isinstance(phases, list) or len(phases) > 8:
                errors.append("prediction trusted history must contain at most 8 phases")
            if history.get("schema_version") == "prediction_trusted_history_manifest.v3":
                errors.extend(
                    f"prediction trusted history: {error}"
                    for error in validate_prediction_trusted_history_manifest(history)
                )
                if type(history.get("truncated")) is not bool:
                    errors.append("prediction trusted history truncated flag is invalid")
                for key in (
                    "original_distinct_phase_count",
                    "selected_distinct_phase_count",
                    "omitted_prefix_phase_count",
                ):
                    if (
                        isinstance(history.get(key), bool)
                        or not isinstance(history.get(key), int)
                        or history.get(key) < 0
                    ):
                        errors.append(f"prediction trusted history {key} is invalid")
                if (
                    isinstance(history.get("selected_distinct_phase_count"), int)
                    and history.get("selected_distinct_phase_count") != len(phases or [])
                ):
                    errors.append(
                        "prediction trusted history selected count is inconsistent"
                    )
                original = history.get("original_distinct_phase_count")
                selected = history.get("selected_distinct_phase_count")
                omitted = history.get("omitted_prefix_phase_count")
                if (
                    isinstance(original, int)
                    and isinstance(selected, int)
                    and isinstance(omitted, int)
                    and original != selected + omitted
                ):
                    errors.append(
                        "prediction trusted history truncation counts do not reconcile"
                    )
                if (
                    isinstance(omitted, int)
                    and history.get("truncated") is not (omitted > 0)
                ):
                    errors.append(
                        "prediction trusted history truncated flag is inconsistent"
                    )
                for phase_index, phase in enumerate(phases or []):
                    if not isinstance(phase, dict):
                        errors.append(
                            f"prediction trusted history phase {phase_index} must be an object"
                        )
                        continue
                    labels = phase.get("labels")
                    if not isinstance(labels, list) or not labels:
                        errors.append(
                            f"prediction trusted history phase {phase_index} labels are invalid"
                        )
                        continue
                    seen_labels = set()
                    for label_index, label in enumerate(labels):
                        if not isinstance(label, dict):
                            errors.append(
                                f"prediction trusted history label {phase_index}:{label_index} must be an object"
                            )
                            continue
                        tactic = _clean(label.get("tactic"))
                        technique = _clean(label.get("technique")).upper()
                        if not tactic or not technique:
                            errors.append(
                                f"prediction trusted history label {phase_index}:{label_index} is incomplete"
                            )
                        key = (tactic, technique)
                        if key in seen_labels:
                            errors.append(
                                f"prediction trusted history phase {phase_index} labels are duplicated"
                            )
                        seen_labels.add(key)
                    expected_tactics = sorted({key[0] for key in seen_labels})
                    expected_techniques = sorted({key[1] for key in seen_labels})
                    if phase.get("tactics") != expected_tactics:
                        errors.append(
                            f"prediction trusted history phase {phase_index} tactics do not match labels"
                        )
                    if phase.get("techniques") != expected_techniques:
                        errors.append(
                            f"prediction trusted history phase {phase_index} techniques do not match labels"
                        )
            if not _is_sha256(history.get("history_manifest_sha256")):
                errors.append("prediction trusted history manifest hash is invalid")

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
        if not _is_pseudonymous_id(group_id, "group"):
            errors.append(f"{path}.group_id must be a pseudonymous group ID")
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
        elif any(tactic.lower() not in TACTIC_VOCABULARY for tactic in tactics):
            errors.append(f"{path}.tactics contains an unknown tactic")
        techniques = _strict_string_list(group.get("techniques"))
        if techniques is None:
            errors.append(f"{path}.techniques must be a string array")
        elif any(
            not _TECHNIQUE_ID.fullmatch(technique.upper())
            for technique in techniques
        ):
            errors.append(f"{path}.techniques contains an invalid technique ID")
        refs = _strict_string_list(group.get("evidence_refs"))
        if refs is None or not refs:
            errors.append(f"{path}.evidence_refs must be a non-empty string array")
            refs = []
        elif any(not _is_pseudonymous_id(ref, "evidence") for ref in refs):
            errors.append(
                f"{path}.evidence_refs contains a non-pseudonymous evidence ID"
            )
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
            if isinstance(provenance, list):
                provenance_tactics = {
                    _clean(item.get("tactic"))
                    for item in provenance
                    if isinstance(item, dict)
                }
                provenance_techniques = {
                    _clean(item.get("technique"))
                    for item in provenance
                    if isinstance(item, dict)
                }
                provenance_refs = {
                    _clean(item.get("evidence_ref"))
                    for item in provenance
                    if isinstance(item, dict)
                }
                if set(tactics or []) != provenance_tactics:
                    errors.append(f"{path}.tactics does not match trusted provenance")
                if set(techniques or []) != provenance_techniques:
                    errors.append(
                        f"{path}.techniques does not match trusted provenance"
                    )
                if set(refs) != provenance_refs:
                    errors.append(
                        f"{path}.evidence_refs does not match trusted provenance"
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
    if isinstance(value.get("audit_summary"), dict):
        attached_audit_count = sum(
            len(group.get("audit_only_labels") or [])
            for group in groups
            if isinstance(group, dict)
        )
        summary_total = value["audit_summary"].get("total")
        if (
            isinstance(summary_total, int)
            and not isinstance(summary_total, bool)
            and summary_total < attached_audit_count
        ):
            errors.append(
                "audit_summary.total cannot be less than attached audit-only labels"
            )
    return errors


def require_valid_next_behavior_session(value: Any) -> Dict[str, Any]:
    errors = validate_next_behavior_session(value)
    if errors:
        raise NextBehaviorContractError("; ".join(errors))
    return deepcopy(value)
