"""Causal target contract for the successor trusted-group prediction study.

This contract is deliberately separate from ``next_behavior_contract``.  The
failed next-distinct-phase v2 experiment remains immutable historical evidence.
The successor target forecasts after every trusted command-behavior group:

* whether another trusted group will be durably observed; and
* conditional on continuation, the exact trusted ATT&CK tactic set of that
  immediately following group.

The deterministic analysis remains authoritative.  This module only constructs
privacy-safe, non-authoritative offline/shadow prediction examples.
"""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence

from production.prediction.next_behavior_contract import (
    AGREEMENT_STATUSES,
    COMMAND_COUNT_BUCKETS,
    CONFIDENCE_BUCKETS,
    LOGIN_OUTCOMES,
    SESSION_AGE_BUCKETS,
    TACTIC_VOCABULARY,
    TRUSTED_LABEL_SOURCES,
    TRUSTED_TIER,
    NextBehaviorContractError,
    require_valid_next_behavior_session,
)
from production.prediction.next_behavior_preprocessing import elapsed_time_bucket
from production.utils.serialization import stable_id, stable_json


TARGET_POLICY_SCHEMA_VERSION = "next_trusted_group_target_policy.v1"
MODEL_INPUT_SCHEMA_VERSION = "next_trusted_group_input.v1"
EXAMPLE_SCHEMA_VERSION = "next_trusted_group_example.v1"
TARGET_CONTRACT_ID = "next_trusted_command_behavior_group_or_session_end.v1"
TERMINAL_OUTCOME = "session_end_no_further_trusted_command_behavior_group"
CONTINUATION_OUTCOME = "another_trusted_command_behavior_group"
MAXIMUM_TRUSTED_GROUPS = 8

DEVELOPMENT_ROLES = ("train", "selection", "calibration")
BINARY_CLASSES = ("continuation", "session_end")

_INPUT_FIELDS = frozenset(
    {
        "schema_version",
        "target_contract_id",
        "maximum_trusted_groups",
        "truncated",
        "original_trusted_group_count",
        "selected_trusted_group_count",
        "omitted_prefix_trusted_group_count",
        "selected_group_ids",
        "group_sequence",
        "session_context",
        "input_evidence_refs",
        "input_hash",
    }
)
_MODEL_GROUP_FIELDS = frozenset(
    {
        "tactics",
        "techniques",
        "labels",
        "elapsed_since_previous_trusted_group_bucket",
        "label_provenance_sources",
        "label_confidence_buckets",
        "label_agreement_statuses",
        "audit_only_label_count",
    }
)
_LABEL_FIELDS = frozenset({"tactic", "technique"})
_CONTEXT_FIELDS = frozenset(
    {
        "login_outcome",
        "command_count_bucket",
        "session_age_bucket",
        "confirmed_transfer_observed",
    }
)
_TARGET_FIELDS = frozenset(
    {
        "outcome_type",
        "will_continue",
        "tactics",
        "techniques",
        "labels",
        "terminal_outcome",
        "target_group_id",
        "target_event_order",
        "target_evidence_refs",
    }
)
_EXAMPLE_FIELDS = frozenset(
    {
        "schema_version",
        "target_contract_id",
        "session_id",
        "source_member_id",
        "prediction_group_id",
        "prediction_event_order",
        "model_input",
        "target",
        "example_id",
    }
)


class NextTrustedGroupTargetError(ValueError):
    """Raised when the successor target contract fails closed."""


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _unique_sorted(values: Iterable[Any]) -> List[str]:
    return sorted({_clean(value) for value in values if _clean(value)})


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


_TECHNIQUE_ID = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")
_SAFE_ID = re.compile(
    r"^nb(?:member|session|group|evidence)_[0-9a-f]{64}$"
)


def _unexpected_fields(
    value: Mapping[str, Any], allowed: frozenset[str], path: str
) -> List[str]:
    return [
        f"{path}.{key} is not defined by the contract"
        for key in sorted(value)
        if key not in allowed
    ]


def _labels_from_group(group: Mapping[str, Any]) -> List[Dict[str, str]]:
    labels = {
        (_clean(item.get("tactic")), _clean(item.get("technique")).upper())
        for item in group.get("label_provenance") or []
        if isinstance(item, Mapping)
    }
    if not labels or any(not tactic or not technique for tactic, technique in labels):
        raise NextTrustedGroupTargetError(
            "trusted group does not contain complete tactic-technique labels"
        )
    return [
        {"tactic": tactic, "technique": technique}
        for tactic, technique in sorted(labels)
    ]


def _group_features(
    group: Mapping[str, Any], previous_group: Mapping[str, Any] | None
) -> Dict[str, Any]:
    labels = _labels_from_group(group)
    elapsed: float | None = None
    if previous_group is not None:
        current_time = group.get("relative_time_ms")
        previous_time = previous_group.get("relative_time_ms")
        if current_time is not None and previous_time is not None:
            elapsed = max(float(current_time) - float(previous_time), 0.0)
    provenance = [
        item
        for item in group.get("label_provenance") or []
        if isinstance(item, Mapping)
    ]
    return {
        "tactics": sorted({item["tactic"] for item in labels}),
        "techniques": sorted({item["technique"] for item in labels}),
        "labels": labels,
        "elapsed_since_previous_trusted_group_bucket": elapsed_time_bucket(elapsed),
        "label_provenance_sources": _unique_sorted(
            item.get("source") for item in provenance
        ),
        "label_confidence_buckets": _unique_sorted(
            item.get("confidence_bucket") for item in provenance
        ),
        "label_agreement_statuses": _unique_sorted(
            item.get("agreement_status") for item in provenance
        ),
        "audit_only_label_count": len(group.get("audit_only_labels") or []),
    }


def build_trusted_group_model_input(
    trusted_groups: Sequence[Mapping[str, Any]],
    *,
    maximum_trusted_groups: int = MAXIMUM_TRUSTED_GROUPS,
) -> Dict[str, Any]:
    """Build the causal model-visible history ending at the prediction group."""

    if maximum_trusted_groups != MAXIMUM_TRUSTED_GROUPS:
        raise NextTrustedGroupTargetError(
            f"v1 requires maximum_trusted_groups={MAXIMUM_TRUSTED_GROUPS}"
        )
    if not trusted_groups:
        raise NextTrustedGroupTargetError("trusted group history must not be empty")
    selected = list(trusted_groups)[-maximum_trusted_groups:]
    omitted = len(trusted_groups) - len(selected)
    selected_start = len(trusted_groups) - len(selected)
    features = []
    for absolute_index, group in enumerate(selected, start=selected_start):
        previous = (
            trusted_groups[absolute_index - 1] if absolute_index > 0 else None
        )
        features.append(_group_features(group, previous))
    value = {
        "schema_version": MODEL_INPUT_SCHEMA_VERSION,
        "target_contract_id": TARGET_CONTRACT_ID,
        "maximum_trusted_groups": maximum_trusted_groups,
        "truncated": omitted > 0,
        "original_trusted_group_count": len(trusted_groups),
        "selected_trusted_group_count": len(selected),
        "omitted_prefix_trusted_group_count": omitted,
        "selected_group_ids": [_clean(group.get("group_id")) for group in selected],
        "group_sequence": features,
        "session_context": deepcopy(selected[-1].get("session_context") or {}),
        "input_evidence_refs": _unique_sorted(
            ref for group in selected for ref in group.get("evidence_refs") or []
        ),
    }
    value["input_hash"] = _sha256_json(value)
    errors = validate_trusted_group_model_input(value)
    if errors:
        raise NextTrustedGroupTargetError("; ".join(errors))
    return value


def _target_from_group(group: Mapping[str, Any]) -> Dict[str, Any]:
    labels = _labels_from_group(group)
    return {
        "outcome_type": "continuation",
        "will_continue": True,
        "tactics": sorted({item["tactic"] for item in labels}),
        "techniques": sorted({item["technique"] for item in labels}),
        "labels": labels,
        "terminal_outcome": "",
        "target_group_id": _clean(group.get("group_id")),
        "target_event_order": int(group["event_order"]),
        "target_evidence_refs": _unique_sorted(group.get("evidence_refs") or []),
    }


def _terminal_target() -> Dict[str, Any]:
    return {
        "outcome_type": "session_end",
        "will_continue": False,
        "tactics": [],
        "techniques": [],
        "labels": [],
        "terminal_outcome": TERMINAL_OUTCOME,
        "target_group_id": "",
        "target_event_order": None,
        "target_evidence_refs": [],
    }


def build_next_trusted_group_examples(
    session_record: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    """Emit one resolved target after each trusted group in causal order.

    Every non-final group targets the immediately following trusted group,
    including an identical tactic set.  The final group is terminal truth only
    for a durably closed session.  An active final group is unresolved and is
    omitted, while earlier observed continuations remain eligible.
    """

    try:
        record = require_valid_next_behavior_session(session_record)
    except NextBehaviorContractError as exc:
        raise NextTrustedGroupTargetError(str(exc)) from exc
    groups = record["observation_groups"]
    closed = _clean(record.get("status")) == "closed"
    examples: List[Dict[str, Any]] = []
    for index, current in enumerate(groups):
        has_next = index + 1 < len(groups)
        if not has_next and not closed:
            continue
        target = _target_from_group(groups[index + 1]) if has_next else _terminal_target()
        model_input = build_trusted_group_model_input(groups[: index + 1])
        example = {
            "schema_version": EXAMPLE_SCHEMA_VERSION,
            "target_contract_id": TARGET_CONTRACT_ID,
            "session_id": _clean(record.get("session_id")),
            "source_member_id": _clean(record.get("source_member_id")),
            "prediction_group_id": _clean(current.get("group_id")),
            "prediction_event_order": int(current["event_order"]),
            "model_input": model_input,
            "target": target,
        }
        example["example_id"] = stable_id(
            "nexttrustedgroupexample",
            {
                "target_contract_id": TARGET_CONTRACT_ID,
                "session_id": example["session_id"],
                "prediction_group_id": example["prediction_group_id"],
                "target": target,
            },
        )
        errors = validate_next_trusted_group_example(example)
        if errors:
            raise NextTrustedGroupTargetError("; ".join(errors))
        examples.append(example)
    return examples


def _validate_labels(value: Any, path: str) -> List[str]:
    if not isinstance(value, list):
        return [f"{path} must be an array"]
    errors: List[str] = []
    normalized = []
    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{item_path} must be an object")
            continue
        errors.extend(_unexpected_fields(item, _LABEL_FIELDS, item_path))
        tactic = _clean(item.get("tactic"))
        technique = _clean(item.get("technique")).upper()
        if tactic not in TACTIC_VOCABULARY:
            errors.append(f"{item_path}.tactic is invalid")
        if not _TECHNIQUE_ID.fullmatch(technique):
            errors.append(f"{item_path}.technique is invalid")
        normalized.append({"tactic": tactic, "technique": technique})
    if value != sorted(normalized, key=lambda item: (item["tactic"], item["technique"])):
        errors.append(f"{path} must be unique and canonically ordered")
    if len({(item["tactic"], item["technique"]) for item in normalized}) != len(normalized):
        errors.append(f"{path} contains duplicate tactic-technique pairs")
    return errors


def _validate_context(value: Any, path: str) -> List[str]:
    if not isinstance(value, dict):
        return [f"{path} must be an object"]
    errors = _unexpected_fields(value, _CONTEXT_FIELDS, path)
    if value.get("login_outcome") not in LOGIN_OUTCOMES:
        errors.append(f"{path}.login_outcome is invalid")
    if value.get("command_count_bucket") not in COMMAND_COUNT_BUCKETS:
        errors.append(f"{path}.command_count_bucket is invalid")
    if value.get("session_age_bucket") not in SESSION_AGE_BUCKETS:
        errors.append(f"{path}.session_age_bucket is invalid")
    if type(value.get("confirmed_transfer_observed")) is not bool:
        errors.append(f"{path}.confirmed_transfer_observed must be boolean")
    return errors


def validate_trusted_group_model_input(value: Any) -> List[str]:
    if not isinstance(value, dict):
        return ["model_input must be an object"]
    errors = _unexpected_fields(value, _INPUT_FIELDS, "model_input")
    if value.get("schema_version") != MODEL_INPUT_SCHEMA_VERSION:
        errors.append("model_input.schema_version is invalid")
    if value.get("target_contract_id") != TARGET_CONTRACT_ID:
        errors.append("model_input.target_contract_id is invalid")
    if value.get("maximum_trusted_groups") != MAXIMUM_TRUSTED_GROUPS:
        errors.append("model_input.maximum_trusted_groups is invalid")
    original = value.get("original_trusted_group_count")
    selected = value.get("selected_trusted_group_count")
    omitted = value.get("omitted_prefix_trusted_group_count")
    if not all(isinstance(item, int) and not isinstance(item, bool) for item in (original, selected, omitted)):
        errors.append("model_input group counts must be integers")
    elif original < 1 or selected < 1 or selected > MAXIMUM_TRUSTED_GROUPS or original != selected + omitted:
        errors.append("model_input group counts do not reconcile")
    elif value.get("truncated") is not (omitted > 0):
        errors.append("model_input.truncated is inconsistent")
    group_ids = value.get("selected_group_ids")
    groups = value.get("group_sequence")
    if not isinstance(group_ids, list) or not all(_clean(item) for item in group_ids):
        errors.append("model_input.selected_group_ids is invalid")
    elif (
        any(not _SAFE_ID.fullmatch(_clean(item)) for item in group_ids)
        or len(group_ids) != len(set(group_ids))
    ):
        errors.append("model_input.selected_group_ids are not unique safe IDs")
    if not isinstance(groups, list) or not groups:
        errors.append("model_input.group_sequence must be non-empty")
    else:
        for index, group in enumerate(groups):
            path = f"model_input.group_sequence[{index}]"
            if not isinstance(group, dict):
                errors.append(f"{path} must be an object")
                continue
            errors.extend(_unexpected_fields(group, _MODEL_GROUP_FIELDS, path))
            errors.extend(_validate_labels(group.get("labels"), f"{path}.labels"))
            labels = group.get("labels") if isinstance(group.get("labels"), list) else []
            expected_tactics = sorted({item.get("tactic") for item in labels if isinstance(item, dict)})
            expected_techniques = sorted({item.get("technique") for item in labels if isinstance(item, dict)})
            if group.get("tactics") != expected_tactics:
                errors.append(f"{path}.tactics do not match labels")
            if group.get("techniques") != expected_techniques:
                errors.append(f"{path}.techniques do not match labels")
            if group.get("elapsed_since_previous_trusted_group_bucket") not in {
                "unknown", "under_1s", "1_to_10s", "10_to_60s", "over_60s"
            }:
                errors.append(f"{path}.elapsed bucket is invalid")
            for field, allowed in (
                ("label_provenance_sources", TRUSTED_LABEL_SOURCES),
                ("label_confidence_buckets", CONFIDENCE_BUCKETS),
                ("label_agreement_statuses", AGREEMENT_STATUSES),
            ):
                field_value = group.get(field)
                if not isinstance(field_value, list) or not field_value or any(item not in allowed for item in field_value):
                    errors.append(f"{path}.{field} is invalid")
            audit_count = group.get("audit_only_label_count")
            if not isinstance(audit_count, int) or isinstance(audit_count, bool) or audit_count < 0:
                errors.append(f"{path}.audit_only_label_count is invalid")
    if isinstance(group_ids, list) and isinstance(groups, list) and len(group_ids) != len(groups):
        errors.append("model_input group IDs and features have different lengths")
    refs = value.get("input_evidence_refs")
    if (
        not isinstance(refs, list)
        or not refs
        or refs != sorted(set(refs))
        or any(not _SAFE_ID.fullmatch(_clean(ref)) for ref in refs)
    ):
        errors.append("model_input.input_evidence_refs is invalid")
    errors.extend(_validate_context(value.get("session_context"), "model_input.session_context"))
    basis = deepcopy(value)
    actual_hash = _clean(basis.pop("input_hash", ""))
    if actual_hash != _sha256_json(basis):
        errors.append("model_input.input_hash is invalid")
    return errors


def validate_next_trusted_group_example(value: Any) -> List[str]:
    if not isinstance(value, dict):
        return ["example must be an object"]
    errors = _unexpected_fields(value, _EXAMPLE_FIELDS, "example")
    if value.get("schema_version") != EXAMPLE_SCHEMA_VERSION:
        errors.append("example.schema_version is invalid")
    if value.get("target_contract_id") != TARGET_CONTRACT_ID:
        errors.append("example.target_contract_id is invalid")
    if not _SAFE_ID.fullmatch(_clean(value.get("session_id"))):
        errors.append("example.session_id is not a safe session ID")
    if not _SAFE_ID.fullmatch(_clean(value.get("source_member_id"))):
        errors.append("example.source_member_id is not a safe member ID")
    if not _SAFE_ID.fullmatch(_clean(value.get("prediction_group_id"))):
        errors.append("example.prediction_group_id is not a safe group ID")
    if not isinstance(value.get("prediction_event_order"), int):
        errors.append("example.prediction_event_order is invalid")
    errors.extend(validate_trusted_group_model_input(value.get("model_input")))
    model_input = value.get("model_input") if isinstance(value.get("model_input"), dict) else {}
    selected_ids = model_input.get("selected_group_ids") or []
    if not selected_ids or value.get("prediction_group_id") != selected_ids[-1]:
        errors.append("example prediction group does not end the causal input")
    target = value.get("target")
    if not isinstance(target, dict):
        errors.append("example.target must be an object")
        target = {}
    else:
        errors.extend(_unexpected_fields(target, _TARGET_FIELDS, "example.target"))
    outcome = target.get("outcome_type")
    errors.extend(_validate_labels(target.get("labels"), "example.target.labels"))
    labels = target.get("labels") if isinstance(target.get("labels"), list) else []
    expected_tactics = sorted({item.get("tactic") for item in labels if isinstance(item, dict)})
    expected_techniques = sorted({item.get("technique") for item in labels if isinstance(item, dict)})
    if target.get("tactics") != expected_tactics or target.get("techniques") != expected_techniques:
        errors.append("example target tactic-technique aggregates are inconsistent")
    if outcome == "continuation":
        if target.get("will_continue") is not True or not labels:
            errors.append("continuation target must contain trusted labels")
        if target.get("terminal_outcome") != "":
            errors.append("continuation target cannot contain a terminal outcome")
        if not _SAFE_ID.fullmatch(_clean(target.get("target_group_id"))) or not isinstance(target.get("target_event_order"), int):
            errors.append("continuation target group identity/order is invalid")
        elif isinstance(value.get("prediction_event_order"), int) and target["target_event_order"] <= value["prediction_event_order"]:
            errors.append("continuation target does not follow the prediction group")
        refs = target.get("target_evidence_refs")
        if (
            not isinstance(refs, list)
            or not refs
            or refs != sorted(set(refs))
            or any(not _SAFE_ID.fullmatch(_clean(ref)) for ref in refs)
        ):
            errors.append("continuation target evidence refs are invalid")
        if set(refs or []) & set(model_input.get("input_evidence_refs") or []):
            errors.append("future target evidence leaked into the model input")
    elif outcome == "session_end":
        if (
            target.get("will_continue") is not False
            or labels
            or target.get("tactics") != []
            or target.get("techniques") != []
            or target.get("terminal_outcome") != TERMINAL_OUTCOME
            or target.get("target_group_id") != ""
            or target.get("target_event_order") is not None
            or target.get("target_evidence_refs") != []
        ):
            errors.append("session-end target is inconsistent")
    else:
        errors.append("example.target.outcome_type is invalid")
    expected_id = stable_id(
        "nexttrustedgroupexample",
        {
            "target_contract_id": TARGET_CONTRACT_ID,
            "session_id": value.get("session_id"),
            "prediction_group_id": value.get("prediction_group_id"),
            "target": target,
        },
    )
    if value.get("example_id") != expected_id:
        errors.append("example.example_id is invalid")
    return errors


def require_valid_next_trusted_group_example(value: Any) -> Dict[str, Any]:
    errors = validate_next_trusted_group_example(value)
    if errors:
        raise NextTrustedGroupTargetError("; ".join(errors))
    return deepcopy(value)


def load_next_trusted_group_target_policy(path: Path) -> Dict[str, Any]:
    """Load and fail-close the frozen successor target design policy."""

    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NextTrustedGroupTargetError(f"target policy is unreadable: {exc}") from exc
    if not isinstance(value, dict):
        raise NextTrustedGroupTargetError("target policy must be an object")
    expected_top = {
        "schema_version", "policy_id", "target_contract_id", "lineage",
        "prediction_point", "input_history", "target",
        "causal_and_privacy_boundaries", "partitions", "support_policy",
        "evaluation", "baselines", "training_authorization",
    }
    if set(value) != expected_top:
        raise NextTrustedGroupTargetError("target policy top-level fields are invalid")
    if value.get("schema_version") != TARGET_POLICY_SCHEMA_VERSION:
        raise NextTrustedGroupTargetError("target policy schema is invalid")
    if value.get("target_contract_id") != TARGET_CONTRACT_ID:
        raise NextTrustedGroupTargetError("target policy contract ID is invalid")
    history = value.get("input_history") or {}
    target = value.get("target") or {}
    partitions = value.get("partitions") or {}
    support = value.get("support_policy") or {}
    authorization = value.get("training_authorization") or {}
    required = (
        history.get("maximum_trusted_groups") == MAXIMUM_TRUSTED_GROUPS,
        history.get("same_tactic_groups_collapsed") is False,
        history.get("raw_commands_allowed") is False,
        history.get("private_identifiers_allowed") is False,
        target.get("same_tactic_continuation_is_positive") is True,
        target.get("audit_only_or_model_only_target_allowed") is False,
        partitions.get("development_roles") == list(DEVELOPMENT_ROLES),
        partitions.get("test_behavioral_content_access_during_support_analysis") is False,
        partitions.get("test_metrics_used_during_support_analysis") is False,
        support.get("minimum_targets_per_role_and_reportable_class") == 30,
        support.get("minimum_distinct_sessions_per_role_and_reportable_class") == 30,
        support.get("required_binary_classes") == list(BINARY_CLASSES),
        support.get("minimum_reportable_conditional_tactic_classes") == 2,
        support.get("threshold_changes_after_support_observation_allowed") is False,
        authorization.get("support_analysis_only") is True,
        authorization.get("transformer_training_authorized") is False,
        authorization.get("production_change_authorized") is False,
    )
    if not all(required):
        raise NextTrustedGroupTargetError("target policy safety bindings are invalid")
    return deepcopy(value)


def target_policy_file_sha256(path: Path) -> str:
    """Return the byte identity of a policy only after contract validation."""

    load_next_trusted_group_target_policy(path)
    return hashlib.sha256(path.read_bytes()).hexdigest()
