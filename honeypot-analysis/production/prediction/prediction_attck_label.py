"""Prediction-only ATT&CK-derived label contracts.

This module is deliberately separate from :mod:`classification.trust` and
from ``prediction_trusted_history_manifest.v3``.  It describes a frozen,
weakly supervised representation that may be used by an offline or shadow
predictor.  Nothing emitted here is canonical observed evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from production.prediction.next_behavior_contract import (
    TACTIC_VOCABULARY,
)
from production.prediction.next_behavior_preprocessing import elapsed_time_bucket
from production.utils.serialization import stable_id, stable_json


POLICY_SCHEMA_VERSION = "prediction_attck_label_policy.v1"
RULE_BINDINGS_SCHEMA_VERSION = "prediction_attck_rule_bindings.v1"
LABEL_SCHEMA_VERSION = "prediction_attck_label.v1"
GROUP_SCHEMA_VERSION = "prediction_attck_label_group.v1"
BARRIER_SCHEMA_VERSION = "prediction_attck_causal_barrier.v1"
HISTORY_SCHEMA_VERSION = "prediction_attck_label_history_manifest.v1"
ENVIRONMENT_SCHEMA_VERSION = "prediction_attck_label_environment.v1"
EXAMPLE_SCHEMA_VERSION = "next_prediction_attck_label_example.v1"
INPUT_SCHEMA_VERSION = "next_prediction_attck_label_input.v1"
TARGET_CONTRACT_ID = "next_prediction_attck_label_group_or_session_end.v1"
AUTHORITY = "prediction_weak_rule_label"
MAXIMUM_HISTORY_GROUPS = 8
ROLES = ("train", "selection", "calibration")
OUTCOMES = ("continuation", "session_end")
TERMINAL_OUTCOME = "session_end_before_another_prediction_label_group"
CONTINUATION_OUTCOME = "another_prediction_label_group"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TECHNIQUE = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")
_SAFE_ID = re.compile(r"^(?:nb|pred)[A-Za-z0-9_-]{8,160}$")
_BARRIER_CODES = frozenset(
    {
        "ambiguous_tactic_mapping",
        "parser_abstention",
        "unresolved_value",
        "unsupported_composition",
        "conditional_execution_unproven",
        "malformed_evidence",
        "quarantined_evidence",
        "missing_durable_order",
        "conflicting_duplicate",
    }
)
_RULE_SOURCES = frozenset({"rule", "both", "rule_securebert_disagreement"})
_MODEL_ONLY_SOURCES = frozenset(
    {
        "securebert",
        "securebert_low_confidence",
        "securebert_error",
        "securebert_unavailable",
        "unclassified",
    }
)
_FORBIDDEN_KEYS = frozenset(
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
        "session",
        "session_id_raw",
    }
)


class PredictionAttckLabelError(ValueError):
    """Raised when a prediction-only contract cannot be constructed."""


def _text(value: Any) -> str:
    return str(value or "").strip()


def _sha(value: Any, field: str) -> str:
    value = _text(value).lower()
    if not _SHA256.fullmatch(value):
        raise PredictionAttckLabelError(f"{field} must be a SHA-256 digest")
    return value


def _safe_id(value: Any, field: str) -> str:
    value = _text(value)
    if not _SAFE_ID.fullmatch(value):
        raise PredictionAttckLabelError(f"{field} must be a pseudonymous stable ID")
    return value


def _ordered_unique(values: Iterable[Any]) -> list[str]:
    return sorted({_text(value) for value in values if _text(value)})


def _sha_json(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def _unexpected(value: Mapping[str, Any], allowed: set[str], path: str) -> list[str]:
    return [
        f"{path}.{key} is not defined by the contract"
        for key in sorted(value)
        if key not in allowed
    ]


def _contains_forbidden(value: Any, path: str = "$") -> list[str]:
    errors: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            if _text(key).lower() in _FORBIDDEN_KEYS:
                errors.append(f"{path}.{key} contains a forbidden privacy field")
            errors.extend(_contains_forbidden(item, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            errors.extend(_contains_forbidden(item, f"{path}[{index}]"))
    return errors


def _rule_ids(policy: Mapping[str, Any]) -> tuple[set[str], set[str]]:
    allow = policy.get("allowlist")
    if not isinstance(allow, Mapping):
        return set(), set()
    structural = {
        _text(item) for item in allow.get("structural_rule_ids") or [] if _text(item)
    }
    regex = {_text(item) for item in allow.get("regex_rule_ids") or [] if _text(item)}
    return structural, regex


def validate_prediction_attck_label_policy(
    document: Any,
    *,
    classification_policy: Mapping[str, Any] | None = None,
) -> list[str]:
    """Validate the frozen policy and its explicit reviewed-rule allowlist."""

    errors: list[str] = []
    if not isinstance(document, Mapping):
        return ["prediction label policy must be an object"]
    allowed = {
        "schema_version",
        "policy_id",
        "authority",
        "label_schema_version",
        "group_schema_version",
        "history_schema_version",
        "target_contract_id",
        "maximum_history_groups",
        "classification_rule_policy_path",
        "classification_rule_policy_sha256",
        "rule_bindings_schema_version",
        "rule_bindings_path",
        "rule_bindings_sha256",
        "rule_bindings",
        "allowlist",
        "admission",
        "barriers",
        "support_policy",
        "privacy",
        "training_authorization",
        # Added by load_prediction_attck_label_policy as the immutable
        # content-address of the policy bytes.  It is deliberately optional
        # for validating a parsed, pre-load document, but required by all
        # runtime constructors that consume a loaded policy.
        "policy_sha256",
    }
    errors.extend(_unexpected(document, allowed, "policy"))
    if document.get("schema_version") != POLICY_SCHEMA_VERSION:
        errors.append("policy.schema_version is invalid")
    if not _text(document.get("policy_id")):
        errors.append("policy.policy_id is required")
    if document.get("authority") != AUTHORITY:
        errors.append("policy.authority is invalid")
    if document.get("label_schema_version") != LABEL_SCHEMA_VERSION:
        errors.append("policy.label_schema_version is invalid")
    if document.get("group_schema_version") != GROUP_SCHEMA_VERSION:
        errors.append("policy.group_schema_version is invalid")
    if document.get("history_schema_version") != HISTORY_SCHEMA_VERSION:
        errors.append("policy.history_schema_version is invalid")
    if document.get("target_contract_id") != TARGET_CONTRACT_ID:
        errors.append("policy.target_contract_id is invalid")
    if document.get("maximum_history_groups") != MAXIMUM_HISTORY_GROUPS:
        errors.append("policy.maximum_history_groups must be 8")
    try:
        classification_hash = _sha(
            document.get("classification_rule_policy_sha256"),
            "policy.classification_rule_policy_sha256",
        )
    except PredictionAttckLabelError as exc:
        errors.append(str(exc))
        classification_hash = ""
    if not _text(document.get("classification_rule_policy_path")):
        errors.append("policy.classification_rule_policy_path is required")
    if document.get("rule_bindings_schema_version") != RULE_BINDINGS_SCHEMA_VERSION:
        errors.append("policy.rule_bindings_schema_version is invalid")
    if not _text(document.get("rule_bindings_path")):
        errors.append("policy.rule_bindings_path is required")
    try:
        _sha(document.get("rule_bindings_sha256"), "policy.rule_bindings_sha256")
    except PredictionAttckLabelError as exc:
        errors.append(str(exc))
    if "policy_sha256" in document:
        try:
            _sha(document.get("policy_sha256"), "policy.policy_sha256")
        except PredictionAttckLabelError as exc:
            errors.append(str(exc))

    structural, regex = _rule_ids(document)
    if not structural or not regex:
        errors.append("policy allowlist must contain structural and regex rule IDs")
    if len(structural) != len(document.get("allowlist", {}).get("structural_rule_ids", [])):
        errors.append("policy structural rule IDs must be unique")
    if len(regex) != len(document.get("allowlist", {}).get("regex_rule_ids", [])):
        errors.append("policy regex rule IDs must be unique")
    if isinstance(classification_policy, Mapping):
        actual_hash = _sha_json(classification_policy)
        # Callers normally pass the parsed policy with source bytes separately;
        # this check intentionally accepts a source_sha256 binding when present.
        declared_source = _text(classification_policy.get("source_sha256")).lower()
        if declared_source and declared_source != classification_hash:
            errors.append("classification policy source hash does not match binding")
        body = classification_policy.get("policy", classification_policy)
        rules = body.get("rules") if isinstance(body, Mapping) else None
        if not isinstance(rules, list):
            errors.append("classification policy rules are unavailable")
        else:
            actual_structural = {
                _text(rule.get("rule_id"))
                for rule in rules
                if isinstance(rule, Mapping)
                and rule.get("enabled") is not False
                and rule.get("evidence_type") == "command_operation"
                and (rule.get("provenance") or {}).get("reviewed") is True
            }
            actual_regex = {
                _text(rule.get("rule_id"))
                for rule in rules
                if isinstance(rule, Mapping)
                and rule.get("enabled") is not False
                and rule.get("evidence_type") == "command_regex"
                and (rule.get("provenance") or {}).get("reviewed") is True
            }
            if structural != actual_structural:
                errors.append("structural rule allowlist does not equal reviewed policy IDs")
            if regex != actual_regex:
                errors.append("regex rule allowlist does not equal reviewed policy IDs")

            bindings = document.get("rule_bindings")
            if isinstance(bindings, Mapping):
                for rule in rules:
                    rule_id = _text(rule.get("rule_id"))
                    if rule_id not in structural | regex:
                        continue
                    binding = bindings.get(rule_id)
                    expected_binding = {
                        "evidence_type": _text(rule.get("evidence_type")),
                        "technique": _text(rule.get("ttp")).upper(),
                        "tactic": _text(rule.get("reviewed_tactic")).lower(),
                    }
                    if binding != expected_binding:
                        errors.append(f"rule binding does not match classification policy: {rule_id}")

    bindings = document.get("rule_bindings")
    if bindings is not None:
        if not isinstance(bindings, Mapping):
            errors.append("policy.rule_bindings must be an object")
        else:
            expected_ids = structural | regex
            if set(bindings) != expected_ids:
                errors.append("policy.rule_bindings must cover exactly the allowlist")
            for rule_id, binding in bindings.items():
                if not isinstance(binding, Mapping) or set(binding) != {"evidence_type", "technique", "tactic"}:
                    errors.append(f"policy.rule_bindings.{rule_id} is invalid")
                    continue
                if binding.get("evidence_type") not in {"command_operation", "command_regex"}:
                    errors.append(f"policy.rule_bindings.{rule_id}.evidence_type is invalid")
                if not _TECHNIQUE.fullmatch(_text(binding.get("technique")).upper()):
                    errors.append(f"policy.rule_bindings.{rule_id}.technique is invalid")
                if _text(binding.get("tactic")).lower() not in TACTIC_VOCABULARY:
                    errors.append(f"policy.rule_bindings.{rule_id}.tactic is invalid")
                if rule_id in structural and binding.get("evidence_type") != "command_operation":
                    errors.append(f"policy.rule_bindings.{rule_id} must be structural")
                if rule_id in regex and binding.get("evidence_type") != "command_regex":
                    errors.append(f"policy.rule_bindings.{rule_id} must be regex")

    admission = document.get("admission")
    if not isinstance(admission, Mapping):
        errors.append("policy.admission is required")
    else:
        for key in (
            "requires_reviewed_rule",
            "requires_exact_reviewed_tactic",
            "requires_exact_technique",
            "requires_parsed_literal_context",
        ):
            if admission.get(key) is not True:
                errors.append(f"policy.admission.{key} must be true")
        for key in (
            "allows_model_only",
            "allows_model_confidence_authority",
            "allows_conditional_fragments",
            "allows_parser_abstention",
            "allows_unresolved_values",
            "allows_emergency_rules",
            "allows_malformed_events",
        ):
            if admission.get(key) is not False:
                errors.append(f"policy.admission.{key} must be false")
        if admission.get("allows_rule_side_of_disagreement") is not True:
            errors.append("policy.admission.allows_rule_side_of_disagreement must be true")

    barriers = document.get("barriers")
    if not isinstance(barriers, Mapping) or barriers.get("schema_version") != BARRIER_SCHEMA_VERSION:
        errors.append("policy.barriers schema is invalid")
    else:
        reasons = barriers.get("reason_codes")
        if not isinstance(reasons, list) or set(reasons) != set(_BARRIER_CODES):
            errors.append("policy.barriers.reason_codes are incomplete or altered")

    support = document.get("support_policy")
    if not isinstance(support, Mapping):
        errors.append("policy.support_policy is required")
    else:
        expected = {
            "minimum_targets_per_role_and_class": 30,
            "minimum_distinct_sessions_per_role_and_class": 30,
            "minimum_conditional_tactic_classes": 2,
            "minimum_changed_targets_per_role_and_class": 30,
            "minimum_changed_distinct_sessions_per_role_and_class": 30,
        }
        for key, expected_value in expected.items():
            if support.get(key) != expected_value:
                errors.append(f"policy.support_policy.{key} must be {expected_value}")
        if support.get("required_binary_classes") != list(OUTCOMES):
            errors.append("policy.support_policy.required_binary_classes is invalid")
        if support.get("execution_required_when_claimed") is not True:
            errors.append("policy.support_policy.execution_required_when_claimed must be true")
        if support.get("unsupported_tactics_retained") is not True:
            errors.append("policy.support_policy.unsupported_tactics_retained must be true")
        if support.get("posthoc_other_class") is not False:
            errors.append("policy.support_policy.posthoc_other_class must be false")

    privacy = document.get("privacy")
    if not isinstance(privacy, Mapping):
        errors.append("policy.privacy is required")
    else:
        for key in (
            "raw_commands_in_model_artifacts",
            "original_session_ids_in_model_artifacts",
            "network_identifiers_in_model_artifacts",
            "credentials_in_model_artifacts",
        ):
            if privacy.get(key) is not False:
                errors.append(f"policy.privacy.{key} must be false")
        for key in ("pseudonymization_policy_required", "sanitizer_policy_required"):
            if privacy.get(key) is not True:
                errors.append(f"policy.privacy.{key} must be true")

    auth = document.get("training_authorization")
    if not isinstance(auth, Mapping) or any(
        auth.get(key) is not False
        for key in ("model_training_authorized", "production_prediction_authorized", "sealed_test_access_authorized")
    ) or not isinstance(auth, Mapping) or auth.get("support_analysis_only") is not True:
        errors.append("policy.training_authorization must remain support-analysis-only")
    errors.extend(_contains_forbidden(document))
    return sorted(set(errors))


def load_prediction_attck_label_policy(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PredictionAttckLabelError(f"cannot load prediction label policy: {exc}") from exc
    errors = validate_prediction_attck_label_policy(document)
    if errors:
        raise PredictionAttckLabelError("; ".join(errors))
    document = dict(document)
    document["policy_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    bindings_path = path.parent / _text(document.get("rule_bindings_path"))
    try:
        bindings_document = json.loads(bindings_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PredictionAttckLabelError("cannot load prediction rule bindings") from exc
    if not isinstance(bindings_document, Mapping):
        raise PredictionAttckLabelError("prediction rule bindings must be an object")
    if bindings_document.get("schema_version") != RULE_BINDINGS_SCHEMA_VERSION:
        raise PredictionAttckLabelError("prediction rule bindings schema is invalid")
    if bindings_document.get("policy_id") != document.get("policy_id"):
        raise PredictionAttckLabelError("prediction rule bindings policy identity is invalid")
    if bindings_document.get("classification_rule_policy_sha256") != document.get("classification_rule_policy_sha256"):
        raise PredictionAttckLabelError("prediction rule bindings classification policy hash is invalid")
    binding_bytes_sha = hashlib.sha256(bindings_path.read_bytes()).hexdigest()
    if binding_bytes_sha != _text(document.get("rule_bindings_sha256")):
        raise PredictionAttckLabelError("prediction rule bindings bytes do not match policy")
    document["rule_bindings"] = dict(bindings_document.get("bindings") or {})
    errors = validate_prediction_attck_label_policy(document)
    if errors:
        raise PredictionAttckLabelError("loaded prediction label policy is invalid: " + "; ".join(errors))
    return document


def prediction_policy_file_sha256(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _candidate_reason(candidate: Mapping[str, Any]) -> str:
    authority = candidate.get("authority_decision")
    if isinstance(authority, Mapping):
        reasons = authority.get("reasons")
        if isinstance(reasons, list) and reasons:
            return _text(reasons[0])
    return _text(candidate.get("eligibility_reason"))


def _candidate_barrier_reason(candidate: Mapping[str, Any]) -> str | None:
    if candidate.get("missing_durable_order") is True or candidate.get("event_order") is None:
        return "missing_durable_order"
    if candidate.get("conflicting_duplicate") is True:
        return "conflicting_duplicate"
    if candidate.get("malformed") is True:
        return "malformed_evidence"
    if candidate.get("quarantined") is True:
        return "quarantined_evidence"
    parser_status = _text(candidate.get("parser_status")).lower()
    authority = candidate.get("authority_decision")
    authority_reasons = set()
    if isinstance(authority, Mapping):
        authority_reasons = {_text(item) for item in authority.get("reasons") or [] if _text(item)}
    if parser_status and parser_status != "parsed":
        return "parser_abstention"
    if candidate.get("parser_abstention") is True or "parser_abstention" in authority_reasons:
        return "parser_abstention"
    if candidate.get("unresolved") is True or candidate.get("dynamic_value") is True:
        return "unresolved_value"
    if candidate.get("unsupported_composition") is True:
        return "unsupported_composition"
    operator = _text(candidate.get("operator_before"))
    if operator in {"&&", "||"} or candidate.get("conditional_unproven") is True:
        return "conditional_execution_unproven"
    if candidate.get("ambiguous_tactic") is True or candidate.get("ambiguous_technique") is True:
        return "ambiguous_tactic_mapping"
    if "unresolved" in " ".join(sorted(authority_reasons)):
        return "unresolved_value"
    if "explicit_abstention" in _text((authority or {}).get("safety_class") if isinstance(authority, Mapping) else ""):
        return "parser_abstention"
    return None


def _prediction_context_allows(candidate: Mapping[str, Any]) -> bool:
    context = candidate.get("prediction_context")
    if not isinstance(context, Mapping):
        # Structural candidates carry their reviewed predicate in the parser
        # decision. Regex candidates must opt into the prediction-specific
        # context predicate; this prevents accidental lexical fallback.
        return _text(candidate.get("evidence_type")) == "command_operation"
    if context.get("reviewed") is not True:
        return False
    if _text(context.get("class")) not in {
        "reviewed_structural_operation",
        "reviewed_literal_command_pattern",
    }:
        return False
    if context.get("inert_text_match") is True:
        return False
    if context.get("operation_proven") is False and _text(candidate.get("evidence_type")) == "command_operation":
        return False
    return True


def _minimal_audit_metadata(candidate: Mapping[str, Any]) -> dict[str, Any]:
    source = _text(candidate.get("source")).lower()
    metadata: dict[str, Any] = {
        "source": source,
        "agreement_status": _text(candidate.get("agreement_status")) or "not_comparable",
        "model_side_present": bool(candidate.get("bert_ttp") or candidate.get("model_tactic")),
    }
    if source == "rule_securebert_disagreement":
        metadata["disagreement"] = True
        metadata["model_label_excluded"] = True
    if candidate.get("confidence") is not None:
        try:
            score = float(candidate.get("confidence"))
            if 0.0 <= score <= 1.0:
                metadata["model_confidence_bucket"] = (
                    "high" if score >= 0.90 else "medium" if score >= 0.55 else "low"
                )
        except (TypeError, ValueError):
            pass
    return metadata


def evaluate_prediction_candidate(
    candidate: Mapping[str, Any],
    *,
    policy: Mapping[str, Any],
    sanitizer_policy_id: str,
    pseudonymization_policy_id: str,
    parser_identity: str,
    splitter_identity: str,
    labeler_identity: str,
) -> dict[str, Any]:
    """Return an eligible label, exclusion, or explicit causal barrier.

    ``command`` may be supplied transiently for matching, but it is never
    copied into the returned safe artifact.
    """

    policy_errors = validate_prediction_attck_label_policy(policy)
    if policy_errors:
        raise PredictionAttckLabelError("invalid prediction label policy: " + "; ".join(policy_errors))
    source = _text(candidate.get("source")).lower()
    barrier = _candidate_barrier_reason(candidate)
    if barrier:
        return {
            "status": "barrier",
            "authority": AUTHORITY,
            "reason_code": barrier,
            "audit": _minimal_audit_metadata(candidate),
        }
    if source in _MODEL_ONLY_SOURCES or source not in _RULE_SOURCES:
        return {
            "status": "excluded",
            "authority": AUTHORITY,
            "reason_code": "model_only_or_unsupported_source",
            "audit": _minimal_audit_metadata(candidate),
        }
    structural_ids, regex_ids = _rule_ids(policy)
    rule_id = _text(candidate.get("rule_id"))
    evidence_type = _text(candidate.get("evidence_type"))
    if rule_id not in structural_ids | regex_ids:
        return {"status": "excluded", "authority": AUTHORITY, "reason_code": "rule_not_allowlisted", "audit": _minimal_audit_metadata(candidate)}
    if evidence_type == "command_operation" and rule_id not in structural_ids:
        return {"status": "excluded", "authority": AUTHORITY, "reason_code": "rule_evidence_type_mismatch", "audit": _minimal_audit_metadata(candidate)}
    if evidence_type == "command_regex" and rule_id not in regex_ids:
        return {"status": "excluded", "authority": AUTHORITY, "reason_code": "rule_evidence_type_mismatch", "audit": _minimal_audit_metadata(candidate)}
    if evidence_type not in {"command_operation", "command_regex"}:
        return {"status": "excluded", "authority": AUTHORITY, "reason_code": "unsupported_evidence_type", "audit": _minimal_audit_metadata(candidate)}
    binding = (policy.get("rule_bindings") or {}).get(rule_id)
    if not isinstance(binding, Mapping):
        return {"status": "excluded", "authority": AUTHORITY, "reason_code": "rule_binding_unavailable", "audit": _minimal_audit_metadata(candidate)}
    if binding.get("evidence_type") != evidence_type:
        return {"status": "barrier", "authority": AUTHORITY, "reason_code": "ambiguous_tactic_mapping", "audit": _minimal_audit_metadata(candidate)}
    if candidate.get("rule_reviewed") is not True and candidate.get("reviewed") is not True:
        return {"status": "excluded", "authority": AUTHORITY, "reason_code": "unreviewed_rule", "audit": _minimal_audit_metadata(candidate)}
    if not _prediction_context_allows(candidate):
        reason = "prediction_context_not_reviewed"
        context = candidate.get("prediction_context")
        if isinstance(context, Mapping) and context.get("inert_text_match") is True:
            reason = "inert_lexical_match"
        return {"status": "excluded", "authority": AUTHORITY, "reason_code": reason, "audit": _minimal_audit_metadata(candidate)}
    try:
        event_id = _safe_id(candidate.get("event_id"), "candidate.event_id")
        member_id = _safe_id(candidate.get("source_member_id"), "candidate.source_member_id")
        member_sha = _sha(candidate.get("source_member_sha256"), "candidate.source_member_sha256")
        event_order = candidate.get("event_order")
        if not isinstance(event_order, int) or isinstance(event_order, bool) or event_order < 0:
            raise PredictionAttckLabelError("candidate.event_order must be a non-negative integer")
        policy_sha = _sha(policy.get("policy_sha256"), "policy.policy_sha256")
        rule_policy_sha = _sha(candidate.get("rule_policy_sha256"), "candidate.rule_policy_sha256")
    except PredictionAttckLabelError as exc:
        return {"status": "barrier", "authority": AUTHORITY, "reason_code": "missing_durable_order" if "event_order" in str(exc) else "malformed_evidence", "audit": {"validation_error": str(exc)}}
    technique = _text(candidate.get("reviewed_technique") or candidate.get("ttp")).upper()
    tactic = _text(candidate.get("reviewed_tactic") or candidate.get("tactic")).lower()
    if not _TECHNIQUE.fullmatch(technique) or tactic not in TACTIC_VOCABULARY:
        return {"status": "barrier", "authority": AUTHORITY, "reason_code": "ambiguous_tactic_mapping", "audit": _minimal_audit_metadata(candidate)}
    if technique != _text(binding.get("technique")).upper() or tactic != _text(binding.get("tactic")).lower():
        return {"status": "barrier", "authority": AUTHORITY, "reason_code": "ambiguous_tactic_mapping", "audit": _minimal_audit_metadata(candidate)}
    if candidate.get("tactic") and _text(candidate.get("tactic")).lower() != tactic:
        return {"status": "barrier", "authority": AUTHORITY, "reason_code": "ambiguous_tactic_mapping", "audit": _minimal_audit_metadata(candidate)}
    identity = {
        "sanitizer_policy_id": _text(sanitizer_policy_id),
        "pseudonymization_policy_id": _text(pseudonymization_policy_id),
        "parser_identity": _text(parser_identity),
        "splitter_identity": _text(splitter_identity),
        "labeler_identity": _text(labeler_identity),
    }
    if any(not value for value in identity.values()):
        return {"status": "barrier", "authority": AUTHORITY, "reason_code": "malformed_evidence", "audit": {"validation_error": "labeler identities are required"}}
    source_kind = "rule_side_of_disagreement" if source == "rule_securebert_disagreement" else "reviewed_rule"
    label = {
        "schema_version": LABEL_SCHEMA_VERSION,
        "authority": AUTHORITY,
        "eligibility": "prediction_eligible",
        "eligibility_reason": "reviewed_rule_prediction_context",
        "event_id": event_id,
        "source_member_id": member_id,
        "source_member_sha256": member_sha,
        "event_order": event_order,
        "prediction_policy_id": _text(policy.get("policy_id")),
        "prediction_policy_sha256": policy_sha,
        "rule_id": rule_id,
        "rule_match_type": evidence_type,
        "rule_source_kind": source_kind,
        "rule_policy_sha256": rule_policy_sha,
        "technique": technique,
        "tactic": tactic,
        "sanitizer_policy_id": identity["sanitizer_policy_id"],
        "pseudonymization_policy_id": identity["pseudonymization_policy_id"],
        "parser_identity": identity["parser_identity"],
        "splitter_identity": identity["splitter_identity"],
        "labeler_identity": identity["labeler_identity"],
        "audit_metadata": _minimal_audit_metadata(candidate),
    }
    label["label_id"] = stable_id("predlabel", {key: label[key] for key in label if key != "label_id"})
    errors = validate_prediction_label(label)
    if errors:
        raise PredictionAttckLabelError("constructed label is invalid: " + "; ".join(errors))
    return {"status": "eligible", "authority": AUTHORITY, "label": label}


def validate_prediction_label(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return ["prediction label must be an object"]
    allowed = {
        "schema_version", "authority", "eligibility", "eligibility_reason", "label_id",
        "event_id", "source_member_id", "source_member_sha256", "event_order",
        "prediction_policy_id", "prediction_policy_sha256", "rule_id", "rule_match_type",
        "rule_source_kind", "rule_policy_sha256", "technique", "tactic",
        "sanitizer_policy_id", "pseudonymization_policy_id", "parser_identity",
        "splitter_identity", "labeler_identity", "audit_metadata",
    }
    errors = _unexpected(value, allowed, "label")
    if value.get("schema_version") != LABEL_SCHEMA_VERSION:
        errors.append("label.schema_version is invalid")
    if value.get("authority") != AUTHORITY:
        errors.append("label.authority is invalid")
    if value.get("eligibility") != "prediction_eligible":
        errors.append("label.eligibility is invalid")
    for field in ("label_id", "event_id", "source_member_id"):
        try:
            _safe_id(value.get(field), f"label.{field}")
        except PredictionAttckLabelError as exc:
            errors.append(str(exc))
    for field in ("source_member_sha256", "prediction_policy_sha256", "rule_policy_sha256"):
        try:
            _sha(value.get(field), f"label.{field}")
        except PredictionAttckLabelError as exc:
            errors.append(str(exc))
    if not isinstance(value.get("event_order"), int) or isinstance(value.get("event_order"), bool) or value.get("event_order") < 0:
        errors.append("label.event_order is invalid")
    if value.get("rule_match_type") not in {"command_operation", "command_regex"}:
        errors.append("label.rule_match_type is invalid")
    if value.get("rule_source_kind") not in {"reviewed_rule", "rule_side_of_disagreement"}:
        errors.append("label.rule_source_kind is invalid")
    if not _TECHNIQUE.fullmatch(_text(value.get("technique")).upper()):
        errors.append("label.technique is invalid")
    if _text(value.get("tactic")).lower() not in TACTIC_VOCABULARY:
        errors.append("label.tactic is invalid")
    for field in ("prediction_policy_id", "rule_id", "eligibility_reason", "sanitizer_policy_id", "pseudonymization_policy_id", "parser_identity", "splitter_identity", "labeler_identity"):
        if not _text(value.get(field)):
            errors.append(f"label.{field} is required")
    if not isinstance(value.get("audit_metadata"), Mapping):
        errors.append("label.audit_metadata is invalid")
    errors.extend(_contains_forbidden(value))
    return sorted(set(errors))


def build_prediction_label_group(
    labels: Sequence[Mapping[str, Any]],
    *,
    relative_time_ms: int | float | None = None,
) -> dict[str, Any]:
    """Build one event group; compatible duplicates are deterministic, conflicts fail closed."""

    if not labels:
        raise PredictionAttckLabelError("a prediction label group requires at least one label")
    normalized: dict[tuple[str, str], dict[str, Any]] = {}
    for label in labels:
        errors = validate_prediction_label(label)
        if errors:
            raise PredictionAttckLabelError("invalid group label: " + "; ".join(errors))
        pair = (_text(label["tactic"]).lower(), _text(label["technique"]).upper())
        existing = normalized.get(pair)
        if existing is not None:
            if stable_json(existing) != stable_json(label):
                raise PredictionAttckLabelError("conflicting duplicate prediction labels")
            continue
        normalized[pair] = dict(label)
    ordered = [normalized[key] for key in sorted(normalized)]
    first = ordered[0]
    event_id = first["event_id"]
    member_id = first["source_member_id"]
    order = first["event_order"]
    for label in ordered[1:]:
        if label["event_id"] != event_id or label["source_member_id"] != member_id or label["event_order"] != order:
            raise PredictionAttckLabelError("labels in one group must share event identity and order")
    group = {
        "schema_version": GROUP_SCHEMA_VERSION,
        "authority": AUTHORITY,
        "group_id": stable_id("predgroup", {"event_id": event_id, "labels": ordered}),
        "event_id": event_id,
        "source_member_id": member_id,
        "source_member_sha256": first["source_member_sha256"],
        "event_order": order,
        "relative_time_ms": relative_time_ms,
        "prediction_policy_id": first["prediction_policy_id"],
        "prediction_policy_sha256": first["prediction_policy_sha256"],
        "labels": ordered,
        "tactics": sorted({_text(label["tactic"]).lower() for label in ordered}),
        "techniques": sorted({_text(label["technique"]).upper() for label in ordered}),
        "evidence_refs": [event_id],
        "same_tactic_group": len({_text(label["tactic"]).lower() for label in ordered}) == 1,
    }
    group["group_sha256"] = _sha_json(group)
    errors = validate_prediction_label_group(group)
    if errors:
        raise PredictionAttckLabelError("constructed group is invalid: " + "; ".join(errors))
    return group


def validate_prediction_label_group(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return ["prediction label group must be an object"]
    allowed = {
        "schema_version", "authority", "group_id", "event_id", "source_member_id",
        "source_member_sha256", "event_order", "prediction_policy_id",
        "prediction_policy_sha256", "labels", "tactics", "techniques", "evidence_refs",
        "same_tactic_group", "group_sha256", "relative_time_ms",
    }
    errors = _unexpected(value, allowed, "group")
    if value.get("schema_version") != GROUP_SCHEMA_VERSION:
        errors.append("group.schema_version is invalid")
    if value.get("authority") != AUTHORITY:
        errors.append("group.authority is invalid")
    for field in ("group_id", "event_id", "source_member_id"):
        try:
            _safe_id(value.get(field), f"group.{field}")
        except PredictionAttckLabelError as exc:
            errors.append(str(exc))
    for field in ("source_member_sha256", "prediction_policy_sha256", "group_sha256"):
        try:
            _sha(value.get(field), f"group.{field}")
        except PredictionAttckLabelError as exc:
            errors.append(str(exc))
    if not isinstance(value.get("event_order"), int) or isinstance(value.get("event_order"), bool) or value.get("event_order") < 0:
        errors.append("group.event_order is invalid")
    if value.get("relative_time_ms") is not None and (
        isinstance(value.get("relative_time_ms"), bool)
        or not isinstance(value.get("relative_time_ms"), (int, float))
        or value.get("relative_time_ms") < 0
    ):
        errors.append("group.relative_time_ms is invalid")
    labels = value.get("labels")
    if not isinstance(labels, list) or not labels:
        errors.append("group.labels must be a non-empty array")
    else:
        for label in labels:
            errors.extend(validate_prediction_label(label))
        pairs = [(_text(label.get("tactic")).lower(), _text(label.get("technique")).upper()) for label in labels if isinstance(label, Mapping)]
        if pairs != sorted(set(pairs)):
            errors.append("group.labels must be unique and canonically ordered")
        if any(label.get("event_id") != value.get("event_id") or label.get("event_order") != value.get("event_order") for label in labels if isinstance(label, Mapping)):
            errors.append("group labels must share event identity and order")
    expected_tactics = sorted({_text(label.get("tactic")).lower() for label in labels if isinstance(label, Mapping)})
    expected_techniques = sorted({_text(label.get("technique")).upper() for label in labels if isinstance(label, Mapping)})
    if value.get("tactics") != expected_tactics:
        errors.append("group.tactics do not match labels")
    if value.get("techniques") != expected_techniques:
        errors.append("group.techniques do not match labels")
    if value.get("same_tactic_group") is not (len(expected_tactics) == 1):
        errors.append("group.same_tactic_group is inconsistent")
    refs = value.get("evidence_refs")
    if refs != sorted(set(refs or [])) or refs != [value.get("event_id")]:
        errors.append("group.evidence_refs are invalid")
    if isinstance(value.get("group_sha256"), str):
        body = dict(value)
        body.pop("group_sha256", None)
        if value["group_sha256"] != _sha_json(body):
            errors.append("group.group_sha256 does not match content")
    errors.extend(_contains_forbidden(value))
    return sorted(set(errors))


def build_prediction_barrier(
    *,
    event_id: str,
    source_member_id: str,
    source_member_sha256: str,
    event_order: int | None,
    reason_code: str,
    prediction_policy_id: str,
    prediction_policy_sha256: str,
    sanitizer_policy_id: str,
    pseudonymization_policy_id: str,
) -> dict[str, Any]:
    if reason_code not in _BARRIER_CODES:
        raise PredictionAttckLabelError("unknown causal barrier reason")
    if not isinstance(event_order, int) or isinstance(event_order, bool) or event_order < 0:
        raise PredictionAttckLabelError("barrier requires durable event order")
    body = {
        "schema_version": BARRIER_SCHEMA_VERSION,
        "authority": AUTHORITY,
        "barrier_id": stable_id("predbarrier", {"event_id": event_id, "reason_code": reason_code}),
        "event_id": _safe_id(event_id, "barrier.event_id"),
        "source_member_id": _safe_id(source_member_id, "barrier.source_member_id"),
        "source_member_sha256": _sha(source_member_sha256, "barrier.source_member_sha256"),
        "event_order": event_order,
        "reason_code": reason_code,
        "prediction_policy_id": _text(prediction_policy_id),
        "prediction_policy_sha256": _sha(prediction_policy_sha256, "barrier.prediction_policy_sha256"),
        "sanitizer_policy_id": _text(sanitizer_policy_id),
        "pseudonymization_policy_id": _text(pseudonymization_policy_id),
        "status": "causal_barrier",
    }
    errors = validate_prediction_barrier(body)
    if errors:
        raise PredictionAttckLabelError("constructed barrier is invalid: " + "; ".join(errors))
    return body


def validate_prediction_barrier(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return ["causal barrier must be an object"]
    allowed = {
        "schema_version", "authority", "barrier_id", "event_id", "source_member_id",
        "source_member_sha256", "event_order", "reason_code", "prediction_policy_id",
        "prediction_policy_sha256", "sanitizer_policy_id", "pseudonymization_policy_id",
        "status",
    }
    errors = _unexpected(value, allowed, "barrier")
    if value.get("schema_version") != BARRIER_SCHEMA_VERSION:
        errors.append("barrier.schema_version is invalid")
    if value.get("authority") != AUTHORITY:
        errors.append("barrier.authority is invalid")
    for field in ("barrier_id", "event_id", "source_member_id"):
        try:
            _safe_id(value.get(field), f"barrier.{field}")
        except PredictionAttckLabelError as exc:
            errors.append(str(exc))
    for field in ("source_member_sha256", "prediction_policy_sha256"):
        try:
            _sha(value.get(field), f"barrier.{field}")
        except PredictionAttckLabelError as exc:
            errors.append(str(exc))
    if value.get("reason_code") not in _BARRIER_CODES:
        errors.append("barrier.reason_code is invalid")
    if value.get("status") != "causal_barrier":
        errors.append("barrier.status is invalid")
    if not all(_text(value.get(field)) for field in ("prediction_policy_id", "sanitizer_policy_id", "pseudonymization_policy_id")):
        errors.append("barrier provenance identities are required")
    errors.extend(_contains_forbidden(value))
    return sorted(set(errors))


def _group_features(group: Mapping[str, Any], previous: Mapping[str, Any] | None) -> dict[str, Any]:
    current_ms = group.get("relative_time_ms")
    previous_ms = previous.get("relative_time_ms") if previous else None
    elapsed = None
    if isinstance(current_ms, (int, float)) and isinstance(previous_ms, (int, float)):
        elapsed = max(float(current_ms) - float(previous_ms), 0.0)
    labels = group.get("labels") or []
    return {
        "tactics": list(group["tactics"]),
        "techniques": list(group["techniques"]),
        "labels": [{"tactic": item["tactic"], "technique": item["technique"]} for item in labels],
        "elapsed_since_previous_group_bucket": elapsed_time_bucket(elapsed),
        "rule_source_kinds": _ordered_unique(item.get("rule_source_kind") for item in labels),
        "agreement_statuses": _ordered_unique((item.get("audit_metadata") or {}).get("agreement_status") for item in labels),
    }


def build_prediction_history_manifest(
    groups: Sequence[Mapping[str, Any]],
    *,
    session_id: str,
    source_member_id: str,
    source_member_sha256: str,
    causal_segment_id: str,
    status: str,
    durable_cutoff: Mapping[str, Any],
    barriers_before_segment: int,
    policy: Mapping[str, Any],
    sanitizer_policy_id: str,
    pseudonymization_policy_id: str,
) -> dict[str, Any]:
    if status not in {"active", "closed"}:
        raise PredictionAttckLabelError("history status must be active or closed")
    if not isinstance(durable_cutoff, Mapping):
        raise PredictionAttckLabelError("durable cutoff is required")
    cutoff_order = durable_cutoff.get("event_order")
    if not isinstance(cutoff_order, int) or isinstance(cutoff_order, bool) or cutoff_order < 0:
        raise PredictionAttckLabelError("durable cutoff event_order is invalid")
    ordered = [dict(group) for group in groups]
    for group in ordered:
        errors = validate_prediction_label_group(group)
        if errors:
            raise PredictionAttckLabelError("invalid history group: " + "; ".join(errors))
    orders = [group["event_order"] for group in ordered]
    if orders != sorted(orders) or len(set(orders)) != len(orders):
        raise PredictionAttckLabelError("history groups must be strictly causal")
    if ordered and cutoff_order < ordered[-1]["event_order"]:
        raise PredictionAttckLabelError("history cutoff precedes the selected history")
    selected = ordered[-MAXIMUM_HISTORY_GROUPS:]
    omitted = len(ordered) - len(selected)
    model_sequence = [
        _group_features(group, ordered[index - 1] if index > 0 else None)
        for index, group in enumerate(ordered[-MAXIMUM_HISTORY_GROUPS:], start=max(0, len(ordered) - MAXIMUM_HISTORY_GROUPS))
    ]
    body = {
        "schema_version": HISTORY_SCHEMA_VERSION,
        "authority": AUTHORITY,
        "target_contract_id": TARGET_CONTRACT_ID,
        "session_id": _safe_id(session_id, "history.session_id"),
        "source_member_id": _safe_id(source_member_id, "history.source_member_id"),
        "source_member_sha256": _sha(source_member_sha256, "history.source_member_sha256"),
        "causal_segment_id": _safe_id(causal_segment_id, "history.causal_segment_id"),
        "status": status,
        "maximum_history_groups": MAXIMUM_HISTORY_GROUPS,
        "original_group_count": len(ordered),
        "selected_group_count": len(selected),
        "omitted_prefix_group_count": omitted,
        "truncated": omitted > 0,
        "selected_group_ids": [group["group_id"] for group in selected],
        "group_sequence": model_sequence,
        "input_evidence_refs": sorted({ref for group in selected for ref in group["evidence_refs"]}),
        "barriers_before_segment": int(barriers_before_segment),
        "durable_cutoff": dict(durable_cutoff),
        "prediction_policy_id": _text(policy.get("policy_id")),
        "prediction_policy_sha256": _sha(policy.get("policy_sha256"), "history.policy_sha256"),
        "sanitizer_policy_id": _text(sanitizer_policy_id),
        "pseudonymization_policy_id": _text(pseudonymization_policy_id),
    }
    body["history_manifest_sha256"] = _sha_json(body)
    errors = validate_prediction_history_manifest(body)
    if errors:
        raise PredictionAttckLabelError("constructed history is invalid: " + "; ".join(errors))
    return body


def validate_prediction_history_manifest(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return ["prediction history must be an object"]
    allowed = {
        "schema_version", "authority", "target_contract_id", "session_id", "source_member_id",
        "source_member_sha256", "causal_segment_id", "status", "maximum_history_groups",
        "original_group_count", "selected_group_count", "omitted_prefix_group_count", "truncated",
        "selected_group_ids", "group_sequence", "input_evidence_refs", "barriers_before_segment",
        "durable_cutoff", "prediction_policy_id", "prediction_policy_sha256",
        "sanitizer_policy_id", "pseudonymization_policy_id", "history_manifest_sha256",
    }
    errors = _unexpected(value, allowed, "history")
    if value.get("schema_version") != HISTORY_SCHEMA_VERSION:
        errors.append("history.schema_version is invalid")
    if value.get("authority") != AUTHORITY:
        errors.append("history.authority is invalid")
    if value.get("target_contract_id") != TARGET_CONTRACT_ID:
        errors.append("history.target_contract_id is invalid")
    for field in ("session_id", "source_member_id", "causal_segment_id"):
        try:
            _safe_id(value.get(field), f"history.{field}")
        except PredictionAttckLabelError as exc:
            errors.append(str(exc))
    for field in ("source_member_sha256", "prediction_policy_sha256", "history_manifest_sha256"):
        try:
            _sha(value.get(field), f"history.{field}")
        except PredictionAttckLabelError as exc:
            errors.append(str(exc))
    if value.get("status") not in {"active", "closed"}:
        errors.append("history.status is invalid")
    if value.get("maximum_history_groups") != MAXIMUM_HISTORY_GROUPS:
        errors.append("history.maximum_history_groups is invalid")
    original, selected, omitted = (value.get(key) for key in ("original_group_count", "selected_group_count", "omitted_prefix_group_count"))
    if not all(isinstance(item, int) and not isinstance(item, bool) for item in (original, selected, omitted)) or original != selected + omitted or selected < 1 or selected > MAXIMUM_HISTORY_GROUPS:
        errors.append("history group counts do not reconcile")
    elif value.get("truncated") is not (omitted > 0):
        errors.append("history.truncated is inconsistent")
    ids = value.get("selected_group_ids")
    if not isinstance(ids, list) or ids != list(dict.fromkeys(ids)) or not all(_SAFE_ID.fullmatch(_text(item)) for item in ids):
        errors.append("history.selected_group_ids are invalid")
    sequence = value.get("group_sequence")
    if not isinstance(sequence, list) or len(sequence) != selected:
        errors.append("history.group_sequence length is invalid")
    for item in sequence if isinstance(sequence, list) else []:
        if not isinstance(item, Mapping) or not isinstance(item.get("tactics"), list) or not isinstance(item.get("techniques"), list) or not isinstance(item.get("labels"), list):
            errors.append("history.group_sequence item is invalid")
    refs = value.get("input_evidence_refs")
    if not isinstance(refs, list) or refs != sorted(set(refs)) or any(not _SAFE_ID.fullmatch(_text(item)) for item in refs):
        errors.append("history.input_evidence_refs are invalid")
    cutoff = value.get("durable_cutoff")
    if not isinstance(cutoff, Mapping) or not isinstance(cutoff.get("event_order"), int) or not _text(cutoff.get("watermark_id")):
        errors.append("history.durable_cutoff is invalid")
    if not all(_text(value.get(key)) for key in ("prediction_policy_id", "sanitizer_policy_id", "pseudonymization_policy_id")):
        errors.append("history provenance identities are required")
    if isinstance(value.get("history_manifest_sha256"), str):
        body = dict(value)
        body.pop("history_manifest_sha256", None)
        if value["history_manifest_sha256"] != _sha_json(body):
            errors.append("history_manifest_sha256 does not match content")
    errors.extend(_contains_forbidden(value))
    return sorted(set(errors))


def _segment_groups(groups: Sequence[Mapping[str, Any]], barriers: Sequence[Mapping[str, Any]]) -> list[tuple[str, list[dict[str, Any]]]]:
    ordered = sorted((dict(group) for group in groups), key=lambda item: item["event_order"])
    barrier_orders = sorted(int(barrier["event_order"]) for barrier in barriers)
    segments: list[tuple[str, list[dict[str, Any]]]] = []
    current: list[dict[str, Any]] = []
    barrier_index = 0
    for group in ordered:
        while barrier_index < len(barrier_orders) and barrier_orders[barrier_index] < group["event_order"]:
            if current:
                segments.append(
                    (
                        stable_id(
                            "predsegment",
                            {
                                "first_group_id": current[0]["group_id"],
                                "first_event_order": current[0]["event_order"],
                            },
                        ),
                        current,
                    )
                )
                current = []
            barrier_index += 1
        current.append(group)
    if current:
        # The segment identity must be causal at the prediction point.  Do not
        # hash all future group IDs here: doing so would make the history
        # manifest (and therefore the model input hash) depend on its target.
        segments.append(
            (
                stable_id(
                    "predsegment",
                    {
                        "first_group_id": current[0]["group_id"],
                        "first_event_order": current[0]["event_order"],
                    },
                ),
                current,
            )
        )
    return segments


def build_next_prediction_label_examples(session: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Build immediate-next-group examples without crossing barriers."""

    if not isinstance(session, Mapping):
        raise PredictionAttckLabelError("prediction session must be an object")
    groups = list(session.get("groups") or [])
    barriers = list(session.get("barriers") or [])
    for group in groups:
        errors = validate_prediction_label_group(group)
        if errors:
            raise PredictionAttckLabelError("invalid session group: " + "; ".join(errors))
    for barrier in barriers:
        errors = validate_prediction_barrier(barrier)
        if errors:
            raise PredictionAttckLabelError("invalid session barrier: " + "; ".join(errors))
    session_id = _safe_id(session.get("session_id"), "session.session_id")
    member_id = _safe_id(session.get("source_member_id"), "session.source_member_id")
    member_sha = _sha(session.get("source_member_sha256"), "session.source_member_sha256")
    status = _text(session.get("status"))
    close_order = session.get("close_event_order")
    close_event_id = _text(session.get("close_event_id"))
    closed = status == "closed" and isinstance(close_order, int) and not isinstance(close_order, bool) and close_order >= 0 and close_event_id
    if status not in {"active", "closed"}:
        raise PredictionAttckLabelError("session.status must be active or closed")
    if status == "closed" and not closed:
        raise PredictionAttckLabelError("closed session requires explicit close event order and ID")
    policy = session.get("policy")
    if not isinstance(policy, Mapping):
        raise PredictionAttckLabelError("session.policy is required")
    sanitizer_id = _text(session.get("sanitizer_policy_id"))
    pseudo_id = _text(session.get("pseudonymization_policy_id"))
    parser_id = _text(session.get("parser_identity"))
    splitter_id = _text(session.get("splitter_identity"))
    labeler_id = _text(session.get("labeler_identity"))
    examples: list[dict[str, Any]] = []
    barrier_orders = sorted(int(barrier["event_order"]) for barrier in barriers)
    for segment_id, segment in _segment_groups(groups, barriers):
        for index, current in enumerate(segment):
            next_group = segment[index + 1] if index + 1 < len(segment) else None
            if next_group is not None:
                target = {
                    "outcome_type": "continuation",
                    "will_continue": True,
                    "tactics": list(next_group["tactics"]),
                    "techniques": list(next_group["techniques"]),
                    "labels": [{"tactic": item["tactic"], "technique": item["technique"]} for item in next_group["labels"]],
                    "terminal_outcome": "",
                    "target_group_id": next_group["group_id"],
                    "target_event_order": next_group["event_order"],
                    "target_evidence_refs": list(next_group["evidence_refs"]),
                }
            else:
                barrier_between = any(current["event_order"] < order < (close_order if isinstance(close_order, int) else 10**18) for order in barrier_orders)
                if not closed or barrier_between:
                    continue
                target = {
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
            history = build_prediction_history_manifest(
                segment[: index + 1],
                session_id=session_id,
                source_member_id=member_id,
                source_member_sha256=member_sha,
                causal_segment_id=segment_id,
                status=status,
                durable_cutoff={
                    "event_order": current["event_order"],
                    "watermark_id": _text(session.get("durable_watermark_id")) or current["event_id"],
                },
                barriers_before_segment=sum(1 for order in barrier_orders if order < current["event_order"]),
                policy=policy,
                sanitizer_policy_id=sanitizer_id,
                pseudonymization_policy_id=pseudo_id,
            )
            current_tactics = set(current["tactics"])
            target_tactics = set(target["tactics"])
            example = {
                "schema_version": EXAMPLE_SCHEMA_VERSION,
                "target_contract_id": TARGET_CONTRACT_ID,
                "session_id": session_id,
                "source_member_id": member_id,
                "prediction_group_id": current["group_id"],
                "prediction_event_order": current["event_order"],
                "causal_segment_id": segment_id,
                "model_input": history,
                "target": target,
                "changed_from_current": target["outcome_type"] == "continuation" and current_tactics != target_tactics,
            }
            example["example_id"] = stable_id("predexample", example)
            errors = validate_next_prediction_label_example(example)
            if errors:
                raise PredictionAttckLabelError("constructed example is invalid: " + "; ".join(errors))
            examples.append(example)
    return examples


def validate_next_prediction_label_example(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return ["prediction example must be an object"]
    allowed = {
        "schema_version", "target_contract_id", "example_id", "session_id", "source_member_id",
        "prediction_group_id", "prediction_event_order", "causal_segment_id", "model_input",
        "target", "changed_from_current",
    }
    errors = _unexpected(value, allowed, "example")
    if value.get("schema_version") != EXAMPLE_SCHEMA_VERSION:
        errors.append("example.schema_version is invalid")
    if value.get("target_contract_id") != TARGET_CONTRACT_ID:
        errors.append("example.target_contract_id is invalid")
    for field in ("example_id", "session_id", "source_member_id", "prediction_group_id", "causal_segment_id"):
        try:
            _safe_id(value.get(field), f"example.{field}")
        except PredictionAttckLabelError as exc:
            errors.append(str(exc))
    if not isinstance(value.get("prediction_event_order"), int) or isinstance(value.get("prediction_event_order"), bool):
        errors.append("example.prediction_event_order is invalid")
    if not isinstance(value.get("model_input"), Mapping) or value["model_input"].get("schema_version") != HISTORY_SCHEMA_VERSION:
        errors.append("example.model_input must be a prediction history manifest")
    target = value.get("target")
    if not isinstance(target, Mapping):
        errors.append("example.target must be an object")
    else:
        required = {"outcome_type", "will_continue", "tactics", "techniques", "labels", "terminal_outcome", "target_group_id", "target_event_order", "target_evidence_refs"}
        errors.extend(_unexpected(target, required, "example.target"))
        if target.get("outcome_type") not in {"continuation", "session_end"}:
            errors.append("example.target.outcome_type is invalid")
        if target.get("outcome_type") == "session_end":
            if target.get("will_continue") is not False or target.get("tactics") or target.get("labels") or target.get("target_group_id") or target.get("target_evidence_refs"):
                errors.append("session-end target contains continuation fields")
        else:
            if target.get("will_continue") is not True or not isinstance(target.get("target_group_id"), str) or not target.get("target_group_id") or not isinstance(target.get("target_evidence_refs"), list) or not target.get("target_evidence_refs"):
                errors.append("continuation target is incomplete")
            if not isinstance(target.get("labels"), list) or not target.get("labels"):
                errors.append("continuation target labels are required")
    if not isinstance(value.get("changed_from_current"), bool):
        errors.append("example.changed_from_current must be boolean")
    input_refs = set(value.get("model_input", {}).get("input_evidence_refs") or {}) if isinstance(value.get("model_input"), Mapping) else set()
    target_refs = set(target.get("target_evidence_refs") or {}) if isinstance(target, Mapping) else set()
    if input_refs & target_refs:
        errors.append("input and target evidence references overlap")
    errors.extend(_contains_forbidden(value))
    return sorted(set(errors))


def validate_prediction_attck_environment(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return ["prediction environment must be an object"]
    allowed = {
        "schema_version", "environment_id", "policy_id", "policy_sha256", "target_contract_id",
        "source_corpus_membership_id", "source_corpus_membership_sha256", "classification_rule_policy_id",
        "classification_rule_policy_sha256", "attack_mapping_id", "attack_mapping_sha256", "parser_id",
        "parser_sha256", "splitter_id", "splitter_sha256", "sanitizer_id", "sanitizer_sha256",
        "pseudonymization_id", "pseudonymization_sha256", "group_builder_id", "group_builder_sha256",
        "history_builder_id", "history_builder_sha256", "target_builder_id", "target_builder_sha256",
        "barrier_policy_id", "barrier_policy_sha256", "runtime_id", "runtime_sha256", "repository_commit",
        "repository_tree", "dependency_identity_sha256", "environment_sha256",
    }
    errors = _unexpected(value, allowed, "environment")
    if value.get("schema_version") != ENVIRONMENT_SCHEMA_VERSION:
        errors.append("environment.schema_version is invalid")
    if value.get("target_contract_id") != TARGET_CONTRACT_ID:
        errors.append("environment.target_contract_id is invalid")
    for field in sorted(allowed):
        if field.endswith("_sha256"):
            try:
                _sha(value.get(field), f"environment.{field}")
            except PredictionAttckLabelError as exc:
                errors.append(str(exc))
    for field in ("environment_id", "policy_id", "source_corpus_membership_id", "classification_rule_policy_id", "attack_mapping_id", "parser_id", "splitter_id", "sanitizer_id", "pseudonymization_id", "group_builder_id", "history_builder_id", "target_builder_id", "barrier_policy_id", "runtime_id", "repository_commit", "repository_tree"):
        if not _text(value.get(field)):
            errors.append(f"environment.{field} is required")
    errors.extend(_contains_forbidden(value))
    if isinstance(value.get("environment_sha256"), str):
        body = dict(value)
        body.pop("environment_sha256", None)
        if value["environment_sha256"] != _sha_json(body):
            errors.append("environment.environment_sha256 does not match content")
    return sorted(set(errors))


def build_prediction_attck_environment(**values: Any) -> dict[str, Any]:
    body = {"schema_version": ENVIRONMENT_SCHEMA_VERSION, **values}
    body.setdefault("target_contract_id", TARGET_CONTRACT_ID)
    body.setdefault(
        "environment_id",
        stable_id("predenv", {key: value for key, value in body.items() if key != "environment_id"}),
    )
    errors = validate_prediction_attck_environment({**body, "environment_sha256": "0" * 64})
    errors = [error for error in errors if "environment_sha256" not in error]
    if errors:
        raise PredictionAttckLabelError("invalid environment inputs: " + "; ".join(errors))
    body["environment_sha256"] = _sha_json(body)
    errors = validate_prediction_attck_environment(body)
    if errors:
        raise PredictionAttckLabelError("constructed environment is invalid: " + "; ".join(errors))
    return body


def support_policy_from_document(policy: Mapping[str, Any]) -> dict[str, Any]:
    errors = validate_prediction_attck_label_policy(policy)
    if errors:
        raise PredictionAttckLabelError("invalid policy: " + "; ".join(errors))
    return deepcopy(dict(policy["support_policy"]))
