"""Versioned legacy-parity admission for prediction-only ATT&CK labels.

This module is a narrow extension of :mod:`prediction_attck_label`.  The v1
contracts and implementation remain immutable.  V2 adds one admission class
for an explicitly allowlisted, historically reviewed rule when the current
reviewed regex is proven to match the effective executable of a simple literal
invocation.  The result remains a non-canonical weak label for submitted
command syntax; it is not proof of execution, success, intent, or observed
ATT&CK behavior.
"""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping, Sequence

from production.prediction import prediction_attck_label as v1
from production.utils.serialization import stable_id, stable_json


POLICY_SCHEMA_VERSION = "prediction_attck_label_policy.v2"
RULE_BINDINGS_SCHEMA_VERSION = "prediction_attck_legacy_literal_bindings.v2"
ENVIRONMENT_SCHEMA_VERSION = "prediction_attck_label_environment.v2"
KNOWN_ANSWERS_SCHEMA_VERSION = "prediction_attck_label_known_answers.v2"
FREEZE_RECEIPT_SCHEMA_VERSION = "prediction_attck_label_freeze_receipt.v2"
ADMISSION_CLASS = "reviewed_legacy_literal_invocation"
STANDARD_ADMISSION_CLASS = "reviewed_standard_context"
PREDICATE_ID = "effective_executable_current_regex.v1"
LABEL_MEANING = (
    "deterministic classifier-derived weak label for submitted command syntax"
)
LEGACY_REVIEW_COMMIT = "9876c52399f1220dacaeb51e70f1653ad12798cf"
LEGACY_REVIEW_PATH = "honeypot-analysis/configs/classification_rules.trusted.json"
LEGACY_REVIEW_SHA256 = (
    "33f332946c53578f2e609a3a039dda712355b9e209721bcc073c61a623d6342b"
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EXECUTABLE = re.compile(r"^[a-z0-9_.+-]+$")
_RULE_SOURCES = frozenset({"rule", "both", "rule_securebert_disagreement"})


class PredictionAttckLabelV2Error(ValueError):
    """Raised when the v2 policy or literal-invocation proof fails."""


def _text(value: Any) -> str:
    return str(value or "").strip()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha_json(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def _unexpected(value: Mapping[str, Any], allowed: set[str], path: str) -> list[str]:
    return [
        f"{path}.{key} is not defined by the contract"
        for key in sorted(value)
        if key not in allowed
    ]


def _legacy_rule_ids(policy: Mapping[str, Any]) -> list[str]:
    admission = policy.get("admission_class")
    if not isinstance(admission, Mapping):
        return []
    values = admission.get("rule_ids")
    if not isinstance(values, list):
        return []
    return [_text(value) for value in values]


def _predecessor_runtime_policy(policy: Mapping[str, Any]) -> dict[str, Any]:
    predecessor = policy.get("predecessor_policy")
    if not isinstance(predecessor, Mapping):
        raise PredictionAttckLabelV2Error("loaded v2 predecessor policy is required")
    runtime = deepcopy(dict(predecessor))
    runtime["policy_id"] = _text(policy.get("policy_id"))
    runtime["policy_sha256"] = _text(policy.get("policy_sha256"))
    errors = v1.validate_prediction_attck_label_policy(runtime)
    if errors:
        raise PredictionAttckLabelV2Error(
            "v2 predecessor runtime view is invalid: " + "; ".join(errors)
        )
    return runtime


def validate_prediction_attck_label_policy_v2(
    document: Any,
    *,
    classification_policy: Mapping[str, Any] | None = None,
) -> list[str]:
    """Validate the v2 delta and, when loaded, its exact predecessor/bindings."""

    if not isinstance(document, Mapping):
        return ["prediction label v2 policy must be an object"]
    allowed = {
        "schema_version",
        "policy_id",
        "authority",
        "predecessor_policy_path",
        "predecessor_policy_sha256",
        "classification_rule_policy_path",
        "classification_rule_policy_sha256",
        "legacy_review_source",
        "target_contract_id",
        "label_schema_version",
        "group_schema_version",
        "history_schema_version",
        "maximum_history_groups",
        "label_semantics",
        "admission_class",
        "legacy_literal_bindings_schema_version",
        "legacy_literal_bindings_path",
        "legacy_literal_bindings_sha256",
        "barrier_invariants",
        "support_policy",
        "privacy",
        "training_authorization",
        "policy_sha256",
        "predecessor_policy",
        "legacy_literal_invocation_bindings",
    }
    errors = _unexpected(document, allowed, "policy")
    if document.get("schema_version") != POLICY_SCHEMA_VERSION:
        errors.append("policy.schema_version is invalid")
    if document.get("authority") != v1.AUTHORITY:
        errors.append("policy.authority is invalid")
    if not _text(document.get("policy_id")):
        errors.append("policy.policy_id is required")
    exact = {
        "target_contract_id": v1.TARGET_CONTRACT_ID,
        "label_schema_version": v1.LABEL_SCHEMA_VERSION,
        "group_schema_version": v1.GROUP_SCHEMA_VERSION,
        "history_schema_version": v1.HISTORY_SCHEMA_VERSION,
        "maximum_history_groups": v1.MAXIMUM_HISTORY_GROUPS,
        "legacy_literal_bindings_schema_version": RULE_BINDINGS_SCHEMA_VERSION,
    }
    for field, expected in exact.items():
        if document.get(field) != expected:
            errors.append(f"policy.{field} is invalid")
    for field in (
        "predecessor_policy_sha256",
        "classification_rule_policy_sha256",
        "legacy_literal_bindings_sha256",
    ):
        if not _SHA256.fullmatch(_text(document.get(field)).lower()):
            errors.append(f"policy.{field} must be a SHA-256 digest")
    for field in (
        "predecessor_policy_path",
        "classification_rule_policy_path",
        "legacy_literal_bindings_path",
    ):
        path = Path(_text(document.get(field)))
        if not _text(document.get(field)) or path.is_absolute() or ".." in path.parts:
            errors.append(f"policy.{field} is unsafe")

    semantics = document.get("label_semantics")
    expected_semantics = {
        "meaning": LABEL_MEANING,
        "canonical_observed_attck_behavior": False,
        "proven_execution": False,
        "successful_execution": False,
        "attacker_intent": False,
    }
    if semantics != expected_semantics:
        errors.append("policy.label_semantics is invalid")

    review = document.get("legacy_review_source")
    expected_review = {
        "repository_commit": LEGACY_REVIEW_COMMIT,
        "path": LEGACY_REVIEW_PATH,
        "sha256": LEGACY_REVIEW_SHA256,
        "reviewed_rule_count": 84,
        "unreviewed_rule_count": 27,
        "reviewed_only": True,
        "unreviewed_rules_restored": False,
    }
    if review != expected_review:
        errors.append("policy.legacy_review_source is invalid")

    admission = document.get("admission_class")
    required_admission_keys = {
        "class_id",
        "semantics",
        "predicate_id",
        "rule_ids",
        "requires_historically_reviewed_rule",
        "requires_current_pattern",
        "requires_current_exact_tactic_technique_binding",
        "requires_effective_executable_binding",
        "requires_durable_order",
        "parser_abstention_override_only",
    }
    if not isinstance(admission, Mapping) or set(admission) != required_admission_keys:
        errors.append("policy.admission_class shape is invalid")
    else:
        expected_values = {
            "class_id": ADMISSION_CLASS,
            "semantics": (
                "reviewed historical rule with current binding and literal effective executable"
            ),
            "predicate_id": PREDICATE_ID,
            "requires_historically_reviewed_rule": True,
            "requires_current_pattern": True,
            "requires_current_exact_tactic_technique_binding": True,
            "requires_effective_executable_binding": True,
            "requires_durable_order": True,
            "parser_abstention_override_only": True,
        }
        for field, expected in expected_values.items():
            if admission.get(field) != expected:
                errors.append(f"policy.admission_class.{field} is invalid")
        ids = _legacy_rule_ids(document)
        if not ids or ids != sorted(set(ids)):
            errors.append("policy.admission_class.rule_ids must be sorted and unique")

    expected_barriers = {
        "conditional_fragments": "barrier",
        "model_only": "excluded",
        "unreviewed_rule": "excluded",
        "malformed_or_quarantined": "barrier",
        "conflicting_duplicate": "barrier",
        "unresolved_or_dynamic": "barrier",
        "unsupported_or_unorderable_composition": "barrier",
        "no_transition_across_barrier": True,
    }
    if document.get("barrier_invariants") != expected_barriers:
        errors.append("policy.barrier_invariants are invalid")

    predecessor = document.get("predecessor_policy")
    if predecessor is not None:
        if not isinstance(predecessor, Mapping):
            errors.append("policy.predecessor_policy is invalid")
        else:
            predecessor_errors = v1.validate_prediction_attck_label_policy(
                predecessor, classification_policy=classification_policy
            )
            errors.extend(
                f"predecessor: {error}" for error in predecessor_errors
            )
    bindings = document.get("legacy_literal_invocation_bindings")
    if bindings is not None:
        ids = set(_legacy_rule_ids(document))
        if not isinstance(bindings, Mapping) or set(bindings) != ids:
            errors.append("policy legacy literal bindings do not exactly cover the allowlist")
        else:
            current_rules: dict[str, Mapping[str, Any]] = {}
            if isinstance(classification_policy, Mapping):
                body = classification_policy.get("policy", classification_policy)
                rules = body.get("rules") if isinstance(body, Mapping) else None
                if isinstance(rules, list):
                    current_rules = {
                        _text(rule.get("rule_id")): rule
                        for rule in rules
                        if isinstance(rule, Mapping)
                    }
            for rule_id, spec in bindings.items():
                required = {
                    "evidence_type",
                    "technique",
                    "tactic",
                    "current_pattern",
                    "current_pattern_sha256",
                    "predicate_id",
                    "effective_executables",
                    "allows_literal_path_executable",
                    "historically_reviewed",
                }
                if not isinstance(spec, Mapping) or set(spec) != required:
                    errors.append(f"legacy literal binding is invalid: {rule_id}")
                    continue
                base = (
                    predecessor.get("rule_bindings", {}).get(rule_id)
                    if isinstance(predecessor, Mapping)
                    else None
                )
                if {
                    key: spec.get(key) for key in ("evidence_type", "technique", "tactic")
                } != base:
                    errors.append(f"legacy literal mapping differs from predecessor: {rule_id}")
                if spec.get("evidence_type") != "command_regex":
                    errors.append(f"legacy literal rule is not a regex: {rule_id}")
                if spec.get("predicate_id") != PREDICATE_ID:
                    errors.append(f"legacy literal predicate differs: {rule_id}")
                executables = spec.get("effective_executables")
                if (
                    not isinstance(executables, list)
                    or not executables
                    or executables != sorted(set(executables))
                    or not all(_EXECUTABLE.fullmatch(_text(item)) for item in executables)
                ):
                    errors.append(f"legacy literal executable allowlist is invalid: {rule_id}")
                if not isinstance(spec.get("allows_literal_path_executable"), bool):
                    errors.append(f"legacy literal path flag is invalid: {rule_id}")
                if spec.get("historically_reviewed") is not True:
                    errors.append(f"legacy literal historical review is invalid: {rule_id}")
                pattern = _text(spec.get("current_pattern"))
                if _sha256_bytes(pattern.encode("utf-8")) != spec.get("current_pattern_sha256"):
                    errors.append(f"legacy literal pattern hash is invalid: {rule_id}")
                try:
                    re.compile(pattern, re.IGNORECASE)
                except re.error:
                    errors.append(f"legacy literal pattern does not compile: {rule_id}")
                current = current_rules.get(rule_id)
                if current_rules:
                    if not isinstance(current, Mapping):
                        errors.append(f"legacy literal rule is absent from current policy: {rule_id}")
                    else:
                        if current.get("enabled") is False or (current.get("provenance") or {}).get("reviewed") is not True:
                            errors.append(f"legacy literal rule is not currently reviewed: {rule_id}")
                        if current.get("pattern") != pattern:
                            errors.append(f"legacy literal pattern differs from current policy: {rule_id}")
                        expected = {
                            "evidence_type": _text(current.get("evidence_type")),
                            "technique": _text(current.get("ttp")).upper(),
                            "tactic": _text(current.get("reviewed_tactic")).lower(),
                        }
                        if {key: spec.get(key) for key in expected} != expected:
                            errors.append(f"legacy literal current mapping differs: {rule_id}")

    support = document.get("support_policy")
    predecessor_support = (
        predecessor.get("support_policy") if isinstance(predecessor, Mapping) else None
    )
    if predecessor is not None and support != predecessor_support:
        errors.append("policy.support_policy must remain identical to v1")
    privacy = document.get("privacy")
    predecessor_privacy = predecessor.get("privacy") if isinstance(predecessor, Mapping) else None
    if predecessor is not None and privacy != predecessor_privacy:
        errors.append("policy.privacy must remain identical to v1")
    authorization = document.get("training_authorization")
    predecessor_auth = (
        predecessor.get("training_authorization")
        if isinstance(predecessor, Mapping)
        else None
    )
    if predecessor is not None and authorization != predecessor_auth:
        errors.append("policy.training_authorization must remain identical to v1")
    return sorted(set(errors))


def load_prediction_attck_label_policy_v2(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    try:
        raw = path.read_bytes()
        document = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PredictionAttckLabelV2Error(f"cannot load prediction label v2 policy: {exc}") from exc
    errors = validate_prediction_attck_label_policy_v2(document)
    if errors:
        raise PredictionAttckLabelV2Error("; ".join(errors))
    result = dict(document)
    result["policy_sha256"] = _sha256_bytes(raw)
    predecessor_path = path.parent / _text(result.get("predecessor_policy_path"))
    if _sha256_bytes(predecessor_path.read_bytes()) != result.get("predecessor_policy_sha256"):
        raise PredictionAttckLabelV2Error("v2 predecessor policy bytes do not match")
    result["predecessor_policy"] = v1.load_prediction_attck_label_policy(
        predecessor_path
    )
    binding_path = path.parent / _text(result.get("legacy_literal_bindings_path"))
    try:
        binding_bytes = binding_path.read_bytes()
        binding_document = json.loads(binding_bytes.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PredictionAttckLabelV2Error(f"cannot load v2 legacy literal bindings: {exc}") from exc
    if _sha256_bytes(binding_bytes) != result.get("legacy_literal_bindings_sha256"):
        raise PredictionAttckLabelV2Error("v2 legacy literal binding bytes do not match")
    if not isinstance(binding_document, Mapping):
        raise PredictionAttckLabelV2Error("v2 legacy literal bindings must be an object")
    if binding_document.get("schema_version") != RULE_BINDINGS_SCHEMA_VERSION:
        raise PredictionAttckLabelV2Error("v2 legacy literal binding schema is invalid")
    if binding_document.get("policy_id") != result.get("policy_id"):
        raise PredictionAttckLabelV2Error("v2 legacy literal binding policy identity differs")
    if binding_document.get("classification_rule_policy_sha256") != result.get("classification_rule_policy_sha256"):
        raise PredictionAttckLabelV2Error("v2 legacy literal classification binding differs")
    if binding_document.get("legacy_review_source_sha256") != LEGACY_REVIEW_SHA256:
        raise PredictionAttckLabelV2Error("v2 legacy review source binding differs")
    result["legacy_literal_invocation_bindings"] = dict(
        binding_document.get("bindings") or {}
    )
    errors = validate_prediction_attck_label_policy_v2(result)
    if errors:
        raise PredictionAttckLabelV2Error(
            "loaded prediction label v2 policy is invalid: " + "; ".join(errors)
        )
    return result


def _non_parser_barrier(candidate: Mapping[str, Any]) -> str | None:
    if candidate.get("missing_durable_order") is True or candidate.get("event_order") is None:
        return "missing_durable_order"
    if candidate.get("conflicting_duplicate") is True:
        return "conflicting_duplicate"
    if candidate.get("malformed") is True:
        return "malformed_evidence"
    if candidate.get("quarantined") is True:
        return "quarantined_evidence"
    if candidate.get("unresolved") is True or candidate.get("dynamic_value") is True:
        return "unresolved_value"
    if candidate.get("unsupported_composition") is True:
        return "unsupported_composition"
    if _text(candidate.get("operator_before")) in {"&&", "||"} or candidate.get("conditional_unproven") is True:
        return "conditional_execution_unproven"
    if candidate.get("ambiguous_tactic") is True or candidate.get("ambiguous_technique") is True:
        return "ambiguous_tactic_mapping"
    return None


def _literal_shell_tokens(command: str) -> list[tuple[str, int, int]] | None:
    if not command or any(char in command for char in ("\x00", "\n", "\r", "`", "$")):
        return None
    tokens: list[tuple[str, int, int]] = []
    value: list[str] = []
    start: int | None = None
    quote = ""
    escaped = False
    for index, char in enumerate(command):
        if escaped:
            value.append(char)
            escaped = False
            continue
        if char == "\\" and quote != "'":
            if start is None:
                start = index
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = ""
            else:
                value.append(char)
            continue
        if char in {"'", '"'}:
            if start is None:
                start = index
            quote = char
            continue
        if char.isspace():
            if start is not None:
                tokens.append(("".join(value), start, index))
                value = []
                start = None
            continue
        if char in ";|&<>*?[":
            return None
        if start is None:
            start = index
        value.append(char)
    if escaped or quote:
        return None
    if start is not None:
        tokens.append(("".join(value), start, len(command)))
    return tokens or None


def _effective_executable(
    tokens: Sequence[tuple[str, int, int]],
) -> tuple[str, int, int] | None:
    index = 0
    assignment = re.compile(
        r"[A-Za-z_][A-Za-z0-9_]*=[A-Za-z0-9_./:+,@%-]*"
    )
    while index < len(tokens) and assignment.fullmatch(tokens[index][0]):
        index += 1
    if index >= len(tokens):
        return None
    executable, start, end = tokens[index]
    if executable == "env":
        index += 1
        while index < len(tokens) and (
            tokens[index][0].startswith("-")
            or assignment.fullmatch(tokens[index][0])
        ):
            index += 1
        if index >= len(tokens):
            return None
        executable, start, end = tokens[index]
    elif executable == "command":
        index += 1
        while index < len(tokens) and tokens[index][0].startswith("-"):
            index += 1
        if index >= len(tokens):
            return None
        executable, start, end = tokens[index]
    return executable, start, end


def reviewed_legacy_literal_invocation(
    candidate: Mapping[str, Any], policy: Mapping[str, Any]
) -> bool:
    """Return true only for the frozen v2 literal effective-executable proof."""

    if policy.get("schema_version") != POLICY_SCHEMA_VERSION:
        return False
    if _non_parser_barrier(candidate):
        return False
    if _text(candidate.get("source")).lower() not in _RULE_SOURCES:
        return False
    if candidate.get("rule_reviewed") is not True and candidate.get("reviewed") is not True:
        return False
    rule_id = _text(candidate.get("rule_id"))
    if rule_id not in set(_legacy_rule_ids(policy)):
        return False
    spec = (policy.get("legacy_literal_invocation_bindings") or {}).get(rule_id)
    if not isinstance(spec, Mapping) or spec.get("predicate_id") != PREDICATE_ID:
        return False
    if _text(candidate.get("evidence_type")) != "command_regex":
        return False
    command = _text(candidate.get("subcommand") or candidate.get("command"))
    tokens = _literal_shell_tokens(command)
    if not tokens:
        return False
    effective = _effective_executable(tokens)
    if effective is None:
        return False
    executable, start, end = effective
    basename = executable.rstrip("/").rsplit("/", 1)[-1].lower()
    literal_path = spec.get("allows_literal_path_executable") is True and (
        executable.startswith("./")
        or executable.startswith("/tmp/")
        or executable.startswith("/var/tmp/")
        or executable.startswith("/dev/shm/")
    )
    if basename not in set(spec.get("effective_executables") or []) and not literal_path:
        return False
    pattern = _text(spec.get("current_pattern"))
    if _sha256_bytes(pattern.encode("utf-8")) != spec.get("current_pattern_sha256"):
        return False
    try:
        return any(
            match.start() < end and match.end() > start
            for match in re.finditer(pattern, command, re.IGNORECASE)
        )
    except re.error:
        return False


def _inert_literal_match(candidate: Mapping[str, Any], policy: Mapping[str, Any]) -> bool:
    """Identify a reviewed pattern appearing only outside the executable span."""

    rule_id = _text(candidate.get("rule_id"))
    spec = (policy.get("legacy_literal_invocation_bindings") or {}).get(rule_id)
    if not isinstance(spec, Mapping):
        return False
    command = _text(candidate.get("subcommand") or candidate.get("command"))
    tokens = _literal_shell_tokens(command)
    effective = _effective_executable(tokens or [])
    if effective is None:
        return False
    _executable, start, end = effective
    try:
        matches = list(
            re.finditer(_text(spec.get("current_pattern")), command, re.IGNORECASE)
        )
    except re.error:
        return False
    return bool(matches) and not any(
        match.start() < end and match.end() > start for match in matches
    )


def _rewrite_eligible_result(
    result: Mapping[str, Any], admission_class: str
) -> dict[str, Any]:
    rewritten = deepcopy(dict(result))
    label = dict(rewritten["label"])
    label["eligibility_reason"] = admission_class
    audit = dict(label.get("audit_metadata") or {})
    audit["admission_class"] = admission_class
    label["audit_metadata"] = audit
    label.pop("label_id", None)
    label["label_id"] = stable_id("predlabel", label)
    errors = v1.validate_prediction_label(label)
    if errors:
        raise PredictionAttckLabelV2Error(
            "rewritten v2 label is invalid: " + "; ".join(errors)
        )
    rewritten["label"] = label
    return rewritten


def evaluate_prediction_candidate_v2(
    candidate: Mapping[str, Any],
    *,
    policy: Mapping[str, Any],
    sanitizer_policy_id: str,
    pseudonymization_policy_id: str,
    parser_identity: str,
    splitter_identity: str,
    labeler_identity: str,
) -> dict[str, Any]:
    errors = validate_prediction_attck_label_policy_v2(policy)
    if errors:
        raise PredictionAttckLabelV2Error("invalid v2 policy: " + "; ".join(errors))
    runtime_policy = _predecessor_runtime_policy(policy)
    barrier = v1._candidate_barrier_reason(candidate)
    admission_class = STANDARD_ADMISSION_CLASS
    effective_candidate = dict(candidate)
    if barrier == "parser_abstention":
        higher = _non_parser_barrier(candidate)
        if higher:
            return {
                "status": "barrier",
                "authority": v1.AUTHORITY,
                "reason_code": higher,
                "audit": v1._minimal_audit_metadata(candidate),
            }
        if reviewed_legacy_literal_invocation(candidate, policy):
            admission_class = ADMISSION_CLASS
            effective_candidate["parser_status"] = "parsed"
            effective_candidate["parser_abstention"] = False
            effective_candidate["authority_decision"] = {}
            effective_candidate["prediction_context"] = {
                "reviewed": True,
                "class": "reviewed_literal_command_pattern",
                "inert_text_match": False,
            }
        elif _inert_literal_match(candidate, policy):
            return {
                "status": "excluded",
                "authority": v1.AUTHORITY,
                "reason_code": "inert_lexical_match",
                "audit": v1._minimal_audit_metadata(candidate),
            }
    result = v1.evaluate_prediction_candidate(
        effective_candidate,
        policy=runtime_policy,
        sanitizer_policy_id=sanitizer_policy_id,
        pseudonymization_policy_id=pseudonymization_policy_id,
        parser_identity=parser_identity,
        splitter_identity=splitter_identity,
        labeler_identity=labeler_identity,
    )
    if result.get("status") == "eligible":
        return _rewrite_eligible_result(result, admission_class)
    return result


def build_next_prediction_label_examples_v2(
    session: Mapping[str, Any], *, policy: Mapping[str, Any]
) -> list[dict[str, Any]]:
    """Use unchanged v1 target semantics with the v2 policy identity."""

    prepared = deepcopy(dict(session))
    prepared["policy"] = _predecessor_runtime_policy(policy)
    return v1.build_next_prediction_label_examples(prepared)


def validate_prediction_attck_environment_v2(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return ["prediction environment v2 must be an object"]
    extra = {
        "base_contract_implementation_sha256",
        "v2_policy_implementation_sha256",
        "v2_admission_predicate_sha256",
    }
    allowed = {
        "schema_version", "environment_id", "policy_id", "policy_sha256",
        "target_contract_id", "source_corpus_membership_id",
        "source_corpus_membership_sha256", "classification_rule_policy_id",
        "classification_rule_policy_sha256", "attack_mapping_id",
        "attack_mapping_sha256", "parser_id", "parser_sha256", "splitter_id",
        "splitter_sha256", "sanitizer_id", "sanitizer_sha256",
        "pseudonymization_id", "pseudonymization_sha256", "group_builder_id",
        "group_builder_sha256", "history_builder_id", "history_builder_sha256",
        "target_builder_id", "target_builder_sha256", "barrier_policy_id",
        "barrier_policy_sha256", "runtime_id", "runtime_sha256",
        "repository_commit", "repository_tree", "dependency_identity_sha256",
        "environment_sha256", *extra,
    }
    errors = _unexpected(value, allowed, "environment")
    if value.get("schema_version") != ENVIRONMENT_SCHEMA_VERSION:
        errors.append("environment.schema_version is invalid")
    if value.get("target_contract_id") != v1.TARGET_CONTRACT_ID:
        errors.append("environment.target_contract_id is invalid")
    for field in sorted(field for field in allowed if field.endswith("_sha256")):
        if not _SHA256.fullmatch(_text(value.get(field)).lower()):
            errors.append(f"environment.{field} must be a SHA-256 digest")
    for field in sorted(allowed - {field for field in allowed if field.endswith("_sha256")}):
        if field == "schema_version":
            continue
        if not _text(value.get(field)):
            errors.append(f"environment.{field} is required")
    if isinstance(value.get("environment_sha256"), str):
        body = dict(value)
        body.pop("environment_sha256", None)
        if value["environment_sha256"] != _sha_json(body):
            errors.append("environment.environment_sha256 does not match content")
    if isinstance(value.get("environment_id"), str):
        body = dict(value)
        body.pop("environment_id", None)
        body.pop("environment_sha256", None)
        if value["environment_id"] != stable_id("predenv", body):
            errors.append("environment.environment_id does not match content")
    return sorted(set(errors))


def build_prediction_attck_environment_v2(**values: Any) -> dict[str, Any]:
    body = {"schema_version": ENVIRONMENT_SCHEMA_VERSION, **values}
    body.setdefault("target_contract_id", v1.TARGET_CONTRACT_ID)
    identity_body = dict(body)
    identity_body.pop("environment_id", None)
    identity_body.pop("environment_sha256", None)
    body["environment_id"] = stable_id("predenv", identity_body)
    hash_body = dict(body)
    hash_body.pop("environment_sha256", None)
    body["environment_sha256"] = _sha_json(hash_body)
    errors = validate_prediction_attck_environment_v2(body)
    if errors:
        raise PredictionAttckLabelV2Error(
            "constructed v2 environment is invalid: " + "; ".join(errors)
        )
    return body
