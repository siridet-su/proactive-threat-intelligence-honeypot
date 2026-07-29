"""Strict loading and validation for the shadow semantic vocabulary."""

from __future__ import annotations

import hashlib
import json
import posixpath
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Iterable, List


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_VOCABULARY_PATH = (
    PROJECT_ROOT / "configs" / "typed_semantic_vocabulary.v1.json"
)
POLICY_SCHEMA = "typed_semantic_vocabulary_policy.v1"
SHA256_LENGTH = 64

_ROOT_KEYS = {
    "schema_version",
    "policy_id",
    "version",
    "semantic_extractor_version",
    "authority",
    "review",
    "contract",
    "sensitive_path_policy",
    "operations",
    "literal_action_map",
    "entity_role_types",
    "vocabulary",
    "limits",
    "activation",
}
_AUTHORITY = {
    "mode": "family_scoped_policy_input",
    "may_select_findings": True,
    "may_select_hypotheses": False,
    "may_select_guidance": True,
    "may_authorize_actions": False,
}
_CONTRACT_KEYS = {
    "fact_set_schema",
    "fact_schema",
    "relationship_schema",
    "chain_schema",
    "shadow_result_schema",
    "shadow_diff_schema",
}
_SENSITIVE_PATH_POLICY_KEYS = {
    "schema_version",
    "match_scope",
    "exact_absolute_paths",
    "suffix_path_segments",
}
_VOCABULARY_KEYS = {
    "operation_families",
    "effects",
    "proof_scopes",
    "effect_statuses",
    "outcome_statuses",
    "outcome_scopes",
    "parse_statuses",
    "abstention_reasons",
    "entity_types",
    "entity_uncertainty_reasons",
    "entity_roles",
    "path_resolution_statuses",
    "working_directory_statuses",
    "directory_change_statuses",
    "relationship_types",
    "relationship_statuses",
    "relationship_bases",
    "chain_statuses",
    "evidence_reference_types",
    "evidence_types",
    "attck_mapping_scopes",
}
_LIMIT_KEYS = {
    "max_facts",
    "max_entities",
    "max_relationships",
    "max_chains",
    "max_command_length",
    "max_total_command_bytes",
}
_HARD_LIMITS = {
    "max_facts": 10_000,
    "max_entities": 40_000,
    "max_relationships": 40_000,
    "max_chains": 10_000,
    "max_command_length": 65_536,
    "max_total_command_bytes": 16 * 1024 * 1024,
}
_ACTIVATION_REQUIREMENT_KEYS = {
    "required_operation_types",
    "allowed_operation_types",
    "operation_match_mode",
    "required_entity_role",
    "required_entity_type",
    "entity_match_mode",
    "required_outcome_status",
    "required_outcome_scope",
    "required_effect_status",
    "required_parse_status",
    "allowed_path_resolution_statuses",
    "require_same_entity",
    "require_linkable_identity",
    "require_empty_abstention_reasons",
}


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _exact_keys(
    value: Any,
    expected: Iterable[str],
    label: str,
    errors: List[str],
) -> bool:
    if not isinstance(value, dict):
        errors.append(f"{label} must be an object")
        return False
    actual = set(value)
    expected_set = set(expected)
    if actual != expected_set:
        errors.append(
            f"{label} keys must be exactly {sorted(expected_set)}; "
            f"got {sorted(actual)}"
        )
        return False
    return True


def _string_list(
    value: Any,
    label: str,
    errors: List[str],
) -> List[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item.strip() for item in value)
    ):
        errors.append(f"{label} must be a non-empty list of strings")
        return []
    cleaned = [item.strip() for item in value]
    if len(cleaned) != len(set(cleaned)):
        errors.append(f"{label} must not contain duplicates")
    return cleaned


def validate_typed_semantic_vocabulary(value: Any) -> List[str]:
    """Validate the complete closed vocabulary without permissive defaults."""

    errors: List[str] = []
    if not _exact_keys(value, _ROOT_KEYS, "policy", errors):
        if not isinstance(value, dict):
            return errors
    if value.get("schema_version") != POLICY_SCHEMA:
        errors.append(f"schema_version must be {POLICY_SCHEMA}")
    for key in ("policy_id", "version", "semantic_extractor_version"):
        if not _clean(value.get(key)):
            errors.append(f"{key} must be a non-empty string")
    if value.get("authority") != _AUTHORITY:
        errors.append(
            "authority must preserve the exact family-scoped boundary"
        )

    review = value.get("review")
    if _exact_keys(
        review,
        {"method", "reviewed", "last_reviewed", "scope"},
        "review",
        errors,
    ):
        if review.get("reviewed") is not True:
            errors.append("review.reviewed must be true")
        for key in ("method", "last_reviewed", "scope"):
            if not _clean(review.get(key)):
                errors.append(f"review.{key} must be a non-empty string")

    contract = value.get("contract")
    if _exact_keys(contract, _CONTRACT_KEYS, "contract", errors):
        for key in _CONTRACT_KEYS:
            if not _clean(contract.get(key)):
                errors.append(f"contract.{key} must be a non-empty string")

    sensitive_paths = value.get("sensitive_path_policy")
    if _exact_keys(
        sensitive_paths,
        _SENSITIVE_PATH_POLICY_KEYS,
        "sensitive_path_policy",
        errors,
    ):
        if (
            sensitive_paths.get("schema_version")
            != "typed_sensitive_path_policy.v1"
        ):
            errors.append(
                "sensitive_path_policy.schema_version is invalid"
            )
        if (
            sensitive_paths.get("match_scope")
            != "complete_parsed_path_operand"
        ):
            errors.append(
                "sensitive_path_policy.match_scope must require complete "
                "parsed path operands"
            )
        exact_paths = _string_list(
            sensitive_paths.get("exact_absolute_paths"),
            "sensitive_path_policy.exact_absolute_paths",
            errors,
        )
        for path in exact_paths:
            if (
                not path.startswith("/")
                or path != posixpath.normpath(path)
                or path != path.strip()
            ):
                errors.append(
                    "sensitive_path_policy exact paths must be canonical "
                    "absolute paths"
                )
        suffixes = sensitive_paths.get("suffix_path_segments")
        if not isinstance(suffixes, list) or not suffixes:
            errors.append(
                "sensitive_path_policy.suffix_path_segments must be a "
                "non-empty list"
            )
        else:
            normalized_suffixes: List[tuple[str, ...]] = []
            for index, suffix in enumerate(suffixes):
                label = (
                    "sensitive_path_policy.suffix_path_segments"
                    f"[{index}]"
                )
                segments = _string_list(suffix, label, errors)
                if len(segments) < 2:
                    errors.append(f"{label} must contain at least two segments")
                if any(
                    segment in {".", ".."}
                    or "/" in segment
                    or segment != segment.strip()
                    for segment in segments
                ):
                    errors.append(
                        f"{label} contains an invalid path segment"
                    )
                normalized_suffixes.append(tuple(segments))
            if len(normalized_suffixes) != len(set(normalized_suffixes)):
                errors.append(
                    "sensitive_path_policy suffixes must not contain "
                    "duplicates"
                )

    vocabulary = value.get("vocabulary")
    lists: Dict[str, List[str]] = {}
    if _exact_keys(vocabulary, _VOCABULARY_KEYS, "vocabulary", errors):
        for key in _VOCABULARY_KEYS:
            lists[key] = _string_list(
                vocabulary.get(key),
                f"vocabulary.{key}",
                errors,
            )

    operations = value.get("operations")
    if not isinstance(operations, dict) or not operations:
        errors.append("operations must be a non-empty object")
        operations = {}
    operation_families = set(lists.get("operation_families") or [])
    effects = set(lists.get("effects") or [])
    for operation_type, definition in operations.items():
        if not _clean(operation_type):
            errors.append("operation names must be non-empty strings")
            continue
        if not _exact_keys(
            definition,
            {"family", "effect"},
            f"operations.{operation_type}",
            errors,
        ):
            continue
        if definition.get("family") not in operation_families:
            errors.append(
                f"operations.{operation_type}.family is outside the vocabulary"
            )
        if definition.get("effect") not in effects:
            errors.append(
                f"operations.{operation_type}.effect is outside the vocabulary"
            )
    if "unknown" not in operations:
        errors.append("operations must define unknown")

    literal_map = value.get("literal_action_map")
    if not isinstance(literal_map, dict) or not literal_map:
        errors.append("literal_action_map must be a non-empty object")
        literal_map = {}
    for literal, operation_type in literal_map.items():
        if not _clean(literal) or operation_type not in operations:
            errors.append(
                f"literal_action_map.{literal!s} must reference a known operation"
            )

    entity_role_types = value.get("entity_role_types")
    if not isinstance(entity_role_types, dict):
        errors.append("entity_role_types must be an object")
    else:
        entity_roles = set(lists.get("entity_roles") or [])
        entity_types = set(lists.get("entity_types") or [])
        if set(entity_role_types) != entity_roles:
            errors.append(
                "entity_role_types must cover every entity role exactly"
            )
        for role, entity_type in entity_role_types.items():
            if role not in entity_roles or entity_type not in entity_types:
                errors.append(
                    f"entity_role_types.{role} must reference a known type"
                )

    limits = value.get("limits")
    if _exact_keys(limits, _LIMIT_KEYS, "limits", errors):
        for key, hard_limit in _HARD_LIMITS.items():
            setting = limits.get(key)
            if type(setting) is not int or setting < 1 or setting > hard_limit:
                errors.append(
                    f"limits.{key} must be an integer from 1 to {hard_limit}"
                )

    activation = value.get("activation")
    if _exact_keys(
        activation,
        {"default", "family_states", "family_requirements"},
        "activation",
        errors,
    ):
        if activation.get("default") != "not_activated":
            errors.append("activation.default must be not_activated")
        family_states = activation.get("family_states")
        if not isinstance(family_states, dict):
            errors.append("activation.family_states must be an object")
        else:
            if set(family_states) != operation_families:
                errors.append(
                    "activation.family_states must cover every operation family"
                )
            for family, state in family_states.items():
                expected = {
                    "unknown": "not_eligible",
                    "sensitive_read": "activated",
                    "transfer": "activated",
                    "inspection": "activated",
                    "filesystem": "activated",
                }.get(family, "not_activated")
                if state != expected:
                    errors.append(
                        f"activation.family_states.{family} must be {expected}"
                    )
        requirements = activation.get("family_requirements")
        if not isinstance(requirements, dict):
            errors.append("activation.family_requirements must be an object")
        elif set(requirements) != {
            "sensitive_read",
            "transfer",
            "inspection",
            "filesystem",
        }:
            errors.append(
                "activation.family_requirements must contain only "
                "sensitive_read, transfer, inspection, and filesystem"
            )
        else:
            expected_requirements = {
                "sensitive_read": {
                    "required_operation_types": {
                        "file_read",
                        "credential_path_read",
                    },
                    "allowed_operation_types": {
                        "file_read",
                        "credential_path_read",
                    },
                    "operation_match_mode": "all_required",
                    "required_entity_role": "credential_paths",
                    "required_entity_type": "path",
                    "entity_match_mode": "shared_required",
                    "required_outcome_status": "reported_success",
                    "required_outcome_scope": "fragment",
                    "required_effect_status": "reported_completed",
                    "required_parse_status": "parsed",
                    "allowed_path_resolution_statuses": {
                        "recorded_resolved",
                        "context_resolved",
                    },
                    "require_same_entity": True,
                    "require_linkable_identity": True,
                    "require_empty_abstention_reasons": True,
                },
                "transfer": {
                    "required_operation_types": {"transfer_observed"},
                    "allowed_operation_types": {"transfer_observed"},
                    "operation_match_mode": "all_required",
                    "required_entity_role": "artifact_hashes",
                    "required_entity_type": "hash",
                    "entity_match_mode": "shared_required",
                    "required_outcome_status": "event_observed",
                    "required_outcome_scope": "direct_cowrie_event",
                    "required_effect_status": "event_observed",
                    "required_parse_status": "parsed",
                    "allowed_path_resolution_statuses": set(),
                    "require_same_entity": True,
                    "require_linkable_identity": True,
                    "require_empty_abstention_reasons": True,
                },
                "inspection": {
                    "required_operation_types": {
                        "host_uptime_inspection",
                        "filesystem_capacity_inspection",
                        "system_identity_inspection",
                        "account_identity_inspection",
                        "network_route_inspection",
                        "process_inspection",
                        "network_socket_inspection",
                        "account_database_inspection",
                        "filesystem_search",
                    },
                    "allowed_operation_types": {
                        "host_uptime_inspection",
                        "filesystem_capacity_inspection",
                        "system_identity_inspection",
                        "account_identity_inspection",
                        "network_route_inspection",
                        "process_inspection",
                        "network_socket_inspection",
                        "account_database_inspection",
                        "filesystem_search",
                    },
                    "operation_match_mode": "exactly_one_required",
                    "required_entity_role": None,
                    "required_entity_type": None,
                    "entity_match_mode": "referenced_if_present",
                    "required_outcome_status": "reported_success",
                    "required_outcome_scope": "fragment",
                    "required_effect_status": "reported_completed",
                    "required_parse_status": "parsed",
                    "allowed_path_resolution_statuses": {
                        "recorded_resolved",
                        "context_resolved",
                    },
                    "require_same_entity": False,
                    "require_linkable_identity": True,
                    "require_empty_abstention_reasons": True,
                },
                "filesystem": {
                    "required_operation_types": {
                        "file_write",
                        "file_append",
                        "file_modify",
                        "permission_modify",
                        "directory_create",
                        "file_move",
                        "file_delete",
                    },
                    "allowed_operation_types": {
                        "file_write",
                        "file_append",
                        "file_modify",
                        "permission_modify",
                        "directory_create",
                        "file_move",
                        "file_delete",
                        "file_read",
                        "literal_data_emission",
                    },
                    "operation_match_mode": "exactly_one_required",
                    "required_entity_role": None,
                    "required_entity_type": None,
                    "entity_match_mode": "referenced_required",
                    "required_outcome_status": "reported_success",
                    "required_outcome_scope": "fragment",
                    "required_effect_status": "reported_completed",
                    "required_parse_status": "parsed",
                    "allowed_path_resolution_statuses": {
                        "recorded_resolved",
                        "context_resolved",
                    },
                    "require_same_entity": False,
                    "require_linkable_identity": True,
                    "require_empty_abstention_reasons": True,
                },
            }
            for family, expected in expected_requirements.items():
                requirement = requirements[family]
                label = f"activation.family_requirements.{family}"
                if not _exact_keys(
                    requirement,
                    _ACTIVATION_REQUIREMENT_KEYS,
                    label,
                    errors,
                ):
                    continue
                required_operations = _string_list(
                    requirement.get("required_operation_types"),
                    f"{label}.required_operation_types",
                    errors,
                )
                allowed_operations = _string_list(
                    requirement.get("allowed_operation_types"),
                    f"{label}.allowed_operation_types",
                    errors,
                )
                if set(required_operations) != expected[
                    "required_operation_types"
                ]:
                    errors.append(
                        f"{family} has invalid required operations"
                    )
                if set(allowed_operations) != expected[
                    "allowed_operation_types"
                ]:
                    errors.append(
                        f"{family} has invalid allowed operations"
                    )
                for operation_type in required_operations:
                    if operation_type not in operations:
                        errors.append(
                            f"{family} references an unknown operation"
                        )
                for key in (
                    "operation_match_mode",
                    "required_entity_role",
                    "required_entity_type",
                    "entity_match_mode",
                    "required_outcome_status",
                    "required_outcome_scope",
                    "required_effect_status",
                    "required_parse_status",
                ):
                    if requirement.get(key) != expected[key]:
                        errors.append(
                            f"{family}.{key} must be {expected[key]}"
                        )
                path_statuses = requirement.get(
                    "allowed_path_resolution_statuses"
                )
                if (
                    not isinstance(path_statuses, list)
                    or any(
                        not isinstance(item, str) or not item.strip()
                        for item in path_statuses
                    )
                    or len(path_statuses) != len(set(path_statuses))
                ):
                    errors.append(
                        f"{label}.allowed_path_resolution_statuses must "
                        "be a unique list of strings"
                    )
                    path_statuses = []
                if set(path_statuses) != expected[
                    "allowed_path_resolution_statuses"
                ]:
                    errors.append(
                        f"{family} path resolution requirements are invalid"
                    )
                for key in (
                    "require_same_entity",
                    "require_linkable_identity",
                    "require_empty_abstention_reasons",
                ):
                    if requirement.get(key) is not expected[key]:
                        errors.append(
                            f"{family}.{key} must be {expected[key]}"
                        )
    return errors


def load_typed_semantic_vocabulary(path_text: str = "") -> Dict[str, Any]:
    """Load exact policy bytes and fail closed on any error."""

    path = (
        Path(path_text).expanduser()
        if _clean(path_text)
        else DEFAULT_VOCABULARY_PATH
    )
    try:
        source = path.resolve().relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        source = str(path.resolve())
    try:
        raw = path.read_bytes()
        document = json.loads(raw.decode("utf-8"))
        errors = validate_typed_semantic_vocabulary(document)
        return {
            "document": document if isinstance(document, dict) else {},
            "sha256": hashlib.sha256(raw).hexdigest(),
            "source": source,
            "status": "valid" if not errors else "invalid",
            "validation_errors": errors,
        }
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {
            "document": {},
            "sha256": "",
            "source": source,
            "status": "unavailable",
            "validation_errors": [
                f"typed semantic vocabulary load failed: {exc.__class__.__name__}"
            ],
        }


def vocabulary_summary(loaded: Dict[str, Any]) -> Dict[str, Any]:
    document = loaded.get("document") or {}
    return {
        "schema_version": _clean(document.get("schema_version")),
        "policy_id": _clean(document.get("policy_id")),
        "version": _clean(document.get("version")),
        "semantic_extractor_version": _clean(
            document.get("semantic_extractor_version")
        ),
        "sha256": _clean(loaded.get("sha256")).lower(),
        "source": _clean(loaded.get("source")),
        "status": _clean(loaded.get("status")),
        "validation_errors": deepcopy(loaded.get("validation_errors") or []),
    }
