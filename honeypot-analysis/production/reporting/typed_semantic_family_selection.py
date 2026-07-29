"""Strict family-scoped selection over ``typed_semantic_fact_set.v2``.

The selector does not generate findings, hypotheses, or guidance. It validates
one immutable fact set and returns the exact facts that satisfy the activated
family requirements. Threat and guidance evaluators invoke it independently.
"""

from __future__ import annotations

import hashlib
import re
from copy import deepcopy
from typing import Any, Dict, List

from production.policies.typed_semantic_vocabulary import (
    load_typed_semantic_vocabulary,
)
from production.reporting.typed_semantic_facts import (
    validate_typed_semantic_fact_set,
)
from production.utils.serialization import stable_json


SCHEMA_VERSION = "typed_semantic_family_selection.v1"
ACTIVATED_FAMILY = "sensitive_read"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SELECTION_KEYS = {
    "schema_version",
    "status",
    "family",
    "activation_state",
    "fact_set_sha256",
    "semantic_vocabulary_sha256",
    "matches",
    "abstentions",
    "selection_sha256",
}
_MATCH_KEYS = {
    "fact_id",
    "source_observation_ref",
    "supporting_evidence_refs",
    "operation_refs",
    "operation_types",
    "entity_ref",
    "entity_role",
    "entity_type",
    "entity_value",
    "path_identity_id",
    "path_resolution_status",
    "outcome_status",
    "outcome_scope",
    "effect_status",
    "proof_scopes",
}
_ABSTENTION_KEYS = {
    "fact_id",
    "source_observation_ref",
    "reasons",
}


class TypedSemanticFamilySelectionError(ValueError):
    """Raised when family selection cannot be proven from validated facts."""


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def _texts(values: Any) -> List[str]:
    output: List[str] = []
    for value in values or []:
        text = _clean(value)
        if text and text not in output:
            output.append(text)
    return output


def _candidate_fact(fact: Dict[str, Any]) -> bool:
    if any(
        operation.get("family") == ACTIVATED_FAMILY
        for operation in fact.get("operations") or []
        if isinstance(operation, dict)
    ):
        return True
    return bool(
        (fact.get("entities") or {}).get("credential_paths")
    )


def _match_or_reasons(
    fact: Dict[str, Any],
    requirement: Dict[str, Any],
) -> tuple[List[Dict[str, Any]], List[str]]:
    reasons: List[str] = []
    parse = fact.get("parse") or {}
    outcome = fact.get("outcome") or {}
    operations = [
        operation
        for operation in fact.get("operations") or []
        if isinstance(operation, dict)
    ]
    operation_types = {
        _clean(operation.get("operation_type"))
        for operation in operations
    }
    required = set(requirement["required_operation_types"])
    allowed = set(requirement["allowed_operation_types"])
    if parse.get("status") != requirement["required_parse_status"]:
        reasons.append("parse_status_not_eligible")
    if (
        requirement["require_empty_abstention_reasons"]
        and fact.get("abstention_reasons")
    ):
        reasons.append("fact_abstained")
    if not required.issubset(operation_types):
        reasons.append("required_operation_missing")
    if operation_types - allowed:
        reasons.append("additional_operation_not_activated")
    if outcome.get("status") != requirement["required_outcome_status"]:
        reasons.append("outcome_not_eligible")
    if outcome.get("scope") != requirement["required_outcome_scope"]:
        reasons.append("outcome_scope_not_eligible")

    required_operations = [
        operation
        for operation in operations
        if operation.get("operation_type") in required
    ]
    if any(
        operation.get("effect_status")
        != requirement["required_effect_status"]
        for operation in required_operations
    ):
        reasons.append("effect_status_not_eligible")

    role = requirement["required_entity_role"]
    entity_type = requirement["required_entity_type"]
    entities = [
        entity
        for entity in (fact.get("entities") or {}).get(role) or []
        if isinstance(entity, dict)
        and entity.get("entity_type") == entity_type
    ]
    path_by_entity = {
        _clean(item.get("entity_ref")): item
        for item in fact.get("path_resolutions") or []
        if isinstance(item, dict) and item.get("role") == role
    }
    operation_refs: Dict[str, set[str]] = {}
    for operation in required_operations:
        operation_refs.setdefault(
            _clean(operation.get("operation_type")),
            set(),
        ).update(_texts(operation.get("entity_refs") or []))
    eligible_entities: List[tuple[Dict[str, Any], Dict[str, Any]]] = []
    for entity in entities:
        entity_ref = _clean(entity.get("entity_id"))
        path = path_by_entity.get(entity_ref) or {}
        if (
            requirement["require_linkable_identity"]
            and (
                entity.get("linkable") is not True
                or entity.get("uncertain") is not False
            )
        ):
            continue
        if path.get("resolution_status") not in set(
            requirement["allowed_path_resolution_statuses"]
        ):
            continue
        if not _clean(path.get("path_identity_id")):
            continue
        if (
            requirement["require_same_entity"]
            and any(
                entity_ref not in operation_refs.get(operation_type, set())
                for operation_type in required
            )
        ):
            continue
        eligible_entities.append((entity, path))
    if not eligible_entities:
        reasons.append("resolved_shared_entity_missing")

    if reasons:
        return [], sorted(set(reasons))

    matches: List[Dict[str, Any]] = []
    operation_ids = sorted(
        _clean(operation.get("operation_id"))
        for operation in required_operations
        if _clean(operation.get("operation_id"))
    )
    proof_scopes = sorted(
        {
            _clean(operation.get("proof_scope"))
            for operation in required_operations
            if _clean(operation.get("proof_scope"))
        }
    )
    effect_status = requirement["required_effect_status"]
    authoritative_refs = sorted({
        _clean(reference.get("evidence_ref"))
        for reference in fact.get("evidence_references") or []
        if isinstance(reference, dict)
        and reference.get("reference_type") in {
            "source_observation",
            "direct_cowrie_event",
        }
        and _clean(reference.get("evidence_ref"))
    })
    for entity, path in eligible_entities:
        matches.append({
            "fact_id": _clean(fact.get("fact_id")),
            "source_observation_ref": _clean(
                fact.get("source_observation_ref")
            ),
            "supporting_evidence_refs": authoritative_refs,
            "operation_refs": operation_ids,
            "operation_types": sorted(required),
            "entity_ref": _clean(entity.get("entity_id")),
            "entity_role": role,
            "entity_type": entity_type,
            "entity_value": _clean(entity.get("normalized_value")),
            "path_identity_id": _clean(path.get("path_identity_id")),
            "path_resolution_status": _clean(
                path.get("resolution_status")
            ),
            "outcome_status": _clean(outcome.get("status")),
            "outcome_scope": _clean(outcome.get("scope")),
            "effect_status": effect_status,
            "proof_scopes": proof_scopes,
        })
    return matches, []


def _selection_payload(
    fact_set: Dict[str, Any],
    policy: Dict[str, Any],
    policy_sha256: str,
) -> Dict[str, Any]:
    activation = policy["activation"]
    state = activation["family_states"][ACTIVATED_FAMILY]
    requirement = activation["family_requirements"][ACTIVATED_FAMILY]
    matches: List[Dict[str, Any]] = []
    abstentions: List[Dict[str, Any]] = []
    for fact in fact_set.get("facts") or []:
        if not isinstance(fact, dict) or not _candidate_fact(fact):
            continue
        fact_matches, reasons = _match_or_reasons(fact, requirement)
        matches.extend(fact_matches)
        if reasons:
            abstentions.append({
                "fact_id": _clean(fact.get("fact_id")),
                "source_observation_ref": _clean(
                    fact.get("source_observation_ref")
                ),
                "reasons": reasons,
            })
    matches.sort(
        key=lambda item: (
            item["source_observation_ref"],
            item["entity_ref"],
            item["fact_id"],
        )
    )
    abstentions.sort(
        key=lambda item: (
            item["source_observation_ref"],
            item["fact_id"],
        )
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "matched" if matches else "abstained",
        "family": ACTIVATED_FAMILY,
        "activation_state": state,
        "fact_set_sha256": _clean(fact_set.get("fact_set_sha256")),
        "semantic_vocabulary_sha256": policy_sha256,
        "matches": matches,
        "abstentions": abstentions,
    }


def select_activated_semantic_family(
    fact_set: Dict[str, Any],
    *,
    family: str,
    vocabulary_path: str = "",
) -> Dict[str, Any]:
    """Select one activated family, rejecting every other family."""

    if family != ACTIVATED_FAMILY:
        raise TypedSemanticFamilySelectionError(
            f"operation family is not activated: {family}"
        )
    fact_errors = validate_typed_semantic_fact_set(
        fact_set,
        vocabulary_path=vocabulary_path,
    )
    if fact_errors:
        raise TypedSemanticFamilySelectionError(
            "typed fact set is invalid: " + "; ".join(fact_errors)
        )
    loaded = load_typed_semantic_vocabulary(vocabulary_path)
    if loaded.get("status") != "valid":
        raise TypedSemanticFamilySelectionError(
            "typed semantic vocabulary is missing or invalid"
        )
    if (
        loaded["document"]["activation"]["family_states"].get(family)
        != "activated"
    ):
        raise TypedSemanticFamilySelectionError(
            f"operation family is not activated: {family}"
        )
    result = _selection_payload(
        fact_set,
        loaded["document"],
        _clean(loaded.get("sha256")).lower(),
    )
    result["selection_sha256"] = _sha256_json(result)
    errors = validate_typed_semantic_family_selection(
        result,
        fact_set,
        vocabulary_path=vocabulary_path,
    )
    if errors:
        raise TypedSemanticFamilySelectionError(
            "family selection validation failed: " + "; ".join(errors)
        )
    return result


def validate_typed_semantic_family_selection(
    value: Any,
    fact_set: Dict[str, Any],
    *,
    vocabulary_path: str = "",
) -> List[str]:
    """Validate selection integrity and resolve every internal reference."""

    errors: List[str] = []
    if not isinstance(value, dict) or set(value) != _SELECTION_KEYS:
        return ["family selection has an invalid whole-contract shape"]
    fact_errors = validate_typed_semantic_fact_set(
        fact_set,
        vocabulary_path=vocabulary_path,
    )
    if fact_errors:
        errors.append("referenced typed fact set is invalid")
        return errors
    loaded = load_typed_semantic_vocabulary(vocabulary_path)
    if loaded.get("status") != "valid":
        return ["typed semantic vocabulary is missing or invalid"]
    digest_input = deepcopy(value)
    recorded = _clean(
        digest_input.pop("selection_sha256", "")
    ).lower()
    if (
        not SHA256_RE.fullmatch(recorded)
        or recorded != _sha256_json(digest_input)
    ):
        errors.append("selection_sha256 mismatch")
    expected = _selection_payload(
        fact_set,
        loaded["document"],
        _clean(loaded.get("sha256")).lower(),
    )
    if digest_input != expected:
        errors.append("family selection does not match immutable facts")
    if value.get("schema_version") != SCHEMA_VERSION:
        errors.append("family selection schema is invalid")
    if value.get("family") != ACTIVATED_FAMILY:
        errors.append("family selection is outside the activated family")
    if value.get("activation_state") != "activated":
        errors.append("family selection activation state is invalid")
    if value.get("status") not in {"matched", "abstained"}:
        errors.append("family selection status is invalid")
    if value.get("fact_set_sha256") != fact_set.get("fact_set_sha256"):
        errors.append("family selection fact-set hash mismatch")
    if value.get("semantic_vocabulary_sha256") != loaded.get("sha256"):
        errors.append("family selection vocabulary hash mismatch")

    fact_by_id = {
        _clean(fact.get("fact_id")): fact
        for fact in fact_set.get("facts") or []
        if isinstance(fact, dict)
    }
    operation_by_id = {
        _clean(operation.get("operation_id")): operation
        for fact in fact_set.get("facts") or []
        if isinstance(fact, dict)
        for operation in fact.get("operations") or []
        if isinstance(operation, dict)
    }
    entity_by_id = {
        _clean(entity.get("entity_id")): entity
        for entity in fact_set.get("entities") or []
        if isinstance(entity, dict)
    }
    for index, match in enumerate(value.get("matches") or []):
        if not isinstance(match, dict) or set(match) != _MATCH_KEYS:
            errors.append(f"matches[{index}] has an invalid shape")
            continue
        if match.get("fact_id") not in fact_by_id:
            errors.append(f"matches[{index}].fact_id is unresolved")
        if match.get("entity_ref") not in entity_by_id:
            errors.append(f"matches[{index}].entity_ref is unresolved")
        for operation_ref in match.get("operation_refs") or []:
            if operation_ref not in operation_by_id:
                errors.append(
                    f"matches[{index}].operation_ref is unresolved"
                )
        source_ref = _clean(match.get("source_observation_ref"))
        fact = fact_by_id.get(_clean(match.get("fact_id"))) or {}
        if source_ref != fact.get("source_observation_ref"):
            errors.append(
                f"matches[{index}].source_observation_ref is unresolved"
            )
    for index, abstention in enumerate(value.get("abstentions") or []):
        if (
            not isinstance(abstention, dict)
            or set(abstention) != _ABSTENTION_KEYS
        ):
            errors.append(f"abstentions[{index}] has an invalid shape")
            continue
        if abstention.get("fact_id") not in fact_by_id:
            errors.append(f"abstentions[{index}].fact_id is unresolved")
        if not _texts(abstention.get("reasons") or []):
            errors.append(f"abstentions[{index}].reasons is empty")
    return errors


def policy_output_trace(selection: Dict[str, Any]) -> Dict[str, Any]:
    """Project a bounded, content-addressed trace without dangling fact IDs."""

    return {
        "schema_version": "typed_semantic_policy_trace.v1",
        "family": _clean(selection.get("family")),
        "fact_set_sha256": _clean(selection.get("fact_set_sha256")),
        "semantic_vocabulary_sha256": _clean(
            selection.get("semantic_vocabulary_sha256")
        ),
        "selection_sha256": _clean(selection.get("selection_sha256")),
        "matches": [
            {
                "supporting_evidence_refs": list(
                    item.get("supporting_evidence_refs") or []
                ),
                "operation_types": list(
                    item.get("operation_types") or []
                ),
                "entity_role": _clean(item.get("entity_role")),
                "entity_type": _clean(item.get("entity_type")),
                "entity_value": _clean(item.get("entity_value")),
                "path_resolution_status": _clean(
                    item.get("path_resolution_status")
                ),
                "outcome_status": _clean(item.get("outcome_status")),
                "outcome_scope": _clean(item.get("outcome_scope")),
                "effect_status": _clean(item.get("effect_status")),
                "proof_scopes": list(item.get("proof_scopes") or []),
            }
            for item in selection.get("matches") or []
        ],
    }


def validate_policy_output_trace(
    value: Any,
    *,
    fact_set_sha256: str,
    semantic_vocabulary_sha256: str,
    allowed_evidence_refs: set[str],
) -> List[str]:
    """Validate the persisted projection without requiring stored full facts."""

    errors: List[str] = []
    root_keys = {
        "schema_version",
        "family",
        "fact_set_sha256",
        "semantic_vocabulary_sha256",
        "selection_sha256",
        "matches",
    }
    match_keys = {
        "supporting_evidence_refs",
        "operation_types",
        "entity_role",
        "entity_type",
        "entity_value",
        "path_resolution_status",
        "outcome_status",
        "outcome_scope",
        "effect_status",
        "proof_scopes",
    }
    if not isinstance(value, dict) or set(value) != root_keys:
        return ["typed semantic policy trace shape is invalid"]
    if value.get("schema_version") != "typed_semantic_policy_trace.v1":
        errors.append("typed semantic policy trace schema is invalid")
    if value.get("family") != ACTIVATED_FAMILY:
        errors.append("typed semantic policy trace family is invalid")
    for key, expected in (
        ("fact_set_sha256", fact_set_sha256),
        ("semantic_vocabulary_sha256", semantic_vocabulary_sha256),
    ):
        digest = _clean(value.get(key)).lower()
        if not SHA256_RE.fullmatch(digest) or digest != expected:
            errors.append(f"typed semantic policy trace {key} mismatch")
    if not SHA256_RE.fullmatch(
        _clean(value.get("selection_sha256")).lower()
    ):
        errors.append(
            "typed semantic policy trace selection_sha256 is invalid"
        )
    matches = value.get("matches")
    if not isinstance(matches, list) or not matches:
        errors.append("typed semantic policy trace requires matches")
        matches = []
    resolved_refs: set[str] = set()
    for index, match in enumerate(matches):
        if not isinstance(match, dict) or set(match) != match_keys:
            errors.append(
                f"typed semantic policy trace matches[{index}] shape is invalid"
            )
            continue
        if match.get("operation_types") != [
            "credential_path_read",
            "file_read",
        ]:
            errors.append(
                f"typed semantic policy trace matches[{index}] operations "
                "are invalid"
            )
        expected_values = {
            "entity_role": "credential_paths",
            "entity_type": "path",
            "outcome_status": "reported_success",
            "outcome_scope": "fragment",
            "effect_status": "reported_completed",
        }
        for key, expected in expected_values.items():
            if match.get(key) != expected:
                errors.append(
                    f"typed semantic policy trace matches[{index}].{key} "
                    "is invalid"
                )
        if match.get("path_resolution_status") not in {
            "recorded_resolved",
            "context_resolved",
        }:
            errors.append(
                f"typed semantic policy trace matches[{index}] path is "
                "unresolved"
            )
        if not _clean(match.get("entity_value")):
            errors.append(
                f"typed semantic policy trace matches[{index}] entity is empty"
            )
        proof_scopes = frozenset(match.get("proof_scopes") or [])
        if proof_scopes not in {
            frozenset({
                "general_command_semantics",
                "literal_command",
            }),
            frozenset({
                "shell_syntax",
                "literal_command",
            }),
            frozenset({
                "general_command_semantics",
                "shell_syntax",
                "literal_command",
            }),
        }:
            errors.append(
                f"typed semantic policy trace matches[{index}] proof scopes "
                "are invalid"
            )
        refs = set(_texts(match.get("supporting_evidence_refs") or []))
        if not refs or not refs.issubset(allowed_evidence_refs):
            errors.append(
                f"typed semantic policy trace matches[{index}] evidence "
                "references are unresolved"
            )
        resolved_refs.update(refs)
    if not resolved_refs:
        errors.append(
            "typed semantic policy trace has no resolved observed evidence"
        )
    return errors
