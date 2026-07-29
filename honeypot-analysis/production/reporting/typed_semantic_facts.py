"""Shadow-only typed semantic facts derived from observed Cowrie evidence.

The fact set is deliberately absent from session_assessment.v4 and
response_guidance.v3.  It provides a versioned comparison surface for a later
policy migration without changing current authority, persistence, APIs, or
content-addressed IDs.
"""

from __future__ import annotations

import hashlib
import posixpath
import shlex
from copy import deepcopy
from typing import Any, Dict, Iterable, List, Tuple

from production.utils.serialization import stable_id, stable_json


FACT_SET_SCHEMA = "typed_semantic_fact_set.v1"
FACT_SCHEMA = "typed_semantic_fact.v1"
SHADOW_RESULT_SCHEMA = "typed_semantic_shadow_result.v1"

_WRAPPERS = {"env", "nohup", "setsid", "sudo"}
_READ_EXECUTABLES = {
    "cat",
    "cut",
    "grep",
    "head",
    "less",
    "more",
    "sed",
    "stat",
    "tail",
    "wc",
}
_SYSTEMCTL_READ = {
    "cat",
    "get-default",
    "is-active",
    "is-enabled",
    "is-failed",
    "list-dependencies",
    "list-sockets",
    "list-timers",
    "list-unit-files",
    "list-units",
    "show",
    "status",
}
_SYSTEMCTL_MODIFY = {
    "daemon-reload",
    "disable",
    "edit",
    "enable",
    "mask",
    "reload",
    "restart",
    "start",
    "stop",
    "unmask",
}
_PRIMARY_OPERATION_PRIORITY = (
    "cowrie_file_transfer_observed",
    "account_modification_attempt",
    "permission_modification_attempt",
    "deletion_attempt",
    "execution_attempt",
    "shell_pipe_consumer",
    "transfer_attempt",
    "remote_content_pipe_source",
    "credential_path_access",
    "remote_content_access",
)
_OPERATION_CLASS = {
    "cowrie_file_transfer_observed": "transfer",
    "account_modification_attempt": "modify",
    "permission_modification_attempt": "modify",
    "deletion_attempt": "delete",
    "execution_attempt": "execute",
    "shell_pipe_consumer": "execute",
    "transfer_attempt": "transfer",
    "remote_content_pipe_source": "transfer",
    "credential_path_access": "read",
    "remote_content_access": "access",
}


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def _texts(values: Iterable[Any]) -> List[str]:
    output: List[str] = []
    for value in values or []:
        text = _clean(value)
        if text and text not in output:
            output.append(text)
    return output


def _tokens(command: Any) -> List[str]:
    try:
        values = shlex.split(_clean(command), posix=True)
    except ValueError:
        values = _clean(command).split()
    while values and values[0].lower() in _WRAPPERS:
        values = values[1:]
        while values and (
            values[0].startswith("-")
            or ("=" in values[0] and not values[0].startswith(("/", "./")))
        ):
            values = values[1:]
    return values


def _operation_semantics(observation: Dict[str, Any]) -> Dict[str, Any]:
    literal_types = _texts(observation.get("action_types") or [])
    primary = next(
        (
            operation
            for operation in _PRIMARY_OPERATION_PRIORITY
            if operation in literal_types
        ),
        literal_types[0] if literal_types else "",
    )
    if primary:
        return {
            "operation_type": primary,
            "operation_class": _OPERATION_CLASS.get(primary, "other"),
            "resolution": "existing_literal_observation",
            "literal_operation_types": literal_types,
        }

    tokens = _tokens(observation.get("command"))
    executable = tokens[0].lower() if tokens else ""
    arguments = tokens[1:]
    lowered = [value.lower() for value in arguments]
    if executable == "cd":
        return {
            "operation_type": "working_directory_change",
            "operation_class": "context_change",
            "resolution": "literal_shell_builtin",
            "literal_operation_types": [],
        }
    if executable == "crontab":
        if any(value in {"-l", "--list"} for value in lowered):
            operation_type = "schedule_inspection"
            operation_class = "read"
        elif any(value in {"-e", "--edit", "-r", "--remove"} for value in lowered):
            operation_type = "schedule_modification"
            operation_class = "modify"
        elif arguments and not all(value.startswith("-") for value in arguments):
            operation_type = "schedule_modification"
            operation_class = "modify"
        else:
            operation_type = "unknown"
            operation_class = "unknown"
        return {
            "operation_type": operation_type,
            "operation_class": operation_class,
            "resolution": (
                "literal_command_semantics"
                if operation_type != "unknown"
                else "unresolved"
            ),
            "literal_operation_types": [],
        }
    if executable == "systemctl":
        subcommand = next(
            (value for value in lowered if value and not value.startswith("-")),
            "",
        )
        if subcommand in _SYSTEMCTL_READ:
            operation_type, operation_class = "service_inspection", "read"
        elif subcommand in _SYSTEMCTL_MODIFY:
            operation_type, operation_class = "service_modification", "modify"
        else:
            operation_type, operation_class = "unknown", "unknown"
        return {
            "operation_type": operation_type,
            "operation_class": operation_class,
            "resolution": (
                "literal_command_semantics"
                if operation_type != "unknown"
                else "unresolved"
            ),
            "literal_operation_types": [],
        }
    if executable in _READ_EXECUTABLES:
        return {
            "operation_type": "file_or_stream_inspection",
            "operation_class": "read",
            "resolution": "literal_command_semantics",
            "literal_operation_types": [],
        }
    return {
        "operation_type": "unknown",
        "operation_class": "unknown",
        "resolution": "unresolved",
        "literal_operation_types": [],
    }


def _absolute_path(value: str, working_directory: str) -> str:
    raw = _clean(value).strip("'\"")
    if not raw or any(
        character in raw for character in ("$", "`", "*", "?", "[", "]", "~")
    ):
        return ""
    if raw.startswith("/"):
        return posixpath.normpath(raw)
    if working_directory.startswith("/"):
        return posixpath.normpath(posixpath.join(working_directory, raw))
    return ""


def _path_resolution(
    entities: Dict[str, Any],
    working_directory: str,
    working_directory_status: str,
) -> List[Dict[str, Any]]:
    output: List[Dict[str, Any]] = []
    for role, values in entities.items():
        if "path" not in role:
            continue
        for entity in values or []:
            if not isinstance(entity, dict):
                continue
            entity_ref = _clean(entity.get("entity_id"))
            original = _clean(entity.get("original_value"))
            recorded = _clean(entity.get("normalized_value"))
            if entity.get("linkable") is True and entity.get("uncertain") is not True:
                status = "recorded_resolved"
                candidate = recorded
            else:
                candidate = _absolute_path(original, working_directory)
                if candidate and working_directory_status in {"observed", "confirmed"}:
                    status = "shadow_resolved"
                elif candidate:
                    status = "conditional_candidate"
                else:
                    status = "unresolved"
            output.append({
                "entity_ref": entity_ref,
                "role": role,
                "recorded_normalized_value": recorded,
                "recorded_uncertain": bool(entity.get("uncertain")),
                "recorded_linkable": entity.get("linkable") is True,
                "resolution_status": status,
                "candidate_normalized_value": candidate,
            })
    return output


def _command_facts(observations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    facts: List[Dict[str, Any]] = []
    confirmed_working_directory = ""
    compound_candidate: Dict[int, Tuple[str, str]] = {}
    for observation in observations:
        if not isinstance(observation, dict):
            continue
        operation = _operation_semantics(observation)
        observed_working_directory = _clean(
            observation.get("working_directory_observed")
        )
        compound_index = int(observation.get("compound_command_index") or 0)
        candidate_directory, candidate_status = compound_candidate.get(
            compound_index, ("", "")
        )
        if observed_working_directory.startswith("/"):
            working_directory = posixpath.normpath(observed_working_directory)
            working_directory_status = "observed"
        elif candidate_directory:
            working_directory = candidate_directory
            working_directory_status = candidate_status
        elif confirmed_working_directory:
            working_directory = confirmed_working_directory
            working_directory_status = "confirmed"
        else:
            working_directory = ""
            working_directory_status = "unknown"

        directory_change: Dict[str, Any] = {}
        if operation["operation_type"] == "working_directory_change":
            tokens = _tokens(observation.get("command"))
            target = tokens[1] if len(tokens) > 1 else ""
            resolved_target = _absolute_path(target, working_directory)
            action_status = _clean(observation.get("action_status"))
            if resolved_target and action_status == "reported_success":
                change_status = "confirmed"
                confirmed_working_directory = resolved_target
            elif resolved_target:
                change_status = "conditional_candidate"
            else:
                change_status = "unresolved"
            directory_change = {
                "original_target": target,
                "resolved_target": resolved_target,
                "status": change_status,
            }
            if resolved_target:
                compound_candidate[compound_index] = (
                    resolved_target,
                    (
                        "confirmed"
                        if change_status == "confirmed"
                        else "conditional_candidate"
                    ),
                )

        entities = deepcopy(observation.get("entities") or {})
        trusted_candidates = deepcopy(
            observation.get("trusted_attck_mappings") or []
        )
        supporting_refs = _texts([
            observation.get("evidence_id"),
            *(observation.get("source_evidence_refs") or []),
            *[
                candidate.get("evidence_ref")
                for candidate in trusted_candidates
                if isinstance(candidate, dict)
            ],
        ])
        content = {
            "schema_version": FACT_SCHEMA,
            "source_observation_ref": _clean(observation.get("evidence_id")),
            "evidence_type": _clean(observation.get("evidence_type")),
            "sequence_index": observation.get("sequence_index"),
            "operation": operation,
            "operation_status": (
                _clean(observation.get("action_status")) or "outcome_unknown"
            ),
            "command_outcome": _clean(observation.get("command_outcome")),
            "outcome_scope": _clean(observation.get("outcome_scope")),
            "entities": entities,
            "shell_context": {
                "command": _clean(observation.get("command")),
                "original_command": _clean(observation.get("original_command")),
                "compound_command_index": observation.get(
                    "compound_command_index"
                ),
                "fragment_index": observation.get("fragment_index"),
                "fragment_count": observation.get("fragment_count"),
                "operator_before": _clean(observation.get("operator_before")),
                "operator_after": _clean(observation.get("operator_after")),
                "pipe_producer": _clean(observation.get("pipe_producer")),
                "pipe_consumer": _clean(observation.get("pipe_consumer")),
                "conditional_execution": deepcopy(
                    observation.get("conditional_execution") or {}
                ),
            },
            "working_directory_context": {
                "observed": observed_working_directory,
                "effective": working_directory,
                "status": working_directory_status,
                "directory_change": directory_change,
            },
            "path_resolutions": _path_resolution(
                entities,
                working_directory,
                working_directory_status,
            ),
            "trusted_attck_candidates": trusted_candidates,
            "supporting_evidence_refs": supporting_refs,
            "duplicate_of": _clean(observation.get("duplicate_of")),
            "semantic_authority": "shadow_non_authoritative",
        }
        facts.append({
            "fact_id": stable_id("typed_semantic_fact", content),
            **content,
        })
    return facts


def _transfer_facts(observations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    facts: List[Dict[str, Any]] = []
    for observation in observations:
        if not isinstance(observation, dict):
            continue
        entities = deepcopy(observation.get("entities") or {})
        working_directory = _clean(observation.get("working_directory_observed"))
        working_status = (
            "observed" if working_directory.startswith("/") else "unknown"
        )
        operation = _operation_semantics(observation)
        content = {
            "schema_version": FACT_SCHEMA,
            "source_observation_ref": _clean(observation.get("evidence_id")),
            "evidence_type": _clean(observation.get("evidence_type")),
            "sequence_index": observation.get("source_index"),
            "operation": operation,
            "operation_status": (
                _clean(observation.get("action_status")) or "outcome_unknown"
            ),
            "command_outcome": "",
            "outcome_scope": "direct_cowrie_event",
            "entities": entities,
            "shell_context": {},
            "working_directory_context": {
                "observed": working_directory,
                "effective": working_directory,
                "status": working_status,
                "directory_change": {},
            },
            "path_resolutions": _path_resolution(
                entities,
                working_directory,
                working_status,
            ),
            "trusted_attck_candidates": [],
            "supporting_evidence_refs": [
                _clean(observation.get("evidence_id"))
            ],
            "duplicate_of": "",
            "semantic_authority": "shadow_non_authoritative",
        }
        facts.append({
            "fact_id": stable_id("typed_semantic_fact", content),
            **content,
        })
    return facts


def _relationship_facts(
    relationships: Iterable[Dict[str, Any]],
    fact_by_evidence: Dict[str, str],
) -> List[Dict[str, Any]]:
    return [
        {
            **deepcopy(relationship),
            "source_fact_id": fact_by_evidence.get(
                _clean(relationship.get("source_evidence_ref")), ""
            ),
            "target_fact_id": fact_by_evidence.get(
                _clean(relationship.get("target_evidence_ref")), ""
            ),
        }
        for relationship in relationships or []
        if isinstance(relationship, dict)
    ]


def _chain_facts(
    chains: Iterable[Dict[str, Any]],
    fact_by_evidence: Dict[str, str],
) -> List[Dict[str, Any]]:
    output: List[Dict[str, Any]] = []
    for chain in chains or []:
        if not isinstance(chain, dict):
            continue
        evidence_refs = _texts(chain.get("evidence_refs") or [])
        output.append({
            "chain_id": _clean(chain.get("chain_id")),
            "fact_ids": [
                fact_by_evidence.get(evidence_ref, "")
                for evidence_ref in evidence_refs
            ],
            "evidence_refs": evidence_refs,
            "relationship_ids": [
                _clean(relationship.get("relationship_id"))
                for relationship in chain.get("relationships") or []
                if isinstance(relationship, dict)
                and _clean(relationship.get("relationship_id"))
            ],
            "entity_refs": _texts(chain.get("entity_refs") or []),
            "action_types": _texts(chain.get("action_types") or []),
            "chain_status": _clean(chain.get("chain_status")),
            "limitations": _texts(chain.get("limitations") or []),
            "completion_gaps": _texts(chain.get("completion_gaps") or []),
            "final_relevant_evidence_ref": _clean(
                chain.get("final_relevant_evidence_ref")
            ),
        })
    return output


def _reference_comparison(
    observed: Dict[str, Any],
    facts: List[Dict[str, Any]],
    relationships: List[Dict[str, Any]],
    chains: List[Dict[str, Any]],
    entities: List[Dict[str, Any]],
    trusted_candidates: List[Dict[str, Any]],
) -> Dict[str, Any]:
    differences: List[str] = []
    expected_observations = _texts([
        *[
            item.get("evidence_id")
            for item in observed.get("ordered_command_observations") or []
            if isinstance(item, dict)
        ],
        *[
            item.get("evidence_id")
            for item in observed.get("transfer_event_observations") or []
            if isinstance(item, dict)
        ],
    ])
    fact_observations = _texts(
        fact.get("source_observation_ref") for fact in facts
    )
    if expected_observations != fact_observations:
        differences.append("observation_identity_mismatch")

    expected_relationships = _texts(
        item.get("relationship_id")
        for item in observed.get("behavior_relationships") or []
        if isinstance(item, dict)
    )
    if expected_relationships != _texts(
        item.get("relationship_id") for item in relationships
    ):
        differences.append("relationship_identity_mismatch")

    expected_chains = _texts(
        item.get("chain_id")
        for item in observed.get("connected_behavior_chains") or []
        if isinstance(item, dict)
    )
    if expected_chains != _texts(item.get("chain_id") for item in chains):
        differences.append("chain_identity_mismatch")

    expected_entities = _texts(
        item.get("entity_id")
        for item in observed.get("normalized_entities") or []
        if isinstance(item, dict)
    )
    if expected_entities != _texts(item.get("entity_id") for item in entities):
        differences.append("entity_identity_mismatch")

    if stable_json(trusted_candidates) != stable_json(
        observed.get("trusted_attck_candidates") or []
    ):
        differences.append("trusted_attck_candidate_mismatch")

    return {
        "status": "exact_reference_match" if not differences else "mismatch",
        "difference_codes": differences,
        "source_observation_count": len(expected_observations),
        "typed_fact_count": len(facts),
        "relationship_count": len(relationships),
        "chain_count": len(chains),
        "entity_count": len(entities),
        "trusted_attck_candidate_count": len(trusted_candidates),
        "unknown_operation_count": sum(
            fact.get("operation", {}).get("operation_type") == "unknown"
            for fact in facts
        ),
        "unresolved_path_count": sum(
            resolution.get("resolution_status") in {
                "conditional_candidate",
                "unresolved",
            }
            for fact in facts
            for resolution in fact.get("path_resolutions") or []
        ),
    }


def build_typed_semantic_fact_set(observed: Dict[str, Any]) -> Dict[str, Any]:
    """Build the deterministic shadow fact set without mutating ``observed``."""

    command_facts = _command_facts(
        deepcopy(observed.get("ordered_command_observations") or [])
    )
    transfer_facts = _transfer_facts(
        deepcopy(observed.get("transfer_event_observations") or [])
    )
    facts = command_facts + transfer_facts
    fact_by_evidence = {
        _clean(fact.get("source_observation_ref")): _clean(fact.get("fact_id"))
        for fact in facts
    }
    relationships = _relationship_facts(
        observed.get("behavior_relationships") or [],
        fact_by_evidence,
    )
    chains = _chain_facts(
        observed.get("connected_behavior_chains") or [],
        fact_by_evidence,
    )
    entities = deepcopy(observed.get("normalized_entities") or [])
    trusted_candidates = deepcopy(observed.get("trusted_attck_candidates") or [])
    comparison = _reference_comparison(
        observed,
        facts,
        relationships,
        chains,
        entities,
        trusted_candidates,
    )
    result = {
        "schema_version": FACT_SET_SCHEMA,
        "session_id": _clean(observed.get("session_id")) or "unknown",
        "mode": "shadow_only_discarded",
        "authority": {
            "authoritative": False,
            "may_select_findings": False,
            "may_select_hypotheses": False,
            "may_select_guidance": False,
            "may_change_canonical_ids": False,
        },
        "facts": facts,
        "entities": entities,
        "relationships": relationships,
        "chains": chains,
        "trusted_attck_candidates": trusted_candidates,
        "shadow_comparison": comparison,
    }
    result["fact_set_sha256"] = _sha256_json(result)
    return result


def validate_typed_semantic_fact_set(value: Any) -> List[str]:
    errors: List[str] = []
    if not isinstance(value, dict):
        return ["typed semantic fact set must be an object"]
    if value.get("schema_version") != FACT_SET_SCHEMA:
        errors.append(f"schema_version must be {FACT_SET_SCHEMA}")
    if value.get("mode") != "shadow_only_discarded":
        errors.append("typed semantic facts must remain shadow-only")
    authority = value.get("authority") or {}
    if authority != {
        "authoritative": False,
        "may_select_findings": False,
        "may_select_hypotheses": False,
        "may_select_guidance": False,
        "may_change_canonical_ids": False,
    }:
        errors.append("typed semantic fact authority is invalid")
    hash_input = deepcopy(value)
    recorded_hash = _clean(hash_input.pop("fact_set_sha256", ""))
    if recorded_hash != _sha256_json(hash_input):
        errors.append("fact_set_sha256 mismatch")

    facts = value.get("facts")
    if not isinstance(facts, list):
        errors.append("facts must be a list")
        facts = []
    fact_ids: set[str] = set()
    evidence_to_fact: Dict[str, str] = {}
    entity_ids = {
        _clean(entity.get("entity_id"))
        for entity in value.get("entities") or []
        if isinstance(entity, dict) and _clean(entity.get("entity_id"))
    }
    for index, fact in enumerate(facts):
        if not isinstance(fact, dict):
            errors.append(f"facts[{index}] must be an object")
            continue
        fact_id = _clean(fact.get("fact_id"))
        content = {key: item for key, item in fact.items() if key != "fact_id"}
        if not fact_id or fact_id in fact_ids:
            errors.append(f"facts[{index}] has missing or duplicate fact_id")
        elif fact_id != stable_id("typed_semantic_fact", content):
            errors.append(f"facts[{index}] fact_id mismatch")
        fact_ids.add(fact_id)
        source_ref = _clean(fact.get("source_observation_ref"))
        evidence_to_fact[source_ref] = fact_id
        if source_ref not in fact.get("supporting_evidence_refs", []):
            errors.append(f"facts[{index}] lacks its source evidence reference")
        operation = fact.get("operation") or {}
        if (
            operation.get("operation_type") == "unknown"
            and operation.get("literal_operation_types")
        ):
            errors.append(f"facts[{index}] promotes an unresolved operation")
        if fact.get("semantic_authority") != "shadow_non_authoritative":
            errors.append(f"facts[{index}] has invalid semantic authority")
        for role, entities in (fact.get("entities") or {}).items():
            if not isinstance(entities, list):
                errors.append(f"facts[{index}].entities.{role} must be a list")
                continue
            for entity in entities:
                if not isinstance(entity, dict):
                    errors.append(
                        f"facts[{index}].entities.{role} must remain structured"
                    )
                    continue
                if _clean(entity.get("entity_id")) not in entity_ids:
                    errors.append(f"facts[{index}] has an unknown entity reference")

    relationships = value.get("relationships")
    if not isinstance(relationships, list):
        errors.append("relationships must be a list")
        relationships = []
    relationship_ids: set[str] = set()
    for index, relationship in enumerate(relationships):
        relationship_id = (
            _clean(relationship.get("relationship_id"))
            if isinstance(relationship, dict)
            else ""
        )
        if not relationship_id or relationship_id in relationship_ids:
            errors.append(
                f"relationships[{index}] has missing or duplicate relationship_id"
            )
        relationship_ids.add(relationship_id)
        if (
            not isinstance(relationship, dict)
            or _clean(relationship.get("source_fact_id")) not in fact_ids
            or _clean(relationship.get("target_fact_id")) not in fact_ids
        ):
            errors.append(f"relationships[{index}] has unresolved fact references")
        entity_ref = (
            _clean(relationship.get("entity_ref"))
            if isinstance(relationship, dict)
            else ""
        )
        if entity_ref and entity_ref not in entity_ids:
            errors.append(f"relationships[{index}] has an unresolved entity reference")

    chains = value.get("chains")
    if not isinstance(chains, list):
        errors.append("chains must be a list")
        chains = []
    chain_ids: set[str] = set()
    for index, chain in enumerate(chains):
        chain_id = _clean(chain.get("chain_id")) if isinstance(chain, dict) else ""
        if not chain_id or chain_id in chain_ids:
            errors.append(f"chains[{index}] has missing or duplicate chain_id")
        chain_ids.add(chain_id)
        if not isinstance(chain, dict):
            continue
        if any(
            _clean(fact_id) not in fact_ids
            for fact_id in chain.get("fact_ids") or []
        ):
            errors.append(f"chains[{index}] has unresolved fact references")
        if any(
            _clean(relationship_id) not in relationship_ids
            for relationship_id in chain.get("relationship_ids") or []
        ):
            errors.append(f"chains[{index}] has unresolved relationship references")
        if any(
            _clean(entity_id) not in entity_ids
            for entity_id in chain.get("entity_refs") or []
        ):
            errors.append(f"chains[{index}] has unresolved entity references")

    comparison = value.get("shadow_comparison") or {}
    if comparison.get("status") != "exact_reference_match":
        errors.append("shadow comparison does not match source identities")
    return errors


def run_typed_semantic_shadow(observed: Dict[str, Any]) -> Dict[str, Any]:
    """Build, compare, and validate facts while returning no authoritative data."""

    try:
        fact_set = build_typed_semantic_fact_set(observed)
        errors = validate_typed_semantic_fact_set(fact_set)
        return {
            "schema_version": SHADOW_RESULT_SCHEMA,
            "status": "valid" if not errors else "invalid",
            "fact_set_sha256": fact_set.get("fact_set_sha256", ""),
            "comparison": deepcopy(fact_set.get("shadow_comparison") or {}),
            "validation_errors": errors,
            "authoritative": False,
            "persistence": "discarded",
        }
    except Exception as exc:  # pragma: no cover - defensive shadow containment
        return {
            "schema_version": SHADOW_RESULT_SCHEMA,
            "status": "unavailable",
            "error_type": exc.__class__.__name__,
            "authoritative": False,
            "persistence": "discarded",
        }
