"""Provenance-bound typed semantics for observed Cowrie evidence.

Only operation families explicitly activated by the immutable vocabulary may
be used as policy inputs. All remaining families stay shadow-only.
"""

from __future__ import annotations

import hashlib
import re
from copy import deepcopy
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from production.policies.typed_semantic_vocabulary import (
    load_typed_semantic_vocabulary,
    vocabulary_summary,
)
from production.reporting.typed_semantic_parser import (
    extract_transfer_semantics,
    extract_typed_semantics,
)
from production.utils.serialization import stable_id, stable_json


FACT_SET_SCHEMA = "typed_semantic_fact_set.v2"
FACT_SCHEMA = "typed_semantic_fact.v2"
RELATIONSHIP_SCHEMA = "typed_semantic_relationship.v1"
CHAIN_SCHEMA = "typed_semantic_chain.v1"
SHADOW_RESULT_SCHEMA = "typed_semantic_shadow_result.v2"
SHADOW_DIFF_SCHEMA = "typed_semantic_shadow_diff.v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_REVISION_RE = re.compile(r"^[0-9a-f]{7,64}$")

_AUTHORITY = {
    "authoritative": False,
    "may_select_findings": True,
    "may_select_hypotheses": False,
    "may_select_guidance": True,
    "may_change_canonical_ids": True,
    "may_authorize_actions": False,
}
_TOP_KEYS = {
    "schema_version",
    "status",
    "session_id",
    "mode",
    "authority",
    "provenance",
    "limits",
    "facts",
    "entities",
    "relationships",
    "chains",
    "attck_candidates",
    "evidence_index",
    "shadow_comparison",
    "fact_set_sha256",
}
_PROVENANCE_KEYS = {
    "canonical_evidence_sha256",
    "source_evidence_sha256",
    "semantic_input_sha256",
    "behavior_policy_sha256",
    "classification_policy_sha256",
    "semantic_vocabulary",
    "evaluator_git_revision",
}
_VOCABULARY_SUMMARY_KEYS = {
    "schema_version",
    "policy_id",
    "version",
    "semantic_extractor_version",
    "sha256",
    "source",
    "status",
    "validation_errors",
}
_LIMIT_SUMMARY_KEYS = {
    "fact_count",
    "entity_count",
    "relationship_count",
    "chain_count",
    "total_command_bytes",
    "within_policy_limits",
}
_FACT_KEYS = {
    "fact_id",
    "schema_version",
    "source_observation_ref",
    "evidence_type",
    "sequence_index",
    "source_index",
    "timestamp",
    "cowrie_eventid",
    "parse",
    "operations",
    "outcome",
    "entities",
    "shell_context",
    "working_directory_context",
    "path_resolutions",
    "attck_candidate_refs",
    "evidence_references",
    "supporting_evidence_refs",
    "duplicate_of",
    "abstention_reasons",
    "semantic_authority",
}
_PARSE_KEYS = {
    "status",
    "abstention_reasons",
    "executable",
    "arguments",
    "redirections",
}
_REDIRECT_KEYS = {"operator", "target", "entity_ref"}
_OPERATION_KEYS = {
    "operation_id",
    "operation_type",
    "family",
    "effect",
    "proof_scope",
    "effect_status",
    "entity_refs",
    "source_literal_action",
}
_OUTCOME_KEYS = {
    "status",
    "scope",
    "proof_scope",
    "source_eventid",
    "semantics",
}
_ENTITY_KEYS = {
    "entity_id",
    "entity_type",
    "normalized_value",
    "original_value",
    "uncertain",
    "linkable",
    "uncertainty_reason",
    "candidate_normalized_value",
    "source_entity_ref",
    "redacted_components",
}
_AGGREGATE_ENTITY_KEYS = _ENTITY_KEYS | {
    "roles",
    "fact_refs",
    "variants",
}
_ENTITY_VARIANT_KEYS = {"fact_ref", "role", "entity"}
_SHELL_KEYS = {
    "command",
    "original_command",
    "compound_command_index",
    "fragment_index",
    "fragment_count",
    "operator_before",
    "operator_after",
    "pipe_producer",
    "pipe_consumer",
    "conditional_execution",
}
_CONDITIONAL_KEYS = {
    "operator",
    "status",
    "predecessor_evidence_ref",
    "semantics",
}
_WORKING_DIRECTORY_KEYS = {
    "observed",
    "effective",
    "status",
    "directory_change",
}
_DIRECTORY_CHANGE_KEYS = {
    "original_target",
    "resolved_target",
    "status",
}
_PATH_RESOLUTION_KEYS = {
    "path_identity_id",
    "candidate_identity_id",
    "entity_ref",
    "role",
    "recorded_normalized_value",
    "recorded_uncertain",
    "recorded_linkable",
    "resolution_status",
    "candidate_normalized_value",
    "proof_scope",
}
_EVIDENCE_REFERENCE_KEYS = {
    "evidence_ref",
    "reference_type",
    "proof_scope",
}
_EVIDENCE_INDEX_KEYS = {"evidence_ref", "reference_type"}
_ATTCK_KEYS = {
    "candidate_id",
    "source_evidence_ref",
    "technique_id",
    "tactic",
    "source",
    "agreement_status",
    "mapping_scope",
    "fact_refs",
    "proof_scope",
    "may_define_operations",
}
_RELATIONSHIP_KEYS = {
    "schema_version",
    "relationship_id",
    "relationship_type",
    "source_fact_id",
    "target_fact_id",
    "source_operation_ids",
    "target_operation_ids",
    "entity_ref",
    "path_identity_id",
    "status",
    "proof_scope",
    "basis",
    "abstention_reasons",
    "connects_chain",
    "causality_semantics",
}
_CHAIN_KEYS = {
    "schema_version",
    "chain_id",
    "status",
    "fact_refs",
    "relationship_refs",
    "entity_refs",
    "operation_refs",
    "proof_scopes",
    "abstention_reasons",
}
_COMPARISON_KEYS = {
    "status",
    "difference_codes",
    "source_observation_count",
    "typed_fact_count",
    "source_relationship_count",
    "typed_relationship_count",
    "source_chain_count",
    "typed_chain_count",
    "entity_count",
    "attck_candidate_count",
    "unknown_operation_count",
    "abstention_count",
    "partial_relationship_count",
    "blocked_relationship_count",
}
_SHADOW_RESULT_KEYS = {
    "schema_version",
    "status",
    "fact_set_sha256",
    "shadow_diff_sha256",
    "comparison",
    "validation_errors",
    "error_type",
    "authoritative",
    "persistence",
}
_SHADOW_DIFF_KEYS = {
    "schema_version",
    "session_id",
    "fact_set_sha256",
    "source_output",
    "typed_output",
    "blocked_matches",
    "abstentions",
    "policy_impact",
    "shadow_diff_sha256",
}


class TypedSemanticFactError(RuntimeError):
    """Raised when a shadow fact set cannot be built safely."""


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def _texts(values: Iterable[Any]) -> List[str]:
    output: List[str] = []
    for value in values or []:
        cleaned = _clean(value)
        if cleaned and cleaned not in output:
            output.append(cleaned)
    return output


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


def _canonical_evidence_hash(snapshot: Dict[str, Any]) -> Tuple[str, str]:
    if not isinstance(snapshot, dict):
        raise TypedSemanticFactError("canonical evidence must be an object")
    copied = deepcopy(snapshot)
    recorded = _clean(copied.pop("evidence_sha256", "")).lower()
    if not SHA256_RE.fullmatch(recorded) or recorded != _sha256_json(copied):
        raise TypedSemanticFactError(
            "canonical evidence SHA-256 is missing or inconsistent"
        )
    source = _clean(snapshot.get("source_evidence_sha256")).lower()
    if not SHA256_RE.fullmatch(source):
        raise TypedSemanticFactError(
            "source evidence SHA-256 is missing or invalid"
        )
    return recorded, source


def _semantic_input(observed: Dict[str, Any]) -> Dict[str, Any]:
    """Select only observed fields that the typed evaluator can read."""

    return {
        "session_id": _clean(observed.get("session_id")) or "unknown",
        "ordered_behavior_chain": [
            {
                key: deepcopy(item.get(key))
                for key in (
                    "evidence_id",
                    "command",
                    "timestamp",
                    "ttp",
                    "tactic",
                    "source",
                    "agreement_status",
                )
            }
            for item in observed.get("ordered_behavior_chain") or []
            if isinstance(item, dict)
        ],
        "ordered_command_observations": deepcopy(
            observed.get("ordered_command_observations") or []
        ),
        "transfer_event_observations": deepcopy(
            observed.get("transfer_event_observations") or []
        ),
    }


def build_typed_semantic_provenance(
    canonical_evidence: Dict[str, Any],
    *,
    observed_behavior: Dict[str, Any],
    behavior_policy_sha256: str,
    classification_policy_sha256: str,
    evaluator_git_revision: str,
    vocabulary_path: str = "",
) -> Dict[str, Any]:
    """Verify and bind every input that can affect shadow semantics."""

    evidence_sha256, source_evidence_sha256 = _canonical_evidence_hash(
        canonical_evidence
    )
    behavior_hash = _clean(behavior_policy_sha256).lower()
    classification_hash = _clean(classification_policy_sha256).lower()
    revision = _clean(evaluator_git_revision).lower()
    if not SHA256_RE.fullmatch(behavior_hash):
        raise TypedSemanticFactError("behavior policy SHA-256 is invalid")
    if not SHA256_RE.fullmatch(classification_hash):
        raise TypedSemanticFactError("classification policy SHA-256 is invalid")
    if not GIT_REVISION_RE.fullmatch(revision):
        raise TypedSemanticFactError("evaluator Git revision is invalid")
    loaded = load_typed_semantic_vocabulary(vocabulary_path)
    if loaded.get("status") != "valid":
        raise TypedSemanticFactError(
            "typed semantic vocabulary is missing or invalid"
        )
    return {
        "canonical_evidence_sha256": evidence_sha256,
        "source_evidence_sha256": source_evidence_sha256,
        "semantic_input_sha256": _sha256_json(
            _semantic_input(observed_behavior)
        ),
        "behavior_policy_sha256": behavior_hash,
        "classification_policy_sha256": classification_hash,
        "semantic_vocabulary": vocabulary_summary(loaded),
        "evaluator_git_revision": revision,
    }


def _outcome(observation: Dict[str, Any], *, transfer: bool) -> Dict[str, Any]:
    eventid = _clean(
        observation.get("eventid") or observation.get("cowrie_eventid")
    )
    if transfer:
        return {
            "status": "event_observed",
            "scope": "direct_cowrie_event",
            "proof_scope": "direct_cowrie_event",
            "source_eventid": eventid,
            "semantics": (
                "direct_cowrie_transfer_observation_not_real_host_effect"
            ),
        }
    action_status = _clean(observation.get("action_status"))
    scope = _clean(observation.get("outcome_scope")) or "legacy_unknown"
    if action_status == "reported_success":
        status, proof = "reported_success", "fragment_outcome"
    elif action_status == "reported_failure":
        status, proof = "reported_failure", "fragment_outcome"
    elif action_status == "compound_outcome_not_fragment_proof":
        status, proof = (
            "compound_outcome_not_fragment_proof",
            "compound_outcome",
        )
    elif action_status == "conditional_not_observed":
        status, proof = "conditional_not_observed", "shell_syntax"
    else:
        status, proof = "outcome_unknown", "unresolved"
    if scope not in {"fragment", "compound_event", "legacy_unknown"}:
        scope = "legacy_unknown"
    return {
        "status": status,
        "scope": scope,
        "proof_scope": proof,
        "source_eventid": eventid,
        "semantics": "cowrie_command_outcome_not_real_host_effect_proof",
    }


def _effect_status(
    operation_type: str,
    outcome: Dict[str, Any],
) -> str:
    if operation_type == "unknown":
        return "abstained"
    status = outcome["status"]
    if status == "event_observed":
        return "event_observed"
    if status == "reported_success":
        return "reported_completed"
    if status == "reported_failure":
        return "reported_failed"
    if status == "compound_outcome_not_fragment_proof":
        return "compound_unconfirmed"
    if status == "conditional_not_observed":
        return "conditional_not_observed"
    return "attempted_unconfirmed"


def _typed_operations(
    extracted: Dict[str, Any],
    outcome: Dict[str, Any],
    policy: Dict[str, Any],
    source_observation_ref: str,
) -> List[Dict[str, Any]]:
    definitions = policy.get("operations") or {}
    output: List[Dict[str, Any]] = []
    for sequence_index, item in enumerate(extracted.get("operations") or []):
        operation_type = _clean(item.get("operation_type"))
        definition = definitions.get(operation_type)
        if not isinstance(definition, dict):
            raise TypedSemanticFactError(
                f"extractor emitted unknown operation: {operation_type}"
            )
        content = {
            "operation_type": operation_type,
            "family": definition["family"],
            "effect": definition["effect"],
            "proof_scope": _clean(item.get("proof_scope")),
            "effect_status": _effect_status(operation_type, outcome),
            "entity_refs": _texts(item.get("entity_refs") or []),
            "source_literal_action": _clean(
                item.get("source_literal_action")
            ),
            "source_observation_ref": _clean(source_observation_ref),
            "sequence_index": sequence_index,
        }
        operation_id = stable_id("typed_semantic_operation", content)
        content.pop("source_observation_ref")
        content.pop("sequence_index")
        output.append({"operation_id": operation_id, **content})
    return output


def _absolute_candidate(value: str, working_directory: str) -> str:
    raw = value if isinstance(value, str) else ""
    if (
        not raw
        or any(character in raw for character in ("$", "`", "*", "?", "[", "]"))
        or raw.startswith("~")
    ):
        return ""
    if raw.startswith("/"):
        import posixpath

        return posixpath.normpath(raw)
    if working_directory.startswith("/"):
        import posixpath

        return posixpath.normpath(posixpath.join(working_directory, raw))
    return ""


def _path_resolutions(
    entities: Dict[str, List[Dict[str, Any]]],
    working_directory: str,
    working_directory_status: str,
) -> List[Dict[str, Any]]:
    output: List[Dict[str, Any]] = []
    for role, values in entities.items():
        if "path" not in role:
            continue
        for entity in values:
            recorded_value = entity.get("normalized_value")
            original_value = entity.get("original_value")
            recorded = (
                recorded_value if isinstance(recorded_value, str) else ""
            )
            original = (
                original_value if isinstance(original_value, str) else ""
            )
            if entity.get("linkable") is True and entity.get("uncertain") is False:
                status = "recorded_resolved"
                candidate = recorded
                proof = "literal_command"
            else:
                candidate_value = entity.get("candidate_normalized_value")
                candidate = (
                    candidate_value
                    if isinstance(candidate_value, str)
                    else ""
                ) or _absolute_candidate(original, working_directory)
                if candidate and working_directory_status in {
                    "observed",
                    "confirmed",
                }:
                    status = "context_resolved"
                    proof = (
                        "observed_context"
                        if working_directory_status == "observed"
                        else "confirmed_context"
                    )
                elif candidate:
                    status = "conditional_candidate"
                    proof = "conditional_context"
                else:
                    status = "unresolved"
                    proof = "unresolved"
            path_identity = (
                stable_id("typed_path_identity", {"path": candidate})
                if candidate and status in {
                    "recorded_resolved",
                    "context_resolved",
                }
                else ""
            )
            candidate_identity = (
                stable_id("typed_path_candidate", {"path": candidate})
                if candidate and status == "conditional_candidate"
                else ""
            )
            output.append({
                "path_identity_id": path_identity,
                "candidate_identity_id": candidate_identity,
                "entity_ref": _clean(entity.get("entity_id")),
                "role": role,
                "recorded_normalized_value": recorded,
                "recorded_uncertain": entity.get("uncertain") is True,
                "recorded_linkable": entity.get("linkable") is True,
                "resolution_status": status,
                "candidate_normalized_value": candidate,
                "proof_scope": proof,
            })
    return output


def _evidence_references(
    observation: Dict[str, Any],
) -> List[Dict[str, Any]]:
    mapping_refs = {
        _clean(item.get("evidence_ref"))
        for item in observation.get("trusted_attck_mappings") or []
        if isinstance(item, dict) and _clean(item.get("evidence_ref"))
    }
    is_direct_transfer = _clean(observation.get("evidence_type")) == (
        "direct_cowrie_transfer_event"
    )
    output = [{
        "evidence_ref": _clean(observation.get("evidence_id")),
        "reference_type": "source_observation",
        "proof_scope": (
            "direct_cowrie_event"
            if is_direct_transfer
            else "literal_command"
        ),
    }]
    if is_direct_transfer:
        output.append({
            "evidence_ref": _clean(observation.get("evidence_id")),
            "reference_type": "direct_cowrie_event",
            "proof_scope": "direct_cowrie_event",
        })
    for reference in observation.get("source_evidence_refs") or []:
        cleaned = _clean(reference)
        if not cleaned:
            continue
        reference_type = (
            "trusted_classification"
            if cleaned in mapping_refs
            else "direct_cowrie_event"
        )
        output.append({
            "evidence_ref": cleaned,
            "reference_type": reference_type,
            "proof_scope": (
                "classification_candidate"
                if reference_type == "trusted_classification"
                else "direct_cowrie_event"
            ),
        })
    duplicate = _clean(observation.get("duplicate_of"))
    if duplicate:
        output.append({
            "evidence_ref": duplicate,
            "reference_type": "duplicate_observation",
            "proof_scope": "literal_command",
        })
    unique: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for item in output:
        unique.setdefault(
            (item["evidence_ref"], item["reference_type"]),
            item,
        )
    return list(unique.values())


def _directory_context(
    observation: Dict[str, Any],
    extracted: Dict[str, Any],
    *,
    effective: str,
    effective_status: str,
) -> Tuple[Dict[str, Any], str, str]:
    observed = _clean(observation.get("working_directory_observed"))
    change = {
        "original_target": "",
        "resolved_target": "",
        "status": "none",
    }
    next_confirmed = ""
    compound_candidate = ""
    is_cd = any(
        item.get("operation_type") == "working_directory_change"
        for item in extracted.get("operations") or []
    )
    if is_cd:
        target = next(
            (
                entity.get("original_value")
                for entity in extracted.get("entities", {}).get(
                    "destination_paths", []
                )
                if isinstance(entity, dict)
            ),
            "",
        )
        resolved = _absolute_candidate(_clean(target), effective)
        action_status = _clean(observation.get("action_status"))
        if resolved and action_status == "reported_success":
            status = "confirmed"
            next_confirmed = resolved
        elif action_status == "reported_failure":
            status = "failed"
        elif resolved and action_status == "compound_outcome_not_fragment_proof":
            status = "conditional_candidate"
            compound_candidate = resolved
        elif resolved:
            status = "unresolved"
        else:
            status = "unresolved"
        change = {
            "original_target": _clean(target),
            "resolved_target": resolved,
            "status": status,
        }
    return {
        "observed": observed,
        "effective": effective,
        "status": effective_status,
        "directory_change": change,
    }, next_confirmed, compound_candidate


def _command_facts(
    observations: List[Dict[str, Any]],
    policy: Dict[str, Any],
) -> List[Dict[str, Any]]:
    facts: List[Dict[str, Any]] = []
    confirmed_working_directory = ""
    candidates_by_compound: Dict[int, str] = {}
    for observation in observations:
        if not isinstance(observation, dict):
            continue
        observed_cwd = _clean(observation.get("working_directory_observed"))
        compound_index = int(observation.get("compound_command_index") or 0)
        if observed_cwd.startswith("/"):
            effective, cwd_status = observed_cwd, "observed"
        elif candidates_by_compound.get(compound_index):
            effective = candidates_by_compound[compound_index]
            cwd_status = "conditional_candidate"
        elif confirmed_working_directory:
            effective = confirmed_working_directory
            cwd_status = "confirmed"
        else:
            effective, cwd_status = "", "unknown"
        extracted = extract_typed_semantics(
            observation,
            working_directory=effective,
            working_directory_status=cwd_status,
            policy=policy,
        )
        outcome = _outcome(observation, transfer=False)
        operations = _typed_operations(
            extracted,
            outcome,
            policy,
            _clean(observation.get("evidence_id")),
        )
        context, next_confirmed, compound_candidate = _directory_context(
            observation,
            extracted,
            effective=effective,
            effective_status=cwd_status,
        )
        if next_confirmed:
            confirmed_working_directory = next_confirmed
        if compound_candidate:
            candidates_by_compound[compound_index] = compound_candidate
        references = _evidence_references(observation)
        entities = deepcopy(extracted["entities"])
        abstentions = _texts([
            *extracted["parse"]["abstention_reasons"],
            *(
                ["identity_unresolved"]
                if any(
                    entity.get("uncertain") is True
                    for values in entities.values()
                    for entity in values
                )
                else []
            ),
        ])
        content = {
            "schema_version": FACT_SCHEMA,
            "source_observation_ref": _clean(observation.get("evidence_id")),
            "evidence_type": _clean(observation.get("evidence_type")),
            "sequence_index": observation.get("sequence_index"),
            "source_index": observation.get("source_index"),
            "timestamp": _clean(observation.get("timestamp")),
            "cowrie_eventid": _clean(observation.get("cowrie_eventid")),
            "parse": extracted["parse"],
            "operations": operations,
            "outcome": outcome,
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
            "working_directory_context": context,
            "path_resolutions": _path_resolutions(
                entities,
                effective,
                cwd_status,
            ),
            "attck_candidate_refs": [],
            "evidence_references": references,
            "supporting_evidence_refs": _texts(
                item["evidence_ref"] for item in references
            ),
            "duplicate_of": _clean(observation.get("duplicate_of")),
            "abstention_reasons": abstentions,
            "semantic_authority": "shadow_non_authoritative",
        }
        facts.append({
            "fact_id": stable_id("typed_semantic_fact", content),
            **content,
        })
    return facts


def _transfer_facts(
    observations: List[Dict[str, Any]],
    policy: Dict[str, Any],
) -> List[Dict[str, Any]]:
    facts: List[Dict[str, Any]] = []
    for observation in observations:
        if not isinstance(observation, dict):
            continue
        working_directory = _clean(observation.get("working_directory_observed"))
        cwd_status = (
            "observed" if working_directory.startswith("/") else "unknown"
        )
        extracted = extract_transfer_semantics(
            observation,
            working_directory=working_directory,
            working_directory_status=cwd_status,
            policy=policy,
        )
        outcome = _outcome(observation, transfer=True)
        operations = _typed_operations(
            extracted,
            outcome,
            policy,
            _clean(observation.get("evidence_id")),
        )
        references = _evidence_references(observation)
        entities = deepcopy(extracted["entities"])
        content = {
            "schema_version": FACT_SCHEMA,
            "source_observation_ref": _clean(observation.get("evidence_id")),
            "evidence_type": _clean(observation.get("evidence_type")),
            "sequence_index": observation.get("source_index"),
            "source_index": observation.get("source_index"),
            "timestamp": _clean(observation.get("timestamp")),
            "cowrie_eventid": _clean(observation.get("eventid")),
            "parse": extracted["parse"],
            "operations": operations,
            "outcome": outcome,
            "entities": entities,
            "shell_context": {
                "command": "",
                "original_command": "",
                "compound_command_index": None,
                "fragment_index": None,
                "fragment_count": None,
                "operator_before": "",
                "operator_after": "",
                "pipe_producer": "",
                "pipe_consumer": "",
                "conditional_execution": {},
            },
            "working_directory_context": {
                "observed": working_directory,
                "effective": working_directory,
                "status": cwd_status,
                "directory_change": {
                    "original_target": "",
                    "resolved_target": "",
                    "status": "none",
                },
            },
            "path_resolutions": _path_resolutions(
                entities,
                working_directory,
                cwd_status,
            ),
            "attck_candidate_refs": [],
            "evidence_references": references,
            "supporting_evidence_refs": _texts(
                item["evidence_ref"] for item in references
            ),
            "duplicate_of": "",
            "abstention_reasons": [],
            "semantic_authority": "shadow_non_authoritative",
        }
        facts.append({
            "fact_id": stable_id("typed_semantic_fact", content),
            **content,
        })
    return facts


def _attck_candidates(
    observed: Dict[str, Any],
    facts: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Bind classification candidates without making labels semantic facts.

    Candidate identity deliberately excludes ``fact_refs``.  Facts refer to
    candidates and candidates resolve back to final fact IDs, so including
    both reference lists in both content-addressed identities would create an
    impossible hash cycle.
    """

    output: List[Dict[str, Any]] = []
    for candidate in observed.get("ordered_behavior_chain") or []:
        if not isinstance(candidate, dict):
            continue
        command = _clean(candidate.get("command"))
        timestamp = _clean(candidate.get("timestamp"))
        exact = [
            fact
            for fact in facts
            if fact["shell_context"]["command"] == command
            and (
                not timestamp
                or not fact["timestamp"]
                or fact["timestamp"] == timestamp
            )
        ]
        if exact:
            scope = "fragment_exact"
            matched = exact
        else:
            compound = [
                fact
                for fact in facts
                if fact["shell_context"]["original_command"] == command
                and (
                    not timestamp
                    or not fact["timestamp"]
                    or fact["timestamp"] == timestamp
                )
            ]
            if compound:
                scope = "compound_command"
                matched = compound
            else:
                scope = "unresolved_command"
                matched = []
        identity = {
            "source_evidence_ref": _clean(candidate.get("evidence_id")),
            "technique_id": _clean(candidate.get("ttp")),
            "tactic": _clean(candidate.get("tactic")),
            "source": _clean(candidate.get("source")),
            "agreement_status": _clean(candidate.get("agreement_status")),
            "mapping_scope": scope,
            "proof_scope": "classification_candidate",
            "may_define_operations": False,
        }
        candidate_id = stable_id("typed_attck_candidate", identity)
        for fact in matched:
            fact["attck_candidate_refs"].append(candidate_id)
        output.append({
            "candidate_id": candidate_id,
            **identity,
            "fact_refs": [],
        })

    # Candidate IDs are now stable, so facts can be finalized exactly once.
    for fact in facts:
        content = {key: value for key, value in fact.items() if key != "fact_id"}
        fact["fact_id"] = stable_id("typed_semantic_fact", content)

    for candidate in output:
        candidate["fact_refs"] = [
            fact["fact_id"]
            for fact in facts
            if candidate["candidate_id"] in fact["attck_candidate_refs"]
        ]
    return output


def _operation_ids(
    fact: Dict[str, Any],
    effects: Iterable[str] = (),
) -> List[str]:
    wanted = set(effects)
    return [
        operation["operation_id"]
        for operation in fact.get("operations") or []
        if not wanted or operation.get("effect") in wanted
    ]


def _relationship(
    relationship_type: str,
    source: Dict[str, Any],
    target: Dict[str, Any],
    *,
    source_operation_ids: Iterable[str],
    target_operation_ids: Iterable[str],
    entity_ref: str = "",
    path_identity_id: str = "",
    status: str,
    proof_scope: str,
    basis: Iterable[str],
    abstention_reasons: Iterable[str] = (),
    connects_chain: bool = True,
) -> Dict[str, Any]:
    content = {
        "schema_version": RELATIONSHIP_SCHEMA,
        "relationship_type": relationship_type,
        "source_fact_id": source["fact_id"],
        "target_fact_id": target["fact_id"],
        "source_operation_ids": _texts(source_operation_ids),
        "target_operation_ids": _texts(target_operation_ids),
        "entity_ref": _clean(entity_ref),
        "path_identity_id": _clean(path_identity_id),
        "status": status,
        "proof_scope": proof_scope,
        "basis": _texts(basis),
        "abstention_reasons": _texts(abstention_reasons),
        "connects_chain": bool(connects_chain),
        "causality_semantics": "evidence_link_not_causal_or_intent_proof",
    }
    return {
        "relationship_id": stable_id("typed_semantic_relationship", content),
        **content,
    }


def _shell_relationships(facts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    output: List[Dict[str, Any]] = []
    by_compound: Dict[int, List[Dict[str, Any]]] = {}
    for fact in facts:
        compound = fact["shell_context"]["compound_command_index"]
        if compound is not None:
            by_compound.setdefault(int(compound), []).append(fact)
    for items in by_compound.values():
        items.sort(
            key=lambda item: (
                int(item["shell_context"]["fragment_index"] or 0),
                int(item.get("sequence_index") or 0),
            )
        )
        for previous, current in zip(items, items[1:]):
            operator = current["shell_context"]["operator_before"]
            if operator == "|":
                output.append(_relationship(
                    "piped_to",
                    previous,
                    current,
                    source_operation_ids=_operation_ids(previous),
                    target_operation_ids=_operation_ids(current),
                    status="supported",
                    proof_scope="shell_syntax",
                    basis=["explicit_pipe_operator", "adjacent_fragments"],
                ))
            elif operator in {"&&", "||"}:
                condition = (
                    current["shell_context"].get("conditional_execution") or {}
                ).get("status")
                if condition == "condition_satisfied":
                    status, scope, connects, reasons = (
                        "supported",
                        "fragment_outcome",
                        True,
                        [],
                    )
                elif condition == "condition_not_satisfied":
                    status, scope, connects, reasons = (
                        "blocked",
                        "fragment_outcome",
                        False,
                        ["condition_not_satisfied"],
                    )
                else:
                    status, scope, connects, reasons = (
                        "partial",
                        "compound_outcome",
                        True,
                        ["source_effect_unconfirmed"],
                    )
                output.append(_relationship(
                    (
                        "conditional_successor"
                        if operator == "&&"
                        else "conditional_failure_successor"
                    ),
                    previous,
                    current,
                    source_operation_ids=_operation_ids(previous),
                    target_operation_ids=_operation_ids(current),
                    status=status,
                    proof_scope=scope,
                    basis=["explicit_shell_operator", "adjacent_fragments"],
                    abstention_reasons=reasons,
                    connects_chain=connects,
                ))
            elif operator in {";", "\n"}:
                output.append(_relationship(
                    "explicit_sequence",
                    previous,
                    current,
                    source_operation_ids=_operation_ids(previous),
                    target_operation_ids=_operation_ids(current),
                    status="supported",
                    proof_scope="shell_syntax",
                    basis=["explicit_sequence_operator"],
                    connects_chain=False,
                ))
    return output


_PATH_TRANSITIONS = {
    ("attempt_transfer", "modify_metadata"),
    ("attempt_transfer", "modify"),
    ("attempt_transfer", "attempt_execution"),
    ("attempt_transfer", "observed_transfer"),
    ("observed_transfer", "modify_metadata"),
    ("observed_transfer", "modify"),
    ("observed_transfer", "attempt_execution"),
    ("create_or_truncate", "modify_metadata"),
    ("create_or_truncate", "modify"),
    ("create_or_truncate", "attempt_execution"),
    ("append_or_create", "modify"),
    ("append_or_create", "attempt_execution"),
    ("create_archive", "attempt_execution"),
    ("modify_metadata", "attempt_execution"),
    ("modify", "attempt_execution"),
    ("attempt_execution", "delete"),
}


def _path_relationships(
    facts: List[Dict[str, Any]],
    max_relationships: int,
    current_count: int,
) -> List[Dict[str, Any]]:
    records: Dict[str, List[Tuple[Dict[str, Any], Dict[str, Any]]]] = {}
    for fact in facts:
        for resolution in fact.get("path_resolutions") or []:
            value = _clean(resolution.get("candidate_normalized_value"))
            if value:
                records.setdefault(value, []).append((fact, resolution))
    output: List[Dict[str, Any]] = []
    for path_value, items in records.items():
        items.sort(
            key=lambda item: (
                int(item[0].get("sequence_index") or 0),
                int(item[0].get("source_index") or 0),
            )
        )
        for source_index, (source, source_resolution) in enumerate(items):
            for target, target_resolution in items[source_index + 1 :]:
                source_ops = [
                    operation
                    for operation in source.get("operations") or []
                    if any(
                        (
                            operation.get("effect"),
                            target_operation.get("effect"),
                        )
                        in _PATH_TRANSITIONS
                        for target_operation in target.get("operations") or []
                    )
                ]
                target_ops = [
                    operation
                    for operation in target.get("operations") or []
                    if any(
                        (
                            source_operation.get("effect"),
                            operation.get("effect"),
                        )
                        in _PATH_TRANSITIONS
                        for source_operation in source.get("operations") or []
                    )
                ]
                if not source_ops or not target_ops:
                    continue
                resolved = (
                    source_resolution["resolution_status"]
                    in {"recorded_resolved", "context_resolved"}
                    and target_resolution["resolution_status"]
                    in {"recorded_resolved", "context_resolved"}
                )
                source_confirmed = all(
                    operation["effect_status"]
                    in {"reported_completed", "event_observed"}
                    for operation in source_ops
                )
                target_confirmed = all(
                    operation["effect_status"]
                    in {"reported_completed", "event_observed"}
                    for operation in target_ops
                )
                reasons: List[str] = []
                if not resolved:
                    reasons.append("identity_unresolved")
                if not source_confirmed:
                    reasons.append("source_effect_unconfirmed")
                if not target_confirmed:
                    reasons.append("target_effect_unconfirmed")
                status = "supported" if not reasons else "partial"
                proof_scope = (
                    "shared_resolved_identity"
                    if resolved
                    else "shared_conditional_identity"
                )
                transfer_confirmation = any(
                    source_operation["effect"] == "attempt_transfer"
                    for source_operation in source_ops
                ) and any(
                    target_operation["effect"] == "observed_transfer"
                    for target_operation in target_ops
                )
                output.append(_relationship(
                    (
                        "transfer_observation_confirmation"
                        if transfer_confirmation
                        else "same_path_transition"
                    ),
                    source,
                    target,
                    source_operation_ids=[
                        operation["operation_id"] for operation in source_ops
                    ],
                    target_operation_ids=[
                        operation["operation_id"] for operation in target_ops
                    ],
                    entity_ref=(
                        target_resolution["entity_ref"] if resolved else ""
                    ),
                    path_identity_id=stable_id(
                        (
                            "typed_path_identity"
                            if resolved
                            else "typed_path_candidate"
                        ),
                        {"path": path_value},
                    ),
                    status=status,
                    proof_scope=proof_scope,
                    basis=[
                        "same_session",
                        "chronological_order",
                        (
                            "shared_resolved_path"
                            if resolved
                            else "shared_conditional_path_candidate"
                        ),
                    ],
                    abstention_reasons=reasons,
                ))
                if current_count + len(output) > max_relationships:
                    raise TypedSemanticFactError(
                        "typed semantic relationship limit exceeded"
                    )
    return output


def _relationships(
    facts: List[Dict[str, Any]],
    limits: Dict[str, int],
) -> List[Dict[str, Any]]:
    shell = _shell_relationships(facts)
    if len(shell) > limits["max_relationships"]:
        raise TypedSemanticFactError(
            "typed semantic relationship limit exceeded"
        )
    paths = _path_relationships(
        facts,
        limits["max_relationships"],
        len(shell),
    )
    unique: Dict[str, Dict[str, Any]] = {}
    for item in shell + paths:
        unique.setdefault(item["relationship_id"], item)
    return list(unique.values())


def _aggregate_entities(facts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    output: Dict[str, Dict[str, Any]] = {}
    for fact in facts:
        for role, values in fact.get("entities", {}).items():
            for entity in values:
                entity_id = entity["entity_id"]
                aggregated = output.setdefault(entity_id, {
                    **deepcopy(entity),
                    "roles": [],
                    "fact_refs": [],
                    "variants": [],
                })
                if role not in aggregated["roles"]:
                    aggregated["roles"].append(role)
                if fact["fact_id"] not in aggregated["fact_refs"]:
                    aggregated["fact_refs"].append(fact["fact_id"])
                variant = {
                    "fact_ref": fact["fact_id"],
                    "role": role,
                    "entity": deepcopy(entity),
                }
                if variant not in aggregated["variants"]:
                    aggregated["variants"].append(variant)
    return sorted(
        output.values(),
        key=lambda item: (
            item["entity_type"],
            item["normalized_value"],
            item["entity_id"],
        ),
    )


def _chains(
    facts: List[Dict[str, Any]],
    relationships: List[Dict[str, Any]],
    max_chains: int,
) -> List[Dict[str, Any]]:
    fact_by_id = {fact["fact_id"]: fact for fact in facts}
    connecting = [
        relationship
        for relationship in relationships
        if relationship["connects_chain"] and relationship["status"] != "blocked"
    ]
    adjacency: Dict[str, set[str]] = {
        fact_id: set() for fact_id in fact_by_id
    }
    for relationship in connecting:
        source = relationship["source_fact_id"]
        target = relationship["target_fact_id"]
        adjacency[source].add(target)
        adjacency[target].add(source)
    output: List[Dict[str, Any]] = []
    visited: set[str] = set()
    for fact_id, neighbours in adjacency.items():
        if fact_id in visited or not neighbours:
            continue
        stack = [fact_id]
        component: set[str] = set()
        while stack:
            current = stack.pop()
            if current in component:
                continue
            component.add(current)
            stack.extend(adjacency[current] - component)
        visited.update(component)
        component_relationships = [
            relationship
            for relationship in connecting
            if relationship["source_fact_id"] in component
            and relationship["target_fact_id"] in component
        ]
        ordered_facts = sorted(
            (fact_by_id[item] for item in component),
            key=lambda item: (
                int(item.get("sequence_index") or 0),
                int(item.get("source_index") or 0),
            ),
        )
        operation_refs = _texts(
            operation["operation_id"]
            for fact in ordered_facts
            for operation in fact["operations"]
        )
        reasons = _texts(
            reason
            for relationship in component_relationships
            for reason in relationship["abstention_reasons"]
        )
        partial_effect = any(
            operation["effect_status"]
            not in {"reported_completed", "event_observed"}
            for fact in ordered_facts
            for operation in fact["operations"]
            if operation["operation_type"] != "unknown"
        )
        status = (
            "partial"
            if reasons
            or partial_effect
            or any(
                relationship["status"] != "supported"
                for relationship in component_relationships
            )
            else "supported"
        )
        content = {
            "schema_version": CHAIN_SCHEMA,
            "status": status,
            "fact_refs": [fact["fact_id"] for fact in ordered_facts],
            "relationship_refs": [
                relationship["relationship_id"]
                for relationship in component_relationships
            ],
            "entity_refs": _texts(
                relationship["entity_ref"]
                for relationship in component_relationships
            ),
            "operation_refs": operation_refs,
            "proof_scopes": _texts(
                relationship["proof_scope"]
                for relationship in component_relationships
            ),
            "abstention_reasons": reasons,
        }
        output.append({
            "chain_id": stable_id("typed_semantic_chain", content),
            **content,
        })
        if len(output) > max_chains:
            raise TypedSemanticFactError(
                "typed semantic chain limit exceeded"
            )
    return output


def _evidence_index(
    facts: List[Dict[str, Any]],
    candidates: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    indexed: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for fact in facts:
        for reference in fact["evidence_references"]:
            key = (
                reference["evidence_ref"],
                reference["reference_type"],
            )
            indexed.setdefault(key, {
                "evidence_ref": key[0],
                "reference_type": key[1],
            })
    for candidate in candidates:
        key = (
            candidate["source_evidence_ref"],
            "trusted_classification",
        )
        if key[0]:
            indexed.setdefault(key, {
                "evidence_ref": key[0],
                "reference_type": key[1],
            })
    return sorted(
        indexed.values(),
        key=lambda item: (item["evidence_ref"], item["reference_type"]),
    )


def _comparison(
    observed: Dict[str, Any],
    facts: List[Dict[str, Any]],
    relationships: List[Dict[str, Any]],
    chains: List[Dict[str, Any]],
    entities: List[Dict[str, Any]],
    candidates: List[Dict[str, Any]],
) -> Dict[str, Any]:
    source_observations = [
        item
        for item in (
            list(observed.get("ordered_command_observations") or [])
            + list(observed.get("transfer_event_observations") or [])
        )
        if isinstance(item, dict)
    ]
    source_refs = [
        _clean(item.get("evidence_id")) for item in source_observations
    ]
    fact_refs = [
        _clean(fact.get("source_observation_ref")) for fact in facts
    ]
    differences: List[str] = []
    if source_refs != fact_refs:
        differences.append("source_observation_identity_mismatch")
    return {
        "status": "exact_source_coverage" if not differences else "mismatch",
        "difference_codes": differences,
        "source_observation_count": len(source_observations),
        "typed_fact_count": len(facts),
        "source_relationship_count": len(
            observed.get("behavior_relationships") or []
        ),
        "typed_relationship_count": len(relationships),
        "source_chain_count": len(
            observed.get("connected_behavior_chains") or []
        ),
        "typed_chain_count": len(chains),
        "entity_count": len(entities),
        "attck_candidate_count": len(candidates),
        "unknown_operation_count": sum(
            any(
                operation["operation_type"] == "unknown"
                for operation in fact["operations"]
            )
            for fact in facts
        ),
        "abstention_count": sum(bool(fact["abstention_reasons"]) for fact in facts),
        "partial_relationship_count": sum(
            relationship["status"] == "partial"
            for relationship in relationships
        ),
        "blocked_relationship_count": sum(
            relationship["status"] == "blocked"
            for relationship in relationships
        ),
    }


def _verify_provenance(
    provenance: Dict[str, Any],
    loaded_vocabulary: Dict[str, Any],
) -> None:
    errors: List[str] = []
    if not _exact_keys(
        provenance,
        _PROVENANCE_KEYS,
        "provenance",
        errors,
    ):
        raise TypedSemanticFactError("; ".join(errors))
    for key in (
        "canonical_evidence_sha256",
        "source_evidence_sha256",
        "semantic_input_sha256",
        "behavior_policy_sha256",
        "classification_policy_sha256",
    ):
        if not SHA256_RE.fullmatch(_clean(provenance.get(key)).lower()):
            errors.append(f"provenance.{key} is invalid")
    if not GIT_REVISION_RE.fullmatch(
        _clean(provenance.get("evaluator_git_revision")).lower()
    ):
        errors.append("provenance.evaluator_git_revision is invalid")
    expected_vocabulary = vocabulary_summary(loaded_vocabulary)
    if provenance.get("semantic_vocabulary") != expected_vocabulary:
        errors.append("provenance semantic vocabulary does not match policy")
    if errors:
        raise TypedSemanticFactError("; ".join(errors))


def build_typed_semantic_fact_set(
    observed: Dict[str, Any],
    *,
    provenance: Dict[str, Any],
    vocabulary_path: str = "",
) -> Dict[str, Any]:
    """Build deterministic facts with one closed family-scoped activation."""

    loaded = load_typed_semantic_vocabulary(vocabulary_path)
    if loaded.get("status") != "valid":
        raise TypedSemanticFactError(
            "typed semantic vocabulary is missing or invalid"
        )
    _verify_provenance(provenance, loaded)
    if provenance["semantic_input_sha256"] != _sha256_json(
        _semantic_input(observed)
    ):
        raise TypedSemanticFactError(
            "typed semantic input does not match bound provenance"
        )
    policy = loaded["document"]
    limits = policy["limits"]
    commands = [
        _clean(item.get("command"))
        for item in observed.get("ordered_command_observations") or []
        if isinstance(item, dict)
    ]
    observation_count = len(commands) + len(
        observed.get("transfer_event_observations") or []
    )
    total_command_bytes = sum(
        len(command.encode("utf-8")) for command in commands
    )
    if observation_count > limits["max_facts"]:
        raise TypedSemanticFactError("typed semantic fact limit exceeded")
    if any(
        len(command.encode("utf-8")) > limits["max_command_length"]
        for command in commands
    ):
        raise TypedSemanticFactError(
            "typed semantic command length limit exceeded"
        )
    if total_command_bytes > limits["max_total_command_bytes"]:
        raise TypedSemanticFactError(
            "typed semantic aggregate command limit exceeded"
        )

    facts = _command_facts(
        deepcopy(observed.get("ordered_command_observations") or []),
        policy,
    ) + _transfer_facts(
        deepcopy(observed.get("transfer_event_observations") or []),
        policy,
    )
    candidates = _attck_candidates(observed, facts)
    relationships = _relationships(facts, limits)
    entities = _aggregate_entities(facts)
    if len(entities) > limits["max_entities"]:
        raise TypedSemanticFactError("typed semantic entity limit exceeded")
    chains = _chains(facts, relationships, limits["max_chains"])
    comparison = _comparison(
        observed,
        facts,
        relationships,
        chains,
        entities,
        candidates,
    )
    result = {
        "schema_version": FACT_SET_SCHEMA,
        "status": "valid",
        "session_id": _clean(observed.get("session_id")) or "unknown",
        "mode": "family_scoped_policy_input",
        "authority": deepcopy(_AUTHORITY),
        "provenance": deepcopy(provenance),
        "limits": {
            "fact_count": len(facts),
            "entity_count": len(entities),
            "relationship_count": len(relationships),
            "chain_count": len(chains),
            "total_command_bytes": total_command_bytes,
            "within_policy_limits": True,
        },
        "facts": facts,
        "entities": entities,
        "relationships": relationships,
        "chains": chains,
        "attck_candidates": candidates,
        "evidence_index": _evidence_index(facts, candidates),
        "shadow_comparison": comparison,
    }
    result["fact_set_sha256"] = _sha256_json(result)
    errors = validate_typed_semantic_fact_set(
        result,
        vocabulary_path=vocabulary_path,
    )
    if errors:
        raise TypedSemanticFactError(
            "typed semantic fact set validation failed: " + "; ".join(errors)
        )
    return result


def _validate_entity(
    value: Any,
    *,
    label: str,
    entity_types: set[str],
    uncertainty_reasons: set[str],
    errors: List[str],
    aggregate: bool,
) -> str:
    expected = _AGGREGATE_ENTITY_KEYS if aggregate else _ENTITY_KEYS
    if not _exact_keys(value, expected, label, errors):
        return ""
    entity_id = _clean(value.get("entity_id"))
    if not entity_id:
        errors.append(f"{label}.entity_id is required")
    if value.get("entity_type") not in entity_types:
        errors.append(f"{label}.entity_type is outside the vocabulary")
    if type(value.get("uncertain")) is not bool:
        errors.append(f"{label}.uncertain must be boolean")
    if type(value.get("linkable")) is not bool:
        errors.append(f"{label}.linkable must be boolean")
    if type(value.get("redacted_components")) is not bool:
        errors.append(f"{label}.redacted_components must be boolean")
    if value.get("uncertain") is True and value.get("linkable") is True:
        errors.append(f"{label} cannot be uncertain and linkable")
    if value.get("uncertainty_reason") not in uncertainty_reasons:
        errors.append(f"{label}.uncertainty_reason is outside the vocabulary")
    if (
        value.get("uncertain") is True
        and value.get("uncertainty_reason") == "none"
    ):
        errors.append(f"{label} uncertain entity requires a reason")
    if (
        value.get("uncertain") is False
        and value.get("uncertainty_reason") != "none"
    ):
        errors.append(f"{label} resolved entity may not retain uncertainty")
    for key in (
        "normalized_value",
        "original_value",
        "uncertainty_reason",
        "candidate_normalized_value",
        "source_entity_ref",
    ):
        if not isinstance(value.get(key), str):
            errors.append(f"{label}.{key} must be a string")
    if aggregate:
        for key in ("roles", "fact_refs"):
            if (
                not isinstance(value.get(key), list)
                or any(not isinstance(item, str) for item in value.get(key))
            ):
                errors.append(f"{label}.{key} must be a string list")
        if not isinstance(value.get("variants"), list):
            errors.append(f"{label}.variants must be a list")
    entity_type = _clean(value.get("entity_type"))
    normalized_value = value.get("normalized_value")
    normalized = (
        normalized_value if isinstance(normalized_value, str) else ""
    )
    identity_value = (
        normalized
        if value.get("linkable") is True
        else f"unresolved:{normalized}"
    )
    expected_id = stable_id(
        "typed_semantic_entity",
        {"type": entity_type, "value": identity_value},
    )
    if entity_id and entity_id != expected_id:
        errors.append(f"{label}.entity_id mismatch")
    return entity_id


def validate_typed_semantic_fact_set(
    value: Any,
    *,
    vocabulary_path: str = "",
) -> List[str]:
    """Validate all semantic values, identities, references, and provenance."""

    errors: List[str] = []
    loaded = load_typed_semantic_vocabulary(vocabulary_path)
    if loaded.get("status") != "valid":
        return ["typed semantic vocabulary is missing or invalid"]
    policy = loaded["document"]
    vocabulary = policy["vocabulary"]
    contract = policy["contract"]
    if not _exact_keys(value, _TOP_KEYS, "fact_set", errors):
        if not isinstance(value, dict):
            return errors
    if value.get("schema_version") != contract["fact_set_schema"]:
        errors.append("fact_set schema_version is invalid")
    if value.get("status") != "valid":
        errors.append("fact_set status must be valid")
    if value.get("mode") != "family_scoped_policy_input":
        errors.append("fact_set mode must be family_scoped_policy_input")
    if value.get("authority") != _AUTHORITY:
        errors.append("fact_set authority is invalid")
    if not _clean(value.get("session_id")):
        errors.append("session_id is required")
    hash_input = deepcopy(value)
    recorded_hash = _clean(hash_input.pop("fact_set_sha256", "")).lower()
    if (
        not SHA256_RE.fullmatch(recorded_hash)
        or recorded_hash != _sha256_json(hash_input)
    ):
        errors.append("fact_set_sha256 mismatch")

    provenance = value.get("provenance")
    if _exact_keys(
        provenance,
        _PROVENANCE_KEYS,
        "provenance",
        errors,
    ):
        for key in (
            "canonical_evidence_sha256",
            "source_evidence_sha256",
            "semantic_input_sha256",
            "behavior_policy_sha256",
            "classification_policy_sha256",
        ):
            if not SHA256_RE.fullmatch(_clean(provenance.get(key)).lower()):
                errors.append(f"provenance.{key} is invalid")
        if not GIT_REVISION_RE.fullmatch(
            _clean(provenance.get("evaluator_git_revision")).lower()
        ):
            errors.append("provenance.evaluator_git_revision is invalid")
        summary = provenance.get("semantic_vocabulary")
        if _exact_keys(
            summary,
            _VOCABULARY_SUMMARY_KEYS,
            "provenance.semantic_vocabulary",
            errors,
        ) and summary != vocabulary_summary(loaded):
            errors.append("semantic vocabulary provenance mismatch")

    allowed_entity_types = set(vocabulary["entity_types"])
    allowed_uncertainty_reasons = set(
        vocabulary["entity_uncertainty_reasons"]
    )
    allowed_entity_roles = set(vocabulary["entity_roles"])
    aggregate_entities = value.get("entities")
    if not isinstance(aggregate_entities, list):
        errors.append("entities must be a list")
        aggregate_entities = []
    entity_by_id: Dict[str, Dict[str, Any]] = {}
    for index, entity in enumerate(aggregate_entities):
        entity_id = _validate_entity(
            entity,
            label=f"entities[{index}]",
            entity_types=allowed_entity_types,
            uncertainty_reasons=allowed_uncertainty_reasons,
            errors=errors,
            aggregate=True,
        )
        if entity_id in entity_by_id:
            errors.append(f"entities[{index}] has duplicate entity_id")
        elif entity_id:
            entity_by_id[entity_id] = entity
        if isinstance(entity, dict) and any(
            role not in allowed_entity_roles
            for role in entity.get("roles") or []
        ):
            errors.append(f"entities[{index}] has an unknown role")
        if isinstance(entity, dict):
            for variant_index, variant in enumerate(
                entity.get("variants") or []
            ):
                variant_label = (
                    f"entities[{index}].variants[{variant_index}]"
                )
                if not _exact_keys(
                    variant,
                    _ENTITY_VARIANT_KEYS,
                    variant_label,
                    errors,
                ):
                    continue
                if variant.get("fact_ref") not in entity.get(
                    "fact_refs", []
                ):
                    errors.append(
                        f"{variant_label}.fact_ref is not aggregated"
                    )
                if variant.get("role") not in entity.get("roles", []):
                    errors.append(
                        f"{variant_label}.role is not aggregated"
                    )
                variant_entity = variant.get("entity")
                variant_id = _validate_entity(
                    variant_entity,
                    label=f"{variant_label}.entity",
                    entity_types=allowed_entity_types,
                    uncertainty_reasons=allowed_uncertainty_reasons,
                    errors=errors,
                    aggregate=False,
                )
                if variant_id != entity_id:
                    errors.append(
                        f"{variant_label}.entity does not match aggregate"
                    )

    facts = value.get("facts")
    if not isinstance(facts, list):
        errors.append("facts must be a list")
        facts = []
    fact_by_id: Dict[str, Dict[str, Any]] = {}
    operation_by_id: Dict[str, Dict[str, Any]] = {}
    allowed_operations = policy["operations"]
    allowed_proof = set(vocabulary["proof_scopes"])
    allowed_effect_status = set(vocabulary["effect_statuses"])
    allowed_outcome_status = set(vocabulary["outcome_statuses"])
    allowed_outcome_scope = set(vocabulary["outcome_scopes"])
    allowed_parse = set(vocabulary["parse_statuses"])
    allowed_reasons = set(vocabulary["abstention_reasons"])
    allowed_path_status = set(vocabulary["path_resolution_statuses"])
    allowed_cwd = set(vocabulary["working_directory_statuses"])
    allowed_change = set(vocabulary["directory_change_statuses"])
    allowed_reference_types = set(vocabulary["evidence_reference_types"])

    for fact_index, fact in enumerate(facts):
        label = f"facts[{fact_index}]"
        if not _exact_keys(fact, _FACT_KEYS, label, errors):
            continue
        fact_id = _clean(fact.get("fact_id"))
        content = {key: item for key, item in fact.items() if key != "fact_id"}
        if not fact_id or fact_id in fact_by_id:
            errors.append(f"{label}.fact_id is missing or duplicated")
        elif fact_id != stable_id("typed_semantic_fact", content):
            errors.append(f"{label}.fact_id mismatch")
        else:
            fact_by_id[fact_id] = fact
        if fact.get("schema_version") != contract["fact_schema"]:
            errors.append(f"{label}.schema_version is invalid")
        if fact.get("semantic_authority") != "shadow_non_authoritative":
            errors.append(f"{label}.semantic_authority is invalid")
        if fact.get("evidence_type") not in set(
            vocabulary["evidence_types"]
        ):
            errors.append(f"{label}.evidence_type is invalid")
        for key in ("sequence_index", "source_index"):
            if (
                fact.get(key) is not None
                and type(fact.get(key)) is not int
            ):
                errors.append(f"{label}.{key} must be an integer or null")
        if not _clean(fact.get("source_observation_ref")):
            errors.append(f"{label}.source_observation_ref is required")
        for key in ("timestamp", "cowrie_eventid", "duplicate_of"):
            if not isinstance(fact.get(key), str):
                errors.append(f"{label}.{key} must be a string")

        parse = fact.get("parse")
        if _exact_keys(parse, _PARSE_KEYS, f"{label}.parse", errors):
            if parse.get("status") not in allowed_parse:
                errors.append(f"{label}.parse.status is invalid")
            reasons = parse.get("abstention_reasons")
            if (
                not isinstance(reasons, list)
                or any(reason not in allowed_reasons for reason in reasons)
            ):
                errors.append(f"{label}.parse.abstention_reasons is invalid")
            for key in ("executable",):
                if not isinstance(parse.get(key), str):
                    errors.append(f"{label}.parse.{key} must be a string")
            if not isinstance(parse.get("arguments"), list) or any(
                not isinstance(item, str) for item in parse.get("arguments") or []
            ):
                errors.append(f"{label}.parse.arguments must be a string list")
            redirects = parse.get("redirections")
            if not isinstance(redirects, list):
                errors.append(f"{label}.parse.redirections must be a list")
            else:
                for redirect_index, redirect in enumerate(redirects):
                    redirect_label = (
                        f"{label}.parse.redirections[{redirect_index}]"
                    )
                    if _exact_keys(
                        redirect,
                        _REDIRECT_KEYS,
                        redirect_label,
                        errors,
                    ):
                        if redirect.get("operator") not in {"<", ">", ">>"}:
                            errors.append(
                                f"{redirect_label}.operator is invalid"
                            )

        fact_entities = fact.get("entities")
        if not isinstance(fact_entities, dict) or set(fact_entities) != allowed_entity_roles:
            errors.append(f"{label}.entities must contain every allowed role")
            fact_entities = {}
        fact_entity_ids: set[str] = set()
        for role, role_entities in fact_entities.items():
            if not isinstance(role_entities, list):
                errors.append(f"{label}.entities.{role} must be a list")
                continue
            for entity_index, entity in enumerate(role_entities):
                entity_id = _validate_entity(
                    entity,
                    label=f"{label}.entities.{role}[{entity_index}]",
                    entity_types=allowed_entity_types,
                    uncertainty_reasons=allowed_uncertainty_reasons,
                    errors=errors,
                    aggregate=False,
                )
                if entity_id:
                    fact_entity_ids.add(entity_id)
                    if entity.get("entity_type") != policy[
                        "entity_role_types"
                    ].get(role):
                        errors.append(
                            f"{label}.entities.{role}[{entity_index}] "
                            "has the wrong entity type"
                        )
                    aggregate = entity_by_id.get(entity_id)
                    if not aggregate:
                        errors.append(
                            f"{label} references an unknown aggregate entity"
                        )
                    else:
                        matching_variant = {
                            "fact_ref": fact_id,
                            "role": role,
                            "entity": entity,
                        }
                        if matching_variant not in aggregate.get(
                            "variants", []
                        ):
                            errors.append(
                                f"{label} entity lacks an aggregate variant"
                            )
                        if role not in aggregate.get("roles", []):
                            errors.append(
                                f"{label} entity role is absent from aggregate"
                            )
                        if fact_id not in aggregate.get("fact_refs", []):
                            errors.append(
                                f"{label} is absent from aggregate fact_refs"
                            )

        operations = fact.get("operations")
        if not isinstance(operations, list) or not operations:
            errors.append(f"{label}.operations must be a non-empty list")
            operations = []
        unknown_count = 0
        for operation_index, operation in enumerate(operations):
            operation_label = f"{label}.operations[{operation_index}]"
            if not _exact_keys(
                operation,
                _OPERATION_KEYS,
                operation_label,
                errors,
            ):
                continue
            operation_type = operation.get("operation_type")
            definition = allowed_operations.get(operation_type)
            if not definition:
                errors.append(f"{operation_label}.operation_type is invalid")
                continue
            if operation.get("family") != definition["family"]:
                errors.append(f"{operation_label}.family is invalid")
            if operation.get("effect") != definition["effect"]:
                errors.append(f"{operation_label}.effect is invalid")
            if operation.get("proof_scope") not in allowed_proof:
                errors.append(f"{operation_label}.proof_scope is invalid")
            if operation.get("proof_scope") not in {
                "unresolved",
                "literal_command",
                "general_command_semantics",
                "shell_syntax",
                "direct_cowrie_event",
            }:
                errors.append(
                    f"{operation_label}.proof_scope cannot prove an operation"
                )
            if operation.get("effect_status") not in allowed_effect_status:
                errors.append(f"{operation_label}.effect_status is invalid")
            entity_refs = operation.get("entity_refs")
            if (
                not isinstance(entity_refs, list)
                or any(
                    not isinstance(reference, str)
                    or reference not in fact_entity_ids
                    for reference in entity_refs or []
                )
            ):
                errors.append(f"{operation_label}.entity_refs is invalid")
            literal_action = operation.get("source_literal_action")
            if not isinstance(literal_action, str):
                errors.append(
                    f"{operation_label}.source_literal_action must be a string"
                )
            elif literal_action and (
                policy["literal_action_map"].get(literal_action)
                != operation_type
            ):
                errors.append(
                    f"{operation_label}.source_literal_action is invalid"
                )
            identity_content = {
                key: operation[key]
                for key in _OPERATION_KEYS
                if key != "operation_id"
            }
            identity_content["source_observation_ref"] = fact.get(
                "source_observation_ref"
            )
            identity_content["sequence_index"] = operation_index
            operation_id = _clean(operation.get("operation_id"))
            if operation_id != stable_id(
                "typed_semantic_operation",
                identity_content,
            ):
                errors.append(f"{operation_label}.operation_id mismatch")
            elif operation_id in operation_by_id:
                errors.append(f"{operation_label}.operation_id is duplicated")
            else:
                operation_by_id[operation_id] = operation
            if operation_type == "unknown":
                unknown_count += 1
                if (
                    operation.get("family") != "unknown"
                    or operation.get("effect") != "unknown"
                    or operation.get("proof_scope") != "unresolved"
                    or operation.get("effect_status") != "abstained"
                    or operation.get("entity_refs")
                    or operation.get("source_literal_action")
                ):
                    errors.append(
                        f"{operation_label} promotes unknown semantics"
                    )
        if unknown_count and len(operations) != 1:
            errors.append(f"{label} mixes unknown with promoted operations")

        outcome = fact.get("outcome")
        if _exact_keys(outcome, _OUTCOME_KEYS, f"{label}.outcome", errors):
            if outcome.get("status") not in allowed_outcome_status:
                errors.append(f"{label}.outcome.status is invalid")
            if outcome.get("scope") not in allowed_outcome_scope:
                errors.append(f"{label}.outcome.scope is invalid")
            if outcome.get("proof_scope") not in allowed_proof:
                errors.append(f"{label}.outcome.proof_scope is invalid")
            for key in ("source_eventid", "semantics"):
                if not isinstance(outcome.get(key), str):
                    errors.append(f"{label}.outcome.{key} must be a string")
            if outcome.get("status") == "reported_failure" and any(
                operation.get("effect_status") == "reported_completed"
                for operation in operations
            ):
                errors.append(
                    f"{label} promotes a failed action to a completed effect"
                )
            for operation_index, operation in enumerate(operations):
                operation_type = _clean(operation.get("operation_type"))
                if operation_type in allowed_operations and (
                    operation.get("effect_status")
                    != _effect_status(operation_type, outcome)
                ):
                    errors.append(
                        f"{label}.operations[{operation_index}]."
                        "effect_status does not match the observed outcome"
                    )
            expected_semantics = (
                "direct_cowrie_transfer_observation_not_real_host_effect"
                if outcome.get("status") == "event_observed"
                else "cowrie_command_outcome_not_real_host_effect_proof"
            )
            if outcome.get("semantics") != expected_semantics:
                errors.append(f"{label}.outcome.semantics is invalid")

        shell = fact.get("shell_context")
        if _exact_keys(shell, _SHELL_KEYS, f"{label}.shell_context", errors):
            for key in (
                "command",
                "original_command",
                "operator_before",
                "operator_after",
                "pipe_producer",
                "pipe_consumer",
            ):
                if not isinstance(shell.get(key), str):
                    errors.append(
                        f"{label}.shell_context.{key} must be a string"
                    )
            if not isinstance(shell.get("conditional_execution"), dict):
                errors.append(
                    f"{label}.shell_context.conditional_execution must be an object"
                )
            conditional = shell.get("conditional_execution")
            if isinstance(conditional, dict) and conditional:
                if _exact_keys(
                    conditional,
                    _CONDITIONAL_KEYS,
                    f"{label}.shell_context.conditional_execution",
                    errors,
                ):
                    if conditional.get("operator") not in {"&&", "||"}:
                        errors.append(
                            f"{label} conditional operator is invalid"
                        )
                    if conditional.get("status") not in {
                        "condition_unknown",
                        "condition_satisfied",
                        "condition_not_satisfied",
                    }:
                        errors.append(
                            f"{label} conditional status is invalid"
                        )
                    if conditional.get("semantics") != (
                        "shell_condition_not_fragment_execution_proof"
                    ):
                        errors.append(
                            f"{label} conditional semantics is invalid"
                        )
            if shell.get("operator_before") not in {
                "",
                "|",
                "&&",
                "||",
                ";",
                "\n",
            }:
                errors.append(f"{label}.operator_before is invalid")
            if shell.get("operator_after") not in {
                "",
                "|",
                "&&",
                "||",
                ";",
                "\n",
            }:
                errors.append(f"{label}.operator_after is invalid")

        cwd = fact.get("working_directory_context")
        if _exact_keys(
            cwd,
            _WORKING_DIRECTORY_KEYS,
            f"{label}.working_directory_context",
            errors,
        ):
            if cwd.get("status") not in allowed_cwd:
                errors.append(
                    f"{label}.working_directory_context.status is invalid"
                )
            for key in ("observed", "effective"):
                if not isinstance(cwd.get(key), str):
                    errors.append(
                        f"{label}.working_directory_context.{key} must be a string"
                    )
            change = cwd.get("directory_change")
            if _exact_keys(
                change,
                _DIRECTORY_CHANGE_KEYS,
                f"{label}.working_directory_context.directory_change",
                errors,
            ):
                if change.get("status") not in allowed_change:
                    errors.append(
                        f"{label} directory change status is invalid"
                    )
                if change.get("status") == "failed" and change.get(
                    "resolved_target"
                ) and cwd.get("effective") == change.get("resolved_target"):
                    errors.append(
                        f"{label} failed directory change became effective"
                    )

        resolutions = fact.get("path_resolutions")
        if not isinstance(resolutions, list):
            errors.append(f"{label}.path_resolutions must be a list")
            resolutions = []
        for resolution_index, resolution in enumerate(resolutions):
            resolution_label = (
                f"{label}.path_resolutions[{resolution_index}]"
            )
            if not _exact_keys(
                resolution,
                _PATH_RESOLUTION_KEYS,
                resolution_label,
                errors,
            ):
                continue
            if resolution.get("resolution_status") not in allowed_path_status:
                errors.append(
                    f"{resolution_label}.resolution_status is invalid"
                )
            if resolution.get("proof_scope") not in allowed_proof:
                errors.append(f"{resolution_label}.proof_scope is invalid")
            if resolution.get("entity_ref") not in fact_entity_ids:
                errors.append(f"{resolution_label}.entity_ref is unresolved")
            if resolution.get("role") not in allowed_entity_roles:
                errors.append(f"{resolution_label}.role is invalid")
            entity = next(
                (
                    item
                    for values in fact_entities.values()
                    for item in values
                    if item.get("entity_id")
                    == resolution.get("entity_ref")
                ),
                None,
            )
            if entity and entity.get("entity_type") != "path":
                errors.append(
                    f"{resolution_label} references a non-path entity"
                )
            if (
                resolution.get("resolution_status")
                == "conditional_candidate"
                and resolution.get("path_identity_id")
            ):
                errors.append(
                    f"{resolution_label} promotes conditional identity"
                )
            if (
                resolution.get("resolution_status") == "unresolved"
                and (
                    resolution.get("path_identity_id")
                    or resolution.get("candidate_identity_id")
                )
            ):
                errors.append(
                    f"{resolution_label} promotes unresolved identity"
                )
            raw_candidate_value = resolution.get(
                "candidate_normalized_value"
            )
            candidate_value = (
                raw_candidate_value
                if isinstance(raw_candidate_value, str)
                else ""
            )
            expected_path_id = (
                stable_id("typed_path_identity", {"path": candidate_value})
                if candidate_value
                and resolution.get("resolution_status")
                in {"recorded_resolved", "context_resolved"}
                else ""
            )
            expected_candidate_id = (
                stable_id("typed_path_candidate", {"path": candidate_value})
                if candidate_value
                and resolution.get("resolution_status")
                == "conditional_candidate"
                else ""
            )
            if resolution.get("path_identity_id") != expected_path_id:
                errors.append(
                    f"{resolution_label}.path_identity_id mismatch"
                )
            if (
                resolution.get("candidate_identity_id")
                != expected_candidate_id
            ):
                errors.append(
                    f"{resolution_label}.candidate_identity_id mismatch"
                )

        evidence_references = fact.get("evidence_references")
        if not isinstance(evidence_references, list) or not evidence_references:
            errors.append(f"{label}.evidence_references must be non-empty")
            evidence_references = []
        source_reference_found = False
        for reference_index, reference in enumerate(evidence_references):
            reference_label = (
                f"{label}.evidence_references[{reference_index}]"
            )
            if not _exact_keys(
                reference,
                _EVIDENCE_REFERENCE_KEYS,
                reference_label,
                errors,
            ):
                continue
            if reference.get("reference_type") not in allowed_reference_types:
                errors.append(
                    f"{reference_label}.reference_type is invalid"
                )
            if reference.get("proof_scope") not in allowed_proof:
                errors.append(f"{reference_label}.proof_scope is invalid")
            if (
                reference.get("reference_type") == "source_observation"
                and reference.get("evidence_ref")
                == fact.get("source_observation_ref")
            ):
                source_reference_found = True
        if not source_reference_found:
            errors.append(f"{label} lacks its source observation reference")
        expected_supporting = _texts(
            reference.get("evidence_ref")
            for reference in evidence_references
            if isinstance(reference, dict)
        )
        if fact.get("supporting_evidence_refs") != expected_supporting:
            errors.append(f"{label}.supporting_evidence_refs mismatch")
        if any(
            reason not in allowed_reasons
            for reason in fact.get("abstention_reasons") or []
        ):
            errors.append(f"{label}.abstention_reasons is invalid")
        if not isinstance(fact.get("attck_candidate_refs"), list) or any(
            not isinstance(item, str)
            for item in fact.get("attck_candidate_refs") or []
        ):
            errors.append(f"{label}.attck_candidate_refs is invalid")

    try:
        expected_entities = _aggregate_entities(facts)
        if aggregate_entities != expected_entities:
            errors.append(
                "entities do not match deterministic fact aggregation"
            )
    except (KeyError, TypeError, ValueError):
        errors.append("entities could not be deterministically rebuilt")

    candidate_values = value.get("attck_candidates")
    if not isinstance(candidate_values, list):
        errors.append("attck_candidates must be a list")
        candidate_values = []
    candidate_by_id: Dict[str, Dict[str, Any]] = {}
    allowed_mapping_scope = set(vocabulary["attck_mapping_scopes"])
    for index, candidate in enumerate(candidate_values):
        label = f"attck_candidates[{index}]"
        if not _exact_keys(candidate, _ATTCK_KEYS, label, errors):
            continue
        content = {
            key: item
            for key, item in candidate.items()
            if key not in {"candidate_id", "fact_refs"}
        }
        candidate_id = _clean(candidate.get("candidate_id"))
        if candidate_id != stable_id("typed_attck_candidate", content):
            errors.append(f"{label}.candidate_id mismatch")
        elif candidate_id in candidate_by_id:
            errors.append(f"{label}.candidate_id is duplicated")
        else:
            candidate_by_id[candidate_id] = candidate
        if candidate.get("mapping_scope") not in allowed_mapping_scope:
            errors.append(f"{label}.mapping_scope is invalid")
        if candidate.get("proof_scope") != "classification_candidate":
            errors.append(f"{label}.proof_scope is invalid")
        if candidate.get("may_define_operations") is not False:
            errors.append(f"{label} may not define operations")
        if any(
            reference not in fact_by_id
            for reference in candidate.get("fact_refs") or []
        ):
            errors.append(f"{label}.fact_refs is unresolved")
        if (
            candidate.get("mapping_scope") == "unresolved_command"
            and candidate.get("fact_refs")
        ):
            errors.append(f"{label} promotes an unresolved mapping")
        if not _clean(candidate.get("source_evidence_ref")):
            errors.append(f"{label}.source_evidence_ref is required")
        if not re.fullmatch(
            r"T[0-9]{4}(?:\.[0-9]{3})?",
            _clean(candidate.get("technique_id")),
        ):
            errors.append(f"{label}.technique_id is invalid")
        for key in ("tactic", "source", "agreement_status"):
            if not isinstance(candidate.get(key), str):
                errors.append(f"{label}.{key} must be a string")
    for fact_index, fact in enumerate(facts):
        if any(
            candidate_ref not in candidate_by_id
            for candidate_ref in fact.get("attck_candidate_refs") or []
        ):
            errors.append(
                f"facts[{fact_index}].attck_candidate_refs is unresolved"
            )
        for candidate_ref in fact.get("attck_candidate_refs") or []:
            candidate = candidate_by_id.get(candidate_ref)
            if candidate and fact.get("fact_id") not in candidate.get(
                "fact_refs", []
            ):
                errors.append(
                    f"facts[{fact_index}] ATT&CK reference is not reciprocal"
                )
    for index, candidate in enumerate(candidate_values):
        for fact_ref in candidate.get("fact_refs") or []:
            fact = fact_by_id.get(fact_ref)
            if fact and candidate.get("candidate_id") not in fact.get(
                "attck_candidate_refs", []
            ):
                errors.append(
                    f"attck_candidates[{index}] fact reference is not reciprocal"
                )

    relationships = value.get("relationships")
    if not isinstance(relationships, list):
        errors.append("relationships must be a list")
        relationships = []
    relationship_by_id: Dict[str, Dict[str, Any]] = {}
    allowed_relationship_type = set(vocabulary["relationship_types"])
    allowed_relationship_status = set(vocabulary["relationship_statuses"])
    for index, relationship in enumerate(relationships):
        label = f"relationships[{index}]"
        if not _exact_keys(
            relationship,
            _RELATIONSHIP_KEYS,
            label,
            errors,
        ):
            continue
        content = {
            key: item
            for key, item in relationship.items()
            if key != "relationship_id"
        }
        relationship_id = _clean(relationship.get("relationship_id"))
        if relationship_id != stable_id(
            "typed_semantic_relationship",
            content,
        ):
            errors.append(f"{label}.relationship_id mismatch")
        elif relationship_id in relationship_by_id:
            errors.append(f"{label}.relationship_id is duplicated")
        else:
            relationship_by_id[relationship_id] = relationship
        if relationship.get("schema_version") != contract["relationship_schema"]:
            errors.append(f"{label}.schema_version is invalid")
        if relationship.get("relationship_type") not in allowed_relationship_type:
            errors.append(f"{label}.relationship_type is invalid")
        if relationship.get("status") not in allowed_relationship_status:
            errors.append(f"{label}.status is invalid")
        if relationship.get("proof_scope") not in allowed_proof:
            errors.append(f"{label}.proof_scope is invalid")
        if (
            not isinstance(relationship.get("basis"), list)
            or any(
                basis not in set(vocabulary["relationship_bases"])
                for basis in relationship.get("basis") or []
            )
        ):
            errors.append(f"{label}.basis is invalid")
        if type(relationship.get("connects_chain")) is not bool:
            errors.append(f"{label}.connects_chain must be boolean")
        if relationship.get("causality_semantics") != (
            "evidence_link_not_causal_or_intent_proof"
        ):
            errors.append(f"{label}.causality_semantics is invalid")
        if relationship.get("source_fact_id") not in fact_by_id:
            errors.append(f"{label}.source_fact_id is unresolved")
        if relationship.get("target_fact_id") not in fact_by_id:
            errors.append(f"{label}.target_fact_id is unresolved")
        for key in ("source_operation_ids", "target_operation_ids"):
            if any(
                operation_id not in operation_by_id
                for operation_id in relationship.get(key) or []
            ):
                errors.append(f"{label}.{key} is unresolved")
        source_fact = fact_by_id.get(relationship.get("source_fact_id"))
        target_fact = fact_by_id.get(relationship.get("target_fact_id"))
        if source_fact and not set(
            relationship.get("source_operation_ids") or []
        ).issubset({
            item["operation_id"]
            for item in source_fact.get("operations") or []
        }):
            errors.append(
                f"{label}.source_operation_ids do not belong to source fact"
            )
        if target_fact and not set(
            relationship.get("target_operation_ids") or []
        ).issubset({
            item["operation_id"]
            for item in target_fact.get("operations") or []
        }):
            errors.append(
                f"{label}.target_operation_ids do not belong to target fact"
            )
        entity_ref = _clean(relationship.get("entity_ref"))
        if entity_ref and entity_ref not in entity_by_id:
            errors.append(f"{label}.entity_ref is unresolved")
        if any(
            reason not in allowed_reasons
            for reason in relationship.get("abstention_reasons") or []
        ):
            errors.append(f"{label}.abstention_reasons is invalid")
        if (
            relationship.get("proof_scope") == "shared_conditional_identity"
            and relationship.get("status") == "supported"
        ):
            errors.append(f"{label} promotes conditional identity")
    try:
        if relationships != _relationships(facts, policy["limits"]):
            errors.append(
                "relationships do not match deterministic whole-session rebuild"
            )
    except (KeyError, TypeError, ValueError, TypedSemanticFactError):
        errors.append("relationships could not be deterministically rebuilt")

    chains = value.get("chains")
    if not isinstance(chains, list):
        errors.append("chains must be a list")
        chains = []
    chain_ids: set[str] = set()
    allowed_chain_status = set(vocabulary["chain_statuses"])
    for index, chain in enumerate(chains):
        label = f"chains[{index}]"
        if not _exact_keys(chain, _CHAIN_KEYS, label, errors):
            continue
        content = {
            key: item for key, item in chain.items() if key != "chain_id"
        }
        chain_id = _clean(chain.get("chain_id"))
        if chain_id != stable_id("typed_semantic_chain", content):
            errors.append(f"{label}.chain_id mismatch")
        elif chain_id in chain_ids:
            errors.append(f"{label}.chain_id is duplicated")
        chain_ids.add(chain_id)
        if chain.get("schema_version") != contract["chain_schema"]:
            errors.append(f"{label}.schema_version is invalid")
        if chain.get("status") not in allowed_chain_status:
            errors.append(f"{label}.status is invalid")
        if any(
            reference not in fact_by_id
            for reference in chain.get("fact_refs") or []
        ):
            errors.append(f"{label}.fact_refs is unresolved")
        if any(
            reference not in relationship_by_id
            for reference in chain.get("relationship_refs") or []
        ):
            errors.append(f"{label}.relationship_refs is unresolved")
        if any(
            reference not in entity_by_id
            for reference in chain.get("entity_refs") or []
        ):
            errors.append(f"{label}.entity_refs is unresolved")
        if any(
            reference not in operation_by_id
            for reference in chain.get("operation_refs") or []
        ):
            errors.append(f"{label}.operation_refs is unresolved")
        if any(
            scope not in allowed_proof
            for scope in chain.get("proof_scopes") or []
        ):
            errors.append(f"{label}.proof_scopes is invalid")
        if any(
            reason not in allowed_reasons
            for reason in chain.get("abstention_reasons") or []
        ):
            errors.append(f"{label}.abstention_reasons is invalid")
        if chain.get("status") == "supported" and any(
            relationship_by_id[reference]["status"] != "supported"
            for reference in chain.get("relationship_refs") or []
            if reference in relationship_by_id
        ):
            errors.append(f"{label} promotes a partial relationship")
    try:
        if chains != _chains(
            facts,
            relationships,
            policy["limits"]["max_chains"],
        ):
            errors.append("chains do not match deterministic rebuild")
    except (KeyError, TypeError, ValueError, TypedSemanticFactError):
        errors.append("chains could not be deterministically rebuilt")

    evidence_index = value.get("evidence_index")
    if not isinstance(evidence_index, list):
        errors.append("evidence_index must be a list")
        evidence_index = []
    indexed: set[Tuple[str, str]] = set()
    for index, item in enumerate(evidence_index):
        label = f"evidence_index[{index}]"
        if not _exact_keys(item, _EVIDENCE_INDEX_KEYS, label, errors):
            continue
        reference_type = item.get("reference_type")
        key = (_clean(item.get("evidence_ref")), reference_type)
        if not key[0] or reference_type not in allowed_reference_types:
            errors.append(f"{label} is invalid")
        if key in indexed:
            errors.append(f"{label} is duplicated")
        indexed.add(key)
    for fact_index, fact in enumerate(facts):
        for reference in fact.get("evidence_references") or []:
            key = (
                _clean(reference.get("evidence_ref")),
                reference.get("reference_type"),
            )
            if key not in indexed:
                errors.append(
                    f"facts[{fact_index}] has an unindexed evidence reference"
                )
    for index, candidate in enumerate(candidate_values):
        if (
            _clean(candidate.get("source_evidence_ref")),
            "trusted_classification",
        ) not in indexed:
            errors.append(
                f"attck_candidates[{index}] has an unindexed evidence reference"
            )
    if evidence_index != _evidence_index(facts, candidate_values):
        errors.append("evidence_index does not match deterministic rebuild")

    limits = value.get("limits")
    if _exact_keys(limits, _LIMIT_SUMMARY_KEYS, "limits", errors):
        expected_counts = {
            "fact_count": len(facts),
            "entity_count": len(aggregate_entities),
            "relationship_count": len(relationships),
            "chain_count": len(chains),
        }
        for key, expected in expected_counts.items():
            if limits.get(key) != expected:
                errors.append(f"limits.{key} mismatch")
            policy_key = {
                "fact_count": "max_facts",
                "entity_count": "max_entities",
                "relationship_count": "max_relationships",
                "chain_count": "max_chains",
            }[key]
            if expected > policy["limits"][policy_key]:
                errors.append(f"limits.{key} exceeds policy")
        if (
            type(limits.get("total_command_bytes")) is not int
            or limits.get("total_command_bytes") < 0
            or limits.get("total_command_bytes")
            > policy["limits"]["max_total_command_bytes"]
        ):
            errors.append("limits.total_command_bytes is invalid")
        if limits.get("within_policy_limits") is not True:
            errors.append("limits.within_policy_limits must be true")

    comparison = value.get("shadow_comparison")
    if _exact_keys(
        comparison,
        _COMPARISON_KEYS,
        "shadow_comparison",
        errors,
    ):
        if comparison.get("status") != "exact_source_coverage":
            errors.append("shadow comparison does not cover source observations")
        if comparison.get("difference_codes") != []:
            errors.append("shadow comparison contains differences")
        expected_comparison = {
            "typed_fact_count": len(facts),
            "typed_relationship_count": len(relationships),
            "typed_chain_count": len(chains),
            "entity_count": len(aggregate_entities),
            "attck_candidate_count": len(candidate_values),
        }
        for key, expected in expected_comparison.items():
            if comparison.get(key) != expected:
                errors.append(f"shadow_comparison.{key} mismatch")
    return errors


def build_typed_semantic_shadow_diff(
    observed: Dict[str, Any],
    fact_set: Dict[str, Any],
) -> Dict[str, Any]:
    """Return deterministic diagnostics for direct review callers only."""

    source_by_ref = {
        _clean(item.get("evidence_id")): item
        for item in (
            list(observed.get("ordered_command_observations") or [])
            + list(observed.get("transfer_event_observations") or [])
        )
        if isinstance(item, dict) and _clean(item.get("evidence_id"))
    }
    source_output = [
        {
            "source_observation_ref": reference,
            "literal_action_types": _texts(
                item.get("action_types") or []
            ),
        }
        for reference, item in source_by_ref.items()
    ]
    typed_output = [
        {
            "fact_id": fact["fact_id"],
            "source_observation_ref": fact["source_observation_ref"],
            "operation_types": [
                operation["operation_type"]
                for operation in fact["operations"]
            ],
            "abstention_reasons": list(fact["abstention_reasons"]),
        }
        for fact in fact_set.get("facts") or []
    ]
    blocked_matches = [
        {
            "relationship_id": relationship["relationship_id"],
            "status": relationship["status"],
            "proof_scope": relationship["proof_scope"],
            "abstention_reasons": list(
                relationship["abstention_reasons"]
            ),
        }
        for relationship in fact_set.get("relationships") or []
        if relationship["status"] != "supported"
    ]
    abstentions = [
        {
            "fact_id": fact["fact_id"],
            "reasons": list(fact["abstention_reasons"]),
        }
        for fact in fact_set.get("facts") or []
        if fact["abstention_reasons"]
    ]
    families = _texts(
        operation["family"]
        for fact in fact_set.get("facts") or []
        for operation in fact["operations"]
        if operation["operation_type"] != "unknown"
    )
    result = {
        "schema_version": SHADOW_DIFF_SCHEMA,
        "session_id": fact_set.get("session_id"),
        "fact_set_sha256": fact_set.get("fact_set_sha256"),
        "source_output": source_output,
        "typed_output": typed_output,
        "blocked_matches": blocked_matches,
        "abstentions": abstentions,
        "policy_impact": {
            "authoritative_change": "sensitive_read_only",
            "candidate_operation_families": families,
            "activation_state": "family_scoped",
        },
    }
    result["shadow_diff_sha256"] = _sha256_json(result)
    return result


def validate_typed_semantic_shadow_diff(value: Any) -> List[str]:
    """Validate the direct-caller diagnostic without granting it authority."""

    errors: List[str] = []
    if not _exact_keys(value, _SHADOW_DIFF_KEYS, "shadow_diff", errors):
        return errors
    digest_input = deepcopy(value)
    recorded = _clean(digest_input.pop("shadow_diff_sha256", "")).lower()
    if not SHA256_RE.fullmatch(recorded) or recorded != _sha256_json(
        digest_input
    ):
        errors.append("shadow_diff_sha256 mismatch")
    if value.get("schema_version") != SHADOW_DIFF_SCHEMA:
        errors.append("shadow_diff.schema_version is invalid")
    if not _clean(value.get("session_id")):
        errors.append("shadow_diff.session_id is required")
    if not SHA256_RE.fullmatch(
        _clean(value.get("fact_set_sha256")).lower()
    ):
        errors.append("shadow_diff.fact_set_sha256 is invalid")
    shapes = {
        "source_output": {
            "source_observation_ref",
            "literal_action_types",
        },
        "typed_output": {
            "fact_id",
            "source_observation_ref",
            "operation_types",
            "abstention_reasons",
        },
        "blocked_matches": {
            "relationship_id",
            "status",
            "proof_scope",
            "abstention_reasons",
        },
        "abstentions": {"fact_id", "reasons"},
    }
    for key, expected in shapes.items():
        values = value.get(key)
        if not isinstance(values, list):
            errors.append(f"shadow_diff.{key} must be a list")
            continue
        for index, item in enumerate(values):
            _exact_keys(
                item,
                expected,
                f"shadow_diff.{key}[{index}]",
                errors,
            )
    impact = value.get("policy_impact")
    if _exact_keys(
        impact,
        {
            "authoritative_change",
            "candidate_operation_families",
            "activation_state",
        },
        "shadow_diff.policy_impact",
        errors,
    ):
        if impact.get("authoritative_change") != "sensitive_read_only":
            errors.append("shadow_diff policy impact is invalid")
        if impact.get("activation_state") != "family_scoped":
            errors.append("shadow_diff activation state is invalid")
    return errors


def validate_typed_semantic_shadow_result(value: Any) -> List[str]:
    """Validate the small discarded runtime result."""

    errors: List[str] = []
    if not _exact_keys(value, _SHADOW_RESULT_KEYS, "shadow_result", errors):
        return errors
    if value.get("schema_version") != SHADOW_RESULT_SCHEMA:
        errors.append("shadow_result.schema_version is invalid")
    if value.get("status") not in {"valid", "unavailable"}:
        errors.append("shadow_result.status is invalid")
    if value.get("authoritative") is not False:
        errors.append("shadow_result must remain non-authoritative")
    if value.get("persistence") != "discarded":
        errors.append("shadow_result persistence is invalid")
    if not isinstance(value.get("validation_errors"), list) or any(
        not isinstance(item, str)
        for item in value.get("validation_errors") or []
    ):
        errors.append("shadow_result.validation_errors is invalid")
    if not isinstance(value.get("error_type"), str):
        errors.append("shadow_result.error_type must be a string")
    if value.get("status") == "valid":
        for key in ("fact_set_sha256", "shadow_diff_sha256"):
            if not SHA256_RE.fullmatch(_clean(value.get(key)).lower()):
                errors.append(f"shadow_result.{key} is invalid")
        if not isinstance(value.get("comparison"), dict):
            errors.append("shadow_result.comparison must be an object")
        if value.get("error_type") or value.get("validation_errors"):
            errors.append("valid shadow_result may not contain errors")
    return errors


def render_typed_semantic_shadow_diff(diff: Dict[str, Any]) -> str:
    """Render deterministic review text without becoming a report artifact."""

    lines = [
        "# Typed semantic shadow diff",
        "",
        f"Session: `{_clean(diff.get('session_id'))}`",
        f"Fact set: `{_clean(diff.get('fact_set_sha256'))}`",
        "Authority impact: `sensitive_read_only`",
        "",
        "## Typed facts",
    ]
    for item in diff.get("typed_output") or []:
        operations = ", ".join(item.get("operation_types") or []) or "unknown"
        reasons = ", ".join(item.get("abstention_reasons") or []) or "none"
        lines.append(
            f"- `{item.get('fact_id')}`: {operations}; abstention={reasons}"
        )
    lines.extend(["", "## Blocked or partial matches"])
    for item in diff.get("blocked_matches") or []:
        reasons = ", ".join(item.get("abstention_reasons") or []) or "none"
        lines.append(
            f"- `{item.get('relationship_id')}`: "
            f"{item.get('status')} ({item.get('proof_scope')}); {reasons}"
        )
    if not diff.get("blocked_matches"):
        lines.append("- none")
    return "\n".join(lines) + "\n"


def run_typed_semantic_shadow(
    observed: Dict[str, Any],
    *,
    canonical_evidence: Dict[str, Any],
    behavior_policy_sha256: str,
    classification_policy_sha256: str,
    evaluator_git_revision: str,
    vocabulary_path: str = "",
) -> Dict[str, Any]:
    """Build and validate facts while returning no authoritative payload."""

    try:
        provenance = build_typed_semantic_provenance(
            canonical_evidence,
            observed_behavior=observed,
            behavior_policy_sha256=behavior_policy_sha256,
            classification_policy_sha256=classification_policy_sha256,
            evaluator_git_revision=evaluator_git_revision,
            vocabulary_path=vocabulary_path,
        )
        fact_set = build_typed_semantic_fact_set(
            observed,
            provenance=provenance,
            vocabulary_path=vocabulary_path,
        )
        shadow_diff = build_typed_semantic_shadow_diff(observed, fact_set)
        if validate_typed_semantic_shadow_diff(shadow_diff):
            raise TypedSemanticFactError(
                "shadow diff validation failed"
            )
        result = {
            "schema_version": SHADOW_RESULT_SCHEMA,
            "status": "valid",
            "fact_set_sha256": fact_set["fact_set_sha256"],
            "shadow_diff_sha256": shadow_diff["shadow_diff_sha256"],
            "comparison": deepcopy(fact_set["shadow_comparison"]),
            "validation_errors": [],
            "error_type": "",
            "authoritative": False,
            "persistence": "discarded",
        }
        validation_errors = validate_typed_semantic_shadow_result(result)
        if validation_errors:
            raise TypedSemanticFactError(
                "shadow result validation failed"
            )
        return result
    except Exception as exc:  # pragma: no cover - defensive shadow containment
        return {
            "schema_version": SHADOW_RESULT_SCHEMA,
            "status": "unavailable",
            "fact_set_sha256": "",
            "shadow_diff_sha256": "",
            "comparison": {},
            "validation_errors": [],
            "error_type": exc.__class__.__name__,
            "authoritative": False,
            "persistence": "discarded",
        }
