"""Evaluate additional bounded hypotheses and review guidance offline.

This module consumes the same validated typed facts and chain selector as the
canonical assessment. It never mutates a report or grants response authority.
"""

from __future__ import annotations

from typing import Any

from production.policies.threat_hypothesis_behavior_policy import (
    load_behavior_policy,
    policy_body,
)
from production.reporting.typed_semantic_chain_selection import (
    select_typed_semantic_chains,
)
from production.reporting.typed_semantic_facts import validate_typed_semantic_fact_set
from production.utils.serialization import stable_id


SCHEMA_VERSION = "research.bounded_hypothesis_guidance_candidate.v1"
_FILE_PREPARATION = {
    "rule_id": "research-file-write-permission-execution",
    "required_operation_types": ["file_write", "permission_modify", "execution_attempt"],
    "minimum_incomplete_operation_count": 2,
    "same_entity_required": True,
    "required_transition_types": ["same_path_transition"],
}
_TRANSFER_EXECUTION = {
    "rule_id": "research-transfer-execution",
    "required_operation_types": ["transfer_attempt", "execution_attempt"],
    "minimum_incomplete_operation_count": 1,
    "same_entity_required": True,
    "required_transition_types": ["same_path_transition"],
}
_EXECUTION_DELETE = {
    "rule_id": "research-execution-delete",
    "required_operation_types": ["execution_attempt", "file_delete"],
    "minimum_incomplete_operation_count": 1,
    "same_entity_required": True,
    "required_transition_types": ["same_path_transition"],
}


def _confirmed_operation(fact: dict[str, Any], operation_type: str) -> bool:
    return (
        (fact.get("outcome") or {}).get("status") == "reported_success"
        and (fact.get("outcome") or {}).get("scope") == "fragment"
        and any(
            operation.get("operation_type") == operation_type
            and operation.get("effect_status") == "reported_completed"
            for operation in fact.get("operations") or []
        )
    )


def _evidence_refs(fact: dict[str, Any]) -> list[str]:
    return sorted({
        str(item.get("evidence_ref"))
        for item in fact.get("evidence_references") or []
        if item.get("reference_type") in {"source_observation", "direct_cowrie_event"}
        and item.get("evidence_ref")
    })


def _resolved_change_path_ids(fact: dict[str, Any]) -> set[str]:
    if fact.get("abstention_reasons"):
        return set()
    entities = fact.get("entities") or {}
    return {
        str(entity["entity_id"])
        for role in ("created_paths", "modified_paths", "destination_paths")
        for entity in entities.get(role) or []
        if entity.get("entity_id")
        and entity.get("entity_type") == "path"
        and entity.get("linkable") is True
        and entity.get("uncertain") is False
    }


def _candidate(kind: str, match: dict[str, Any], *, alternatives: list[str],
               falsifiers: list[str], gap: str) -> dict[str, Any]:
    basis = {
        "kind": kind,
        "chain_id": match["chain_id"],
        "entity_ref": match["entity_ref"],
        "fact_refs": match["fact_refs"],
        "relationship_refs": match["relationship_refs"],
    }
    return {
        "candidate_id": stable_id("research_hypothesis", basis),
        "kind": kind,
        "status": "UNVERIFIED_RESEARCH_CANDIDATE",
        "alternatives": alternatives,
        "evidence_gap": gap,
        "falsification_conditions": falsifiers,
        "fact_refs": list(match["fact_refs"]),
        "relationship_refs": list(match["relationship_refs"]),
        "evidence_refs": list(match["supporting_evidence_refs"]),
        "entity_ref": match["entity_ref"],
        "chronology_quality": match["chronology_quality"],
        "limitations": [
            "Cowrie command outcomes do not prove effects on a real host.",
            "A shared path and chronological order do not establish intent or causality.",
        ],
    }


def _guidance(kind: str, fact_refs: list[str], evidence_refs: list[str],
              relationship_refs: list[str], description: str, why_selected: str,
              review_sources: list[str], confirming_evidence: str,
              disconfirming_evidence: str, entity_ref: str) -> dict[str, Any]:
    basis = {"kind": kind, "facts": fact_refs, "relationships": relationship_refs,
             "entity_ref": entity_ref}
    return {
        "candidate_id": stable_id("research_guidance", basis),
        "kind": kind,
        "status": "RESEARCH_REVIEW_SUGGESTION",
        "description": description,
        "why_selected": why_selected,
        "review_sources": review_sources,
        "confirming_evidence": confirming_evidence,
        "disconfirming_evidence": disconfirming_evidence,
        "fact_refs": fact_refs,
        "relationship_refs": relationship_refs,
        "evidence_refs": evidence_refs,
        "entity_ref": entity_ref,
        "requires_manual_approval": True,
        "safe_to_auto_execute": False,
        "execution_integration": "not_implemented",
    }


def evaluate_candidate(fact_set: dict[str, Any]) -> dict[str, Any]:
    """Produce bounded candidates from validated Cowrie facts only."""

    errors = validate_typed_semantic_fact_set(fact_set)
    if errors:
        raise ValueError("invalid typed fact set: " + "; ".join(errors))
    baseline_policy = load_behavior_policy()
    if not policy_body(baseline_policy).get("enabled"):
        raise ValueError("baseline behavior policy is unavailable")
    baseline_rules = policy_body(baseline_policy)["claims"]["typed_connected"]
    finding_rules = [rule for rule in baseline_rules if rule.get("hypothesis_only") is not True]
    selected = select_typed_semantic_chains(
        fact_set, [*baseline_rules, _FILE_PREPARATION, _TRANSFER_EXECUTION, _EXECUTION_DELETE]
    )
    matches = selected["matches"]
    established_entities = {
        match["entity_ref"]
        for match in matches
        if match["rule_id"] in {rule["rule_id"] for rule in finding_rules}
    }
    # A direct transfer event anywhere in the session is not enough to bind
    # its hash to this path. Abstain rather than call it an unconfirmed fetch.
    direct_transfer_present = any(
        any(op.get("operation_type") == "transfer_observed" for op in fact.get("operations") or [])
        for fact in fact_set.get("facts") or []
    )
    hypotheses = []
    guidance = []
    for match in matches:
        kind = match["rule_id"]
        if not match.get("entity_ref") or match["chronology_quality"] != "timestamp_supported":
            continue
        if kind == _FILE_PREPARATION["rule_id"] and match["status"] == "incomplete":
            if match["entity_ref"] not in established_entities:
                hypotheses.append(_candidate(
                    "file_preparation_without_execution", match,
                    alternatives=[
                        "The observed write and permission change may prepare a file for later use.",
                        "The same sequence may be ordinary file maintenance or may stop here.",
                    ],
                    falsifiers=[
                        "A failed write or permission operation weakens the sequence.",
                        "A later exact-path execution changes the evidence state.",
                    ],
                    gap="No supported execution attempt for the same resolved path was observed.",
                ))
        elif kind == _TRANSFER_EXECUTION["rule_id"] and match["status"] == "complete":
            if not direct_transfer_present and match["entity_ref"] not in established_entities:
                hypotheses.append(_candidate(
                    "execution_after_unconfirmed_transfer", match,
                    alternatives=[
                        "The operator may have attempted to use content requested from the remote source.",
                        "The fetch may have failed and the execution attempt may refer to a pre-existing file.",
                    ],
                    falsifiers=[
                        "A bound direct transfer event changes the transfer evidence state.",
                        "A failed fetch or unavailable file weakens a linked-transfer explanation.",
                    ],
                    gap="No direct Cowrie transfer observation binds received bytes to the executed path.",
                ))
        elif kind == _EXECUTION_DELETE["rule_id"] and match["status"] == "complete":
            guidance.append(_guidance(
                "file_lifecycle_review", list(match["fact_refs"]),
                list(match["supporting_evidence_refs"]), list(match["relationship_refs"]),
                "Review authorized process and file audit telemetry for the same path and time window; the Cowrie commands do not establish cleanup intent or real-host effects.",
                "An execution attempt and a deletion command share a resolved path in supported chronological order.",
                ["authorized process audit", "authorized file audit", "change records"],
                "A matching process start and subsequent file deletion on an authorized real host would support a corresponding real-host sequence.",
                "Missing or conflicting process/file audit records, or an approved maintenance change, would weaken an incident interpretation.",
                match["entity_ref"],
            ))
    changed_paths: dict[str, dict[str, set[str]]] = {}
    for fact in fact_set.get("facts") or []:
        if not any(_confirmed_operation(fact, op) for op in ("file_write", "permission_modify")):
            continue
        refs = _evidence_refs(fact)
        for path_id in _resolved_change_path_ids(fact):
            if refs:
                grouped = changed_paths.setdefault(path_id, {"facts": set(), "evidence": set()})
                grouped["facts"].add(fact["fact_id"])
                grouped["evidence"].update(refs)
    for path_id, grouped in sorted(changed_paths.items()):
        guidance.append(_guidance(
            "file_change_review", sorted(grouped["facts"]), sorted(grouped["evidence"]), [],
            "Review authorized file audit telemetry for the observed path and time window; confirm the file state before drawing conclusions.",
            "Cowrie reported a parsed file write or permission change for a resolved path.",
            ["authorized file audit", "approved change records"],
            "A corresponding file or permission change in authorized telemetry would support a real-host change claim.",
            "No corresponding change, a failed operation, or an approved change record would weaken an incident interpretation.",
            path_id,
        ))
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "RESEARCH_ONLY",
        "typed_fact_set_sha256": fact_set["fact_set_sha256"],
        "hypotheses": sorted(hypotheses, key=lambda item: item["candidate_id"]),
        "guidance": sorted(guidance, key=lambda item: item["candidate_id"]),
        "authority": {
            "may_create_canonical_findings": False,
            "may_authorize_response": False,
            "may_write_production_reports": False,
        },
    }
