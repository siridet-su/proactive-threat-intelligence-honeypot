"""Policy-driven same-entity chain selection over validated typed facts."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from typing import Any

from production.reporting.typed_semantic_facts import validate_typed_semantic_fact_set
from production.utils.serialization import stable_json


SCHEMA_VERSION = "typed_semantic_chain_selection.v2"


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _sha(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def _ordered_required_facts(
    chain: dict[str, Any],
    facts: dict[str, dict[str, Any]],
    required: list[str],
) -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
    selected: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    position = 0
    for fact_ref in chain.get("fact_refs") or []:
        fact = facts.get(_clean(fact_ref)) or {}
        for operation in fact.get("operations") or []:
            if position >= len(required):
                break
            if operation.get("operation_type") == required[position]:
                selected.append((fact_ref, fact, operation))
                position += 1
                break
    return selected


def _selection_for_rule(
    fact_set: dict[str, Any], rule: dict[str, Any]
) -> list[dict[str, Any]]:
    required = [
        _clean(value) for value in rule.get("required_operation_types") or []
    ]
    facts = {
        _clean(item.get("fact_id")): item
        for item in fact_set.get("facts") or []
        if isinstance(item, dict) and _clean(item.get("fact_id"))
    }
    relationships = {
        _clean(item.get("relationship_id")): item
        for item in fact_set.get("relationships") or []
        if isinstance(item, dict) and _clean(item.get("relationship_id"))
    }
    matches: list[dict[str, Any]] = []
    for chain in fact_set.get("chains") or []:
        if not isinstance(chain, dict) or chain.get("status") not in {
            "supported",
            "partial",
        }:
            continue
        entity_refs = [
            _clean(value) for value in chain.get("entity_refs") or [] if _clean(value)
        ]
        same_entity_rule = rule.get("same_entity_required", True) is not False
        if same_entity_rule and len(entity_refs) != 1:
            continue
        if not same_entity_rule and len(entity_refs) > 1:
            continue
        selected = _ordered_required_facts(chain, facts, required)
        selected_types = [item[2].get("operation_type") for item in selected]
        complete = selected_types == required
        if not complete and selected_types != required[: len(selected_types)]:
            continue
        if (
            not complete
            and len(selected_types)
            < int(rule.get("minimum_incomplete_operation_count") or 1)
        ):
            continue
        if not selected or any(
            operation.get("effect_status") != "reported_completed"
            or (fact.get("outcome") or {}).get("status") != "reported_success"
            or (fact.get("outcome") or {}).get("scope") != "fragment"
            for _fact_ref, fact, operation in selected
        ):
            continue
        chain_relationships = [
            relationships.get(_clean(reference)) or {}
            for reference in chain.get("relationship_refs") or []
        ]
        transition_types = rule.get("required_transition_types") or [
            "same_path_transition"
        ]
        transition_types = {
            _clean(value) for value in transition_types if _clean(value)
        }
        transition_rules = rule.get("required_transitions") or []
        required_relationship_refs: list[str] = []
        invalid = False
        selected_facts = [item[1] for item in selected]
        for transition_index, (source_fact, target_fact) in enumerate(
            zip(selected_facts, selected_facts[1:])
        ):
            configured = (
                transition_rules[transition_index]
                if transition_index < len(transition_rules)
                and isinstance(transition_rules[transition_index], dict)
                else {}
            )
            allowed_types = {
                _clean(value)
                for value in configured.get("relationship_types") or transition_types
                if _clean(value)
            }
            same_entity = configured.get("same_entity_required", same_entity_rule)
            candidates = []
            endpoint_relationships = []
            for relationship in chain_relationships:
                endpoints = {
                    _clean(relationship.get("source_fact_id")),
                    _clean(relationship.get("target_fact_id")),
                }
                if endpoints != {
                    _clean(source_fact.get("fact_id")),
                    _clean(target_fact.get("fact_id")),
                }:
                    continue
                endpoint_relationships.append(relationship)
                if _clean(relationship.get("relationship_type")) not in allowed_types:
                    continue
                if same_entity and _clean(relationship.get("entity_ref")) != entity_refs[0]:
                    continue
                candidates.append(relationship)
            if any(
                item.get("status") in {"blocked", "conflicting"}
                for item in endpoint_relationships
                if _clean(item.get("relationship_type")) in allowed_types
            ):
                invalid = True
                break
            if any(
                item.get("status") in {"blocked", "conflicting"}
                for item in candidates
            ):
                invalid = True
                break
            supported = [
                item
                for item in candidates
                if item.get("status") == "supported"
                and item.get("causality_semantics")
                in {"", "evidence_link_not_causal_or_intent_proof"}
            ]
            if not supported:
                invalid = True
                break
            required_relationship_refs.append(
                min(
                    _clean(item.get("relationship_id")) for item in supported
                )
            )
        if invalid:
            continue
        required_set = set(required_relationship_refs)
        supporting_types = {
            _clean(value)
            for value in rule.get("supporting_relationship_types") or [
                "transfer_observation_confirmation"
            ]
            if _clean(value)
        }
        supporting_relationship_refs = sorted({
            _clean(item.get("relationship_id"))
            for item in chain_relationships
            if _clean(item.get("relationship_id"))
            and _clean(item.get("relationship_id")) not in required_set
            and _clean(item.get("relationship_type")) in supporting_types
            and item.get("status") == "supported"
        })
        selected_relationship_refs = set(required_relationship_refs) | set(
            supporting_relationship_refs
        )
        conflicting_relationship_refs = sorted({
            _clean(item.get("relationship_id"))
            for item in chain_relationships
            if _clean(item.get("relationship_id"))
            and item.get("status") == "conflicting"
        })
        irrelevant_relationship_refs = sorted({
            _clean(item.get("relationship_id"))
            for item in chain_relationships
            if _clean(item.get("relationship_id"))
            and _clean(item.get("relationship_id")) not in selected_relationship_refs
            and _clean(item.get("relationship_id")) not in conflicting_relationship_refs
            and item.get("status") not in {"blocked"}
        })
        evidence_refs = sorted({
            _clean(reference.get("evidence_ref"))
            for _fact_ref, fact, _operation in selected
            for reference in fact.get("evidence_references") or []
            if isinstance(reference, dict)
            and reference.get("reference_type") in {
                "source_observation",
                "direct_cowrie_event",
            }
            and _clean(reference.get("evidence_ref"))
        })
        source_observation_refs = sorted({
            _clean(reference.get("evidence_ref"))
            for _fact_ref, fact, _operation in selected
            for reference in fact.get("evidence_references") or []
            if isinstance(reference, dict)
            and reference.get("reference_type") == "source_observation"
            and _clean(reference.get("evidence_ref"))
        })
        matches.append({
            "rule_id": _clean(rule.get("rule_id")),
            "chain_id": _clean(chain.get("chain_id")),
            "status": "complete" if complete else "incomplete",
            "matched_operation_types": selected_types,
            "missing_operation_types": required[len(selected_types):],
            "entity_ref": entity_refs[0] if entity_refs else "",
            "fact_refs": [item[0] for item in selected],
            "relationship_refs": sorted(
                required_relationship_refs
            ),
            "required_relationship_refs": sorted(required_relationship_refs),
            "supporting_relationship_refs": supporting_relationship_refs,
            "conflicting_relationship_refs": conflicting_relationship_refs,
            "irrelevant_relationship_refs": irrelevant_relationship_refs,
            "supporting_evidence_refs": evidence_refs,
            "source_observation_refs": source_observation_refs,
            "limitations": [
                "Same-entity chronology is an evidence link, not proof of causality or attacker intent.",
                "Cowrie-reported command success does not prove transfer completion, payload identity, execution effects, compromise, or persistence on a real host.",
            ],
        })
    return matches


def select_typed_semantic_chains(
    fact_set: dict[str, Any], rules: list[dict[str, Any]]
) -> dict[str, Any]:
    errors = validate_typed_semantic_fact_set(fact_set)
    if errors:
        raise ValueError("typed fact set is invalid: " + "; ".join(errors))
    matches = [
        match
        for rule in rules
        if isinstance(rule, dict)
        for match in _selection_for_rule(fact_set, rule)
    ]
    matches.sort(
        key=lambda item: (
            item["status"],
            item["rule_id"],
            item["chain_id"],
        )
    )
    result = {
        "schema_version": SCHEMA_VERSION,
        "fact_set_sha256": _clean(fact_set.get("fact_set_sha256")),
        "matches": matches,
            "authority": {
            "may_select_findings": True,
            "may_select_hypotheses": True,
            "may_authorize_actions": False,
            "causality_claimed": False,
        },
    }
    result["selection_sha256"] = _sha(result)
    return deepcopy(result)
