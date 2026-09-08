"""Policy-driven same-entity chain selection over validated typed facts."""

from __future__ import annotations

import hashlib
from datetime import datetime
from copy import deepcopy
from typing import Any

from production.reporting.typed_semantic_facts import validate_typed_semantic_fact_set
from production.utils.serialization import stable_json


SCHEMA_VERSION = "typed_semantic_chain_selection.v2"
PROJECT_LOCAL_HEURISTIC = "PROJECT_LOCAL_HEURISTIC"
_CHRONOLOGY_QUALITIES = {
    "timestamp_supported",
    "fallback_input_order",
    "mixed_timestamp",
    "malformed_timestamp",
    "contradictory_timestamp",
    "insufficient_ordering",
}


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _sha(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def _parsed_timestamp(value: Any) -> datetime | None:
    text = _clean(value)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo is not None else None


def _integer_or_none(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def chronology_quality_for_records(records: Any) -> dict[str, Any]:
    """Classify the evidence ordering without treating list order as time.

    This is deliberately a small representation-level vocabulary.  It does
    not assign a confidence score and never upgrades index/input order to
    timestamp-proven chronology.
    """

    if not isinstance(records, (list, tuple)):
        records = []
    items = [item for item in records if isinstance(item, dict)]
    indexed = []
    for input_index, item in enumerate(items):
        sequence_index = _integer_or_none(item.get("sequence_index"))
        source_index = _integer_or_none(item.get("source_index"))
        indexed.append((sequence_index, source_index, input_index, item))
    indexed.sort(
        key=lambda entry: (
            entry[0] if entry[0] is not None else (
                entry[1] if entry[1] is not None else entry[2]
            ),
            entry[1] if entry[1] is not None else entry[2],
            entry[2],
            _clean(entry[3].get("fact_id") or entry[3].get("evidence_id")),
        )
    )
    items = [entry[3] for entry in indexed]
    if not items:
        return {
            "quality": "insufficient_ordering",
            "ordering_basis": "no_orderable_records",
            "timestamp_count": 0,
            "record_count": 0,
        }
    # ``timestamp`` is the event/fact timestamp.  Durable replay may expose
    # only the receipt's canonical ``received_at``; that is still an
    # authoritative timestamp, whereas sequence/source order alone is not.
    raw_timestamps = [
        _clean(item.get("timestamp") or item.get("received_at"))
        for item in items
    ]
    present = [bool(value) for value in raw_timestamps]
    if not any(present):
        return {
            "quality": "fallback_input_order",
            "ordering_basis": "sequence_index_then_source_index",
            "timestamp_count": 0,
            "record_count": len(items),
        }
    parsed = [_parsed_timestamp(value) for value in raw_timestamps]
    if any(value and parsed[index] is None for index, value in enumerate(raw_timestamps)):
        quality = "malformed_timestamp"
    elif not all(present):
        quality = "mixed_timestamp"
    elif any(
        parsed[index] > parsed[index + 1]
        for index in range(len(parsed) - 1)
        if parsed[index] is not None and parsed[index + 1] is not None
    ):
        quality = "contradictory_timestamp"
    else:
        quality = "timestamp_supported"
    return {
        "quality": quality,
        "ordering_basis": (
            "timestamp_then_sequence_index"
            if quality == "timestamp_supported"
            else "sequence_index_then_source_index_with_timestamp_diagnostics"
        ),
        "timestamp_count": sum(present),
        "record_count": len(items),
    }


def chronology_quality_for_fact_set(fact_set: dict[str, Any]) -> dict[str, Any]:
    """Return the bounded chronology representation for a typed fact set."""

    return chronology_quality_for_records(fact_set.get("facts") or [])


def _selection_hash_basis(value: dict[str, Any]) -> dict[str, Any]:
    basis = deepcopy(value)
    basis.pop("selection_sha256", None)
    return basis


def validate_typed_chain_selection_provenance(
    selection: Any,
    match: Any,
    *,
    expected_status: str | None = None,
) -> list[str]:
    """Validate current selector provenance before it becomes a claim basis.

    Historical selector-v1 records are readable by their existing adapters;
    this validator is intentionally strict for the current v2 path.
    """

    errors: list[str] = []
    if not isinstance(selection, dict):
        return ["typed chain selection provenance is not an object"]
    if selection.get("schema_version") != SCHEMA_VERSION:
        errors.append("selector schema/version is not authoritative v2")
    fact_hash = _clean(selection.get("fact_set_sha256")).lower()
    if len(fact_hash) != 64 or any(char not in "0123456789abcdef" for char in fact_hash):
        errors.append("selector fact_set_sha256 is invalid")
    recorded = _clean(selection.get("selection_sha256")).lower()
    if len(recorded) != 64 or recorded != _sha(_selection_hash_basis(selection)):
        errors.append("selector selection_sha256 is invalid")
    if not isinstance(match, dict):
        errors.append("selector match provenance is not an object")
        return errors
    provenance = match.get("selector_provenance")
    expected_keys = {
        "schema_version", "claim_basis_type", "rule_id", "chain_id", "status"
    }
    if not isinstance(provenance, dict) or set(provenance) != expected_keys:
        errors.append("selector match provenance shape is invalid")
    else:
        if provenance.get("schema_version") != SCHEMA_VERSION:
            errors.append("selector match provenance schema/version is invalid")
        if provenance.get("claim_basis_type") != SCHEMA_VERSION:
            errors.append("selector claim-basis type is invalid")
        for key in ("rule_id", "chain_id"):
            if not _clean(provenance.get(key)):
                errors.append(f"selector provenance {key} is required")
        if provenance.get("status") not in {"complete", "incomplete"}:
            errors.append("selector provenance status is invalid")
    if not _clean(match.get("rule_id")) or not _clean(match.get("chain_id")):
        errors.append("selector match rule_id and chain_id are required")
    if expected_status and match.get("status") != expected_status:
        errors.append("selector match status is incompatible")
    if match.get("status") not in {"complete", "incomplete"}:
        errors.append("selector match status is invalid")
    if isinstance(provenance, dict):
        if provenance.get("rule_id") != match.get("rule_id"):
            errors.append("selector provenance rule_id mismatch")
        if provenance.get("chain_id") != match.get("chain_id"):
            errors.append("selector provenance chain_id mismatch")
        if provenance.get("status") != match.get("status"):
            errors.append("selector provenance status mismatch")
    for key in ("fact_refs", "relationship_refs", "supporting_evidence_refs"):
        if not isinstance(match.get(key), list) or any(
            not isinstance(item, str) or not item.strip() for item in match.get(key) or []
        ):
            errors.append(f"selector match {key} is invalid")
    return errors


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
    chronology = chronology_quality_for_fact_set(fact_set)
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
            # These values are deliberately surfaced as local policy
            # provenance.  They are not externally validated sufficiency
            # thresholds and must not be read as calibrated evidence.
            "numeric_provenance": PROJECT_LOCAL_HEURISTIC,
            "heuristic_parameters": {
                "minimum_incomplete_operation_count": (
                    _integer_or_none(rule.get("minimum_incomplete_operation_count"))
                ),
                "same_entity_required": same_entity_rule,
            },
            "chronology_quality": chronology["quality"],
            "chronology_basis": chronology["ordering_basis"],
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
        matches[-1]["selector_provenance"] = {
            "schema_version": SCHEMA_VERSION,
            "claim_basis_type": SCHEMA_VERSION,
            "rule_id": matches[-1]["rule_id"],
            "chain_id": matches[-1]["chain_id"],
            "status": matches[-1]["status"],
        }
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
        "numeric_provenance": PROJECT_LOCAL_HEURISTIC,
        "selection_parameter_provenance": {
            "minimum_incomplete_operation_count": PROJECT_LOCAL_HEURISTIC,
            "same_entity_required": PROJECT_LOCAL_HEURISTIC,
        },
        "chronology": chronology_quality_for_fact_set(fact_set),
        "authority": {
            "may_select_findings": True,
            "may_derive_hypotheses": True,
            "may_render_hypotheses": True,
            "may_select_hypotheses": False,
            "may_select_authoritative_hypothesis": False,
            "may_authorize_response": False,
            "may_authorize_actions": False,
            "causality_claimed": False,
        },
    }
    result["selection_sha256"] = _sha(result)
    return deepcopy(result)
