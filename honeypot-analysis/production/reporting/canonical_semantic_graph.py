"""One deterministic semantic graph shared by reports, guidance, and AI."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from typing import Any, Mapping

from production.reporting.semantic_coverage import validate_semantic_coverage
from production.reporting.behavioral_authority import validate_behavioral_authority
from production.utils.serialization import stable_json


SCHEMA_VERSION = "canonical_semantic_graph.v1"


def _text(value: Any) -> str:
    return str(value or "").strip()


def _sha(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def _evidence_id(item: Mapping[str, Any]) -> str:
    return _text(item.get("evidence_id") or item.get("evidence_ref"))


def _evidence_integrity_signature(item: Mapping[str, Any]) -> dict[str, Any]:
    """Project duplicate evidence onto semantic/status/provenance fields.

    Presentation fields (raw command text, collection name, and transport
    metadata) are deliberately excluded.  A duplicate may be represented by
    several canonical collections, but those collections must agree on the
    meaning and provenance of the evidence identity.
    """

    status = _text(item.get("status") or item.get("evidence_status") or "observed")
    signature: dict[str, Any] = {"status": status}
    for key in (
        "semantic_family",
        "semantic_type",
        "operation_type",
        "source",
        "source_type",
        "rule_id",
        "policy_rule_id",
        "rule_policy_id",
        "rule_policy_version",
        "rule_policy_sha256",
        "rule_policy_load_status",
        "classification_evidence_id",
        "tactic",
        "technique",
        "ttp",
        "outcome_status",
    ):
        if key in item:
            value = item.get(key)
            signature[key] = _text(value).upper() if key in {"technique", "ttp"} else value
    if isinstance(item.get("authority_decision"), Mapping):
        signature["authority_decision"] = deepcopy(dict(item["authority_decision"]))
    for key in ("provenance", "semantic_provenance"):
        if key in item:
            signature[key] = deepcopy(item.get(key))
    return signature


def _evidence_nodes(observed: Mapping[str, Any]) -> list[dict[str, Any]]:
    collections = (
        ("observations", "command_observation"),
        ("ordered_command_observations", "command_observation"),
        ("transfer_observations", "direct_transfer_observation"),
        ("transfer_event_observations", "direct_transfer_observation"),
        ("direct_cowrie_events", "cowrie_event_observation"),
        ("cowrie_event_evidence", "cowrie_event_observation"),
        ("classification_events", "classification_observation"),
        ("trusted_attck_candidates", "trusted_attck_candidate"),
    )
    by_id: dict[str, dict[str, Any]] = {}
    signatures: dict[str, dict[str, Any]] = {}
    for collection, kind in collections:
        for item in observed.get(collection) or []:
            if not isinstance(item, Mapping):
                continue
            evidence_id = _evidence_id(item)
            if not evidence_id:
                continue
            signature = _evidence_integrity_signature(item)
            prior_signature = signatures.get(evidence_id)
            if prior_signature is None:
                signatures[evidence_id] = signature
            elif prior_signature != signature:
                raise ValueError(
                    "evidence identity has conflicting semantic/status/provenance data"
                )
            node = by_id.setdefault(
                evidence_id,
                {
                    "evidence_id": evidence_id,
                    "evidence_kinds": [],
                    "durable_event_ref": _text(
                        item.get("durable_event_id")
                        or item.get("eventid")
                        or item.get("cowrie_eventid")
                    ),
                    "sequence_index": item.get("sequence_index"),
                    "status": _text(
                        item.get("status")
                        or item.get("evidence_status")
                        or "observed"
                    ),
                },
            )
            if kind not in node["evidence_kinds"]:
                node["evidence_kinds"].append(kind)
            event_ref = _text(
                item.get("durable_event_id")
                or item.get("eventid")
                or item.get("cowrie_eventid")
            )
            if node["durable_event_ref"] and event_ref and node["durable_event_ref"] != event_ref:
                raise ValueError("evidence identity has conflicting durable event references")
            if not node["durable_event_ref"]:
                node["durable_event_ref"] = event_ref
    return [
        {
            **node,
            "evidence_kinds": sorted(node["evidence_kinds"]),
        }
        for node in sorted(by_id.values(), key=lambda item: item["evidence_id"])
    ]


def _fact_nodes(fact_set: Mapping[str, Any]) -> list[dict[str, Any]]:
    output = []
    for fact in fact_set.get("facts") or []:
        if not isinstance(fact, Mapping):
            continue
        evidence_refs = sorted({
            _text(item.get("evidence_ref"))
            for item in fact.get("evidence_references") or []
            if isinstance(item, Mapping) and _text(item.get("evidence_ref"))
        })
        output.append({
            "fact_id": _text(fact.get("fact_id")),
            "semantic_family": _text(fact.get("semantic_family")),
            "operation_types": sorted({
                _text(item.get("operation_type"))
                for item in fact.get("operations") or []
                if isinstance(item, Mapping) and _text(item.get("operation_type"))
            }),
            "outcome_status": _text((fact.get("outcome") or {}).get("status")),
            "source_evidence_refs": evidence_refs,
            "entity_refs": sorted({
                _text(entity.get("entity_id"))
                for values in (fact.get("entities") or {}).values()
                if isinstance(values, list)
                for entity in values
                if isinstance(entity, Mapping) and _text(entity.get("entity_id"))
            }),
            "abstention_reasons": sorted({
                _text(item)
                for item in fact.get("abstention_reasons") or []
                if _text(item)
            }),
        })
    return sorted(output, key=lambda item: item["fact_id"])


def _entity_nodes(fact_set: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Expose only typed entity identity metadata, never entity values."""

    by_id: dict[str, dict[str, Any]] = {}
    aggregate_entities = fact_set.get("entities") or []
    if isinstance(aggregate_entities, Mapping):
        aggregate_items = [
            (role, entity)
            for role, values in aggregate_entities.items()
            if isinstance(values, list)
            for entity in values
        ]
    else:
        aggregate_items = (
            [
                (role, entity)
                for entity in aggregate_entities
                if isinstance(entity, Mapping)
                for role in (entity.get("roles") or [])
            ]
            if isinstance(aggregate_entities, list)
            else []
        )
    for role, entity in aggregate_items:
        if not isinstance(entity, Mapping):
            continue
        entity_id = _text(entity.get("entity_id"))
        if not entity_id:
            continue
        node = by_id.setdefault(
            entity_id,
            {
                "entity_id": entity_id,
                "entity_type": _text(entity.get("entity_type")),
                "roles": [],
                "fact_refs": [],
            },
        )
        entity_type = _text(entity.get("entity_type"))
        if node["entity_type"] and entity_type and node["entity_type"] != entity_type:
            raise ValueError("entity identity has conflicting entity types")
        if entity_type and not node["entity_type"]:
            node["entity_type"] = entity_type
        if _text(role) and _text(role) not in node["roles"]:
            node["roles"].append(_text(role))
        for fact_ref in entity.get("fact_refs") or []:
            fact_id = _text(fact_ref)
            if fact_id and fact_id not in node["fact_refs"]:
                node["fact_refs"].append(fact_id)
    # The per-fact entity declarations are the authoritative relation when
    # aggregate entity entries do not carry their own fact_refs projection.
    for fact in fact_set.get("facts") or []:
        if not isinstance(fact, Mapping):
            continue
        fact_id = _text(fact.get("fact_id"))
        for values in (fact.get("entities") or {}).values():
            if not isinstance(values, list):
                continue
            for entity in values:
                if not isinstance(entity, Mapping):
                    continue
                entity_id = _text(entity.get("entity_id"))
                if entity_id in by_id and fact_id and fact_id not in by_id[entity_id]["fact_refs"]:
                    by_id[entity_id]["fact_refs"].append(fact_id)
    return [
        {
            **node,
            "roles": sorted(node["roles"]),
            "fact_refs": sorted(node["fact_refs"]),
        }
        for node in sorted(by_id.values(), key=lambda item: item["entity_id"])
    ]


def _add_typed_evidence_nodes(
    evidence_nodes: list[dict[str, Any]],
    fact_set: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Index content-addressed classifier evidence referenced by valid facts."""

    by_id = {_text(item.get("evidence_id")): item for item in evidence_nodes}
    classification_refs = {
        _text(item.get("evidence_ref"))
        for item in fact_set.get("evidence_index") or []
        if isinstance(item, Mapping)
        and _text(item.get("reference_type")) == "trusted_classification"
        and _text(item.get("evidence_ref"))
    }
    for evidence_id in sorted(classification_refs):
        # Classification events are redacted before the v3 observed snapshot
        # is assembled, but the typed evidence index explicitly binds their
        # stable IDs as trusted classification provenance.  Do not synthesize
        # arbitrary missing IDs: unresolved references remain a validation
        # error.
        if evidence_id and evidence_id not in by_id:
            by_id[evidence_id] = {
                "evidence_id": evidence_id,
                "evidence_kinds": ["classification_observation"],
                "durable_event_ref": "",
                "sequence_index": None,
                "status": "observed",
            }
    return [
        {
            **node,
            "evidence_kinds": sorted(node.get("evidence_kinds") or []),
        }
        for node in sorted(by_id.values(), key=lambda item: _text(item.get("evidence_id")))
    ]


def _relationship_nodes(fact_set: Mapping[str, Any]) -> list[dict[str, Any]]:
    output = []
    for relationship in fact_set.get("relationships") or []:
        if not isinstance(relationship, Mapping):
            continue
        output.append({
            "relationship_id": _text(relationship.get("relationship_id")),
            "relationship_type": _text(relationship.get("relationship_type")),
            "status": _text(relationship.get("status")),
            "source_fact_ref": _text(relationship.get("source_fact_id")),
            "target_fact_ref": _text(relationship.get("target_fact_id")),
            "entity_ref": _text(relationship.get("entity_ref")),
            "evidence_refs": sorted({
                _text(item.get("evidence_ref"))
                for item in relationship.get("evidence_references") or []
                if isinstance(item, Mapping) and _text(item.get("evidence_ref"))
            }),
            "proof_scope": _text(relationship.get("proof_scope")),
            "connects_chain": relationship.get("connects_chain") is True,
            "limitation_codes": sorted({
                _text(item)
                for item in relationship.get("abstention_reasons") or []
                if _text(item)
            }),
        })
    return sorted(output, key=lambda item: item["relationship_id"])


def _chain_nodes(
    fact_set: Mapping[str, Any],
    chain_selection: Mapping[str, Any] | None,
) -> list[dict[str, Any]]:
    selected_by_chain = {
        _text(item.get("chain_id")): item
        for item in (chain_selection or {}).get("matches") or []
        if isinstance(item, Mapping) and _text(item.get("chain_id"))
    }
    output = []
    for chain in fact_set.get("chains") or []:
        if not isinstance(chain, Mapping):
            continue
        chain_id = _text(chain.get("chain_id"))
        selected = selected_by_chain.get(chain_id) or {}
        output.append({
            "chain_id": chain_id,
            "status": _text(selected.get("status") or chain.get("status")),
            "fact_refs": sorted({_text(item) for item in chain.get("fact_refs") or [] if _text(item)}),
            "required_relationship_refs": sorted({
                _text(item)
                for item in selected.get("required_relationship_refs")
                or selected.get("relationship_refs")
                or chain.get("relationship_refs")
                or []
                if _text(item)
            }),
            "supporting_relationship_refs": sorted({
                _text(item)
                for item in selected.get("supporting_relationship_refs") or []
                if _text(item)
            }),
            "evidence_refs": sorted({
                _text(item)
                for item in selected.get("supporting_evidence_refs")
                or []
                if _text(item)
            }),
            "entity_refs": sorted({_text(item) for item in chain.get("entity_refs") or [] if _text(item)}),
        })
    return sorted(output, key=lambda item: item["chain_id"])


def build_canonical_semantic_graph(
    observed: Mapping[str, Any],
    *,
    typed_fact_set: Mapping[str, Any] | None,
    coverage: Mapping[str, Any],
    authority_decisions: list[Mapping[str, Any]] | None = None,
    audit_only_candidates: list[Mapping[str, Any]] | None = None,
    chain_selection: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if validate_semantic_coverage(coverage):
        raise ValueError("semantic coverage is invalid")
    fact_set = typed_fact_set if isinstance(typed_fact_set, Mapping) else {}
    evidence_nodes = _add_typed_evidence_nodes(
        _evidence_nodes(observed),
        fact_set,
    )
    fact_nodes = _fact_nodes(fact_set)
    entity_nodes = _entity_nodes(fact_set)
    relationship_edges = _relationship_nodes(fact_set)
    chain_nodes = _chain_nodes(fact_set, chain_selection)
    evidence_ids = {
        _text(item.get("evidence_id")) for item in evidence_nodes
    }
    relationship_ids = {
        _text(item.get("relationship_id")) for item in relationship_edges
    }
    chain_ids = {_text(item.get("chain_id")) for item in chain_nodes}
    result = {
        "schema_version": SCHEMA_VERSION,
        "observed_evidence_sha256": _text(observed.get("evidence_sha256")),
        "typed_fact_set_sha256": _text(fact_set.get("fact_set_sha256")),
        "semantic_coverage_sha256": _text(coverage.get("coverage_sha256")),
        "evidence_nodes": evidence_nodes,
        "fact_nodes": fact_nodes,
        "entity_nodes": entity_nodes,
        "relationship_edges": relationship_edges,
        "chain_nodes": chain_nodes,
        "authority_decisions": [
            deepcopy(dict(item))
            for item in authority_decisions or []
            if isinstance(item, Mapping)
        ],
        "audit_only_candidates": [
            {
                "candidate_id": _text(
                    item.get("finding_id") or item.get("claim_id")
                ),
                "finding_type": _text(
                    item.get("finding_type") or item.get("claim_type")
                ),
                "policy_rule_id": _text(
                    item.get("behavior_policy_rule_id")
                    or item.get("policy_rule_id")
                ),
                "evidence_refs": sorted({
                    _text(ref)
                    for ref in item.get("evidence_refs") or []
                    if _text(ref)
                }),
                "relationship_refs": sorted({
                    _text(ref)
                    for ref in item.get("relationship_refs") or []
                    if _text(ref)
                }),
                "chain_ref": (
                    _text(item.get("connected_chain_id"))
                    if _text(item.get("connected_chain_id"))
                    else ""
                ),
            }
            for item in audit_only_candidates or []
            if isinstance(item, Mapping)
            and _text(item.get("finding_id") or item.get("claim_id"))
        ],
    }
    result["graph_sha256"] = _sha(result)
    return result


def validate_canonical_semantic_graph(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return ["canonical semantic graph must be an object"]
    errors: list[str] = []
    if value.get("schema_version") != SCHEMA_VERSION:
        errors.append("canonical semantic graph schema is invalid")
    evidence_ids = {
        _text(item.get("evidence_id"))
        for item in value.get("evidence_nodes") or []
        if isinstance(item, Mapping)
    }
    fact_ids = {
        _text(item.get("fact_id"))
        for item in value.get("fact_nodes") or []
        if isinstance(item, Mapping)
    }
    entity_nodes = value.get("entity_nodes")
    if entity_nodes is not None and not isinstance(entity_nodes, list):
        errors.append("canonical entity nodes must be a list")
        entity_nodes = []
    entity_ids = {
        _text(item.get("entity_id"))
        for item in (entity_nodes or [])
        if isinstance(item, Mapping)
    }
    relationship_ids = {
        _text(item.get("relationship_id"))
        for item in value.get("relationship_edges") or []
        if isinstance(item, Mapping)
    }
    chain_ids = {
        _text(item.get("chain_id"))
        for item in value.get("chain_nodes") or []
        if isinstance(item, Mapping)
    }
    if entity_nodes is None:
        # Graphs created before the entity-node extension remain readable;
        # their fact entity references are the only available index.
        entity_ids = {
            _text(ref)
            for fact in value.get("fact_nodes") or []
            if isinstance(fact, Mapping)
            for ref in fact.get("entity_refs") or []
            if _text(ref)
        }
    for key, label in (
        ("evidence_nodes", "evidence"),
        ("fact_nodes", "fact"),
        ("relationship_edges", "relationship"),
        ("chain_nodes", "chain"),
    ):
        if not isinstance(value.get(key), list):
            errors.append(f"canonical {label} nodes must be lists")
    if not _text(value.get("observed_evidence_sha256")):
        errors.append("canonical graph must bind observed evidence")
    if not _text(value.get("semantic_coverage_sha256")):
        errors.append("canonical graph must bind semantic coverage")
    if len(evidence_ids) != len(list(value.get("evidence_nodes") or [])):
        errors.append("canonical evidence IDs are duplicated")
    if len(fact_ids) != len(list(value.get("fact_nodes") or [])):
        errors.append("canonical fact IDs are duplicated")
    if entity_nodes is not None and len(entity_ids) != len(entity_nodes):
        errors.append("canonical entity IDs are duplicated")
    if len(relationship_ids) != len(list(value.get("relationship_edges") or [])):
        errors.append("canonical relationship IDs are duplicated")
    if len(chain_ids) != len(list(value.get("chain_nodes") or [])):
        errors.append("canonical chain IDs are duplicated")
    for edge in value.get("relationship_edges") or []:
        if not isinstance(edge, Mapping):
            continue
        if _text(edge.get("source_fact_ref")) not in fact_ids or _text(edge.get("target_fact_ref")) not in fact_ids:
            errors.append("canonical relationship fact reference is unresolved")
        if any(_text(ref) not in evidence_ids for ref in edge.get("evidence_refs") or []):
            errors.append("canonical relationship evidence reference is unresolved")
        entity_ref = _text(edge.get("entity_ref"))
        if entity_ref and entity_ref not in entity_ids:
            errors.append("canonical relationship entity reference is unresolved")
    for fact in value.get("fact_nodes") or []:
        if not isinstance(fact, Mapping):
            continue
        if any(_text(ref) not in evidence_ids for ref in fact.get("source_evidence_refs") or []):
            errors.append("canonical fact evidence reference is unresolved")
        if any(_text(ref) not in entity_ids for ref in fact.get("entity_refs") or []):
            errors.append("canonical fact entity reference is unresolved")
    for entity in entity_nodes or []:
        if not isinstance(entity, Mapping):
            errors.append("canonical entity node must be an object")
            continue
        entity_id = _text(entity.get("entity_id"))
        if not entity_id:
            errors.append("canonical entity ID is required")
        if any(_text(ref) not in fact_ids for ref in entity.get("fact_refs") or []):
            errors.append("canonical entity fact reference is unresolved")
    for chain in value.get("chain_nodes") or []:
        if not isinstance(chain, Mapping):
            continue
        if any(_text(ref) not in fact_ids for ref in chain.get("fact_refs") or []):
            errors.append("canonical chain fact reference is unresolved")
        if any(_text(ref) not in relationship_ids for ref in chain.get("required_relationship_refs") or []):
            errors.append("canonical chain required relationship is unresolved")
        if any(_text(ref) not in relationship_ids for ref in chain.get("supporting_relationship_refs") or []):
            errors.append("canonical chain supporting relationship is unresolved")
        if any(
            _text(ref) not in evidence_ids
            for ref in chain.get("evidence_refs") or []
        ):
            errors.append("canonical chain evidence reference is unresolved")
        if any(_text(ref) not in entity_ids for ref in chain.get("entity_refs") or []):
            errors.append("canonical chain entity reference is unresolved")
    for candidate in value.get("audit_only_candidates") or []:
        if not isinstance(candidate, Mapping):
            errors.append("canonical audit-only candidate must be an object")
            continue
        if any(_text(ref) not in evidence_ids for ref in candidate.get("evidence_refs") or []):
            errors.append("canonical audit-only evidence reference is unresolved")
        if any(_text(ref) not in relationship_ids for ref in candidate.get("relationship_refs") or []):
            errors.append("canonical audit-only relationship reference is unresolved")
        chain_ref = _text(candidate.get("chain_ref"))
        if chain_ref and chain_ref not in chain_ids:
            errors.append("canonical audit-only chain reference is unresolved")
    for decision in value.get("authority_decisions") or []:
        decision_errors = validate_behavioral_authority(decision)
        errors.extend(
            f"canonical authority decision: {error}"
            for error in decision_errors
        )
        if isinstance(decision, Mapping):
            if any(_text(ref) not in evidence_ids for ref in decision.get("evidence_refs") or []):
                errors.append("canonical authority evidence reference is unresolved")
            if any(_text(ref) not in relationship_ids for ref in decision.get("relationship_refs") or []):
                errors.append("canonical authority relationship reference is unresolved")
            if any(_text(ref) not in chain_ids for ref in decision.get("chain_refs") or []):
                errors.append("canonical authority chain reference is unresolved")
    digest = _text(value.get("graph_sha256"))
    copied = deepcopy(dict(value))
    copied.pop("graph_sha256", None)
    if len(digest) != 64 or _sha(copied) != digest:
        errors.append("canonical semantic graph hash mismatch")
    return errors
