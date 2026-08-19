"""Read-only, fail-closed queries over the one canonical semantic graph."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from production.reporting.canonical_semantic_graph import (
    validate_canonical_semantic_graph,
)


SCHEMA_VERSION = "canonical_graph_query_view.v1"
INSPECTION_OPERATIONS = frozenset({
    "host_uptime_inspection", "filesystem_capacity_inspection",
    "system_identity_inspection", "account_identity_inspection",
    "network_route_inspection", "process_inspection",
    "network_socket_inspection", "account_database_inspection",
    "account_metadata_read", "filesystem_search",
})
FILESYSTEM_OPERATIONS = frozenset({
    "file_write", "file_append", "file_modify", "permission_modify",
    "directory_create", "file_move", "file_delete",
})


class CanonicalGraphQueryError(ValueError):
    """Raised when a query cannot be proven from the validated graph."""


@dataclass(frozen=True)
class ChronologicalGraphView:
    """A validated causal ordering over the existing canonical graph."""

    canonical: "CanonicalGraphView"
    ordered_fact_ids: tuple[str, ...]
    fact_sequence_indices: dict[str, int]
    dense_ordinals: dict[str, int]

    def fact_ids_at_ordinal(self, ordinal: int) -> tuple[str, ...]:
        return tuple(
            fact_id for fact_id in self.ordered_fact_ids
            if self.dense_ordinals[fact_id] == ordinal
        )


def _text(value: Any) -> str:
    return str(value or "").strip()


def _texts(values: Iterable[Any]) -> tuple[str, ...]:
    return tuple(sorted({_text(item) for item in values if _text(item)}))


@dataclass(frozen=True)
class CanonicalGraphView:
    graph: dict[str, Any]
    evidence_by_id: dict[str, dict[str, Any]]
    facts_by_id: dict[str, dict[str, Any]]
    entities_by_id: dict[str, dict[str, Any]]
    relationships_by_id: dict[str, dict[str, Any]]
    chains_by_id: dict[str, dict[str, Any]]
    authority_by_candidate_id: dict[str, dict[str, Any]]

    @property
    def graph_sha256(self) -> str:
        return _text(self.graph.get("graph_sha256"))

    @property
    def observed_evidence_sha256(self) -> str:
        return _text(self.graph.get("observed_evidence_sha256"))

    @property
    def typed_fact_set_sha256(self) -> str:
        return _text(self.graph.get("typed_fact_set_sha256"))

    def command_evidence_refs(self) -> tuple[str, ...]:
        return _texts(
            evidence_id
            for evidence_id, node in self.evidence_by_id.items()
            if "command_observation" in set(node.get("evidence_kinds") or [])
        )

    def entity_ids_for_facts(
        self,
        fact_ids: Iterable[str],
        *,
        role: str = "",
    ) -> tuple[str, ...]:
        selected = set(_texts(fact_ids))
        return _texts(
            entity_id
            for entity_id, entity in self.entities_by_id.items()
            if selected.intersection(entity.get("fact_refs") or [])
            and (not role or role in set(entity.get("roles") or []))
        )

    def matching_facts(
        self,
        *,
        semantic_family: str,
        required_operation_types: Iterable[str] = (),
        required_outcome_statuses: Iterable[str] = (),
    ) -> tuple[dict[str, Any], ...]:
        required_ops = set(_texts(required_operation_types))
        outcomes = set(_texts(required_outcome_statuses))
        matches = []
        for fact in self.facts_by_id.values():
            operations = set(_texts(fact.get("operation_types") or []))
            outcome = _text(fact.get("outcome_status"))
            if fact.get("abstention_reasons"):
                continue
            if required_ops and not required_ops.issubset(operations):
                continue
            if outcomes and outcome not in outcomes:
                continue
            if not _fact_matches_family(fact, semantic_family, self):
                continue
            matches.append(deepcopy(fact))
        return tuple(sorted(matches, key=lambda item: _text(item.get("fact_id"))))

    def semantic_families_for_fact(self, fact_id: str) -> tuple[str, ...]:
        fact = self.facts_by_id.get(_text(fact_id))
        if fact is None:
            raise CanonicalGraphQueryError("canonical fact reference is unresolved")
        return tuple(
            family for family in (
                "sensitive_read", "transfer", "transfer_attempt",
                "inspection", "filesystem", "execution",
            )
            if _fact_matches_family(fact, family, self)
        )


def _fact_matches_family(
    fact: Mapping[str, Any],
    family: str,
    view: CanonicalGraphView,
) -> bool:
    operations = set(_texts(fact.get("operation_types") or []))
    fact_id = _text(fact.get("fact_id"))
    if family == "inspection":
        return bool(operations.intersection(INSPECTION_OPERATIONS))
    if family == "filesystem":
        return bool(operations.intersection(FILESYSTEM_OPERATIONS))
    if family == "execution":
        return "execution_attempt" in operations
    if family == "transfer":
        return "transfer_observed" in operations
    if family == "transfer_attempt":
        return {"remote_content_access", "transfer_attempt"}.issubset(operations)
    if family == "sensitive_read":
        return (
            {"credential_material_read", "file_read"}.issubset(operations)
            and bool(view.entity_ids_for_facts([fact_id], role="credential_paths"))
        )
    return False


def canonical_graph_view(
    graph: Any,
    *,
    expected_graph_sha256: str = "",
    expected_observed_evidence_sha256: str = "",
    expected_typed_fact_set_sha256: str = "",
) -> CanonicalGraphView:
    """Validate and index one existing graph without constructing another."""

    errors = validate_canonical_semantic_graph(graph)
    if errors:
        raise CanonicalGraphQueryError("; ".join(errors))
    copied = deepcopy(dict(graph))
    bindings = (
        ("graph", expected_graph_sha256, copied.get("graph_sha256")),
        (
            "observed evidence",
            expected_observed_evidence_sha256,
            copied.get("observed_evidence_sha256"),
        ),
        (
            "typed fact set",
            expected_typed_fact_set_sha256,
            copied.get("typed_fact_set_sha256"),
        ),
    )
    for label, expected, actual in bindings:
        if _text(expected) and _text(expected) != _text(actual):
            raise CanonicalGraphQueryError(f"canonical {label} binding mismatch")

    def index(collection: str, identity: str) -> dict[str, dict[str, Any]]:
        result = {
            _text(item.get(identity)): deepcopy(dict(item))
            for item in copied.get(collection) or []
            if isinstance(item, Mapping) and _text(item.get(identity))
        }
        if len(result) != len(copied.get(collection) or []):
            raise CanonicalGraphQueryError(
                f"canonical {collection} identity is incomplete"
            )
        return result

    return CanonicalGraphView(
        graph=copied,
        evidence_by_id=index("evidence_nodes", "evidence_id"),
        facts_by_id=index("fact_nodes", "fact_id"),
        entities_by_id=index("entity_nodes", "entity_id"),
        relationships_by_id=index("relationship_edges", "relationship_id"),
        chains_by_id=index("chain_nodes", "chain_id"),
        authority_by_candidate_id=index(
            "authority_decisions", "candidate_id"
        ),
    )


def chronological_graph_view(
    graph: Any,
    *,
    expected_graph_sha256: str = "",
    expected_observed_evidence_sha256: str = "",
    expected_typed_fact_set_sha256: str = "",
) -> ChronologicalGraphView:
    """Derive dense causal order without copying or constructing another graph.

    A fact is positioned only by source evidence with an integer
    ``sequence_index``. Unpositioned classification-only evidence may support a
    positioned fact, but it can never create a timeline step. Every graph edge
    and chain must resolve to positioned facts and agree with durable order.
    """

    view = canonical_graph_view(
        graph,
        expected_graph_sha256=expected_graph_sha256,
        expected_observed_evidence_sha256=expected_observed_evidence_sha256,
        expected_typed_fact_set_sha256=expected_typed_fact_set_sha256,
    )
    sequence_by_fact: dict[str, int] = {}
    for fact_id, fact in view.facts_by_id.items():
        indices = set()
        for evidence_ref in fact.get("source_evidence_refs") or []:
            node = view.evidence_by_id.get(_text(evidence_ref))
            if node is None:
                raise CanonicalGraphQueryError(
                    "canonical fact evidence reference is unresolved"
                )
            index = node.get("sequence_index")
            if index is None:
                continue
            if type(index) is not int or index < 0:
                raise CanonicalGraphQueryError(
                    "canonical evidence sequence index is invalid"
                )
            indices.add(index)
        if len(indices) > 1:
            raise CanonicalGraphQueryError(
                "canonical fact has conflicting causal placement"
            )
        if indices:
            sequence_by_fact[fact_id] = next(iter(indices))

    adjacency = {fact_id: set() for fact_id in view.facts_by_id}
    indegree = {fact_id: 0 for fact_id in view.facts_by_id}
    for edge in view.relationships_by_id.values():
        source = _text(edge.get("source_fact_ref"))
        target = _text(edge.get("target_fact_ref"))
        if source not in view.facts_by_id or target not in view.facts_by_id:
            raise CanonicalGraphQueryError(
                "canonical relationship fact reference is unresolved"
            )
        if source not in sequence_by_fact or target not in sequence_by_fact:
            raise CanonicalGraphQueryError(
                "canonical relationship has unresolved causal placement"
            )
        if sequence_by_fact[source] >= sequence_by_fact[target]:
            raise CanonicalGraphQueryError(
                "canonical relationship contradicts durable evidence order"
            )
        if target not in adjacency[source]:
            adjacency[source].add(target)
            indegree[target] += 1

    for chain in view.chains_by_id.values():
        for fact_ref in chain.get("fact_refs") or []:
            fact_id = _text(fact_ref)
            if fact_id not in view.facts_by_id:
                raise CanonicalGraphQueryError(
                    "canonical chain fact reference is unresolved"
                )
            if fact_id not in sequence_by_fact:
                raise CanonicalGraphQueryError(
                    "canonical chain has unresolved causal placement"
                )
        for relationship_ref in (
            (chain.get("required_relationship_refs") or [])
            + (chain.get("supporting_relationship_refs") or [])
        ):
            if _text(relationship_ref) not in view.relationships_by_id:
                raise CanonicalGraphQueryError(
                    "canonical chain relationship reference is unresolved"
                )

    ready = sorted(
        (fact_id for fact_id, degree in indegree.items() if degree == 0),
        key=lambda fact_id: (sequence_by_fact.get(fact_id, 2**63), fact_id),
    )
    visited = []
    while ready:
        fact_id = ready.pop(0)
        visited.append(fact_id)
        for target in sorted(adjacency[fact_id]):
            indegree[target] -= 1
            if indegree[target] == 0:
                ready.append(target)
                ready.sort(
                    key=lambda item: (sequence_by_fact.get(item, 2**63), item)
                )
    if len(visited) != len(view.facts_by_id):
        raise CanonicalGraphQueryError("canonical relationship graph contains a cycle")

    ordered = tuple(sorted(
        sequence_by_fact,
        key=lambda fact_id: (sequence_by_fact[fact_id], fact_id),
    ))
    sequence_ordinals = {
        sequence: ordinal
        for ordinal, sequence in enumerate(sorted(set(sequence_by_fact.values())), 1)
    }
    dense = {
        fact_id: sequence_ordinals[sequence]
        for fact_id, sequence in sequence_by_fact.items()
    }
    return ChronologicalGraphView(
        canonical=view,
        ordered_fact_ids=ordered,
        fact_sequence_indices=sequence_by_fact,
        dense_ordinals=dense,
    )


__all__ = [
    "CanonicalGraphQueryError",
    "CanonicalGraphView",
    "ChronologicalGraphView",
    "SCHEMA_VERSION",
    "canonical_graph_view",
    "chronological_graph_view",
]
