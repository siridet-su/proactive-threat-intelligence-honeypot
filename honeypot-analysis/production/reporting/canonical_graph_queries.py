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


__all__ = [
    "CanonicalGraphQueryError",
    "CanonicalGraphView",
    "SCHEMA_VERSION",
    "canonical_graph_view",
]
