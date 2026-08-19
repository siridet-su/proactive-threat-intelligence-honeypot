"""Integrity-bound current session assessment contract.

Historical v4 reports remain readable through their original validator.  New
v5 records use trusted-only canonical findings and content-address the complete
bounded hypothesis meaning and every graph reference domain.
"""

from __future__ import annotations

import hashlib
from copy import deepcopy
from typing import Any, Iterable, Mapping, Optional

from production.reporting.behavioral_authority import validate_behavioral_authority
from production.reporting.canonical_semantic_graph import validate_canonical_semantic_graph
from production.reporting.response_guidance_v3 import validate_response_guidance_v3
from production.reporting.session_assessment_v4 import (
    SessionAssessmentV4Error,
    build_session_assessment_v4,
    read_legacy_session_assessment,
    validate_session_assessment_v4,
)
from production.utils.serialization import stable_id, stable_json


SCHEMA_VERSION = "session_assessment.v5"
HYPOTHESIS_SCHEMA_VERSION = "threat_hypothesis_set.v2"
ALTERNATIVE_SCHEMA_VERSION = "threat_hypothesis_alternative.v2"
_SET_KEYS = frozenset({
    "schema_version", "hypothesis_set_id", "content_sha256", "question",
    "scope", "status", "alternatives_are_exhaustive",
    "alternatives_are_mutually_exclusive", "chain_refs", "relationship_refs",
    "fact_refs", "entity_refs", "evidence_refs", "chronological_order",
    "evidence_strength", "evidence_gaps", "limitations", "semantic_coverage",
    "selector_provenance", "hypotheses",
})
_ALT_KEYS = frozenset({
    "schema_version", "hypothesis_id", "statement", "status",
    "supporting_evidence_refs", "disconfirming_evidence_refs",
    "falsification_conditions", "limitations",
})


class SessionAssessmentV5Error(SessionAssessmentV4Error):
    """Raised when a current v5 record violates its whole-contract validator."""

    def __init__(
        self,
        message: str,
        *,
        validation_errors: Optional[list[str]] = None,
        source_revision: str = "",
        producer: str = "build_session_assessment_v5",
    ) -> None:
        ValueError.__init__(self, message)
        self.validation_errors = tuple(validation_errors or ())
        self.contract_name = SCHEMA_VERSION
        self.validator_name = "validate_session_assessment_v5"
        self.source_revision = _text(source_revision).lower()
        self.producer = producer


def _text(value: Any) -> str:
    return str(value or "").strip()


def _sha(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def _without(value: Mapping[str, Any], *keys: str) -> dict[str, Any]:
    return {key: deepcopy(item) for key, item in value.items() if key not in keys}


def _alternative(content: dict[str, Any]) -> dict[str, Any]:
    basis = {"schema_version": ALTERNATIVE_SCHEMA_VERSION, **content}
    return {**basis, "hypothesis_id": stable_id("hypothesis_v2", basis)}


def _hypothesis_sets(graph: Mapping[str, Any], coverage: Mapping[str, Any]) -> list[dict[str, Any]]:
    output = []
    for chain in graph.get("chain_nodes") or []:
        if not isinstance(chain, Mapping) or chain.get("status") != "incomplete":
            continue
        chain_ref = _text(chain.get("chain_id"))
        relationship_refs = sorted({
            _text(item)
            for item in [
                *(chain.get("required_relationship_refs") or []),
                *(chain.get("supporting_relationship_refs") or []),
            ]
            if _text(item)
        })
        evidence_refs = sorted({_text(item) for item in chain.get("evidence_refs") or [] if _text(item)})
        limitations = [
            "This is a bounded alternative over Cowrie-observed evidence, not an observed fact or attacker-intent claim.",
            "Cowrie command outcomes do not establish execution effects, persistence, compromise, or real-host impact.",
        ]
        alternatives = [
            _alternative({
                "statement": "The observed same-entity sequence may represent an incomplete follow-on behavior chain.",
                "status": "bounded_unverified_alternative",
                "supporting_evidence_refs": evidence_refs,
                "disconfirming_evidence_refs": [],
                "falsification_conditions": [
                    "A conflicting same-entity relationship or failed required operation weakens this alternative.",
                    "Evidence that the referenced entity was unavailable weakens this alternative.",
                ],
                "limitations": limitations,
            }),
            _alternative({
                "statement": "No further linked behavior is established within the exact durable evidence prefix.",
                "status": "bounded_unverified_alternative",
                "supporting_evidence_refs": [],
                "disconfirming_evidence_refs": [],
                "falsification_conditions": [
                    "A later exact-prefix assessment with a supported same-entity completion disconfirms this alternative for that later prefix."
                ],
                "limitations": limitations,
            }),
        ]
        basis = {
            "schema_version": HYPOTHESIS_SCHEMA_VERSION,
            "question": "What bounded alternatives explain the incomplete same-entity behavior sequence?",
            "scope": "exact_durable_prefix_cowrie_observables_only",
            "status": "unverified_falsifiable_alternatives",
            "alternatives_are_exhaustive": False,
            "alternatives_are_mutually_exclusive": False,
            "chain_refs": [chain_ref],
            "relationship_refs": relationship_refs,
            "fact_refs": sorted({_text(item) for item in chain.get("fact_refs") or [] if _text(item)}),
            "entity_refs": sorted({_text(item) for item in chain.get("entity_refs") or [] if _text(item)}),
            "evidence_refs": evidence_refs,
            "chronological_order": "graph_sequence_order",
            "evidence_strength": "partially_supported_same_entity_sequence",
            "evidence_gaps": ["one_or_more_required_follow_on_operations_not_observed"],
            "limitations": limitations,
            "semantic_coverage": {
                "coverage_sha256": _text(coverage.get("coverage_sha256")),
                "coverage_status": _text(coverage.get("coverage_status")),
            },
            "selector_provenance": {
                "schema_version": "typed_semantic_chain_selection.v3",
                "graph_sha256": _text(graph.get("graph_sha256")),
            },
            "hypotheses": alternatives,
        }
        content_hash = _sha(basis)
        output.append({
            **basis,
            "content_sha256": content_hash,
            "hypothesis_set_id": stable_id("threat_hypothesis_set_v2", basis),
        })
    return sorted(output, key=lambda item: item["hypothesis_set_id"])


def canonical_assessment_id(value: Mapping[str, Any]) -> str:
    identity = {
        "schema_version": SCHEMA_VERSION,
        "canonical_evidence_sha256": _text((value.get("canonical_evidence") or {}).get("evidence_sha256")),
        "finding_ids": [_text(item.get("finding_id")) for item in value.get("behavioral_findings") or []],
        "audit_candidate_ids": [_text(item.get("finding_id")) for item in value.get("audit_only_behavioral_candidates") or []],
        "hypothesis_set_ids": [_text(item.get("hypothesis_set_id")) for item in value.get("hypothesis_sets") or []],
        "provenance": deepcopy(value.get("provenance") or {}),
        "authority": deepcopy(value.get("authority") or {}),
        "status": _text(value.get("status")),
        "abstention": deepcopy(value.get("abstention") or {}),
    }
    return stable_id("session_assessment_v5", identity)


def build_session_assessment_v5(
    sessions: Iterable[Any],
    raw_events: Optional[list[dict[str, Any]]] = None,
    **kwargs: Any,
) -> dict[str, Any]:
    record = build_session_assessment_v4(sessions, raw_events=raw_events, **kwargs)
    graph = (record.get("canonical_evidence") or {}).get("semantic_graph") or {}
    coverage = (record.get("canonical_evidence") or {}).get("semantic_coverage") or {}
    decisions = {
        _text(item.get("candidate_id")): _text(item.get("decision"))
        for item in graph.get("authority_decisions") or []
        if isinstance(item, Mapping)
    }
    all_findings = [
        deepcopy(dict(item))
        for item in record.get("behavioral_findings") or []
        if isinstance(item, Mapping)
    ]
    record["behavioral_findings"] = [
        item for item in all_findings
        if decisions.get(_text(item.get("finding_id"))) == "trusted"
    ]
    record["audit_only_behavioral_candidates"] = [
        item for item in all_findings
        if decisions.get(_text(item.get("finding_id"))) == "audit_only"
    ]
    record["schema_version"] = SCHEMA_VERSION
    record["hypothesis_sets"] = _hypothesis_sets(graph, coverage)
    record["compatibility"] = {
        "historical_v4_records": "read_only_not_recomputed",
        "new_record_authority": SCHEMA_VERSION,
        "hypothesis_contract": HYPOTHESIS_SCHEMA_VERSION,
    }
    record["assessment_id"] = canonical_assessment_id(record)
    validate_session_assessment_v5(record, raise_on_error=True)
    return record


def validate_threat_hypothesis_set_v2(value: Any, graph: Mapping[str, Any], coverage: Mapping[str, Any]) -> list[str]:
    if not isinstance(value, Mapping):
        return ["hypothesis set must be an object"]
    errors = []
    if set(value) != _SET_KEYS:
        errors.append("hypothesis set fields are invalid")
    basis = _without(value, "hypothesis_set_id", "content_sha256")
    if value.get("schema_version") != HYPOTHESIS_SCHEMA_VERSION:
        errors.append("hypothesis set schema is invalid")
    if _text(value.get("content_sha256")) != _sha(basis):
        errors.append("hypothesis set content hash mismatch")
    if value.get("hypothesis_set_id") != stable_id("threat_hypothesis_set_v2", basis):
        errors.append("hypothesis set ID mismatch")
    if value.get("status") != "unverified_falsifiable_alternatives":
        errors.append("hypothesis set status is invalid")
    if value.get("scope") != "exact_durable_prefix_cowrie_observables_only":
        errors.append("hypothesis set scope is invalid")
    if value.get("alternatives_are_exhaustive") is not False or value.get("alternatives_are_mutually_exclusive") is not False:
        errors.append("hypothesis alternatives must remain non-exhaustive and non-exclusive")
    domains = {
        "chain_refs": {_text(item.get("chain_id")) for item in graph.get("chain_nodes") or [] if isinstance(item, Mapping)},
        "relationship_refs": {_text(item.get("relationship_id")) for item in graph.get("relationship_edges") or [] if isinstance(item, Mapping)},
        "fact_refs": {_text(item.get("fact_id")) for item in graph.get("fact_nodes") or [] if isinstance(item, Mapping)},
        "entity_refs": {_text(item.get("entity_id")) for item in graph.get("entity_nodes") or [] if isinstance(item, Mapping)},
        "evidence_refs": {_text(item.get("evidence_id")) for item in graph.get("evidence_nodes") or [] if isinstance(item, Mapping)},
    }
    for field, domain in domains.items():
        refs = {_text(item) for item in value.get(field) or [] if _text(item)}
        if refs - domain:
            errors.append(f"hypothesis {field} do not resolve")
    if value.get("semantic_coverage") != {
        "coverage_sha256": _text(coverage.get("coverage_sha256")),
        "coverage_status": _text(coverage.get("coverage_status")),
    }:
        errors.append("hypothesis semantic coverage binding mismatch")
    if value.get("selector_provenance") != {
        "schema_version": "typed_semantic_chain_selection.v3",
        "graph_sha256": _text(graph.get("graph_sha256")),
    }:
        errors.append("hypothesis selector provenance mismatch")
    hypotheses = value.get("hypotheses")
    if not isinstance(hypotheses, list) or len(hypotheses) < 2:
        errors.append("hypothesis set requires bounded alternatives")
        hypotheses = []
    ids = []
    for alternative in hypotheses:
        if not isinstance(alternative, Mapping) or set(alternative) != _ALT_KEYS:
            errors.append("hypothesis alternative fields are invalid")
            continue
        alt_basis = _without(alternative, "hypothesis_id")
        if alternative.get("schema_version") != ALTERNATIVE_SCHEMA_VERSION:
            errors.append("hypothesis alternative schema is invalid")
        if alternative.get("hypothesis_id") != stable_id("hypothesis_v2", alt_basis):
            errors.append("hypothesis alternative ID mismatch")
        if alternative.get("status") != "bounded_unverified_alternative":
            errors.append("hypothesis alternative status is invalid")
        if not _text(alternative.get("statement")) or not alternative.get("falsification_conditions") or not alternative.get("limitations"):
            errors.append("hypothesis alternative meaning is incomplete")
        if set(alternative.get("supporting_evidence_refs") or []) - domains["evidence_refs"]:
            errors.append("hypothesis alternative evidence does not resolve")
        if set(alternative.get("disconfirming_evidence_refs") or []) - domains["evidence_refs"]:
            errors.append("hypothesis alternative disconfirming evidence does not resolve")
        ids.append(_text(alternative.get("hypothesis_id")))
    if len(ids) != len(set(ids)):
        errors.append("hypothesis alternative IDs are duplicated")
    return errors


def validate_session_assessment_v5(value: Any, *, raise_on_error: bool = False) -> list[str]:
    errors = []
    if not isinstance(value, Mapping) or value.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")
        value = value if isinstance(value, Mapping) else {}
    evidence = value.get("canonical_evidence") or {}
    graph = evidence.get("semantic_graph") or {}
    coverage = evidence.get("semantic_coverage") or {}
    copied_evidence = deepcopy(dict(evidence)) if isinstance(evidence, Mapping) else {}
    recorded = _text(copied_evidence.pop("evidence_sha256", ""))
    if recorded != _sha(copied_evidence):
        errors.append("canonical evidence hash mismatch")
    errors.extend(f"semantic graph: {error}" for error in validate_canonical_semantic_graph(graph))
    decision_items = [
        item
        for item in graph.get("authority_decisions") or []
        if isinstance(item, Mapping)
    ]
    decisions = {
        _text(item.get("candidate_id")): item
        for item in decision_items
    }
    if len(decisions) != len(decision_items):
        errors.append("authority decision candidate IDs must be unique")
    for decision in decisions.values():
        errors.extend(f"authority decision: {error}" for error in validate_behavioral_authority(decision))
    finding_ids = []
    for finding in value.get("behavioral_findings") or []:
        finding_id = _text(finding.get("finding_id")) if isinstance(finding, Mapping) else ""
        finding_ids.append(finding_id)
        if not finding_id or (decisions.get(finding_id) or {}).get("decision") != "trusted":
            errors.append("canonical finding lacks one trusted authority decision")
    if len(finding_ids) != len(set(finding_ids)):
        errors.append("canonical finding IDs are invalid")
    for finding in value.get("audit_only_behavioral_candidates") or []:
        finding_id = _text(finding.get("finding_id")) if isinstance(finding, Mapping) else ""
        if not finding_id or (decisions.get(finding_id) or {}).get("decision") != "audit_only":
            errors.append("audit-only candidate lacks one audit authority decision")
    hypothesis_ids = []
    hypothesis_sets = value.get("hypothesis_sets") or []
    for hypothesis_set in hypothesis_sets:
        errors.extend(validate_threat_hypothesis_set_v2(hypothesis_set, graph, coverage))
        hypothesis_ids.append(_text(hypothesis_set.get("hypothesis_set_id")))
    if len(hypothesis_ids) != len(set(hypothesis_ids)):
        errors.append("hypothesis set IDs are invalid")
    if hypothesis_sets != _hypothesis_sets(graph, coverage):
        errors.append("hypothesis sets do not match the reviewed graph-derived contract")
    guidance = value.get("response_guidance_v3")
    errors.extend(f"response guidance: {error}" for error in validate_response_guidance_v3(guidance))
    if value.get("assessment_id") != canonical_assessment_id(value):
        errors.append("assessment ID mismatch")
    if raise_on_error and errors:
        raise SessionAssessmentV5Error("; ".join(errors))
    return errors


def validate_session_assessment(value: Any, *, raise_on_error: bool = False) -> list[str]:
    if isinstance(value, Mapping) and value.get("schema_version") == SCHEMA_VERSION:
        return validate_session_assessment_v5(value, raise_on_error=raise_on_error)
    return validate_session_assessment_v4(value, raise_on_error=raise_on_error)


def trusted_behavioral_findings_for_presentation(
    value: Any,
    *,
    raise_on_error: bool = False,
) -> list[dict[str, Any]]:
    """Return only findings backed by a trusted graph authority decision.

    Historical v4 records remain immutable and readable, but their top-level
    finding list is not itself an authority boundary.  Current consumers use
    this derived view so an audit-only candidate in a historical record cannot
    be presented as canonical.
    """

    errors = validate_session_assessment(value)
    if errors:
        if raise_on_error:
            raise SessionAssessmentV5Error(
                "; ".join(errors),
                producer="trusted_behavioral_findings_for_presentation",
            )
        return []
    if not isinstance(value, Mapping):
        return []
    graph = ((value.get("canonical_evidence") or {}).get("semantic_graph") or {})
    decisions = {
        _text(item.get("candidate_id")): _text(item.get("decision"))
        for item in graph.get("authority_decisions") or []
        if isinstance(item, Mapping)
    }
    return [
        deepcopy(dict(finding))
        for finding in value.get("behavioral_findings") or []
        if isinstance(finding, Mapping)
        and decisions.get(_text(finding.get("finding_id"))) == "trusted"
    ]


__all__ = [
    "SessionAssessmentV5Error", "build_session_assessment_v5",
    "canonical_assessment_id",
    "read_legacy_session_assessment", "validate_session_assessment",
    "validate_session_assessment_v5", "validate_threat_hypothesis_set_v2",
    "trusted_behavioral_findings_for_presentation",
]
