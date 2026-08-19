"""Final graph-bound canonical session assessment contract."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from typing import Any, Iterable, Mapping, Optional

from production.reporting.behavioral_authority import validate_behavioral_authority
from production.reporting.canonical_graph_queries import canonical_graph_view
from production.reporting.canonical_semantic_graph import validate_canonical_semantic_graph
from production.reporting.response_guidance_v4 import (
    build_response_guidance_v4_from_paths,
    validate_response_guidance_v4,
)
from production.reporting.session_assessment_v5 import (
    SessionAssessmentV5Error,
    _hypothesis_sets,
    build_session_assessment_v5,
    read_legacy_session_assessment,
    trusted_behavioral_findings_for_presentation as _legacy_trusted_findings,
    validate_session_assessment as validate_legacy_session_assessment,
    validate_threat_hypothesis_set_v2,
)
from production.utils.serialization import stable_id, stable_json
from production.storage.session_provenance import (
    CONTROLLED_SYNTHETIC_PROVENANCE_MARKER,
    SESSION_SOURCE_E2E_TEST,
)


SCHEMA_VERSION = "session_assessment.v6"
_REQUIRED_KEYS = frozenset({
    "schema_version", "assessment_id", "report_content_sha256",
    "generated_at", "status", "abstention", "canonical_evidence",
    "behavioral_findings", "audit_only_behavioral_candidates",
    "hypothesis_sets", "response_guidance_v4", "provenance", "authority",
    "non_authoritative_context", "compatibility",
})
_OPERATIONAL_KEYS = frozenset({
    "session_id", "created_at", "worker", "correlation_id", "artifacts",
    "bpg_list", "data_provenance", "ioc_summary",
})
_CONTENT_EXCLUSIONS = frozenset({
    "assessment_id", "report_content_sha256", "generated_at",
    "session_id", "created_at", "worker", "correlation_id", "artifacts",
    "non_authoritative_context", "bpg_list", "data_provenance", "ioc_summary",
})


class SessionAssessmentV6Error(SessionAssessmentV5Error):
    """Raised when a current v6 report violates its complete core contract."""


def _text(value: Any) -> str:
    return str(value or "").strip()


def _sha(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def report_content_basis(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return the complete authoritative report content.

    Operational envelope fields and explicitly non-authoritative context are
    excluded; every canonical, authority, hypothesis, guidance, policy, and
    compatibility field is included.
    """

    basis = {
        key: deepcopy(item)
        for key, item in value.items()
        if key not in _CONTENT_EXCLUSIONS
    }
    guidance = basis.get("response_guidance_v4")
    if isinstance(guidance, dict):
        guidance.pop("generated_at", None)
    return basis


def refresh_session_assessment_v6_identity(value: dict[str, Any]) -> dict[str, Any]:
    if value.get("schema_version") != SCHEMA_VERSION:
        raise SessionAssessmentV6Error("only v6 assessments can be re-identified")
    value["report_content_sha256"] = _sha(report_content_basis(value))
    value["assessment_id"] = stable_id(
        "session_assessment_v6", value["report_content_sha256"]
    )
    return value


def build_session_assessment_v6(
    sessions: Iterable[Any],
    raw_events: Optional[list[dict[str, Any]]] = None,
    **kwargs: Any,
) -> dict[str, Any]:
    guidance_policy_path = _text(kwargs.get("response_guidance_policy_path"))
    guidance_profile_path = _text(
        kwargs.get("response_guidance_asset_profile_path")
    )
    record = build_session_assessment_v5(
        sessions,
        raw_events=raw_events,
        **kwargs,
    )
    evidence = record.get("canonical_evidence") or {}
    graph = evidence.get("semantic_graph") or {}
    view = canonical_graph_view(
        graph,
        expected_graph_sha256=_text(graph.get("graph_sha256")),
        expected_observed_evidence_sha256=_text(
            evidence.get("observed_evidence_sha256")
        ),
        expected_typed_fact_set_sha256=_text(
            graph.get("typed_fact_set_sha256")
        ),
    )
    guidance = build_response_guidance_v4_from_paths(
        graph,
        session_id=_text(evidence.get("session_id")) or "unknown",
        policy_path=guidance_policy_path,
        asset_profile_path=guidance_profile_path,
        expected_graph_sha256=view.graph_sha256,
        expected_observed_evidence_sha256=view.observed_evidence_sha256,
        expected_typed_fact_set_sha256=view.typed_fact_set_sha256,
        generated_at=_text(record.get("generated_at")),
    )
    record.pop("response_guidance_v3", None)
    record["schema_version"] = SCHEMA_VERSION
    record["response_guidance_v4"] = guidance
    record["compatibility"] = {
        "historical_v4_v5_records": "read_only_not_recomputed",
        "historical_response_guidance_v3": "read_only_not_recomputed",
        "new_record_authority": SCHEMA_VERSION,
        "canonical_graph": "single_existing_canonical_semantic_graph_v1",
    }
    record["report_content_sha256"] = ""
    refresh_session_assessment_v6_identity(record)
    validate_session_assessment_v6(record, raise_on_error=True)
    return record


def validate_session_assessment_v6(
    value: Any,
    *,
    raise_on_error: bool = False,
) -> list[str]:
    errors = []
    if not isinstance(value, Mapping):
        errors.append("session assessment v6 must be an object")
        value = {}
    keys = set(value)
    if not _REQUIRED_KEYS.issubset(keys) or keys - _REQUIRED_KEYS - _OPERATIONAL_KEYS:
        errors.append("session assessment v6 has an invalid closed shape")
    if value.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")
    evidence = value.get("canonical_evidence") or {}
    copied_evidence = deepcopy(dict(evidence)) if isinstance(evidence, Mapping) else {}
    recorded_evidence = _text(copied_evidence.pop("evidence_sha256", ""))
    if recorded_evidence != _sha(copied_evidence):
        errors.append("canonical evidence hash mismatch")
    graph = evidence.get("semantic_graph") or {}
    errors.extend(
        f"semantic graph: {error}"
        for error in validate_canonical_semantic_graph(graph)
    )
    if _text(graph.get("observed_evidence_sha256")) != _text(
        evidence.get("observed_evidence_sha256")
    ):
        errors.append("canonical graph observed-evidence binding mismatch")
    coverage = evidence.get("semantic_coverage") or {}
    if _text(graph.get("semantic_coverage_sha256")) != _text(
        coverage.get("coverage_sha256")
    ):
        errors.append("canonical graph semantic-coverage binding mismatch")
    decision_items = [
        item for item in graph.get("authority_decisions") or []
        if isinstance(item, Mapping)
    ]
    decisions = {_text(item.get("candidate_id")): item for item in decision_items}
    if len(decisions) != len(decision_items):
        errors.append("authority decision candidate IDs must be unique")
    for decision in decisions.values():
        errors.extend(
            f"authority decision: {error}"
            for error in validate_behavioral_authority(decision)
        )
    finding_ids = []
    for finding in value.get("behavioral_findings") or []:
        finding_id = _text(finding.get("finding_id")) if isinstance(finding, Mapping) else ""
        finding_ids.append(finding_id)
        if not finding_id or (decisions.get(finding_id) or {}).get("decision") != "trusted":
            errors.append("canonical finding lacks one trusted authority decision")
    if len(finding_ids) != len(set(finding_ids)):
        errors.append("canonical finding IDs are invalid")
    audit_ids = []
    for finding in value.get("audit_only_behavioral_candidates") or []:
        finding_id = _text(finding.get("finding_id")) if isinstance(finding, Mapping) else ""
        audit_ids.append(finding_id)
        if not finding_id or (decisions.get(finding_id) or {}).get("decision") != "audit_only":
            errors.append("audit-only candidate lacks one audit authority decision")
    if len(audit_ids) != len(set(audit_ids)):
        errors.append("audit-only candidate IDs are invalid")
    expected_trusted = sorted(
        candidate_id
        for candidate_id, decision in decisions.items()
        if decision.get("decision") == "trusted"
    )
    expected_audit = sorted(
        candidate_id
        for candidate_id, decision in decisions.items()
        if decision.get("decision") == "audit_only"
    )
    processing_fallback = (
        value.get("status") == "observation_only_abstention"
        and (value.get("abstention") or {}).get("abstained") is True
        and (value.get("abstention") or {}).get("reason")
        == "analysis_pipeline_failed"
    )
    if processing_fallback:
        if finding_ids or value.get("hypothesis_sets"):
            errors.append("processing fallback must not publish findings or hypotheses")
    elif sorted(finding_ids) != expected_trusted:
        errors.append("canonical findings do not equal trusted authority decisions")
    if sorted(audit_ids) != expected_audit:
        errors.append("audit-only candidates do not equal audit authority decisions")
    hypothesis_sets = value.get("hypothesis_sets") or []
    for hypothesis_set in hypothesis_sets:
        errors.extend(validate_threat_hypothesis_set_v2(hypothesis_set, graph, coverage))
    if not processing_fallback and hypothesis_sets != _hypothesis_sets(
        graph, coverage
    ):
        errors.append("hypothesis sets do not match the graph-derived contract")
    guidance = value.get("response_guidance_v4")
    errors.extend(
        f"response guidance: {error}"
        for error in validate_response_guidance_v4(
            guidance,
            parent_graph=graph,
        )
    )
    if _text((guidance or {}).get("session_id")) != _text(evidence.get("session_id")):
        errors.append("response guidance session binding mismatch")
    expected_authority = {
        "observed_evidence_authoritative": True,
        "predictions_authoritative": False,
        "enrichment_authoritative": False,
        "correlations_authoritative": False,
        "llm_authoritative": False,
        "automatic_response_authorized": False,
        "automatic_alerts_authorized": False,
    }
    if value.get("authority") != expected_authority:
        errors.append("session assessment authority boundary is invalid")
    provenance = value.get("provenance")
    if not isinstance(provenance, Mapping):
        errors.append("session assessment provenance is required")
    else:
        if _text(provenance.get("evidence_sha256")) != recorded_evidence:
            errors.append("session assessment evidence provenance mismatch")
        for label in ("behavior_policy", "classification_policy"):
            digest = _text((provenance.get(label) or {}).get("sha256")).lower()
            if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                errors.append(f"session assessment {label} provenance is invalid")
        evaluation_provenance = provenance.get("evaluation_provenance")
        if evaluation_provenance is not None:
            expected_evaluation_provenance = {
                "schema_version": "controlled_synthetic_provenance.v1",
                "session_source": SESSION_SOURCE_E2E_TEST,
                "provenance_marker": CONTROLLED_SYNTHETIC_PROVENANCE_MARKER,
                "authority": "authenticated_sensor_metadata_allowlist",
                "excluded_from": [
                    "empirical_attacker_statistics",
                    "transformer_training",
                    "transformer_calibration",
                    "transformer_test",
                    "trusted_prediction_history",
                    "real_attacker_evaluation_claims",
                    "production_incident_alert_claims",
                ],
            }
            if evaluation_provenance != expected_evaluation_provenance:
                errors.append("controlled synthetic evaluation provenance is invalid")
    recorded_content = _text(value.get("report_content_sha256")).lower()
    if recorded_content != _sha(report_content_basis(value)):
        errors.append("report content hash mismatch")
    if value.get("assessment_id") != stable_id(
        "session_assessment_v6", recorded_content
    ):
        errors.append("assessment ID mismatch")
    if value.get("compatibility") != {
        "historical_v4_v5_records": "read_only_not_recomputed",
        "historical_response_guidance_v3": "read_only_not_recomputed",
        "new_record_authority": SCHEMA_VERSION,
        "canonical_graph": "single_existing_canonical_semantic_graph_v1",
    }:
        errors.append("session assessment v6 compatibility contract mismatch")
    if raise_on_error and errors:
        raise SessionAssessmentV6Error("; ".join(errors))
    return errors


def validate_session_assessment(value: Any, *, raise_on_error: bool = False) -> list[str]:
    if isinstance(value, Mapping) and value.get("schema_version") == SCHEMA_VERSION:
        return validate_session_assessment_v6(value, raise_on_error=raise_on_error)
    return validate_legacy_session_assessment(value, raise_on_error=raise_on_error)


def trusted_behavioral_findings_for_presentation(
    value: Any,
    *,
    raise_on_error: bool = False,
) -> list[dict[str, Any]]:
    if not isinstance(value, Mapping) or value.get("schema_version") != SCHEMA_VERSION:
        return _legacy_trusted_findings(value, raise_on_error=raise_on_error)
    errors = validate_session_assessment_v6(value)
    if errors:
        if raise_on_error:
            raise SessionAssessmentV6Error("; ".join(errors))
        return []
    decisions = {
        _text(item.get("candidate_id")): _text(item.get("decision"))
        for item in (
            ((value.get("canonical_evidence") or {}).get("semantic_graph") or {}).get(
                "authority_decisions"
            )
            or []
        )
        if isinstance(item, Mapping)
    }
    return [
        deepcopy(dict(finding))
        for finding in value.get("behavioral_findings") or []
        if isinstance(finding, Mapping)
        and decisions.get(_text(finding.get("finding_id"))) == "trusted"
    ]


__all__ = [
    "SCHEMA_VERSION", "SessionAssessmentV6Error",
    "build_session_assessment_v6", "read_legacy_session_assessment",
    "refresh_session_assessment_v6_identity", "report_content_basis",
    "trusted_behavioral_findings_for_presentation",
    "validate_session_assessment", "validate_session_assessment_v6",
]
