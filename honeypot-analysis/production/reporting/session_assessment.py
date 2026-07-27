"""Additive Session Assessment v3 adapter for canonical Threat Hypothesis v2.

The adapter does not reinterpret raw telemetry.  It copies the authoritative
v2 observations, relationships, and claims into a clearer assessment contract
and adds bounded hypothesis-management fields.  Existing v2 reports remain
unchanged and historical payloads are never recomputed implicitly.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Iterable, List

from production.utils.serialization import stable_id, utc_now


SCHEMA_VERSION = "session_assessment.v3"
LIFECYCLE_STATES = (
    "active",
    "supported",
    "partially_supported",
    "disconfirmed",
    "abstained",
    "superseded",
    "resolved",
)


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _dicts(values: Iterable[Any]) -> List[Dict[str, Any]]:
    return [deepcopy(item) for item in values or [] if isinstance(item, dict)]


def _texts(values: Iterable[Any]) -> List[str]:
    output: List[str] = []
    for item in values or []:
        text = _clean(item.get("text")) if isinstance(item, dict) else _clean(item)
        if text and text not in output:
            output.append(text)
    return output


def _claim_record(claim: Dict[str, Any]) -> Dict[str, Any]:
    evidence_status = _clean(claim.get("evidence_status")) or "insufficient_evidence"
    lifecycle_state = {
        "supported": "supported",
        "partially_supported": "partially_supported",
        "insufficient_evidence": "abstained",
    }.get(evidence_status, "abstained")
    refs = [_clean(ref) for ref in claim.get("evidence_refs") or [] if _clean(ref)]
    limitations = _texts(claim.get("limitations") or []) or [
        "The claim is limited to behavior observable inside this Cowrie session."
    ]
    return {
        "claim_id": _clean(claim.get("claim_id")),
        "claim_type": _clean(claim.get("claim_type")),
        "statement": _clean(claim.get("text")),
        "lifecycle_state": lifecycle_state,
        "evidence_status": evidence_status,
        "supporting_evidence_refs": refs,
        "counterevidence": [],
        "assumptions": [
            "Referenced Cowrie telemetry and trusted classification provenance remain valid.",
        ],
        "limitations": limitations,
        "information_gaps": [],
        "falsification_conditions": [
            "Withdraw or revise this claim if its supporting evidence is invalidated or reclassified as audit-only."
        ],
        "source_claim": {
            "schema_version": "threat_hypothesis.v2",
            "claim_basis": _clean(claim.get("claim_basis")),
            "behavior_policy_rule_id": _clean(claim.get("behavior_policy_rule_id")),
        },
    }


def _hypothesis_sets(follow_on: Dict[str, Any]) -> List[Dict[str, Any]]:
    claims = _dicts(follow_on.get("claims") or [])
    if not claims:
        return []
    gaps = _dicts(follow_on.get("evidence_gaps") or [])
    disconfirming = _dicts(follow_on.get("disconfirming_observations") or [])
    gap_text = _texts(gaps)
    sets: List[Dict[str, Any]] = []
    for claim in claims:
        chain_id = _clean(claim.get("connected_chain_id"))
        relevant_counterevidence = [
            item for item in disconfirming
            if not chain_id or _clean(item.get("connected_chain_id")) == chain_id
        ]
        primary_id = stable_id("hypothesis", {
            "claim_id": claim.get("claim_id"),
            "chain_id": chain_id,
            "kind": "follow_on_execution",
        })
        alternative_id = stable_id("hypothesis", {
            "claim_id": claim.get("claim_id"),
            "chain_id": chain_id,
            "kind": "no_observable_follow_on",
        })
        sets.append({
            "hypothesis_set_id": stable_id("hypothesis_set", {
                "claim_id": claim.get("claim_id"),
                "chain_id": chain_id,
            }),
            "question": "What best explains the incomplete transfer-related behavior visible in this Cowrie session?",
            "scope": "bounded_post_session_cowrie_observable_behavior",
            "alternatives_are_exhaustive": False,
            "alternatives_are_mutually_exclusive": False,
            "hypotheses": [
                {
                    "hypothesis_id": primary_id,
                    "statement": _clean(claim.get("text")),
                    "lifecycle_state": "active",
                    "supporting_evidence_refs": [
                        _clean(ref) for ref in claim.get("evidence_refs") or [] if _clean(ref)
                    ],
                    "counterevidence": relevant_counterevidence,
                    "assumptions": [
                        "The incomplete connected chain represents meaningful attacker activity rather than an abandoned or failed attempt."
                    ],
                    "limitations": _texts(claim.get("limitations") or []),
                    "information_gaps": gap_text,
                    "falsification_conditions": [
                        "A Cowrie-reported failed prerequisite transfer weakens this hypothesis.",
                        "Evidence that the referenced artifact was never available for execution weakens this hypothesis.",
                    ],
                },
                {
                    "hypothesis_id": alternative_id,
                    "statement": (
                        "No follow-on artifact execution is observable in this Cowrie session; "
                        "the transfer attempt may have failed, stopped, or continued outside Cowrie visibility."
                    ),
                    "lifecycle_state": "active",
                    "supporting_evidence_refs": [
                        _clean(ref)
                        for item in relevant_counterevidence
                        for ref in item.get("evidence_refs") or []
                        if _clean(ref)
                    ],
                    "counterevidence": [{
                        "text": "The incomplete connected chain supports considering follow-on execution.",
                        "evidence_refs": [
                            _clean(ref) for ref in claim.get("evidence_refs") or [] if _clean(ref)
                        ],
                    }],
                    "assumptions": [
                        "Cowrie visibility ends with the recorded session and cannot establish activity on external systems."
                    ],
                    "limitations": [
                        "Absence of an observed execution command is not proof that execution did not occur elsewhere."
                    ],
                    "information_gaps": gap_text,
                    "falsification_conditions": [
                        "A later evidence-linked execution observation would disconfirm the no-observable-follow-on explanation for the expanded evidence window."
                    ],
                },
            ],
        })
    return sets


def forecast_section(model_prediction: Any) -> Dict[str, Any]:
    prediction = deepcopy(model_prediction) if isinstance(model_prediction, dict) else {}
    return {
        "separation_semantics": "statistical_forecast_not_observed_evidence_or_factual_confidence",
        "status": _clean(prediction.get("status")) or "unavailable",
        "forecast": prediction,
    }


def build_session_assessment_v3(v2_report: Dict[str, Any]) -> Dict[str, Any]:
    """Adapt a canonical v2 report without changing its existing fields."""

    observed = v2_report.get("observed_behavior") or {}
    supported = v2_report.get("supported_assessment") or {}
    follow_on = v2_report.get("follow_on_hypothesis") or {}
    claims = [_claim_record(item) for item in supported.get("possible_objectives") or [] if isinstance(item, dict)]
    hypothesis_sets = _hypothesis_sets(follow_on)
    falsification_conditions = list(dict.fromkeys(
        condition
        for hypothesis_set in hypothesis_sets
        for hypothesis in hypothesis_set.get("hypotheses") or []
        for condition in hypothesis.get("falsification_conditions") or []
        if _clean(condition)
    ))
    evidence_refs = sorted({
        _clean(ref)
        for claim in claims
        for ref in claim.get("supporting_evidence_refs") or []
        if _clean(ref)
    })
    behavior_policy = deepcopy(v2_report.get("behavior_policy") or observed.get("behavior_policy") or {})
    session_id = _clean(observed.get("session_id") or v2_report.get("session_id")) or "unknown"
    assessment_id = stable_id("session_assessment", {
        "session_id": session_id,
        "behavior_policy": behavior_policy,
        "claim_ids": [item.get("claim_id") for item in claims],
        "evidence_refs": evidence_refs,
        "hypothesis_set_ids": [item.get("hypothesis_set_id") for item in hypothesis_sets],
    })
    return {
        "schema_version": SCHEMA_VERSION,
        "assessment_id": assessment_id,
        "generated_at": _clean(v2_report.get("created_at")) or utc_now(),
        "source_scope": {
            "session_ids": [session_id],
            "session_count": 1,
            "scope": "single_cowrie_ssh_session",
        },
        "provenance": {
            "source_schema": "threat_hypothesis.v2",
            "adapter": "deterministic_additive_v3",
            "behavior_policy": behavior_policy,
            "degraded_mode": (
                behavior_policy.get("operating_mode")
                if behavior_policy.get("operating_mode") != "trusted_selected_policy"
                else "none"
            ),
        },
        "evidence": {
            "ordered_behavior_chain": _dicts(observed.get("ordered_behavior_chain") or []),
            "observations": _dicts(observed.get("ordered_command_observations") or []),
            "transfer_observations": _dicts(observed.get("transfer_event_observations") or []),
            "entities": _dicts(observed.get("normalized_entities") or []),
            "relationships": _dicts(observed.get("behavior_relationships") or []),
            "connected_behavior_chains": _dicts(observed.get("connected_behavior_chains") or []),
            "direct_cowrie_events": _dicts(observed.get("cowrie_event_evidence") or []),
            "audit_only_candidates": _dicts(observed.get("audit_only_candidates") or []),
        },
        "assessment": {
            "status": _clean(supported.get("assessment_status")) or "observed_behavior_only",
            "summary": _clean(supported.get("behavior_summary")),
            "claims": claims,
            "unknowns": _texts(supported.get("unknowns") or []),
        },
        "hypothesis_management": {
            "lifecycle_states": list(LIFECYCLE_STATES),
            "hypothesis_sets": hypothesis_sets,
            "abstained": bool(follow_on.get("abstained")),
            "abstention_reason": _clean(follow_on.get("abstention_reason")),
            "information_gaps": _dicts(follow_on.get("evidence_gaps") or []),
            "counterevidence": _dicts(follow_on.get("disconfirming_observations") or []),
            "falsification_conditions": falsification_conditions,
        },
        "enrichment": {
            "separation_semantics": "context_only_not_behavioral_claim_evidence",
            "context": deepcopy(v2_report.get("contextual_intelligence") or {}),
        },
        "next_tactic_forecast": forecast_section(v2_report.get("model_prediction")),
        "response_guidance_ref": {
            "schema_version": "response_guidance.v3",
            "status": "not_attached",
        },
        "compatibility": {
            "threat_hypothesis_v2_preserved": True,
            "historical_reports_recomputed": False,
        },
    }


def attach_forecast_to_session_assessment(
    assessment: Dict[str, Any],
    model_prediction: Dict[str, Any],
) -> Dict[str, Any]:
    """Update only the separated forecast section of an existing v3 record."""

    updated = deepcopy(assessment)
    updated["next_tactic_forecast"] = forecast_section(model_prediction)
    return updated
