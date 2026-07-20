"""Additive advisory Response Guidance v2 contract.

The trusted v1 policy decision remains authoritative.  This module separates
its finding, triage, and advisory action concerns and adds only a lightweight
human decision/outcome record.  It never selects actions with a model or
executes a response.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Iterable, List

from production.utils.serialization import stable_id, utc_now


SCHEMA_VERSION = "response_guidance.v2"
ANALYST_RECORD_SCHEMA_VERSION = "analyst_guidance_decision.v1"
ANALYST_DECISION_STATES = ("unreviewed", "approved", "rejected", "deferred")
OUTCOME_STATES = ("not_recorded", "completed", "partially_completed", "not_applicable", "failed")


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _texts(values: Iterable[Any]) -> List[str]:
    output: List[str] = []
    for value in values or []:
        text = _clean(value)
        if text and text not in output:
            output.append(text)
    return output


def new_analyst_decision_record(guidance_id: str) -> Dict[str, Any]:
    """Return an inert, non-authorizing analyst record template."""

    return {
        "schema_version": ANALYST_RECORD_SCHEMA_VERSION,
        "guidance_id": guidance_id,
        "decision_state": "unreviewed",
        "decided_by": "",
        "decided_at": "",
        "notes": "",
        "outcome": {
            "state": "not_recorded",
            "verified": False,
            "verified_by": "",
            "verified_at": "",
            "notes": "",
        },
        "semantics": "record_only_no_execution_authority",
    }


def validate_analyst_decision_record(record: Any) -> List[str]:
    errors: List[str] = []
    if not isinstance(record, dict):
        return ["analyst decision record must be an object"]
    if record.get("schema_version") != ANALYST_RECORD_SCHEMA_VERSION:
        errors.append("unsupported analyst decision schema")
    if _clean(record.get("decision_state")) not in ANALYST_DECISION_STATES:
        errors.append("unsupported analyst decision state")
    outcome = record.get("outcome")
    if not isinstance(outcome, dict) or _clean(outcome.get("state")) not in OUTCOME_STATES:
        errors.append("unsupported analyst outcome state")
    if record.get("semantics") != "record_only_no_execution_authority":
        errors.append("analyst record may not grant execution authority")
    return errors


def _action_applicability(action: Dict[str, Any]) -> Dict[str, Any]:
    scopes = _texts(action.get("evidence_scope") or [])
    canonical = bool(set(scopes).intersection({
        "observed_session_evidence",
        "canonical_observed_evidence",
        "session_context",
    })) or bool(action.get("evidence_refs"))
    status = "applicable_under_policy" if canonical else "context_dependent"
    return {
        "status": status,
        "basis": "trusted_policy_match",
        "evidence_scope": scopes,
        "evidence_refs": _texts(action.get("evidence_refs") or []),
    }


def _advisory_action(action: Dict[str, Any]) -> Dict[str, Any]:
    applicability = _action_applicability(action)
    return {
        "action_id": _clean(action.get("action_id")),
        "description": _clean(action.get("action")),
        "rationale": _clean(action.get("why")),
        "action_class": "advisory_investigation_or_protective_task",
        "applicability": applicability,
        "policy_order": action.get("priority"),
        "preconditions": [
            "Verify the cited evidence and its Cowrie visibility limitations.",
            "Confirm the target system is owned or explicitly authorized for the proposed action.",
            "Obtain the required human approval before making any external-system change.",
        ],
        "owner_role": "security_analyst",
        "verification_steps": [
            "Record whether the advisory action was applicable to an authorized real system.",
            "Record the observed result and the evidence used to verify it.",
        ],
        "rollback_guidance": (
            "No action is executed by this system. Define and approve a target-specific rollback "
            "before performing any change on an authorized real system."
        ),
        "expires_at": None,
        "expiry_policy": "Re-evaluate evidence, policy version, and asset context before later use.",
        "manual_approval": {
            "required": True,
            "state": "pending",
            "execution_authority": False,
        },
        "provenance": deepcopy(action.get("provenance") or {}),
        "source_action": deepcopy(action),
    }


def validate_response_guidance(value: Any) -> List[str]:
    errors: List[str] = []
    if not isinstance(value, dict):
        return ["response guidance must be an object"]
    if value.get("schema_version") != SCHEMA_VERSION:
        errors.append("unsupported response guidance schema")
    if _clean(value.get("authority")) not in {"trusted_policy_engine", "policy_unavailable"}:
        errors.append("unsupported response guidance authority")
    from production.reporting.smb_decision import is_trusted_recommendation_action

    for index, action in enumerate(value.get("advisory_actions") or []):
        if not isinstance(action, dict):
            errors.append(f"advisory_actions[{index}] must be an object")
            continue
        source_action = action.get("source_action")
        if not is_trusted_recommendation_action(source_action):
            errors.append(f"advisory_actions[{index}] lacks a trusted source action")
        scopes = set((action.get("applicability") or {}).get("evidence_scope") or [])
        if scopes and scopes.issubset({"model_prediction"}):
            errors.append(f"advisory_actions[{index}] relies only on statistical prediction")
        if (action.get("manual_approval") or {}).get("required") is not True:
            errors.append(f"advisory_actions[{index}] must require manual approval")
        for field in ("preconditions", "verification_steps"):
            if not action.get(field):
                errors.append(f"advisory_actions[{index}] missing {field}")
        if not _clean(action.get("rollback_guidance")):
            errors.append(f"advisory_actions[{index}] missing rollback guidance")
    errors.extend(validate_analyst_decision_record(value.get("analyst_decision")))
    return errors


def build_response_guidance_v2(
    v1_decision: Dict[str, Any],
    *,
    observed_behavior: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Adapt a trusted v1 decision; never generate an independent action."""

    decision = v1_decision if isinstance(v1_decision, dict) else {}
    observed = observed_behavior if isinstance(observed_behavior, dict) else {}
    trust = decision.get("trust") or {}
    policy = deepcopy(trust.get("policy") or {})
    canonical_status = _clean(
        ((decision.get("evidence") or {}).get("canonical_summary") or {}).get("status")
    ) or ("available" if observed else "unavailable")
    authority = _clean(decision.get("authority")) or "policy_unavailable"
    policy_available = decision.get("status") == "available" and authority == "trusted_policy_engine"
    canonical_available = canonical_status == "available"

    advisory_actions: List[Dict[str, Any]] = []
    rejected: List[Dict[str, Any]] = []
    if policy_available and canonical_available:
        for source_action in decision.get("immediate_actions") or []:
            if not isinstance(source_action, dict):
                continue
            candidate = _advisory_action(source_action)
            scopes = set((candidate.get("applicability") or {}).get("evidence_scope") or [])
            if scopes and scopes.issubset({"model_prediction"}):
                rejected.append({
                    "action_id": candidate.get("action_id"),
                    "reason": "statistical_prediction_cannot_be_the_sole_action_basis",
                })
                continue
            advisory_actions.append(candidate)

    guidance_id = stable_id("response_guidance", {
        "decision_id": decision.get("decision_id"),
        "policy": policy,
        "action_ids": [item.get("action_id") for item in advisory_actions],
        "canonical_status": canonical_status,
    })
    risk = deepcopy(decision.get("risk") or {})
    severity = _clean(risk.get("severity")) or "info"
    guidance = {
        "schema_version": SCHEMA_VERSION,
        "guidance_id": guidance_id,
        "generated_at": _clean(decision.get("generated_at")) or utc_now(),
        "status": "available" if policy_available and canonical_available else "unavailable",
        "authority": authority if policy_available else "policy_unavailable",
        "session_id": _clean(decision.get("session_id")) or "unknown",
        "source_decision": {
            "schema_version": _clean(decision.get("schema_version")),
            "decision_id": _clean(decision.get("decision_id")),
        },
        "finding": {
            "finding_id": stable_id("guidance_finding", {
                "decision_id": decision.get("decision_id"),
                "risk_rule": risk.get("rule_id"),
            }),
            "kind": "cowrie_session_policy_finding",
            "observation_state": "observed_or_policy_inferred_from_canonical_evidence",
            "policy_severity": severity,
            "statement": _clean(risk.get("reason")),
            "supporting_evidence_refs": _texts(risk.get("evidence_refs") or []),
            "limitations": _texts(trust.get("limitations") or []),
        },
        "triage": {
            "review_priority": severity,
            "urgency": "prompt_review" if severity in {"high", "critical"} else "routine_review",
            "scope": "honeypot_observation_and_configured_asset_context",
            "rationale": _clean(risk.get("reason")),
            "semantics": "categorical_policy_triage_not_numeric_risk",
        },
        "advisory_actions": advisory_actions,
        "rejected_candidates": rejected,
        "analyst_decision": new_analyst_decision_record(guidance_id),
        "provenance": {
            "policy": policy,
            "canonical_evidence_status": canonical_status,
            "degraded_mode": "none" if canonical_available else "canonical_evidence_unavailable",
            "selection_authority": "deterministic_trusted_policy",
            "prediction_authority": "advisory_forecast_only_no_action_selection",
        },
        "safety": {
            "automatic_execution": False,
            "manual_approval_required": True,
            "execution_integration": "not_implemented",
        },
        "compatibility": {
            "smb_decision_v1_preserved": True,
            "historical_decisions_recomputed": False,
        },
    }
    validation_errors = validate_response_guidance(guidance)
    if validation_errors:
        guidance["status"] = "unavailable"
        guidance["authority"] = "policy_unavailable"
        guidance["advisory_actions"] = []
        guidance["validation"] = {"status": "rejected", "errors": validation_errors}
    else:
        guidance["validation"] = {"status": "valid", "errors": []}
    return guidance
