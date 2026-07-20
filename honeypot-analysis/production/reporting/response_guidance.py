"""Additive advisory Response Guidance v2 contract.

The trusted v1 policy decision remains authoritative.  This module separates
its finding, triage, and advisory action concerns and adds only a lightweight
human decision/outcome record.  It never selects actions with a model or
executes a response.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Iterable, List, Optional, Set

from production.utils.serialization import stable_id, utc_now


SCHEMA_VERSION = "response_guidance.v2"
ANALYST_RECORD_SCHEMA_VERSION = "analyst_guidance_decision.v1"
ANALYST_DECISION_STATES = ("unreviewed", "approved", "rejected", "deferred")
OUTCOME_STATES = ("not_recorded", "completed", "partially_completed", "not_applicable", "failed")
CANONICAL_BEHAVIORAL_EVIDENCE_SCOPES = frozenset({"observed_behavior"})


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _texts(values: Iterable[Any]) -> List[str]:
    output: List[str] = []
    for value in values or []:
        text = _clean(value)
        if text and text not in output:
            output.append(text)
    return output


def _strict_text_list(value: Any) -> Optional[List[str]]:
    """Return normalized JSON string-list content, or ``None`` when malformed."""

    if not isinstance(value, list):
        return None
    output: List[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            return None
        text = item.strip()
        if text not in output:
            output.append(text)
    return output


def canonical_behavioral_evidence_refs(observed_behavior: Any) -> Set[str]:
    """Return IDs emitted by the deterministic observed-behavior reconstruction."""

    if not isinstance(observed_behavior, dict):
        return set()
    refs: Set[str] = set()
    for key in (
        "ordered_behavior_chain",
        "ordered_command_observations",
        "cowrie_event_evidence",
        "transfer_event_observations",
        "trusted_attck_candidates",
    ):
        for item in observed_behavior.get(key) or []:
            if isinstance(item, dict) and _clean(item.get("evidence_id")):
                refs.add(_clean(item.get("evidence_id")))
    for key in ("connected_behavior_chains", "behavior_relationships"):
        for item in observed_behavior.get(key) or []:
            if not isinstance(item, dict):
                continue
            item_refs = _strict_text_list(item.get("evidence_refs") or [])
            if item_refs is not None:
                refs.update(item_refs)
    return refs


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


def _action_applicability(
    action: Dict[str, Any],
    canonical_evidence_refs: Optional[Set[str]],
) -> Dict[str, Any]:
    scopes = _strict_text_list(action.get("evidence_scope")) or []
    source_refs = _strict_text_list(action.get("evidence_refs")) or []
    matched_refs = (
        source_refs
        if canonical_evidence_refs is None
        else [ref for ref in source_refs if ref in canonical_evidence_refs]
    )
    canonical = bool(
        set(scopes).intersection(CANONICAL_BEHAVIORAL_EVIDENCE_SCOPES)
        and matched_refs
    )
    status = "applicable_under_policy" if canonical else "context_dependent"
    return {
        "status": status,
        "basis": "trusted_policy_match",
        "evidence_scope": scopes,
        "evidence_refs": matched_refs,
    }


def _advisory_action(
    action: Dict[str, Any],
    canonical_evidence_refs: Set[str],
) -> Dict[str, Any]:
    applicability = _action_applicability(action, canonical_evidence_refs)
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


def _canonical_grounding_errors(
    action: Any,
    *,
    canonical_evidence_refs: Optional[Set[str]] = None,
) -> List[str]:
    if not isinstance(action, dict):
        return ["source action must be an object"]
    errors: List[str] = []
    scopes = _strict_text_list(action.get("evidence_scope"))
    refs = _strict_text_list(action.get("evidence_refs"))
    if scopes is None:
        errors.append("malformed evidence_scope")
    elif not set(scopes).intersection(CANONICAL_BEHAVIORAL_EVIDENCE_SCOPES):
        errors.append("missing canonical behavioral evidence scope")
    if refs is None:
        errors.append("malformed evidence_refs")
    elif not refs:
        errors.append("missing canonical behavioral evidence reference")
    elif canonical_evidence_refs is not None and not set(refs).intersection(canonical_evidence_refs):
        errors.append("evidence_refs do not identify canonical observed behavior")
    return errors


def validate_response_guidance(
    value: Any,
    *,
    canonical_actions: Optional[List[Dict[str, Any]]] = None,
    canonical_evidence_refs: Optional[Set[str]] = None,
    source_decision: Optional[Dict[str, Any]] = None,
) -> List[str]:
    errors: List[str] = []
    if not isinstance(value, dict):
        return ["response guidance must be an object"]
    if value.get("schema_version") != SCHEMA_VERSION:
        errors.append("unsupported response guidance schema")
    if _clean(value.get("authority")) not in {"trusted_policy_engine", "policy_unavailable"}:
        errors.append("unsupported response guidance authority")
    from production.reporting.smb_decision import is_trusted_recommendation_action

    actions = value.get("advisory_actions")
    if not isinstance(actions, list):
        errors.append("advisory_actions must be an array")
        actions = []
    expected_actions = {
        _clean(action.get("action_id")): action
        for action in (canonical_actions or [])
        if isinstance(action, dict) and _clean(action.get("action_id"))
    }
    seen_action_ids: Set[str] = set()
    for index, action in enumerate(actions):
        if not isinstance(action, dict):
            errors.append(f"advisory_actions[{index}] must be an object")
            continue
        source_action = action.get("source_action")
        if not is_trusted_recommendation_action(source_action):
            errors.append(f"advisory_actions[{index}] lacks a trusted source action")
        grounding_errors = _canonical_grounding_errors(
            source_action,
            canonical_evidence_refs=canonical_evidence_refs,
        )
        errors.extend(
            f"advisory_actions[{index}] {error}" for error in grounding_errors
        )
        applicability = action.get("applicability")
        applicability_errors = _canonical_grounding_errors(
            applicability,
            canonical_evidence_refs=canonical_evidence_refs,
        )
        errors.extend(
            f"advisory_actions[{index}] applicability {error}"
            for error in applicability_errors
        )
        action_id = _clean(action.get("action_id"))
        if not action_id:
            errors.append(f"advisory_actions[{index}] missing action_id")
        elif action_id in seen_action_ids:
            errors.append(f"advisory_actions[{index}] duplicates action_id")
        else:
            seen_action_ids.add(action_id)
        if canonical_actions is not None:
            expected = expected_actions.get(action_id)
            if expected is None or source_action != expected:
                errors.append(f"advisory_actions[{index}] is inconsistent with canonical action")
        expected_applicability = _action_applicability(
            source_action if isinstance(source_action, dict) else {},
            canonical_evidence_refs,
        )
        if action.get("applicability") != expected_applicability:
            errors.append(f"advisory_actions[{index}] has inconsistent applicability")
        for field, source_field in (
            ("description", "action"),
            ("rationale", "why"),
            ("policy_order", "priority"),
            ("provenance", "provenance"),
        ):
            expected_value = (
                deepcopy(source_action.get(source_field))
                if isinstance(source_action, dict) else None
            )
            if action.get(field) != expected_value:
                errors.append(f"advisory_actions[{index}] has inconsistent {field}")
        if action.get("manual_approval") != {
            "required": True,
            "state": "pending",
            "execution_authority": False,
        }:
            errors.append(f"advisory_actions[{index}] must require manual approval")
        for field in ("preconditions", "verification_steps"):
            if not action.get(field):
                errors.append(f"advisory_actions[{index}] missing {field}")
        if not _clean(action.get("rollback_guidance")):
            errors.append(f"advisory_actions[{index}] missing rollback guidance")
    source = value.get("source_decision") or {}
    if source_decision is not None and source != {
        "schema_version": _clean(source_decision.get("schema_version")),
        "decision_id": _clean(source_decision.get("decision_id")),
    }:
        errors.append("source_decision is inconsistent with canonical decision")
    if source_decision is not None:
        expected_policy = deepcopy((source_decision.get("trust") or {}).get("policy") or {})
        provenance = value.get("provenance") or {}
        if not isinstance(provenance, dict) or provenance.get("policy") != expected_policy:
            errors.append("guidance policy provenance is inconsistent with canonical decision")
        if provenance.get("selection_authority") != "deterministic_trusted_policy":
            errors.append("guidance selection authority is inconsistent")
        if provenance.get("prediction_authority") != "advisory_forecast_only_no_action_selection":
            errors.append("guidance prediction authority is inconsistent")
    analyst_record = value.get("analyst_decision")
    if (
        isinstance(analyst_record, dict)
        and analyst_record.get("guidance_id") != value.get("guidance_id")
    ):
        errors.append("analyst decision guidance_id is inconsistent")
    errors.extend(validate_analyst_decision_record(analyst_record))
    return errors


def build_response_guidance_v2(
    v1_decision: Dict[str, Any],
    *,
    observed_behavior: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Adapt a trusted v1 decision; never generate an independent action."""

    from production.reporting.smb_decision import is_trusted_recommendation_action

    decision = v1_decision if isinstance(v1_decision, dict) else {}
    observed = observed_behavior if isinstance(observed_behavior, dict) else {}
    canonical_refs = canonical_behavioral_evidence_refs(observed)
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
            grounding_errors = _canonical_grounding_errors(
                source_action,
                canonical_evidence_refs=canonical_refs,
            )
            if not is_trusted_recommendation_action(source_action):
                grounding_errors.append("source action failed trusted policy contract")
            if grounding_errors:
                rejected.append({
                    "action_id": _clean(source_action.get("action_id")),
                    "reason": "canonical_behavioral_evidence_required",
                    "errors": grounding_errors,
                })
                continue
            candidate = _advisory_action(source_action, canonical_refs)
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
        "status": (
            "available"
            if policy_available
            and canonical_available
            and (advisory_actions or not decision.get("immediate_actions"))
            else "unavailable"
        ),
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
    validation_errors = validate_response_guidance(
        guidance,
        canonical_actions=[
            action for action in decision.get("immediate_actions") or []
            if isinstance(action, dict)
        ],
        canonical_evidence_refs=canonical_refs,
        source_decision=decision,
    )
    if rejected and not advisory_actions:
        validation_errors.append("no immediate action has canonical behavioral grounding")
    if validation_errors:
        guidance["status"] = "unavailable"
        guidance["authority"] = "policy_unavailable"
        guidance["advisory_actions"] = []
        guidance["validation"] = {"status": "rejected", "errors": validation_errors}
    else:
        guidance["validation"] = {"status": "valid", "errors": []}
    return guidance
