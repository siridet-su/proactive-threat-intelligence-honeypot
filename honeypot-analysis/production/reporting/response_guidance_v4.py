"""Closed, content-bound response guidance selected only from the canonical graph."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from string import Formatter
from typing import Any, Iterable, Mapping

from production.policies.validate_response_guidance_policy import (
    validate_response_guidance_asset_profile,
    validate_response_guidance_policy,
)
from production.reporting.canonical_graph_queries import (
    SCHEMA_VERSION as GRAPH_QUERY_SCHEMA_VERSION,
    CanonicalGraphQueryError,
    CanonicalGraphView,
    canonical_graph_view,
)
from production.reporting.response_guidance_v3 import (
    load_response_guidance_asset_profile,
    load_response_guidance_policy,
)
from production.utils.serialization import stable_id, stable_json, utc_now


SCHEMA_VERSION = "response_guidance.v4"
REVIEWED_POLICY_FILE_SHA256 = (
    "f32aa0a45215b8f355dc540327c69dcb75d684bb9876692791e0568cceda5e7d"
)
REVIEWED_POLICY_DOCUMENT_SHA256 = (
    "1424c0436950ecc2eb682038cfad9abf639c662ffc6da5f6e9c1d7b24cc183af"
)
_SAFETY = {
    "automatic_execution": False,
    "manual_approval_required": True,
    "alerting_side_effect": False,
    "response_action_side_effect": False,
    "execution_integration": "not_implemented",
}
_TOP_KEYS = frozenset({
    "schema_version", "guidance_id", "content_sha256", "generated_at",
    "status", "guidance_state", "authority", "session_id",
    "canonical_graph", "graph_binding", "findings", "triage",
    "advisory_actions", "provenance", "safety", "compatibility",
    "presentation_semantics",
})


class ResponseGuidanceV4Error(ValueError):
    """Raised when graph-bound guidance cannot be proven."""


def _text(value: Any) -> str:
    return str(value or "").strip()


def _sha(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def _content_basis(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: deepcopy(item)
        for key, item in value.items()
        if key not in {"guidance_id", "content_sha256", "generated_at"}
    }


def _entity_context(view: CanonicalGraphView, fact_ids: Iterable[str]) -> dict[str, str]:
    context = {
        role: ", ".join(view.entity_ids_for_facts(fact_ids, role=role))
        for role in ("credential_paths", "artifact_hashes", "executed_paths")
    }
    context["src_ip"] = "not available in canonical graph"
    return {
        key: value or "not available in canonical graph"
        for key, value in context.items()
    }


def _render_policy_text(template: Any, values: Mapping[str, str]) -> str:
    text = _text(template)
    fields = {
        field_name
        for _literal, field_name, _format_spec, _conversion
        in Formatter().parse(text)
        if field_name
    }
    if fields - set(values):
        raise ResponseGuidanceV4Error("policy template uses an unbound field")
    return text.format_map(dict(values))


def _rule_match(
    view: CanonicalGraphView,
    rule: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[str], list[dict[str, Any]]]:
    condition = rule.get("applies_when") or {}
    family = _text(rule.get("semantic_family"))
    if not family:
        refs = list(view.command_evidence_refs())
        minimum = int(condition.get("min_command_count") or 0)
        matched = len(refs) >= minimum and minimum > 0
        trace = [{
            "predicate": "min_command_count",
            "expected": minimum,
            "matched": len(refs),
            "result": matched,
            "fact_refs": [],
            "evidence_refs": refs if matched else [],
        }]
        return [], refs if matched else [], trace

    outcomes = list(condition.get("required_outcome_statuses") or [])
    facts = list(view.matching_facts(
        semantic_family=family,
        required_operation_types=(
            condition.get("required_operation_types") or []
        ),
        required_outcome_statuses=outcomes,
    ))
    fact_refs = [_text(item.get("fact_id")) for item in facts]
    evidence_refs = sorted({
        _text(ref)
        for fact in facts
        for ref in fact.get("source_evidence_refs") or []
        if _text(ref)
    })
    trace = [{
        "predicate": "canonical_graph_family_match",
        "expected": family,
        "matched": family if facts else "",
        "result": bool(facts and evidence_refs),
        "fact_refs": fact_refs,
        "evidence_refs": evidence_refs,
    }]
    return facts, evidence_refs, trace


def _policy_binding(loaded: Mapping[str, Any]) -> dict[str, Any]:
    document = deepcopy(loaded.get("document") or {})
    return {
        "source": _text(loaded.get("source")),
        "file_sha256": _text(loaded.get("sha256")).lower(),
        "document_sha256": _sha(document),
        "document": document,
    }


def _build_payload(
    view: CanonicalGraphView,
    *,
    session_id: str,
    policy_binding: Mapping[str, Any],
    profile_binding: Mapping[str, Any],
    generated_at: str,
) -> dict[str, Any]:
    policy = policy_binding.get("document") or {}
    findings = []
    actions = []
    for rule in policy.get("finding_rules") or []:
        facts, refs, trace = _rule_match(view, rule)
        if not refs:
            continue
        fact_refs = [_text(item.get("fact_id")) for item in facts]
        item = {
            "finding_id": "",
            "rule_id": _text(rule.get("rule_id")),
            "semantic_family": _text(rule.get("semantic_family")),
            "severity": _text(rule.get("severity")) or "info",
            "statement": _render_policy_text(
                rule.get("statement"), _entity_context(view, fact_refs)
            ),
            "fact_refs": fact_refs,
            "evidence_refs": refs,
            "matched_predicates": trace,
            "references": deepcopy(rule.get("references") or []),
            "provenance": deepcopy(rule.get("provenance") or {}),
        }
        item["finding_id"] = stable_id(
            "response_guidance_v4_finding",
            {key: value for key, value in item.items() if key != "finding_id"},
        )
        findings.append(item)
    for rule in policy.get("action_playbooks") or []:
        facts, refs, trace = _rule_match(view, rule)
        if not refs:
            continue
        fact_refs = [_text(item.get("fact_id")) for item in facts]
        context = _entity_context(view, fact_refs)
        for action in rule.get("actions") or []:
            item = {
                "action_id": _text(action.get("action_id")),
                "rule_id": _text(rule.get("rule_id")),
                "semantic_family": _text(rule.get("semantic_family")),
                "description": _render_policy_text(action.get("action"), context),
                "rationale": _render_policy_text(action.get("rationale"), context),
                "policy_order": action.get("priority"),
                "fact_refs": fact_refs,
                "evidence_refs": refs,
                "matched_predicates": trace,
                "requires_manual_approval": True,
                "safe_to_auto_execute": False,
                "execution_integration": "not_implemented",
                "references": deepcopy(action.get("references") or []),
                "provenance": {
                    "rule": deepcopy(rule.get("provenance") or {}),
                    "action": deepcopy(action.get("provenance") or {}),
                },
            }
            actions.append(item)
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    findings.sort(key=lambda item: (
        -severity_order.get(item["severity"], 0), item["rule_id"], item["finding_id"]
    ))
    actions.sort(key=lambda item: (
        int(item.get("policy_order") or 9999), item["action_id"], item["rule_id"]
    ))
    priority = _text((findings[0] if findings else {}).get("severity")) or "info"
    return {
        "schema_version": SCHEMA_VERSION,
        "guidance_id": "",
        "content_sha256": "",
        "generated_at": generated_at,
        "status": "available",
        "guidance_state": (
            "actions_available" if actions else "no_applicable_grounded_action"
        ),
        "authority": "deterministic_canonical_graph_policy",
        "session_id": session_id or "unknown",
        "canonical_graph": deepcopy(view.graph),
        "graph_binding": {
            "query_schema_version": GRAPH_QUERY_SCHEMA_VERSION,
            "graph_sha256": view.graph_sha256,
            "observed_evidence_sha256": view.observed_evidence_sha256,
            "typed_fact_set_sha256": view.typed_fact_set_sha256,
        },
        "findings": findings,
        "triage": {
            "review_priority": priority,
            "urgency": "prompt_review" if priority in {"high", "critical"} else "routine_review",
            "semantics": "categorical_canonical_graph_policy_not_score_or_forecast",
            "finding_ids": [item["finding_id"] for item in findings],
        },
        "advisory_actions": actions,
        "provenance": {
            "policy": deepcopy(dict(policy_binding)),
            "asset_profile": deepcopy(dict(profile_binding)),
            "selection_authority": "validated_canonical_graph_only",
        },
        "safety": deepcopy(_SAFETY),
        "compatibility": {
            "historical_response_guidance_v3": "read_only_not_recomputed",
            "separate_typed_fact_set_source": "excluded",
            "denormalized_session_source": "excluded",
        },
        "presentation_semantics": {
            "mode": "point_in_time_graph_bound_guidance",
            "replaces_stored_historical_guidance": False,
        },
    }


def build_response_guidance_v4(
    canonical_graph: Any,
    *,
    session_id: str,
    policy: Mapping[str, Any],
    policy_sha256: str,
    policy_source: str,
    asset_profile: Mapping[str, Any] | None = None,
    asset_profile_sha256: str = "",
    asset_profile_source: str = "",
    expected_graph_sha256: str = "",
    expected_observed_evidence_sha256: str = "",
    expected_typed_fact_set_sha256: str = "",
    generated_at: str = "",
) -> dict[str, Any]:
    if validate_response_guidance_policy(dict(policy)):
        raise ResponseGuidanceV4Error("response guidance policy is invalid")
    if (
        _text(policy_sha256).lower() != REVIEWED_POLICY_FILE_SHA256
        or _sha(policy) != REVIEWED_POLICY_DOCUMENT_SHA256
    ):
        raise ResponseGuidanceV4Error(
            "response guidance policy is outside the reviewed v4 registry"
        )
    profile = dict(asset_profile or {})
    if profile and validate_response_guidance_asset_profile(profile):
        raise ResponseGuidanceV4Error("response guidance asset profile is invalid")
    view = canonical_graph_view(
        canonical_graph,
        expected_graph_sha256=expected_graph_sha256,
        expected_observed_evidence_sha256=expected_observed_evidence_sha256,
        expected_typed_fact_set_sha256=expected_typed_fact_set_sha256,
    )
    payload = _build_payload(
        view,
        session_id=_text(session_id) or "unknown",
        policy_binding={
            "source": _text(policy_source),
            "file_sha256": _text(policy_sha256).lower(),
            "document_sha256": _sha(policy),
            "document": deepcopy(dict(policy)),
        },
        profile_binding={
            "source": _text(asset_profile_source),
            "file_sha256": _text(asset_profile_sha256).lower(),
            "document_sha256": _sha(profile),
            "document": profile,
        },
        generated_at=_text(generated_at) or utc_now(),
    )
    payload["content_sha256"] = _sha(_content_basis(payload))
    payload["guidance_id"] = stable_id(
        "response_guidance_v4", payload["content_sha256"]
    )
    validate_response_guidance_v4(payload, raise_on_error=True)
    return payload


def build_response_guidance_v4_from_paths(
    canonical_graph: Any,
    *,
    session_id: str,
    policy_path: str = "",
    asset_profile_path: str = "",
    expected_graph_sha256: str = "",
    expected_observed_evidence_sha256: str = "",
    expected_typed_fact_set_sha256: str = "",
    generated_at: str = "",
) -> dict[str, Any]:
    policy = load_response_guidance_policy(policy_path)
    profile = load_response_guidance_asset_profile(asset_profile_path)
    if policy.get("status") != "valid" or profile.get("status") not in {
        "valid", "not_configured"
    }:
        raise ResponseGuidanceV4Error("response guidance policy inputs are unavailable")
    return build_response_guidance_v4(
        canonical_graph,
        session_id=session_id,
        policy=policy["document"],
        policy_sha256=policy["sha256"],
        policy_source=policy["source"],
        asset_profile=profile["document"],
        asset_profile_sha256=profile["sha256"],
        asset_profile_source=profile["source"],
        expected_graph_sha256=expected_graph_sha256,
        expected_observed_evidence_sha256=expected_observed_evidence_sha256,
        expected_typed_fact_set_sha256=expected_typed_fact_set_sha256,
        generated_at=generated_at,
    )


def validate_response_guidance_v4(
    value: Any,
    *,
    parent_graph: Any = None,
    raise_on_error: bool = False,
) -> list[str]:
    errors = []
    if not isinstance(value, Mapping) or set(value) != _TOP_KEYS:
        errors.append("response guidance v4 has an invalid closed shape")
        value = value if isinstance(value, Mapping) else {}
    if value.get("schema_version") != SCHEMA_VERSION:
        errors.append("response guidance v4 schema is invalid")
    graph = value.get("canonical_graph") or {}
    binding = value.get("graph_binding") or {}
    try:
        view = canonical_graph_view(
            graph,
            expected_graph_sha256=_text(binding.get("graph_sha256")),
            expected_observed_evidence_sha256=_text(
                binding.get("observed_evidence_sha256")
            ),
            expected_typed_fact_set_sha256=_text(
                binding.get("typed_fact_set_sha256")
            ),
        )
        if parent_graph is not None and dict(parent_graph) != view.graph:
            errors.append("response guidance parent graph mismatch")
    except (CanonicalGraphQueryError, TypeError, ValueError) as exc:
        errors.append(f"response guidance graph is invalid: {exc}")
        view = None
    provenance = value.get("provenance") or {}
    policy_binding = provenance.get("policy") or {}
    profile_binding = provenance.get("asset_profile") or {}
    policy = policy_binding.get("document") or {}
    profile = profile_binding.get("document") or {}
    if _text(policy_binding.get("document_sha256")) != _sha(policy):
        errors.append("response guidance policy content hash mismatch")
    if (
        _text(policy_binding.get("file_sha256")).lower()
        != REVIEWED_POLICY_FILE_SHA256
        or _sha(policy) != REVIEWED_POLICY_DOCUMENT_SHA256
    ):
        errors.append("response guidance policy registry binding mismatch")
    if validate_response_guidance_policy(policy):
        errors.append("response guidance embedded policy is invalid")
    if _text(profile_binding.get("document_sha256")) != _sha(profile):
        errors.append("response guidance profile content hash mismatch")
    if profile and validate_response_guidance_asset_profile(profile):
        errors.append("response guidance embedded profile is invalid")
    if value.get("safety") != _SAFETY:
        errors.append("response guidance safety boundary is invalid")
    recorded_content = _text(value.get("content_sha256")).lower()
    if recorded_content != _sha(_content_basis(value)):
        errors.append("response guidance content hash mismatch")
    if value.get("guidance_id") != stable_id(
        "response_guidance_v4", recorded_content
    ):
        errors.append("response guidance ID mismatch")
    if view is not None and not errors:
        expected = _build_payload(
            view,
            session_id=_text(value.get("session_id")) or "unknown",
            policy_binding=policy_binding,
            profile_binding=profile_binding,
            generated_at=_text(value.get("generated_at")),
        )
        expected["content_sha256"] = _sha(_content_basis(expected))
        expected["guidance_id"] = stable_id(
            "response_guidance_v4", expected["content_sha256"]
        )
        if dict(value) != expected:
            errors.append("response guidance does not match graph and policy content")
    if raise_on_error and errors:
        raise ResponseGuidanceV4Error("; ".join(errors))
    return errors


__all__ = [
    "ResponseGuidanceV4Error", "SCHEMA_VERSION",
    "build_response_guidance_v4", "build_response_guidance_v4_from_paths",
    "validate_response_guidance_v4",
]
