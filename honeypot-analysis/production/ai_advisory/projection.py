"""Positive allowlist projection from a validated persisted v4 assessment."""

from __future__ import annotations

from copy import deepcopy
import re
from typing import Any, Dict, Iterable, Mapping

from production.ai_advisory.contracts import (
    AIAdvisoryContractError,
    sha256_json,
)
from production.reporting.session_assessment_v4 import validate_session_assessment_v4
from production.reporting.response_guidance_v3 import validate_response_guidance_v3


PROJECTION_KEYS = {
    "schema_version",
    "assessment_id",
    "evidence_sha256",
    "projection_sha256",
    "provenance",
    "authority",
    "evidence_index",
    "findings",
    "relationships",
    "hypotheses",
    "guidance",
    "abstention",
    "allowed_output",
}
PROHIBITED_PROJECTION_KEYS = {
    "command",
    "commands",
    "credential",
    "credentials",
    "input",
    "password",
    "payload",
    "raw_event",
    "raw_events",
    "secret",
    "source_ip",
    "src_ip",
    "token",
    "url",
    "username",
    "value",
}
PROVENANCE_KEYS = {
    "evaluator_git_revision",
    "behavior_policy_sha256",
    "classification_policy_sha256",
    "mitre_provenance_sha256",
    "model_artifacts_provenance_sha256",
    "typed_fact_set_sha256",
    "typed_vocabulary_sha256",
    "guidance_policy_sha256",
    "guidance_profile_sha256",
    "guidance_profile_status",
    "ai_policy_sha256",
}
AUTHORITY_KEYS = {
    "ai_canonical_authority",
    "ai_finding_authority",
    "ai_hypothesis_authority",
    "ai_guidance_authority",
    "ai_alert_authority",
    "ai_automatic_execution",
}
EVIDENCE_ITEM_KEYS = {"evidence_id", "evidence_kind", "ordinal", "status"}
FINDING_KEYS = {
    "finding_id",
    "origin",
    "finding_type",
    "policy_rule_id",
    "semantic_family",
    "severity",
    "status",
    "evidence_refs",
    "relationship_refs",
    "limitation_codes",
}
RELATIONSHIP_KEYS = {
    "relationship_id",
    "relationship_type",
    "status",
    "source_evidence_ref",
    "target_evidence_ref",
    "entity_ref",
    "chain_ref",
    "limitation_codes",
}
HYPOTHESIS_KEYS = {
    "hypothesis_id",
    "hypothesis_set_id",
    "status",
    "evidence_refs",
    "relationship_refs",
    "limitation_codes",
    "falsifier_codes",
}
GUIDANCE_KEYS = {"guidance_id", "status", "guidance_state", "actions"}
ACTION_KEYS = {
    "action_id",
    "rule_id",
    "policy_order",
    "finding_ids",
    "evidence_refs",
    "requires_manual_approval",
    "safe_to_auto_execute",
    "execution_integration",
}
ABSTENTION_KEYS = {"abstained", "reason_code"}
ALLOWED_OUTPUT_KEYS = {
    "template_ids",
    "reason_codes",
    "limitation_codes",
    "candidate_types",
    "missing_evidence_codes",
    "falsifier_codes",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
SAFE_ATOM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _strings(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple, set)):
        return []
    return sorted({_clean(item) for item in value if _clean(item)})


def _limitation_codes(values: Any) -> list[str]:
    text = " ".join(_clean(item).lower() for item in values or [])
    codes = []
    mappings = (
        ("intent", "attacker_intent_not_established"),
        ("real-host", "real_host_effect_not_established"),
        ("real host", "real_host_effect_not_established"),
        ("execution", "execution_not_established"),
        ("transfer", "transfer_not_confirmed"),
        ("acquisition", "credential_acquisition_not_established"),
        ("outcome", "outcome_unknown"),
        ("unresolved", "unresolved_identity"),
        ("causal", "relationship_not_causal_proof"),
    )
    for needle, code in mappings:
        if needle in text and code not in codes:
            codes.append(code)
    if text and not codes:
        codes.append("canonical_scope_limitation")
    return codes


def _walk_keys(value: Any) -> Iterable[str]:
    if isinstance(value, Mapping):
        for key, item in value.items():
            yield str(key).lower()
            yield from _walk_keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_keys(item)


def _exact(value: Any, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise AIAdvisoryContractError(
            f"{label} violates additionalProperties=false",
            code="projection_contract_invalid",
        )
    return value


def _atoms(value: Any, label: str, *, allow_empty: bool = True) -> list[str]:
    if not isinstance(value, list) or len(value) > 128:
        raise AIAdvisoryContractError(f"{label} must be a bounded array")
    if len(value) != len(set(value)):
        raise AIAdvisoryContractError(f"{label} contains duplicates")
    for item in value:
        if not isinstance(item, str) or (
            not item and not allow_empty
        ) or (item and not SAFE_ATOM_RE.fullmatch(item)):
            raise AIAdvisoryContractError(f"{label} contains an unsafe value")
    return list(value)


def _atom(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not value and not allow_empty):
        raise AIAdvisoryContractError(f"{label} must be a string")
    if value and not SAFE_ATOM_RE.fullmatch(value):
        raise AIAdvisoryContractError(f"{label} is not an allowlisted atom")
    return value


def validate_ai_advisory_projection(
    projection: Any,
    *,
    policy: Mapping[str, Any],
    policy_sha256: str,
) -> Dict[str, Any]:
    """Validate the complete request contract before it can leave the host."""

    root = _exact(projection, PROJECTION_KEYS, "projection")
    if root.get("schema_version") != "ai_advisory_projection.v1":
        raise AIAdvisoryContractError("projection schema is invalid")
    _atom(root.get("assessment_id"), "assessment_id")
    if not SHA256_RE.fullmatch(str(root.get("evidence_sha256") or "")):
        raise AIAdvisoryContractError("evidence_sha256 is invalid")
    recorded_hash = str(root.get("projection_sha256") or "")
    base = {key: deepcopy(value) for key, value in root.items() if key != "projection_sha256"}
    if not SHA256_RE.fullmatch(recorded_hash) or recorded_hash != sha256_json(base):
        raise AIAdvisoryContractError("projection_sha256 mismatch", code="hash_mismatch")

    provenance = _exact(root.get("provenance"), PROVENANCE_KEYS, "provenance")
    if not REVISION_RE.fullmatch(str(provenance.get("evaluator_git_revision") or "")):
        raise AIAdvisoryContractError("evaluator Git revision is invalid")
    for key in PROVENANCE_KEYS - {
        "evaluator_git_revision",
        "guidance_profile_sha256",
        "guidance_profile_status",
    }:
        if not SHA256_RE.fullmatch(str(provenance.get(key) or "")):
            raise AIAdvisoryContractError(f"{key} is invalid")
    profile_status = provenance.get("guidance_profile_status")
    if profile_status not in {"configured", "not_configured"}:
        raise AIAdvisoryContractError("guidance_profile_status is invalid")
    profile_hash = str(provenance.get("guidance_profile_sha256") or "")
    if profile_status == "configured":
        if not SHA256_RE.fullmatch(profile_hash):
            raise AIAdvisoryContractError(
                "configured guidance profile requires a SHA-256"
            )
    elif profile_hash:
        raise AIAdvisoryContractError(
            "unconfigured guidance profile must not carry a SHA-256"
        )
    if provenance.get("ai_policy_sha256") != policy_sha256:
        raise AIAdvisoryContractError("AI policy hash mismatch", code="hash_mismatch")

    authority = _exact(root.get("authority"), AUTHORITY_KEYS, "authority")
    if any(authority.get(key) is not False for key in AUTHORITY_KEYS):
        raise AIAdvisoryContractError("projection grants AI authority")

    evidence_items = root.get("evidence_index")
    if not isinstance(evidence_items, list) or len(evidence_items) > 100_000:
        raise AIAdvisoryContractError("evidence_index must be bounded")
    evidence_ids: set[str] = set()
    for index, raw in enumerate(evidence_items):
        item = _exact(raw, EVIDENCE_ITEM_KEYS, f"evidence_index[{index}]")
        evidence_id = _atom(item.get("evidence_id"), "evidence_id")
        _atom(item.get("evidence_kind"), "evidence_kind")
        _atom(item.get("status"), "evidence status")
        if type(item.get("ordinal")) is not int or item["ordinal"] != index:
            raise AIAdvisoryContractError("evidence ordinals are invalid")
        if evidence_id in evidence_ids:
            raise AIAdvisoryContractError("evidence IDs are duplicated")
        evidence_ids.add(evidence_id)

    relationship_items = root.get("relationships")
    if not isinstance(relationship_items, list) or len(relationship_items) > policy["limits"]["max_relationships"]:
        raise AIAdvisoryContractError("relationships must be bounded")
    relationship_ids: set[str] = set()
    for index, raw in enumerate(relationship_items):
        item = _exact(raw, RELATIONSHIP_KEYS, f"relationships[{index}]")
        relationship_id = _atom(item.get("relationship_id"), "relationship_id")
        for key in ("relationship_type", "status"):
            _atom(item.get(key), key)
        for key in ("source_evidence_ref", "target_evidence_ref"):
            ref = _atom(item.get(key), key, allow_empty=True)
            if ref and ref not in evidence_ids:
                raise AIAdvisoryContractError("relationship evidence reference is unresolved")
        _atom(item.get("entity_ref"), "entity_ref", allow_empty=True)
        _atom(item.get("chain_ref"), "chain_ref", allow_empty=True)
        _atoms(item.get("limitation_codes"), "relationship limitation_codes")
        if relationship_id in relationship_ids:
            raise AIAdvisoryContractError("relationship IDs are duplicated")
        relationship_ids.add(relationship_id)

    finding_items = root.get("findings")
    if not isinstance(finding_items, list) or len(finding_items) > policy["limits"]["max_findings"]:
        raise AIAdvisoryContractError("findings must be bounded")
    finding_ids: set[str] = set()
    for index, raw in enumerate(finding_items):
        item = _exact(raw, FINDING_KEYS, f"findings[{index}]")
        finding_id = _atom(item.get("finding_id"), "finding_id")
        for key in ("origin", "finding_type", "policy_rule_id", "severity", "status"):
            _atom(item.get(key), key)
        _atom(item.get("semantic_family"), "semantic_family", allow_empty=True)
        refs = set(_atoms(item.get("evidence_refs"), "finding evidence_refs"))
        rel_refs = set(_atoms(item.get("relationship_refs"), "finding relationship_refs"))
        if refs - evidence_ids or rel_refs - relationship_ids:
            raise AIAdvisoryContractError("finding reference is unresolved")
        limitations = _atoms(item.get("limitation_codes"), "finding limitation_codes")
        if set(limitations) - set(policy["limitation_codes"]):
            raise AIAdvisoryContractError("finding limitation code is unknown")
        if finding_id in finding_ids:
            raise AIAdvisoryContractError("finding IDs are duplicated")
        finding_ids.add(finding_id)

    hypothesis_items = root.get("hypotheses")
    if not isinstance(hypothesis_items, list) or len(hypothesis_items) > 128:
        raise AIAdvisoryContractError("hypotheses must be bounded")
    for index, raw in enumerate(hypothesis_items):
        item = _exact(raw, HYPOTHESIS_KEYS, f"hypotheses[{index}]")
        for key in ("hypothesis_id", "hypothesis_set_id", "status"):
            _atom(item.get(key), key)
        if set(_atoms(item.get("evidence_refs"), "hypothesis evidence_refs")) - evidence_ids:
            raise AIAdvisoryContractError("hypothesis evidence reference is unresolved")
        if set(_atoms(item.get("relationship_refs"), "hypothesis relationship_refs")) - relationship_ids:
            raise AIAdvisoryContractError("hypothesis relationship reference is unresolved")
        limitations = _atoms(item.get("limitation_codes"), "hypothesis limitation_codes")
        falsifiers = _atoms(item.get("falsifier_codes"), "hypothesis falsifier_codes")
        if set(limitations) - set(policy["limitation_codes"]) or set(falsifiers) - set(policy["falsifier_codes"]):
            raise AIAdvisoryContractError("hypothesis code is unknown")

    guidance = _exact(root.get("guidance"), GUIDANCE_KEYS, "guidance")
    for key in ("guidance_id", "status", "guidance_state"):
        _atom(guidance.get(key), key)
    actions = guidance.get("actions")
    if not isinstance(actions, list) or len(actions) > policy["limits"]["max_actions"]:
        raise AIAdvisoryContractError("guidance actions must be bounded")
    action_ids: set[str] = set()
    for index, raw in enumerate(actions):
        item = _exact(raw, ACTION_KEYS, f"actions[{index}]")
        action_id = _atom(item.get("action_id"), "action_id")
        _atom(item.get("rule_id"), "rule_id")
        if type(item.get("policy_order")) is not int or item["policy_order"] < 0:
            raise AIAdvisoryContractError("action policy_order is invalid")
        if set(_atoms(item.get("finding_ids"), "action finding_ids")) - finding_ids:
            raise AIAdvisoryContractError("action finding reference is unresolved")
        if set(_atoms(item.get("evidence_refs"), "action evidence_refs")) - evidence_ids:
            raise AIAdvisoryContractError("action evidence reference is unresolved")
        if item.get("requires_manual_approval") is not True or item.get("safe_to_auto_execute") is not False or item.get("execution_integration") != "not_implemented":
            raise AIAdvisoryContractError("action safety boundary is invalid")
        if action_id in action_ids:
            raise AIAdvisoryContractError("action IDs are duplicated")
        action_ids.add(action_id)

    abstention = _exact(root.get("abstention"), ABSTENTION_KEYS, "abstention")
    if type(abstention.get("abstained")) is not bool:
        raise AIAdvisoryContractError("abstained must be boolean")
    _atom(abstention.get("reason_code"), "reason_code", allow_empty=True)
    allowed_output = _exact(root.get("allowed_output"), ALLOWED_OUTPUT_KEYS, "allowed_output")
    expected_output = _available_output_codes(
        policy=policy,
        findings=list(finding_items),
        relationships=list(relationship_items),
        hypotheses=list(hypothesis_items),
        actions=list(actions),
        abstained=bool(abstention["abstained"]),
    )
    if dict(allowed_output) != expected_output:
        raise AIAdvisoryContractError(
            "allowed_output does not match canonical context"
        )

    prohibited = set(_walk_keys(root)) & PROHIBITED_PROJECTION_KEYS
    if prohibited:
        raise AIAdvisoryContractError(
            f"allowlisted projection contains prohibited fields: {sorted(prohibited)}",
            code="projection_privacy_violation",
        )
    return deepcopy(dict(root))


def _evidence_index(evidence: Mapping[str, Any]) -> list[Dict[str, Any]]:
    output = []
    ordinal = 0
    for collection, kind in (
        ("observations", "command_observation"),
        ("transfer_observations", "direct_transfer_observation"),
        ("direct_cowrie_events", "cowrie_event_observation"),
        ("trusted_attck_candidates", "trusted_attck_candidate"),
    ):
        for item in evidence.get(collection) or []:
            if not isinstance(item, Mapping):
                continue
            evidence_id = _clean(item.get("evidence_id"))
            if not evidence_id:
                continue
            output.append(
                {
                    "evidence_id": evidence_id,
                    "evidence_kind": kind,
                    "ordinal": ordinal,
                    "status": _clean(item.get("status") or item.get("evidence_status") or "observed"),
                }
            )
            ordinal += 1
    return output


def _relationships(evidence: Mapping[str, Any], evidence_ids: set[str]) -> list[Dict[str, Any]]:
    entity_ids = {
        _clean(item.get("entity_id"))
        for item in evidence.get("entities") or []
        if isinstance(item, Mapping) and _clean(item.get("entity_id"))
    }
    chain_ids = {
        _clean(item.get("chain_id"))
        for item in evidence.get("connected_behavior_chains") or []
        if isinstance(item, Mapping) and _clean(item.get("chain_id"))
    }
    output = []
    for item in evidence.get("relationships") or []:
        if not isinstance(item, Mapping):
            continue
        relationship_id = _clean(item.get("relationship_id") or item.get("chain_id"))
        if not relationship_id:
            continue
        source_ref = _clean(item.get("source_evidence_ref") or item.get("source_observation_ref"))
        target_ref = _clean(item.get("target_evidence_ref") or item.get("target_observation_ref"))
        entity_ref = _clean(item.get("entity_ref"))
        chain_ref = _clean(item.get("chain_ref") or item.get("chain_id"))
        for ref in (source_ref, target_ref):
            if ref and ref not in evidence_ids:
                raise AIAdvisoryContractError("relationship has unresolved evidence reference")
        if entity_ref and entity_ref not in entity_ids:
            raise AIAdvisoryContractError("relationship has unresolved entity reference")
        if chain_ref and chain_ref not in chain_ids and chain_ref != relationship_id:
            raise AIAdvisoryContractError("relationship has unresolved chain reference")
        output.append(
            {
                "relationship_id": relationship_id,
                "relationship_type": _clean(item.get("relationship_type") or item.get("type") or "observed_relationship"),
                "status": _clean(item.get("status") or item.get("resolution_status") or "observed"),
                "source_evidence_ref": source_ref,
                "target_evidence_ref": target_ref,
                "entity_ref": entity_ref,
                "chain_ref": chain_ref,
                "limitation_codes": _limitation_codes(item.get("limitations") or []),
            }
        )
    return sorted(output, key=lambda item: item["relationship_id"])


def _available_output_codes(
    *,
    policy: Mapping[str, Any],
    findings: list[Mapping[str, Any]],
    relationships: list[Mapping[str, Any]],
    hypotheses: list[Mapping[str, Any]],
    actions: list[Mapping[str, Any]],
    abstained: bool,
) -> Dict[str, list[str]]:
    policy_limitations = set(policy["limitation_codes"])
    limitations = sorted(
        {
            str(code)
            for item in [*findings, *relationships, *hypotheses]
            for code in item.get("limitation_codes") or []
            if str(code) in policy_limitations
        }
    )
    reason_codes = []
    if sum(str(item.get("status") or "") == "supported" for item in findings) >= 2:
        reason_codes.append("multiple_supported_findings")
    if relationships:
        reason_codes.append("supported_relationship_present")
    if actions:
        reason_codes.append("existing_manual_actions_available")
    if limitations:
        reason_codes.append("canonical_limitations_present")
    reason_codes.append("insufficient_allowlisted_context")
    if not findings and not relationships and not actions:
        reason_codes.append("no_eligible_selection")
    if abstained:
        reason_codes.append("policy_requires_abstention")
    policy_reasons = set(policy["reason_codes"])
    return {
        "template_ids": list(policy["template_ids"]),
        "reason_codes": [code for code in reason_codes if code in policy_reasons],
        "limitation_codes": limitations,
        "candidate_types": list(policy["candidate_types"]),
        "missing_evidence_codes": list(policy["missing_evidence_codes"]),
        "falsifier_codes": list(policy["falsifier_codes"]),
    }


def build_ai_advisory_projection(
    report: Mapping[str, Any],
    *,
    policy: Mapping[str, Any],
    policy_sha256: str,
) -> Dict[str, Any]:
    """Build the only data object allowed to cross the external AI boundary."""

    report_copy = deepcopy(dict(report))
    errors = validate_session_assessment_v4(report_copy)
    if errors:
        raise AIAdvisoryContractError("persisted v4 report failed validation")
    guidance = report_copy.get("response_guidance_v3") or {}
    if validate_response_guidance_v3(guidance):
        raise AIAdvisoryContractError("persisted v3 guidance failed validation")
    evidence = report_copy["canonical_evidence"]
    evidence_index = _evidence_index(evidence)
    evidence_ids = {item["evidence_id"] for item in evidence_index}
    relationships = _relationships(evidence, evidence_ids)
    relationship_ids = {item["relationship_id"] for item in relationships}

    findings = []
    for item in report_copy.get("behavioral_findings") or []:
        if not isinstance(item, Mapping):
            continue
        refs = _strings(item.get("evidence_refs"))
        rel_refs = _strings(item.get("relationship_refs"))
        if set(refs) - evidence_ids or set(rel_refs) - relationship_ids:
            raise AIAdvisoryContractError("finding references do not resolve")
        findings.append(
            {
                "finding_id": _clean(item.get("finding_id")),
                "origin": "session_assessment.v4",
                "finding_type": _clean(item.get("finding_type")),
                "policy_rule_id": _clean(item.get("behavior_policy_rule_id")),
                "semantic_family": _clean(item.get("semantic_family")),
                "severity": "not_applicable",
                "status": _clean(item.get("status")),
                "evidence_refs": refs,
                "relationship_refs": rel_refs,
                "limitation_codes": _limitation_codes(item.get("limitations") or []),
            }
        )

    for item in guidance.get("findings") or []:
        if not isinstance(item, Mapping):
            continue
        refs = _strings(
            item.get("supporting_evidence_refs") or item.get("evidence_refs")
        )
        rel_refs = _strings(item.get("relationship_refs"))
        if set(refs) - evidence_ids or set(rel_refs) - relationship_ids:
            raise AIAdvisoryContractError("guidance finding references do not resolve")
        findings.append(
            {
                "finding_id": _clean(item.get("finding_id")),
                "origin": "response_guidance.v3",
                "finding_type": _clean(item.get("rule_id") or "guidance_finding"),
                "policy_rule_id": _clean(item.get("rule_id")),
                "semantic_family": _clean(item.get("semantic_family")),
                "severity": _clean(item.get("severity") or "info"),
                "status": "supported",
                "evidence_refs": refs,
                "relationship_refs": rel_refs,
                "limitation_codes": _limitation_codes(item.get("limitations") or []),
            }
        )

    hypotheses = []
    for hypothesis_set in report_copy.get("hypothesis_sets") or []:
        if not isinstance(hypothesis_set, Mapping):
            continue
        set_relationship_refs = _strings(hypothesis_set.get("relationship_refs"))
        if set(set_relationship_refs) - relationship_ids:
            raise AIAdvisoryContractError("hypothesis relationship references do not resolve")
        for item in hypothesis_set.get("hypotheses") or []:
            if not isinstance(item, Mapping):
                continue
            refs = _strings(item.get("supporting_evidence_refs"))
            if set(refs) - evidence_ids:
                raise AIAdvisoryContractError("hypothesis evidence references do not resolve")
            hypotheses.append(
                {
                    "hypothesis_id": _clean(item.get("hypothesis_id")),
                    "hypothesis_set_id": _clean(hypothesis_set.get("hypothesis_set_id")),
                    "status": _clean(item.get("status")),
                    "evidence_refs": refs,
                    "relationship_refs": set_relationship_refs,
                    "limitation_codes": ["canonical_scope_limitation"],
                    "falsifier_codes": (
                        ["alternative_explanation_supported"]
                        if item.get("falsification_conditions")
                        else []
                    ),
                }
            )

    guidance_findings = {
        _clean(item.get("finding_id"))
        for item in guidance.get("findings") or []
        if isinstance(item, Mapping)
    }
    actions = []
    for item in guidance.get("advisory_actions") or []:
        if not isinstance(item, Mapping):
            continue
        if item.get("requires_manual_approval") is not True or item.get("safe_to_auto_execute") is not False:
            raise AIAdvisoryContractError("canonical action safety boundary is invalid")
        finding_refs = _strings(item.get("finding_ids"))
        evidence_refs = _strings(item.get("evidence_refs"))
        if set(finding_refs) - guidance_findings:
            raise AIAdvisoryContractError("guidance action finding references do not resolve")
        if set(evidence_refs) - evidence_ids:
            raise AIAdvisoryContractError("guidance action evidence references do not resolve")
        actions.append(
            {
                "action_id": _clean(item.get("action_id")),
                "rule_id": _clean(item.get("rule_id")),
                "policy_order": int(item.get("policy_order") or 0),
                "finding_ids": finding_refs,
                "evidence_refs": evidence_refs,
                "requires_manual_approval": True,
                "safe_to_auto_execute": False,
                "execution_integration": "not_implemented",
            }
        )

    provenance = report_copy.get("provenance") or {}
    guidance_provenance = guidance.get("provenance") or {}
    profile_metadata = guidance_provenance.get("asset_profile") or {}
    profile_source_status = _clean(profile_metadata.get("status"))
    if profile_source_status == "verified":
        guidance_profile_status = "configured"
    elif profile_source_status in {"", "not_configured"}:
        guidance_profile_status = "not_configured"
    else:
        # Preserve a configured-but-invalid state as configured so the strict
        # hash validator fails closed instead of silently treating it as absent.
        guidance_profile_status = "configured"
    typed = provenance.get("typed_semantics") or {}
    report_abstained = bool((report_copy.get("abstention") or {}).get("abstained"))
    base = {
        "schema_version": "ai_advisory_projection.v1",
        "assessment_id": _clean(report_copy.get("assessment_id")),
        "evidence_sha256": _clean(evidence.get("evidence_sha256")),
        "provenance": {
            "evaluator_git_revision": _clean(provenance.get("evaluator_git_revision")),
            "behavior_policy_sha256": _clean((provenance.get("behavior_policy") or {}).get("sha256")),
            "classification_policy_sha256": _clean((provenance.get("classification_policy") or {}).get("sha256")),
            "mitre_provenance_sha256": sha256_json(provenance.get("mitre_attack") or {}),
            "model_artifacts_provenance_sha256": sha256_json(provenance.get("model_artifacts") or []),
            "typed_fact_set_sha256": _clean(typed.get("fact_set_sha256")),
            "typed_vocabulary_sha256": _clean((typed.get("semantic_vocabulary") or {}).get("sha256")),
            "guidance_policy_sha256": _clean((guidance_provenance.get("policy") or {}).get("sha256")),
            "guidance_profile_sha256": _clean(
                profile_metadata.get("sha256")
            ),
            "guidance_profile_status": guidance_profile_status,
            "ai_policy_sha256": policy_sha256,
        },
        "authority": {
            "ai_canonical_authority": False,
            "ai_finding_authority": False,
            "ai_hypothesis_authority": False,
            "ai_guidance_authority": False,
            "ai_alert_authority": False,
            "ai_automatic_execution": False,
        },
        "evidence_index": evidence_index,
        "findings": sorted(findings, key=lambda item: item["finding_id"]),
        "relationships": relationships,
        "hypotheses": sorted(hypotheses, key=lambda item: item["hypothesis_id"]),
        "guidance": {
            "guidance_id": _clean(guidance.get("guidance_id")),
            "status": _clean(guidance.get("status")),
            "guidance_state": _clean(guidance.get("guidance_state")),
            "actions": sorted(actions, key=lambda item: (item["policy_order"], item["action_id"])),
        },
        "abstention": {
            "abstained": report_abstained,
            "reason_code": (
                "policy_requires_abstention"
                if (report_copy.get("abstention") or {}).get("abstained")
                else ""
            ),
        },
        "allowed_output": _available_output_codes(
            policy=policy,
            findings=findings,
            relationships=relationships,
            hypotheses=hypotheses,
            actions=actions,
            abstained=report_abstained,
        ),
    }
    prohibited = set(_walk_keys(base)) & PROHIBITED_PROJECTION_KEYS
    if prohibited:
        raise AIAdvisoryContractError(
            f"allowlisted projection contains prohibited fields: {sorted(prohibited)}",
            code="projection_privacy_violation",
        )
    projection = {**base, "projection_sha256": sha256_json(base)}
    return validate_ai_advisory_projection(
        projection,
        policy=policy,
        policy_sha256=policy_sha256,
    )
