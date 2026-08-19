"""Positive allowlist projection from a validated persisted assessment."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Dict, Iterable, Mapping

from production.ai_advisory.contracts import (
    AIAdvisoryContractError,
    sha256_json,
)
from production.ai_advisory.security import AssessmentAliasScope, ProviderAliasScope
from production.utils.serialization import stable_id, stable_json
from production.reporting.session_assessment_v5 import validate_session_assessment
from production.reporting.response_guidance_v3 import validate_response_guidance_v3
from production.reporting.response_guidance_v4 import validate_response_guidance_v4
from production.reporting.session_assessment_v6 import (
    validate_session_assessment_v6,
)
from production.reporting.canonical_graph_queries import (
    CanonicalGraphQueryError,
    ChronologicalGraphView,
    chronological_graph_view,
)
from production.policies.typed_semantic_vocabulary import (
    load_typed_semantic_vocabulary,
)
from production.reporting.typed_semantic_family_selection import (
    ACTIVATED_FAMILIES as CANONICAL_ACTIVATED_SEMANTIC_FAMILIES,
)


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
EVIDENCE_KINDS = {
    "command_observation",
    "direct_transfer_observation",
    "cowrie_event_observation",
    "trusted_attck_candidate",
}
EVIDENCE_STATUSES = {
    "observed",
    "supported",
    "partially_supported",
    "trusted",
}
FINDING_ORIGINS = {"session_assessment.v4", "session_assessment.v5", "response_guidance.v3"}
FINDING_STATUSES = {"supported", "partially_supported", "insufficient_evidence"}
FINDING_TYPES = {
    "connected_artifact_activity",
    "connected_transfer_execution",
    "connected_transfer_permission_change",
    "connected_transfer_permission_execution",
    "observed_cowrie_command_transfer_attempt",
    "observed_cowrie_execution_attempt_command",
    "observed_cowrie_file_transfer",
    "observed_cowrie_filesystem_change_command",
    "observed_cowrie_inspection_command",
    "observed_cowrie_transfer_event",
    "observed_credential_path_read_command",
    "observed_transfer_without_linked_execution",
    "piped_remote_content_execution_attempt",
    "possible_continued_access_preparation",
    "possible_credential_access_preparation",
    "possible_follow_on_execution",
    "possible_tool_transfer_or_staging",
    "possible_trace_removal",
    "observed-command-corroboration",
    "observed-cowrie-command-transfer-attempt",
    "observed-cowrie-execution-attempt-command",
    "observed-cowrie-filesystem-change-command",
    "observed-cowrie-inspection-command",
    "observed-cowrie-transfer-event",
    "observed-credential-access-candidate",
    "observed-credential-access-corroboration",
    "observed-execution-corroboration",
    "observed-interactive-command",
    "observed-transfer-event-corroboration",
}
POLICY_RULE_IDS = {
    "observed-command-corroboration",
    "observed-cowrie-command-transfer-attempt",
    "observed-cowrie-execution-attempt-command",
    "observed-cowrie-filesystem-change-command",
    "observed-cowrie-inspection-command",
    "observed-cowrie-transfer-event",
    "observed-credential-access-candidate",
    "observed-credential-access-corroboration",
    "observed-direct-cowrie-transfer-event",
    "observed-execution-corroboration",
    "observed-interactive-command",
    "observed-resolved-credential-path-read",
    "observed-supported-cowrie-command-transfer-attempt",
    "observed-supported-cowrie-execution-attempt",
    "observed-supported-cowrie-filesystem-change-command",
    "observed-supported-cowrie-inspection-command",
    "observed-transfer-event-corroboration",
    "observed-transfer-without-execution",
    "remote-content-piped-to-shell",
    "transfer-execution",
    "transfer-permission-change",
    "transfer-permission-execution",
    "transfer-permission-execution-deletion",
}
SEVERITIES = {"not_applicable", "info", "low", "medium", "high", "critical"}
# The deterministic typed-semantic contract is the source of truth.  Keep the
# empty value for guidance findings that intentionally have no semantic family,
# while preserving strict rejection for every non-canonical value.
SEMANTIC_FAMILIES = {"", *CANONICAL_ACTIVATED_SEMANTIC_FAMILIES}
RELATIONSHIP_TYPES = {
    "observed_relationship",
    "account_modified",
    "conditional_failure_successor",
    "conditional_successor",
    "explicit_sequence",
    "piped_to",
    "same_path_transition",
    "transfer_observation_confirmation",
}
RELATIONSHIP_STATUSES = {
    "observed",
    "supported",
    "partially_supported",
    "condition_satisfied",
    "condition_not_satisfied",
    "condition_unknown",
}
HYPOTHESIS_STATUSES = {"active"}
GUIDANCE_STATUSES = {"available", "unavailable", "validation_rejected"}
GUIDANCE_STATES = {
    "actions_available",
    "no_applicable_grounded_action",
    "policy_or_profile_unavailable",
    "validation_rejected",
}


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
        if _atom(item.get("evidence_kind"), "evidence_kind") not in EVIDENCE_KINDS:
            raise AIAdvisoryContractError("evidence kind is not allowlisted")
        if _atom(item.get("status"), "evidence status") not in EVIDENCE_STATUSES:
            raise AIAdvisoryContractError("evidence status is not allowlisted")
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
        if _atom(item.get("relationship_type"), "relationship_type") not in RELATIONSHIP_TYPES:
            raise AIAdvisoryContractError("relationship type is not allowlisted")
        if _atom(item.get("status"), "status") not in RELATIONSHIP_STATUSES:
            raise AIAdvisoryContractError("relationship status is not allowlisted")
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
        if _atom(item.get("origin"), "origin") not in FINDING_ORIGINS:
            raise AIAdvisoryContractError("finding origin is not allowlisted")
        if _atom(item.get("finding_type"), "finding_type") not in FINDING_TYPES:
            raise AIAdvisoryContractError("finding type is not allowlisted")
        if _atom(item.get("policy_rule_id"), "policy_rule_id") not in POLICY_RULE_IDS:
            raise AIAdvisoryContractError("finding policy rule is not allowlisted")
        if _atom(item.get("severity"), "severity") not in SEVERITIES:
            raise AIAdvisoryContractError("finding severity is not allowlisted")
        if _atom(item.get("status"), "status") not in FINDING_STATUSES:
            raise AIAdvisoryContractError("finding status is not allowlisted")
        if _atom(item.get("semantic_family"), "semantic_family", allow_empty=True) not in SEMANTIC_FAMILIES:
            raise AIAdvisoryContractError("semantic family is not allowlisted")
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
        for key in ("hypothesis_id", "hypothesis_set_id"):
            _atom(item.get(key), key)
        if _atom(item.get("status"), "status") not in HYPOTHESIS_STATUSES:
            raise AIAdvisoryContractError("hypothesis status is not allowlisted")
        if set(_atoms(item.get("evidence_refs"), "hypothesis evidence_refs")) - evidence_ids:
            raise AIAdvisoryContractError("hypothesis evidence reference is unresolved")
        if set(_atoms(item.get("relationship_refs"), "hypothesis relationship_refs")) - relationship_ids:
            raise AIAdvisoryContractError("hypothesis relationship reference is unresolved")
        limitations = _atoms(item.get("limitation_codes"), "hypothesis limitation_codes")
        falsifiers = _atoms(item.get("falsifier_codes"), "hypothesis falsifier_codes")
        if set(limitations) - set(policy["limitation_codes"]) or set(falsifiers) - set(policy["falsifier_codes"]):
            raise AIAdvisoryContractError("hypothesis code is unknown")

    guidance = _exact(root.get("guidance"), GUIDANCE_KEYS, "guidance")
    _atom(guidance.get("guidance_id"), "guidance_id")
    if _atom(guidance.get("status"), "status") not in GUIDANCE_STATUSES:
        raise AIAdvisoryContractError("guidance status is not allowlisted")
    if _atom(guidance.get("guidance_state"), "guidance_state") not in GUIDANCE_STATES:
        raise AIAdvisoryContractError("guidance state is not allowlisted")
    actions = guidance.get("actions")
    if not isinstance(actions, list) or len(actions) > policy["limits"]["max_actions"]:
        raise AIAdvisoryContractError("guidance actions must be bounded")
    action_ids: set[str] = set()
    for index, raw in enumerate(actions):
        item = _exact(raw, ACTION_KEYS, f"actions[{index}]")
        action_id = _atom(item.get("action_id"), "action_id")
        if _atom(item.get("rule_id"), "rule_id") not in POLICY_RULE_IDS:
            raise AIAdvisoryContractError("action rule is not allowlisted")
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
    abstention_reason = _atom(
        abstention.get("reason_code"), "reason_code", allow_empty=True
    )
    if abstention_reason not in {"", *policy["reason_codes"]}:
        raise AIAdvisoryContractError("abstention reason is not allowlisted")
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
    graph = evidence.get("semantic_graph") or {}
    if isinstance(graph, Mapping) and isinstance(graph.get("evidence_nodes"), list):
        precedence = (
            "direct_transfer_observation",
            "cowrie_event_observation",
            "command_observation",
            "trusted_attck_candidate",
        )
        output = []
        for ordinal, item in enumerate(sorted(
            (node for node in graph.get("evidence_nodes") or [] if isinstance(node, Mapping)),
            key=lambda node: _clean(node.get("evidence_id")),
        )):
            kinds = set(item.get("evidence_kinds") or [])
            evidence_kind = next(
                (kind for kind in precedence if kind in kinds),
                "command_observation",
            )
            output.append({
                "evidence_id": _clean(item.get("evidence_id")),
                "evidence_kind": evidence_kind,
                "ordinal": ordinal,
                "status": _clean(item.get("status") or "observed"),
            })
        return output
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
    graph = evidence.get("semantic_graph") or {}
    if isinstance(graph, Mapping) and isinstance(graph.get("relationship_edges"), list):
        chain_ids = {
            _clean(item.get("chain_id"))
            for item in graph.get("chain_nodes") or []
            if isinstance(item, Mapping) and _clean(item.get("chain_id"))
        }
        output = []
        for item in graph.get("relationship_edges") or []:
            if not isinstance(item, Mapping):
                continue
            relationship_id = _clean(item.get("relationship_id"))
            if not relationship_id:
                continue
            refs = [
                _clean(ref)
                for ref in item.get("evidence_refs") or []
                if _clean(ref)
            ]
            if any(ref not in evidence_ids for ref in refs):
                raise AIAdvisoryContractError("relationship has unresolved evidence reference")
            output.append({
                "relationship_id": relationship_id,
                "relationship_type": _clean(item.get("relationship_type")),
                "status": _clean(item.get("status")),
                "source_evidence_ref": refs[0] if refs else "",
                "target_evidence_ref": refs[1] if len(refs) > 1 else "",
                "entity_ref": _clean(item.get("entity_ref")),
                "chain_ref": next(
                    (
                        _clean(chain.get("chain_id"))
                        for chain in graph.get("chain_nodes") or []
                        if isinstance(chain, Mapping)
                        and relationship_id in {
                            _clean(ref)
                            for ref in (
                                (chain.get("required_relationship_refs") or [])
                                + (chain.get("supporting_relationship_refs") or [])
                            )
                        }
                    ),
                    "",
                ),
                "limitation_codes": list(item.get("limitation_codes") or []),
            })
        return output
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
    alias_scope: ProviderAliasScope | None = None,
) -> Dict[str, Any]:
    """Build the only data object allowed to cross the external AI boundary."""

    report_copy = deepcopy(dict(report))
    errors = validate_session_assessment(report_copy)
    if errors:
        raise AIAdvisoryContractError("persisted assessment failed validation")
    guidance = report_copy.get("response_guidance_v3") or {}
    if validate_response_guidance_v3(guidance):
        raise AIAdvisoryContractError("persisted v3 guidance failed validation")
    evidence = report_copy["canonical_evidence"]
    evidence_index = _evidence_index(evidence)
    evidence_ids = {item["evidence_id"] for item in evidence_index}
    relationships = _relationships(evidence, evidence_ids)
    relationship_ids = {item["relationship_id"] for item in relationships}
    graph = evidence.get("semantic_graph") or {}
    trusted_authority_ids = {
        _clean(item.get("candidate_id"))
        for item in graph.get("authority_decisions") or []
        if isinstance(item, Mapping) and item.get("decision") == "trusted"
    }
    has_authority_decisions = isinstance(
        graph.get("authority_decisions"), list
    )

    findings = []
    for item in report_copy.get("behavioral_findings") or []:
        if not isinstance(item, Mapping):
            continue
        if has_authority_decisions and _clean(item.get("finding_id")) not in trusted_authority_ids:
            # Preserve audit-only candidates in the local report/graph, but
            # fail closed before any provider-scoped projection.
            continue
        refs = _strings(item.get("evidence_refs"))
        rel_refs = _strings(item.get("relationship_refs"))
        if set(refs) - evidence_ids or set(rel_refs) - relationship_ids:
            raise AIAdvisoryContractError("finding references do not resolve")
        findings.append(
            {
                "finding_id": _clean(item.get("finding_id")),
                "origin": _clean(report_copy.get("schema_version")) or "session_assessment.v5",
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
                    # The closed provider contract retains its historical
                    # non-authoritative "active" enum. Local v5 meaning was
                    # already validated as a bounded unverified alternative.
                    "status": "active",
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
    validation_policy_sha256 = policy_sha256
    if alias_scope is not None:
        base = _provider_alias_projection(base, alias_scope)
        validation_policy_sha256 = str(
            base["provenance"]["ai_policy_sha256"]
        )
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
        policy_sha256=validation_policy_sha256,
    )


def _provider_alias_projection(
    base: Mapping[str, Any], alias_scope: ProviderAliasScope
) -> Dict[str, Any]:
    """Replace every provider-visible canonical identity with a scoped alias."""

    result = deepcopy(dict(base))
    result["assessment_id"] = alias_scope.alias(
        "assessment", result["assessment_id"]
    )
    result["evidence_sha256"] = alias_scope.digest(
        "evidence_digest", result["evidence_sha256"]
    )
    provenance = result["provenance"]
    provenance["evaluator_git_revision"] = alias_scope.digest(
        "evaluator_revision", provenance["evaluator_git_revision"], length=40
    )
    for key in PROVENANCE_KEYS - {
        "evaluator_git_revision",
        "guidance_profile_status",
    }:
        if provenance.get(key):
            provenance[key] = alias_scope.digest(
                f"provenance_{key}", provenance[key]
            )

    for item in result["evidence_index"]:
        item["evidence_id"] = alias_scope.alias("evidence", item["evidence_id"])
    for item in result["relationships"]:
        item["relationship_id"] = alias_scope.alias(
            "relationship", item["relationship_id"]
        )
        for key in ("source_evidence_ref", "target_evidence_ref"):
            if item[key]:
                item[key] = alias_scope.alias("evidence", item[key])
        if item["entity_ref"]:
            item["entity_ref"] = alias_scope.alias("entity", item["entity_ref"])
        if item["chain_ref"]:
            item["chain_ref"] = alias_scope.alias("chain", item["chain_ref"])
    for item in result["findings"]:
        item["finding_id"] = alias_scope.alias("finding", item["finding_id"])
        item["evidence_refs"] = [
            alias_scope.alias("evidence", value) for value in item["evidence_refs"]
        ]
        item["relationship_refs"] = [
            alias_scope.alias("relationship", value)
            for value in item["relationship_refs"]
        ]
    for item in result["hypotheses"]:
        item["hypothesis_id"] = alias_scope.alias(
            "hypothesis", item["hypothesis_id"]
        )
        item["hypothesis_set_id"] = alias_scope.alias(
            "hypothesis_set", item["hypothesis_set_id"]
        )
        item["evidence_refs"] = [
            alias_scope.alias("evidence", value) for value in item["evidence_refs"]
        ]
        item["relationship_refs"] = [
            alias_scope.alias("relationship", value)
            for value in item["relationship_refs"]
        ]
    guidance = result["guidance"]
    guidance["guidance_id"] = alias_scope.alias("guidance", guidance["guidance_id"])
    for item in guidance["actions"]:
        item["action_id"] = alias_scope.alias("action", item["action_id"])
        item["finding_ids"] = [
            alias_scope.alias("finding", value) for value in item["finding_ids"]
        ]
        item["evidence_refs"] = [
            alias_scope.alias("evidence", value) for value in item["evidence_refs"]
        ]
    return result


def restore_validated_output_aliases(
    value: Mapping[str, Any], alias_scope: ProviderAliasScope
) -> Dict[str, Any]:
    """Restore accepted provider aliases to exact local canonical identities."""

    result = deepcopy(dict(value))
    advisory = result["validated_advisory"]
    mappings = {
        "selected_finding_ids": "finding",
        "selected_relationship_ids": "relationship",
        "ranked_action_ids": "action",
    }
    for key, kind in mappings.items():
        advisory[key] = [alias_scope.restore(kind, item) for item in advisory[key]]
    for selection in advisory["template_selections"]:
        for key, kind in (
            ("finding_ids", "finding"),
            ("relationship_ids", "relationship"),
            ("action_ids", "action"),
        ):
            selection[key] = [
                alias_scope.restore(kind, item) for item in selection[key]
            ]
    for candidate in result["shadow_candidates"]["candidates"]:
        candidate.pop("candidate_id", None)
        for key, kind in (
            ("premise_finding_ids", "finding"),
            ("premise_relationship_ids", "relationship"),
            ("premise_evidence_refs", "evidence"),
        ):
            candidate[key] = [
                alias_scope.restore(kind, item) for item in candidate[key]
            ]
        candidate["candidate_id"] = stable_id(
            "ai_candidate",
            {
                "provider_scope": alias_scope.scope,
                **{key: item for key, item in candidate.items() if key != "candidate_id"},
            },
        )
    return result


# Additive Final-F projection contract. The v1 builder/validator above remains
# unchanged for immutable historical advisory records.
V2_SCHEMA_VERSION = "ai_advisory_projection.v2"
FROZEN_FINAL_F_CONTRACT_SHA256 = (
    "acf6e3a017af771a24cc936e94ccf2edee1bb1612ae3896f6f491c207292e611"
)
FROZEN_FINAL_F_POLICY_SHA256 = (
    "521d6222f7bfaddb5617a93a03d22a490770dbbcd57c1fc7310496403e3be115"
)
V2_ALIAS_RE = re.compile(r"^a_[0-9a-f]{32}$")
V2_TOP_KEYS = {
    "schema_version", "assessment_id", "report_content_sha256",
    "evidence_sha256", "graph_sha256", "typed_fact_set_sha256",
    "guidance_content_sha256", "provenance", "authority",
    "timeline_steps", "facts", "chains", "relationships", "findings",
    "hypotheses", "actions", "limitations", "evidence_gaps",
    "allowed_output", "abstention", "projection_sha256",
}
V2_PROVENANCE_KEYS = {
    "evaluator_git_revision", "behavior_policy_sha256",
    "classification_policy_sha256", "typed_vocabulary_sha256",
    "guidance_policy_sha256", "ai_policy_sha256",
    "projection_contract_sha256",
}
V2_AUTHORITY_KEYS = {
    "ai_canonical_authority", "ai_finding_authority",
    "ai_hypothesis_authority", "ai_guidance_authority",
    "ai_alert_authority", "ai_prediction_authority",
    "ai_execution_authority",
}
V2_TIMELINE_KEYS = {
    "ordinal", "evidence_ids", "fact_ids", "semantic_families",
    "operation_types", "outcome_status", "entity_ids",
    "relationship_ids", "chain_ids", "finding_ids",
}
V2_FACT_KEYS = {
    "fact_id", "causal_ordinal", "semantic_family", "operation_types",
    "outcome_status", "evidence_ids", "entity_ids",
}
V2_CHAIN_KEYS = {
    "chain_id", "status", "fact_ids", "relationship_ids",
    "evidence_ids", "entity_ids", "limitation_codes",
    "evidence_gap_codes", "ai_eligible",
}
V2_RELATIONSHIP_KEYS = {
    "relationship_id", "relationship_type", "status", "source_fact_id",
    "target_fact_id", "entity_id", "limitation_codes",
}
V2_FINDING_KEYS = {
    "finding_id", "finding_type", "semantic_family", "status",
    "priority_band", "chain_ids", "relationship_ids", "evidence_ids",
    "limitation_codes",
}
V2_HYPOTHESIS_KEYS = {
    "hypothesis_id", "hypothesis_set_id", "status", "chain_ids",
    "relationship_ids", "fact_ids", "evidence_ids", "limitation_codes",
    "evidence_gap_codes", "falsifier_codes",
}
V2_ACTION_KEYS = {
    "action_id", "action_category", "rule_id", "policy_order",
    "finding_ids", "evidence_ids", "requires_manual_approval",
    "safe_to_auto_execute", "execution_integration",
}
V2_ALLOWED_OUTPUT_KEYS = {
    "chain_ids", "relationship_ids", "finding_ids", "hypothesis_ids",
    "action_ids", "limitation_codes", "evidence_gap_codes",
    "analyst_question_template_ids", "explanation_template_ids",
    "step_types", "anchor_types", "abstention_reason_codes",
}
V2_ABSTENTION_KEYS = {"assessment_abstained", "reason_codes"}
V2_PROHIBITED_FIELDS = {
    "raw_command", "command_fragment", "durable_event_ref", "source_ip",
    "destination_address", "username", "password", "credential", "url",
    "payload", "filename", "entity_value", "description", "statement",
    "previous_ai_prose", "raw_events", "commands", "src_ip", "input",
}
V2_FAMILIES = {
    "sensitive_read", "transfer", "transfer_attempt", "inspection",
    "filesystem", "execution",
}


def _read_v2_json(path_text: str, label: str) -> tuple[dict[str, Any], str]:
    path = Path(str(path_text or ""))
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AIAdvisoryContractError(f"{label} is unavailable") from exc
    if not isinstance(value, dict):
        raise AIAdvisoryContractError(f"{label} must be an object")
    return value, hashlib.sha256(raw).hexdigest()


def _v2_inputs(
    ai_policy_path: str,
    projection_contract_path: str,
) -> tuple[dict[str, Any], str, str]:
    policy, policy_sha256 = _read_v2_json(ai_policy_path, "AI policy v2")
    bundle, contract_sha256 = _read_v2_json(
        projection_contract_path, "Final F projection contract"
    )
    if contract_sha256 != FROZEN_FINAL_F_CONTRACT_SHA256:
        raise AIAdvisoryContractError("projection contract identity mismatch")
    if policy_sha256 != FROZEN_FINAL_F_POLICY_SHA256:
        raise AIAdvisoryContractError("AI policy v2 identity mismatch")
    contract = bundle.get("projection_contract") or {}
    nested = contract.get("nested_exact_keys") or {}
    expected_nested = {
        "provenance": V2_PROVENANCE_KEYS,
        "authority": V2_AUTHORITY_KEYS,
        "timeline_step": V2_TIMELINE_KEYS,
        "fact": V2_FACT_KEYS,
        "chain": V2_CHAIN_KEYS,
        "relationship": V2_RELATIONSHIP_KEYS,
        "finding": V2_FINDING_KEYS,
        "hypothesis": V2_HYPOTHESIS_KEYS,
        "action": V2_ACTION_KEYS,
        "allowed_output": V2_ALLOWED_OUTPUT_KEYS,
        "abstention": V2_ABSTENTION_KEYS,
    }
    if (
        bundle.get("versions", {}).get("projection") != V2_SCHEMA_VERSION
        or set(contract.get("exact_keys") or []) != V2_TOP_KEYS
        or any(set(nested.get(key) or []) != value for key, value in expected_nested.items())
    ):
        raise AIAdvisoryContractError("projection contract fields mismatch")
    required_policy = {
        "schema_version", "step_types", "anchor_types",
        "abstention_reason_codes", "limitation_codes", "evidence_gap_codes",
        "falsifier_codes", "analyst_question_templates",
        "explanation_templates", "limits",
    }
    if (
        not required_policy.issubset(policy)
        or policy.get("schema_version") != "ai_advisory_policy.v2"
    ):
        raise AIAdvisoryContractError("AI policy v2 contract is invalid")
    for key in (
        "step_types", "anchor_types", "abstention_reason_codes",
        "limitation_codes", "evidence_gap_codes", "falsifier_codes",
    ):
        values = policy.get(key)
        if (
            not isinstance(values, list)
            or not values
            or any(not isinstance(item, str) or not item for item in values)
            or len(values) != len(set(values))
        ):
            raise AIAdvisoryContractError(f"AI policy {key} is invalid")
    for key in ("analyst_question_templates", "explanation_templates"):
        if not isinstance(policy.get(key), dict) or not policy[key]:
            raise AIAdvisoryContractError(f"AI policy {key} is invalid")
    return policy, policy_sha256, contract_sha256


def _v2_aliases(
    scope: AssessmentAliasScope, kind: str, values: Iterable[Any]
) -> list[str]:
    return sorted({scope.alias(kind, value) for value in values if _clean(value)})


def _v2_codes(
    values: Iterable[Any],
    *,
    allowed: set[str],
    mappings: tuple[tuple[str, str], ...],
) -> list[str]:
    output = []
    for raw in values:
        text = _clean(raw).lower().replace("-", "_").replace(" ", "_")
        if text in allowed and text not in output:
            output.append(text)
        for needle, code in mappings:
            if needle in text and code in allowed and code not in output:
                output.append(code)
    return sorted(output)


def _v2_limitation_codes(values: Iterable[Any], policy: Mapping[str, Any]) -> list[str]:
    allowed = set(policy["limitation_codes"])
    return _v2_codes(values, allowed=allowed, mappings=(
        ("intent", "attacker_intent_not_established"),
        ("real_host", "real_host_effect_not_established"),
        ("real-host", "real_host_effect_not_established"),
        ("effect_unconfirmed", "real_host_effect_not_established"),
        ("execution", "execution_not_established"),
        ("transfer", "transfer_not_confirmed"),
        ("acquisition", "credential_acquisition_not_established"),
        ("causal", "relationship_not_causal_proof"),
        ("relationship", "relationship_not_causal_proof"),
        ("outcome", "outcome_unknown"),
        ("unresolved", "unresolved_identity"),
    ))


def _v2_gap_codes(values: Iterable[Any], policy: Mapping[str, Any]) -> list[str]:
    return _v2_codes(values, allowed=set(policy["evidence_gap_codes"]), mappings=(
        ("transfer", "direct_transfer_event_missing"),
        ("execution", "execution_observation_missing"),
        ("follow_on", "execution_observation_missing"),
        ("entity", "resolved_entity_link_missing"),
        ("outcome", "reported_outcome_missing"),
        ("classification", "trusted_classification_missing"),
        ("corrobor", "corroborating_event_missing"),
    ))


def _v2_falsifier_codes(values: Iterable[Any], policy: Mapping[str, Any]) -> list[str]:
    return _v2_codes(values, allowed=set(policy["falsifier_codes"]), mappings=(
        ("entity", "entity_identity_mismatch"),
        ("order", "event_order_mismatch"),
        ("failed", "reported_failure"),
        ("absent", "direct_event_absent"),
        ("unavailable", "trusted_evidence_absent"),
        ("alternative", "alternative_explanation_supported"),
        ("later", "alternative_explanation_supported"),
    ))


def _v2_relationship_status(value: Any) -> str:
    status = _clean(value)
    if status in {"supported", "condition_satisfied", "observed"}:
        return "supported"
    if status in {"partial", "condition_unknown", "condition_not_satisfied"}:
        return "partial"
    raise AIAdvisoryContractError("relationship status is not projectable")


def _v2_chain_status(value: Any) -> str:
    status = _clean(value)
    if status in {"complete", "supported"}:
        return "supported"
    if status == "partial":
        return "partial"
    raise AIAdvisoryContractError("chain status is not projectable")


def _v2_projectable_facts(
    chronology: ChronologicalGraphView,
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    projected = {}
    families = {}
    for fact_id in chronology.ordered_fact_ids:
        family_values = chronology.canonical.semantic_families_for_fact(fact_id)
        if not family_values:
            continue
        if len(family_values) != 1:
            raise AIAdvisoryContractError("fact semantic family is ambiguous")
        projected[fact_id] = chronology.canonical.facts_by_id[fact_id]
        families[fact_id] = family_values[0]
    return projected, families


def _build_ai_advisory_projection_v2_payload(
    report: Mapping[str, Any],
    *,
    alias_scope: AssessmentAliasScope,
    policy: Mapping[str, Any],
    policy_sha256: str,
    contract_sha256: str,
) -> dict[str, Any]:
    if validate_session_assessment_v6(report):
        raise AIAdvisoryContractError("current v6 assessment failed validation")
    assessment_id = _clean(report.get("assessment_id"))
    if alias_scope.assessment_id != assessment_id:
        raise AIAdvisoryContractError("assessment alias scope is stale")
    evidence = report.get("canonical_evidence") or {}
    graph = evidence.get("semantic_graph") or {}
    guidance = report.get("response_guidance_v4") or {}
    if validate_response_guidance_v4(guidance, parent_graph=graph):
        raise AIAdvisoryContractError("current guidance v4 failed validation")
    try:
        chronology = chronological_graph_view(
            graph,
            expected_graph_sha256=_clean(graph.get("graph_sha256")),
            expected_observed_evidence_sha256=_clean(
                evidence.get("observed_evidence_sha256")
            ),
            expected_typed_fact_set_sha256=_clean(
                graph.get("typed_fact_set_sha256")
            ),
        )
    except CanonicalGraphQueryError as exc:
        raise AIAdvisoryContractError("canonical chronology is invalid") from exc
    facts_by_id, families = _v2_projectable_facts(chronology)
    projected_fact_ids = set(facts_by_id)
    graph_relationships = chronology.canonical.relationships_by_id
    relationships = []
    for relationship_id, item in sorted(graph_relationships.items()):
        source = _clean(item.get("source_fact_ref"))
        target = _clean(item.get("target_fact_ref"))
        if source not in projected_fact_ids or target not in projected_fact_ids:
            raise AIAdvisoryContractError(
                "relationship references a non-projectable fact"
            )
        relationships.append({
            "relationship_id": alias_scope.alias("relationship", relationship_id),
            "relationship_type": _clean(item.get("relationship_type")),
            "status": _v2_relationship_status(item.get("status")),
            "source_fact_id": alias_scope.alias("fact", source),
            "target_fact_id": alias_scope.alias("fact", target),
            "entity_id": (
                alias_scope.alias("entity", item.get("entity_ref"))
                if _clean(item.get("entity_ref")) else ""
            ),
            "limitation_codes": _v2_limitation_codes(
                item.get("limitation_codes") or [], policy
            ),
        })

    hypothesis_chain_ids = {
        _clean(ref)
        for hypothesis_set in report.get("hypothesis_sets") or []
        if isinstance(hypothesis_set, Mapping)
        for ref in hypothesis_set.get("chain_refs") or []
        if _clean(ref)
    }
    chains = []
    for chain_id, item in sorted(chronology.canonical.chains_by_id.items()):
        fact_ids = [_clean(ref) for ref in item.get("fact_refs") or []]
        relationship_ids = sorted({
            _clean(ref) for ref in (
                (item.get("required_relationship_refs") or [])
                + (item.get("supporting_relationship_refs") or [])
            ) if _clean(ref)
        })
        if set(fact_ids) - projected_fact_ids:
            raise AIAdvisoryContractError("chain references a non-projectable fact")
        if set(relationship_ids) - set(graph_relationships):
            raise AIAdvisoryContractError("chain relationship reference is unresolved")
        ordered_fact_ids = sorted(
            fact_ids,
            key=lambda fact_id: (chronology.dense_ordinals[fact_id], fact_id),
        )
        evidence_ids = sorted({
            _clean(ref)
            for fact_id in fact_ids
            for ref in facts_by_id[fact_id].get("source_evidence_refs") or []
            if _clean(ref)
        })
        entity_ids = sorted({
            _clean(ref)
            for fact_id in fact_ids
            for ref in facts_by_id[fact_id].get("entity_refs") or []
            if _clean(ref)
        })
        status = _v2_chain_status(item.get("status"))
        gaps = []
        chain_families = {families[fact_id] for fact_id in fact_ids}
        if status == "partial":
            if "transfer_attempt" in chain_families and "transfer" not in chain_families:
                gaps.append("direct_transfer_event_missing")
            if "execution" not in chain_families:
                gaps.append("execution_observation_missing")
        limitations = _v2_limitation_codes(
            (
                code for relationship_id in relationship_ids
                for code in graph_relationships[relationship_id].get(
                    "limitation_codes"
                ) or []
            ),
            policy,
        )
        if relationship_ids and "relationship_not_causal_proof" in set(
            policy["limitation_codes"]
        ):
            limitations = sorted({
                *limitations, "relationship_not_causal_proof"
            })
        chains.append({
            "chain_id": alias_scope.alias("chain", chain_id),
            "status": status,
            "fact_ids": _v2_aliases(alias_scope, "fact", ordered_fact_ids),
            "relationship_ids": _v2_aliases(
                alias_scope, "relationship", relationship_ids
            ),
            "evidence_ids": _v2_aliases(alias_scope, "evidence", evidence_ids),
            "entity_ids": _v2_aliases(alias_scope, "entity", entity_ids),
            "limitation_codes": limitations,
            "evidence_gap_codes": sorted(gaps),
            "ai_eligible": (
                status == "supported"
                or (status == "partial" and bool(gaps or chain_id in hypothesis_chain_ids))
            ),
        })

    chain_alias_by_local = {
        local_id: alias_scope.alias("chain", local_id)
        for local_id in chronology.canonical.chains_by_id
    }
    relationship_alias_by_local = {
        local_id: alias_scope.alias("relationship", local_id)
        for local_id in graph_relationships
    }
    trusted = {
        _clean(item.get("candidate_id"))
        for item in graph.get("authority_decisions") or []
        if isinstance(item, Mapping) and item.get("decision") == "trusted"
    }
    findings = []
    finding_local_by_alias = {}
    for item in report.get("behavioral_findings") or []:
        if not isinstance(item, Mapping):
            continue
        finding_id = _clean(item.get("finding_id"))
        if finding_id not in trusted:
            raise AIAdvisoryContractError("projection finding is not trusted")
        evidence_ids = _strings(item.get("evidence_refs"))
        relationship_ids = _strings(item.get("relationship_refs"))
        if set(evidence_ids) - set(chronology.canonical.evidence_by_id):
            raise AIAdvisoryContractError("finding evidence reference is unresolved")
        if set(relationship_ids) - set(graph_relationships):
            raise AIAdvisoryContractError("finding relationship reference is unresolved")
        chain_ids = []
        connected = _clean(item.get("connected_chain_id"))
        if connected:
            if connected not in chain_alias_by_local:
                raise AIAdvisoryContractError("finding chain reference is unresolved")
            chain_ids.append(connected)
        else:
            for chain_id, chain in chronology.canonical.chains_by_id.items():
                refs = set(chain.get("required_relationship_refs") or []) | set(
                    chain.get("supporting_relationship_refs") or []
                )
                if refs.intersection(relationship_ids):
                    chain_ids.append(chain_id)
        alias = alias_scope.alias("finding", finding_id)
        semantic_family = _clean(item.get("semantic_family"))
        if not semantic_family and chain_ids:
            chain_fact_ids = {
                _clean(ref)
                for chain_id in chain_ids
                for ref in chronology.canonical.chains_by_id[chain_id].get(
                    "fact_refs"
                ) or []
                if _clean(ref) in projected_fact_ids
            }
            if chain_fact_ids:
                last_fact_id = max(
                    chain_fact_ids,
                    key=lambda fact_id: (
                        chronology.dense_ordinals[fact_id], fact_id
                    ),
                )
                semantic_family = families[last_fact_id]
        if semantic_family not in V2_FAMILIES:
            raise AIAdvisoryContractError(
                "finding semantic family is not projectable"
            )
        finding_local_by_alias[alias] = {
            "evidence_ids": set(evidence_ids),
            "semantic_family": semantic_family,
        }
        findings.append({
            "finding_id": alias,
            "finding_type": _clean(item.get("finding_type")),
            "semantic_family": semantic_family,
            "status": "supported",
            "priority_band": "not_applicable",
            "chain_ids": _v2_aliases(alias_scope, "chain", chain_ids),
            "relationship_ids": _v2_aliases(
                alias_scope, "relationship", relationship_ids
            ),
            "evidence_ids": _v2_aliases(alias_scope, "evidence", evidence_ids),
            "limitation_codes": _v2_limitation_codes(
                item.get("limitations") or [], policy
            ),
        })

    hypotheses = []
    for hypothesis_set in report.get("hypothesis_sets") or []:
        if not isinstance(hypothesis_set, Mapping):
            continue
        set_chain_ids = _strings(hypothesis_set.get("chain_refs"))
        set_relationship_ids = _strings(hypothesis_set.get("relationship_refs"))
        set_fact_ids = _strings(hypothesis_set.get("fact_refs"))
        set_evidence_ids = _strings(hypothesis_set.get("evidence_refs"))
        if (
            set(set_chain_ids) - set(chain_alias_by_local)
            or set(set_relationship_ids) - set(graph_relationships)
            or set(set_fact_ids) - projected_fact_ids
            or set(set_evidence_ids) - set(chronology.canonical.evidence_by_id)
        ):
            raise AIAdvisoryContractError("hypothesis set reference is unresolved")
        set_limitations = _v2_limitation_codes(
            hypothesis_set.get("limitations") or [], policy
        )
        set_gaps = _v2_gap_codes(
            hypothesis_set.get("evidence_gaps") or [], policy
        )
        for item in hypothesis_set.get("hypotheses") or []:
            if not isinstance(item, Mapping):
                continue
            supporting = _strings(item.get("supporting_evidence_refs"))
            if set(supporting) - set(chronology.canonical.evidence_by_id):
                raise AIAdvisoryContractError("hypothesis evidence is unresolved")
            hypotheses.append({
                "hypothesis_id": alias_scope.alias(
                    "hypothesis", item.get("hypothesis_id")
                ),
                "hypothesis_set_id": alias_scope.alias(
                    "hypothesis_set", hypothesis_set.get("hypothesis_set_id")
                ),
                "status": "bounded_unverified_alternative",
                "chain_ids": _v2_aliases(alias_scope, "chain", set_chain_ids),
                "relationship_ids": _v2_aliases(
                    alias_scope, "relationship", set_relationship_ids
                ),
                "fact_ids": _v2_aliases(alias_scope, "fact", set_fact_ids),
                "evidence_ids": _v2_aliases(
                    alias_scope, "evidence", {*set_evidence_ids, *supporting}
                ),
                "limitation_codes": sorted({
                    *set_limitations,
                    *_v2_limitation_codes(item.get("limitations") or [], policy),
                }),
                "evidence_gap_codes": set_gaps,
                "falsifier_codes": _v2_falsifier_codes(
                    item.get("falsification_conditions") or [], policy
                ),
            })

    actions = []
    for item in guidance.get("advisory_actions") or []:
        if not isinstance(item, Mapping):
            continue
        if (
            item.get("requires_manual_approval") is not True
            or item.get("safe_to_auto_execute") is not False
            or item.get("execution_integration") != "not_implemented"
        ):
            raise AIAdvisoryContractError("guidance action safety is invalid")
        evidence_ids = set(_strings(item.get("evidence_refs")))
        finding_ids = sorted(
            alias for alias, source in finding_local_by_alias.items()
            if evidence_ids.intersection(source["evidence_ids"])
            and (
                not _clean(item.get("semantic_family"))
                or source["semantic_family"] == _clean(item.get("semantic_family"))
            )
        )
        if not finding_ids:
            continue
        actions.append({
            "action_id": alias_scope.alias("action", item.get("action_id")),
            "action_category": "policy_manual_review",
            "rule_id": _clean(item.get("rule_id")),
            "policy_order": int(item.get("policy_order") or 0),
            "finding_ids": finding_ids,
            "evidence_ids": _v2_aliases(alias_scope, "evidence", evidence_ids),
            "requires_manual_approval": True,
            "safe_to_auto_execute": False,
            "execution_integration": "not_implemented",
        })

    fact_items = []
    for fact_id in chronology.ordered_fact_ids:
        if fact_id not in projected_fact_ids:
            continue
        item = facts_by_id[fact_id]
        fact_items.append({
            "fact_id": alias_scope.alias("fact", fact_id),
            "causal_ordinal": chronology.dense_ordinals[fact_id],
            "semantic_family": families[fact_id],
            "operation_types": _strings(item.get("operation_types")),
            "outcome_status": _clean(item.get("outcome_status")),
            "evidence_ids": _v2_aliases(
                alias_scope, "evidence", item.get("source_evidence_refs") or []
            ),
            "entity_ids": _v2_aliases(
                alias_scope, "entity", item.get("entity_refs") or []
            ),
        })
    relationship_local_by_alias = {
        alias_scope.alias("relationship", local_id): item
        for local_id, item in graph_relationships.items()
    }
    chain_local_by_alias = {
        alias_scope.alias("chain", local_id): item
        for local_id, item in chronology.canonical.chains_by_id.items()
    }
    timeline = []
    for ordinal in sorted(set(chronology.dense_ordinals.values())):
        local_fact_ids = [
            fact_id for fact_id in chronology.fact_ids_at_ordinal(ordinal)
            if fact_id in projected_fact_ids
        ]
        if not local_fact_ids:
            continue
        fact_aliases = _v2_aliases(alias_scope, "fact", local_fact_ids)
        local_evidence = {
            _clean(ref) for fact_id in local_fact_ids
            for ref in facts_by_id[fact_id].get("source_evidence_refs") or []
            if _clean(ref)
        }
        local_entities = {
            _clean(ref) for fact_id in local_fact_ids
            for ref in facts_by_id[fact_id].get("entity_refs") or []
            if _clean(ref)
        }
        relationship_aliases = sorted(
            alias for alias, edge in relationship_local_by_alias.items()
            if _clean(edge.get("source_fact_ref")) in local_fact_ids
            or _clean(edge.get("target_fact_ref")) in local_fact_ids
        )
        chain_aliases = sorted(
            alias for alias, chain in chain_local_by_alias.items()
            if set(local_fact_ids).intersection(chain.get("fact_refs") or [])
        )
        finding_aliases = sorted(
            finding["finding_id"] for finding in findings
            if set(finding["evidence_ids"]).intersection(
                _v2_aliases(alias_scope, "evidence", local_evidence)
            )
        )
        timeline.append({
            "ordinal": len(timeline) + 1,
            "evidence_ids": _v2_aliases(
                alias_scope, "evidence", local_evidence
            ),
            "fact_ids": fact_aliases,
            "semantic_families": sorted({families[item] for item in local_fact_ids}),
            "operation_types": sorted({
                operation for fact_id in local_fact_ids
                for operation in facts_by_id[fact_id].get("operation_types") or []
            }),
            "outcome_status": (
                _clean(facts_by_id[local_fact_ids[0]].get("outcome_status"))
                if len({
                    _clean(facts_by_id[item].get("outcome_status"))
                    for item in local_fact_ids
                }) == 1 else "outcome_unknown"
            ),
            "entity_ids": _v2_aliases(alias_scope, "entity", local_entities),
            "relationship_ids": relationship_aliases,
            "chain_ids": chain_aliases,
            "finding_ids": finding_aliases,
        })
    ordinal_remap = {
        original: item["ordinal"]
        for original, item in zip(
            sorted({
                chronology.dense_ordinals[fact_id]
                for fact_id in projected_fact_ids
            }),
            timeline,
        )
    }
    for item in fact_items:
        local_id = alias_scope.restore("fact", item["fact_id"])
        item["causal_ordinal"] = ordinal_remap[
            chronology.dense_ordinals[local_id]
        ]

    limitations = sorted({
        code for collection in (chains, relationships, findings, hypotheses)
        for item in collection for code in item.get("limitation_codes") or []
    })
    gaps = sorted({
        code for collection in (chains, hypotheses)
        for item in collection for code in item.get("evidence_gap_codes") or []
    })
    question_map = {
        "execution_observation_missing": "ask_for_execution_corroboration",
        "direct_transfer_event_missing": "ask_for_transfer_corroboration",
        "resolved_entity_link_missing": "ask_to_resolve_entity_identity",
        "reported_outcome_missing": "ask_to_verify_reported_outcome",
    }
    questions = sorted({
        question_map[gap] for gap in gaps
        if gap in question_map and question_map[gap] in policy["analyst_question_templates"]
    })
    explanations = []
    for present, template_id in (
        (chains, "explain_chain_and_limits"),
        (findings, "explain_finding_priority"),
        (hypotheses, "explain_hypothesis_test"),
        (actions, "explain_manual_checks"),
        (gaps, "explain_evidence_gaps"),
    ):
        if present and template_id in policy["explanation_templates"]:
            explanations.append(template_id)

    provenance = report.get("provenance") or {}
    typed = provenance.get("typed_semantics") or {}
    vocabulary = load_typed_semantic_vocabulary()
    if (
        vocabulary.get("status") != "valid"
        or vocabulary.get("sha256")
        != _clean((typed.get("semantic_vocabulary") or {}).get("sha256"))
    ):
        raise AIAdvisoryContractError("typed semantic vocabulary identity mismatch")
    base = {
        "schema_version": V2_SCHEMA_VERSION,
        "assessment_id": alias_scope.alias("assessment", assessment_id),
        "report_content_sha256": _clean(report.get("report_content_sha256")),
        "evidence_sha256": _clean(evidence.get("evidence_sha256")),
        "graph_sha256": _clean(graph.get("graph_sha256")),
        "typed_fact_set_sha256": _clean(graph.get("typed_fact_set_sha256")),
        "guidance_content_sha256": _clean(guidance.get("content_sha256")),
        "provenance": {
            "evaluator_git_revision": _clean(provenance.get("evaluator_git_revision")),
            "behavior_policy_sha256": _clean(
                (provenance.get("behavior_policy") or {}).get("sha256")
            ),
            "classification_policy_sha256": _clean(
                (provenance.get("classification_policy") or {}).get("sha256")
            ),
            "typed_vocabulary_sha256": vocabulary["sha256"],
            "guidance_policy_sha256": _clean(
                ((guidance.get("provenance") or {}).get("policy") or {}).get(
                    "file_sha256"
                )
            ),
            "ai_policy_sha256": policy_sha256,
            "projection_contract_sha256": contract_sha256,
        },
        "authority": {key: False for key in sorted(V2_AUTHORITY_KEYS)},
        "timeline_steps": timeline,
        "facts": fact_items,
        "chains": chains,
        "relationships": relationships,
        "findings": findings,
        "hypotheses": hypotheses,
        "actions": actions,
        "limitations": limitations,
        "evidence_gaps": gaps,
        "allowed_output": {
            "chain_ids": sorted(item["chain_id"] for item in chains if item["ai_eligible"]),
            "relationship_ids": sorted(item["relationship_id"] for item in relationships),
            "finding_ids": sorted(item["finding_id"] for item in findings),
            "hypothesis_ids": sorted(item["hypothesis_id"] for item in hypotheses),
            "action_ids": sorted(item["action_id"] for item in actions),
            "limitation_codes": limitations,
            "evidence_gap_codes": gaps,
            "analyst_question_template_ids": questions,
            "explanation_template_ids": sorted(explanations),
            "step_types": sorted(policy["step_types"]),
            "anchor_types": sorted(policy["anchor_types"]),
            "abstention_reason_codes": sorted(policy["abstention_reason_codes"]),
        },
        "abstention": {
            "assessment_abstained": bool(
                (report.get("abstention") or {}).get("abstained")
            ),
            "reason_codes": (
                ["canonical_abstention_only"]
                if (report.get("abstention") or {}).get("abstained")
                else []
            ),
        },
    }
    limits = policy["limits"]
    bounded_collections = {
        "chains": "max_chains",
        "relationships": "max_relationships",
        "findings": "max_findings",
        "hypotheses": "max_hypotheses",
        "actions": "max_actions",
        "limitations": "max_limitations",
        "evidence_gaps": "max_evidence_gaps",
    }
    for collection, limit_key in bounded_collections.items():
        limit = limits.get(limit_key)
        if type(limit) is not int or limit < 0 or len(base[collection]) > limit:
            raise AIAdvisoryContractError(
                f"projection exceeds reviewed {collection} limit"
            )
    request_limit = limits.get("max_request_bytes")
    if (
        type(request_limit) is not int
        or request_limit <= 0
        or len(stable_json(base).encode("utf-8")) > request_limit
    ):
        raise AIAdvisoryContractError("projection exceeds reviewed request limit")
    return base


def _v2_exact(value: Any, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise AIAdvisoryContractError(
            f"{label} violates additionalProperties=false"
        )
    return value


def _v2_alias_list(value: Any, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) != len(set(value))
        or any(not isinstance(item, str) or not V2_ALIAS_RE.fullmatch(item) for item in value)
    ):
        raise AIAdvisoryContractError(f"{label} contains invalid aliases")
    return value


def validate_ai_advisory_projection_v2(
    projection: Any,
    *,
    report: Mapping[str, Any],
    alias_scope: AssessmentAliasScope,
    ai_policy_path: str,
    projection_contract_path: str,
) -> dict[str, Any]:
    policy, policy_sha256, contract_sha256 = _v2_inputs(
        ai_policy_path, projection_contract_path
    )
    root = _v2_exact(projection, V2_TOP_KEYS, "projection v2")
    if root.get("schema_version") != V2_SCHEMA_VERSION:
        raise AIAdvisoryContractError("projection v2 schema is invalid")
    if validate_session_assessment_v6(report):
        raise AIAdvisoryContractError("current v6 assessment failed validation")
    if alias_scope.assessment_id != _clean(report.get("assessment_id")):
        raise AIAdvisoryContractError("assessment alias scope is stale")
    if root.get("assessment_id") != alias_scope.alias(
        "assessment", report.get("assessment_id")
    ):
        raise AIAdvisoryContractError("projection assessment identity mismatch")
    evidence = report.get("canonical_evidence") or {}
    graph = evidence.get("semantic_graph") or {}
    guidance = report.get("response_guidance_v4") or {}
    expected_hashes = {
        "report_content_sha256": report.get("report_content_sha256"),
        "evidence_sha256": evidence.get("evidence_sha256"),
        "graph_sha256": graph.get("graph_sha256"),
        "typed_fact_set_sha256": graph.get("typed_fact_set_sha256"),
        "guidance_content_sha256": guidance.get("content_sha256"),
    }
    for key, expected in expected_hashes.items():
        value = _clean(root.get(key)).lower()
        if not SHA256_RE.fullmatch(value) or value != _clean(expected).lower():
            raise AIAdvisoryContractError(f"projection {key} mismatch")
    provenance = _v2_exact(
        root.get("provenance"), V2_PROVENANCE_KEYS, "projection provenance"
    )
    for key in V2_PROVENANCE_KEYS - {"evaluator_git_revision"}:
        if not SHA256_RE.fullmatch(_clean(provenance.get(key)).lower()):
            raise AIAdvisoryContractError(f"projection {key} is invalid")
    if provenance.get("ai_policy_sha256") != policy_sha256:
        raise AIAdvisoryContractError("projection AI policy hash mismatch")
    if provenance.get("projection_contract_sha256") != contract_sha256:
        raise AIAdvisoryContractError("projection contract hash mismatch")
    if not SAFE_ATOM_RE.fullmatch(_clean(provenance.get("evaluator_git_revision"))):
        raise AIAdvisoryContractError("projection evaluator revision is invalid")
    authority = _v2_exact(
        root.get("authority"), V2_AUTHORITY_KEYS, "projection authority"
    )
    if any(value is not False for value in authority.values()):
        raise AIAdvisoryContractError("projection grants AI authority")

    vocabulary = load_typed_semantic_vocabulary()
    operations = set((vocabulary.get("document") or {}).get("operations") or {})
    outcomes = set(
        ((vocabulary.get("document") or {}).get("vocabulary") or {}).get(
            "outcome_statuses"
        ) or []
    )
    collections = (
        ("timeline_steps", V2_TIMELINE_KEYS),
        ("facts", V2_FACT_KEYS),
        ("chains", V2_CHAIN_KEYS),
        ("relationships", V2_RELATIONSHIP_KEYS),
        ("findings", V2_FINDING_KEYS),
        ("hypotheses", V2_HYPOTHESIS_KEYS),
        ("actions", V2_ACTION_KEYS),
    )
    for collection, keys in collections:
        if not isinstance(root.get(collection), list):
            raise AIAdvisoryContractError(f"projection {collection} must be a list")
        for index, item in enumerate(root[collection]):
            _v2_exact(item, keys, f"projection {collection}[{index}]")
    ordinals = [item.get("ordinal") for item in root["timeline_steps"]]
    if ordinals != list(range(1, len(ordinals) + 1)):
        raise AIAdvisoryContractError("projection timeline ordinals are invalid")
    for item in root["timeline_steps"]:
        for key in (
            "evidence_ids", "fact_ids", "entity_ids", "relationship_ids",
            "chain_ids", "finding_ids",
        ):
            _v2_alias_list(item.get(key), f"timeline {key}")
        if set(item.get("semantic_families") or []) - V2_FAMILIES:
            raise AIAdvisoryContractError("timeline semantic family is invalid")
        if set(item.get("operation_types") or []) - operations:
            raise AIAdvisoryContractError("timeline operation type is invalid")
        if item.get("outcome_status") not in outcomes:
            raise AIAdvisoryContractError("timeline outcome is invalid")
    for item in root["facts"]:
        _v2_alias_list([item.get("fact_id")], "fact ID")
        _v2_alias_list(item.get("evidence_ids"), "fact evidence IDs")
        _v2_alias_list(item.get("entity_ids"), "fact entity IDs")
        if item.get("semantic_family") not in V2_FAMILIES:
            raise AIAdvisoryContractError("fact semantic family is invalid")
        if set(item.get("operation_types") or []) - operations:
            raise AIAdvisoryContractError("fact operation type is invalid")
        if item.get("outcome_status") not in outcomes:
            raise AIAdvisoryContractError("fact outcome is invalid")
        if item.get("causal_ordinal") not in ordinals:
            raise AIAdvisoryContractError("fact causal ordinal is invalid")
    for collection, identity in (
        ("chains", "chain_id"), ("relationships", "relationship_id"),
        ("findings", "finding_id"), ("hypotheses", "hypothesis_id"),
        ("actions", "action_id"),
    ):
        _v2_alias_list(
            [item[identity] for item in root[collection]],
            f"{collection} identities",
        )
    for item in root["chains"]:
        if item.get("status") not in {"supported", "partial"}:
            raise AIAdvisoryContractError("projection chain status is invalid")
        if type(item.get("ai_eligible")) is not bool:
            raise AIAdvisoryContractError("projection chain eligibility is invalid")
        for key in ("fact_ids", "relationship_ids", "evidence_ids", "entity_ids"):
            _v2_alias_list(item.get(key), f"chain {key}")
    for item in root["relationships"]:
        if item.get("status") not in {"supported", "partial"}:
            raise AIAdvisoryContractError(
                "projection relationship status is invalid"
            )
        for key in ("relationship_id", "source_fact_id", "target_fact_id"):
            _v2_alias_list([item.get(key)], f"relationship {key}")
        if item.get("entity_id"):
            _v2_alias_list([item.get("entity_id")], "relationship entity_id")
        if not SAFE_ATOM_RE.fullmatch(_clean(item.get("relationship_type"))):
            raise AIAdvisoryContractError(
                "projection relationship type is invalid"
            )
    for item in root["findings"]:
        if (
            item.get("status") != "supported"
            or item.get("semantic_family") not in V2_FAMILIES
            or item.get("priority_band") not in {
                "not_applicable", "reviewed_low", "reviewed_medium",
                "reviewed_high", "reviewed_critical",
            }
        ):
            raise AIAdvisoryContractError("projection finding state is invalid")
        for key in ("chain_ids", "relationship_ids", "evidence_ids"):
            _v2_alias_list(item.get(key), f"finding {key}")
        if not SAFE_ATOM_RE.fullmatch(_clean(item.get("finding_type"))):
            raise AIAdvisoryContractError("projection finding type is invalid")
    for item in root["hypotheses"]:
        if item.get("status") != "bounded_unverified_alternative":
            raise AIAdvisoryContractError("projection hypothesis status is invalid")
        _v2_alias_list([item.get("hypothesis_set_id")], "hypothesis set ID")
        for key in ("chain_ids", "relationship_ids", "fact_ids", "evidence_ids"):
            _v2_alias_list(item.get(key), f"hypothesis {key}")
    for item in root["actions"]:
        if (
            item.get("requires_manual_approval") is not True
            or item.get("safe_to_auto_execute") is not False
            or item.get("execution_integration") != "not_implemented"
            or type(item.get("policy_order")) is not int
            or item.get("policy_order") < 0
        ):
            raise AIAdvisoryContractError("projection action safety is invalid")
        for key in ("finding_ids", "evidence_ids"):
            _v2_alias_list(item.get(key), f"action {key}")
        for key in ("action_category", "rule_id"):
            if not SAFE_ATOM_RE.fullmatch(_clean(item.get(key))):
                raise AIAdvisoryContractError(f"projection action {key} is invalid")
    _v2_exact(
        root.get("allowed_output"), V2_ALLOWED_OUTPUT_KEYS,
        "projection allowed_output",
    )
    _v2_exact(root.get("abstention"), V2_ABSTENTION_KEYS, "projection abstention")
    if set(root.get("limitations") or []) - set(policy["limitation_codes"]):
        raise AIAdvisoryContractError("projection limitation code is unknown")
    if set(root.get("evidence_gaps") or []) - set(policy["evidence_gap_codes"]):
        raise AIAdvisoryContractError("projection evidence gap is unknown")
    found = set(_walk_keys(root)).intersection(V2_PROHIBITED_FIELDS)
    if found:
        raise AIAdvisoryContractError(
            f"projection contains prohibited fields: {sorted(found)}",
            code="projection_privacy_violation",
        )
    basis = {key: deepcopy(value) for key, value in root.items() if key != "projection_sha256"}
    if root.get("projection_sha256") != sha256_json(basis):
        raise AIAdvisoryContractError("projection v2 content hash mismatch")
    expected = _build_ai_advisory_projection_v2_payload(
        report,
        alias_scope=alias_scope,
        policy=policy,
        policy_sha256=policy_sha256,
        contract_sha256=contract_sha256,
    )
    expected["projection_sha256"] = sha256_json(expected)
    if dict(root) != expected:
        raise AIAdvisoryContractError(
            "projection v2 does not match the current graph and policy"
        )
    return deepcopy(dict(root))


def build_ai_advisory_projection_v2(
    report: Mapping[str, Any],
    *,
    alias_scope: AssessmentAliasScope,
    ai_policy_path: str,
    projection_contract_path: str,
) -> dict[str, Any]:
    """Build the deterministic, chronological, provider-safe v2 projection."""

    policy, policy_sha256, contract_sha256 = _v2_inputs(
        ai_policy_path, projection_contract_path
    )
    base = _build_ai_advisory_projection_v2_payload(
        report,
        alias_scope=alias_scope,
        policy=policy,
        policy_sha256=policy_sha256,
        contract_sha256=contract_sha256,
    )
    projection = {**base, "projection_sha256": sha256_json(base)}
    return validate_ai_advisory_projection_v2(
        projection,
        report=report,
        alias_scope=alias_scope,
        ai_policy_path=ai_policy_path,
        projection_contract_path=projection_contract_path,
    )
