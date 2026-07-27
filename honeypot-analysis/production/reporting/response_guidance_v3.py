"""Deterministic, evidence-bounded advisory response guidance v3.

This module is intentionally independent of ``smb_decision``.  Only the
immutable canonical observed-behaviour snapshot and a content-addressed,
reviewed policy may select a finding, triage value, or advisory task.  Model
forecasts and enrichment are copied into a clearly non-authoritative context
section and are excluded from selection and identity calculation.
"""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

from production.policies.validate_response_guidance_policy import (
    SCHEMA_VERSION as POLICY_SCHEMA_VERSION,
    validate_response_guidance_policy,
)
from production.policies.validate_smb_policy import validate_asset_profile
from production.utils.serialization import stable_id, stable_json, utc_now


SCHEMA_VERSION = "response_guidance.v3"
CANONICAL_EVIDENCE_SCHEMA_VERSION = "response_guidance_evidence.v1"
LEGACY_ADAPTER_SCHEMA_VERSION = "response_guidance_legacy_adapter.v1"
CANONICAL_EVIDENCE_SCOPE = "observed_behavior"
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_POLICY_PATH = PROJECT_ROOT / "configs" / "response_guidance_policy.v3.json"


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _texts(values: Iterable[Any]) -> List[str]:
    output: List[str] = []
    for value in values or []:
        text = _clean(value)
        if text and text not in output:
            output.append(text)
    return output


def _canonical_text_list(values: Any) -> List[str]:
    """Deduplicate text while retaining its observed order."""

    return _texts(values if isinstance(values, (list, tuple, set)) else [values])


def _canonical_mapping(mapping: Any) -> Dict[str, Any]:
    """Keep the observed fields v3 may display, hash, or evaluate.

    In particular this intentionally discards classifier confidence, scores,
    source reputation, forecast fields, generated prose, and mutable metadata.
    Those values cannot change a v3 guidance ID merely by being attached to a
    session's broader reporting object.
    """

    if not isinstance(mapping, dict):
        return {}
    output: Dict[str, Any] = {}
    for key in (
        "evidence_id",
        "evidence_ref",
        "tactic",
        "ttp",
        "technique_id",
        "eventid",
        "timestamp",
        "command_outcome",
        "sha256",
    ):
        value = _clean(mapping.get(key))
        if value:
            output[key] = value
    if isinstance(mapping.get("sequence_index"), int) and not isinstance(mapping.get("sequence_index"), bool):
        output["sequence_index"] = mapping["sequence_index"]
    if mapping.get("transfer_observed") is True:
        output["transfer_observed"] = True
    for key in ("evidence_refs", "source_evidence_refs", "action_types"):
        values = _canonical_text_list(mapping.get(key))
        if values:
            output[key] = values
    entities = mapping.get("entities")
    if isinstance(entities, dict):
        canonical_entities = {
            _clean(entity_type): _canonical_text_list(entity_values)
            for entity_type, entity_values in entities.items()
            if _clean(entity_type) and _canonical_text_list(entity_values)
        }
        if canonical_entities:
            output["entities"] = canonical_entities
    mappings = []
    for item in mapping.get("trusted_attck_mappings") or []:
        canonical_item = _canonical_mapping(item)
        if canonical_item:
            mappings.append(canonical_item)
    if mappings:
        output["trusted_attck_mappings"] = mappings
    return output


def _canonical_mapping_list(values: Any) -> List[Dict[str, Any]]:
    output = []
    for item in values or []:
        canonical_item = _canonical_mapping(item)
        if canonical_item:
            output.append(canonical_item)
    return output


def _sha256_bytes(value: bytes) -> str:
    return sha256(value).hexdigest()


def _document_sha256(document: Mapping[str, Any]) -> str:
    return _sha256_bytes(stable_json(document).encode("utf-8"))


def _path_label(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_ROOT))
    except ValueError:
        return path.name


def _configured_path(path_text: str, default: Path) -> Path:
    """Resolve configured relative paths from the repository package root."""

    if not _clean(path_text):
        return default
    candidate = Path(path_text)
    return candidate if candidate.is_absolute() else PROJECT_ROOT / candidate


def _evidence_refs_from_item(item: Mapping[str, Any]) -> Set[str]:
    refs: Set[str] = set()
    for key in ("evidence_id", "evidence_ref"):
        if _clean(item.get(key)):
            refs.add(_clean(item.get(key)))
    for key in ("evidence_refs", "source_evidence_refs"):
        refs.update(_texts(item.get(key) or []))
    for mapping in item.get("trusted_attck_mappings") or []:
        if isinstance(mapping, dict) and _clean(mapping.get("evidence_ref")):
            refs.add(_clean(mapping.get("evidence_ref")))
    return refs


def canonical_evidence_snapshot(observed_behavior: Any) -> Dict[str, Any]:
    """Copy only canonical observed-behaviour fields into a stable snapshot.

    The returned data is the v3 evaluator's entire selection input.  It
    deliberately omits model forecasts, enrichment, report recommendations,
    asset context, and mutable runtime policy metadata.
    """

    observed = observed_behavior if isinstance(observed_behavior, dict) else {}
    snapshot = {
        "schema_version": CANONICAL_EVIDENCE_SCHEMA_VERSION,
        "session_id": _clean(observed.get("session_id")) or "unknown",
        "src_ip": _clean(observed.get("src_ip")),
        "ordered_behavior_chain": _canonical_mapping_list(observed.get("ordered_behavior_chain")),
        "ordered_command_observations": _canonical_mapping_list(observed.get("ordered_command_observations")),
        "cowrie_event_evidence": _canonical_mapping_list(observed.get("cowrie_event_evidence")),
        "transfer_event_observations": _canonical_mapping_list(observed.get("transfer_event_observations")),
        "trusted_attck_candidates": _canonical_mapping_list(observed.get("trusted_attck_candidates")),
        "connected_behavior_chains": _canonical_mapping_list(observed.get("connected_behavior_chains")),
        "behavior_relationships": _canonical_mapping_list(observed.get("behavior_relationships")),
    }
    return json.loads(stable_json(snapshot))


def canonical_behavioral_evidence_refs(observed_behavior: Any) -> Set[str]:
    """Return evidence IDs from the immutable v3 observed-evidence snapshot."""

    snapshot = canonical_evidence_snapshot(observed_behavior)
    refs: Set[str] = set()
    for key in (
        "ordered_behavior_chain",
        "ordered_command_observations",
        "cowrie_event_evidence",
        "transfer_event_observations",
        "trusted_attck_candidates",
        "connected_behavior_chains",
        "behavior_relationships",
    ):
        for item in snapshot.get(key) or []:
            if isinstance(item, dict):
                refs.update(_evidence_refs_from_item(item))
    return refs


def _mapping_values(snapshot: Dict[str, Any]) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
    tactics: Dict[str, Set[str]] = {}
    ttps: Dict[str, Set[str]] = {}

    def add(tactic: Any, ttp: Any, refs: Set[str]) -> None:
        tactic_text = _clean(tactic).lower()
        ttp_text = _clean(ttp).upper()
        if tactic_text:
            tactics.setdefault(tactic_text, set()).update(refs)
        if ttp_text:
            ttps.setdefault(ttp_text, set()).update(refs)

    for item in snapshot.get("trusted_attck_candidates") or []:
        if isinstance(item, dict):
            add(item.get("tactic"), item.get("technique_id") or item.get("ttp"), _evidence_refs_from_item(item))
    for item in snapshot.get("ordered_behavior_chain") or []:
        if isinstance(item, dict):
            add(item.get("tactic"), item.get("ttp"), _evidence_refs_from_item(item))
    for observation in snapshot.get("ordered_command_observations") or []:
        if not isinstance(observation, dict):
            continue
        refs = _evidence_refs_from_item(observation)
        for mapping in observation.get("trusted_attck_mappings") or []:
            if isinstance(mapping, dict):
                add(mapping.get("tactic"), mapping.get("ttp"), refs | _evidence_refs_from_item(mapping))
    return tactics, ttps


def _observed_facts(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    all_refs = canonical_behavioral_evidence_refs(snapshot)
    tactics, ttps = _mapping_values(snapshot)
    command_observations = snapshot.get("ordered_command_observations") or []
    command_refs: Set[str] = set()
    entities: Dict[str, Set[str]] = {
        "account_names": set(),
        "artifact_hashes": set(),
        "credential_paths": set(),
        "deleted_paths": set(),
        "destination_paths": set(),
        "executed_paths": set(),
        "modified_paths": set(),
        "source_paths": set(),
        "urls": set(),
    }
    action_types: Dict[str, Set[str]] = {}
    for observation in command_observations:
        if not isinstance(observation, dict):
            continue
        refs = _evidence_refs_from_item(observation)
        command_refs.update(refs)
        for action_type in _texts(observation.get("action_types") or []):
            action_types.setdefault(action_type.lower(), set()).update(refs)
        for entity_type, values in (observation.get("entities") or {}).items():
            if entity_type not in entities:
                continue
            entities[entity_type].update(_texts(values or []))
    transfer_refs: Set[str] = set()
    for observation in snapshot.get("transfer_event_observations") or []:
        if isinstance(observation, dict):
            transfer_refs.update(_evidence_refs_from_item(observation))
    return {
        "evidence_refs": all_refs,
        "tactics": tactics,
        "ttps": ttps,
        "action_types": action_types,
        "command_count": len(command_observations),
        "command_refs": command_refs,
        "flags": {
            "has_commands": bool(command_observations),
            "has_cowrie_transfer_event": bool(transfer_refs),
        },
        "flag_refs": {
            "has_commands": command_refs,
            "has_cowrie_transfer_event": transfer_refs,
        },
        "entities": {key: sorted(values) for key, values in entities.items()},
    }


def _condition_match(condition: Any, facts: Dict[str, Any]) -> Tuple[bool, List[Dict[str, Any]], List[str]]:
    if not isinstance(condition, dict) or not condition:
        return False, [], []
    traces: List[Dict[str, Any]] = []
    evidence_refs: Set[str] = set()

    def values_match(key: str, source: Dict[str, Set[str]], *, all_required: bool) -> bool:
        requested = [_clean(value) for value in condition.get(key) or []]
        requested = [value.lower() if key.endswith("tactics") or key == "any_action_types" else value.upper() if key.endswith("ttps") else value for value in requested]
        available = set(source)
        matched = [value for value in requested if value in available]
        result = len(matched) == len(requested) if all_required else bool(matched)
        refs = sorted({ref for value in matched for ref in source.get(value, set())})
        traces.append({"predicate": key, "expected": requested, "matched": matched, "result": result, "evidence_refs": refs})
        evidence_refs.update(refs)
        return result

    for key, source, all_required in (
        ("all_tactics", facts["tactics"], True),
        ("any_tactics", facts["tactics"], False),
        ("all_ttps", facts["ttps"], True),
        ("any_ttps", facts["ttps"], False),
        ("all_claim_types", {}, True),
        ("any_claim_types", {}, False),
        ("any_action_types", facts["action_types"], False),
    ):
        if key in condition and not values_match(key, source, all_required=all_required):
            return False, traces, sorted(evidence_refs)

    for key, expected in (("required_flags", True), ("absent_flags", False)):
        if key not in condition:
            continue
        requested = _texts(condition.get(key) or [])
        matched = [flag for flag in requested if facts["flags"].get(flag) is expected]
        result = len(matched) == len(requested)
        refs = sorted({ref for flag in matched for ref in facts["flag_refs"].get(flag, set())})
        traces.append({"predicate": key, "expected": requested, "matched": matched, "result": result, "evidence_refs": refs})
        evidence_refs.update(refs)
        if not result:
            return False, traces, sorted(evidence_refs)

    if "min_command_count" in condition:
        expected = int(condition["min_command_count"])
        result = facts["command_count"] >= expected
        refs = sorted(facts["command_refs"])
        traces.append({"predicate": "min_command_count", "expected": expected, "actual": facts["command_count"], "result": result, "evidence_refs": refs})
        evidence_refs.update(refs)
        if not result:
            return False, traces, sorted(evidence_refs)
    return bool(evidence_refs), traces, sorted(evidence_refs)


def _safe_template(template: Any, values: Mapping[str, str]) -> str:
    class _SafeValues(dict[str, str]):
        def __missing__(self, key: str) -> str:
            return "not observed"

    try:
        return _clean(template).format_map(_SafeValues(values))
    except (KeyError, ValueError):
        return _clean(template)


def _context_values(snapshot: Dict[str, Any], facts: Dict[str, Any]) -> Dict[str, str]:
    """Return template values only from the canonical evidence snapshot."""

    values = {key: ", ".join(item) if item else "not observed" for key, item in facts["entities"].items()}
    values.update({
        "src_ip": _clean(snapshot.get("src_ip")) or "not observed",
        "session_id": _clean(snapshot.get("session_id")) or "unknown",
    })
    return values


def _policy_metadata(document: Dict[str, Any], digest: str, source: str, status: str, errors: List[str]) -> Dict[str, Any]:
    return {
        "schema_version": _clean(document.get("schema_version")),
        "policy_id": _clean(document.get("policy_id")),
        "version": _clean(document.get("version")),
        "updated_at": _clean(document.get("updated_at")),
        "review_expires_at": _clean(document.get("review_expires_at")),
        "sha256": digest,
        "source": source,
        "status": status,
        "validation_errors": list(errors),
    }


def _profile_metadata(document: Dict[str, Any], digest: str, source: str, status: str, errors: List[str]) -> Dict[str, Any]:
    return {
        "schema_version": _clean(document.get("schema_version")),
        "sha256": digest,
        "source": source,
        "status": status,
        "validation_errors": list(errors),
        "selection_influence": "none",
    }


def load_response_guidance_policy(path_text: str = "") -> Dict[str, Any]:
    """Load and content-address a v3 policy, failing closed on any error."""

    path = _configured_path(path_text, DEFAULT_POLICY_PATH)
    try:
        raw = path.read_bytes()
        document = json.loads(raw.decode("utf-8"))
        if not isinstance(document, dict):
            raise ValueError("policy root must be an object")
        errors = validate_response_guidance_policy(document)
        return {
            "document": document,
            "sha256": _sha256_bytes(raw),
            "source": _path_label(path),
            "status": "valid" if not errors else "invalid",
            "validation_errors": errors,
        }
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        return {
            "document": {},
            "sha256": "",
            "source": _path_label(path),
            "status": "unavailable",
            "validation_errors": [f"policy load failed: {exc.__class__.__name__}"],
        }


def load_response_guidance_asset_profile(path_text: str = "") -> Dict[str, Any]:
    """Load an optional explicitly configured asset profile without using it to select actions."""

    if not _clean(path_text):
        return {"document": {}, "sha256": "", "source": "", "status": "not_configured", "validation_errors": []}
    path = _configured_path(path_text, PROJECT_ROOT)
    try:
        if ".example." in path.name:
            return {
                "document": {},
                "sha256": "",
                "source": _path_label(path),
                "status": "invalid",
                "validation_errors": ["example asset profiles are prohibited for response guidance"],
            }
        raw = path.read_bytes()
        document = json.loads(raw.decode("utf-8"))
        if not isinstance(document, dict):
            raise ValueError("asset profile root must be an object")
        errors = validate_asset_profile(document)
        return {
            "document": document,
            "sha256": _sha256_bytes(raw),
            "source": _path_label(path),
            "status": "valid" if not errors else "invalid",
            "validation_errors": errors,
        }
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        return {
            "document": {},
            "sha256": "",
            "source": _path_label(path),
            "status": "unavailable",
            "validation_errors": [f"asset profile load failed: {exc.__class__.__name__}"],
        }


def _guidance_identity(
    *,
    session_id: str,
    evidence_sha256: str,
    policy_sha256: str,
    profile_sha256: str,
    finding_rules: List[Dict[str, Any]],
    actions: List[Dict[str, Any]],
    status: str,
    guidance_state: str,
) -> str:
    return stable_id("response_guidance_v3", {
        "schema_version": SCHEMA_VERSION,
        "session_id": session_id,
        "canonical_evidence_sha256": evidence_sha256,
        "policy_sha256": policy_sha256,
        "profile_sha256": profile_sha256,
        "findings": [
            {"rule_id": item.get("rule_id"), "evidence_refs": item.get("supporting_evidence_refs")}
            for item in finding_rules
        ],
        "actions": [
            {"rule_id": item.get("rule_id"), "action_id": item.get("action_id"), "evidence_refs": item.get("evidence_refs")}
            for item in actions
        ],
        "status": status,
        "guidance_state": guidance_state,
    })


def validate_response_guidance_v3(value: Any) -> List[str]:
    """Validate the immutable-evidence and no-automation v3 output contract."""

    errors: List[str] = []
    if not isinstance(value, dict):
        return ["response guidance must be an object"]
    if value.get("schema_version") != SCHEMA_VERSION:
        errors.append("unsupported response guidance schema")
    if value.get("authority") not in {"deterministic_observed_evidence_policy", "policy_unavailable"}:
        errors.append("unsupported guidance authority")
    evidence = value.get("canonical_evidence")
    if not isinstance(evidence, dict):
        errors.append("canonical_evidence is required")
        evidence = {}
    expected_evidence_hash = _document_sha256(canonical_evidence_snapshot(evidence)) if evidence else ""
    recorded_evidence_hash = _clean((value.get("provenance") or {}).get("canonical_evidence_sha256"))
    if not recorded_evidence_hash or recorded_evidence_hash != expected_evidence_hash:
        errors.append("canonical evidence digest is inconsistent")
    policy = (value.get("provenance") or {}).get("policy") or {}
    policy_hash = _clean(policy.get("sha256"))
    if len(policy_hash) != 64 or any(char not in "0123456789abcdef" for char in policy_hash):
        errors.append("policy SHA-256 is required")
    profile = (value.get("provenance") or {}).get("asset_profile") or {}
    profile_hash = _clean(profile.get("sha256"))
    if profile_hash and (len(profile_hash) != 64 or any(char not in "0123456789abcdef" for char in profile_hash)):
        errors.append("asset profile SHA-256 is malformed")
    if (value.get("safety") or {}).get("automatic_execution") is not False:
        errors.append("automatic execution must be false")
    if (value.get("safety") or {}).get("alerting_side_effect") is not False:
        errors.append("guidance must not create alerts")
    allowed_refs = canonical_behavioral_evidence_refs(evidence)
    actions = value.get("advisory_actions")
    if not isinstance(actions, list):
        errors.append("advisory_actions must be an array")
        actions = []
    seen: Set[str] = set()
    for index, action in enumerate(actions):
        if not isinstance(action, dict):
            errors.append(f"advisory_actions[{index}] must be an object")
            continue
        action_id = _clean(action.get("action_id"))
        if not action_id or action_id in seen:
            errors.append(f"advisory_actions[{index}] has missing or duplicate action_id")
        seen.add(action_id)
        refs = _texts(action.get("evidence_refs") or [])
        if not refs or not set(refs).issubset(allowed_refs):
            errors.append(f"advisory_actions[{index}] lacks canonical observed-evidence grounding")
        if action.get("evidence_scope") != [CANONICAL_EVIDENCE_SCOPE]:
            errors.append(f"advisory_actions[{index}] has invalid evidence scope")
        if action.get("requires_manual_approval") is not True:
            errors.append(f"advisory_actions[{index}] must require manual approval")
        if action.get("safe_to_auto_execute") is not False:
            errors.append(f"advisory_actions[{index}] must prohibit automatic execution")
        if action.get("execution_integration") != "not_implemented":
            errors.append(f"advisory_actions[{index}] may not have an execution integration")
        traces = action.get("matched_predicates")
        if not isinstance(traces, list) or not traces or not all(item.get("result") is True for item in traces if isinstance(item, dict)):
            errors.append(f"advisory_actions[{index}] lacks a complete matched predicate trace")
    findings = value.get("findings")
    if not isinstance(findings, list):
        errors.append("findings must be an array")
        findings = []
    for index, finding in enumerate(findings):
        refs = _texts(finding.get("supporting_evidence_refs") if isinstance(finding, dict) else [])
        if not isinstance(finding, dict) or not refs or not set(refs).issubset(allowed_refs):
            errors.append(f"findings[{index}] lacks canonical observed-evidence grounding")
    expected_id = _guidance_identity(
        session_id=_clean(value.get("session_id")) or "unknown",
        evidence_sha256=recorded_evidence_hash,
        policy_sha256=policy_hash,
        profile_sha256=profile_hash,
        finding_rules=findings,
        actions=actions,
        status=_clean(value.get("status")),
        guidance_state=_clean(value.get("guidance_state")),
    )
    if _clean(value.get("guidance_id")) != expected_id:
        errors.append("guidance_id is inconsistent with immutable inputs")
    return errors


def build_response_guidance_v3(
    observed_behavior: Any,
    *,
    policy: Optional[Dict[str, Any]] = None,
    policy_sha256: str = "",
    policy_source: str = "",
    policy_status: str = "valid",
    policy_validation_errors: Optional[List[str]] = None,
    asset_profile: Optional[Dict[str, Any]] = None,
    asset_profile_sha256: str = "",
    asset_profile_source: str = "",
    asset_profile_status: str = "not_configured",
    asset_profile_validation_errors: Optional[List[str]] = None,
    session_context: Optional[Dict[str, Any]] = None,
    forecast_context: Any = None,
    enrichment_context: Any = None,
) -> Dict[str, Any]:
    """Evaluate v3 policy directly against immutable observed Cowrie evidence."""

    snapshot = canonical_evidence_snapshot(observed_behavior)
    evidence_sha256 = _document_sha256(snapshot)
    facts = _observed_facts(snapshot)
    document = deepcopy(policy) if isinstance(policy, dict) else {}
    policy_errors = list(policy_validation_errors or validate_response_guidance_policy(document))
    digest = _clean(policy_sha256) or (_document_sha256(document) if document else "")
    profile_document = deepcopy(asset_profile) if isinstance(asset_profile, dict) else {}
    profile_errors = list(
        asset_profile_validation_errors
        or (validate_asset_profile(profile_document) if profile_document else [])
    )
    profile_digest = _clean(asset_profile_sha256) or (_document_sha256(profile_document) if profile_document else "")
    policy_ok = policy_status == "valid" and not policy_errors and bool(digest)
    profile_ok = asset_profile_status in {"valid", "not_configured"} and not profile_errors
    status = "available" if policy_ok and profile_ok else "unavailable"
    authority = "deterministic_observed_evidence_policy" if status == "available" else "policy_unavailable"
    context_values = _context_values(snapshot, facts)
    findings: List[Dict[str, Any]] = []
    actions: List[Dict[str, Any]] = []
    if status == "available":
        for rule in document.get("finding_rules") or []:
            if not isinstance(rule, dict):
                continue
            matched, trace, refs = _condition_match(rule.get("applies_when"), facts)
            if not matched or not refs:
                continue
            findings.append({
                "finding_id": stable_id("response_guidance_finding", {"rule_id": rule.get("rule_id"), "evidence_refs": refs, "evidence_sha256": evidence_sha256}),
                "rule_id": _clean(rule.get("rule_id")),
                "severity": _clean(rule.get("severity")) or "info",
                "statement": _safe_template(rule.get("statement"), context_values),
                "supporting_evidence_refs": refs,
                "matched_predicates": trace,
                "references": deepcopy(rule.get("references") or []),
                "provenance": deepcopy(rule.get("provenance") or {}),
            })
        for rule in document.get("action_playbooks") or []:
            if not isinstance(rule, dict):
                continue
            matched, trace, refs = _condition_match(rule.get("applies_when"), facts)
            if not matched or not refs:
                continue
            for action in rule.get("actions") or []:
                if not isinstance(action, dict):
                    continue
                actions.append({
                    "action_id": _clean(action.get("action_id")),
                    "rule_id": _clean(rule.get("rule_id")),
                    "description": _safe_template(action.get("action"), context_values),
                    "rationale": _safe_template(action.get("rationale"), context_values),
                    "policy_order": action.get("priority"),
                    "evidence_scope": [CANONICAL_EVIDENCE_SCOPE],
                    "evidence_refs": refs,
                    "matched_predicates": deepcopy(trace),
                    "preconditions": [
                        "Verify each cited Cowrie observation and its visibility limitation.",
                        "Confirm the target system is owned or explicitly authorized before any external change.",
                        "Obtain human approval before performing any external-system action.",
                    ],
                    "verification_steps": [
                        "Record the authorized system and the evidence used for the review.",
                        "Record the observed result without treating absence of evidence as proof of safety.",
                    ],
                    "rollback_guidance": "This system performs no action. Define and approve target-specific rollback before an authorized external change.",
                    "requires_manual_approval": True,
                    "safe_to_auto_execute": False,
                    "execution_integration": "not_implemented",
                    "references": deepcopy(action.get("references") or []),
                    "provenance": {"rule": deepcopy(rule.get("provenance") or {}), "action": deepcopy(action.get("provenance") or {})},
                })
    findings.sort(key=lambda item: (-SEVERITY_ORDER.get(item["severity"], 0), item["rule_id"], item["finding_id"]))
    actions.sort(key=lambda item: (int(item.get("policy_order") or 9999), item["action_id"], item["rule_id"]))
    strongest = findings[0] if findings else None
    guidance_state = "actions_available" if actions else "no_applicable_grounded_action"
    if status != "available":
        guidance_state = "policy_or_profile_unavailable"
    severity = _clean((strongest or {}).get("severity")) or "info"
    guidance_id = _guidance_identity(
        session_id=_clean(snapshot.get("session_id")) or "unknown",
        evidence_sha256=evidence_sha256,
        policy_sha256=digest,
        profile_sha256=profile_digest,
        finding_rules=findings,
        actions=actions,
        status=status,
        guidance_state=guidance_state,
    )
    guidance = {
        "schema_version": SCHEMA_VERSION,
        "guidance_id": guidance_id,
        "generated_at": utc_now(),
        "status": status,
        "guidance_state": guidance_state,
        "authority": authority,
        "session_id": _clean(snapshot.get("session_id")) or "unknown",
        "canonical_evidence": snapshot,
        "findings": findings,
        "triage": {
            "review_priority": severity,
            "urgency": "prompt_review" if severity in {"high", "critical"} else "routine_review",
            "semantics": "categorical_observed_evidence_policy_not_score_or_forecast",
            "finding_ids": [item["finding_id"] for item in findings],
        },
        "advisory_actions": actions,
        "non_authoritative_context": {
            "semantics": "Forecast and enrichment are display context only; they do not select findings, triage, actions, or guidance IDs.",
            "forecast": deepcopy(forecast_context) if isinstance(forecast_context, (dict, list)) else {},
            "enrichment": deepcopy(enrichment_context) if isinstance(enrichment_context, (dict, list)) else {},
        },
        "provenance": {
            "canonical_evidence_sha256": evidence_sha256,
            "policy": _policy_metadata(document, digest, policy_source, policy_status, policy_errors),
            "asset_profile": _profile_metadata(profile_document, profile_digest, asset_profile_source, asset_profile_status, profile_errors),
            "selection_authority": "deterministic_canonical_observed_evidence_only",
            "forecast_authority": "non_authoritative_context_only",
            "enrichment_authority": "non_authoritative_context_only",
        },
        "safety": {
            "automatic_execution": False,
            "manual_approval_required": True,
            "alerting_side_effect": False,
            "response_action_side_effect": False,
            "execution_integration": "not_implemented",
        },
        "compatibility": {
            "legacy_v1_v2_records_read_only": True,
            "historical_records_recomputed": False,
            "prediction_snapshot_embedding": "prohibited",
        },
    }
    validation_errors = validate_response_guidance_v3(guidance)
    if validation_errors:
        guidance["status"] = "unavailable"
        guidance["guidance_state"] = "validation_rejected"
        guidance["authority"] = "policy_unavailable"
        guidance["findings"] = []
        guidance["advisory_actions"] = []
        guidance["triage"] = {
            "review_priority": "info",
            "urgency": "routine_review",
            "semantics": "categorical_observed_evidence_policy_not_score_or_forecast",
            "finding_ids": [],
        }
        guidance["guidance_id"] = _guidance_identity(
            session_id=_clean(snapshot.get("session_id")) or "unknown",
            evidence_sha256=evidence_sha256,
            policy_sha256=digest,
            profile_sha256=profile_digest,
            finding_rules=[],
            actions=[],
            status="unavailable",
            guidance_state="validation_rejected",
        )
    guidance["validation"] = {"status": "valid" if not validation_errors else "rejected", "errors": validation_errors}
    return guidance


def build_response_guidance_v3_from_paths(
    observed_behavior: Any,
    *,
    policy_path: str = "",
    asset_profile_path: str = "",
    session_context: Optional[Dict[str, Any]] = None,
    forecast_context: Any = None,
    enrichment_context: Any = None,
) -> Dict[str, Any]:
    """Load exact configuration files and evaluate canonical observed evidence."""

    loaded_policy = load_response_guidance_policy(policy_path)
    loaded_profile = load_response_guidance_asset_profile(asset_profile_path)
    return build_response_guidance_v3(
        observed_behavior,
        policy=loaded_policy["document"],
        policy_sha256=loaded_policy["sha256"],
        policy_source=loaded_policy["source"],
        policy_status=loaded_policy["status"],
        policy_validation_errors=loaded_policy["validation_errors"],
        asset_profile=loaded_profile["document"],
        asset_profile_sha256=loaded_profile["sha256"],
        asset_profile_source=loaded_profile["source"],
        asset_profile_status=loaded_profile["status"],
        asset_profile_validation_errors=loaded_profile["validation_errors"],
        session_context=session_context,
        forecast_context=forecast_context,
        enrichment_context=enrichment_context,
    )


def build_response_guidance_v3_from_session(
    session_payload: Dict[str, Any],
    *,
    policy_path: str = "",
    asset_profile_path: str = "",
    forecast_context: Any = None,
    enrichment_context: Any = None,
) -> Dict[str, Any]:
    """Build a current-policy reevaluation without using forecast for selection."""

    from production.reporting.threat_hypothesis import build_observed_behavior

    session = deepcopy(session_payload) if isinstance(session_payload, dict) else {}
    observed = build_observed_behavior([session], raw_events=session.get("raw_events") or [])
    return build_response_guidance_v3_from_paths(
        observed,
        policy_path=policy_path,
        asset_profile_path=asset_profile_path,
        session_context=session,
        forecast_context=forecast_context,
        enrichment_context=enrichment_context,
    )


def attach_non_authoritative_guidance_context(
    guidance: Dict[str, Any],
    *,
    forecast_context: Any = None,
    enrichment_context: Any = None,
) -> Dict[str, Any]:
    """Attach display context without changing selection, validation, or ID."""

    updated = deepcopy(guidance) if isinstance(guidance, dict) else {}
    if updated.get("schema_version") != SCHEMA_VERSION:
        return updated
    updated["non_authoritative_context"] = {
        "semantics": "Forecast and enrichment are display context only; they do not select findings, triage, actions, or guidance IDs.",
        "forecast": deepcopy(forecast_context) if isinstance(forecast_context, (dict, list)) else {},
        "enrichment": deepcopy(enrichment_context) if isinstance(enrichment_context, (dict, list)) else {},
    }
    return updated


def read_legacy_response_guidance(record: Any) -> Dict[str, Any]:
    """Expose v1/v2 historical records without promoting legacy actions.

    This is deliberately a display-only adapter.  It never reconstructs or
    authorizes an action, so a historical legacy payload cannot bypass v3.
    """

    value = record if isinstance(record, dict) else {}
    schema = _clean(value.get("schema_version"))
    return {
        "schema_version": LEGACY_ADAPTER_SCHEMA_VERSION,
        "status": "legacy_read_only" if schema in {"smb_decision.v1", "response_guidance.v2"} else "not_available",
        "legacy_schema_version": schema,
        "legacy_guidance_id": _clean(value.get("guidance_id") or value.get("decision_id")),
        "advisory_actions": [],
        "semantics": "Historical v1/v2 data is retained without recomputation or action authorization. Reevaluate under response_guidance.v3 for current advisory tasks.",
    }
