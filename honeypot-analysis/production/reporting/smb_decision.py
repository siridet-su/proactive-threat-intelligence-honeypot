"""SMB-facing proactive CTI decision layer.

The realtime prediction engine produces technical hypotheses. This module turns
those hypotheses, observed session evidence, enrichment, and asset context into
plain-language action guidance for small businesses.

Important boundary: action mappings live in a versioned policy JSON file with
provenance and references. This module only performs generic evidence
extraction, condition matching, and template rendering.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from string import Formatter
from typing import Any, Dict, Iterable, List, Optional, Tuple

from production.classification.trust import is_trusted_classification_event
from production.policies.validate_smb_policy import (
    BEHAVIOR_FLAG_KEYS,
    ENRICHMENT_FLAG_KEYS,
    validate_action_policy,
    validate_asset_profile,
)
from production.utils.sensitive_data import redact_exception_for_log, redact_for_artifact
from production.utils.serialization import stable_id, utc_now


SCHEMA_VERSION = "smb_decision.v1"
DEFAULT_LIMITATIONS = [
    "Recommendations are generated from honeypot-observed behavior and configured trusted-source policy.",
    "They are not proof that a real production asset was compromised.",
    "Treat predicted next steps as likely/possible hypotheses, not certainty.",
]

RISK_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

CONFIDENCE_ORDER = {
    "low": 1,
    "possible": 2,
    "medium": 2,
    "likely": 3,
    "high": 3,
}

DEFAULT_AUTOMATION_SAFETY = {
    "level": "manual_approval_required",
    "safe_to_auto_execute": False,
    "requires_manual_approval": True,
    "rationale": "Operator must review business impact before changing production controls.",
}


class SafeTemplateDict(dict):
    def __missing__(self, key: str) -> str:
        return "-"


def _as_list(value: Any) -> List[Any]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return list(value)
    return [value]


def _clean_strings(values: Iterable[Any]) -> List[str]:
    result: List[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in result:
            result.append(text)
    return result


def _lower_set(values: Iterable[Any]) -> set[str]:
    return {str(value or "").strip().lower() for value in values if str(value or "").strip()}


def _load_json_file(path_text: str, default: Dict[str, Any]) -> Dict[str, Any]:
    if not path_text:
        return dict(default)
    path = Path(path_text)
    if not path.exists():
        return {
            **dict(default),
            "load_error": f"file not found: {path}",
            "source_path": str(path),
        }
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            **dict(default),
            "load_error": redact_exception_for_log(exc),
            "source_path": str(path),
        }
    if not isinstance(loaded, dict):
        return {
            **dict(default),
            "load_error": "JSON root must be an object",
            "source_path": str(path),
        }
    loaded.setdefault("source_path", str(path))
    return loaded


def _safe_validation_errors(values: Iterable[Any]) -> List[str]:
    redacted = redact_for_artifact([str(value or "") for value in values])
    if not isinstance(redacted, list):
        return ["policy validation failed"]
    return [str(value) for value in redacted[:50] if str(value).strip()]


def is_trusted_recommendation_action(value: Any) -> bool:
    """Return true only for a reviewed action emitted by the trusted policy engine."""

    if not isinstance(value, dict):
        return False
    provenance = value.get("provenance")
    if not isinstance(provenance, dict):
        return False
    policy = provenance.get("policy")
    rule = provenance.get("rule")
    action_template = provenance.get("action_template")
    return bool(
        value.get("approved_by_policy") is True
        and value.get("authority") == "trusted_policy_engine"
        and value.get("recommendation_tier") == "trusted_recommendation"
        and provenance.get("authority") == "trusted_policy_engine"
        and isinstance(policy, dict)
        and str(policy.get("policy_id") or "").strip()
        and str(policy.get("version") or "").strip()
        and isinstance(rule, dict)
        and rule.get("reviewed") is True
        and isinstance(action_template, dict)
        and action_template.get("reviewed") is True
    )


def is_trusted_recommendation_decision(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    validation = (value.get("trust") or {}).get("policy_validation")
    policy = (value.get("trust") or {}).get("policy")
    return bool(
        value.get("status") == "available"
        and value.get("authority") == "trusted_policy_engine"
        and isinstance(validation, dict)
        and validation.get("status") == "valid"
        and isinstance(policy, dict)
        and str(policy.get("policy_id") or "").strip()
        and str(policy.get("version") or "").strip()
    )


def is_trusted_recommendation_provenance(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    policy = value.get("policy")
    return bool(
        value.get("authority") == "trusted_policy_engine"
        and value.get("status") == "available"
        and isinstance(policy, dict)
        and str(policy.get("policy_id") or "").strip()
        and str(policy.get("version") or "").strip()
    )


def _runtime_action_policy(policy: Any, *, unavailable: bool = False) -> Dict[str, Any]:
    raw = dict(policy) if isinstance(policy, dict) else {}
    unavailable = unavailable or raw.get("policy_status") == "unavailable"
    errors: List[str] = []
    if raw.get("load_error"):
        errors.append(str(raw.get("load_error")))
    try:
        errors.extend(validate_action_policy(raw))
    except Exception as exc:
        errors.append(redact_exception_for_log(exc))
    if errors:
        return {
            "schema_version": "smb_action_policy.v1",
            "policy_status": "unavailable" if unavailable else "invalid",
            "load_error": "action policy unavailable" if unavailable else "action policy validation failed",
            "validation_errors": _safe_validation_errors(errors),
            "source_path": str(raw.get("source_path") or ""),
            "trusted_sources": {},
            "risk_rules": [],
            "goal_rules": [],
            "action_playbooks": [],
            "default_guidance": {"actions": []},
        }
    raw["policy_status"] = "valid"
    raw["validation_errors"] = []
    return raw


def _runtime_asset_profile(profile: Any, *, unavailable: bool = False) -> Dict[str, Any]:
    raw = dict(profile) if isinstance(profile, dict) else {}
    unavailable = unavailable or raw.get("profile_status") == "unavailable"
    errors: List[str] = []
    if raw.get("load_error"):
        errors.append(str(raw.get("load_error")))
    try:
        errors.extend(validate_asset_profile(raw))
    except Exception as exc:
        errors.append(redact_exception_for_log(exc))
    if errors:
        return {
            "schema_version": "smb_asset_profile.v1",
            "profile_status": "unavailable" if unavailable else "invalid",
            "load_error": "asset profile unavailable" if unavailable else "asset profile validation failed",
            "validation_errors": _safe_validation_errors(errors),
            "source_path": str(raw.get("source_path") or ""),
            "assets": [],
        }
    raw["profile_status"] = "valid"
    raw["validation_errors"] = []
    return raw


def load_asset_profile(path_text: str) -> Dict[str, Any]:
    if not path_text:
        return _runtime_asset_profile({}, unavailable=True)
    return _runtime_asset_profile(
        _load_json_file(path_text, {"schema_version": "smb_asset_profile.v1", "assets": []}),
        unavailable=not Path(path_text).exists(),
    )


def load_action_policy(path_text: str) -> Dict[str, Any]:
    if not path_text:
        return _runtime_action_policy({}, unavailable=True)
    return _runtime_action_policy(
        _load_json_file(path_text, {"schema_version": "smb_action_policy.v1", "action_playbooks": []}),
        unavailable=not Path(path_text).exists(),
    )


def _nested_get(payload: Dict[str, Any], dotted_key: str) -> Any:
    current: Any = payload
    for part in dotted_key.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _regex_find_all(pattern: str, text: str) -> List[str]:
    if not pattern:
        return []
    try:
        compiled = re.compile(pattern, re.IGNORECASE)
    except re.error:
        return []
    matches: List[str] = []
    for match in compiled.finditer(text):
        if match.groups():
            value = next((group for group in match.groups() if group), "")
        else:
            value = match.group(0)
        value = str(value or "").strip().strip("'\";,)")
        if value and value not in matches:
            matches.append(value)
    return matches


def _extract_policy_artifacts(commands: List[str], raw_events: List[Dict[str, Any]], policy: Dict[str, Any]) -> Dict[str, Any]:
    text = "\n".join(commands)
    artifact_patterns = policy.get("artifact_patterns") or {}
    artifacts: Dict[str, Any] = {}
    for name, pattern in artifact_patterns.items():
        if not isinstance(pattern, str):
            continue
        artifacts[str(name)] = _regex_find_all(pattern, text)

    urls = list(artifacts.get("download_urls") or [])
    paths = list(artifacts.get("download_paths") or [])
    hashes = list(artifacts.get("hashes") or [])
    for event in raw_events:
        if not isinstance(event, dict):
            continue
        for key in ("url", "destfile", "outfile", "shasum"):
            value = str(event.get(key) or "").strip()
            if not value:
                continue
            if key == "url" and value not in urls:
                urls.append(value)
            elif key in {"destfile", "outfile"} and value not in paths:
                paths.append(value)
            elif key == "shasum" and value not in hashes:
                hashes.append(value)
    artifacts.setdefault("download_urls", urls)
    artifacts.setdefault("download_paths", paths)
    artifacts.setdefault("hashes", hashes)
    return artifacts


def _prediction_payload(prediction_snapshot: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(prediction_snapshot, dict):
        return {}
    payload = prediction_snapshot.get("payload")
    if isinstance(payload, dict):
        return payload
    return prediction_snapshot


def _session_enrichment_tags(session_payload: Dict[str, Any]) -> List[str]:
    tags: List[Any] = []
    enrichment_status = session_payload.get("enrichment_status") or {}
    enrichment_context = session_payload.get("enrichment_context") or {}
    for source in (session_payload, enrichment_status, enrichment_context):
        if not isinstance(source, dict):
            continue
        for key in ("otx_tags", "infrastructure_tags", "abuse_tags", "shodan_tags", "censys_labels"):
            tags.extend(_as_list(source.get(key)))
    return _clean_strings(tags)


def _enrichment_context(session_payload: Dict[str, Any]) -> Dict[str, Any]:
    context: Dict[str, Any] = {}
    for source in (
        session_payload,
        session_payload.get("enrichment_status") or {},
        session_payload.get("enrichment_context") or {},
    ):
        if not isinstance(source, dict):
            continue
        for key, value in source.items():
            if value not in (None, "", []):
                context.setdefault(str(key), value)
    return context


def _canonical_recommendation_evidence(session_payload: Dict[str, Any]) -> Dict[str, Any]:
    """Build the same bounded evidence layers used by threat_hypothesis.v2."""

    try:
        from production.reporting.threat_hypothesis import (
            build_follow_on_hypothesis,
            build_observed_behavior,
            build_supported_assessment,
        )

        raw_events = [
            event for event in _as_list(session_payload.get("raw_events"))
            if isinstance(event, dict)
        ]
        observed = build_observed_behavior([session_payload], raw_events=raw_events)
        assessment = build_supported_assessment(observed)
        follow_on = build_follow_on_hypothesis(observed)
        claims = [
            claim
            for claim in (
                _as_list(assessment.get("possible_objectives"))
                + _as_list(follow_on.get("claims"))
            )
            if isinstance(claim, dict)
        ]
        return {
            "status": "available",
            "observed_behavior": observed,
            "supported_assessment": assessment,
            "follow_on_hypothesis": follow_on,
            "claims": claims,
        }
    except Exception as exc:
        return {
            "status": "unavailable",
            "error": redact_exception_for_log(exc),
            "observed_behavior": {},
            "supported_assessment": {},
            "follow_on_hypothesis": {},
            "claims": [],
        }


def _append_ref(index: Dict[str, List[str]], key: str, value: Any) -> None:
    ref = str(value or "").strip()
    if not ref:
        return
    bucket = index.setdefault(key, [])
    if ref not in bucket:
        bucket.append(ref)


def _canonical_feature_index(
    session_payload: Dict[str, Any],
    canonical: Dict[str, Any],
) -> Dict[str, Any]:
    observed = canonical.get("observed_behavior") or {}
    claims = [item for item in canonical.get("claims") or [] if isinstance(item, dict)]
    observations = [
        item for item in observed.get("ordered_command_observations") or []
        if isinstance(item, dict)
    ]
    candidates = [
        item for item in observed.get("trusted_attck_candidates") or []
        if isinstance(item, dict)
    ]
    event_evidence = [
        item for item in observed.get("cowrie_event_evidence") or []
        if isinstance(item, dict)
    ]
    connected_chains = [
        item for item in observed.get("connected_behavior_chains") or []
        if isinstance(item, dict)
    ]

    refs: Dict[str, List[str]] = {}
    action_types: set[str] = set()
    action_type_refs: Dict[str, List[str]] = {}
    outcome_counts = {
        "cowrie_reported_success": 0,
        "cowrie_reported_failure": 0,
        "outcome_unknown": 0,
        "legacy_outcome_unknown": 0,
    }
    for item in observations:
        evidence_id = item.get("evidence_id")
        _append_ref(refs, "commands", evidence_id)
        outcome = str(item.get("command_outcome") or "outcome_unknown")
        outcome_counts[outcome] = outcome_counts.get(outcome, 0) + 1
        for action_type in _clean_strings(item.get("action_types") or []):
            action_types.add(action_type)
            _append_ref(action_type_refs, action_type, evidence_id)

    for item in candidates:
        evidence_id = item.get("evidence_id")
        tactic = str(item.get("tactic") or "").strip().lower()
        ttp = str(item.get("technique_id") or "").strip().lower()
        if tactic:
            _append_ref(refs, f"tactic:{tactic}", evidence_id)
        if ttp:
            _append_ref(refs, f"ttp:{ttp}", evidence_id)

    claim_types: set[str] = set()
    supported_claim_types: set[str] = set()
    claim_refs: Dict[str, List[str]] = {}
    claim_limitations: Dict[str, List[str]] = {}
    for claim in claims:
        claim_type = str(claim.get("claim_type") or "").strip().lower()
        if not claim_type:
            continue
        claim_types.add(claim_type)
        if claim.get("evidence_status") == "supported":
            supported_claim_types.add(claim_type)
        for ref in claim.get("evidence_refs") or []:
            _append_ref(claim_refs, claim_type, ref)
        claim_limitations[claim_type] = _clean_strings(claim.get("limitations") or [])

    confirmed_transfer_refs: List[str] = []
    for item in event_evidence:
        if item.get("transfer_observed"):
            ref = str(item.get("evidence_id") or "").strip()
            if ref and ref not in confirmed_transfer_refs:
                confirmed_transfer_refs.append(ref)

    session_ref = stable_id(
        "session-evidence",
        {
            "session_id": session_payload.get("session_id") or "unknown",
            "command_refs": refs.get("commands") or [],
            "event_refs": [item.get("evidence_id") for item in event_evidence],
        },
    )
    refs["session"] = [session_ref]
    refs["confirmed_transfer"] = confirmed_transfer_refs
    for action_type, values in action_type_refs.items():
        refs[f"action_type:{action_type}"] = values
    for claim_type, values in claim_refs.items():
        refs[f"claim:{claim_type}"] = values

    return {
        "observed": observed,
        "claims": claims,
        "claim_types_l": claim_types,
        "supported_claim_types_l": supported_claim_types,
        "claim_limitations": claim_limitations,
        "action_types_l": action_types,
        "connected_chains": connected_chains,
        "event_evidence": event_evidence,
        "evidence_ref_index": refs,
        "outcome_counts": outcome_counts,
        "confirmed_transfer_refs": confirmed_transfer_refs,
        "session_evidence_ref": session_ref,
    }


def _float_value(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _match_asset(asset: Dict[str, Any], session_payload: Dict[str, Any]) -> bool:
    protocol = str(session_payload.get("protocol") or "").lower()
    dst_port = str(session_payload.get("dst_port") or "")
    sensor = str(session_payload.get("sensor") or session_payload.get("sensor_id") or "")
    protocols = _lower_set(asset.get("protocols") or [])
    ports = {str(port) for port in _as_list(asset.get("ports"))}
    sensors = {str(value) for value in _as_list(asset.get("sensor_ids")) if str(value)}
    if protocols and (not protocol or protocol not in protocols):
        return False
    if ports and (not dst_port or dst_port not in ports):
        return False
    if sensors and (not sensor or sensor not in sensors):
        return False
    return bool(protocols or ports or sensors)


def _matched_assets(session_payload: Dict[str, Any], asset_profile: Dict[str, Any]) -> List[Dict[str, Any]]:
    assets = [asset for asset in _as_list(asset_profile.get("assets")) if isinstance(asset, dict)]
    matched = [asset for asset in assets if _match_asset(asset, session_payload)]
    if matched:
        return matched
    fallback = [asset for asset in assets if asset.get("default_for_honeypot")]
    return fallback[:3]


def _features(
    session_payload: Dict[str, Any],
    prediction_snapshot: Optional[Dict[str, Any]],
    asset_profile: Dict[str, Any],
    action_policy: Dict[str, Any],
) -> Dict[str, Any]:
    prediction = _prediction_payload(prediction_snapshot)
    final_ranking = [item for item in _as_list(prediction.get("final_ranking")) if isinstance(item, dict)]
    top_prediction = final_ranking[0] if final_ranking else {}
    raw_events = [event for event in _as_list(session_payload.get("raw_events")) if isinstance(event, dict)]
    commands = _clean_strings(session_payload.get("commands") or [])
    assets = _matched_assets(session_payload, asset_profile)
    canonical = _canonical_recommendation_evidence(session_payload)
    canonical_index = _canonical_feature_index(session_payload, canonical)
    all_classification_events = [
        item for item in _as_list(session_payload.get("classification_events")) if isinstance(item, dict)
    ]
    classification_events = [
        item for item in all_classification_events
        if is_trusted_classification_event(item)
    ]
    canonical_candidates = [
        item
        for item in (canonical_index.get("observed") or {}).get("trusted_attck_candidates") or []
        if isinstance(item, dict)
    ]
    aggregate_tactics = [] if all_classification_events else _as_list(session_payload.get("tactics"))
    aggregate_ttps = [] if all_classification_events else _as_list(session_payload.get("ttps"))
    tactics = _clean_strings(
        aggregate_tactics
        + [item.get("tactic") for item in canonical_candidates if item.get("tactic")]
        + [item.get("tactic") for item in classification_events if item.get("tactic")]
    )
    ttps = _clean_strings(
        aggregate_ttps
        + [item.get("technique_id") for item in canonical_candidates if item.get("technique_id")]
        + [item.get("ttp") for item in classification_events if item.get("ttp")]
    )
    artifact_values = _extract_policy_artifacts(commands, raw_events, action_policy)
    enrichment_context = _enrichment_context(session_payload)
    risk_score = _float_value(enrichment_context.get("risk_score"), 0.0)
    total_reports = _float_value(enrichment_context.get("total_reports"), 0.0)
    vt_hit = bool(enrichment_context.get("vt_hit"))
    raw_enrichment_flags = {
        "is_tor_exit": bool(enrichment_context.get("is_tor_exit")),
        "is_vpn": bool(enrichment_context.get("is_vpn")),
        "has_high_reputation_risk": risk_score >= 75 or total_reports >= 25,
        "has_elevated_reputation_risk": risk_score >= 25 or total_reports >= 5,
        "has_vt_hit": vt_hit,
        "has_malware_family": bool(enrichment_context.get("vt_malware_family")),
        "has_open_ports": bool(enrichment_context.get("open_ports")),
    }
    enrichment_flags = {
        key: bool(raw_enrichment_flags.get(key)) for key in ENRICHMENT_FLAG_KEYS
    }
    usernames = _clean_strings(
        [session_payload.get("login_username")]
        + [event.get("username") for event in raw_events if event.get("username")]
    )
    action_types = canonical_index.get("action_types_l") or set()
    claim_types = canonical_index.get("claim_types_l") or set()
    has_transfer_attempt = "transfer_attempt" in action_types
    has_execution_attempt = bool(
        action_types.intersection({"execution_attempt", "shell_pipe_consumer"})
    )
    has_confirmed_transfer = bool(canonical_index.get("confirmed_transfer_refs"))
    if canonical.get("status") != "available":
        command_text = "\n".join(commands)
        has_transfer_attempt = bool(re.search(
            r"\b(?:curl|wget|tftp|ftp)\b[^\n]*(?:https?://|ftp://)",
            command_text,
            re.IGNORECASE,
        ))
        has_confirmed_transfer = any(
            event.get("eventid") in {
                "cowrie.session.file_download",
                "cowrie.session.file_upload",
            }
            for event in raw_events
        )
        has_execution_attempt = bool(re.search(
            r"(?:^|[;&|]\s*)(?:sh|bash|python\d*|perl)\s+(?:/tmp|/var/tmp|/dev/shm)/\S+|"
            r"(?:^|[;&|]\s*)(?:\./|/tmp/|/var/tmp/|/dev/shm/)\S+",
            command_text,
            re.IGNORECASE,
        ))
    raw_behavior_flags = {
        "has_commands": bool(commands),
        "has_login_success": bool(session_payload.get("login_success")),
        "has_downloader": has_transfer_attempt,
        "has_transfer_attempt": has_transfer_attempt,
        "has_confirmed_transfer": has_confirmed_transfer,
        "has_execution_attempt": has_execution_attempt,
        "has_connected_behavior_chain": bool(canonical_index.get("connected_chains")),
        "has_persistence_attempt": "possible_continued_access_preparation" in claim_types,
        "has_cleanup_attempt": "possible_trace_removal" in claim_types,
        "has_credential_access_candidate": "possible_credential_access_preparation" in claim_types,
        "has_credential_paths": bool(artifact_values.get("credential_paths")),
        "has_hashes": bool(artifact_values.get("hashes")),
    }
    behavior_flags = {key: bool(raw_behavior_flags.get(key)) for key in BEHAVIOR_FLAG_KEYS}
    for tactic in tactics:
        behavior_flags[f"has_tactic_{str(tactic).lower()}"] = True
    return {
        "session_id": str(session_payload.get("session_id") or "unknown"),
        "src_ip": str(session_payload.get("src_ip") or "unknown"),
        "sensor": str(session_payload.get("sensor") or session_payload.get("sensor_id") or ""),
        "commands": commands,
        "raw_events": raw_events,
        "command_count": len(commands),
        "tactics": tactics,
        "ttps": ttps,
        "tactics_l": _lower_set(tactics),
        "ttps_l": _lower_set(ttps),
        "predicted_tactics_l": _lower_set([item.get("tactic") for item in final_ranking if item.get("tactic")]),
        "top_prediction": top_prediction,
        "top_predicted_tactic": str(top_prediction.get("tactic") or ""),
        "top_prediction_confidence": str(top_prediction.get("confidence") or ""),
        "top_prediction_score": top_prediction.get("score", ""),
        "trust_status": prediction.get("trust_status") or {},
        "classification_quality": prediction.get("classification_quality") or {},
        "agreement": prediction.get("agreement") or {},
        "canonical_evidence": canonical,
        "canonical_evidence_status": canonical.get("status") or "unavailable",
        "claim_types_l": canonical_index.get("claim_types_l") or set(),
        "supported_claim_types_l": canonical_index.get("supported_claim_types_l") or set(),
        "claim_limitations": canonical_index.get("claim_limitations") or {},
        "action_types_l": canonical_index.get("action_types_l") or set(),
        "connected_chains": canonical_index.get("connected_chains") or [],
        "event_evidence": canonical_index.get("event_evidence") or [],
        "evidence_ref_index": canonical_index.get("evidence_ref_index") or {},
        "outcome_counts": canonical_index.get("outcome_counts") or {},
        "session_evidence_ref": canonical_index.get("session_evidence_ref") or "",
        "assets": assets,
        "asset_categories_l": _lower_set(asset.get("service_category") for asset in assets),
        "asset_criticalities_l": _lower_set(asset.get("criticality") for asset in assets),
        "internet_exposed_asset": any(bool(asset.get("internet_exposed")) for asset in assets),
        "asset_names": _clean_strings(asset.get("display_name") or asset.get("asset_id") for asset in assets),
        "behavior_flags": behavior_flags,
        "enrichment_context": enrichment_context,
        "enrichment_flags": enrichment_flags,
        "risk_score": risk_score,
        "total_reports": total_reports,
        "enrichment_tags_l": _lower_set(_session_enrichment_tags(session_payload)),
        "artifacts": artifact_values,
        "usernames": usernames,
    }


def _condition_matches(
    condition: Dict[str, Any],
    features: Dict[str, Any],
) -> Tuple[bool, List[str], List[str], List[str]]:
    evidence: List[str] = []
    evidence_refs: List[str] = []
    evidence_scopes: List[str] = []
    tactics = features["tactics_l"]
    ttps = features["ttps_l"]
    predicted_tactics = features["predicted_tactics_l"]
    flags = features["behavior_flags"]
    enrichment_flags = features["enrichment_flags"]
    commands_text = "\n".join(features["commands"])
    ref_index = features.get("evidence_ref_index") or {}

    def add_refs(key: str, scope: str = "observed_behavior") -> None:
        for ref in ref_index.get(key) or []:
            if ref not in evidence_refs:
                evidence_refs.append(ref)
        if scope and scope not in evidence_scopes:
            evidence_scopes.append(scope)

    def no_match() -> Tuple[bool, List[str], List[str], List[str]]:
        return False, [], [], []

    all_tactics = _lower_set(condition.get("all_tactics") or [])
    if all_tactics and not all_tactics.issubset(tactics):
        return no_match()
    if all_tactics:
        evidence.append(f"observed tactics include {', '.join(sorted(all_tactics))}")
        for tactic in all_tactics:
            add_refs(f"tactic:{tactic}")

    any_tactics = _lower_set(condition.get("any_tactics") or [])
    if any_tactics and not tactics.intersection(any_tactics):
        return no_match()
    if any_tactics:
        matched_tactics = tactics.intersection(any_tactics)
        evidence.append(f"observed tactic matched {', '.join(sorted(matched_tactics))}")
        for tactic in matched_tactics:
            add_refs(f"tactic:{tactic}")

    all_ttps = _lower_set(condition.get("all_ttps") or [])
    if all_ttps and not all_ttps.issubset(ttps):
        return no_match()
    if all_ttps:
        evidence.append(f"observed techniques include {', '.join(sorted(all_ttps))}")
        for ttp in all_ttps:
            add_refs(f"ttp:{ttp}")

    any_ttps = _lower_set(condition.get("any_ttps") or [])
    if any_ttps and not ttps.intersection(any_ttps):
        return no_match()
    if any_ttps:
        matched_ttps = ttps.intersection(any_ttps)
        evidence.append(f"observed technique matched {', '.join(sorted(matched_ttps))}")
        for ttp in matched_ttps:
            add_refs(f"ttp:{ttp}")

    all_claim_types = _lower_set(condition.get("all_claim_types") or [])
    if all_claim_types and not all_claim_types.issubset(features["claim_types_l"]):
        return no_match()
    if all_claim_types:
        evidence.append(f"canonical claims include {', '.join(sorted(all_claim_types))}")
        for claim_type in all_claim_types:
            add_refs(f"claim:{claim_type}")

    any_claim_types = _lower_set(condition.get("any_claim_types") or [])
    matched_claim_types = features["claim_types_l"].intersection(any_claim_types)
    if any_claim_types and not matched_claim_types:
        return no_match()
    if matched_claim_types:
        evidence.append(f"canonical claim matched {', '.join(sorted(matched_claim_types))}")
        for claim_type in matched_claim_types:
            add_refs(f"claim:{claim_type}")

    any_action_types = _lower_set(condition.get("any_action_types") or [])
    matched_action_types = features["action_types_l"].intersection(any_action_types)
    if any_action_types and not matched_action_types:
        return no_match()
    if matched_action_types:
        evidence.append(f"observed action type matched {', '.join(sorted(matched_action_types))}")
        for action_type in matched_action_types:
            add_refs(f"action_type:{action_type}")

    any_predicted = _lower_set(condition.get("any_predicted_tactics") or [])
    if any_predicted and not predicted_tactics.intersection(any_predicted):
        return no_match()
    if any_predicted:
        evidence.append(f"realtime prediction includes {', '.join(sorted(predicted_tactics.intersection(any_predicted)))}")
        prediction_ref = str((features.get("top_prediction") or {}).get("snapshot_id") or "").strip()
        if prediction_ref:
            evidence_refs.append(prediction_ref)
        if "model_prediction" not in evidence_scopes:
            evidence_scopes.append("model_prediction")

    required_flags = _clean_strings(condition.get("required_flags") or [])
    missing_flags = [flag for flag in required_flags if not flags.get(flag)]
    if missing_flags:
        return no_match()
    if required_flags:
        evidence.append(f"session flags matched {', '.join(required_flags)}")
        for flag in required_flags:
            if flag == "has_confirmed_transfer":
                add_refs("confirmed_transfer")
            elif flag == "has_transfer_attempt" or flag == "has_downloader":
                add_refs("action_type:transfer_attempt")
            elif flag == "has_execution_attempt":
                add_refs("action_type:execution_attempt")
                add_refs("action_type:shell_pipe_consumer")
            elif flag == "has_commands":
                add_refs("commands")
            elif flag == "has_login_success":
                add_refs("session")
            elif flag == "has_persistence_attempt":
                add_refs("claim:possible_continued_access_preparation")
            elif flag == "has_cleanup_attempt":
                add_refs("claim:possible_trace_removal")
            elif flag == "has_credential_access_candidate":
                add_refs("claim:possible_credential_access_preparation")

    absent_flags = _clean_strings(condition.get("absent_flags") or [])
    present_absent = [flag for flag in absent_flags if flags.get(flag)]
    if present_absent:
        return no_match()

    asset_categories = _lower_set(condition.get("any_asset_categories") or [])
    if asset_categories and not features["asset_categories_l"].intersection(asset_categories):
        return no_match()
    if asset_categories:
        evidence.append(f"asset category matched {', '.join(sorted(features['asset_categories_l'].intersection(asset_categories)))}")
        if "configured_asset_context" not in evidence_scopes:
            evidence_scopes.append("configured_asset_context")

    if "internet_exposed_asset" in condition:
        expected_exposure = condition.get("internet_exposed_asset")
        if features["internet_exposed_asset"] is not expected_exposure:
            return no_match()
        exposure_label = "internet-exposed" if expected_exposure else "not internet-exposed"
        evidence.append(f"matched asset is marked {exposure_label}")
        if "configured_asset_context" not in evidence_scopes:
            evidence_scopes.append("configured_asset_context")

    enrichment_tags = _lower_set(condition.get("any_enrichment_tags") or [])
    if enrichment_tags and not features["enrichment_tags_l"].intersection(enrichment_tags):
        return no_match()
    if enrichment_tags:
        evidence.append(f"enrichment tag matched {', '.join(sorted(features['enrichment_tags_l'].intersection(enrichment_tags)))}")
        if "contextual_intelligence" not in evidence_scopes:
            evidence_scopes.append("contextual_intelligence")

    min_command_count = condition.get("min_command_count")
    if min_command_count is not None:
        try:
            if int(features["command_count"]) < int(min_command_count):
                return no_match()
            evidence.append(f"command count >= {int(min_command_count)}")
            add_refs("commands")
        except (TypeError, ValueError):
            return no_match()

    max_command_count = condition.get("max_command_count")
    if max_command_count is not None:
        try:
            if int(features["command_count"]) > int(max_command_count):
                return no_match()
            evidence.append(f"command count <= {int(max_command_count)}")
        except (TypeError, ValueError):
            return no_match()

    required_enrichment_flags = _clean_strings(condition.get("required_enrichment_flags") or [])
    missing_enrichment_flags = [flag for flag in required_enrichment_flags if not enrichment_flags.get(flag)]
    if missing_enrichment_flags:
        return no_match()
    if required_enrichment_flags:
        evidence.append(f"enrichment context matched {', '.join(required_enrichment_flags)}")
        if "contextual_intelligence" not in evidence_scopes:
            evidence_scopes.append("contextual_intelligence")

    min_risk_score = condition.get("min_reputation_risk_score")
    if min_risk_score is not None:
        try:
            if float(features["risk_score"]) < float(min_risk_score):
                return no_match()
            evidence.append(f"reputation risk score >= {float(min_risk_score):.0f}")
            if "contextual_intelligence" not in evidence_scopes:
                evidence_scopes.append("contextual_intelligence")
        except (TypeError, ValueError):
            return no_match()

    regexes = _clean_strings(condition.get("any_command_regex") or [])
    if regexes:
        matched = []
        for pattern in regexes:
            try:
                if re.search(pattern, commands_text, re.IGNORECASE):
                    matched.append(pattern)
            except re.error:
                continue
        if not matched:
            return no_match()
        evidence.append(f"command evidence matched {len(matched)} policy pattern(s)")
        add_refs("commands")

    if not evidence_refs:
        add_refs("session", "session_context")
    return True, evidence, evidence_refs, evidence_scopes


def _render_template(text: str, context: Dict[str, Any]) -> str:
    values = SafeTemplateDict(context)
    for key, value in list(context.items()):
        if isinstance(value, list):
            values[key] = ", ".join(str(item) for item in value[:5]) if value else "-"
    try:
        return Formatter().vformat(str(text), (), values)
    except (KeyError, ValueError):
        return str(text)


def _template_context(features: Dict[str, Any]) -> Dict[str, Any]:
    artifacts = features.get("artifacts") or {}
    return {
        "session_id": features.get("session_id", "unknown"),
        "src_ip": features.get("src_ip", "unknown"),
        "sensor": features.get("sensor", ""),
        "asset_names": features.get("asset_names") or [],
        "commands": features.get("commands") or [],
        "command_count": features.get("command_count", 0),
        "tactics": features.get("tactics") or [],
        "ttps": features.get("ttps") or [],
        "top_predicted_tactic": features.get("top_predicted_tactic") or "-",
        "top_prediction_confidence": features.get("top_prediction_confidence") or "-",
        "credential_paths": artifacts.get("credential_paths") or [],
        "download_urls": artifacts.get("download_urls") or [],
        "download_paths": artifacts.get("download_paths") or [],
        "hashes": artifacts.get("hashes") or [],
        "usernames": features.get("usernames") or [],
        "enrichment_tags": sorted(features.get("enrichment_tags_l") or []),
        "risk_score": features.get("risk_score", 0),
        "total_reports": features.get("total_reports", 0),
        "vt_malware_family": features.get("enrichment_context", {}).get("vt_malware_family") or "-",
        "open_ports": features.get("enrichment_context", {}).get("open_ports") or [],
        "running_services": features.get("enrichment_context", {}).get("running_services") or [],
        "session_evidence_ref": features.get("session_evidence_ref") or "",
        "confirmed_transfer": bool(features.get("behavior_flags", {}).get("has_confirmed_transfer")),
        "outcome_counts": features.get("outcome_counts") or {},
    }


def _policy_metadata(policy: Dict[str, Any]) -> Dict[str, Any]:
    return {
        key: policy.get(key)
        for key in ("schema_version", "policy_id", "version", "updated_at", "owner", "source_path")
        if policy.get(key)
    }


def _entry_provenance(entry: Dict[str, Any]) -> Dict[str, Any]:
    provenance = entry.get("provenance") if isinstance(entry, dict) else {}
    return dict(provenance) if isinstance(provenance, dict) else {}


def _normalise_severity(value: Any, default: str = "medium") -> str:
    text = str(value or default).strip().lower()
    return text if text in RISK_ORDER else default


def _normalise_confidence(value: Any, default: str = "medium") -> str:
    text = str(value or default).strip().lower()
    return text if text in CONFIDENCE_ORDER else default


def _automation_safety(rule: Dict[str, Any], action: Dict[str, Any]) -> Dict[str, Any]:
    raw = action.get("automation_safety")
    if not isinstance(raw, dict):
        raw = rule.get("automation_safety")
    if not isinstance(raw, dict):
        raw = DEFAULT_AUTOMATION_SAFETY
    safety = {**DEFAULT_AUTOMATION_SAFETY, **raw}
    safety["safe_to_auto_execute"] = bool(safety.get("safe_to_auto_execute"))
    safety["requires_manual_approval"] = bool(
        safety.get("requires_manual_approval", not safety["safe_to_auto_execute"])
    )
    if not str(safety.get("level") or "").strip():
        safety["level"] = (
            "automation_allowed" if safety["safe_to_auto_execute"]
            else "manual_approval_required"
        )
    return safety


def _build_action_payload(
    *,
    rule: Dict[str, Any],
    action_item: Dict[str, Any],
    evidence: List[str],
    evidence_refs: List[str],
    evidence_scopes: List[str],
    context: Dict[str, Any],
    action_policy: Dict[str, Any],
    default_rule_id: str = "",
    default_playbook: str = "",
    recommendation_tier: str = "trusted_recommendation",
) -> Dict[str, Any]:
    rendered_evidence = list(evidence or [])
    if not rendered_evidence:
        why_text = _render_template(action_item.get("why") or rule.get("why") or "", context)
        if why_text:
            rendered_evidence.append(why_text)
        else:
            rendered_evidence.append("matched trusted policy default guidance")
    safety = _automation_safety(rule, action_item)
    authority = (
        "policy_default_guidance"
        if recommendation_tier == "default_guidance"
        else "trusted_policy_engine"
    )
    visibility_limitations = _clean_strings(
        _as_list(rule.get("visibility_limitations"))
        + _as_list(action_item.get("visibility_limitations"))
        + [
            "Cowrie evidence describes activity inside a simulated SSH environment, not a real production compromise.",
            "Validate the recommendation against real-host or network telemetry before taking disruptive action.",
        ]
    )
    return {
        "action_id": action_item.get("action_id") or stable_id(
            "smbaction",
            {"rule": rule.get("rule_id") or default_rule_id, "action": action_item},
        ),
        "priority": int(action_item.get("priority") or rule.get("priority") or 50),
        "action": _render_template(action_item.get("action") or action_item.get("text") or "", context),
        "why": _render_template(action_item.get("why") or rule.get("why") or "", context),
        "rule_id": rule.get("rule_id") or default_rule_id,
        "playbook": rule.get("title") or default_playbook,
        "severity": _normalise_severity(action_item.get("severity") or rule.get("severity")),
        "confidence": _normalise_confidence(action_item.get("confidence") or rule.get("confidence")),
        "evidence": rendered_evidence,
        "evidence_refs": _clean_strings(evidence_refs or [context.get("session_evidence_ref")]),
        "evidence_scope": _clean_strings(evidence_scopes or ["session_context"]),
        "visibility_limitations": visibility_limitations,
        "source_type": rule.get("source_type") or action_item.get("source_type") or "",
        "references": _rule_references(rule or action_item, action_policy),
        "automation_safety": safety,
        "requires_manual_approval": bool(safety.get("requires_manual_approval")),
        "recommendation_tier": recommendation_tier,
        "authority": authority,
        "approved_by_policy": True,
        "provenance": {
            "authority": authority,
            "policy": _policy_metadata(action_policy),
            "rule": _entry_provenance(rule),
            "action_template": _entry_provenance(action_item),
        },
    }


def _action_contract_errors(action: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    for key in ("action_id", "action", "why", "rule_id", "source_type", "severity", "confidence"):
        if not str(action.get(key) or "").strip():
            errors.append(f"missing {key}")
    if action.get("severity") not in RISK_ORDER:
        errors.append("invalid severity")
    if action.get("confidence") not in CONFIDENCE_ORDER:
        errors.append("invalid confidence")
    if not action.get("references"):
        errors.append("missing references")
    if not action.get("evidence"):
        errors.append("missing evidence")
    if not action.get("evidence_refs"):
        errors.append("missing evidence_refs")
    if not action.get("visibility_limitations"):
        errors.append("missing visibility_limitations")
    safety = action.get("automation_safety")
    if not isinstance(safety, dict):
        errors.append("missing automation_safety")
    else:
        if "safe_to_auto_execute" not in safety:
            errors.append("automation_safety missing safe_to_auto_execute")
        if "requires_manual_approval" not in safety:
            errors.append("automation_safety missing requires_manual_approval")
        if not str(safety.get("level") or "").strip():
            errors.append("automation_safety missing level")
    tier = str(action.get("recommendation_tier") or "trusted_recommendation")
    expected_authority = (
        "policy_default_guidance"
        if tier == "default_guidance"
        else "trusted_policy_engine"
    )
    if tier not in {"trusted_recommendation", "default_guidance"}:
        errors.append("invalid recommendation_tier")
    if action.get("authority") != expected_authority:
        errors.append("invalid authority")
    if action.get("approved_by_policy") is not True:
        errors.append("not policy approved")
    provenance = action.get("provenance")
    if not isinstance(provenance, dict):
        errors.append("missing provenance")
    else:
        if provenance.get("authority") != expected_authority:
            errors.append("invalid provenance authority")
        if not isinstance(provenance.get("policy"), dict) or not provenance["policy"].get("policy_id"):
            errors.append("missing policy provenance")
        if not isinstance(provenance.get("rule"), dict) or not provenance["rule"].get("method"):
            errors.append("missing rule provenance")
        if not isinstance(provenance.get("action_template"), dict) or not provenance["action_template"].get("method"):
            errors.append("missing action template provenance")
    return errors


def _asset_metadata(asset_profile: Dict[str, Any]) -> Dict[str, Any]:
    return {
        key: asset_profile.get(key)
        for key in ("schema_version", "profile_id", "version", "updated_at", "owner", "source_path")
        if asset_profile.get(key)
    }


def _rule_references(rule: Dict[str, Any], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    trusted_sources = policy.get("trusted_sources") or {}
    references: List[Dict[str, Any]] = []
    for ref in _as_list(rule.get("references")):
        if isinstance(ref, dict):
            references.append(ref)
        elif isinstance(ref, str):
            source = trusted_sources.get(ref)
            if isinstance(source, dict):
                references.append({"source_id": ref, **source})
            else:
                references.append({"source_id": ref, "url": ref})
    return references


def _attack_technique_url(ttp: str) -> str:
    text = str(ttp or "").strip().upper()
    return f"https://attack.mitre.org/techniques/{text.replace('.', '/')}/" if text else ""


def _mitre_reference_guidance(features: Dict[str, Any], mitre_db: Any = None) -> List[Dict[str, Any]]:
    """Return trusted MITRE reference guidance for observed TTPs.

    This is deliberately separated from `immediate_actions`. Curated SMB
    playbooks remain the operator-action authority; MITRE mitigations provide
    broad reference guidance for techniques not yet covered by a playbook.
    """

    if mitre_db is None:
        return []
    guidance: List[Dict[str, Any]] = []
    seen = set()
    for ttp in _clean_strings(features.get("ttps") or []):
        technique = str(ttp or "").strip().upper()
        if not technique or technique in seen:
            continue
        seen.add(technique)
        try:
            name = mitre_db.get_name(technique)
            mitigations = list(mitre_db.get_mitigations(technique) or [])
        except Exception:
            continue
        if not mitigations:
            continue
        guidance.append(
            {
                "guidance_id": stable_id("mitreref", {"ttp": technique, "mitigations": mitigations[:5]}),
                "technique": technique,
                "technique_name": name or technique,
                "source_type": "mitre_attack_stix_reference",
                "authority": "trusted_external_reference",
                "approved_by_policy": False,
                "automation_safety": DEFAULT_AUTOMATION_SAFETY,
                "requires_manual_approval": True,
                "confidence": "reference",
                "mitigations": mitigations[:5],
                "reason": (
                    "MITRE ATT&CK lists these mitigations for the observed technique. "
                    "They are broad reference guidance, not a curated SMB playbook action."
                ),
                "evidence": [f"observed technique {technique} in session evidence"],
                "references": [
                    {
                        "source_id": f"mitre-{technique.lower()}",
                        "name": f"MITRE ATT&CK {technique} {name or technique}",
                        "type": "attack_technique",
                        "url": _attack_technique_url(technique),
                    }
                ],
                "provenance": {
                    "authority": "trusted_external_reference",
                    "source": "MITRE ATT&CK STIX/cache via MitreAttackDB.get_mitigations",
                },
            }
        )
    return guidance


def build_smb_decision(
    session_payload: Dict[str, Any],
    prediction_snapshot: Optional[Dict[str, Any]] = None,
    report_recommendations: Optional[Dict[str, Any]] = None,
    asset_profile: Optional[Dict[str, Any]] = None,
    action_policy: Optional[Dict[str, Any]] = None,
    mitre_db: Any = None,
) -> Dict[str, Any]:
    """Build a small-business friendly proactive CTI decision object."""
    session_payload = session_payload if isinstance(session_payload, dict) else {}
    asset_profile = _runtime_asset_profile(asset_profile)
    action_policy = _runtime_action_policy(action_policy)
    policy_valid = action_policy.get("policy_status") == "valid"
    features = _features(session_payload, prediction_snapshot, asset_profile, action_policy)
    context = _template_context(features)
    matched_actions: List[Dict[str, Any]] = []
    matched_goals: List[Dict[str, Any]] = []
    matched_risks: List[Dict[str, Any]] = []

    for rule in _as_list(action_policy.get("risk_rules")):
        if not isinstance(rule, dict) or rule.get("enabled") is False:
            continue
        matched, evidence, evidence_refs, evidence_scopes = _condition_matches(
            rule.get("applies_when") or {}, features
        )
        if not matched:
            continue
        severity = str(rule.get("severity") or "low").lower()
        matched_risks.append(
            {
                "rule_id": rule.get("rule_id") or "",
                "severity": severity,
                "reason": _render_template(rule.get("reason") or "", context),
                "evidence": evidence,
                "evidence_refs": evidence_refs,
                "evidence_scope": evidence_scopes,
                "source_type": rule.get("source_type") or "",
                "references": _rule_references(rule, action_policy),
                "provenance": {
                    "authority": "trusted_policy_engine",
                    "policy": _policy_metadata(action_policy),
                    "rule": _entry_provenance(rule),
                },
            }
        )

    for rule in _as_list(action_policy.get("goal_rules")):
        if not isinstance(rule, dict) or rule.get("enabled") is False:
            continue
        matched, evidence, evidence_refs, evidence_scopes = _condition_matches(
            rule.get("applies_when") or {}, features
        )
        if not matched:
            continue
        matched_goals.append(
            {
                "rule_id": rule.get("rule_id") or "",
                "likely_goal": _render_template(rule.get("likely_goal") or "", context),
                "confidence": rule.get("confidence") or "possible",
                "evidence": evidence,
                "evidence_refs": evidence_refs,
                "evidence_scope": evidence_scopes,
                "source_type": rule.get("source_type") or "",
                "references": _rule_references(rule, action_policy),
                "provenance": {
                    "authority": "trusted_policy_engine",
                    "policy": _policy_metadata(action_policy),
                    "rule": _entry_provenance(rule),
                },
            }
        )

    for rule in _as_list(action_policy.get("action_playbooks")):
        if not isinstance(rule, dict) or rule.get("enabled") is False:
            continue
        matched, evidence, evidence_refs, evidence_scopes = _condition_matches(
            rule.get("applies_when") or {}, features
        )
        if not matched:
            continue
        for action in _as_list(rule.get("actions")):
            if isinstance(action, str):
                action_item = {"action": action}
            elif isinstance(action, dict):
                action_item = dict(action)
            else:
                continue
            matched_actions.append(
                _build_action_payload(
                    rule=rule,
                    action_item=action_item,
                    evidence=evidence,
                    evidence_refs=evidence_refs,
                    evidence_scopes=evidence_scopes,
                    context=context,
                    action_policy=action_policy,
                )
            )

    default_actions: List[Dict[str, Any]] = []
    if not matched_actions and policy_valid:
        for action in _as_list((action_policy.get("default_guidance") or {}).get("actions")):
            if isinstance(action, dict):
                default_actions.append(
                    _build_action_payload(
                        rule={
                            **action,
                            "rule_id": "default_guidance",
                            "title": "Default guidance",
                            "source_type": action.get("source_type") or "trusted_control_guidance",
                        },
                        action_item=action,
                        evidence=[],
                        evidence_refs=[features.get("session_evidence_ref") or ""],
                        evidence_scopes=["policy_default"],
                        context=context,
                        action_policy=action_policy,
                        default_rule_id="default_guidance",
                        default_playbook="Default guidance",
                        recommendation_tier="default_guidance",
                    )
                )

    rejected_actions: List[Dict[str, Any]] = []
    valid_actions: List[Dict[str, Any]] = []
    valid_default_actions: List[Dict[str, Any]] = []
    for candidates, output in (
        (matched_actions, valid_actions),
        (default_actions, valid_default_actions),
    ):
        seen_action_ids: set[str] = set()
        for action in candidates:
            errors = _action_contract_errors(action)
            action_id = str(action.get("action_id") or "").strip()
            if action_id in seen_action_ids:
                errors.append("duplicate action_id in runtime result")
            elif action_id:
                seen_action_ids.add(action_id)
            if errors:
                rejected_actions.append(
                    {
                        "action_id": action_id,
                        "rule_id": action.get("rule_id") or "",
                        "recommendation_tier": action.get("recommendation_tier") or "audit_only_candidate",
                        "errors": sorted(set(errors)),
                    }
                )
                continue
            output.append(action)

    matched_actions = sorted(
        valid_actions,
        key=lambda item: (
            int(item.get("priority", 50)),
            str(item.get("action_id") or ""),
            str(item.get("action") or ""),
            str(item.get("rule_id") or ""),
        ),
    )
    default_actions = sorted(
        valid_default_actions,
        key=lambda item: (
            int(item.get("priority", 50)),
            str(item.get("action_id") or ""),
            str(item.get("action") or ""),
        ),
    )
    matched_risks.sort(
        key=lambda item: (
            -RISK_ORDER.get(str(item.get("severity") or "low"), 1),
            str(item.get("rule_id") or ""),
            str(item.get("reason") or ""),
        )
    )
    matched_goals.sort(
        key=lambda item: (
            -CONFIDENCE_ORDER.get(str(item.get("confidence") or "low"), 1),
            str(item.get("rule_id") or ""),
            str(item.get("likely_goal") or ""),
        )
    )
    strongest_risk = max(matched_risks, key=lambda item: RISK_ORDER.get(item.get("severity", "low"), 1), default=None)
    if not strongest_risk:
        strongest_risk = {
            "severity": "low" if features["command_count"] else "info",
            "reason": "No higher-risk playbook matched the current session evidence.",
            "evidence": [],
            "evidence_refs": [features.get("session_evidence_ref") or ""],
            "evidence_scope": ["policy_default"],
            "references": [],
            "source_type": "policy_default",
        }
    likely_goal = matched_goals[0] if matched_goals else {
        "likely_goal": "No specific attacker goal inferred from the current trusted-source playbooks.",
        "confidence": "low",
        "evidence": [],
        "evidence_refs": [features.get("session_evidence_ref") or ""],
        "evidence_scope": ["policy_default"],
        "references": [],
        "source_type": "policy_default",
    }
    prediction = features.get("top_prediction") or {}
    reference_guidance = _mitre_reference_guidance(features, mitre_db)
    audit_only_candidates = list(rejected_actions)
    if not policy_valid:
        audit_only_candidates.insert(
            0,
            {
                "candidate_type": "action_policy",
                "recommendation_tier": "audit_only_candidate",
                "errors": list(action_policy.get("validation_errors") or []),
            },
        )
    decision = {
        "schema_version": SCHEMA_VERSION,
        "decision_id": stable_id(
            "smbdecision",
            {
                "session_id": features["session_id"],
                "prediction": prediction,
                "actions": [item.get("action_id") for item in matched_actions[:8]],
                "policy": _policy_metadata(action_policy),
            },
        ),
        "generated_at": utc_now(),
        "status": "available" if policy_valid else "unavailable",
        "authority": "trusted_policy_engine" if policy_valid else "policy_unavailable",
        "session_id": features["session_id"],
        "mode": "smb_proactive_threat_intelligence",
        "risk": strongest_risk,
        "likely_goal": likely_goal,
        "likely_next_step": {
            "tactic": prediction.get("tactic") or "",
            "confidence": prediction.get("confidence") or "",
            "score": prediction.get("score", ""),
            "reasons": prediction.get("reasons") or [],
            "source": "realtime_prediction" if prediction else "not_available",
        },
        "immediate_actions": matched_actions[:8],
        "default_guidance": default_actions[:8],
        "reference_guidance": reference_guidance[:8],
        "rejected_actions": rejected_actions,
        "recommendation_tiers": {
            "trusted_recommendations": matched_actions[:8],
            "default_guidance": default_actions[:8],
            "audit_only_candidates": audit_only_candidates[:20],
        },
        "matched_risk_rules": matched_risks,
        "matched_goal_rules": matched_goals,
        "asset_context": {
            "profile": _asset_metadata(asset_profile),
            "matched_assets": [
                {
                    "asset_id": asset.get("asset_id"),
                    "display_name": asset.get("display_name"),
                    "service_category": asset.get("service_category"),
                    "criticality": asset.get("criticality"),
                    "internet_exposed": bool(asset.get("internet_exposed")),
                    "owner": asset.get("owner"),
                }
                for asset in features["assets"]
            ],
        },
        "evidence": {
            "src_ip": features["src_ip"],
            "sensor": features["sensor"],
            "command_count": features["command_count"],
            "observed_tactics": features["tactics"],
            "observed_ttps": features["ttps"],
            "artifact_summary": {
                key: values[:10] if isinstance(values, list) else values
                for key, values in (features.get("artifacts") or {}).items()
                if values
            },
            "enrichment_summary": {
                "risk_score": features.get("risk_score", 0),
                "total_reports": features.get("total_reports", 0),
                "tags": sorted(features.get("enrichment_tags_l") or [])[:12],
                "flags": {
                    key: value
                    for key, value in (features.get("enrichment_flags") or {}).items()
                    if value
                },
            },
            "canonical_summary": {
                "status": features.get("canonical_evidence_status") or "unavailable",
                "claim_types": sorted(features.get("claim_types_l") or []),
                "supported_claim_types": sorted(features.get("supported_claim_types_l") or []),
                "observed_action_types": sorted(features.get("action_types_l") or []),
                "connected_behavior_chain_count": len(features.get("connected_chains") or []),
                "command_outcome_counts": features.get("outcome_counts") or {},
                "confirmed_cowrie_transfer": bool(
                    features.get("behavior_flags", {}).get("has_confirmed_transfer")
                ),
                "evidence_semantics": (
                    "Canonical threat_hypothesis.v2 evidence is used for recommendation matching; "
                    "context and prediction remain separate from observed behavior."
                ),
            },
        },
        "trust": {
            "policy": _policy_metadata(action_policy),
            "policy_load_error": action_policy.get("load_error", ""),
            "policy_validation": {
                "status": action_policy.get("policy_status") or "invalid",
                "errors": list(action_policy.get("validation_errors") or []),
            },
            "asset_profile_validation": {
                "status": asset_profile.get("profile_status") or "invalid",
                "errors": list(asset_profile.get("validation_errors") or []),
            },
            "trusted_source_count": len(action_policy.get("trusted_sources") or {}),
            "reference_guidance_source": (
                "MITRE ATT&CK STIX/cache" if reference_guidance else ""
            ),
            "classification_quality": features.get("classification_quality") or {},
            "prediction_trust_status": features.get("trust_status") or {},
            "agreement": features.get("agreement") or {},
            "limitations": list(action_policy.get("limitations") or DEFAULT_LIMITATIONS),
        },
        "report_recommendations": report_recommendations or {},
    }
    return decision


def build_smb_decision_from_paths(
    session_payload: Dict[str, Any],
    prediction_snapshot: Optional[Dict[str, Any]] = None,
    report_recommendations: Optional[Dict[str, Any]] = None,
    asset_profile_path: str = "",
    action_policy_path: str = "",
    mitre_attack_path: str = "",
) -> Dict[str, Any]:
    mitre_db = None
    if mitre_attack_path:
        try:
            from production.enrichment.mitre_attack_loader import load_mitre_attack_db

            mitre_db = load_mitre_attack_db(cache_path=mitre_attack_path, force_refresh=False, silent=True)
        except Exception:
            mitre_db = None
    return build_smb_decision(
        session_payload=session_payload,
        prediction_snapshot=prediction_snapshot,
        report_recommendations=report_recommendations,
        asset_profile=load_asset_profile(asset_profile_path),
        action_policy=load_action_policy(action_policy_path),
        mitre_db=mitre_db,
    )
