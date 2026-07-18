"""Feature extraction for real-time session prediction.

This module turns the mutable SessionState object into a stable dictionary that
scorers can consume without knowing about the monitor implementation.
"""

from __future__ import annotations

import math
import re
from typing import Any, Dict, Iterable, List, Optional

from production.enrichment.enrichment_cache import iter_session_observables
from production.classification.trust import is_trusted_classification_event
from production.utils.sensitive_data import redact_for_session_state
from production.utils.serialization import session_to_payload, stable_id
from production.correlation.session_ttp_knowledge import main_ttp_id
from production.correlation.campaign_clustering import build_session_fingerprint
from production.prediction.behavior_regime import command_timing_events


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return list(value)
    return [value]


def _clean_strings(values: Iterable[Any]) -> List[str]:
    cleaned: List[str] = []
    for value in values:
        text = str(value or "").strip()
        if text:
            cleaned.append(text)
    return cleaned


def _unique_ordered(values: Iterable[Any]) -> List[str]:
    seen = set()
    ordered: List[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        ordered.append(text)
    return ordered


def _is_prediction_eligible_correlation(item: Dict[str, Any]) -> bool:
    """Reject legacy ``apply_to_prediction`` flags without review/evaluation proof."""

    if not item.get("apply_to_prediction", False):
        return False
    eligibility = item.get("prediction_eligibility") or {}
    return bool(
        eligibility.get("effective")
        and eligibility.get("reviewed")
        and eligibility.get("evaluated")
    )


CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def _extract_cves(commands: Iterable[str]) -> List[str]:
    found: List[str] = []
    for command in commands:
        found.extend(match.group(0).upper() for match in CVE_PATTERN.finditer(str(command or "")))
    return _unique_ordered(found)


def _payload_from_session(session: Any) -> Dict[str, Any]:
    payload = dict(session) if isinstance(session, dict) else session_to_payload(session)
    redacted = redact_for_session_state(payload)
    if not isinstance(redacted, dict):
        raise TypeError("session feature input redaction must return an object")
    return redacted


def _confidence_stats(confidences: List[float], has_classifications: bool) -> Dict[str, Any]:
    """Return conservative confidence features for downstream scorers.

    Older stored sessions may not have confidence fields. In that case we avoid
    damping to zero, but explicitly mark the confidence as unavailable.
    """
    clean = [min(max(float(value), 0.0), 1.0) for value in confidences]
    if not clean:
        fallback = 1.0 if has_classifications else 0.0
        return {
            "classification_confidence_available": False,
            "classification_confidence_count": 0,
            "classification_average_confidence": fallback,
            "classification_min_confidence": fallback,
            "classification_chain_confidence_geomean": fallback,
        }
    safe = [max(value, 0.0001) for value in clean]
    geomean = math.exp(sum(math.log(value) for value in safe) / len(safe))
    return {
        "classification_confidence_available": True,
        "classification_confidence_count": len(clean),
        "classification_average_confidence": round(sum(clean) / len(clean), 4),
        "classification_min_confidence": round(min(clean), 4),
        "classification_chain_confidence_geomean": round(geomean, 4),
    }


def _event_time(payload: Dict[str, Any], current_event: Optional[Dict[str, Any]]) -> str:
    if current_event and current_event.get("timestamp"):
        return str(current_event["timestamp"])
    raw_events = _as_list(payload.get("raw_events"))
    for event in reversed(raw_events):
        if isinstance(event, dict) and event.get("timestamp"):
            return str(event["timestamp"])
    return str(payload.get("updated_at") or payload.get("start_time") or "")


def _enrichment_context(payload: Dict[str, Any], enrichment_status: Dict[str, Any]) -> Dict[str, Any]:
    fields = (
        "asn",
        "geo",
        "country",
        "isp",
        "risk_score",
        "vt_hit",
        "vt_detection_ratio",
        "vt_malware_family",
        "is_tor_exit",
        "is_vpn",
        "host_type",
        "infrastructure_tags",
        "otx_tags",
        "abuse_tags",
        "abuseipdb_categories",
        "shodan_tags",
        "censys_labels",
        "open_ports",
        "running_services",
        "provider_status",
        "total_reports",
        "raw_otx_pulse",
        "shodan_hostnames",
        "shodan_cpes",
        "shodan_vulns",
        "censys_api",
        "shodan_api",
    )
    context = {
        "status": enrichment_status.get("status", ""),
        "source": enrichment_status.get("source", ""),
        "providers": enrichment_status.get("providers", []),
    }
    for field in fields:
        if field in payload and payload.get(field) not in (None, "", []):
            context[field] = payload.get(field)
    return context


def build_session_features(
    session: Any,
    current_event: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a restart-safe feature dictionary for scorer plugins.

    The output is intentionally plain JSON-like data. It should be safe to store
    in prediction snapshots and replay later during backtesting.
    """
    payload = _payload_from_session(session)
    safe_current_event: Optional[Dict[str, Any]] = None
    if current_event is not None:
        redacted_current_event = redact_for_session_state(current_event)
        if isinstance(redacted_current_event, dict):
            safe_current_event = redacted_current_event
    commands = _clean_strings(_as_list(payload.get("commands")))
    raw_events = [event for event in _as_list(payload.get("raw_events")) if isinstance(event, dict)]
    classification_events = [
        dict(event)
        for event in _as_list(payload.get("classification_events"))
        if isinstance(event, dict)
    ]
    trusted_classification_events = [
        event for event in classification_events if is_trusted_classification_event(event)
    ]
    session_ttp_correlations = [
        dict(item)
        for item in _as_list(payload.get("session_ttp_correlations"))
        if isinstance(item, dict)
    ]

    classified_ttps = [
        main_ttp_id(event.get("ttp"))
        for event in trusted_classification_events
        if event.get("ttp") and event.get("ttp") != "unknown"
    ]
    classified_tactics = [
        event.get("tactic")
        for event in trusted_classification_events
        if event.get("tactic") and event.get("tactic") != "unknown"
    ]

    payload_ttps = [main_ttp_id(item) for item in _as_list(payload.get("ttps"))]
    payload_tactics = _as_list(payload.get("tactics"))
    if classification_events:
        observed_ttps = _unique_ordered(classified_ttps)
        observed_tactics = _unique_ordered(classified_tactics)
    else:
        observed_ttps = _unique_ordered(payload_ttps)
        observed_tactics = _unique_ordered(payload_tactics)
    correlated_ttps = [
        main_ttp_id(item.get("ttp"))
        for item in session_ttp_correlations
        if item.get("ttp") and _is_prediction_eligible_correlation(item)
    ]
    correlated_tactics = [
        item.get("tactic")
        for item in session_ttp_correlations
        if item.get("tactic") and _is_prediction_eligible_correlation(item)
    ]
    observed_ttps = _unique_ordered(observed_ttps + correlated_ttps)
    observed_tactics = _unique_ordered(observed_tactics + correlated_tactics)
    ttp_sequence = _clean_strings(classified_ttps) or ([] if classification_events else observed_ttps)
    correlated_subtechniques = [
        item.get("source_subtechnique") or item.get("source_ttp")
        for item in session_ttp_correlations
        if item.get("source_subtechnique")
    ]
    tactic_sequence = _clean_strings(classified_tactics) or ([] if classification_events else observed_tactics)

    source_counts: Dict[str, int] = {}
    confidences: List[float] = []
    for event in classification_events:
        source = str(event.get("source") or "unknown")
        source_counts[source] = source_counts.get(source, 0) + 1
        try:
            confidence = event.get("confidence")
            if is_trusted_classification_event(event) and confidence is not None and confidence != "":
                confidences.append(float(confidence))
        except (TypeError, ValueError):
            pass
    confidence_features = _confidence_stats(confidences, bool(trusted_classification_events))

    command_text = "\n".join(commands).lower()
    tactics_set = set(observed_tactics)
    enrichment_status = payload.get("enrichment_status") or {}
    if not isinstance(enrichment_status, dict):
        enrichment_status = {"status": str(enrichment_status)}
    sigma_hits = _clean_strings(_as_list(payload.get("sigma_hits")))
    kev_matches = [
        dict(item)
        for item in _as_list(payload.get("kev_matches"))
        if isinstance(item, dict)
    ]

    observables = [
        {"type": kind, "value": value}
        for kind, value in iter_session_observables(payload)
    ]
    try:
        session_fingerprint = build_session_fingerprint(payload)
    except Exception:
        session_fingerprint = {}
    timing_events = command_timing_events(
        raw_events,
        classification_events,
        safe_current_event,
    )

    features: Dict[str, Any] = {
        "schema_version": "session_features.v1",
        "session_id": str(payload.get("session_id") or "unknown"),
        "src_ip": str(payload.get("src_ip") or "unknown"),
        "sensor": str(payload.get("sensor") or ""),
        "status": "closed" if payload.get("is_ended") else str(payload.get("status") or "active"),
        "session_outcome": str(payload.get("session_outcome") or ""),
        "is_ended": bool(payload.get("is_ended")),
        "start_time": str(payload.get("start_time") or ""),
        "event_time": _event_time(payload, safe_current_event),
        "duration": payload.get("duration"),
        "login_success": bool(payload.get("login_success")),
        "login_attempts": int(payload.get("login_attempts") or 0),
        "commands": commands,
        "command_count": len(commands),
        "raw_event_count": len(raw_events),
        "current_eventid": str((safe_current_event or {}).get("eventid") or ""),
        "observed_ttps": observed_ttps,
        "ttp_sequence": ttp_sequence,
        "last_ttp": ttp_sequence[-1] if ttp_sequence else "",
        "observed_tactics": observed_tactics,
        "tactic_sequence": tactic_sequence,
        "last_tactic": tactic_sequence[-1] if tactic_sequence else "",
        "classification_events": classification_events,
        "session_ttp_correlations": session_ttp_correlations,
        "session_ttp_correlation_summary": payload.get("session_ttp_correlation_summary") or {},
        "session_evidence_graph_summary": payload.get("session_evidence_graph_summary") or ((payload.get("session_evidence_graph") or {}).get("summary") if isinstance(payload.get("session_evidence_graph"), dict) else {}),
        "correlated_ttps": _unique_ordered(correlated_ttps),
        "correlated_subtechniques": _unique_ordered(correlated_subtechniques),
        "correlated_tactics": _unique_ordered(correlated_tactics),
        "classification_source_counts": source_counts,
        **confidence_features,
        "sigma_hits": sigma_hits,
        "sigma_hit_count": len(sigma_hits),
        "observed_cves": _extract_cves(commands),
        "kev_matches": kev_matches,
        "kev_match_count": len(kev_matches),
        "enrichment_status": enrichment_status,
        "enrichment_context": _enrichment_context(payload, enrichment_status),
        "observables": observables,
        "session_fingerprint": session_fingerprint,
        "command_timing_events": timing_events,
        "behavior_flags": {
            "has_downloader": any(token in command_text for token in ("wget ", "curl ", "tftp ", "ftp ")),
            "has_execution": "execution" in tactics_set or "chmod +x" in command_text or "bash " in command_text,
            "has_credential_access": "credential-access" in tactics_set,
            "has_defense_evasion": "defense-evasion" in tactics_set or "history -c" in command_text,
            "has_command_and_control": "command-and-control" in tactics_set,
            "has_collection": "collection" in tactics_set,
            "has_exfiltration": "exfiltration" in tactics_set or "curl -d" in command_text or "scp " in command_text,
        },
    }
    features["features_hash"] = stable_id("features", features)
    return features
