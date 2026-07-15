"""Production report artifacts: JSON, STIX 2.1, and PDF/Markdown fallback."""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from production.utils.config import ProductionConfig
from production.utils.serialization import stable_json, utc_now


TI_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "my-ti-pipeline.local")


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in value)[:120] or "unknown"


def _stix_timestamp(value: str) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if not value:
        return now
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            parsed = datetime.strptime(value, fmt)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    return now


def _ioc_items(ioc_summary: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    for key in ("ips", "urls", "domains", "hashes", "ports"):
        for item in ioc_summary.get(key, []) or []:
            yield item


def _layer_items(report: Dict[str, Any], layer_name: str) -> List[Dict[str, Any]]:
    layers = report.get("threat_evidence_layers") or {}
    layer = layers.get(layer_name) if isinstance(layers, dict) else {}
    items = layer.get("items") if isinstance(layer, dict) else []
    return [item for item in items or [] if isinstance(item, dict)]


def _evidence_layer_summary_lines(report: Dict[str, Any]) -> List[str]:
    layers = report.get("threat_evidence_layers") or {}
    if not isinstance(layers, dict):
        return []
    summary = layers.get("summary") or {}
    if not isinstance(summary, dict):
        summary = {}
    return [
        f"Direct command TTPs: {summary.get('direct_command_ttp_count', 0)}",
        f"Session-correlated TTPs: {summary.get('session_correlated_ttp_count', 0)}",
        f"Prediction-only hypotheses: {summary.get('prediction_hypothesis_count', 0)}",
    ]


def _trusted_ttp_ids(report: Dict[str, Any], session_payload: Dict[str, Any]) -> List[str]:
    observed = report.get("observed_behavior") or {}
    candidates = observed.get("trusted_attck_candidates") if isinstance(observed, dict) else []
    if report.get("schema_version") == "threat_hypothesis.v2":
        return list(dict.fromkeys(
            str(item.get("technique_id") or "").strip()
            for item in candidates or []
            if isinstance(item, dict) and str(item.get("technique_id") or "").strip()
        ))
    return list(dict.fromkeys(
        str(value).strip()
        for value in (session_payload.get("ttps", []) or report.get("ttps", []) or [])
        if str(value).strip()
    ))


def write_json_report(report: Dict[str, Any], session_id: str, output_dir: Path) -> str:
    path = output_dir / f"{_safe_name(session_id)}_report.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return str(path)


def _stix_id(object_type: str, key: str) -> str:
    return f"{object_type}--{uuid.uuid5(TI_NAMESPACE, object_type + ':' + key)}"


def _append_stix_object(
    objects: List[Dict[str, Any]],
    report_obj: Dict[str, Any],
    obj: Dict[str, Any],
    seen_ids: set[str],
    *,
    reference_from_report: bool = True,
) -> None:
    object_id = str(obj.get("id") or "")
    if not object_id or object_id in seen_ids:
        return
    seen_ids.add(object_id)
    objects.append(obj)
    if reference_from_report and object_id not in report_obj["object_refs"]:
        report_obj["object_refs"].append(object_id)


def _trusted_recommendation_actions(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    candidates: List[Any] = []
    candidates.extend(report.get("recommended_actions_structured") or [])
    recommendations = report.get("recommendations")
    if isinstance(recommendations, dict):
        candidates.extend(recommendations.get("recommended_actions_structured") or [])
    hypothesis = report.get("threat_hypothesis")
    if isinstance(hypothesis, dict):
        candidates.extend(hypothesis.get("recommended_actions_structured") or [])

    actions: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for item in candidates:
        if not isinstance(item, dict):
            continue
        provenance = item.get("provenance") if isinstance(item.get("provenance"), dict) else {}
        authority = str(item.get("authority") or provenance.get("authority") or "").strip()
        if item.get("approved_by_policy") is not True:
            continue
        if authority and authority != "trusted_policy_engine":
            continue
        key = str(item.get("action_id") or item.get("rule_id") or item.get("action") or stable_json(item))
        if key in seen:
            continue
        seen.add(key)
        actions.append(item)
    return actions


def _external_references(raw_refs: Any) -> List[Dict[str, Any]]:
    refs: List[Dict[str, Any]] = []
    for ref in raw_refs or []:
        if not isinstance(ref, dict):
            continue
        name = str(ref.get("name") or ref.get("source_name") or ref.get("title") or "reference").strip()
        url = str(ref.get("url") or "").strip()
        external_id = str(ref.get("external_id") or ref.get("id") or "").strip()
        out = {"source_name": name}
        if url:
            out["url"] = url
        if external_id:
            out["external_id"] = external_id
        refs.append(out)
    return refs


def _extract_ttp_ids_from_action(action: Dict[str, Any]) -> List[str]:
    values: List[str] = []
    for key in ("ttp", "ttps", "technique", "techniques", "mitre_techniques"):
        raw = action.get(key)
        if isinstance(raw, list):
            values.extend(str(item) for item in raw)
        elif raw:
            values.append(str(raw))
    for ref in action.get("references") or []:
        if not isinstance(ref, dict):
            continue
        values.extend(str(ref.get(key) or "") for key in ("external_id", "id", "name", "url"))
    values.extend(str(item) for item in action.get("evidence") or [])
    joined = "\n".join(values)
    ttps = []
    for match in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", joined, flags=re.IGNORECASE):
        main = match.upper().split(".", 1)[0]
        if main not in ttps:
            ttps.append(main)
    return ttps


def _sco_for_ioc(ioc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    ioc_type = str(ioc.get("type") or "").strip().lower()
    value = str(ioc.get("value") or "").strip()
    if not value:
        return None
    if ioc_type in {"ipv4", "ipv6"}:
        object_type = "ipv6-addr" if ioc_type == "ipv6" else "ipv4-addr"
        return {
            "type": object_type,
            "spec_version": "2.1",
            "id": _stix_id(object_type, value),
            "value": value,
        }
    if ioc_type == "domain":
        return {
            "type": "domain-name",
            "spec_version": "2.1",
            "id": _stix_id("domain-name", value),
            "value": value,
        }
    if ioc_type == "url":
        return {
            "type": "url",
            "spec_version": "2.1",
            "id": _stix_id("url", value),
            "value": value,
        }
    if ioc_type in {"sha256", "sha1", "md5"}:
        return {
            "type": "file",
            "spec_version": "2.1",
            "id": _stix_id("file", ioc_type + ":" + value),
            "hashes": {ioc_type.upper(): value},
        }
    return None


def _build_identity(now: str, session_payload: Dict[str, Any]) -> Dict[str, Any]:
    sensor = str(session_payload.get("sensor") or session_payload.get("sensor_id") or "honeypot").strip()
    identity_id = _stix_id("identity", "honeypot-sensor:" + sensor)
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now,
        "modified": now,
        "name": f"Honeypot sensor {sensor}",
        "identity_class": "system",
    }


def build_stix_bundle(report: Dict[str, Any], session_payload: Dict[str, Any]) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    session_id = session_payload.get("session_id", "unknown")
    objects: List[Dict[str, Any]] = []
    seen_ids: set[str] = set()
    report_obj = {
        "type": "report",
        "spec_version": "2.1",
        "id": f"report--{uuid.uuid4()}",
        "created": now,
        "modified": now,
        "name": f"Automated Threat Intelligence Report - {session_id}",
        "published": now,
        "report_types": ["threat-actor-activity"],
        "object_refs": [],
    }

    ttp_obj_map = {}
    for tid in sorted(set(_trusted_ttp_ids(report, session_payload))):
        ap_id = f"attack-pattern--{uuid.uuid5(TI_NAMESPACE, 'attack-pattern:' + tid)}"
        attack_pattern = {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": ap_id,
            "created": now,
            "modified": now,
            "name": tid,
            "external_references": [{
                "source_name": "mitre-attack",
                "external_id": tid,
                "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}",
            }],
        }
        ttp_obj_map[tid] = attack_pattern
        _append_stix_object(objects, report_obj, attack_pattern, seen_ids)

    legacy_actor_matches = [] if report.get("schema_version") == "threat_hypothesis.v2" else report.get("actor_matches", []) or []
    for actor in legacy_actor_matches:
        actor_name = actor.get("actor", "Unknown")
        actor_id = f"threat-actor--{uuid.uuid5(TI_NAMESPACE, 'actor:' + actor_name)}"
        actor_obj = {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": actor_id,
            "created": now,
            "modified": now,
            "name": actor_name,
            "confidence": int(actor.get("score", 0)),
            "labels": ["apt"],
            "description": f"Matched: {', '.join(actor.get('matched_ttps', []))}",
            "x_honeypot_attribution_warning": "TTP overlap only; not confirmed named-actor attribution.",
        }
        _append_stix_object(objects, report_obj, actor_obj, seen_ids)
        for tid in actor.get("matched_ttps", []):
            if tid in ttp_obj_map:
                relationship_id = f"relationship--{uuid.uuid5(TI_NAMESPACE, 'rel:' + actor_id + ':' + ttp_obj_map[tid]['id'])}"
                _append_stix_object(objects, report_obj, {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": relationship_id,
                    "created": now,
                    "modified": now,
                    "relationship_type": "uses",
                    "source_ref": actor_id,
                    "target_ref": ttp_obj_map[tid]["id"],
                }, seen_ids, reference_from_report=False)

    ioc_summary = report.get("ioc_summary") or session_payload.get("ioc_summary") or {}
    indicator_ids: Dict[str, str] = {}
    sco_refs: List[str] = []
    for ioc in _ioc_items(ioc_summary):
        ioc_type = ioc.get("type", "")
        value = ioc.get("value", "")
        if not value:
            continue
        if ioc_type in {"ipv4", "ipv6"}:
            pattern = f"[ipv4-addr:value = '{value}']"
        elif ioc_type == "domain":
            pattern = f"[domain-name:value = '{value}']"
        elif ioc_type == "url":
            pattern = f"[url:value = '{value}']"
        elif ioc_type in {"sha256", "sha1", "md5"}:
            pattern = f"[file:hashes.'{ioc_type.upper()}' = '{value}']"
        else:
            continue
        indicator_id = f"indicator--{uuid.uuid5(TI_NAMESPACE, 'indicator:' + ioc_type + ':' + value)}"
        indicator_ids[f"{ioc_type}:{value}"] = indicator_id
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now,
            "modified": now,
            "name": value,
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": _stix_timestamp(ioc.get("first_seen", "")),
            "indicator_types": ["malicious-activity"],
        }
        _append_stix_object(objects, report_obj, indicator, seen_ids)
        sco = _sco_for_ioc(ioc)
        if sco:
            _append_stix_object(objects, report_obj, sco, seen_ids, reference_from_report=False)
            if sco["id"] not in sco_refs:
                sco_refs.append(sco["id"])

    src_ip = str(session_payload.get("src_ip") or "").strip()
    if src_ip and src_ip not in {"unknown", "-"}:
        src_ioc = {"type": "ipv6" if ":" in src_ip else "ipv4", "value": src_ip}
        sco = _sco_for_ioc(src_ioc)
        if sco:
            _append_stix_object(objects, report_obj, sco, seen_ids, reference_from_report=False)
            if sco["id"] not in sco_refs:
                sco_refs.append(sco["id"])

    identity = _build_identity(now, session_payload)
    has_sightings = bool(indicator_ids)
    has_campaign = bool((session_payload.get("campaign_summary") or report.get("campaign_context") or {}).get("campaign_id"))
    if has_sightings or has_campaign:
        _append_stix_object(objects, report_obj, identity, seen_ids)

    commands = [str(command) for command in session_payload.get("commands") or [] if str(command).strip()]
    if commands:
        command_sequence = {
            "type": "x-honeypot-command-sequence",
            "spec_version": "2.1",
            "id": _stix_id("x-honeypot-command-sequence", "session-commands:" + str(session_id)),
            "created": now,
            "modified": now,
            "x_honeypot_session_id": session_id,
            "x_honeypot_commands": commands[:50],
            "x_honeypot_command_count": len(commands),
        }
        _append_stix_object(objects, report_obj, command_sequence, seen_ids, reference_from_report=False)
        if command_sequence["id"] not in sco_refs:
            sco_refs.append(command_sequence["id"])
    if sco_refs or commands:
        observed_id = _stix_id("observed-data", "session-observed-data:" + str(session_id))
        first_observed = _stix_timestamp(str(session_payload.get("start_time") or report.get("created_at") or ""))
        last_observed = _stix_timestamp(str(session_payload.get("end_time") or session_payload.get("updated_at") or report.get("created_at") or ""))
        observed = {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": observed_id,
            "created": now,
            "modified": now,
            "first_observed": first_observed,
            "last_observed": last_observed,
            "number_observed": 1,
            "object_refs": sco_refs,
            "x_honeypot_session_id": session_id,
            "x_honeypot_commands": commands[:50],
            "x_honeypot_event_count": len(session_payload.get("raw_events") or []),
        }
        _append_stix_object(objects, report_obj, observed, seen_ids)

    for marker, indicator_id in sorted(indicator_ids.items()):
        sighting_id = _stix_id("sighting", "session-sighting:" + str(session_id) + ":" + marker)
        sighting = {
            "type": "sighting",
            "spec_version": "2.1",
            "id": sighting_id,
            "created": now,
            "modified": now,
            "sighting_of_ref": indicator_id,
            "where_sighted_refs": [identity["id"]],
            "count": 1,
            "first_seen": _stix_timestamp(str(session_payload.get("start_time") or "")),
            "last_seen": _stix_timestamp(str(session_payload.get("end_time") or session_payload.get("updated_at") or "")),
            "x_honeypot_session_id": session_id,
        }
        _append_stix_object(objects, report_obj, sighting, seen_ids)

    campaign_summary = session_payload.get("campaign_summary") or report.get("campaign_context") or {}
    if isinstance(campaign_summary, dict) and campaign_summary.get("campaign_id"):
        campaign_id_value = str(campaign_summary.get("campaign_id"))
        campaign_id = _stix_id("campaign", "honeypot-campaign:" + campaign_id_value)
        campaign = {
            "type": "campaign",
            "spec_version": "2.1",
            "id": campaign_id,
            "created": now,
            "modified": now,
            "name": f"Honeypot behavioral cluster {campaign_id_value}",
            "description": (
                "Local honeypot behavioral cluster based on observable and command-pattern "
                "similarity. This is not confirmed named-actor attribution."
            ),
            "first_seen": _stix_timestamp(str(campaign_summary.get("first_seen") or session_payload.get("start_time") or "")),
            "last_seen": _stix_timestamp(str(campaign_summary.get("last_seen") or session_payload.get("updated_at") or "")),
            "x_honeypot_campaign_id": campaign_id_value,
            "x_honeypot_matched_existing_campaign": bool(campaign_summary.get("matched_existing_campaign")),
            "x_honeypot_session_count": campaign_summary.get("campaign_session_count") or campaign_summary.get("session_count") or 0,
            "x_honeypot_max_confirmed_severity": campaign_summary.get("max_confirmed_severity") or "",
        }
        _append_stix_object(objects, report_obj, campaign, seen_ids)
        for tid, attack_pattern in ttp_obj_map.items():
            rel_id = _stix_id("relationship", "campaign-uses:" + campaign_id + ":" + attack_pattern["id"])
            _append_stix_object(objects, report_obj, {
                "type": "relationship",
                "spec_version": "2.1",
                "id": rel_id,
                "created": now,
                "modified": now,
                "relationship_type": "uses",
                "source_ref": campaign_id,
                "target_ref": attack_pattern["id"],
            }, seen_ids, reference_from_report=False)

    for action in _trusted_recommendation_actions(report):
        action_id_value = str(action.get("action_id") or action.get("rule_id") or action.get("action") or stable_json(action))
        coa_id = _stix_id("course-of-action", "policy-action:" + action_id_value)
        safety = action.get("automation_safety") if isinstance(action.get("automation_safety"), dict) else {}
        coa = {
            "type": "course-of-action",
            "spec_version": "2.1",
            "id": coa_id,
            "created": now,
            "modified": now,
            "name": str(action.get("action") or action_id_value),
            "description": str(action.get("why") or action.get("reason") or ""),
            "external_references": _external_references(action.get("references")),
            "x_honeypot_action_id": action.get("action_id") or "",
            "x_honeypot_rule_id": action.get("rule_id") or "",
            "x_honeypot_authority": "trusted_policy_engine",
            "x_honeypot_source_type": action.get("source_type") or "",
            "x_honeypot_severity": action.get("severity") or "",
            "x_honeypot_confidence": action.get("confidence") or "",
            "x_honeypot_evidence": action.get("evidence") or [],
            "x_honeypot_requires_manual_approval": bool(
                action.get("requires_manual_approval") or safety.get("requires_manual_approval")
            ),
            "x_honeypot_safe_to_auto_execute": bool(safety.get("safe_to_auto_execute")),
        }
        _append_stix_object(objects, report_obj, coa, seen_ids)
        for tid in _extract_ttp_ids_from_action(action):
            attack_pattern = ttp_obj_map.get(tid)
            if not attack_pattern:
                continue
            rel_id = _stix_id("relationship", "coa-mitigates:" + coa_id + ":" + attack_pattern["id"])
            _append_stix_object(objects, report_obj, {
                "type": "relationship",
                "spec_version": "2.1",
                "id": rel_id,
                "created": now,
                "modified": now,
                "relationship_type": "mitigates",
                "source_ref": coa_id,
                "target_ref": attack_pattern["id"],
            }, seen_ids, reference_from_report=False)

    summary_text = report.get("executive_summary") or report.get("summary") or ""
    if summary_text:
        note_id = f"note--{uuid.uuid4()}"
        note = {
            "type": "note",
            "spec_version": "2.1",
            "id": note_id,
            "created": now,
            "modified": now,
            "abstract": "Threat Hypothesis",
            "content": summary_text,
            "object_refs": report_obj["object_refs"][:1] or [report_obj["id"]],
            "authors": ["Honeypot Threat Hypothesis Engine"],
        }
        _append_stix_object(objects, report_obj, note, seen_ids)

    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": [report_obj] + objects}


def write_stix_bundle(report: Dict[str, Any], session_payload: Dict[str, Any], output_dir: Path) -> str:
    session_id = session_payload.get("session_id", report.get("session_id", "unknown"))
    path = output_dir / f"{_safe_name(session_id)}_threat_bundle.json"
    path.write_text(json.dumps(build_stix_bundle(report, session_payload), indent=2, sort_keys=True), encoding="utf-8")
    return str(path)


def write_markdown_report(report: Dict[str, Any], session_payload: Dict[str, Any], output_dir: Path) -> str:
    session_id = session_payload.get("session_id", report.get("session_id", "unknown"))
    ioc_summary = report.get("ioc_summary") or session_payload.get("ioc_summary") or {}
    lines = [
        "# Threat Intelligence Report",
        "",
        f"Generated: {utc_now()}",
        f"Session: {session_id}",
        f"Source IP: {session_payload.get('src_ip', 'unknown')}",
        "",
        "## Summary",
        str((report.get("presentation") or {}).get("summary") or report.get("executive_summary") or report.get("summary") or "No summary available."),
        "",
        "## TTPs",
    ]
    for tid in _trusted_ttp_ids(report, session_payload):
        lines.append(f"- {tid}")
    assessment = report.get("supported_assessment") or {}
    follow_on = report.get("follow_on_hypothesis") or {}
    if report.get("schema_version") == "threat_hypothesis.v2":
        lines.extend(["", "## Evidence-Grounded Assessment"])
        lines.append(str(assessment.get("behavior_summary") or "No trusted behavioral evidence."))
        objectives = assessment.get("possible_objectives") or []
        if objectives:
            for claim in objectives:
                lines.append(
                    f"- [{claim.get('evidence_status', 'insufficient_evidence')}] "
                    f"{claim.get('text', '')} (claim `{claim.get('claim_id', '')}`)"
                )
        else:
            lines.append("- No attacker objective inferred from the observed evidence.")
        lines.extend(["", "## Post-Session Follow-On Hypothesis"])
        if follow_on.get("abstained"):
            lines.append(f"- Abstained: {follow_on.get('abstention_reason', '')}")
        else:
            for claim in follow_on.get("claims") or []:
                lines.append(f"- [{claim.get('evidence_status', '')}] {claim.get('text', '')}")
    evidence_lines = _evidence_layer_summary_lines(report)
    if evidence_lines:
        lines.extend(["", "## Evidence Layers"])
        lines.append("Direct observations, session correlations, and predictions are separated to avoid mixing facts with hypotheses.")
        for line in evidence_lines:
            lines.append(f"- {line}")
        direct_items = _layer_items(report, "direct_command_ttps")
        if direct_items:
            lines.append("")
            lines.append("### Direct Command TTPs")
            for item in direct_items[:20]:
                confidence = item.get("confidence") or {}
                lines.append(
                    f"- {item.get('main_ttp', '')} | {item.get('tactic', '')} | "
                    f"sources={', '.join(item.get('sources') or [])} | "
                    f"avg_confidence={confidence.get('average', '-')}"
                )
        correlated_items = _layer_items(report, "session_correlated_ttps")
        if correlated_items:
            lines.append("")
            lines.append("### Session-Correlated TTPs")
            for item in correlated_items[:20]:
                lines.append(
                    f"- {item.get('main_ttp', '')} | {item.get('predicted_technique', {}).get('tactic', item.get('tactic', ''))} | "
                    f"source_type={item.get('source_type', '')} | confidence={item.get('confidence', '-')}"
                )
        prediction_items = _layer_items(report, "prediction_only_hypotheses")
        if prediction_items:
            lines.append("")
            lines.append("### Prediction-Only Hypotheses")
            for item in prediction_items[:10]:
                lines.append(
                    f"- {item.get('predicted_tactic', '')} | confidence={item.get('confidence', '-')} | "
                    f"source_types={', '.join(item.get('source_types') or [])}"
                )
    lines.extend(["", "## IoCs"])
    for item in _ioc_items(ioc_summary):
        lines.append(f"- {item.get('type')}: {item.get('value')} ({item.get('confidence', 'unknown')})")
    path = output_dir / f"{_safe_name(session_id)}_threat_report.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return str(path)


def write_pdf_report(report: Dict[str, Any], session_payload: Dict[str, Any], output_dir: Path) -> str:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError:
        return write_markdown_report(report, session_payload, output_dir)

    session_id = session_payload.get("session_id", report.get("session_id", "unknown"))
    path = output_dir / f"{_safe_name(session_id)}_threat_report.pdf"
    doc = SimpleDocTemplate(str(path), pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm, topMargin=2 * cm, bottomMargin=2 * cm)
    styles = getSampleStyleSheet()
    title = ParagraphStyle("TitleCustom", parent=styles["Title"], fontSize=20, textColor=colors.HexColor("#C0392B"), spaceAfter=4)
    h2 = ParagraphStyle("HeadingCustom", parent=styles["Heading2"], fontSize=13, textColor=colors.HexColor("#2C3E50"), spaceBefore=14, spaceAfter=4)
    body = ParagraphStyle("BodyCustom", parent=styles["Normal"], fontSize=10, leading=15, spaceAfter=3)
    meta = ParagraphStyle("MetaCustom", parent=styles["Normal"], fontSize=8, textColor=colors.grey)
    story = [
        Paragraph("Threat Intelligence Report", title),
        Paragraph(f"Generated: {utc_now()}", meta),
        HRFlowable(width="100%", thickness=2, color=colors.HexColor("#C0392B"), spaceAfter=12),
        Paragraph("Executive Summary", h2),
        Paragraph(str((report.get("presentation") or {}).get("summary") or report.get("executive_summary") or report.get("summary") or "No summary available."), body),
        Spacer(1, 8),
    ]

    ttp_rows = [["TTP ID", "Source"]]
    sources = session_payload.get("ttp_sources", {})
    for tid in _trusted_ttp_ids(report, session_payload):
        ttp_rows.append([tid, ", ".join(sources.get(tid, []))])
    if len(ttp_rows) > 1:
        table = Table(ttp_rows, colWidths=[4 * cm, 12 * cm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2C3E50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#DEE2E6")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        story.extend([Paragraph("Detected Techniques", h2), table, Spacer(1, 8)])

    evidence_lines = _evidence_layer_summary_lines(report)
    if evidence_lines:
        story.extend([
            Paragraph("Evidence Layers", h2),
            Paragraph("Direct command TTPs, session-correlated TTPs, and prediction-only hypotheses are separated so facts, correlations, and forecasts are not mixed.", body),
        ])
        layer_rows = [["Layer", "Count"]]
        for line in evidence_lines:
            label, _, value = line.partition(":")
            layer_rows.append([label, value.strip()])
        table = Table(layer_rows, colWidths=[8 * cm, 8 * cm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2C3E50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#DEE2E6")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        story.extend([table, Spacer(1, 8)])

    ioc_rows = [["Type", "Value", "Confidence"]]
    for item in _ioc_items(report.get("ioc_summary") or session_payload.get("ioc_summary") or {}):
        ioc_rows.append([item.get("type", ""), item.get("value", "")[:60], item.get("confidence", "")])
    if len(ioc_rows) > 1:
        table = Table(ioc_rows, colWidths=[3 * cm, 10 * cm, 3 * cm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2C3E50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#DEE2E6")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        story.extend([Paragraph("Indicators of Compromise", h2), table, Spacer(1, 8)])

    story.extend([
        Spacer(1, 20),
        HRFlowable(width="100%", thickness=1, color=colors.HexColor("#95A5A6")),
        Paragraph("CONFIDENTIAL - For authorised recipients only. Do not redistribute.", meta),
    ])
    doc.build(story)
    return str(path)


def attach_report_artifacts(report: Dict[str, Any], session_payload: Dict[str, Any], config: ProductionConfig) -> Dict[str, Any]:
    if not config.enable_artifacts:
        return report
    output_dir = Path(config.reports_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    artifacts: Dict[str, Any] = {}
    try:
        artifacts["json"] = write_json_report(report, session_payload.get("session_id", report.get("session_id", "unknown")), output_dir)
    except Exception as exc:
        artifacts["json_error"] = f"{type(exc).__name__}: {exc}"
    if config.enable_stix_export:
        try:
            artifacts["stix"] = write_stix_bundle(report, session_payload, output_dir)
        except Exception as exc:
            artifacts["stix_error"] = f"{type(exc).__name__}: {exc}"
    if config.enable_pdf_export:
        try:
            artifacts["pdf"] = write_pdf_report(report, session_payload, output_dir)
        except Exception as exc:
            artifacts["pdf_error"] = f"{type(exc).__name__}: {exc}"
    report["artifacts"] = artifacts
    return report
