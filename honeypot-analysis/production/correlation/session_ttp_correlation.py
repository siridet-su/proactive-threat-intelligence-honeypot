"""Session-level TTP correlation over command-level classifications.

Command classification answers "what did this command most likely do?"
Session correlation answers "what behavior is supported by the whole session?"

The rules are intentionally loaded from a versioned policy file. This module
contains the evaluator and validation helpers, not the authoritative mappings.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from production.classification.trust import is_trusted_classification_event
from production.utils.serialization import stable_id, utc_now
from production.correlation.session_evidence_graph import build_session_evidence_graph
from production.correlation.session_ttp_knowledge import (
    KNOWLEDGE_PACK_SCHEMA_VERSION,
    POLICY_SCHEMA_VERSION,
    load_correlation_knowledge,
    load_json_document,
    main_ttp_id,
    normalize_correlation_document,
)


SCHEMA_VERSION = "session_ttp_correlation.v1"

ALLOWED_SOURCE_TYPES = {
    "human_curated_attck_detection",
    "mitre_car_analytic",
    "sigma_detection_correlation",
    "operational_threshold",
    "mitre_attack_stix",
    "mitre_tie_generated_prior",
    "external_cowrie_seed",
    "generated_detection_correlation",
}

ALLOWED_EVIDENCE_TYPES = {
    "session_correlated_confirmed",
    "session_correlated_candidate",
    "sequence_correlation",
    "threshold_correlation",
    "external_dataset_correlation",
    "knowledge_pack_correlation",
}

ALLOWED_CONDITION_TYPES = {
    "classification_ttp",
    "classification_tactic",
    "command_regex",
    "eventid",
    "eventid_prefix",
    "min_event_count",
    "min_login_failures",
    "login_success",
    "ordered_tactics",
    "ordered_ttps",
    "evidence_flag",
    "min_graph_count",
}

EXTERNAL_REFERENCE_SOURCE_TYPES = {
    "mitre_attack_stix",
    "mitre_tie_generated_prior",
    "mitre_car_analytic",
    "sigma_detection_correlation",
    "generated_detection_correlation",
    "external_cowrie_seed",
}

INFLUENCE_CONSUMERS = ("report", "prediction", "campaign", "threat_hunt", "alert")


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _clean_text(value: Any) -> str:
    return str(value or "").strip()


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _clamp_confidence(value: Any, default: float = 0.0) -> float:
    return round(min(max(_safe_float(value, default), 0.0), 1.0), 4)


def _normalize_refs(references: Iterable[Any]) -> List[Dict[str, str]]:
    refs: List[Dict[str, str]] = []
    for ref in references or []:
        if isinstance(ref, dict):
            url = _clean_text(ref.get("url"))
            name = _clean_text(ref.get("name") or ref.get("source_id") or url)
            refs.append({k: v for k, v in {"name": name, "url": url}.items() if v})
            continue
        text = _clean_text(ref)
        if text:
            refs.append({"name": text, "url": text if text.startswith(("http://", "https://")) else ""})
    return refs


def load_policy(path: str | Path = "") -> Dict[str, Any]:
    """Load a correlation policy. Missing/empty path returns a disabled policy."""
    if not path:
        return {
            "schema_version": POLICY_SCHEMA_VERSION,
            "policy_id": "disabled",
            "version": "0",
            "policy": {"enabled": False, "rules": []},
        }
    return load_json_document(path)


def load_knowledge(policy_path: str | Path = "", knowledge_pack_paths: Any = None) -> Dict[str, Any]:
    return load_correlation_knowledge(str(policy_path or ""), knowledge_pack_paths)


def _policy_body(policy_document: Dict[str, Any]) -> Dict[str, Any]:
    body = policy_document.get("policy", policy_document)
    return body if isinstance(body, dict) else {}


class SessionEvidence:
    def __init__(self, session_payload: Dict[str, Any], evidence_graph: Dict[str, Any] | None = None) -> None:
        self.payload = session_payload
        self.graph = evidence_graph or build_session_evidence_graph(session_payload)
        self.commands = [
            _clean_text(command)
            for command in _as_list(session_payload.get("commands"))
            if _clean_text(command)
        ]
        self.classification_events = [
            dict(item)
            for item in _as_list(session_payload.get("classification_events"))
            if isinstance(item, dict)
        ]
        self.trusted_classification_events = [
            item for item in self.classification_events
            if is_trusted_classification_event(item)
        ]
        self.raw_events = [
            dict(item)
            for item in _as_list(session_payload.get("raw_events"))
            if isinstance(item, dict)
        ]
        self.classification_ttps = {
            main_ttp_id(item.get("ttp"))
            for item in self.trusted_classification_events
            if _clean_text(item.get("ttp"))
        }
        self.classification_tactics = {
            _clean_text(item.get("tactic"))
            for item in self.trusted_classification_events
            if _clean_text(item.get("tactic")) and _clean_text(item.get("tactic")) != "unknown"
        }
        self.eventids = [_clean_text(item.get("eventid")) for item in self.raw_events if _clean_text(item.get("eventid"))]
        self.login_failed_count = self.eventids.count("cowrie.login.failed")
        self.login_attempts = int(session_payload.get("login_attempts") or self.login_failed_count)

    def command_texts(self) -> List[str]:
        texts = list(self.commands)
        for event in self.trusted_classification_events:
            command = _clean_text(event.get("command"))
            if command:
                texts.append(command)
            original = _clean_text(event.get("original_command"))
            if original:
                texts.append(original)
        return texts

    def tactic_sequence(self) -> List[str]:
        sequence: List[str] = []
        for event in self.trusted_classification_events:
            tactic = _clean_text(event.get("tactic"))
            if tactic and tactic != "unknown":
                sequence.append(tactic)
        if not sequence and not self.classification_events:
            sequence = [
                _clean_text(item)
                for item in _as_list(self.payload.get("tactics"))
                if _clean_text(item)
            ]
        return sequence

    def ttp_sequence(self) -> List[str]:
        sequence: List[str] = []
        for event in self.trusted_classification_events:
            ttp = _clean_text(event.get("ttp"))
            if ttp:
                sequence.append(main_ttp_id(ttp))
        if not sequence and not self.classification_events:
            sequence = [
                main_ttp_id(item)
                for item in _as_list(self.payload.get("ttps"))
                if _clean_text(item)
            ]
        return sequence

    def graph_count(self, name: str) -> int:
        counts = self.graph.get("counts") or {}
        try:
            return int(counts.get(name) or 0)
        except (TypeError, ValueError):
            return 0

    def graph_flag(self, name: str) -> bool:
        return bool((self.graph.get("flags") or {}).get(name))


def _compile_regex(pattern: str) -> re.Pattern[str] | None:
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error:
        return None


def _match_ordered(required: List[str], sequence: List[str]) -> bool:
    if not required:
        return True
    cursor = 0
    for value in sequence:
        if value == required[cursor]:
            cursor += 1
            if cursor >= len(required):
                return True
    return False


def _condition_result(matched: bool, condition: Dict[str, Any], evidence: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "matched": matched,
        "condition": {k: v for k, v in condition.items() if k != "description"},
        "description": condition.get("description") or "",
        "evidence": evidence[:10],
    }


def _match_condition(condition: Dict[str, Any], evidence: SessionEvidence) -> Dict[str, Any]:
    ctype = _clean_text(condition.get("type"))
    found: List[Dict[str, Any]] = []

    if ctype == "classification_ttp":
        ttp = main_ttp_id(condition.get("ttp"))
        min_confidence = _safe_float(condition.get("min_confidence"), 0.0)
        command_regex = _clean_text(condition.get("command_regex"))
        command_pattern = _compile_regex(command_regex) if command_regex else None
        for event in evidence.trusted_classification_events:
            if main_ttp_id(event.get("ttp")) != ttp:
                continue
            if _safe_float(event.get("confidence"), 0.0) < min_confidence:
                continue
            command = _clean_text(event.get("command"))
            original = _clean_text(event.get("original_command"))
            if command_pattern and not (command_pattern.search(command) or command_pattern.search(original)):
                continue
            found.append({
                "type": "classification_event",
                "command": command,
                "original_command": original,
                "ttp": ttp,
                "source_ttp": event.get("source_ttp") or event.get("source_subtechnique") or event.get("ttp"),
                "tactic": event.get("tactic"),
                "source": event.get("source"),
                "confidence": event.get("confidence"),
            })
        return _condition_result(bool(found), condition, found)

    if ctype == "classification_tactic":
        tactic = _clean_text(condition.get("tactic"))
        min_confidence = _safe_float(condition.get("min_confidence"), 0.0)
        for event in evidence.trusted_classification_events:
            if _clean_text(event.get("tactic")) != tactic:
                continue
            if _safe_float(event.get("confidence"), 0.0) < min_confidence:
                continue
            found.append({
                "type": "classification_event",
                "command": event.get("command"),
                "ttp": event.get("ttp"),
                "tactic": tactic,
                "source": event.get("source"),
                "confidence": event.get("confidence"),
            })
        return _condition_result(bool(found), condition, found)

    if ctype == "command_regex":
        pattern_text = _clean_text(condition.get("pattern"))
        pattern = _compile_regex(pattern_text)
        if pattern:
            for command in evidence.command_texts():
                if pattern.search(command):
                    found.append({"type": "command", "command": command, "pattern": pattern_text})
        return _condition_result(bool(found), condition, found)

    if ctype == "eventid":
        eventid = _clean_text(condition.get("eventid"))
        for event in evidence.raw_events:
            if _clean_text(event.get("eventid")) == eventid:
                found.append({
                    "type": "raw_event",
                    "eventid": eventid,
                    "timestamp": event.get("timestamp"),
                    "input": event.get("input"),
                    "outfile": event.get("outfile"),
                    "shasum": event.get("shasum"),
                })
        return _condition_result(bool(found), condition, found)

    if ctype == "eventid_prefix":
        prefix = _clean_text(condition.get("prefix"))
        for event in evidence.raw_events:
            eventid = _clean_text(event.get("eventid"))
            if eventid.startswith(prefix):
                found.append({"type": "raw_event", "eventid": eventid, "timestamp": event.get("timestamp")})
        return _condition_result(bool(found), condition, found)

    if ctype == "min_event_count":
        eventid = _clean_text(condition.get("eventid"))
        count = sum(1 for item in evidence.eventids if item == eventid)
        required = int(condition.get("count") or 1)
        found.append({"type": "event_count", "eventid": eventid, "count": count, "required": required})
        return _condition_result(count >= required, condition, found)

    if ctype == "min_login_failures":
        required = int(condition.get("count") or 5)
        found.append({"type": "login_failures", "count": evidence.login_failed_count, "required": required})
        return _condition_result(evidence.login_failed_count >= required, condition, found)

    if ctype == "login_success":
        expected = bool(condition.get("value", True))
        actual = bool(evidence.payload.get("login_success"))
        found.append({"type": "login_success", "value": actual, "expected": expected})
        return _condition_result(actual is expected, condition, found)

    if ctype == "ordered_tactics":
        required = [_clean_text(item) for item in _as_list(condition.get("sequence")) if _clean_text(item)]
        sequence = evidence.tactic_sequence()
        found.append({"type": "tactic_sequence", "sequence": sequence, "required_sequence": required})
        return _condition_result(_match_ordered(required, sequence), condition, found)

    if ctype == "ordered_ttps":
        required = [main_ttp_id(item) for item in _as_list(condition.get("sequence")) if _clean_text(item)]
        sequence = evidence.ttp_sequence()
        found.append({"type": "ttp_sequence", "sequence": sequence, "required_sequence": required})
        return _condition_result(_match_ordered(required, sequence), condition, found)

    if ctype == "evidence_flag":
        flag = _clean_text(condition.get("flag"))
        expected = bool(condition.get("value", True))
        actual = evidence.graph_flag(flag)
        found.append({"type": "evidence_graph_flag", "flag": flag, "value": actual, "expected": expected})
        return _condition_result(actual is expected, condition, found)

    if ctype == "min_graph_count":
        count_name = _clean_text(condition.get("count_name"))
        required = int(condition.get("count") or 1)
        actual = evidence.graph_count(count_name)
        found.append({"type": "evidence_graph_count", "count_name": count_name, "count": actual, "required": required})
        return _condition_result(actual >= required, condition, found)

    return _condition_result(False, condition, [{"type": "unsupported_condition", "condition_type": ctype}])


def _match_condition_group(rule: Dict[str, Any], evidence: SessionEvidence) -> Tuple[bool, List[Dict[str, Any]]]:
    conditions = rule.get("conditions") or {}
    if not isinstance(conditions, dict):
        return False, []

    all_results = [_match_condition(item, evidence) for item in _as_list(conditions.get("all")) if isinstance(item, dict)]
    any_conditions = [item for item in _as_list(conditions.get("any")) if isinstance(item, dict)]
    any_results = [_match_condition(item, evidence) for item in any_conditions]
    none_results = [_match_condition(item, evidence) for item in _as_list(conditions.get("none")) if isinstance(item, dict)]

    all_matched = all(result["matched"] for result in all_results)
    any_matched = True if not any_conditions else any(result["matched"] for result in any_results)
    none_matched = not any(result["matched"] for result in none_results)
    matched = all_matched and any_matched and none_matched
    return matched, all_results + any_results + none_results


def _prediction_eligibility(rule: Dict[str, Any]) -> Dict[str, Any]:
    """Require explicit review and evaluation before correlation affects prediction."""

    requested = bool(rule.get("apply_to_prediction", False))
    provenance = rule.get("provenance") or {}
    eligibility = rule.get("prediction_eligibility") or {}
    reviewed = bool(eligibility.get("reviewed", provenance.get("reviewed", False)))
    evaluated = bool(eligibility.get("evaluated", rule.get("prediction_evaluated", False)))
    effective = requested and reviewed and evaluated
    if effective:
        reason = "rule is explicitly reviewed and empirically evaluated for prediction use"
    elif not requested:
        reason = "rule is report-only by policy"
    elif not reviewed:
        reason = "prediction use requested but rule is not reviewed"
    else:
        reason = "prediction use requested but rule is not empirically evaluated"
    return {
        "requested": requested,
        "reviewed": reviewed,
        "evaluated": evaluated,
        "effective": effective,
        "reason": reason,
    }


def _reviewed_consumer_eligibility(
    rule: Dict[str, Any],
    consumer: str,
) -> Dict[str, Any]:
    requested = bool(rule.get(f"apply_to_{consumer}", False))
    provenance = rule.get("provenance") or {}
    reviewed = provenance.get("reviewed") is True
    effective = requested and reviewed
    if effective:
        reason = f"rule explicitly permits reviewed {consumer} influence"
    elif not requested:
        reason = f"rule is not permitted to influence {consumer}"
    else:
        reason = f"{consumer} influence requested but rule is not reviewed"
    return {
        "requested": requested,
        "reviewed": reviewed,
        "effective": effective,
        "reason": reason,
    }


def correlation_allows_influence(item: Dict[str, Any], consumer: str) -> bool:
    """Fail closed when a correlation lacks an explicit downstream scope."""

    name = _clean_text(consumer).lower()
    if name not in INFLUENCE_CONSUMERS:
        return False
    if name == "report":
        return True
    scope = item.get("influence_scope") or {}
    entry = scope.get(name) if isinstance(scope, dict) else None
    if isinstance(entry, dict):
        return entry.get("effective") is True
    if entry is True:
        return True
    if name != "prediction":
        return False

    # Correlations persisted before influence_scope was introduced already
    # carried a strict prediction contract. Preserve those reviewed/evaluated
    # records without accepting the legacy apply_to_prediction flag by itself.
    eligibility = item.get("prediction_eligibility") or {}
    return bool(
        item.get("apply_to_prediction") is True
        and isinstance(eligibility, dict)
        and eligibility.get("effective") is True
        and eligibility.get("reviewed") is True
        and eligibility.get("evaluated") is True
    )


def correlate_session(
    session_payload: Dict[str, Any],
    policy_document: Dict[str, Any],
) -> Dict[str, Any]:
    """Return session-level TTP correlations with explicit provenance."""
    if not policy_document.get("knowledge_summary"):
        policy_document = normalize_correlation_document(policy_document)
    body = _policy_body(policy_document)
    if not body.get("enabled", True):
        return {
            "schema_version": SCHEMA_VERSION,
            "enabled": False,
            "correlations": [],
            "evidence_graph": build_session_evidence_graph(session_payload),
            "summary": {"status": "disabled", "correlation_count": 0},
        }

    evidence_graph = build_session_evidence_graph(session_payload)
    evidence = SessionEvidence(session_payload, evidence_graph)
    correlations: List[Dict[str, Any]] = []
    policy_refs = policy_document.get("policy_id") or body.get("policy_id") or ""
    knowledge_summary = policy_document.get("knowledge_summary") or {}
    for rule in body.get("rules") or []:
        if not isinstance(rule, dict) or not bool(rule.get("enabled", True)):
            continue
        matched, condition_results = _match_condition_group(rule, evidence)
        if not matched:
            continue
        rule_id = _clean_text(rule.get("rule_id"))
        confidence = _clamp_confidence(rule.get("confidence"), 0.5)
        prediction_eligibility = _prediction_eligibility(rule)
        influence_scope = {
            "report": {
                "requested": True,
                "reviewed": True,
                "effective": True,
                "reason": "matched correlations are report-visible",
            },
            "prediction": prediction_eligibility,
            "campaign": _reviewed_consumer_eligibility(rule, "campaign"),
            "threat_hunt": _reviewed_consumer_eligibility(rule, "threat_hunt"),
            "alert": _reviewed_consumer_eligibility(rule, "alert"),
        }
        correlation = {
            "correlation_id": stable_id(
                "sessionttp",
                {
                    "session_id": session_payload.get("session_id", "unknown"),
                    "rule_id": rule_id,
                    "ttp": rule.get("ttp"),
                    "matched_conditions": condition_results,
                },
            ),
            "schema_version": SCHEMA_VERSION,
            "session_id": session_payload.get("session_id", "unknown"),
            "rule_id": rule_id,
            "enabled": True,
            "ttp": main_ttp_id(rule.get("ttp")),
            "source_ttp": _clean_text(rule.get("source_ttp") or rule.get("source_subtechnique") or rule.get("ttp")),
            "source_subtechnique": _clean_text(rule.get("source_subtechnique")),
            "technique_granularity": _clean_text(rule.get("technique_granularity") or "parent"),
            "tactic": _clean_text(rule.get("tactic")),
            "technique_name": _clean_text(rule.get("technique_name")),
            "confidence": confidence,
            "evidence_type": _clean_text(rule.get("evidence_type") or "session_correlated_candidate"),
            "source_type": _clean_text(rule.get("source_type")),
            "temporal_claim": bool(rule.get("temporal_claim", False)),
            "apply_to_prediction": prediction_eligibility["effective"],
            "apply_to_prediction_requested": prediction_eligibility["requested"],
            "prediction_eligibility": prediction_eligibility,
            "influence_scope": influence_scope,
            "reason": _clean_text(rule.get("reason")),
            "matched_conditions": condition_results,
            "evidence": [item for result in condition_results for item in result.get("evidence", [])][:20],
            "references": _normalize_refs(rule.get("references") or []),
            "provenance": rule.get("provenance") or {},
            "policy_id": policy_refs,
            "policy_version": policy_document.get("version") or body.get("version") or "",
            "source_document_type": _clean_text(rule.get("source_document_type") or "policy"),
            "source_document_id": _clean_text(rule.get("source_document_id") or rule.get("source_policy_id") or policy_refs),
            "source_document_version": _clean_text(rule.get("source_document_version")),
            "knowledge_pack_id": _clean_text(rule.get("knowledge_pack_id")),
            "source_policy_id": _clean_text(rule.get("source_policy_id")),
            "generated_at": utc_now(),
        }
        correlations.append(correlation)

    ttps_for_prediction = [
        item["ttp"]
        for item in correlations
        if item.get("ttp") and item.get("apply_to_prediction")
    ]
    tactics_for_prediction = [
        item["tactic"]
        for item in correlations
        if item.get("tactic") and item.get("apply_to_prediction")
    ]
    summary = {
        "status": "applied",
        "correlation_count": len(correlations),
        "prediction_input_count": len(ttps_for_prediction),
        "policy_id": policy_refs,
        "policy_version": policy_document.get("version") or "",
        "source_types": sorted({item.get("source_type") for item in correlations if item.get("source_type")}),
        "correlated_ttps_for_prediction": _unique(ttps_for_prediction),
        "correlated_tactics_for_prediction": _unique(tactics_for_prediction),
        "effective_influence_counts": {
            consumer: sum(
                1
                for item in correlations
                if correlation_allows_influence(item, consumer)
            )
            for consumer in INFLUENCE_CONSUMERS
        },
        "session_evidence_graph_summary": evidence_graph.get("summary") or {},
        "knowledge_summary": knowledge_summary,
        "knowledge_pack_ids": knowledge_summary.get("knowledge_pack_ids") or [],
        "policy_ids": knowledge_summary.get("policy_ids") or ([policy_refs] if policy_refs else []),
        "manual_rule_count": knowledge_summary.get("manual_rule_count", 0),
        "generated_rule_count": knowledge_summary.get("generated_rule_count", 0),
        "rule_source_counts": knowledge_summary.get("source_type_counts") or {},
        "rule_evidence_type_counts": knowledge_summary.get("evidence_type_counts") or {},
        "source_document_counts": knowledge_summary.get("source_document_counts") or {},
        "import_status": knowledge_summary.get("import_status") or {},
        "source_artifacts": knowledge_summary.get("source_artifacts") or [],
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "enabled": True,
        "evidence_graph": evidence_graph,
        "correlations": correlations,
        "summary": summary,
    }


def _unique(values: Iterable[Any]) -> List[str]:
    seen = set()
    output: List[str] = []
    for value in values:
        text = _clean_text(value)
        if text and text not in seen:
            seen.add(text)
            output.append(text)
    return output


def apply_session_ttp_correlations(
    session_payload: Dict[str, Any],
    policy_document: Dict[str, Any],
) -> Dict[str, Any]:
    result = correlate_session(session_payload, policy_document)
    payload = dict(session_payload)
    payload["session_evidence_graph"] = result.get("evidence_graph") or {}
    payload["session_evidence_graph_summary"] = (result.get("evidence_graph") or {}).get("summary") or {}
    payload["session_ttp_correlations"] = result["correlations"]
    payload["session_ttp_correlation_summary"] = result["summary"]
    return payload


def validate_policy_document(document: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    if document.get("schema_version") not in {POLICY_SCHEMA_VERSION, KNOWLEDGE_PACK_SCHEMA_VERSION}:
        errors.append(f"schema_version must be {POLICY_SCHEMA_VERSION} or {KNOWLEDGE_PACK_SCHEMA_VERSION}")
    document = normalize_correlation_document(document)
    body = _policy_body(document)
    if not isinstance(body, dict) or not body:
        errors.append("policy object is required")
        return errors
    if "enabled" in body and not isinstance(body.get("enabled"), bool):
        errors.append("policy.enabled must be boolean")
    rules = body.get("rules") or []
    if not isinstance(rules, list):
        errors.append("policy.rules must be a list")
        return errors
    for index, rule in enumerate(rules):
        path = f"policy.rules[{index}]"
        if not isinstance(rule, dict):
            errors.append(f"{path} must be an object")
            continue
        if not bool(rule.get("enabled", True)):
            continue
        for field in ("rule_id", "ttp", "tactic", "technique_name", "reason"):
            if not _clean_text(rule.get(field)):
                errors.append(f"{path}.{field} is required")
        if _clean_text(rule.get("source_type")) not in ALLOWED_SOURCE_TYPES:
            errors.append(f"{path}.source_type must be one of {sorted(ALLOWED_SOURCE_TYPES)}")
        if _clean_text(rule.get("evidence_type")) not in ALLOWED_EVIDENCE_TYPES:
            errors.append(f"{path}.evidence_type must be one of {sorted(ALLOWED_EVIDENCE_TYPES)}")
        if not (0.0 <= _safe_float(rule.get("confidence"), -1.0) <= 1.0):
            errors.append(f"{path}.confidence must be between 0 and 1")
        if "temporal_claim" in rule and not isinstance(rule.get("temporal_claim"), bool):
            errors.append(f"{path}.temporal_claim must be boolean")
        for consumer in ("prediction", "campaign", "threat_hunt", "alert"):
            field = f"apply_to_{consumer}"
            if field in rule and not isinstance(rule.get(field), bool):
                errors.append(f"{path}.{field} must be boolean")
        provenance = rule.get("provenance")
        if not isinstance(provenance, dict) or not provenance:
            errors.append(f"{path}.provenance is required")
        else:
            for field in ("method", "basis", "author", "created", "version"):
                if not provenance.get(field):
                    errors.append(f"{path}.provenance.{field} is required")
            if provenance.get("generated") and not provenance.get("artifact_sha256"):
                errors.append(f"{path}.provenance.artifact_sha256 is required for generated rules")
            if provenance.get("generated") and rule.get("apply_to_prediction") and not provenance.get("reviewed"):
                errors.append(
                    f"{path}.apply_to_prediction cannot be true for unreviewed generated rules"
                )
            if rule.get("apply_to_prediction"):
                eligibility = _prediction_eligibility(rule)
                if not eligibility["reviewed"] or not eligibility["evaluated"]:
                    errors.append(
                        f"{path}.apply_to_prediction requires explicit reviewed=true and evaluated=true"
                    )
            for consumer in ("campaign", "threat_hunt", "alert"):
                if rule.get(f"apply_to_{consumer}") and provenance.get("reviewed") is not True:
                    errors.append(
                        f"{path}.apply_to_{consumer} requires provenance.reviewed=true"
                    )
        references = _normalize_refs(rule.get("references") or [])
        if not references:
            errors.append(f"{path}.references is required")
        if (
            _clean_text(rule.get("source_type")) in EXTERNAL_REFERENCE_SOURCE_TYPES
            and not any(_clean_text(ref.get("url")) for ref in references)
        ):
            errors.append(f"{path}.references must include at least one URL for external-source rules")
        if not isinstance(rule.get("conditions"), dict) or not rule.get("conditions"):
            errors.append(f"{path}.conditions is required")
        else:
            for group in ("all", "any", "none"):
                for condition_index, condition in enumerate(_as_list(rule.get("conditions", {}).get(group))):
                    condition_path = f"{path}.conditions.{group}[{condition_index}]"
                    if not isinstance(condition, dict):
                        errors.append(f"{condition_path} must be an object")
                        continue
                    condition_type = _clean_text(condition.get("type"))
                    if condition_type not in ALLOWED_CONDITION_TYPES:
                        errors.append(
                            f"{condition_path}.type must be one of {sorted(ALLOWED_CONDITION_TYPES)}"
                        )
                    pattern_text = _clean_text(condition.get("pattern"))
                    if condition_type == "command_regex" and not pattern_text:
                        errors.append(f"{condition_path}.pattern is required for command_regex")
                    if pattern_text:
                        try:
                            re.compile(pattern_text, re.IGNORECASE)
                        except re.error:
                            errors.append(f"{condition_path}.pattern invalid regex")
                    command_regex = _clean_text(condition.get("command_regex"))
                    if command_regex:
                        try:
                            re.compile(command_regex, re.IGNORECASE)
                        except re.error:
                            errors.append(f"{condition_path}.command_regex invalid regex")
                    if condition_type in {"ordered_tactics", "ordered_ttps"} and not _as_list(condition.get("sequence")):
                        errors.append(f"{condition_path}.sequence is required for {condition_type}")
    return errors


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate or test session-level TTP correlation policy.")
    parser.add_argument("--policy", required=True, help="Session TTP correlation policy JSON path.")
    parser.add_argument("--sample-session", help="Optional session payload JSON path to test correlation output.")
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    return parser


def main(argv: List[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    policy = load_policy(args.policy)
    errors = validate_policy_document(policy)
    output: Dict[str, Any] = {
        "policy": args.policy,
        "valid": not errors,
        "errors": errors,
    }
    if args.sample_session:
        with Path(args.sample_session).open("r", encoding="utf-8") as f:
            session_payload = json.load(f)
        output["correlation"] = correlate_session(session_payload, policy)
    if args.json:
        print(json.dumps(output, indent=2, sort_keys=True))
    else:
        if errors:
            print("Session TTP correlation policy validation failed:")
            for error in errors:
                print(f"- {error}")
        else:
            print("Session TTP correlation policy validation passed.")
        if "correlation" in output:
            print(json.dumps(output["correlation"], indent=2, sort_keys=True))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
