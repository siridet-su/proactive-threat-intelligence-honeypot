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
from production.correlation.semantics import (
    CORRELATION_CONFIDENCE_SEMANTICS,
    declared_confidence_semantics,
    LEGACY_CORRELATION_CONFIDENCE_SEMANTICS,
    is_valid_confidence_semantics,
)
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

ALLOWED_RULE_TYPES = {
    "DIRECT_COMMAND_RECONFIRMATION",
    "DIRECT_EVENT_RECONFIRMATION",
    "GENUINE_MULTI_EVENT_CORRELATION",
    "MULTI_EVENT_CORRELATION",
    "SINGLE_SESSION_THRESHOLD",
    "THRESHOLD_CONTEXT_RULE",
    "SESSION_CONTEXT_RULE",
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

# These namespaces are intentionally separate.  The first is built only from
# command/event mappings that passed the classification trust contract; the
# second contains rule matches that are useful for report context but are not
# ATT&CK authority.
OBSERVED_TRUSTED_TTPS_KEY = "observed_trusted_ttps"
CORRELATED_TTP_HYPOTHESES_KEY = "correlated_ttp_hypotheses"
PROJECT_LOCAL_HEURISTIC = "PROJECT_LOCAL_HEURISTIC"
TEMPORAL_SEMANTICS_ORDERED_SEQUENCE = "ordered_sequence"
TEMPORAL_SEMANTICS_SESSION_SCOPED = "session_scoped_no_elapsed_window"
TEMPORAL_SEMANTICS_TIME_BOUNDED = "time_bounded_correlation"
TEMPORAL_RELATIONSHIP_ORDERED_SAME_SESSION = "ORDERED_SAME_SESSION_RELATIONSHIP"
TEMPORAL_RELATIONSHIP_SESSION_SCOPED = "SAME_SESSION_SCOPE_NO_ELAPSED_WINDOW"
TEMPORAL_RELATIONSHIP_TIME_BOUNDED = "TIME_BOUNDED_CORRELATION"


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


def _correlation_confidence_semantics(policy_document: Dict[str, Any]) -> str:
    """Return the declared score meaning, never an implied probability."""

    return declared_confidence_semantics(
        _policy_body(policy_document).get("confidence_semantics")
    )


def _classification_event_ref(
    session_id: str,
    index: int,
    event: Dict[str, Any],
) -> str:
    """Return a stable reference without trusting a caller-supplied ID."""

    explicit = _clean_text(
        event.get("evidence_id")
        or event.get("classification_event_id")
        or event.get("event_id")
    )
    if explicit:
        return explicit
    return stable_id(
        "classification-event",
        {
            "session_id": session_id or "unknown",
            "index": index,
            "ttp": _clean_text(event.get("ttp")),
            "command": _clean_text(event.get("command") or event.get("input")),
            "event_timestamp": _clean_text(event.get("event_timestamp")),
        },
    )


def build_observed_trusted_ttps(
    session_payload: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Aggregate trusted command/event mappings into a traceable session set.

    Only events accepted by :func:`is_trusted_classification_event` are used.
    Raw ``ttps``/``tactics`` aggregate fields are deliberately not treated as
    trusted evidence because they do not carry the authority and provenance
    needed to reconstruct the current contract.  The output order follows the
    deterministic event order supplied by the session and is stable for a
    given input.
    """

    session_id = _clean_text(session_payload.get("session_id")) or "unknown"
    grouped: Dict[str, Dict[str, Any]] = {}
    events = [
        item
        for item in _as_list(session_payload.get("classification_events"))
        if isinstance(item, dict)
    ]
    for index, event in enumerate(events):
        if not is_trusted_classification_event(event):
            continue
        raw_ttp = _clean_text(event.get("ttp")).upper()
        if not raw_ttp or raw_ttp == "UNKNOWN":
            continue
        technique_id = main_ttp_id(raw_ttp)
        if not technique_id:
            continue
        item = grouped.setdefault(
            technique_id,
            {
                "observation_namespace": OBSERVED_TRUSTED_TTPS_KEY,
                "technique_id": technique_id,
                "source_ttp_values": [],
                "source_subtechnique_values": [],
                "tactics": [],
                "classification_event_refs": [],
                "command_evidence_refs": [],
                "authority_decision_refs": [],
                "evidence_refs": [],
                "commands": [],
                "sequence_indices": [],
                "first_sequence_index": index,
                "trust_tier": "trusted_observation",
                "mapping_scope": "command_event_observation",
                "mapping_semantics": "trusted_command_event_observation",
                "authority": {
                    "status": "trusted_observation",
                    "correlation_may_override": False,
                    "correlation_may_remove": False,
                    "correlation_may_promote": False,
                    "correlation_may_drive_prediction": False,
                    "may_authorize_response": False,
                    "canonical_write_allowed": False,
                },
                "_confidence_values": [],
                "_confidence_semantics": [],
            },
        )
        source_ttp = _clean_text(
            event.get("source_ttp")
            or event.get("source_subtechnique")
            or event.get("ttp")
        ).upper()
        source_subtechnique = _clean_text(
            event.get("source_subtechnique")
            or (source_ttp if "." in source_ttp else "")
        ).upper()
        for key, value in (
            ("source_ttp_values", source_ttp),
            ("source_subtechnique_values", source_subtechnique),
            ("tactics", _clean_text(event.get("tactic"))),
        ):
            if value and value not in item[key]:
                item[key].append(value)
        event_ref = _classification_event_ref(session_id, index, event)
        for key in ("classification_event_refs", "evidence_refs"):
            if event_ref not in item[key]:
                item[key].append(event_ref)
        command = _clean_text(event.get("command") or event.get("input"))
        if command:
            command_ref = stable_id(
                "command-evidence",
                {"session_id": session_id, "index": index, "command": command},
            )
            if command_ref not in item["command_evidence_refs"]:
                item["command_evidence_refs"].append(command_ref)
            if command not in item["commands"]:
                item["commands"].append(command)
        decision = event.get("authority_decision")
        if isinstance(decision, dict):
            decision_ref = _clean_text(
                decision.get("decision_id") or decision.get("authority_decision_id")
            )
            if decision_ref and decision_ref not in item["authority_decision_refs"]:
                item["authority_decision_refs"].append(decision_ref)
        item["sequence_indices"].append(index)
        try:
            confidence = float(event.get("confidence"))
        except (TypeError, ValueError):
            confidence = None
        if confidence is not None:
            item["_confidence_values"].append(max(0.0, min(1.0, confidence)))
        semantics = _clean_text(event.get("confidence_semantics"))
        if semantics and semantics not in item["_confidence_semantics"]:
            item["_confidence_semantics"].append(semantics)

    output: List[Dict[str, Any]] = []
    for item in sorted(
        grouped.values(),
        key=lambda value: (int(value.get("first_sequence_index", 0)), value["technique_id"]),
    ):
        confidence_values = item.pop("_confidence_values")
        item["confidence"] = {
            "min": round(min(confidence_values), 4) if confidence_values else None,
            "average": round(sum(confidence_values) / len(confidence_values), 4)
            if confidence_values
            else None,
            "count": len(confidence_values),
        }
        semantics_values = item.pop("_confidence_semantics")
        item["confidence_semantics_values"] = semantics_values
        item["confidence_semantics"] = (
            semantics_values[0]
            if len(semantics_values) == 1
            else LEGACY_CORRELATION_CONFIDENCE_SEMANTICS
            if not semantics_values
            else "mixed_classification_event_score_semantics"
        )
        output.append(item)
    return output


def _rule_condition_types(rule: Dict[str, Any]) -> set[str]:
    conditions = rule.get("conditions") or {}
    if not isinstance(conditions, dict):
        return set()
    return {
        _clean_text(condition.get("type"))
        for group in ("all", "any", "none")
        for condition in _as_list(conditions.get(group))
        if isinstance(condition, dict) and _clean_text(condition.get("type"))
    }


def _rule_type(rule: Dict[str, Any]) -> str:
    """Classify rule shape without changing matching behavior."""

    declared = _clean_text(rule.get("rule_type"))
    if declared in {
        "DIRECT_COMMAND_RECONFIRMATION",
        "DIRECT_EVENT_RECONFIRMATION",
        "GENUINE_MULTI_EVENT_CORRELATION",
        "MULTI_EVENT_CORRELATION",
        "SINGLE_SESSION_THRESHOLD",
        "THRESHOLD_CONTEXT_RULE",
        "SESSION_CONTEXT_RULE",
    }:
        return declared
    condition_types = _rule_condition_types(rule)
    if condition_types & {"ordered_tactics", "ordered_ttps"}:
        return "GENUINE_MULTI_EVENT_CORRELATION"
    if condition_types & {"min_event_count", "min_login_failures", "min_graph_count"}:
        return "SINGLE_SESSION_THRESHOLD"
    if condition_types <= {"eventid", "eventid_prefix"}:
        return "DIRECT_EVENT_RECONFIRMATION"
    if condition_types & {"classification_ttp", "classification_tactic", "command_regex"}:
        return "DIRECT_COMMAND_RECONFIRMATION"
    return "SESSION_CONTEXT_RULE"


def _temporal_semantics(rule: Dict[str, Any]) -> Dict[str, Any]:
    """Expose ordering separately from a measured elapsed-time window."""

    window_keys = (
        "time_window_seconds",
        "elapsed_time_window_seconds",
        "maxspan_seconds",
        "timespan_seconds",
        "maxspan",
        "timespan",
    )
    window_value = next(
        (rule.get(key) for key in window_keys if rule.get(key) is not None),
        None,
    )
    condition_types = _rule_condition_types(rule)
    if window_value is not None:
        return {
            "temporal_semantics": TEMPORAL_SEMANTICS_TIME_BOUNDED,
            "temporal_relationship": TEMPORAL_RELATIONSHIP_TIME_BOUNDED,
            "temporal_window_present": True,
            "temporal_window": window_value,
        }
    if condition_types & {"ordered_tactics", "ordered_ttps"}:
        return {
            "temporal_semantics": TEMPORAL_SEMANTICS_ORDERED_SEQUENCE,
            "temporal_relationship": TEMPORAL_RELATIONSHIP_ORDERED_SAME_SESSION,
            "temporal_window_present": False,
            "temporal_window": None,
        }
    return {
        "temporal_semantics": TEMPORAL_SEMANTICS_SESSION_SCOPED,
        "temporal_relationship": TEMPORAL_RELATIONSHIP_SESSION_SCOPED,
        "temporal_window_present": False,
        "temporal_window": None,
    }


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
    # A malformed explicit marker must never authorize a stronger consumer.
    # Missing metadata is retained as an explicitly unresolved legacy value for
    # historical records and compatibility fixtures.
    if name != "report" and not is_valid_confidence_semantics(
        item.get("confidence_semantics"), allow_absent=True
    ):
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
        semantics = _correlation_confidence_semantics(policy_document)
        observed_trusted_ttps = build_observed_trusted_ttps(session_payload)
        return {
            "schema_version": SCHEMA_VERSION,
            "enabled": False,
            "confidence_semantics": semantics,
            OBSERVED_TRUSTED_TTPS_KEY: observed_trusted_ttps,
            CORRELATED_TTP_HYPOTHESES_KEY: [],
            "correlations": [],
            "evidence_graph": build_session_evidence_graph(session_payload),
            "summary": {
                "status": "disabled",
                "correlation_count": 0,
                "observed_trusted_ttp_count": len(observed_trusted_ttps),
                "confidence_semantics": semantics,
                "correlation_output_namespace": CORRELATED_TTP_HYPOTHESES_KEY,
            },
        }

    evidence_graph = build_session_evidence_graph(session_payload)
    evidence = SessionEvidence(session_payload, evidence_graph)
    observed_trusted_ttps = build_observed_trusted_ttps(session_payload)
    correlations: List[Dict[str, Any]] = []
    policy_refs = policy_document.get("policy_id") or body.get("policy_id") or ""
    knowledge_summary = policy_document.get("knowledge_summary") or {}
    confidence_semantics = _correlation_confidence_semantics(policy_document)
    for rule in body.get("rules") or []:
        if not isinstance(rule, dict) or not bool(rule.get("enabled", True)):
            continue
        matched, condition_results = _match_condition_group(rule, evidence)
        if not matched:
            continue
        rule_id = _clean_text(rule.get("rule_id"))
        confidence = _clamp_confidence(rule.get("confidence"), 0.5)
        prediction_eligibility = _prediction_eligibility(rule)
        temporal = _temporal_semantics(rule)
        rule_type = _rule_type(rule)
        source_document_type = _clean_text(
            rule.get("source_document_type") or "policy"
        )
        numeric_provenance = _clean_text(
            rule.get("numeric_provenance")
            or body.get("numeric_provenance")
            or PROJECT_LOCAL_HEURISTIC
        )
        ontology_binding = rule.get("ontology_binding")
        if not isinstance(ontology_binding, dict):
            ontology_binding = {}
        ontology_status = _clean_text(
            rule.get("ontology_status") or ontology_binding.get("status")
        )
        claim_status = (
            "ONTOLOGY_MISMATCH"
            if ontology_status in {
                "invalid_identifier",
                "ontology_mismatch",
                "ontology_version_mismatch",
            }
            else "UNRESOLVED_ONTOLOGY"
            if ontology_status == "unresolved"
            else "UNREVIEWED_RULE"
            if source_document_type == "knowledge_pack"
            else "CONTEXTUAL_ONLY"
        )
        optional_pack_status = _clean_text(rule.get("optional_pack_status"))
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
            # ``confidence`` remains a compatibility alias.  The canonical
            # meaning is a bounded deterministic rule strength, never a
            # calibrated probability.
            "strength": confidence,
            "strength_semantics": confidence_semantics,
            "confidence_semantics": confidence_semantics,
            "numeric_provenance": numeric_provenance,
            "evidence_type": _clean_text(rule.get("evidence_type") or "session_correlated_candidate"),
            "source_type": _clean_text(rule.get("source_type")),
            "output_namespace": CORRELATED_TTP_HYPOTHESES_KEY,
            "correlation_kind": "contextual",
            "rule_type": rule_type,
            "claim_status": claim_status,
            "ontology_status": ontology_status or "not_applicable",
            "ontology_binding": ontology_binding,
            "optional_pack_status": optional_pack_status,
            "authority": {
                "status": "non_authoritative",
                "can_override_trusted": False,
                "can_remove_trusted": False,
                "can_promote_trusted": False,
                "may_drive_prediction": False,
                "may_authorize_response": False,
                "canonical_write_allowed": False,
            },
            # ``temporal_claim`` is retained as a compatibility field, but it
            # now reflects an actual elapsed-time predicate only.  Historical
            # policy metadata used ``true`` for ordered subsequences; exposing
            # that value would incorrectly imply bounded temporal proximity.
            "temporal_claim": bool(temporal["temporal_window_present"]),
            **temporal,
            "chronology_quality": _clean_text(
                (evidence_graph.get("summary") or {}).get("chronology_quality")
                or evidence_graph.get("chronology_quality")
            ) or "not_available",
            "chronology_basis": _clean_text(
                (evidence_graph.get("summary") or {}).get("chronology_basis")
                or evidence_graph.get("chronology_basis")
            ),
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
            "source_document_type": source_document_type,
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
        "observed_trusted_ttp_count": len(observed_trusted_ttps),
        "correlation_output_namespace": CORRELATED_TTP_HYPOTHESES_KEY,
        "observed_output_namespace": OBSERVED_TRUSTED_TTPS_KEY,
        "correlation_authority": {
            "status": "non_authoritative",
            "can_override_trusted": False,
            "can_remove_trusted": False,
            "can_promote_trusted": False,
            "may_drive_prediction": False,
            "may_authorize_response": False,
            "canonical_write_allowed": False,
        },
        "prediction_input_count": len(ttps_for_prediction),
        "policy_id": policy_refs,
        "policy_version": policy_document.get("version") or "",
        "confidence_semantics": confidence_semantics,
        "numeric_provenance": _clean_text(
            body.get("numeric_provenance") or PROJECT_LOCAL_HEURISTIC
        ),
        "temporal_semantics": _clean_text(
            body.get("temporal_semantics") or TEMPORAL_SEMANTICS_SESSION_SCOPED
        ),
        "temporal_window_present": bool(
            body.get("time_window_seconds")
            or body.get("elapsed_time_window_seconds")
            or body.get("maxspan_seconds")
            or body.get("timespan_seconds")
            or body.get("maxspan")
            or body.get("timespan")
        ),
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
        "confidence_semantics": confidence_semantics,
        OBSERVED_TRUSTED_TTPS_KEY: observed_trusted_ttps,
        CORRELATED_TTP_HYPOTHESES_KEY: correlations,
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
    payload[OBSERVED_TRUSTED_TTPS_KEY] = result.get(OBSERVED_TRUSTED_TTPS_KEY) or []
    payload[CORRELATED_TTP_HYPOTHESES_KEY] = result.get(
        CORRELATED_TTP_HYPOTHESES_KEY
    ) or []
    payload["session_ttp_correlations"] = result["correlations"]
    payload["session_ttp_correlation_summary"] = result["summary"]
    return payload


def validate_policy_document(
    document: Dict[str, Any],
    *,
    require_current_semantics: bool = False,
) -> List[str]:
    errors: List[str] = []
    if document.get("schema_version") not in {POLICY_SCHEMA_VERSION, KNOWLEDGE_PACK_SCHEMA_VERSION}:
        errors.append(f"schema_version must be {POLICY_SCHEMA_VERSION} or {KNOWLEDGE_PACK_SCHEMA_VERSION}")
    raw_body = _policy_body(document)
    raw_semantics = raw_body.get("confidence_semantics")
    raw_output_contract = raw_body.get("correlation_output_contract")
    raw_numeric_provenance = raw_body.get("numeric_provenance")
    raw_temporal_semantics = raw_body.get("temporal_semantics")
    if raw_semantics is not None and not is_valid_confidence_semantics(
        raw_semantics, allow_absent=False
    ):
        errors.append(
            "policy.confidence_semantics must be a recognized non-probability marker"
        )
    if require_current_semantics and raw_semantics != CORRELATION_CONFIDENCE_SEMANTICS:
        errors.append(
            "policy.confidence_semantics must equal "
            f"{CORRELATION_CONFIDENCE_SEMANTICS}"
        )
    if require_current_semantics and not isinstance(raw_output_contract, dict):
        errors.append("policy.correlation_output_contract is required")
    if require_current_semantics and not _clean_text(raw_numeric_provenance):
        errors.append("policy.numeric_provenance is required")
    if require_current_semantics and not _clean_text(raw_temporal_semantics):
        errors.append("policy.temporal_semantics is required")
    document = normalize_correlation_document(document)
    body = _policy_body(document)
    if not isinstance(body, dict) or not body:
        errors.append("policy object is required")
        return errors
    output_contract = body.get("correlation_output_contract")
    required_contract = {
        "observed_namespace": OBSERVED_TRUSTED_TTPS_KEY,
        "context_namespace": CORRELATED_TTP_HYPOTHESES_KEY,
        "authority": "non_authoritative",
        "can_override_observed": False,
        "can_remove_observed": False,
        "can_promote_trusted": False,
        "may_drive_prediction": False,
        "may_authorize_response": False,
        "canonical_write_allowed": False,
    }
    if not isinstance(output_contract, dict):
        errors.append("policy.correlation_output_contract is required")
    else:
        for field, expected in required_contract.items():
            if output_contract.get(field) != expected:
                errors.append(
                    "policy.correlation_output_contract."
                    f"{field} must equal {expected!r}"
                )
    numeric_provenance = _clean_text(body.get("numeric_provenance"))
    if not numeric_provenance:
        errors.append("policy.numeric_provenance is required")
    temporal_semantics = _clean_text(body.get("temporal_semantics"))
    if not temporal_semantics:
        errors.append("policy.temporal_semantics is required")
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
        if not _clean_text(rule.get("numeric_provenance")):
            errors.append(f"{path}.numeric_provenance is required")
        declared_rule_type = _clean_text(rule.get("rule_type"))
        if declared_rule_type and declared_rule_type not in ALLOWED_RULE_TYPES:
            errors.append(
                f"{path}.rule_type must be one of {sorted(ALLOWED_RULE_TYPES)}"
            )
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
