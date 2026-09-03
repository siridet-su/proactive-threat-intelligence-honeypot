"""Build a compact evidence graph for session-level reasoning.

The command classifier produces command-level labels. This module normalizes
the broader session evidence into a graph-like JSON structure so correlation
and future knowledge-pack importers can reason over the same stable contract.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from production.classification.trust import (
    classification_audit_reason,
    is_trusted_classification_event,
)
from production.classification.classification_pipeline import split_compound_command
from production.enrichment.enrichment_cache import iter_session_observables
from production.utils.serialization import stable_id, utc_now
from production.correlation.session_ttp_knowledge import main_ttp_id
from production.correlation.session_behavior_relationships import (
    build_session_behavior_relationships,
)


SCHEMA_VERSION = "session_evidence_graph.v2"

SENSITIVE_EVENT_FIELDS = {"password", "passwd", "token", "api_key", "authorization"}


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


def _clean_text(value: Any) -> str:
    return str(value or "").strip()


def _unique(values: Iterable[Any]) -> List[str]:
    seen = set()
    output: List[str] = []
    for value in values:
        text = _clean_text(value)
        if text and text not in seen:
            seen.add(text)
            output.append(text)
    return output


def _ordered_behavior_chain(classification_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    indexed_events = list(enumerate(classification_events))
    parsed_timestamps: Dict[int, datetime] = {}
    for index, event in indexed_events:
        timestamp = _clean_text(event.get("event_timestamp"))
        if not timestamp:
            continue
        try:
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        parsed_timestamps[index] = parsed.astimezone(timezone.utc)

    def fragment_position(event: Dict[str, Any]) -> int:
        try:
            return int(event.get("subcommand_index") or 0)
        except (TypeError, ValueError):
            return 0

    if classification_events and len(parsed_timestamps) == len(classification_events):
        indexed_events.sort(
            key=lambda pair: (
                parsed_timestamps[pair[0]],
                fragment_position(pair[1]),
                pair[0],
            )
        )

    chain: List[Dict[str, Any]] = []
    for original_index, event in indexed_events:
        command = _clean_text(event.get("subcommand") or event.get("command"))
        ttp = main_ttp_id(event.get("ttp"))
        tactic = _clean_text(event.get("tactic"))
        if not command or not ttp or ttp.lower() == "unknown" or not tactic or tactic.lower() == "unknown":
            continue
        evidence_id = _clean_text(event.get("evidence_id")) or stable_id(
            "class",
            {
                "index": original_index,
                "command": command,
                "ttp": ttp,
                "tactic": tactic,
                "source": event.get("source"),
            },
        )
        shell_fragments = split_compound_command(command, split_pipes=True)
        chain.append({
            "sequence_index": len(chain),
            "evidence_id": evidence_id,
            "command": command,
            "original_command": _clean_text(event.get("original_command")),
            "command_outcome": _clean_text(event.get("command_outcome")) or "legacy_outcome_unknown",
            "outcome_scope": _clean_text(event.get("outcome_scope")) or "legacy_unknown",
            "cowrie_eventid": _clean_text(event.get("cowrie_eventid")),
            "timestamp": _clean_text(event.get("event_timestamp")),
            "compound_command_index": event.get("compound_command_index"),
            "fragment_index": event.get("subcommand_index"),
            "fragment_count": event.get("subcommand_count"),
            "operator_before": _clean_text(event.get("operator_before")),
            "operator_after": _clean_text(event.get("operator_after")),
            "shell_fragments": [
                {
                    "command": fragment.text,
                    "fragment_index": fragment.index,
                    "fragment_count": fragment.count,
                    "operator_before": fragment.operator_before,
                    "operator_after": fragment.operator_after,
                }
                for fragment in shell_fragments
            ],
            "ttp": ttp,
            "tactic": tactic,
            "source": _clean_text(event.get("source")) or "unknown",
            "agreement_status": _clean_text(event.get("agreement_status")),
            "confidence": event.get("confidence"),
            "confidence_semantics": _clean_text(event.get("confidence_semantics")) or "legacy_unscoped_score",
            "evidence_tier": "trusted_observation",
        })
    return chain


def _chronology_metadata(
    classification_events: List[Dict[str, Any]],
) -> Dict[str, str]:
    """Describe whether ordered evidence is timestamp-supported or degraded.

    The existing ordering algorithm is intentionally unchanged: when every
    classification event has a valid timestamp it sorts by UTC time, otherwise
    it preserves input/fragment order.  This metadata makes that distinction
    visible to consumers instead of implying an elapsed-time or causal claim.
    """

    if not classification_events:
        return {
            "chronology_quality": "not_available",
            "chronology_basis": "no_classification_events",
        }
    parsed: List[datetime] = []
    invalid_nonempty = False
    for event in classification_events:
        raw = _clean_text(event.get("event_timestamp"))
        if not raw:
            continue
        try:
            value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            invalid_nonempty = True
            continue
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        parsed.append(value.astimezone(timezone.utc))
    if len(parsed) == len(classification_events):
        quality = (
            "timestamp_supported_with_ties"
            if len({value for value in parsed}) < len(parsed)
            else "timestamp_supported"
        )
        return {
            "chronology_quality": quality,
            "chronology_basis": "all_classification_timestamps_valid_utc",
        }
    if parsed:
        return {
            "chronology_quality": "mixed_timestamp_input_order",
            "chronology_basis": "some_classification_timestamps_missing_or_invalid",
        }
    return {
        "chronology_quality": "input_order_fallback",
        "chronology_basis": (
            "classification_timestamps_invalid"
            if invalid_nonempty
            else "classification_timestamps_missing"
        ),
    }


def _safe_event_fields(event: Dict[str, Any]) -> Dict[str, Any]:
    allowed = {
        "eventid",
        "timestamp",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "session",
        "sensor",
        "protocol",
        "input",
        "username",
        "duration",
        "outfile",
        "destfile",
        "shasum",
        "arch",
        "hassh",
        "version",
    }
    result: Dict[str, Any] = {}
    for key, value in event.items():
        key_text = str(key)
        if key_text.lower() in SENSITIVE_EVENT_FIELDS:
            continue
        if key_text in allowed:
            result[key_text] = value
    return result


def _classification_nodes(classification_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    nodes: List[Dict[str, Any]] = []
    for index, event in enumerate(classification_events):
        command = _clean_text(event.get("command"))
        original_command = _clean_text(event.get("original_command"))
        ttp = main_ttp_id(event.get("ttp"))
        tactic = _clean_text(event.get("tactic"))
        nodes.append(
            {
                "node_id": f"classification:{index}",
                "type": "classification",
                "sequence_index": index,
                "command": command,
                "original_command": original_command,
                "ttp": ttp,
                "source_ttp": event.get("source_ttp") or event.get("source_subtechnique") or event.get("ttp"),
                "tactic": tactic,
                "confidence": event.get("confidence"),
                "source": event.get("source") or "unknown",
                "subcommand_index": event.get("subcommand_index"),
            }
        )
    return nodes


def _audit_only_classification_candidates(
    classification_events: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Retain weak classifier output without promoting it into graph facts."""

    candidates: List[Dict[str, Any]] = []
    for event in classification_events:
        if is_trusted_classification_event(event):
            continue
        candidates.append(
            {
                "evidence_id": _clean_text(event.get("evidence_id")),
                "command": _clean_text(event.get("command") or event.get("input")),
                "candidate_ttp": _clean_text(event.get("ttp")),
                "candidate_tactic": _clean_text(event.get("tactic")),
                "source": _clean_text(event.get("source") or "unknown"),
                "agreement_status": _clean_text(event.get("agreement_status")),
                "confidence": event.get("confidence"),
                "confidence_semantics": _clean_text(event.get("confidence_semantics")),
                "high_confidence": event.get("high_confidence"),
                "rule_policy_id": _clean_text(event.get("rule_policy_id")),
                "rule_policy_version": _clean_text(event.get("rule_policy_version")),
                "evidence_type": "audit_only_classification_candidate",
                "reason": classification_audit_reason(event),
                "excluded_from_strong_graph": True,
                "excluded_from_correlation": True,
            }
        )
    return candidates


def _command_nodes(commands: List[str]) -> List[Dict[str, Any]]:
    return [
        {
            "node_id": f"command:{index}",
            "type": "command",
            "sequence_index": index,
            "command": command,
        }
        for index, command in enumerate(commands)
    ]


def _event_nodes(raw_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    nodes: List[Dict[str, Any]] = []
    for index, event in enumerate(raw_events):
        eventid = _clean_text(event.get("eventid"))
        nodes.append(
            {
                "node_id": f"event:{index}",
                "type": "cowrie_event",
                "sequence_index": index,
                "eventid": eventid,
                "timestamp": event.get("timestamp"),
                "fields": _safe_event_fields(event),
            }
        )
    return nodes


def _observable_nodes(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    nodes: List[Dict[str, Any]] = []
    for index, (kind, value) in enumerate(iter_session_observables(payload)):
        nodes.append(
            {
                "node_id": f"observable:{kind}:{stable_id('obs', {'type': kind, 'value': value})[-12:]}",
                "type": "observable",
                "sequence_index": index,
                "observable_type": kind,
                "value": value,
            }
        )
    return nodes


def _edges(
    commands: List[str],
    classification_events: List[Dict[str, Any]],
    raw_events: List[Dict[str, Any]],
    observables: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    edges: List[Dict[str, Any]] = []
    classification_occurrences: Dict[str, int] = {}
    for index, event in enumerate(classification_events):
        original_command = _clean_text(event.get("original_command"))
        command = _clean_text(event.get("command"))
        target_command = original_command or command
        command_index = -1
        declared_index = event.get("compound_command_index")
        if (
            isinstance(declared_index, int)
            and 0 <= declared_index < len(commands)
            and commands[declared_index] == target_command
        ):
            command_index = declared_index
        else:
            start = classification_occurrences.get(target_command, 0)
            for candidate in range(start, len(commands)):
                if commands[candidate] == target_command:
                    command_index = candidate
                    classification_occurrences[target_command] = candidate + 1
                    break
        if command_index >= 0:
            edges.append(
                {
                    "source": f"command:{command_index}",
                    "target": f"classification:{index}",
                    "relation": "classified_as",
                }
            )
    raw_occurrences: Dict[str, int] = {}
    for index, event in enumerate(raw_events):
        eventid = _clean_text(event.get("eventid"))
        if eventid.startswith("cowrie.command."):
            command_text = _clean_text(event.get("input"))
            command_index = -1
            start = raw_occurrences.get(command_text, 0)
            for candidate in range(start, len(commands)):
                if commands[candidate] == command_text:
                    command_index = candidate
                    raw_occurrences[command_text] = candidate + 1
                    break
            if command_index >= 0:
                edges.append(
                    {
                        "source": f"event:{index}",
                        "target": f"command:{command_index}",
                        "relation": "emitted_command",
                    }
                )
    for node in observables:
        edges.append(
            {
                "source": "session",
                "target": node["node_id"],
                "relation": "observed_observable",
            }
        )
    return edges


def build_session_evidence_graph(
    session_payload: Dict[str, Any],
    *,
    behavior_policy_document: Optional[Dict[str, Any]] = None,
    behavior_policy_path: str = "",
) -> Dict[str, Any]:
    """Return a compact, safe graph of commands, events, labels, and observables."""

    commands = [
        _clean_text(command)
        for command in _as_list(session_payload.get("commands"))
        if _clean_text(command)
    ]
    all_classification_events = [
        dict(item)
        for item in _as_list(session_payload.get("classification_events"))
        if isinstance(item, dict)
    ]
    classification_events = [
        item for item in all_classification_events
        if is_trusted_classification_event(item)
    ]
    audit_only_candidates = _audit_only_classification_candidates(
        all_classification_events
    )
    raw_events = [
        dict(item)
        for item in _as_list(session_payload.get("raw_events"))
        if isinstance(item, dict)
    ]
    command_nodes = _command_nodes(commands)
    classification_nodes = _classification_nodes(classification_events)
    event_nodes = _event_nodes(raw_events)
    observable_nodes = _observable_nodes(session_payload)
    ttp_sequence = [
        main_ttp_id(item.get("ttp"))
        for item in classification_events
        if _clean_text(item.get("ttp")) and _clean_text(item.get("ttp")) != "unknown"
    ]
    tactic_sequence = [
        _clean_text(item.get("tactic"))
        for item in classification_events
        if _clean_text(item.get("tactic")) and _clean_text(item.get("tactic")) != "unknown"
    ]
    ordered_behavior_chain = _ordered_behavior_chain(classification_events)
    relationship_analysis = build_session_behavior_relationships({
        **session_payload,
        "classification_events": all_classification_events,
        "raw_events": raw_events,
    }, policy_document=behavior_policy_document, policy_path=behavior_policy_path)
    eventids = [
        _clean_text(item.get("eventid"))
        for item in raw_events
        if _clean_text(item.get("eventid"))
    ]
    chronology = _chronology_metadata(classification_events)
    login_failures = sum(1 for eventid in eventids if eventid == "cowrie.login.failed")
    graph = {
        "schema_version": SCHEMA_VERSION,
        "graph_id": stable_id(
            "egraph",
            {
                "session_id": session_payload.get("session_id", "unknown"),
                "commands": commands,
                "eventids": eventids,
                "ttps": ttp_sequence,
                "tactics": tactic_sequence,
            },
        ),
        "session_id": str(session_payload.get("session_id") or "unknown"),
        "generated_at": utc_now(),
        "nodes": [{"node_id": "session", "type": "session"}]
        + command_nodes
        + classification_nodes
        + event_nodes
        + observable_nodes,
        "audit_only_classification_candidates": audit_only_candidates,
        "behavior_policy": relationship_analysis["behavior_policy"],
        "ordered_behavior_chain": ordered_behavior_chain,
        "ordered_command_observations": relationship_analysis["ordered_command_observations"],
        "transfer_event_observations": relationship_analysis["transfer_event_observations"],
        "normalized_entities": relationship_analysis["normalized_entities"],
        "behavior_relationships": relationship_analysis["behavior_relationships"],
        "connected_behavior_chains": relationship_analysis["connected_behavior_chains"],
        "relationship_semantics": relationship_analysis["semantics"],
        **chronology,
        "edges": _edges(commands, classification_events, raw_events, observable_nodes),
        "sequences": {
            "commands": commands,
            "eventids": eventids,
            "ttps": ttp_sequence,
            "tactics": tactic_sequence,
        },
        "counts": {
            "commands": len(commands),
            "classification_events": len(classification_events),
            "ordered_behavior_chain": len(ordered_behavior_chain),
            "ordered_command_observations": len(relationship_analysis["ordered_command_observations"]),
            "normalized_entities": len(relationship_analysis["normalized_entities"]),
            "behavior_relationships": len(relationship_analysis["behavior_relationships"]),
            "connected_behavior_chains": len(relationship_analysis["connected_behavior_chains"]),
            "audit_only_classification_events": len(audit_only_candidates),
            "raw_events": len(raw_events),
            "observables": len(observable_nodes),
            "login_failures": login_failures,
            "chronology_quality": chronology["chronology_quality"],
        },
        "flags": {
            "has_commands": bool(commands),
            "has_login_success": bool(session_payload.get("login_success")),
            "has_login_failures": login_failures > 0,
            "has_file_transfer_event": any(eventid == "cowrie.session.file_download" for eventid in eventids),
            "has_upload_event": any(eventid == "cowrie.session.file_upload" for eventid in eventids),
            "has_command_and_control_tactic": "command-and-control" in tactic_sequence,
            "has_execution_tactic": "execution" in tactic_sequence,
            "has_credential_access_tactic": "credential-access" in tactic_sequence,
            "has_defense_evasion_tactic": "defense-evasion" in tactic_sequence,
        },
    }
    graph["summary"] = summarize_evidence_graph(graph)
    return graph


def summarize_evidence_graph(graph: Dict[str, Any]) -> Dict[str, Any]:
    sequences = graph.get("sequences") or {}
    counts = graph.get("counts") or {}
    flags = graph.get("flags") or {}
    return {
        "schema_version": "session_evidence_graph_summary.v1",
        "graph_id": graph.get("graph_id") or "",
        "session_id": graph.get("session_id") or "unknown",
        "command_count": counts.get("commands", 0),
        "classification_event_count": counts.get("classification_events", 0),
        "ordered_behavior_chain_count": counts.get("ordered_behavior_chain", 0),
        "ordered_command_observation_count": counts.get("ordered_command_observations", 0),
        "normalized_entity_count": counts.get("normalized_entities", 0),
        "behavior_relationship_count": counts.get("behavior_relationships", 0),
        "connected_behavior_chain_count": counts.get("connected_behavior_chains", 0),
        "audit_only_classification_event_count": counts.get(
            "audit_only_classification_events", 0
        ),
        "raw_event_count": counts.get("raw_events", 0),
        "observable_count": counts.get("observables", 0),
        "login_failure_count": counts.get("login_failures", 0),
        "ttp_sequence": _unique(sequences.get("ttps") or []),
        "tactic_sequence": _unique(sequences.get("tactics") or []),
        "eventid_sequence": _unique(sequences.get("eventids") or []),
        "last_trusted_tactic": _clean_text((graph.get("ordered_behavior_chain") or [{}])[-1].get("tactic")),
        "last_trusted_ttp": _clean_text((graph.get("ordered_behavior_chain") or [{}])[-1].get("ttp")),
        "evidence_flags": {k: v for k, v in flags.items() if v},
        "chronology_quality": graph.get("chronology_quality") or "not_available",
        "chronology_basis": graph.get("chronology_basis") or "",
    }
