"""Build a compact evidence graph for session-level reasoning.

The command classifier produces command-level labels. This module normalizes
the broader session evidence into a graph-like JSON structure so correlation
and future knowledge-pack importers can reason over the same stable contract.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

from production.classification.trust import (
    classification_audit_reason,
    is_trusted_classification_event,
)
from production.enrichment.enrichment_cache import iter_session_observables
from production.utils.serialization import stable_id, utc_now
from production.correlation.session_ttp_knowledge import main_ttp_id


SCHEMA_VERSION = "session_evidence_graph.v1"

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
                "command": _clean_text(event.get("command") or event.get("input")),
                "candidate_ttp": _clean_text(event.get("ttp")),
                "candidate_tactic": _clean_text(event.get("tactic")),
                "source": _clean_text(event.get("source") or "unknown"),
                "confidence": event.get("confidence"),
                "high_confidence": event.get("high_confidence"),
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
    for index, event in enumerate(classification_events):
        original_command = _clean_text(event.get("original_command"))
        command = _clean_text(event.get("command"))
        target_command = original_command or command
        try:
            command_index = commands.index(target_command)
        except ValueError:
            command_index = -1
        if command_index >= 0:
            edges.append(
                {
                    "source": f"command:{command_index}",
                    "target": f"classification:{index}",
                    "relation": "classified_as",
                }
            )
    for index, event in enumerate(raw_events):
        eventid = _clean_text(event.get("eventid"))
        if eventid.startswith("cowrie.command."):
            command_text = _clean_text(event.get("input"))
            if command_text in commands:
                edges.append(
                    {
                        "source": f"event:{index}",
                        "target": f"command:{commands.index(command_text)}",
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


def build_session_evidence_graph(session_payload: Dict[str, Any]) -> Dict[str, Any]:
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
    eventids = [
        _clean_text(item.get("eventid"))
        for item in raw_events
        if _clean_text(item.get("eventid"))
    ]
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
            "audit_only_classification_events": len(audit_only_candidates),
            "raw_events": len(raw_events),
            "observables": len(observable_nodes),
            "login_failures": login_failures,
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
        "audit_only_classification_event_count": counts.get(
            "audit_only_classification_events", 0
        ),
        "raw_event_count": counts.get("raw_events", 0),
        "observable_count": counts.get("observables", 0),
        "login_failure_count": counts.get("login_failures", 0),
        "ttp_sequence": _unique(sequences.get("ttps") or []),
        "tactic_sequence": _unique(sequences.get("tactics") or []),
        "eventid_sequence": _unique(sequences.get("eventids") or []),
        "evidence_flags": {k: v for k, v in flags.items() if v},
    }
