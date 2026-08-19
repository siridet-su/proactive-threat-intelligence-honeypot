"""Build notebook-equivalent runtime context for a closed session."""

from __future__ import annotations

from typing import Any, Dict, List

from production.utils.cowrie_adapter import cowrie_to_events
from production.enrichment.ioc_extraction import extract_from_process_sessions
from production.utils.process_tree import parse_and_build_sessions, process_events_to_context


def attach_runtime_context(state: Any) -> Any:
    """Attach process tree, BPG, and IoC context to a SessionState-like object."""
    raw_events = list(getattr(state, "raw_events", []) or [])
    if not raw_events:
        setattr(state, "process_tree_status", {"status": "skipped", "reason": "no_raw_events"})
        setattr(state, "bpg_list", [])
        setattr(state, "ioc_summary", {"total": 0})
        return state

    process_events, session_meta, _ = cowrie_to_events(raw_events, honeypot_mode=True)
    context = process_events_to_context(process_events)
    process_sessions = parse_and_build_sessions(process_events)
    ioc_bundle = extract_from_process_sessions(process_sessions)

    setattr(state, "process_events", process_events)
    # ``session_metadata`` also carries the worker-authenticated provenance
    # boundary.  The Cowrie adapter's derived metadata must not replace those
    # server-owned fields at session close, otherwise a controlled synthetic
    # session could lose its exclusion marker just before report/prediction
    # guards run.  Preserve only the two private trusted keys; all other
    # runtime metadata remains adapter-derived as before.
    prior_metadata = getattr(state, "session_metadata", {})
    if isinstance(prior_metadata, dict) and isinstance(session_meta, dict):
        for key in ("_trusted_session_source", "_trusted_provenance_marker"):
            if key in prior_metadata:
                session_meta[key] = prior_metadata[key]
    setattr(state, "session_metadata", session_meta)
    setattr(state, "process_sessions_summary", context["process_sessions"])
    setattr(state, "bpg_list", context["bpg_list"])
    setattr(state, "ioc_summary", ioc_bundle.to_dict())
    setattr(
        state,
        "process_tree_status",
        {
            "status": "built",
            "process_event_count": len(process_events),
            "process_session_count": context["process_session_count"],
            "bpg_count": len(context["bpg_list"]),
            "ioc_count": len(ioc_bundle.all),
        },
    )
    return state


def attach_runtime_context_to_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    class _State:
        pass

    state = _State()
    for key, value in payload.items():
        setattr(state, key, value)
    attach_runtime_context(state)
    for key in (
        "process_events",
        "session_metadata",
        "process_sessions_summary",
        "bpg_list",
        "ioc_summary",
        "process_tree_status",
    ):
        if hasattr(state, key):
            payload[key] = getattr(state, key)
    return payload
