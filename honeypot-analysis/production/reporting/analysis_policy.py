from __future__ import annotations

from typing import Any, Dict, Iterable


def _has_nonempty_value(values: Iterable[Any]) -> bool:
    return any(str(value).strip() for value in values if value is not None)


def session_analysis_skip_reason(session_payload: Dict[str, Any]) -> str:
    """Return a stable skip reason when a closed session has no reportable action."""
    commands = session_payload.get("commands") or []
    login_success = bool(session_payload.get("login_success"))
    if not _has_nonempty_value(commands) and not login_success:
        return "no_commands"
    return ""


def session_outcome_label(session_payload: Dict[str, Any]) -> str:
    """Classify how far a session got for prediction/backtest filtering."""
    commands = session_payload.get("commands") or []
    has_commands = _has_nonempty_value(commands)
    login_success = bool(session_payload.get("login_success"))
    is_ended = bool(session_payload.get("is_ended")) or str(session_payload.get("status") or "") == "closed"

    if not is_ended:
        return "active"
    if not has_commands and not login_success:
        return "scanner_no_command"
    if not has_commands and login_success:
        return "login_only"
    if has_commands:
        return "completed"
    return "unknown"


def mark_session_outcome(session_payload: Dict[str, Any]) -> Dict[str, Any]:
    session_payload["session_outcome"] = session_outcome_label(session_payload)
    return session_payload


def mark_session_analysis_skipped(session_payload: Dict[str, Any], reason: str) -> Dict[str, Any]:
    session_payload["analysis_status"] = "skipped"
    session_payload["analysis_skip_reason"] = reason
    return session_payload


def mark_session_analysis_queued(session_payload: Dict[str, Any], job_id: str) -> Dict[str, Any]:
    session_payload["analysis_status"] = "queued"
    session_payload["analysis_job_id"] = job_id
    session_payload.pop("analysis_skip_reason", None)
    return session_payload
