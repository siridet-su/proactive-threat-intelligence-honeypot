from __future__ import annotations

import dataclasses
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def to_jsonable(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return to_jsonable(dataclasses.asdict(value))
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(v) for v in value]
    return value


def stable_json(value: Any) -> str:
    return json.dumps(to_jsonable(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def stable_id(prefix: str, value: Any) -> str:
    digest = hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()
    return f"{prefix}_{digest[:32]}"


def event_id(sensor_id: str, event: Dict[str, Any]) -> str:
    return stable_id("evt", {"sensor_id": sensor_id, "event": event})


def session_to_payload(state: Any) -> Dict[str, Any]:
    payload = to_jsonable(state)
    payload.setdefault("session_id", getattr(state, "session_id", "unknown"))
    payload.setdefault("src_ip", getattr(state, "src_ip", "unknown"))
    payload.setdefault("is_ended", getattr(state, "is_ended", False))
    return payload


def _clean_command_list(values: Iterable[Any]) -> List[str]:
    return [str(value or "").strip() for value in values or [] if str(value or "").strip()]


def command_observation_provenance(
    commands: Iterable[Any],
    commands_success: Iterable[Any] | None = None,
    commands_failed: Iterable[Any] | None = None,
) -> Dict[str, Any]:
    """Describe command input and explicit command-outcome evidence.

    Cowrie reliably emits ``cowrie.command.input`` when an interactive command
    is entered. It does not always emit an explicit success/failure outcome for
    that command. Reports should therefore distinguish "command was observed"
    from "command outcome was observed" instead of silently counting unknown
    outcomes as failures.
    """
    observed = _clean_command_list(commands)
    success = _clean_command_list(commands_success)
    failed = _clean_command_list(commands_failed)
    explicit_outcomes = len(success) + len(failed)
    unknown = max(len(observed) - explicit_outcomes, 0)
    has_explicit_outcome = explicit_outcomes > 0
    return {
        "command_count": len(observed),
        "command_input_count": len(observed),
        "successful_command_count": len(success) if has_explicit_outcome else None,
        "failed_command_count": len(failed) if has_explicit_outcome else None,
        "unknown_command_outcome_count": unknown,
        "command_outcome_observed": has_explicit_outcome,
        "command_outcome_semantics": (
            "command_input_count counts Cowrie command.input events. "
            "successful_command_count and failed_command_count are only populated "
            "when Cowrie provides explicit command success/failure metadata."
        ),
    }
