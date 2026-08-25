"""Backend-neutral materialization for claimed durable job records."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, Dict


class JobMaterializationError(ValueError):
    """Raised when persisted job state cannot satisfy the domain contract."""


def _required(row: Mapping[str, Any], field: str) -> Any:
    if field not in row:
        raise JobMaterializationError(f"claimed job is missing {field}")
    return row[field]


def _payload_object(row: Mapping[str, Any]) -> Dict[str, Any]:
    raw = _required(row, "payload_json")
    if not isinstance(raw, str):
        raise JobMaterializationError("claimed job payload_json must be text")
    try:
        payload = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise JobMaterializationError("claimed job payload_json is malformed") from exc
    if not isinstance(payload, dict):
        raise JobMaterializationError("claimed job payload_json must contain an object")
    return payload


def materialize_analysis_job_claim(row: Mapping[str, Any]) -> Dict[str, Any]:
    """Return the logical analysis-job shape consumed by analysis workers."""

    return {
        "job_id": _required(row, "job_id"),
        "session_id": _required(row, "session_id"),
        "session": _payload_object(row),
        "attempts": _required(row, "attempts"),
        "claim_owner": _required(row, "claim_owner"),
        "claim_token": _required(row, "claim_token"),
        "claim_expires_at": _required(row, "claim_expires_at"),
    }


def materialize_ai_advisory_job_claim(row: Mapping[str, Any]) -> Dict[str, Any]:
    """Return the logical AI-advisory job shape consumed by its worker.

    Historical SQLite behavior exposes a malformed task as ``None`` so the
    worker can record a fenced terminal contract failure. Preserve that
    behavior across backends while keeping identity and lease metadata exact.
    """

    try:
        task: Dict[str, Any] | None = _payload_object(row)
    except JobMaterializationError:
        task = None
    return {
        "job_id": _required(row, "job_id"),
        "report_id": _required(row, "report_id"),
        "session_id": _required(row, "session_id"),
        "assessment_id": _required(row, "assessment_id"),
        "task": task,
        "attempts": _required(row, "attempts"),
        "claim_owner": _required(row, "claim_owner"),
        "claim_token": _required(row, "claim_token"),
        "claim_expires_at": _required(row, "claim_expires_at"),
    }
