"""Read-only command-to-session Model1 advisory, never an observed finding.

Only the selected per-command prediction is counted.  The source command text,
top-k alternatives, and uncalibrated margins are deliberately not copied here.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Mapping


_TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_EVIDENCE_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")
_USABLE = {"loaded", "predicted", "ok"}


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def summarize_session_model1_ttp(
    classification_events: Any, *, session_id: str
) -> dict[str, Any]:
    """Count distinct command events per selected TTP with bounded references.

    Rows without a stable command identity cannot safely be deduplicated and
    are excluded.  One compound command may support several TTPs, but never
    more than once per TTP.  No score in this projection is a probability.
    """

    expected = _text(session_id)
    if not expected:
        raise ValueError("session_id is required")
    seen_commands: set[str] = set()
    support: dict[str, dict[str, dict[str, str]]] = defaultdict(dict)
    excluded = 0
    for row in classification_events if isinstance(classification_events, list) else []:
        if not isinstance(row, Mapping):
            excluded += 1
            continue
        bound = _text(row.get("session_id"))
        if bound and bound != expected:
            excluded += 1
            continue
        # Cowrie emits command.input for the entered line and may emit a
        # command.failed/success event for that same line.  Those outcome
        # events remain classification evidence, but are not another command
        # vote.  Legacy rows without event provenance retain their old path.
        cowrie_eventid = _text(row.get("cowrie_eventid"))
        if cowrie_eventid and cowrie_eventid != "cowrie.command.input":
            excluded += 1
            continue
        prediction = row.get("s1_advisory")
        if not isinstance(prediction, Mapping):
            excluded += 1
            continue
        status = _text(prediction.get("status")).lower()
        if status and status not in _USABLE:
            excluded += 1
            continue
        score_type = _text(prediction.get("score_type"))
        if score_type and score_type != "linear_svc_decision_margin":
            excluded += 1
            continue
        technique = _text(prediction.get("predicted_technique")).upper()
        if not _TECHNIQUE.fullmatch(technique):
            excluded += 1
            continue
        command_index = row.get("compound_command_index")
        if isinstance(command_index, int) and not isinstance(command_index, bool) and command_index >= 0:
            command_key = f"index:{command_index}"
        else:
            event_id = _text(row.get("command_event_id") or row.get("source_event_id"))
            if not _EVIDENCE_ID.fullmatch(event_id):
                excluded += 1
                continue
            command_key = f"event:{event_id}"
        seen_commands.add(command_key)
        raw_evidence_id = _text(row.get("evidence_id"))
        evidence_id = raw_evidence_id if _EVIDENCE_ID.fullmatch(raw_evidence_id) else ""
        raw_timestamp = _text(row.get("event_timestamp"))
        observed_at = raw_timestamp if _TIMESTAMP.fullmatch(raw_timestamp) and len(raw_timestamp) <= 64 else ""
        support[technique].setdefault(command_key, {
            "command_ref": command_key,
            "evidence_id": evidence_id,
            "observed_at": observed_at,
        })
    ranked = sorted(support.items(), key=lambda item: (-len(item[1]), item[0]))
    return {
        "schema_version": "session_model1_ttp_advisory.v1",
        "session_id": expected,
        "authority": "ADVISORY_ONLY",
        "method": "distinct_command_event_count",
        "assessed_command_events": len(seen_commands),
        "excluded_classification_rows": excluded,
        "techniques": [
            {
                "technique_id": technique,
                "supporting_command_events": len(refs),
                "rank": index + 1,
                "evidence_refs": list(refs.values())[:100],
            }
            for index, (technique, refs) in enumerate(ranked)
        ],
        "is_confidence": False,
        "is_observed_finding": False,
    }
