"""Minimal trusted-classification features for explicit VOMM rollback."""

from __future__ import annotations

import math
from typing import Any, Dict, Optional

from production.classification.trust import is_trusted_classification_event
from production.correlation.session_ttp_knowledge import main_ttp_id
from production.utils.sensitive_data import redact_for_session_state
from production.utils.serialization import session_to_payload, stable_id


def _ordered_unique(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value != "unknown" and value not in result:
            result.append(value)
    return result


def _adjacent_deduplicate(values: list[str]) -> list[str]:
    return [
        value
        for index, value in enumerate(values)
        if index == 0 or values[index - 1] != value
    ]


def build_session_features(
    session: Any,
    current_event: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return only fields consumed by the validated hard-backoff VOMM.

    Correlation, enrichment, actor fingerprints, command text, heuristics, and
    timing features are deliberately excluded because the rollback ranker has
    no supported path for them.
    """

    raw = dict(session) if isinstance(session, dict) else session_to_payload(session)
    payload = redact_for_session_state(raw)
    if not isinstance(payload, dict):
        raise TypeError("session feature input redaction must return an object")
    events = [
        dict(item)
        for item in payload.get("classification_events") or []
        if isinstance(item, dict)
    ]
    trusted = [item for item in events if is_trusted_classification_event(item)]
    tactics = _adjacent_deduplicate(
        [
            str(item.get("tactic") or "").strip()
            for item in trusted
            if str(item.get("tactic") or "").strip() not in {"", "unknown"}
        ]
    )
    techniques = _adjacent_deduplicate(
        [
            main_ttp_id(item.get("ttp") or item.get("technique"))
            for item in trusted
            if main_ttp_id(item.get("ttp") or item.get("technique"))
            not in {"", "unknown"}
        ]
    )
    if not events:
        tactics = _adjacent_deduplicate(
            [
                str(item or "").strip()
                for item in payload.get("tactics") or []
                if str(item or "").strip() not in {"", "unknown"}
            ]
        )
        techniques = _adjacent_deduplicate(
            [
                main_ttp_id(item)
                for item in payload.get("ttps") or []
                if main_ttp_id(item) not in {"", "unknown"}
            ]
        )

    confidences: list[float] = []
    for item in trusted:
        try:
            value = float(item.get("confidence"))
        except (TypeError, ValueError):
            continue
        confidences.append(min(max(value, 0.0), 1.0))
    if confidences:
        geomean = math.exp(
            sum(math.log(max(value, 0.0001)) for value in confidences)
            / len(confidences)
        )
        available = True
    else:
        geomean = 1.0 if trusted else 0.0
        available = False

    features: Dict[str, Any] = {
        "schema_version": "vomm_rollback_features.v1",
        "session_id": str(payload.get("session_id") or "unknown"),
        "src_ip": str(payload.get("src_ip") or "unknown"),
        "status": str(
            payload.get("status")
            or ("closed" if payload.get("is_ended") else "active")
        ),
        "classification_events": trusted,
        "classification_event_count": len(events),
        "trusted_classification_event_count": len(trusted),
        "observed_tactics": _ordered_unique(tactics),
        "observed_ttps": _ordered_unique(techniques),
        "correlated_tactics": [],
        "correlated_ttps": [],
        "tactic_sequence": tactics,
        "ttp_sequence": techniques,
        "last_tactic": tactics[-1] if tactics else "",
        "last_ttp": techniques[-1] if techniques else "",
        "classification_confidence_available": available,
        "classification_chain_confidence_geomean": round(geomean, 4),
    }
    features["features_hash"] = stable_id("features", features)
    return features
