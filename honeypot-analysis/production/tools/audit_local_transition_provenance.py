"""Compare local-transition training data before and after provenance filtering."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from copy import deepcopy
from typing import Any, Dict, Iterable, List

from production.prediction.realtime_prediction import build_transition_model
from production.storage import open_storage, safe_database_label
from production.storage.session_provenance import SESSION_SOURCE_PRODUCTION_LIVE


def _decode_payload(row: Dict[str, Any]) -> Dict[str, Any]:
    raw = row.get("payload_json")
    if isinstance(raw, dict):
        payload = dict(raw)
    else:
        try:
            parsed = json.loads(str(raw or "{}"))
        except json.JSONDecodeError:
            return {}
        payload = parsed if isinstance(parsed, dict) else {}
    payload.setdefault("session_source", row.get("session_source") or "")
    return payload


def _payloads(rows: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [payload for row in rows for payload in [_decode_payload(row)] if payload]


def _compact_model(model: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "completed_sessions": model.get("completed_sessions", 0),
        "usable_sessions": model.get("usable_sessions", 0),
        "classification_event_count": model.get("classification_event_count", 0),
        "trusted_classification_event_count": model.get("trusted_classification_event_count", 0),
        "audit_only_classification_event_count": model.get("audit_only_classification_event_count", 0),
        "transition_count": model.get("transition_count", 0),
        "prefix_transition_count": model.get("prefix_transition_count", 0),
        "technique_transition_count": model.get("technique_transition_count", 0),
        "transition_keys": len(model.get("transitions") or {}),
        "prefix_transition_keys": len(model.get("prefix_transitions") or {}),
        "technique_transition_keys": len(model.get("technique_transitions") or {}),
    }


def _legacy_unfiltered_payloads(payloads: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Reconstruct the former all-label sequence behavior for impact auditing."""
    output: List[Dict[str, Any]] = []
    for payload in payloads:
        copied = deepcopy(payload)
        events = []
        for event in copied.get("classification_events") or []:
            if not isinstance(event, dict):
                continue
            item = dict(event)
            if item.get("ttp") or item.get("tactic"):
                item["source"] = "legacy_unfiltered_audit"
                item["high_confidence"] = True
            events.append(item)
        copied["classification_events"] = events
        output.append(copied)
    return output


def _top_transitions(model: Dict[str, Any], limit: int = 10) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for current, next_counts in (model.get("transitions") or {}).items():
        if not isinstance(next_counts, dict):
            continue
        for next_tactic, count in next_counts.items():
            rows.append(
                {
                    "current": current,
                    "next": next_tactic,
                    "count": count,
                }
            )
    return sorted(rows, key=lambda item: float(item["count"]), reverse=True)[: max(limit, 0)]


def build_audit(database_url: str, limit: int = 5000, prefix_max_length: int = 3) -> Dict[str, Any]:
    storage = open_storage(database_url)
    database_label = safe_database_label(database_url)
    all_rows = storage.list_session_rows(limit=limit, session_source=None) if hasattr(storage, "list_session_rows") else storage.list_rows("sessions", limit=limit)
    live_rows = storage.list_session_rows(limit=limit, session_source=SESSION_SOURCE_PRODUCTION_LIVE) if hasattr(storage, "list_session_rows") else [
        row for row in all_rows if str(row.get("session_source") or "") == SESSION_SOURCE_PRODUCTION_LIVE
    ]
    live_external_rows = storage.list_session_rows(
        limit=limit,
        session_source=SESSION_SOURCE_PRODUCTION_LIVE,
        external_only=True,
    ) if hasattr(storage, "list_session_rows") else [
        row
        for row in live_rows
        if bool(row.get("is_external_source"))
    ]
    source_counts = Counter(str(row.get("session_source") or "unknown_legacy") for row in all_rows)
    external_counts = Counter(bool(row.get("is_external_source")) for row in live_rows)
    all_payloads = _payloads(all_rows)
    live_payloads = _payloads(live_rows)
    live_external_payloads = _payloads(live_external_rows)
    all_model = build_transition_model(
        all_payloads,
        prefix_max_length=prefix_max_length,
        source_name="local_transition_all_session_sources_audit",
        source_database=database_label,
    )
    live_model = build_transition_model(
        live_payloads,
        prefix_max_length=prefix_max_length,
        source_name="local_transition_production_live_audit",
        source_database=database_label,
    )
    live_external_model = build_transition_model(
        live_external_payloads,
        prefix_max_length=prefix_max_length,
        source_name="local_transition_production_live_external_audit",
        source_database=database_label,
    )
    all_compact = _compact_model(all_model)
    live_compact = _compact_model(live_model)
    live_external_compact = _compact_model(live_external_model)
    legacy_all_model = build_transition_model(
        _legacy_unfiltered_payloads(all_payloads),
        prefix_max_length=prefix_max_length,
        source_name="legacy_unfiltered_all_session_sources_audit",
        source_database=database_label,
    )
    legacy_live_external_model = build_transition_model(
        _legacy_unfiltered_payloads(live_external_payloads),
        prefix_max_length=prefix_max_length,
        source_name="legacy_unfiltered_production_live_external_audit",
        source_database=database_label,
    )
    legacy_all_compact = _compact_model(legacy_all_model)
    legacy_live_external_compact = _compact_model(legacy_live_external_model)
    return {
        "schema_version": "local_transition_provenance_audit.v1",
        "database_url": database_label,
        "session_source_counts": dict(sorted(source_counts.items())),
        "production_live_external_source_counts": {
            str(key).lower(): value for key, value in sorted(external_counts.items())
        },
        "all_session_sources": all_compact,
        "production_live_only": live_compact,
        "production_live_external_only": live_external_compact,
        "legacy_unfiltered_all_session_sources": legacy_all_compact,
        "legacy_unfiltered_production_live_external": legacy_live_external_compact,
        "delta_legacy_unfiltered_minus_trusted_all": {
            key: legacy_all_compact.get(key, 0) - all_compact.get(key, 0)
            for key in all_compact
        },
        "delta_legacy_unfiltered_minus_trusted_live_external": {
            key: legacy_live_external_compact.get(key, 0) - live_external_compact.get(key, 0)
            for key in live_external_compact
        },
        "delta_all_minus_production_live": {
            key: all_compact.get(key, 0) - live_compact.get(key, 0)
            for key in all_compact
        },
        "delta_production_live_minus_external": {
            key: live_compact.get(key, 0) - live_external_compact.get(key, 0)
            for key in live_compact
        },
        "top_all_transitions": _top_transitions(all_model),
        "top_production_live_transitions": _top_transitions(live_model),
        "top_production_live_external_transitions": _top_transitions(live_external_model),
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit local-transition impact of session_source filtering.")
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--limit", type=int, default=5000)
    parser.add_argument("--prefix-max-length", type=int, default=3)
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    print(json.dumps(build_audit(args.database_url, args.limit, args.prefix_max_length), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
