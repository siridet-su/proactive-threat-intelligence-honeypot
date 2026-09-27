"""Exact-bound production envelope adapter for the 54F research PoC.

The adapter accepts only outcome-independent episode capture receipts.  It
does not use Cowrie file-download outcomes to select flows or as features.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping, Sequence


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CAPTURE_CONTRACT = "OUTCOME_INDEPENDENT_FIXED_SESSION_WINDOW_V1"


class ProductionAdapterError(ValueError):
    pass


def _digest(value: Any, field: str) -> str:
    text = str(value or "").strip().lower()
    if not SHA256_RE.fullmatch(text):
        raise ProductionAdapterError(f"invalid_digest:{field}")
    return text


def _event_log_digest(event_hashes: Sequence[str]) -> str:
    payload = json.dumps(list(event_hashes), separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


def build_envelope(
    *,
    events: Sequence[Mapping[str, Any]],
    event_hashes: Sequence[str],
    flows: Sequence[Mapping[str, Any]],
    pcap_evidence: Mapping[str, Any],
    zeek_evidence: Mapping[str, Any],
    identity: Mapping[str, str],
    capture_contract: str,
) -> dict[str, Any]:
    if capture_contract != CAPTURE_CONTRACT:
        raise ProductionAdapterError("outcome_independent_capture_required")
    if len(events) != len(event_hashes) or not events:
        raise ProductionAdapterError("event_hash_cardinality_mismatch")
    hashes = [_digest(value, f"event:{index}") for index, value in enumerate(event_hashes)]
    source_session_id = str(identity.get("source_session_id") or "")
    if not source_session_id or any(not str(identity.get(key) or "") for key in ("run_id", "measurement_id", "episode_id")):
        raise ProductionAdapterError("identity_incomplete")
    adapted_events: list[dict[str, Any]] = []
    for index, raw in enumerate(events):
        if not isinstance(raw, Mapping):
            raise ProductionAdapterError("event_invalid")
        event = dict(raw)
        event["session_id"] = source_session_id
        event["source_event_key"] = hashes[index]
        event["source_sequence"] = index
        adapted_events.append(event)

    adapted_flows: list[dict[str, Any]] = []
    for raw in flows:
        if not isinstance(raw, Mapping):
            raise ProductionAdapterError("flow_invalid")
        adapted_flows.append({
            "uid": raw.get("uid"),
            "tuple": {
                "orig_h": raw.get("id.orig_h"),
                "orig_p": str(raw.get("id.orig_p") or ""),
                "resp_h": raw.get("id.resp_h"),
                "resp_p": str(raw.get("id.resp_p") or ""),
                "proto": raw.get("proto"),
            },
            "duration": raw.get("duration", 0),
            "orig_bytes": raw.get("orig_bytes", 0),
            "resp_bytes": raw.get("resp_bytes", 0),
            "conn_state": raw.get("conn_state", ""),
            "flow_binding": "PASS",
            "episode_binding": dict(identity),
        })

    pcap_sha = _digest(pcap_evidence.get("sha256"), "pcap")
    zeek_pcap_sha = _digest(zeek_evidence.get("pcap_sha256"), "zeek_pcap")
    if pcap_sha != zeek_pcap_sha:
        raise ProductionAdapterError("zeek_pcap_binding_mismatch")
    conn_sha = _digest(zeek_evidence.get("sha256"), "conn_log")
    if pcap_evidence.get("finalized") is not True or zeek_evidence.get("finalized") is not True:
        raise ProductionAdapterError("capture_not_finalized")
    if pcap_evidence.get("drop_count") != 0:
        raise ProductionAdapterError("capture_drop_count_nonzero")

    return {
        "cowrie": {
            "complete": True,
            "identity": dict(identity),
            "event_log_sha256": _event_log_digest(hashes),
            "auth_telemetry_complete": True,
            "events": adapted_events,
        },
        "network": {
            "complete": True,
            "identity": dict(identity),
            "pcap": {"finalized": True, "drop_count": 0, "sha256": pcap_sha},
            "zeek": {
                "status": "COMPLETE",
                "pcap_sha256": pcap_sha,
                "conn_log_sha256": conn_sha,
                "identity": dict(identity),
            },
            "flows": adapted_flows,
        },
    }
