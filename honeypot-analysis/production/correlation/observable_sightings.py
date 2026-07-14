"""Durable observable and sighting extraction helpers.

Enrichment answers "what do providers know about this observable?".
Sightings answer "where, when, and how did this system observe it?".
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse


URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")


def normalize_sighting_observable(observable_type: str, value: Any) -> Optional[Tuple[str, str, Dict[str, Any]]]:
    """Normalize an observable for durable sightings.

    Unlike enrichment cache keys, sightings keep private/lab IPs because they
    are still useful for test sessions and internal correlation.
    """
    kind = str(observable_type or "").strip().lower()
    raw = str(value or "").strip()
    if not raw:
        return None

    if kind in {"ipv4", "ipv6", "src_ip", "dst_ip"}:
        kind = "ip"
    elif kind in {"sha256", "sha1", "md5", "shasum"}:
        kind = "hash"

    metadata: Dict[str, Any] = {}
    if kind == "ip":
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            return None
        metadata.update(
            {
                "ip_version": ip.version,
                "is_private": ip.is_private,
                "is_loopback": ip.is_loopback,
                "is_public": ip.is_global,
            }
        )
        return "ip", str(ip), metadata

    if kind == "url":
        cleaned = raw.rstrip(".,;)]}")
        parsed = urlparse(cleaned)
        if not parsed.scheme or not parsed.netloc:
            return None
        metadata["domain"] = parsed.hostname or ""
        return "url", cleaned, metadata

    if kind == "domain":
        cleaned = raw.lower().strip(".")
        if "." not in cleaned:
            return None
        return "domain", cleaned, metadata

    if kind == "hash":
        cleaned = raw.lower()
        if len(cleaned) not in {32, 40, 64} or any(ch not in "0123456789abcdef" for ch in cleaned):
            return None
        metadata["hash_type"] = {32: "md5", 40: "sha1", 64: "sha256"}[len(cleaned)]
        return "hash", cleaned, metadata

    if kind in {"hassh", "ja3"}:
        return kind, raw.lower(), metadata

    return None


def _base_sighting(
    event: Dict[str, Any],
    event_id: str,
    sensor_id: str,
    observable_type: str,
    observable_value: str,
    role: str,
    source: str,
    metadata: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "observable_type": observable_type,
        "observable_value": observable_value,
        "role": role,
        "source": source,
        "session_id": str(event.get("session") or event.get("session_id") or "unknown"),
        "sensor_id": str(sensor_id or event.get("sensor") or ""),
        "src_ip": str(event.get("src_ip") or ""),
        "event_id": event_id,
        "eventid": str(event.get("eventid") or ""),
        "timestamp": str(event.get("timestamp") or ""),
        "payload": {
            "role": role,
            "source": source,
            "eventid": event.get("eventid") or "",
            "metadata": metadata,
        },
    }


def _add_sighting(
    sightings: List[Dict[str, Any]],
    event: Dict[str, Any],
    event_id: str,
    sensor_id: str,
    kind: str,
    value: Any,
    role: str,
    source: str,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    normalized = normalize_sighting_observable(kind, value)
    if not normalized:
        return
    observable_type, observable_value, metadata = normalized
    if extra:
        metadata.update(extra)
    sighting = _base_sighting(event, event_id, sensor_id, observable_type, observable_value, role, source, metadata)
    marker = (
        sighting["observable_type"],
        sighting["observable_value"],
        sighting["role"],
        sighting["event_id"],
        sighting["source"],
    )
    existing = {
        (item["observable_type"], item["observable_value"], item["role"], item.get("event_id", ""), item.get("source", ""))
        for item in sightings
    }
    if marker not in existing:
        sightings.append(sighting)


def extract_event_observable_sightings(
    event: Dict[str, Any],
    event_id: str = "",
    sensor_id: str = "",
) -> List[Dict[str, Any]]:
    sightings: List[Dict[str, Any]] = []
    _add_sighting(sightings, event, event_id, sensor_id, "ip", event.get("src_ip"), "source_ip", "cowrie_event")
    _add_sighting(sightings, event, event_id, sensor_id, "ip", event.get("dst_ip"), "destination_ip", "cowrie_event")
    _add_sighting(sightings, event, event_id, sensor_id, "hassh", event.get("hassh"), "ssh_fingerprint", "cowrie_event")
    _add_sighting(sightings, event, event_id, sensor_id, "ja3", event.get("ja3"), "tls_fingerprint", "cowrie_event")

    for field in ("shasum", "sha256", "sha1", "md5"):
        _add_sighting(sightings, event, event_id, sensor_id, "hash", event.get(field), "file_hash", "cowrie_event", {"field": field})

    text_parts = [
        str(event.get("input") or ""),
        str(event.get("message") or ""),
        str(event.get("url") or ""),
        str(event.get("destfile") or ""),
    ]
    text = " ".join(part for part in text_parts if part)
    for url in URL_RE.findall(text):
        _add_sighting(sightings, event, event_id, sensor_id, "url", url, "command_url", "cowrie_event")
        parsed = urlparse(url.rstrip(".,;)]}"))
        if parsed.hostname:
            _add_sighting(sightings, event, event_id, sensor_id, "domain", parsed.hostname, "command_domain", "cowrie_event")
    for hash_value in HASH_RE.findall(text):
        _add_sighting(sightings, event, event_id, sensor_id, "hash", hash_value, "command_hash", "cowrie_event")
    return sightings


def extract_session_observable_sightings(
    session_payload: Dict[str, Any],
    source: str = "session_close",
) -> List[Dict[str, Any]]:
    event = {
        "session": session_payload.get("session_id"),
        "src_ip": session_payload.get("src_ip"),
        "sensor": session_payload.get("sensor"),
        "timestamp": session_payload.get("updated_at") or session_payload.get("start_time") or "",
        "eventid": source,
    }
    sightings: List[Dict[str, Any]] = []
    sensor_id = str(session_payload.get("sensor") or "")
    _add_sighting(sightings, event, "", sensor_id, "ip", session_payload.get("src_ip"), "session_source_ip", source)
    _add_sighting(sightings, event, "", sensor_id, "hassh", session_payload.get("hassh"), "session_hassh", source)
    _add_sighting(sightings, event, "", sensor_id, "ja3", session_payload.get("ja3"), "session_ja3", source)

    ioc_summary = session_payload.get("ioc_summary") or {}
    for item in ioc_summary.get("ips") or []:
        if isinstance(item, dict):
            _add_sighting(sightings, event, "", sensor_id, item.get("type", "ip"), item.get("value"), "ioc_ip", source)
    for item in ioc_summary.get("urls") or []:
        if isinstance(item, dict):
            _add_sighting(sightings, event, "", sensor_id, "url", item.get("value"), "ioc_url", source)
    for item in ioc_summary.get("domains") or []:
        if isinstance(item, dict):
            _add_sighting(sightings, event, "", sensor_id, "domain", item.get("value"), "ioc_domain", source)
    for item in ioc_summary.get("hashes") or []:
        if isinstance(item, dict):
            _add_sighting(sightings, event, "", sensor_id, item.get("type", "hash"), item.get("value"), "ioc_hash", source)
    return sightings


def record_sightings(storage: Any, sightings: Iterable[Dict[str, Any]]) -> int:
    count = 0
    for sighting in sightings:
        storage.record_observable_sighting(sighting)
        count += 1
    return count
