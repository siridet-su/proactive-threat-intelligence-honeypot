"""Cached enrichment helpers shared by session, analysis, and worker services."""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, Iterable, Iterator, Optional, Tuple
from urllib.parse import urlparse

from production.enrichment.enrichment_mapping import load_enrichment_db


SUPPORTED_OBSERVABLES = {"ip", "url", "domain", "hash", "hassh", "ja3"}


def normalize_observable(observable_type: str, value: Any) -> Optional[Tuple[str, str]]:
    """Normalize an observable into a durable cache key."""
    kind = str(observable_type or "").strip().lower()
    raw = str(value or "").strip()
    if not raw:
        return None

    if kind in {"ipv4", "ipv6", "src_ip"}:
        kind = "ip"
    elif kind in {"sha256", "sha1", "md5"}:
        kind = "hash"

    if kind == "ip":
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            return None
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            return None
        return "ip", str(ip)

    if kind == "url":
        parsed = urlparse(raw)
        if not parsed.scheme or not parsed.netloc:
            return None
        return "url", raw

    if kind == "domain":
        cleaned = raw.lower().strip(".")
        if "." not in cleaned:
            return None
        return "domain", cleaned

    if kind == "hash":
        cleaned = raw.lower()
        if len(cleaned) not in {32, 40, 64} or any(ch not in "0123456789abcdef" for ch in cleaned):
            return None
        return "hash", cleaned

    if kind in {"hassh", "ja3"}:
        return kind, raw.lower()

    return None


def iter_session_observables(payload: Dict[str, Any]) -> Iterator[Tuple[str, str]]:
    """Yield unique observables from a serialized SessionState payload."""
    seen = set()

    def emit(kind: str, value: Any) -> Iterator[Tuple[str, str]]:
        normalized = normalize_observable(kind, value)
        if normalized and normalized not in seen:
            seen.add(normalized)
            yield normalized

    yield from emit("ip", payload.get("src_ip"))
    yield from emit("hassh", payload.get("hassh"))
    yield from emit("ja3", payload.get("ja3"))

    ioc_summary = payload.get("ioc_summary") or {}
    for item in ioc_summary.get("ips", []) or []:
        yield from emit(item.get("type", "ip"), item.get("value"))
    for item in ioc_summary.get("urls", []) or []:
        yield from emit("url", item.get("value"))
    for item in ioc_summary.get("domains", []) or []:
        yield from emit("domain", item.get("value"))
    for item in ioc_summary.get("hashes", []) or []:
        yield from emit(item.get("type", "hash"), item.get("value"))


def enqueue_event_observables(storage: Any, event: Dict[str, Any], enabled: bool = True) -> int:
    """Queue fast event-level observables without blocking event processing."""
    if not enabled:
        return 0
    count = 0
    for kind, value in (("ip", event.get("src_ip")),):
        normalized = normalize_observable(kind, value)
        if not normalized:
            continue
        storage.enqueue_enrichment_job(
            normalized[0],
            normalized[1],
            session_id=str(event.get("session", "")),
            payload={"source": "event", "eventid": event.get("eventid", "")},
        )
        count += 1
    return count


def enqueue_session_observables(storage: Any, session_payload: Dict[str, Any], enabled: bool = True) -> int:
    """Queue all observables extracted from a closed session."""
    if not enabled:
        return 0
    count = 0
    session_id = str(session_payload.get("session_id", ""))
    for kind, value in iter_session_observables(session_payload):
        storage.enqueue_enrichment_job(
            kind,
            value,
            session_id=session_id,
            payload={"source": "session_close", "session_id": session_id},
        )
        count += 1
    return count


def load_combined_ip_enrichment(
    storage: Any = None,
    file_path: str = "",
    allow_stale: bool = True,
) -> Dict[str, Dict[str, Any]]:
    """
    Load IP enrichment from the legacy JSON file and durable storage cache.

    File data is loaded first for notebook/demo compatibility. Storage records
    then override the same IP when a fresher production enrichment record exists.
    """
    merged: Dict[str, Dict[str, Any]] = {}
    if file_path:
        merged.update(load_enrichment_db(file_path))
    if storage is not None:
        merged.update(storage.load_enrichment_cache("ip", allow_stale=allow_stale))
    return merged


def summarize_cache_hit(cache: Dict[str, Dict[str, Any]], src_ip: str) -> Dict[str, Any]:
    if not cache:
        return {"status": "missing", "source": "none"}
    record = cache.get(src_ip)
    if not record:
        return {"status": "missing", "source": "enrichment_cache"}
    cache_meta = record.get("enrichment_cache", {})
    return {
        "status": cache_meta.get("status", "available"),
        "source": cache_meta.get("source", "enrichment_cache"),
        "expires_at": cache_meta.get("expires_at"),
        "providers": sorted((record.get("provider_status") or {}).keys()),
    }
