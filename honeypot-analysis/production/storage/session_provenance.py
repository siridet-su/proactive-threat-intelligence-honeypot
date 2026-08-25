from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, Iterable


SESSION_SOURCE_PRODUCTION_LIVE = "production_live"
SESSION_SOURCE_E2E_TEST = "e2e_test"
SESSION_SOURCE_SEED_DATA = "seed_data"
SESSION_SOURCE_DEMO_FIXTURE = "demo_fixture"
SESSION_SOURCE_UNKNOWN_LEGACY = "unknown_legacy"

VALID_SESSION_SOURCES = {
    SESSION_SOURCE_PRODUCTION_LIVE,
    SESSION_SOURCE_E2E_TEST,
    SESSION_SOURCE_SEED_DATA,
    SESSION_SOURCE_DEMO_FIXTURE,
    SESSION_SOURCE_UNKNOWN_LEGACY,
}

_SEED_RE = re.compile(r"(sme-auto-evidence-seed|external-shrink-grid|external-seed|seed-)", re.I)
_E2E_RE = re.compile(r"(controlled-test|codex-|tailscale-test|public-map-test|e2e)", re.I)
_DEMO_RE = re.compile(
    r"(^cs\d|smoke|demo|fixture|ai-hypo|ai-report|trusted-reco|deploy-|maturity-|"
    r"prediction-trigger|compound-health|scalable-|main-ttp|ttp-source|hunt-flow|"
    r"status-sync|evidence-layer|^systemd-|^tail-|^pi-live-test)",
    re.I,
)


def normalize_session_source(value: Any, default: str = SESSION_SOURCE_UNKNOWN_LEGACY) -> str:
    text = str(value or "").strip().lower()
    return text if text in VALID_SESSION_SOURCES else default


def _is_global_ip(value: Any) -> bool:
    try:
        return ipaddress.ip_address(str(value or "")).is_global
    except ValueError:
        return False


def is_external_source_ip(value: Any) -> bool:
    """Return true only for globally routable source addresses.

    This deliberately excludes RFC1918, loopback/link-local, and CGNAT
    addresses such as Tailscale's 100.64.0.0/10 range.
    """

    return _is_global_ip(value)


def infer_legacy_session_source(row: Dict[str, Any], payload: Dict[str, Any] | None = None) -> str:
    """Conservatively classify legacy sessions for backfill.

    The goal is exclusion-safe provenance, not optimistic recovery of every
    possible real session. Only post-fix public sessions that are not known test
    traffic become `production_live`; ambiguous historical rows stay
    `unknown_legacy`.
    """

    payload = payload or {}
    existing = normalize_session_source(
        row.get("session_source") or payload.get("session_source"),
        default="",
    )
    if existing and existing != SESSION_SOURCE_UNKNOWN_LEGACY:
        return existing

    session_id = str(row.get("session_id") or payload.get("session_id") or "")
    src_ip = str(row.get("src_ip") or payload.get("src_ip") or "")
    start_time = str(row.get("start_time") or payload.get("start_time") or "")

    if _SEED_RE.search(session_id):
        return SESSION_SOURCE_SEED_DATA
    if _E2E_RE.search(session_id):
        return SESSION_SOURCE_E2E_TEST
    if _DEMO_RE.search(session_id):
        return SESSION_SOURCE_DEMO_FIXTURE
    if not _is_global_ip(src_ip):
        return SESSION_SOURCE_UNKNOWN_LEGACY

    if start_time >= "2026-07-06T17:41:00":
        return SESSION_SOURCE_PRODUCTION_LIVE

    return SESSION_SOURCE_UNKNOWN_LEGACY


def production_live_payloads(rows: Iterable[Dict[str, Any]]) -> list[Dict[str, Any]]:
    return [
        row
        for row in rows
        if normalize_session_source(row.get("session_source")) == SESSION_SOURCE_PRODUCTION_LIVE
    ]
