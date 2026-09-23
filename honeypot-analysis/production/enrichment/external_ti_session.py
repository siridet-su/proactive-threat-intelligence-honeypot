"""Bounded, read-only external TI session projection and exact joins."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from production.enrichment.external_ti_contract import (
    EXTERNAL_TI_AUTHORITY,
    EXTERNAL_TI_EVIDENCE_SCHEMA,
    FINDING_STATES,
    KNOWN_ENDPOINTS,
    KNOWN_PROVIDERS,
    SOURCE_IP_ENRICHMENT_MODE,
    SOURCE_IP_POLICY_ID,
    SOURCE_IP_POLICY_VERSION,
    SOURCE_IP_PRODUCTION_POLICY_VERSIONS,
    build_external_ti_evidence,
    default_external_ti_provider_configs,
    evaluate_outbound_sighting,
    load_source_ip_governance_amendment,
    parse_source_ip_cutoff_utc,
    provider_config,
)
from production.enrichment.enrichment_cache import (
    SOURCE_IP_CACHE_PROVIDERS,
    SOURCE_IP_CACHE_AUTHORITY,
    SourceIPCacheService,
    SourceIPCacheUnavailable,
    source_ip_cache_session_projection,
)
from production.correlation.observable_sightings import normalize_sighting_observable
from production.utils.serialization import stable_id, stable_json, utc_now


SESSION_TI_SCHEMA = "monitor.session_external_ti.v1"
MAX_SIGHTINGS = 100
MAX_OBSERVABLES = 50
MAX_EVIDENCE = 50
MAX_SHARED_ENTITIES = 20
MAX_LINKED_SESSIONS = 20

# Read-side ETI projections are intentionally separate contracts.  They reuse
# the durable observable_sightings/enrichment/cache stores and never add a
# collection, provider, score, or canonical write path.
SOURCE_IP_CROSS_SESSION_SCHEMA = "monitor.source_ip_cross_session.v1"
OBSERVABLE_TI_SCHEMA = "monitor.observable_external_ti.v1"
MAX_PIVOT_SESSIONS = 20
MAX_PIVOT_SIGHTINGS = 500
MAX_OBSERVABLE_LOOKUP_SIGHTINGS = 100
SUPPORTED_OBSERVABLE_LOOKUP_TYPES = frozenset({"ip", "hash"})
# Public contract alias used by diagnostics and callers that do not need to
# distinguish lookup from the broader extractor's observable vocabulary.
SUPPORTED_OBSERVABLE_TYPES = SUPPORTED_OBSERVABLE_LOOKUP_TYPES
SOURCE_IP_RELATION_ROLES = frozenset({"source_ip", "session_source_ip"})

# ``status`` is retained as the stable coarse compatibility field used by
# existing callers.  ``status_reason`` is the bounded read-model explanation
# that prevents "pending" from being mistaken for one undifferentiated state.
TI_STATUS_REASON_TEXT = {
    "PROVIDER_EVIDENCE_AVAILABLE": "A stored provider result is available as non-authoritative context.",
    "NO_ELIGIBLE_OBSERVABLE": "No hash or policy-authorized source-IP observable was eligible for lookup.",
    "NO_STORED_PROVIDER_RESULT": "An eligible observable exists, but no stored provider result is available.",
    "POLICY_BLOCKED": "No provider lookup was executed for this session under the configured source/provider governance.",
    "EXPIRED_STORED_RESULT": "Stored provider context exists, but it is stale or expired.",
    "PROVIDER_UNAVAILABLE": "A provider result was attempted or recorded as unavailable, rate-limited, or errored.",
    "PROVIDER_RESULT_PENDING": "An eligible lookup is awaiting a stored provider result.",
}


def _ti_status_reason(
    *,
    observables: Sequence[Tuple[str, str]],
    evidence: Sequence[Mapping[str, Any]],
    source_ip_cache_context: Sequence[Mapping[str, Any]],
    lookup_states: Sequence[str],
    freshness_states: Sequence[str],
    stale_count: int,
    has_available: bool,
    has_error: bool,
    pending_jobs: bool = False,
) -> str:
    """Return a deterministic explanation for the coarse TI status.

    This is presentation metadata only.  It does not promote a provider
    record, authorize a lookup, or change canonical classification.
    """

    if has_available:
        return "PROVIDER_EVIDENCE_AVAILABLE"
    if not observables:
        return "NO_ELIGIBLE_OBSERVABLE"
    normalized_lookup = {str(item or "").strip().upper() for item in lookup_states}
    # A stale stored row is historical context, not proof that the current
    # provider policy blocked this session.  Report the freshness failure
    # first so operators do not mistake an old policy-prohibited result for a
    # current configuration decision.
    normalized_freshness = {str(item or "").strip().upper() for item in freshness_states}
    if stale_count or normalized_freshness & {"STALE", "EXPIRED"}:
        return "EXPIRED_STORED_RESULT"
    if normalized_lookup and normalized_lookup.issubset(
        {"DISABLED", "AUTH_DISABLED", "INVALID_OBSERVABLE"}
    ):
        return "POLICY_BLOCKED"
    if has_error:
        return "PROVIDER_UNAVAILABLE"
    if pending_jobs:
        return "PROVIDER_RESULT_PENDING"
    if evidence or source_ip_cache_context:
        return "PROVIDER_RESULT_PENDING"
    return "NO_STORED_PROVIDER_RESULT"


def _bounded_positive_limit(value: Any, default: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return min(max(parsed, 1), maximum)


def _safe_session_id(value: Any) -> Tuple[str, Optional[str]]:
    session_id = str(value or "").strip()
    if not session_id:
        return "", "missing_session_id"
    if len(session_id) > 256 or any(
        ord(character) < 0x20 or ord(character) == 0x7F
        for character in session_id
    ):
        return session_id[:256], "malformed_session_id"
    return session_id, None


def _payload(row: Mapping[str, Any]) -> Dict[str, Any]:
    value = row.get("payload")
    if isinstance(value, Mapping):
        return dict(value)
    raw = row.get("payload_json")
    if raw:
        try:
            decoded = json.loads(str(raw))
        except (TypeError, json.JSONDecodeError):
            decoded = {}
        return dict(decoded) if isinstance(decoded, Mapping) else {}
    return {}


def _sighting(row: Mapping[str, Any]) -> Dict[str, Any]:
    result = dict(row)
    payload = _payload(row)
    result["payload"] = payload
    for key in ("role", "source", "algorithm", "hash_algorithm", "hash_type", "field"):
        if key not in result and key in payload:
            result[key] = payload[key]
    return result


def _record_digest(record: Mapping[str, Any]) -> str:
    return str(
        record.get("payload_sha256")
        or hashlib.sha256(stable_json(record.get("payload") or {}).encode("utf-8")).hexdigest()
    )


def _status_evidence(
    provider: str,
    status: Mapping[str, Any],
    record: Mapping[str, Any],
) -> Dict[str, Any]:
    existing = status.get("provider_evidence")
    if isinstance(existing, Mapping):
        return dict(existing)
    normalized = str(status.get("status") or "unavailable").strip().lower()
    lookup = {
        "ok": "OK",
        "cached": "OK",
        "not_found": "NOT_FOUND",
        "not_configured": "DISABLED",
        "disabled": "DISABLED",
        "policy_prohibited": "DISABLED",
        "rate_limited": "RATE_LIMITED",
    }.get(normalized, "UNAVAILABLE")
    finding = {
        "ok": "NO_ADDITIONAL_CONTEXT",
        "cached": "NO_ADDITIONAL_CONTEXT",
        "not_found": "NOT_FOUND",
        "not_configured": "PENDING",
        "disabled": "PENDING",
        "policy_prohibited": "PENDING",
        "rate_limited": "RATE_LIMITED",
    }.get(normalized, "UNAVAILABLE")
    return {
        "schema_version": "external_ti_provider_evidence.v1",
        "provider": provider,
        "provider_mode": "lookup",
        "endpoint_id": "",
        "api_version": "",
        "lookup_status": lookup,
        "status": normalized,
        "finding_state": finding if finding in FINDING_STATES else "UNKNOWN",
        "summary": "stored provider status without a Phase 0 extension",
        "normalized_extension_type": "",
        "normalized_extension": {},
        "provider_observed_at": None,
        "provider_updated_at": None,
        "retrieved_at": status.get("fetched_at"),
        "expires_at": status.get("expires_at") or record.get("expires_at"),
        "freshness_state": "STALE" if record.get("is_stale") else "FRESH",
        "raw_response_digest": "",
        "normalized_payload_sha256": _record_digest(record),
        "normalizer_identity": EXTERNAL_TI_EVIDENCE_SCHEMA,
        "privacy_policy_identity": "external_ti_non_ip.v1",
        "provider_config_identity": "",
        "authority": EXTERNAL_TI_AUTHORITY,
        "uncertainty": {"classification": "CONTEXT_ONLY", "limitations": ["legacy provider status"]},
    }


def _provider_evidence(record: Mapping[str, Any]) -> Dict[str, Mapping[str, Any]]:
    payload = record.get("payload")
    payload_map = payload if isinstance(payload, Mapping) else {}
    evidence = payload_map.get("provider_evidence")
    if isinstance(evidence, Mapping):
        return {
            str(provider).strip().lower(): value
            for provider, value in evidence.items()
            if str(provider).strip() and isinstance(value, Mapping)
        }
    statuses = record.get("provider_status")
    if not isinstance(statuses, Mapping):
        return {}
    output: Dict[str, Mapping[str, Any]] = {}
    for provider, status in statuses.items():
        if isinstance(status, Mapping):
            output[str(provider).strip().lower()] = _status_evidence(
                str(provider).strip().lower(), status, record
            )
    return output


def _provider_summary(
    records: Sequence[Mapping[str, Any]],
    configured: Optional[Mapping[str, Any]],
) -> Dict[str, Any]:
    output: Dict[str, Any] = {}
    configs = configured or default_external_ti_provider_configs()
    for provider in sorted(KNOWN_PROVIDERS):
        settings = provider_config(provider, configs.get(provider) if isinstance(configs, Mapping) else None)
        output[provider] = {
            "status": "disabled" if not bool(settings.get("enabled", False)) else "configured",
            "mode": str(settings.get("mode") or "lookup")[:64],
            "endpoint_id": str(settings.get("endpoint_id") or "")[:96],
            "record_count": 0,
        }
    for record in records:
        for provider, evidence in _provider_evidence(record).items():
            if provider not in output:
                output[provider] = {"status": "unknown", "record_count": 0}
            item = output[provider]
            item["record_count"] = int(item.get("record_count") or 0) + 1
            item["status"] = str(evidence.get("status") or item.get("status") or "unknown")
            item["lookup_status"] = str(evidence.get("lookup_status") or "UNAVAILABLE")
            item["finding_state"] = str(evidence.get("finding_state") or "UNKNOWN")
            item["freshness_state"] = str(evidence.get("freshness_state") or "UNKNOWN")
    return output


def _safe_linked_session(row: Mapping[str, Any]) -> Dict[str, Any]:
    try:
        sighting_count = int(row.get("sighting_count") or 0)
    except (TypeError, ValueError):
        sighting_count = 0
    result = {
        "session_id": str(row.get("session_id") or "")[:256],
        "sighting_count": max(0, min(sighting_count, MAX_SIGHTINGS)),
        "first_seen": str(row.get("first_seen") or "")[:64],
        "last_seen": str(row.get("last_seen") or "")[:64],
        "roles": sorted({str(item)[:64] for item in (row.get("roles") or []) if str(item)})[:16],
        "sources": sorted({str(item)[:64] for item in (row.get("sources") or []) if str(item)})[:16],
    }
    for key, maximum in (("sensor_ids", 16), ("sighting_ids", 100)):
        values = row.get(key) or []
        if isinstance(values, str):
            values = values.split(",")
        if isinstance(values, (list, tuple, set)):
            result[key] = sorted({str(item)[:256] for item in values if str(item)})[:maximum]
    return result


def _safe_sighting_reference(row: Mapping[str, Any]) -> Dict[str, Any]:
    """Project sighting identity/provenance without payload or source fields."""

    result: Dict[str, Any] = {}
    for key, maximum in (
        ("sighting_id", 256),
        ("observable_id", 256),
        ("observable_type", 32),
        ("observable_value", 256),
        ("role", 64),
        ("source", 64),
        ("session_id", 256),
        ("sensor_id", 128),
        ("event_id", 256),
        ("eventid", 128),
        ("timestamp", 64),
    ):
        value = row.get(key)
        if value not in (None, ""):
            result[key] = str(value)[:maximum]
    # A few historical adapters expose ``sensor`` instead of ``sensor_id``.
    if "sensor_id" not in result and row.get("sensor") not in (None, ""):
        result["sensor_id"] = str(row.get("sensor"))[:128]
    return result


def _normalize_lookup_observable(
    observable_type: Any,
    observable_value: Any,
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Normalize only the two observable lookup identities in this contract.

    Read-side lookup intentionally preserves syntactically valid private,
    loopback, link-local, documentation, and otherwise non-global IPs when
    matching already-stored sightings.  This function never authorizes
    provider egress: source-IP cache/provider paths apply the separate
    globally-routable and post-cutoff governance gate.
    """

    raw_kind = str(observable_type or "").strip().lower()
    if not raw_kind:
        return None, None, "missing_observable_type"
    kind_alias = {
        "ipv4": "ip",
        "ipv6": "ip",
        "src_ip": "ip",
        "source_ip": "ip",
        "sha256": "hash",
    }
    kind = kind_alias.get(raw_kind, raw_kind)
    if kind not in SUPPORTED_OBSERVABLE_LOOKUP_TYPES:
        return None, None, "unsupported_observable_type"
    normalized = normalize_sighting_observable(kind, observable_value)
    if not normalized or normalized[0] != kind:
        return None, None, "invalid_observable"
    _normalized_kind, value, _metadata = normalized
    if kind == "hash" and (
        len(value) != 64 or any(character not in "0123456789abcdef" for character in value.lower())
    ):
        return None, None, "invalid_observable"
    return kind, value.lower() if kind == "hash" else value, None


def _source_ip_binding(config: Any) -> Tuple[str, Any, Any]:
    """Load the already-reviewed source-IP governance binding fail-closed."""

    mode = str(
        getattr(config, "source_ip_enrichment_mode", "disabled") or "disabled"
    ).strip() if config is not None else "disabled"
    if config is None or mode != SOURCE_IP_ENRICHMENT_MODE:
        return mode, None, None
    try:
        cutoff = parse_source_ip_cutoff_utc(
            getattr(config, "source_ip_enrichment_not_before_utc", "")
        )
        governance = load_source_ip_governance_amendment(
            getattr(config, "source_ip_governance_path", ""),
            expected_sha256=getattr(config, "source_ip_governance_sha256", ""),
        )
        return mode, governance, cutoff
    except (OSError, TypeError, ValueError):
        return mode, None, None


def _lookup_governed_source_ip_cache(
    cache_service: SourceIPCacheService,
    provider: str,
    normalized_source_ip: str,
    governance: Any,
) -> Optional[Dict[str, Any]]:
    """Read one production-governed cache row without provider credentials.

    The monitor may not hold the worker's provider credential references, so
    its provider-config digest can legitimately differ from the worker's.
    That digest is therefore not used as the read-side join key here.  The
    durable cache row must instead prove the stronger immutable binding:
    active production policy, approved provider/endpoint/mode, canonical
    normalizer, and non-authoritative cache authority.  A row carrying the
    reviewed pre-production policy version remains readable as explicitly
    non-authoritative historical context when every other binding matches;
    this compatibility path never authorizes provider I/O or a canonical
    write. ``lookup`` still enforces the exact normalized IP and expiry
    boundary.
    """

    name = str(provider or "").strip().lower()
    if (
        name not in SOURCE_IP_CACHE_PROVIDERS
        or governance is None
        or str(getattr(governance, "policy_id", "") or "") != SOURCE_IP_POLICY_ID
        or str(getattr(governance, "version", "") or "")
        not in {SOURCE_IP_POLICY_VERSION, *SOURCE_IP_PRODUCTION_POLICY_VERSIONS}
        or not bool(getattr(governance, "authorizes_provider", lambda _name: False)(name))
    ):
        return None
    expected_modes = {
        "abuseipdb": "lookup",
        "otx": "lookup",
        "shodan_official": "official_lookup",
    }
    try:
        cache_entry = cache_service.lookup(
            name,
            normalized_source_ip,
            expected_config_identity="",
        )
    except SourceIPCacheUnavailable:
        return None
    if cache_entry is None:
        return None
    provenance = cache_entry.get("provenance")
    if not isinstance(provenance, Mapping):
        return None
    if (
        str(cache_entry.get("provider") or "").strip().lower() != name
        or str(cache_entry.get("normalized_observable_identity") or "")
        != str(normalized_source_ip or "")
        or str(provenance.get("provider") or "").strip().lower() != name
        or str(provenance.get("provider_mode") or "") != expected_modes[name]
        or str(provenance.get("endpoint_id") or "")
        not in KNOWN_ENDPOINTS.get(name, set())
        or str(provenance.get("normalizer_identity") or "")
        != EXTERNAL_TI_EVIDENCE_SCHEMA
        or str(provenance.get("privacy_policy_identity") or "")
        != SOURCE_IP_POLICY_ID
        or str(provenance.get("privacy_policy_version") or "")
        not in {
            str(getattr(governance, "version", "") or ""),
            SOURCE_IP_POLICY_VERSION,
        }
        or str(provenance.get("authority") or "") != EXTERNAL_TI_AUTHORITY
        or str(provenance.get("cache_authority") or "")
        != SOURCE_IP_CACHE_AUTHORITY
    ):
        return None
    return cache_entry


def _source_ip_cache_policy_binding(cache_entry: Mapping[str, Any], governance: Any) -> str:
    """Label whether a cache row is current policy or legacy context-only data."""

    recorded_version = str(
        (cache_entry.get("provenance") or {}).get("privacy_policy_version") or ""
    )
    current_version = str(getattr(governance, "version", "") or "")
    return (
        "CURRENT_POLICY"
        if recorded_version == current_version
        else "LEGACY_NON_AUTHORITATIVE_CONTEXT_ONLY"
    )


def _group_source_ip_sightings(
    rows: Sequence[Mapping[str, Any]],
    normalized_source_ip: str,
    *,
    exclude_session_id: str = "",
    limit: int = MAX_PIVOT_SESSIONS,
) -> Tuple[List[Dict[str, Any]], int, bool]:
    """Group exact source-IP sightings into deterministic safe session rows."""

    groups: Dict[str, Dict[str, Any]] = {}
    seen_by_session: Dict[str, set[str]] = {}
    examined = 0
    for raw_row in rows[:MAX_PIVOT_SIGHTINGS]:
        examined += 1
        row = _sighting(raw_row)
        kind, value, _metadata = normalize_sighting_observable(
            str(row.get("observable_type") or ""), row.get("observable_value")
        ) or ("", "", {})
        if kind != "ip" or value != normalized_source_ip:
            continue
        role = str(row.get("role") or "").strip().lower()
        if role not in SOURCE_IP_RELATION_ROLES:
            continue
        session_id = str(row.get("session_id") or "").strip()
        if not session_id or session_id == exclude_session_id:
            continue
        sighting_id = str(row.get("sighting_id") or "").strip()
        dedupe_key = sighting_id or stable_id(
            "source-ip-sighting",
            {
                "session_id": session_id,
                "role": role,
                "source": row.get("source"),
                "event_id": row.get("event_id"),
                "timestamp": row.get("timestamp"),
            },
        )
        seen = seen_by_session.setdefault(session_id, set())
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        timestamp = str(row.get("timestamp") or row.get("created_at") or "")[:64]
        item = groups.setdefault(
            session_id,
            {
                "session_id": session_id,
                "sighting_count": 0,
                "first_seen": timestamp,
                "last_seen": timestamp,
                "roles": set(),
                "sources": set(),
                "sensor_ids": set(),
                "sighting_ids": [],
            },
        )
        item["sighting_count"] += 1
        if timestamp:
            item["first_seen"] = min(str(item["first_seen"] or timestamp), timestamp)
            item["last_seen"] = max(str(item["last_seen"] or timestamp), timestamp)
        item["roles"].add(role)
        source = str(row.get("source") or "").strip()
        sensor_id = str(row.get("sensor_id") or row.get("sensor") or "").strip()
        if source:
            item["sources"].add(source)
        if sensor_id:
            item["sensor_ids"].add(sensor_id)
        if sighting_id and len(item["sighting_ids"]) < 100:
            item["sighting_ids"].append(sighting_id)

    all_summaries = [
        {
            "session_id": item["session_id"],
            "sighting_count": item["sighting_count"],
            "first_seen": item["first_seen"],
            "last_seen": item["last_seen"],
            "roles": sorted(item["roles"]),
            "sources": sorted(item["sources"]),
            "sensor_ids": sorted(item["sensor_ids"]),
            "sighting_ids": sorted(item["sighting_ids"]),
        }
        for item in groups.values()
    ]
    all_summaries.sort(
        key=lambda item: (str(item.get("last_seen") or ""), str(item.get("session_id") or "")),
        reverse=True,
    )
    selected_limit = _bounded_positive_limit(limit, MAX_PIVOT_SESSIONS, MAX_PIVOT_SESSIONS)
    return all_summaries[:selected_limit], examined, len(all_summaries) > selected_limit


def _load_source_ip_cache_context(
    storage: Any,
    normalized_source_ip: str,
    *,
    config: Any = None,
    sightings: Sequence[Mapping[str, Any]] = (),
) -> List[Dict[str, Any]]:
    """Read existing governed source-IP cache entries; never invoke providers."""

    mode, governance, cutoff = _source_ip_binding(config)
    if mode != SOURCE_IP_ENRICHMENT_MODE or governance is None or config is None:
        return []
    eligible = any(
        evaluate_outbound_sighting(
            row,
            source_ip_governance=governance,
            source_ip_cutoff_utc=cutoff,
            source_ip_mode=mode,
        ).eligible
        for row in sightings
    )
    if not eligible:
        return []
    configured = getattr(config, "external_ti_provider_configs", {}) or {}
    allowlist = {
        str(item).strip().lower()
        for item in getattr(config, "external_ti_provider_allowlist", []) or []
    }
    cache_service = SourceIPCacheService(storage)
    output: List[Dict[str, Any]] = []
    for provider in sorted(SOURCE_IP_CACHE_PROVIDERS):
        settings = provider_config(provider, configured.get(provider))
        if (
            provider not in allowlist
            or not bool(settings.get("enabled", False))
            or not governance.authorizes_provider(provider)
        ):
            continue
        cache_entry = _lookup_governed_source_ip_cache(
            cache_service,
            provider,
            normalized_source_ip,
            governance,
        )
        if cache_entry is None:
            continue
        projected = source_ip_cache_session_projection(cache_entry)
        projected["policy_binding"] = _source_ip_cache_policy_binding(
            cache_entry,
            governance,
        )
        projected["lookup_scope"] = "observable"
        output.append(projected)
    return output[:MAX_EVIDENCE]


def _safe_observable_sessions(
    storage: Any,
    kind: str,
    value: str,
    *,
    limit: int,
) -> List[Dict[str, Any]]:
    loader_name = "find_sessions_by_source_ip" if kind == "ip" else "find_sessions_by_observable"
    loader = getattr(storage, loader_name, None)
    if not callable(loader):
        return []
    try:
        rows = (
            loader(value, limit=limit)
            if kind == "ip"
            else loader(kind, value, limit=limit)
        ) or []
    except Exception:
        return []
    return [
        _safe_linked_session(row)
        for row in rows[:limit]
        if str(row.get("session_id") or "").strip()
    ]


def _shared_entities(
    storage: Any,
    observables: Sequence[Tuple[str, str]],
    session_id: str,
) -> List[Dict[str, Any]]:
    if not observables:
        return []
    grouped: List[Mapping[str, Any]] = []
    batch_loader = getattr(storage, "find_sessions_by_observables", None)
    if batch_loader is not None:
        try:
            grouped = list(
                batch_loader(
                    observables[:MAX_OBSERVABLES],
                    exclude_session_id=session_id,
                    limit_per_observable=MAX_LINKED_SESSIONS,
                )
                or []
            )
        except Exception:
            grouped = []
    if not grouped:
        loader = getattr(storage, "find_sessions_by_observable", None)
        if loader is None:
            return []
        for observable_type, observable_value in observables[:MAX_OBSERVABLES]:
            try:
                rows = loader(
                    observable_type,
                    observable_value,
                    exclude_session_id=session_id,
                    limit=MAX_LINKED_SESSIONS,
                )
            except Exception:
                rows = []
            grouped.append(
                {
                    "observable_type": observable_type,
                    "observable_value": observable_value,
                    "sessions": rows or [],
                }
            )
    output: List[Dict[str, Any]] = []
    for item in grouped[:MAX_SHARED_ENTITIES]:
        kind = str(item.get("observable_type") or "").strip().lower()
        value = str(item.get("observable_value") or "").strip().lower()
        decision = evaluate_outbound_sighting(
            {
                "observable_type": kind,
                "observable_value": value,
                "role": "file_hash",
                "source": "cowrie_event",
                "payload": {"metadata": {"algorithm": "sha256", "field": "sha256"}},
            }
        )
        if not decision.eligible or kind != "hash":
            continue
        linked = [
            _safe_linked_session(row)
            for row in (item.get("sessions") or [])[:MAX_LINKED_SESSIONS]
            if str(row.get("session_id") or "") and str(row.get("session_id")) != session_id
        ]
        if not linked:
            continue
        output.append(
            {
                "relation": "STRONG_SHARED_ENTITY",
                "entity_type": "shared_file_sha256",
                "observable_type": "hash",
                "safe_observable_reference": {"kind": "sha256", "value": decision.observable_value},
                "linked_sessions": linked,
                "authority": EXTERNAL_TI_AUTHORITY,
                "uncertainty": "exact normalized file SHA-256 equality; not attribution",
            }
        )
        if len(output) >= MAX_SHARED_ENTITIES:
            break
    return output


def build_source_ip_cross_session_projection(
    storage: Any,
    source_ip: Any,
    *,
    exclude_session_id: str = "",
    limit: int = MAX_PIVOT_SESSIONS,
    config: Any = None,
) -> Dict[str, Any]:
    """Build an exact normalized source-IP, cross-session read projection."""

    kind, normalized, error_code = _normalize_lookup_observable("ip", source_ip)
    base: Dict[str, Any] = {
        "schema_version": SOURCE_IP_CROSS_SESSION_SCHEMA,
        "timestamp": utc_now(),
        "authority": EXTERNAL_TI_AUTHORITY,
        "supported_observable_types": sorted(SUPPORTED_OBSERVABLE_LOOKUP_TYPES),
        "provider_calls": False,
        "read_only": True,
    }
    if error_code or kind != "ip" or not normalized:
        return {
            "ok": False,
            **base,
            "error_code": error_code or "invalid_observable",
            "error": "source_ip must be an exact normalized IP address",
        }

    selected_limit = _bounded_positive_limit(limit, MAX_PIVOT_SESSIONS, MAX_PIVOT_SESSIONS)
    clean_exclude = str(exclude_session_id or "").strip()[:256]
    summaries: List[Dict[str, Any]] = []
    sightings_examined = 0
    sessions_truncated: Optional[bool] = None
    sessions_completeness = "UNKNOWN"
    dedicated_loader = getattr(storage, "find_sessions_by_source_ip", None)
    if callable(dedicated_loader):
        try:
            dedicated_rows = dedicated_loader(
                normalized,
                exclude_session_id=clean_exclude,
                limit=selected_limit,
            ) or []
            summaries = [
                _safe_linked_session(row)
                for row in dedicated_rows[:selected_limit]
                if str(row.get("session_id") or "").strip()
            ]
            sightings_examined = sum(int(row.get("sighting_count") or 0) for row in dedicated_rows)
            # The storage method is bounded to the requested session count and
            # returns no total cardinality.  A short result therefore cannot
            # be represented as ``sessions_truncated=false`` or as a complete
            # total.  Keep completeness explicitly undetermined.
        except Exception:
            summaries = []

    if not summaries:
        try:
            loader = getattr(storage, "list_observable_sightings", None)
            rows = (
                loader("ip", normalized, limit=MAX_PIVOT_SIGHTINGS)
                if callable(loader)
                else []
            ) or []
        except Exception:
            rows = []
        summaries, sightings_examined, sessions_truncated = _group_source_ip_sightings(
            rows,
            normalized,
            exclude_session_id=clean_exclude,
            limit=selected_limit,
        )
        sessions_completeness = "UNKNOWN"

    cache_context: List[Dict[str, Any]] = []
    # A source-IP pivot is allowed to show cache provenance only when the
    # queried identity is backed by an eligible canonical source sighting.  A
    # dedicated session-summary query has no raw rows, so perform one bounded
    # sighting read for the governance check rather than weakening that gate.
    cache_rows = rows if "rows" in locals() else []
    if config is not None and not cache_rows:
        try:
            listing = getattr(storage, "list_observable_sightings", None)
            cache_rows = (
                listing("ip", normalized, limit=MAX_PIVOT_SIGHTINGS)
                if callable(listing)
                else []
            ) or []
        except Exception:
            cache_rows = []
    cache_context = _load_source_ip_cache_context(
        storage,
        normalized,
        config=config,
        sightings=cache_rows,
    )

    return {
        "ok": True,
        **base,
        "status": "CONTEXTUAL_ONLY",
        "observable": {
            "type": "ip",
            "value": normalized,
            "normalization": "ipaddress_exact_canonical_text",
        },
        "provenance": {
            "source": "observable_sightings",
            "normalizer": "production.correlation.observable_sightings.normalize_sighting_observable",
            "role_scope": sorted(SOURCE_IP_RELATION_ROLES),
            "matching": "exact_normalized_value",
        },
        "relationship": "EXACT_NORMALIZED_SOURCE_IP_OBSERVATION",
        "exclude_session_id": clean_exclude,
        "sessions": summaries,
        "source_ip_cache": cache_context,
        "counts": {
            "sightings_examined": max(0, min(sightings_examined, MAX_PIVOT_SIGHTINGS)),
            "sessions_found": len(summaries),
            "sessions_returned": len(summaries),
            "sessions_total": None,
            "source_ip_cache_records": len(cache_context),
        },
        "completeness": {
            "sessions": sessions_completeness,
            "sessions_total": None,
            "sessions_truncated": sessions_truncated,
            "semantics": "bounded_returned_sessions; total matching sessions is undetermined",
        },
        "truncation": {
            "sightings": sightings_examined >= MAX_PIVOT_SIGHTINGS,
            "sessions": sessions_truncated,
            "source_ip_cache": len(cache_context) >= MAX_EVIDENCE,
        },
        "interpretation": "bounded analyst context for exact normalized source-IP observations",
        "non_claims": [
            "does not infer attacker identity or attribution",
            "does not infer organization, location, campaign, or intent",
            "does not treat source-IP repetition as maliciousness",
            "does not alter classification, prediction, response, or canonical truth",
        ],
    }


def build_observable_ti_projection(
    storage: Any,
    observable_type: Any,
    observable_value: Any,
    *,
    config: Any = None,
    limit: int = MAX_OBSERVABLE_LOOKUP_SIGHTINGS,
) -> Dict[str, Any]:
    """Build an exact observable-centric TI projection from stored evidence."""

    kind, normalized, error_code = _normalize_lookup_observable(
        observable_type,
        observable_value,
    )
    base: Dict[str, Any] = {
        "schema_version": OBSERVABLE_TI_SCHEMA,
        "timestamp": utc_now(),
        "authority": EXTERNAL_TI_AUTHORITY,
        "supported_observable_types": sorted(SUPPORTED_OBSERVABLE_LOOKUP_TYPES),
        "provider_calls": False,
        "read_only": True,
    }
    if error_code or not kind or not normalized:
        return {
            "ok": False,
            **base,
            "error_code": error_code or "invalid_observable",
            "error": "observable type/value is unsupported or malformed",
        }

    selected_limit = _bounded_positive_limit(
        limit,
        MAX_OBSERVABLE_LOOKUP_SIGHTINGS,
        MAX_OBSERVABLE_LOOKUP_SIGHTINGS,
    )
    try:
        loader = getattr(storage, "list_observable_sightings", None)
        rows = (
            loader(kind, normalized, limit=selected_limit)
            if callable(loader)
            else []
        ) or []
    except Exception as exc:
        return {
            "ok": False,
            **base,
            "error_code": "storage_unavailable",
            "error": f"observable query failed: {type(exc).__name__}",
            "observable": {"type": kind, "value": normalized},
        }

    eligible_rows: List[Dict[str, Any]] = []
    rejected = 0
    for raw_row in rows[:selected_limit]:
        row = _sighting(raw_row)
        row_kind, row_value, _metadata = normalize_sighting_observable(
            str(row.get("observable_type") or ""), row.get("observable_value")
        ) or ("", "", {})
        if row_kind != kind or row_value != normalized:
            continue
        if kind == "hash":
            decision = evaluate_outbound_sighting(row)
            if not decision.eligible:
                rejected += 1
                continue
        else:
            if str(row.get("role") or "").strip().lower() not in SOURCE_IP_RELATION_ROLES:
                rejected += 1
                continue
        eligible_rows.append(row)

    if not eligible_rows:
        return {
            "ok": False,
            **base,
            "error_code": "observable_not_found",
            "error": "no eligible exact observable sightings were found",
            "observable": {"type": kind, "value": normalized},
            "counts": {
                "sightings_examined": len(rows),
                "sightings_rejected": rejected,
            },
        }

    key = (kind, normalized)
    records: List[Dict[str, Any]] = []
    if kind == "hash":
        try:
            records = [
                dict(item)
                for item in (
                    storage.list_enrichment_records_for_observables(
                        [key],
                        allow_stale=True,
                    )
                    or []
                )[:1]
            ]
        except Exception:
            records = []

    evidence: List[Dict[str, Any]] = []
    for record in records:
        for provider, provider_evidence in _provider_evidence(record).items():
            evidence_item = build_external_ti_evidence(
                session_id="",
                observable_type=kind,
                observable_value=normalized,
                sightings=eligible_rows,
                provider=provider,
                provider_evidence=provider_evidence,
                record=record,
            )
            evidence_item["scope"] = "observable"
            evidence.append(evidence_item)
            if len(evidence) >= MAX_EVIDENCE:
                break
        if len(evidence) >= MAX_EVIDENCE:
            break

    cache_context = _load_source_ip_cache_context(
        storage,
        normalized,
        config=config,
        sightings=eligible_rows,
    ) if kind == "ip" else []
    sessions: List[Dict[str, Any]] = []
    if kind == "hash":
        sessions = _safe_observable_sessions(storage, kind, normalized, limit=MAX_LINKED_SESSIONS)
    else:
        dedicated = getattr(storage, "find_sessions_by_source_ip", None)
        if callable(dedicated):
            try:
                sessions = [
                    _safe_linked_session(item)
                    for item in (dedicated(normalized, limit=MAX_LINKED_SESSIONS) or [])[:MAX_LINKED_SESSIONS]
                ]
            except Exception:
                sessions = []
        if not sessions:
            sessions, _examined, _truncated = _group_source_ip_sightings(
                eligible_rows,
                normalized,
                limit=MAX_LINKED_SESSIONS,
            )

    configured = getattr(config, "external_ti_provider_configs", None) if config is not None else None
    provider_status = _provider_summary(records, configured)
    for item in cache_context:
        provider = str(item.get("provider") or "").strip().lower()
        if provider:
            provider_status.setdefault(provider, {"status": "cached", "record_count": 0})
            provider_status[provider].update(
                {
                    "status": "cached",
                    "lookup_status": item.get("lookup_status") or "UNAVAILABLE",
                    "finding_state": "CONTEXT_PRESENT"
                    if item.get("lookup_status") == "OK"
                    else "NOT_FOUND",
                    "record_count": int(provider_status[provider].get("record_count") or 0) + 1,
                }
            )
    available = any(
        str(item.get("lookup_status") or "") in {"OK", "NOT_FOUND"}
        for item in evidence
    ) or bool(cache_context)
    status = "TI_AVAILABLE" if available else "TI_PENDING"
    stale_count = sum(1 for item in evidence if item.get("freshness_state") in {"STALE", "EXPIRED"})
    return {
        "ok": True,
        **base,
        "status": status,
        "observable": {
            "type": kind,
            "value": normalized,
            "normalization": "ipaddress_exact_canonical_text" if kind == "ip" else "verified_sha256_lower_hex",
        },
        "provenance": {
            "sighting_source": "observable_sightings",
            "normalizer": "production.correlation.observable_sightings.normalize_sighting_observable",
            "provider_source": "stored_enrichment_records_or_source_ip_cache",
            "matching": "exact_normalized_value",
        },
        "sightings": [_safe_sighting_reference(row) for row in eligible_rows[:selected_limit]],
        "sessions": sessions,
        "evidence": evidence,
        "source_ip_cache": cache_context,
        "provider_status": provider_status,
        "freshness": {
            "state": "TI_EXPIRED" if stale_count else "TI_FRESH" if evidence or cache_context else "TI_PENDING",
            "stale_record_count": stale_count,
        },
        "counts": {
            "sightings_examined": len(rows),
            "sightings_rejected": rejected,
            "sightings_returned": len(eligible_rows),
            "sessions_returned": len(sessions),
            "records_found": len(records),
            "evidence_returned": len(evidence),
            "source_ip_cache_records": len(cache_context),
        },
        "truncation": {
            "sightings": len(rows) >= selected_limit,
            "sessions": len(sessions) >= MAX_LINKED_SESSIONS,
            "evidence": len(evidence) >= MAX_EVIDENCE,
            "source_ip_cache": len(cache_context) >= MAX_EVIDENCE,
        },
        "non_claims": [
            "stored provider context is non-authoritative",
            "observable repetition does not establish maliciousness or attribution",
            "this projection cannot alter classification, prediction, response, or canonical truth",
        ],
    }


# Explicit aliases keep the read-model naming discoverable for callers while
# retaining one implementation and one authority contract.
build_source_ip_pivot_projection = build_source_ip_cross_session_projection
build_observable_ti_lookup = build_observable_ti_projection


def build_session_ti_projection(
    storage: Any,
    session_id: str,
    *,
    config: Any = None,
) -> Dict[str, Any]:
    """Build the independently loadable session TI contract without I/O out."""

    clean_session_id, error_code = _safe_session_id(session_id)
    if error_code:
        return {
            "ok": False,
            "schema_version": SESSION_TI_SCHEMA,
            "error_code": error_code,
            "error": "session_id is required" if error_code == "missing_session_id" else "session_id is malformed",
            "session_id": clean_session_id,
            "timestamp": utc_now(),
        }
    try:
        session_rows = storage.list_rows_for_session("sessions", clean_session_id, limit=1)
    except Exception as exc:
        return {
            "ok": False,
            "schema_version": SESSION_TI_SCHEMA,
            "error_code": "storage_unavailable",
            "error": f"session query failed: {type(exc).__name__}",
            "session_id": clean_session_id,
            "timestamp": utc_now(),
        }
    if not session_rows:
        return {
            "ok": False,
            "schema_version": SESSION_TI_SCHEMA,
            "error_code": "session_not_found",
            "error": "session was not found",
            "session_id": clean_session_id,
            "timestamp": utc_now(),
        }
    try:
        loader = getattr(storage, "list_session_observable_sightings", None)
        sighting_rows = (
            loader(clean_session_id, limit=MAX_SIGHTINGS)
            if loader is not None
            else storage.list_rows_for_session("observable_sightings", clean_session_id, limit=MAX_SIGHTINGS)
        )
    except Exception as exc:
        return {
            "ok": False,
            "schema_version": SESSION_TI_SCHEMA,
            "error_code": "storage_unavailable",
            "error": f"sighting query failed: {type(exc).__name__}",
            "session_id": clean_session_id,
            "timestamp": utc_now(),
        }

    bounded_sightings = [_sighting(row) for row in (sighting_rows or [])[:MAX_SIGHTINGS]]
    source_ip_mode, source_ip_governance, source_ip_cutoff_utc = _source_ip_binding(config)
    eligible: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    rejected = 0
    for row in bounded_sightings:
        decision = evaluate_outbound_sighting(
            row,
            source_ip_governance=source_ip_governance,
            source_ip_cutoff_utc=source_ip_cutoff_utc,
            source_ip_mode=source_ip_mode,
        )
        if not decision.eligible:
            rejected += 1
            continue
        key = (decision.observable_type, decision.observable_value)
        eligible.setdefault(key, []).append(row)
    observables = list(eligible)[:MAX_OBSERVABLES]
    omitted_observables = max(0, len(eligible) - len(observables))

    # Source-IP ETI uses the governed provider cache as its only durable
    # provider-result store.  Do not merge pre-policy canonical
    # ``enrichment_records`` for an IP into this projection: those rows can be
    # stale legacy context and otherwise make a fresh source-IP lookup appear
    # to have a current finding.
    record_observables = [
        key
        for key in observables
        if not (source_ip_mode == SOURCE_IP_ENRICHMENT_MODE and key[0] == "ip")
    ]
    records: List[Dict[str, Any]] = []
    if record_observables:
        try:
            batch_records = storage.list_enrichment_records_for_observables(
                record_observables,
                allow_stale=True,
            )
            records = [dict(item) for item in (batch_records or [])[:MAX_OBSERVABLES]]
        except Exception:
            records = []
    record_map = {
        (
            str(record.get("observable_type") or "").strip().lower(),
            str(record.get("observable_value") or "").strip().lower(),
        ): record
        for record in records
    }

    # Source-IP provider results intentionally do not have a canonical
    # ``enrichment_records`` row. Join a fresh durable cache row as a bounded
    # response projection/reference instead of copying it into the session.
    source_ip_cache_context: List[Dict[str, Any]] = []
    if source_ip_mode == SOURCE_IP_ENRICHMENT_MODE and source_ip_governance is not None and config is not None:
        cache_service = SourceIPCacheService(storage)
        configured = getattr(config, "external_ti_provider_configs", {}) or {}
        allowlist = {
            str(item).strip().lower()
            for item in getattr(config, "external_ti_provider_allowlist", []) or []
        }
        for kind, value in observables:
            if kind != "ip":
                continue
            for provider in sorted(SOURCE_IP_CACHE_PROVIDERS):
                settings = provider_config(provider, configured.get(provider))
                if provider not in allowlist or not bool(settings.get("enabled", False)):
                    continue
                cache_entry = _lookup_governed_source_ip_cache(
                    cache_service,
                    provider,
                    value,
                    source_ip_governance,
                )
                if cache_entry is not None:
                    projected = source_ip_cache_session_projection(cache_entry)
                    projected["policy_binding"] = _source_ip_cache_policy_binding(
                        cache_entry,
                        source_ip_governance,
                    )
                    source_ip_cache_context.append(projected)
                    if len(source_ip_cache_context) >= MAX_EVIDENCE:
                        break
            if len(source_ip_cache_context) >= MAX_EVIDENCE:
                break

    job_rows: List[Dict[str, Any]] = []
    try:
        job_loader = getattr(storage, "list_rows_for_session", None)
        if callable(job_loader):
            job_rows = [
                dict(item)
                for item in (job_loader("enrichment_jobs", clean_session_id, limit=100) or [])
                if isinstance(item, Mapping)
            ]
    except Exception:
        job_rows = []
    job_status_counts: Dict[str, int] = {}
    for row in job_rows:
        status = str(row.get("status") or "unknown").strip().lower() or "unknown"
        job_status_counts[status] = job_status_counts.get(status, 0) + 1
    pending_jobs = any(
        status in {"queued", "running", "retry"}
        for status in job_status_counts
    )

    evidence: List[Dict[str, Any]] = []
    provider_records: List[Mapping[str, Any]] = []
    stale_count = 0
    latest_retrieved: Optional[str] = None
    for key in observables:
        record = record_map.get(key)
        if not record:
            continue
        provider_records.append(record)
        if bool(record.get("is_stale")):
            stale_count += 1
        for provider, provider_evidence in _provider_evidence(record).items():
            enriched = dict(provider_evidence)
            if bool(record.get("is_stale")):
                enriched["freshness_state"] = "STALE"
                if enriched.get("finding_state") not in {"NOT_FOUND", "PENDING", "RATE_LIMITED"}:
                    enriched["finding_state"] = "STALE"
            retrieved = str(enriched.get("retrieved_at") or "")
            if retrieved and (latest_retrieved is None or retrieved > latest_retrieved):
                latest_retrieved = retrieved
            evidence.append(
                build_external_ti_evidence(
                    session_id=clean_session_id,
                    observable_type=key[0],
                    observable_value=key[1],
                    sightings=eligible[key],
                    provider=provider,
                    provider_evidence=enriched,
                    record=record,
                )
            )
            if len(evidence) >= MAX_EVIDENCE:
                break
        if len(evidence) >= MAX_EVIDENCE:
            break

    shared_entities = _shared_entities(storage, observables, clean_session_id)
    configured = getattr(config, "external_ti_provider_configs", None) if config is not None else None
    eligible_counts: Dict[str, int] = {}
    for observable_type, _observable_value in observables:
        eligible_counts[observable_type] = eligible_counts.get(observable_type, 0) + 1
    cache_lookup_states = {
        str(item.get("lookup_status") or "UNAVAILABLE").strip().upper()
        for item in source_ip_cache_context
    }
    has_available = any(item.get("lookup_status") in {"OK", "NOT_FOUND"} for item in evidence) or bool(
        cache_lookup_states & {"OK", "NOT_FOUND"}
    )
    has_error = any(
        item.get("lookup_status")
        in {"PROVIDER_ERROR", "RATE_LIMITED", "AUTH_DISABLED", "BUDGET_EXHAUSTED", "UNAVAILABLE"}
        for item in evidence
    ) or bool(
        cache_lookup_states
        & {"PROVIDER_ERROR", "RATE_LIMITED", "AUTH_DISABLED", "BUDGET_EXHAUSTED", "UNAVAILABLE"}
    )
    ti_status = "TI_AVAILABLE" if has_available else "TI_PARTIAL" if has_error else "TI_PENDING"
    freshness_states = {
        str(item.get("freshness_state") or "UNKNOWN").strip().upper()
        for item in evidence
    }
    if source_ip_cache_context:
        freshness_states.add("FRESH")
    lookup_states = {
        str(item.get("lookup_status") or "UNAVAILABLE").strip().upper()
        for item in evidence
    } | cache_lookup_states
    if "AUTH_DISABLED" in lookup_states:
        freshness_state = "TI_AUTH_DISABLED"
    elif "RATE_LIMITED" in lookup_states:
        freshness_state = "TI_RATE_LIMITED"
    elif "EXPIRED" in freshness_states or stale_count:
        freshness_state = "TI_EXPIRED"
    elif "STALE" in freshness_states:
        freshness_state = "TI_STALE"
    elif "PROVIDER_ERROR" in lookup_states or "UNAVAILABLE" in lookup_states:
        freshness_state = "TI_UNAVAILABLE"
    elif evidence or source_ip_cache_context:
        freshness_state = "TI_FRESH"
    else:
        freshness_state = "TI_PENDING"
    status_reason = _ti_status_reason(
        observables=observables,
        evidence=evidence,
        source_ip_cache_context=source_ip_cache_context,
        lookup_states=lookup_states,
        freshness_states=freshness_states,
        stale_count=stale_count,
        has_available=has_available,
        has_error=has_error,
        pending_jobs=pending_jobs,
    )
    return {
        "ok": True,
        "schema_version": SESSION_TI_SCHEMA,
        "evidence_schema_version": EXTERNAL_TI_EVIDENCE_SCHEMA,
        "timestamp": utc_now(),
        "session_id": clean_session_id,
        "status": ti_status,
        "status_reason": status_reason,
        "status_reason_text": TI_STATUS_REASON_TEXT[status_reason],
        "external_ti_summary": {
            "status": ti_status,
            "status_reason": status_reason,
            "status_reason_text": TI_STATUS_REASON_TEXT[status_reason],
            # Backward-compatible field name retained, but its semantics are
            # now explicitly hash-only rather than all eligible observables.
            "eligible_file_sha256_count": eligible_counts.get("hash", 0),
            "eligible_source_ip_count": eligible_counts.get("ip", 0),
            "eligible_observable_count": len(observables),
            "eligible_observable_types": sorted(eligible_counts),
            "eligible_observable_counts": {
                key: eligible_counts[key] for key in sorted(eligible_counts)
            },
            "records_found": len(records),
            "evidence_returned": len(evidence),
            "source_ip_cache_records_found": len(source_ip_cache_context),
            "source_ip_cache_policy_bindings": sorted(
                {
                    str(item.get("policy_binding") or "UNKNOWN")
                    for item in source_ip_cache_context
                }
            ),
            "source_ip_cache_freshness": "FRESH" if source_ip_cache_context else "NONE",
            "source_ip_cache_latest_lookup_at": max(
                (
                    str(item.get("lookup_at") or "")
                    for item in source_ip_cache_context
                    if str(item.get("lookup_at") or "")
                ),
                default=None,
            ),
            "enrichment_jobs": len(job_rows),
            "enrichment_jobs_pending": pending_jobs,
            "shared_entity_count": len(shared_entities),
            "authority": EXTERNAL_TI_AUTHORITY,
            "uncertainty": "context only; no provider finding is a project classification",
        },
        "evidence": evidence,
        "source_ip_cache": source_ip_cache_context,
        "shared_entities": shared_entities,
        "enrichment_job_summary": {
            "total": len(job_rows),
            "status_counts": dict(sorted(job_status_counts.items())),
            "pending": pending_jobs,
        },
        "provider_status": _provider_summary(provider_records, configured),
        "freshness": {
            "state": freshness_state,
            "stale_record_count": stale_count,
            "latest_retrieved_at": latest_retrieved,
        },
        "counts": {
            "sightings_examined": len(bounded_sightings),
            "sightings_rejected_by_eligibility": rejected,
            "eligible_observables": len(observables),
            "eligible_file_sha256": eligible_counts.get("hash", 0),
            "eligible_source_ip": eligible_counts.get("ip", 0),
            "eligible_observable_types": sorted(eligible_counts),
            "records_found": len(records),
            "evidence_returned": len(evidence),
            "source_ip_cache_records": len(source_ip_cache_context),
            "enrichment_jobs": len(job_rows),
            "enrichment_jobs_pending": pending_jobs,
            "shared_entities": len(shared_entities),
        },
        "truncation": {
            "sightings": len(sighting_rows or []) > MAX_SIGHTINGS,
            "observables": bool(omitted_observables),
            "evidence": len(evidence) >= MAX_EVIDENCE,
            "source_ip_cache": len(source_ip_cache_context) >= MAX_EVIDENCE,
            "shared_entities": len(shared_entities) >= MAX_SHARED_ENTITIES,
        },
    }
