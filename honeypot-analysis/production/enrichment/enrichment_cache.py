"""Cached enrichment helpers shared by session, analysis, and worker services."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, Iterator, Optional, Tuple
from urllib.parse import urlparse

from production.enrichment.external_ti_contract import (
    EXTERNAL_TI_AUTHORITY,
    EXTERNAL_TI_EVIDENCE_SCHEMA,
    KNOWN_ENDPOINTS,
    SOURCE_IP_POLICY_ID,
    SOURCE_IP_POLICY_VERSION,
    provider_config_identity as compute_provider_config_identity,
    sanitize_provider_extension,
    normalize_provider_extension,
)
from production.enrichment.local_snapshot import load_local_enrichment_snapshot
from production.utils.serialization import stable_id, stable_json, utc_now


SUPPORTED_OBSERVABLES = {"ip", "url", "domain", "hash", "hassh", "ja3"}


# This is a deliberately separate logical object from canonical
# ``enrichment_records``.  It is provider context only and is never included in
# the canonical 31-collection MongoDB manifest.
SOURCE_IP_CACHE_COLLECTION = "external_ti_source_ip_cache"
SOURCE_IP_CACHE_SCHEMA = "external_ti_source_ip_cache.v1"
SOURCE_IP_CACHE_AUTHORITY = "NON_AUTHORITATIVE_CACHE"
SOURCE_IP_CACHE_PROVIDERS = frozenset({"abuseipdb", "otx", "shodan_official"})
SOURCE_IP_CACHE_STATUSES = frozenset(
    {
        "DATA",
        "NO_DATA",
        "AUTH_FAILED",
        "RATE_LIMITED",
        "REQUEST_FAILED",
        "NORMALIZATION_FAILED",
    }
)

# Provider-specific normalizers have tighter source bounds.  These cache
# bounds are repeated here as a storage boundary so a future adapter cannot
# turn a bounded response into an unbounded durable record.
MAX_CACHE_HOSTNAMES = 32
MAX_CACHE_HOSTNAME_CHARS = 253
MAX_CACHE_PORTS = 256
MAX_CACHE_TAGS = 32
MAX_CACHE_TAG_CHARS = 256
MAX_CACHE_SERVICES = 64
MAX_CACHE_SERVICE_CHARS = 128
MAX_CACHE_CPE = 64
MAX_CACHE_CPE_CHARS = 256
MAX_CACHE_VULNERABILITIES = 128
MAX_CACHE_VULNERABILITY_CHARS = 64
MAX_NORMALIZED_CACHE_CONTEXT_BYTES = 8_192
MAX_CACHE_PROVENANCE_BYTES = 2_048
MAX_NORMALIZED_CACHE_ENTRY_BYTES = 16_384
MIN_CACHE_WINDOW_SECONDS = 86_400
MAX_CACHE_WINDOW_SECONDS = 7 * 86_400
MAX_FAILURE_CACHE_SECONDS = 86_400


class SourceIPCacheUnavailable(RuntimeError):
    """The durable source-IP cache failed; provider lookup must fail closed."""


class SourceIPCacheEntryInvalid(ValueError):
    """A cache entry cannot satisfy the bounded source-IP cache contract."""


def source_ip_cache_key(provider: str, normalized_ip: str) -> str:
    """Return the deterministic provider-plus-IP cache identity."""

    return stable_id(
        "external-ti-source-ip-cache",
        {
            "schema_version": SOURCE_IP_CACHE_SCHEMA,
            "provider": str(provider or "").strip().lower(),
            "observable_type": "source_ip",
            "normalized_observable_identity": str(normalized_ip or "").strip(),
        },
    )


def _cache_datetime(value: Any = None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError) as exc:
            raise SourceIPCacheEntryInvalid("cache timestamp is malformed") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SourceIPCacheEntryInvalid("cache timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _cache_iso(value: Any = None) -> str:
    return _cache_datetime(value).isoformat()


def _cache_seconds(
    value: Any,
    default: int,
    *,
    maximum: int,
    minimum: int = 1,
) -> int:
    try:
        selected = int(value)
    except (TypeError, ValueError):
        selected = default
    return max(minimum, min(selected, maximum))


def _cache_context(provider: str, extension: Mapping[str, Any]) -> Dict[str, Any]:
    """Select only provider-approved normalized fields for durable storage."""

    name = str(provider or "").strip().lower()
    if name == "abuseipdb":
        allowed = (
            "abuse_confidence_score",
            "total_reports",
            "categories",
            "usage_type",
            "isp",
            "country_code",
            "last_reported_at",
        )
    elif name == "otx":
        allowed = (
            "pulses",
            "truncated",
        )
    else:
        allowed = (
            "asn",
            "organization",
            "isp",
            "country",
            "ports",
            "service_product_summary",
            "cpe",
            "vulnerabilities",
            "tags",
            "hostnames",
            "last_update",
            "truncated",
        )
    return {
        key: extension.get(key)
        for key in allowed
        if extension.get(key) not in (None, "", [], {})
    }


def _fit_cache_context(context: Mapping[str, Any]) -> Dict[str, Any]:
    """Fit a sanitized context to the serialized cache-context ceiling."""

    candidate = dict(context)
    if len(stable_json(candidate).encode("utf-8")) <= MAX_NORMALIZED_CACHE_CONTEXT_BYTES:
        return candidate

    # Retain compact identity/reputation fields and deterministically trim the
    # least essential repeated context first.  This never examines or stores a
    # raw provider response.
    for key in (
        "vulnerabilities",
        "cpe",
        "pulses",
        "tags",
        "hostnames",
        "service_product_summary",
        "ports",
    ):
        values = candidate.get(key)
        if not isinstance(values, list):
            continue
        while values and len(stable_json(candidate).encode("utf-8")) > MAX_NORMALIZED_CACHE_CONTEXT_BYTES:
            values.pop()

    if len(stable_json(candidate).encode("utf-8")) > MAX_NORMALIZED_CACHE_CONTEXT_BYTES:
        for key in ("vulnerabilities", "cpe", "pulses", "tags", "hostnames", "service_product_summary"):
            candidate.pop(key, None)
            if len(stable_json(candidate).encode("utf-8")) <= MAX_NORMALIZED_CACHE_CONTEXT_BYTES:
                break
    if len(stable_json(candidate).encode("utf-8")) > MAX_NORMALIZED_CACHE_CONTEXT_BYTES:
        # The scalar fields are already bounded by the shared normalizer.  An
        # empty context is safer than storing an oversized or provider-shaped
        # object; the DATA status still records that the lookup completed.
        return {}
    return candidate


def _cache_status_for_result(status: Any) -> Optional[str]:
    return {
        "ok": "DATA",
        "not_found": "NO_DATA",
        "auth_disabled": "AUTH_FAILED",
        "rate_limited": "RATE_LIMITED",
        "error": "REQUEST_FAILED",
        "temporary_error": "REQUEST_FAILED",
        "permanent_error": "REQUEST_FAILED",
        "malformed_response": "NORMALIZATION_FAILED",
    }.get(str(status or "").strip().lower())


def _cache_lookup_status(status: str) -> str:
    return {
        "DATA": "OK",
        "NO_DATA": "NOT_FOUND",
        "AUTH_FAILED": "AUTH_DISABLED",
        "RATE_LIMITED": "RATE_LIMITED",
        "REQUEST_FAILED": "PROVIDER_ERROR",
        "NORMALIZATION_FAILED": "PROVIDER_ERROR",
    }[status]


def _cache_finding(status: str, context: Mapping[str, Any]) -> str:
    if status == "DATA":
        return "CONTEXT_PRESENT" if context else "NO_ADDITIONAL_CONTEXT"
    if status == "NO_DATA":
        return "NOT_FOUND"
    if status == "AUTH_FAILED":
        return "AUTH_DISABLED"
    if status == "RATE_LIMITED":
        return "RATE_LIMITED"
    return "ERROR"


def _bounded_cache_provenance(row: Mapping[str, Any]) -> Dict[str, Any]:
    raw = row.get("provenance")
    source = raw if isinstance(raw, Mapping) else {}
    allowed = (
        "provider",
        "provider_mode",
        "endpoint_id",
        "provider_config_identity",
        "normalizer_identity",
        "privacy_policy_identity",
        "privacy_policy_version",
        "authority",
        "cache_authority",
    )
    result = {key: source.get(key) for key in allowed if source.get(key) not in (None, "")}
    encoded = stable_json(result).encode("utf-8")
    if len(encoded) > MAX_CACHE_PROVENANCE_BYTES:
        raise SourceIPCacheEntryInvalid("cache provenance exceeds the bounded limit")
    return result


def _validated_cache_context(provider: str, value: Any) -> Dict[str, Any]:
    sanitized = sanitize_provider_extension(provider, value)
    context = _cache_context(provider, sanitized)
    fitted = _fit_cache_context(context)
    if len(stable_json(fitted).encode("utf-8")) > MAX_NORMALIZED_CACHE_CONTEXT_BYTES:
        raise SourceIPCacheEntryInvalid("normalized cache context exceeds the bounded limit")
    return fitted


def build_source_ip_cache_entry(
    provider: str,
    normalized_ip: str,
    result: Any,
    settings: Optional[Mapping[str, Any]] = None,
    *,
    now: Any = None,
    privacy_policy_version: str = SOURCE_IP_POLICY_VERSION,
) -> Optional[Dict[str, Any]]:
    """Build one bounded provider-specific source-IP cache record.

    The function intentionally does not copy ``result.error`` or any raw
    provider data.  Results that are control-plane outcomes (disabled, cached,
    policy blocked, or budget exhausted) do not create a cache record.
    """

    name = str(provider or "").strip().lower()
    if name not in SOURCE_IP_CACHE_PROVIDERS:
        raise SourceIPCacheEntryInvalid("provider is not enabled for source-IP cache")
    normalized = normalize_observable("ip", normalized_ip)
    if not normalized or normalized[0] != "ip":
        raise SourceIPCacheEntryInvalid("source-IP cache identity is invalid")
    try:
        parsed_ip = ipaddress.ip_address(normalized[1])
    except ValueError as exc:
        raise SourceIPCacheEntryInvalid("source-IP cache identity is invalid") from exc
    if not parsed_ip.is_global:
        raise SourceIPCacheEntryInvalid("source-IP cache identity is not globally routable")

    cache_status = _cache_status_for_result(getattr(result, "status", ""))
    if cache_status is None:
        return None
    provider_settings = dict(settings or {})
    current = _cache_datetime(now)
    context: Dict[str, Any] = {}
    if cache_status == "DATA":
        try:
            _extension_type, extension, _finding, _summary, _observed, _updated = normalize_provider_extension(
                name, getattr(result, "data", {})
            )
            context = _validated_cache_context(name, extension)
        except Exception:
            cache_status = "NORMALIZATION_FAILED"
            context = {}

    # Recompute the identity from the validated, secret-free settings.  Never
    # trust an adapter-provided identity field as durable provenance because a
    # faulty adapter must not be able to persist arbitrary text here.
    config_identity = compute_provider_config_identity(name, provider_settings)
    endpoint_id = str(
        getattr(result, "endpoint_id", "") or provider_settings.get("endpoint_id") or ""
    ).strip()
    if endpoint_id not in KNOWN_ENDPOINTS.get(name, set()):
        endpoint_id = ""
    provider_mode = {
        "abuseipdb": "lookup",
        "otx": "lookup",
        "shodan_official": "official_lookup",
    }.get(name, "lookup")
    provenance = {
        "provider": name,
        "provider_mode": provider_mode,
        "endpoint_id": endpoint_id,
        "provider_config_identity": config_identity[:128],
        "normalizer_identity": EXTERNAL_TI_EVIDENCE_SCHEMA,
        "privacy_policy_identity": SOURCE_IP_POLICY_ID,
        "privacy_policy_version": str(
            privacy_policy_version or SOURCE_IP_POLICY_VERSION
        )[:64],
        "authority": EXTERNAL_TI_AUTHORITY,
        "cache_authority": SOURCE_IP_CACHE_AUTHORITY,
    }
    if len(stable_json(provenance).encode("utf-8")) > MAX_CACHE_PROVENANCE_BYTES:
        raise SourceIPCacheEntryInvalid("cache provenance exceeds the bounded limit")

    if cache_status == "DATA":
        window = _cache_seconds(
            provider_settings.get("refresh_window_seconds"),
            MIN_CACHE_WINDOW_SECONDS,
            maximum=MAX_CACHE_WINDOW_SECONDS,
            minimum=MIN_CACHE_WINDOW_SECONDS,
        )
    elif cache_status == "NO_DATA":
        window = _cache_seconds(
            provider_settings.get("negative_cache_seconds"),
            MIN_CACHE_WINDOW_SECONDS,
            maximum=MAX_CACHE_WINDOW_SECONDS,
            minimum=MIN_CACHE_WINDOW_SECONDS,
        )
    else:
        window = _cache_seconds(
            provider_settings.get("error_ttl_seconds"),
            3_600,
            maximum=MAX_FAILURE_CACHE_SECONDS,
        )
    expires_at = (current + timedelta(seconds=window)).isoformat()
    lookup_at = current.isoformat()
    try:
        provider_observed_at = _cache_iso(getattr(result, "fetched_at", ""))
    except SourceIPCacheEntryInvalid:
        provider_observed_at = lookup_at
    entry: Dict[str, Any] = {
        "cache_key": source_ip_cache_key(name, normalized[1]),
        "schema_version": SOURCE_IP_CACHE_SCHEMA,
        "provider": name,
        "observable_type": "source_ip",
        "normalized_observable_identity": normalized[1],
        "lookup_status": cache_status,
        "normalized_context": context,
        "provider_observed_at": provider_observed_at,
        "lookup_at": lookup_at,
        "expires_at": expires_at,
        "negative_cache_until": expires_at if cache_status == "NO_DATA" else None,
        "provenance": provenance,
        "created_at": lookup_at,
        "updated_at": lookup_at,
    }
    if len(stable_json(entry).encode("utf-8")) > MAX_NORMALIZED_CACHE_ENTRY_BYTES:
        raise SourceIPCacheEntryInvalid("source-IP cache entry exceeds the bounded limit")
    return entry


class SourceIPCacheService:
    """Provider-specific durable cache facade with fail-closed semantics."""

    def __init__(self, storage: Any) -> None:
        self.storage = storage

    @staticmethod
    def _clean_entry(row: Mapping[str, Any]) -> Dict[str, Any]:
        provider = str(row.get("provider") or "").strip().lower()
        if provider not in SOURCE_IP_CACHE_PROVIDERS:
            raise SourceIPCacheEntryInvalid("unsupported cached provider")
        if str(row.get("schema_version") or "") != SOURCE_IP_CACHE_SCHEMA:
            raise SourceIPCacheEntryInvalid("unsupported cache schema")
        identity = normalize_observable("ip", row.get("normalized_observable_identity"))
        if not identity or identity[0] != "ip" or not ipaddress.ip_address(identity[1]).is_global:
            raise SourceIPCacheEntryInvalid("invalid cached source-IP identity")
        if identity[1] != str(row.get("normalized_observable_identity") or ""):
            raise SourceIPCacheEntryInvalid("cached source-IP identity is not normalized")
        status = str(row.get("lookup_status") or "").strip().upper()
        if status not in SOURCE_IP_CACHE_STATUSES:
            raise SourceIPCacheEntryInvalid("unsupported cached lookup status")
        context = _validated_cache_context(provider, row.get("normalized_context") or {})
        provenance = _bounded_cache_provenance(row)
        clean = {
            "cache_key": str(row.get("cache_key") or source_ip_cache_key(provider, identity[1])),
            "schema_version": SOURCE_IP_CACHE_SCHEMA,
            "provider": provider,
            "observable_type": "source_ip",
            "normalized_observable_identity": identity[1],
            "lookup_status": status,
            "normalized_context": context,
            "provider_observed_at": str(row.get("provider_observed_at") or "")[:64] or None,
            "lookup_at": str(row.get("lookup_at") or "")[:64],
            "expires_at": str(row.get("expires_at") or "")[:64],
            "negative_cache_until": str(row.get("negative_cache_until") or "")[:64] or None,
            "provenance": provenance,
            "created_at": str(row.get("created_at") or "")[:64],
            "updated_at": str(row.get("updated_at") or "")[:64],
        }
        if clean["cache_key"] != source_ip_cache_key(provider, identity[1]):
            raise SourceIPCacheEntryInvalid("cache key does not match provider identity")
        if len(stable_json(clean).encode("utf-8")) > MAX_NORMALIZED_CACHE_ENTRY_BYTES:
            raise SourceIPCacheEntryInvalid("cached entry exceeds the bounded limit")
        return clean

    def lookup(
        self,
        provider: str,
        normalized_ip: str,
        *,
        expected_config_identity: str = "",
        now: Any = None,
    ) -> Optional[Dict[str, Any]]:
        name = str(provider or "").strip().lower()
        normalized = normalize_observable("ip", normalized_ip)
        if name not in SOURCE_IP_CACHE_PROVIDERS or not normalized or not ipaddress.ip_address(normalized[1]).is_global:
            return None
        getter = getattr(self.storage, "get_external_ti_source_ip_cache", None)
        if not callable(getter):
            raise SourceIPCacheUnavailable("source-IP cache read is unavailable")
        try:
            row = getter(name, normalized[1], expected_config_identity, now=now)
            if row is None:
                return None
            clean = self._clean_entry(row)
            recorded_identity = str(
                clean["provenance"].get("provider_config_identity") or ""
            )
            if expected_config_identity and recorded_identity != expected_config_identity:
                return None
            current = _cache_datetime(now)
            if _cache_datetime(clean["expires_at"]) <= current:
                return None
            if clean["lookup_status"] == "NO_DATA" and (
                not clean["negative_cache_until"]
                or _cache_datetime(clean["negative_cache_until"]) <= current
            ):
                return None
            return clean
        except SourceIPCacheUnavailable:
            raise
        except Exception as exc:
            raise SourceIPCacheUnavailable("source-IP cache read failed") from exc

    def store_result(
        self,
        provider: str,
        normalized_ip: str,
        result: Any,
        settings: Optional[Mapping[str, Any]] = None,
        *,
        now: Any = None,
        privacy_policy_version: str = SOURCE_IP_POLICY_VERSION,
    ) -> Optional[Dict[str, Any]]:
        entry = build_source_ip_cache_entry(
            provider,
            normalized_ip,
            result,
            settings,
            now=now,
            privacy_policy_version=privacy_policy_version,
        )
        if entry is None:
            return None
        setter = getattr(self.storage, "upsert_external_ti_source_ip_cache", None)
        if not callable(setter):
            raise SourceIPCacheUnavailable("source-IP cache write is unavailable")
        try:
            setter(entry)
        except Exception as exc:
            raise SourceIPCacheUnavailable("source-IP cache write failed") from exc
        return entry

    def prune_expired(self, *, now: Any = None, max_records: int = 1_000) -> int:
        """Run bounded expiry maintenance; callers must schedule it explicitly."""

        pruner = getattr(self.storage, "prune_external_ti_source_ip_cache", None)
        if not callable(pruner):
            raise SourceIPCacheUnavailable("source-IP cache maintenance is unavailable")
        try:
            return max(
                0,
                int(pruner(now=now, max_records=max_records)),
            )
        except Exception as exc:
            raise SourceIPCacheUnavailable("source-IP cache maintenance failed") from exc

    @staticmethod
    def cached_result(entry: Mapping[str, Any]) -> Any:
        """Convert a fresh cache row into a non-network ProviderResult."""

        from production.enrichment.enrichment_providers import ProviderResult

        clean = SourceIPCacheService._clean_entry(entry)
        status = clean["lookup_status"]
        try:
            remaining = max(
                1,
                int((_cache_datetime(clean["expires_at"]) - datetime.now(timezone.utc)).total_seconds()),
            )
        except SourceIPCacheEntryInvalid:
            remaining = 1
        provenance = clean["provenance"]
        return ProviderResult(
            provider=clean["provider"],
            status="cached",
            data={},
            ttl_seconds=remaining,
            fetched_at=clean["lookup_at"] or utc_now(),
            endpoint_id=str(provenance.get("endpoint_id") or ""),
            provider_mode=str(provenance.get("provider_mode") or "lookup"),
            normalizer_identity=str(provenance.get("normalizer_identity") or EXTERNAL_TI_EVIDENCE_SCHEMA),
            privacy_policy_identity=str(provenance.get("privacy_policy_identity") or SOURCE_IP_POLICY_ID),
            provider_config_identity=str(provenance.get("provider_config_identity") or ""),
            normalized_extension=dict(clean["normalized_context"]),
            normalized_finding=_cache_finding(status, clean["normalized_context"]),
            cached_lookup_status=_cache_lookup_status(status),
            attempt_count=0,
            budget_consumed=0,
        )


def source_ip_cache_session_projection(entry: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a bounded cache reference without exposing the source IP."""

    clean = SourceIPCacheService._clean_entry(entry)
    return {
        "cache_key": clean["cache_key"],
        "schema_version": clean["schema_version"],
        "provider": clean["provider"],
        "lookup_status": _cache_lookup_status(clean["lookup_status"]),
        "normalized_context": dict(clean["normalized_context"]),
        # Provenance is already bounded and secret-free in the cache contract;
        # expose it so read-side projections remain traceable without copying
        # a provider payload or source-IP identity into a session response.
        "provenance": dict(clean["provenance"]),
        "lookup_at": clean["lookup_at"],
        "expires_at": clean["expires_at"],
        "authority": SOURCE_IP_CACHE_AUTHORITY,
        "join": "provider_plus_normalized_source_ip_cache_key",
    }


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


def enqueue_event_observables(
    storage: Any,
    event: Dict[str, Any],
    enabled: bool = True,
    *,
    event_id: str = "",
    sensor_id: str = "",
    force: bool = False,
) -> int:
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
            force=bool(force),
            payload={
                # Source-IP provider eligibility is evaluated against this
                # original observation, never against queue/worker time.
                "source": "cowrie_event",
                "role": "source_ip",
                "event_id": str(event_id or ""),
                "eventid": event.get("eventid", ""),
                "sensor_id": str(sensor_id or event.get("sensor_id") or event.get("sensor") or ""),
                "timestamp": event.get("timestamp", ""),
            },
        )
        count += 1
    return count


def enqueue_session_observables(
    storage: Any,
    session_payload: Dict[str, Any],
    enabled: bool = True,
    *,
    force_source_ip: bool = False,
) -> int:
    """Queue all observables extracted from a closed session.

    The queue is keyed by observable identity, so a source IP can have an old
    terminal job from a previous session.  A generic ``session_close`` payload
    is not sufficient for the source-IP outbound gate: it must carry the
    current canonical terminal-event binding and timestamp.  Build that
    binding only for the session's own source IP; other session observables
    remain session-close context and stay ineligible for source-IP provider
    traffic.
    """
    if not enabled:
        return 0
    count = 0
    session_id = str(session_payload.get("session_id", ""))
    source_ip = str(session_payload.get("src_ip") or "").strip()
    manifest = session_payload.get("canonical_event_manifest")
    manifest = manifest if isinstance(manifest, dict) else {}
    terminal_event_id = str(
        session_payload.get("last_applied_event_id")
        or manifest.get("through_event_id")
        or ""
    ).strip()
    sensor_id = str(
        session_payload.get("sensor_id")
        or session_payload.get("sensor")
        or ""
    ).strip()
    terminal_timestamp = ""
    raw_events = session_payload.get("raw_events")
    if isinstance(raw_events, list):
        for event in reversed(raw_events):
            if not isinstance(event, dict):
                continue
            event_id = str(event.get("eventid") or "").strip().lower()
            timestamp = str(event.get("timestamp") or "").strip()
            if event_id == "cowrie.session.closed" and timestamp:
                terminal_timestamp = timestamp
                break
            if not terminal_timestamp and timestamp:
                terminal_timestamp = timestamp
    if not terminal_timestamp:
        terminal_timestamp = str(
            session_payload.get("updated_at")
            or session_payload.get("end_timestamp")
            or ""
        ).strip()

    source_ip_payload = {
        "source": "cowrie_event",
        "role": "source_ip",
        "event_id": terminal_event_id,
        "eventid": "cowrie.session.closed",
        "sensor_id": sensor_id,
        "timestamp": terminal_timestamp,
        "session_id": session_id,
    }
    for kind, value in iter_session_observables(session_payload):
        is_session_source_ip = (
            kind == "ip"
            and source_ip
            and str(value or "").strip() == source_ip
            and terminal_event_id
            and sensor_id
            and terminal_timestamp
        )
        # A hash may already have a terminal queue row from an older policy
        # generation.  Re-open that row at session close so the worker can
        # serve a fresh cache hit or apply the current provider/policy gates.
        # This does not force provider I/O: provider caches and proof guards
        # remain authoritative inside the enrichment worker.
        force_terminal_job = bool(
            (force_source_ip and kind == "ip") or kind == "hash"
        )
        storage.enqueue_enrichment_job(
            kind,
            value,
            session_id=session_id,
            force=force_terminal_job,
            payload=(
                source_ip_payload
                if is_session_source_ip
                else {"source": "session_close", "session_id": session_id}
            ),
        )
        count += 1
    return count


def load_combined_ip_enrichment(
    storage: Any = None,
    file_path: str = "",
    allow_stale: bool = True,
    local_max_bytes: int = 16 * 1024 * 1024,
    local_max_records: int = 100_000,
) -> Dict[str, Dict[str, Any]]:
    """
    Load IP enrichment from a verified local snapshot and durable storage cache.

    File data is loaded first for notebook/demo compatibility. Storage records
    then override the same IP when a fresher production enrichment record exists.
    """
    merged: Dict[str, Dict[str, Any]] = {}
    if file_path:
        merged.update(
            load_local_enrichment_snapshot(
                file_path,
                max_bytes=local_max_bytes,
                max_records=local_max_records,
                allow_stale=allow_stale,
            )
        )
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
