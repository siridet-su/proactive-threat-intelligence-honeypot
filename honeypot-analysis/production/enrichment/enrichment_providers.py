"""External enrichment provider adapters and normalization logic.

These adapters are used only by the background enrichment worker. Real-time
ingest/session processing reads cached records and never waits on these APIs.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional

from production.enrichment.external_ti_contract import (
    EXTERNAL_TI_EVIDENCE_SCHEMA,
    parse_retry_after,
    provider_config,
    provider_config_identity,
    provider_evidence_from_result,
    normalize_provider_extension,
    SOURCE_IP_PROFILE,
    validate_fixed_endpoint_url,
)
from production.utils.config import ProductionConfig
from production.utils.sensitive_data import (
    redact_error_for_log,
    redact_exception_for_log,
    redact_for_api,
)
from production.utils.serialization import utc_now


def _normalize_public_source_ip(value: Any) -> str:
    """Return only a syntactically valid globally routable IP for adapters."""

    try:
        parsed = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return ""
    return str(parsed) if parsed.is_global else ""


@dataclass
class ProviderResult:
    provider: str
    status: str
    data: Dict[str, Any] = field(default_factory=dict)
    ttl_seconds: int = 86400
    error: str = ""
    fetched_at: str = field(default_factory=utc_now)
    latency_ms: float = 0.0
    http_status: Optional[int] = None
    retry_after_seconds: Optional[float] = None
    endpoint_id: str = ""
    provider_mode: str = "lookup"
    api_version: str = ""
    normalizer_identity: str = EXTERNAL_TI_EVIDENCE_SCHEMA
    privacy_policy_identity: str = "external_ti_non_ip.v1"
    provider_config_identity: str = ""
    attempt_count: int = 0
    budget_consumed: int = 0
    next_eligible_at: Optional[str] = None
    # A durable source-IP cache hit carries already-sanitized context rather
    # than a provider response.  These fields are intentionally optional so
    # normal provider adapters continue to expose their existing contract.
    normalized_extension: Optional[Dict[str, Any]] = None
    normalized_finding: str = ""
    cached_lookup_status: str = ""

    def to_status(self) -> Dict[str, Any]:
        try:
            fetched = datetime.fromisoformat(self.fetched_at.replace("Z", "+00:00"))
            if fetched.tzinfo is None:
                fetched = fetched.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            fetched = datetime.now(timezone.utc)
        result = {
            "status": self.status,
            "error": redact_error_for_log(self.error) if self.error else "",
            "fetched_at": self.fetched_at,
            "ttl_seconds": self.ttl_seconds,
            "latency_ms": round(max(float(self.latency_ms), 0.0), 3),
            "expires_at": (
                fetched + timedelta(seconds=max(int(self.ttl_seconds), 0))
            ).isoformat(),
            "http_status": self.http_status,
            "retry_after_seconds": self.retry_after_seconds,
            "endpoint_id": self.endpoint_id,
            "provider_mode": self.provider_mode,
            "api_version": self.api_version,
            "normalizer_identity": self.normalizer_identity,
            "privacy_policy_identity": self.privacy_policy_identity,
            "provider_config_identity": self.provider_config_identity,
            "attempt_count": max(int(self.attempt_count), 0),
            "budget_consumed": max(int(self.budget_consumed), 0),
            "next_eligible_at": self.next_eligible_at,
            "cache_lookup_status": self.cached_lookup_status,
        }
        result["provider_evidence"] = provider_evidence_from_result(self, {})
        return result


class ProviderBudgetError(RuntimeError):
    """Internal non-network outcome raised when a per-attempt budget blocks."""

    def __init__(self, decision: Any) -> None:
        self.decision = decision
        super().__init__(str(getattr(decision, "status", "budget_exhausted")))


class EnrichmentProvider:
    name = "base"
    supported_types: set[str] = set()
    external = False

    def supports(self, observable_type: str) -> bool:
        return observable_type in self.supported_types

    def enrich(self, observable_type: str, observable_value: str) -> ProviderResult:
        raise NotImplementedError


class StaticProvider(EnrichmentProvider):
    """Test/local provider that returns precomputed records."""

    name = "static"
    supported_types = {"ip", "url", "domain", "hash", "hassh", "ja3"}

    def __init__(self, records: Dict[tuple[str, str], Dict[str, Any]], ttl_seconds: int = 86400) -> None:
        self.records = records
        self.ttl_seconds = ttl_seconds

    def enrich(self, observable_type: str, observable_value: str) -> ProviderResult:
        data = self.records.get((observable_type, observable_value), {})
        return ProviderResult(
            provider=self.name,
            status="ok" if data else "not_found",
            data=data,
            ttl_seconds=self.ttl_seconds,
        )


class HTTPProvider(EnrichmentProvider):
    """Small stdlib HTTP helper for JSON enrichment APIs."""

    external = True

    def __init__(
        self,
        api_key: str = "",
        timeout: float = 20,
        ttl_seconds: int = 86400,
        max_response_bytes: int = 1024 * 1024,
        retries: int = 1,
        retry_delay_seconds: float = 0.25,
        endpoint_id: str = "",
        provider_mode: str = "lookup",
        activation_enabled: bool = True,
        transport: Optional[Callable[..., Any]] = None,
        normalizer_identity: str = EXTERNAL_TI_EVIDENCE_SCHEMA,
        privacy_policy_identity: str = "external_ti_non_ip.v1",
        provider_config_identity_value: str = "",
    ) -> None:
        self.api_key = api_key
        # The activation gate deliberately consumes an explicit credential
        # presence signal instead of inspecting provider internals.  Built-in
        # HTTP adapters receive their credential through the reviewed config
        # file, so expose only the boolean needed by that gate.
        self.credential_present = bool(api_key)
        self.timeout = timeout
        self.ttl_seconds = ttl_seconds
        self.max_response_bytes = max(int(max_response_bytes), 1024)
        self.retries = max(int(retries), 0)
        self.retry_delay_seconds = max(float(retry_delay_seconds), 0.0)
        self.endpoint_id = str(endpoint_id or "")
        self.provider_mode = str(provider_mode or "lookup")
        self.activation_enabled = bool(activation_enabled)
        self.transport = transport
        self.normalizer_identity = str(normalizer_identity or EXTERNAL_TI_EVIDENCE_SCHEMA)
        self.privacy_policy_identity = str(privacy_policy_identity or "external_ti_non_ip.v1")
        self.provider_config_identity_value = str(provider_config_identity_value or "")
        self.attempt_reserver: Optional[Callable[[], Any]] = None
        self._last_attempt_count = 0

    @property
    def enabled(self) -> bool:
        return self.activation_enabled and bool(self.api_key)

    def _result(self, status: str, data: Optional[Dict[str, Any]] = None, **kwargs: Any) -> ProviderResult:
        kwargs.setdefault("attempt_count", self._last_attempt_count)
        return ProviderResult(
            provider=self.name,
            status=status,
            data=data or {},
            endpoint_id=self.endpoint_id,
            provider_mode=self.provider_mode,
            normalizer_identity=self.normalizer_identity,
            privacy_policy_identity=self.privacy_policy_identity,
            provider_config_identity=self.provider_config_identity_value,
            **kwargs,
        )

    def _json_get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        *,
        endpoint_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        request_endpoint_id = str(endpoint_id or self.endpoint_id or "")
        if request_endpoint_id:
            validate_fixed_endpoint_url(self.name, request_endpoint_id, url)
        request = urllib.request.Request(url, headers=headers or {}, method="GET")
        opener = None
        if request_endpoint_id:
            class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
                    raise urllib.error.HTTPError(req.full_url, code, "provider redirect rejected", headers, None)

            # Fixed-origin provider traffic does not inherit workstation or
            # service proxy environment variables.  The default TLS context
            # retains certificate and hostname verification.
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                _NoRedirectHandler(),
                urllib.request.HTTPSHandler(context=ssl.create_default_context()),
            )
        for attempt in range(self.retries + 1):
            try:
                self._last_attempt_count = attempt + 1
                if self.attempt_reserver is not None:
                    decision = self.attempt_reserver()
                    if not bool(getattr(decision, "allowed", decision)):
                        raise ProviderBudgetError(decision)
                if self.transport is not None:
                    response_context = self.transport(request, timeout=self.timeout)
                elif opener is not None:
                    response_context = opener.open(request, timeout=self.timeout)
                else:
                    # Keep direct adapter construction compatible with the
                    # existing unit tests; production-built adapters always
                    # carry a fixed endpoint identity.
                    response_context = urllib.request.urlopen(request, timeout=self.timeout)
                with response_context as response:
                    final_url = getattr(response, "geturl", lambda: url)()
                    if request_endpoint_id:
                        validate_fixed_endpoint_url(self.name, request_endpoint_id, final_url)
                    content_length = response.headers.get("Content-Length")
                    if content_length and int(content_length) > self.max_response_bytes:
                        raise ValueError("provider response exceeds configured limit")
                    body = response.read(self.max_response_bytes + 1)
                    if len(body) > self.max_response_bytes:
                        raise ValueError("provider response exceeds configured limit")
                decoded = json.loads(body.decode("utf-8"))
                if not isinstance(decoded, dict):
                    raise ValueError("provider response must contain a JSON object")
                return decoded
            except Exception as exc:
                if isinstance(exc, ProviderBudgetError):
                    raise
                if isinstance(exc, urllib.error.HTTPError) and exc.code == 429:
                    retry_after = parse_retry_after(
                        exc.headers.get("Retry-After") if exc.headers else None
                    )
                    # A server-provided retry window is handled by the worker's
                    # provider-local defer state; never retry early in this
                    # adapter.
                    if retry_after is not None:
                        raise
                retryable = self._is_temporary_error(exc)
                if not retryable or attempt >= self.retries:
                    raise
                time.sleep(self.retry_delay_seconds * (attempt + 1))
        raise RuntimeError("provider request did not complete")

    @staticmethod
    def _is_temporary_error(exc: Exception) -> bool:
        if isinstance(exc, urllib.error.HTTPError):
            return exc.code in {408, 425, 429} or 500 <= exc.code <= 599
        return isinstance(exc, (TimeoutError, ConnectionError, urllib.error.URLError))

    def _disabled(self) -> ProviderResult:
        return self._result("not_configured", ttl_seconds=min(self.ttl_seconds, 3600))

    def _error(self, exc: Exception) -> ProviderResult:
        if isinstance(exc, ProviderBudgetError):
            raise exc
        if isinstance(exc, urllib.error.HTTPError) and exc.code in {401, 403}:
            status = "auth_disabled"
        elif isinstance(exc, urllib.error.HTTPError) and exc.code == 429:
            status = "rate_limited"
        elif self._is_temporary_error(exc):
            status = "temporary_error"
        else:
            status = "permanent_error"
        http_status = exc.code if isinstance(exc, urllib.error.HTTPError) else None
        retry_after = None
        if isinstance(exc, urllib.error.HTTPError):
            retry_after = parse_retry_after(exc.headers.get("Retry-After")) if exc.headers else None
        return self._result(
            status,
            ttl_seconds=min(self.ttl_seconds, 3600),
            error=redact_exception_for_log(exc),
            http_status=http_status,
            retry_after_seconds=retry_after,
        )


class OTXProvider(HTTPProvider):
    name = "otx"
    supported_types = {"ip", "domain", "url", "hash"}

    def enrich(self, observable_type: str, observable_value: str) -> ProviderResult:
        if not self.enabled:
            return self._disabled()
        indicator_type = {
            "ip": "IPv4",
            "domain": "domain",
            "url": "url",
            "hash": "file",
        }.get(observable_type)
        if not indicator_type:
            return self._result("unsupported")
        encoded = urllib.parse.quote(observable_value, safe="")
        url = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{encoded}/general"
        try:
            data = self._json_get(url, headers={"X-OTX-API-KEY": self.api_key})
            return self._result("ok", data, ttl_seconds=self.ttl_seconds)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return self._result("not_found", ttl_seconds=self.ttl_seconds)
            return self._error(exc)
        except Exception as exc:
            return self._error(exc)


class AbuseIPDBProvider(HTTPProvider):
    name = "abuseipdb"
    supported_types = {"ip"}

    def enrich(self, observable_type: str, observable_value: str) -> ProviderResult:
        if not self.enabled:
            return self._disabled()
        normalized_ip = _normalize_public_source_ip(observable_value)
        if not normalized_ip:
            return self._result("invalid_observable", ttl_seconds=min(self.ttl_seconds, 3600))
        query = urllib.parse.urlencode({"ipAddress": normalized_ip, "maxAgeInDays": 90, "verbose": ""})
        url = f"https://api.abuseipdb.com/api/v2/check?{query}"
        try:
            data = self._json_get(
                url,
                headers={"Key": self.api_key, "Accept": "application/json"},
                endpoint_id="abuseipdb_check_v2",
            )
            return self._result("ok", data.get("data", data), ttl_seconds=self.ttl_seconds)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return self._result("not_found", ttl_seconds=self.ttl_seconds)
            return self._error(exc)
        except Exception as exc:
            return self._error(exc)


class ShodanOfficialProvider(HTTPProvider):
    """Official Shodan host lookup; query-key auth is deliberately explicit."""

    name = "shodan_official"
    supported_types = {"ip"}

    def enrich(self, observable_type: str, observable_value: str) -> ProviderResult:
        if not self.enabled:
            return self._disabled()
        normalized_ip = _normalize_public_source_ip(observable_value)
        if not normalized_ip:
            return self._result("invalid_observable", ttl_seconds=min(self.ttl_seconds, 3600))
        url = (
            "https://api.shodan.io/shodan/host/"
            f"{urllib.parse.quote(normalized_ip, safe='')}?key="
            f"{urllib.parse.quote(self.api_key, safe='')}"
        )
        try:
            data = self._json_get(
                url,
                headers={"Accept": "application/json"},
                endpoint_id="shodan_host_v1",
            )
            _, _, finding, _, _, _ = normalize_provider_extension(self.name, data)
            if finding == "NO_ADDITIONAL_CONTEXT":
                return self._result(
                    "malformed_response",
                    error="provider response contained no bounded Shodan context",
                    ttl_seconds=min(self.ttl_seconds, 3600),
                )
            return self._result("ok", data, ttl_seconds=self.ttl_seconds)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return self._result("not_found", ttl_seconds=self.ttl_seconds)
            return self._error(exc)
        except ProviderBudgetError:
            raise
        except Exception as exc:
            return self._error(exc)


class ShodanInternetDBProvider(HTTPProvider):
    """Explicit unauthenticated InternetDB context; never an official fallback."""

    name = "shodan_internetdb"
    supported_types = {"ip"}
    requires_credential = False

    @property
    def enabled(self) -> bool:
        return self.activation_enabled

    def enrich(self, observable_type: str, observable_value: str) -> ProviderResult:
        if not self.enabled:
            return self._disabled()
        normalized_ip = _normalize_public_source_ip(observable_value)
        if not normalized_ip:
            return self._result("invalid_observable", ttl_seconds=min(self.ttl_seconds, 3600))
        url = f"https://internetdb.shodan.io/{urllib.parse.quote(normalized_ip, safe='')}"
        try:
            data = self._json_get(
                url,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "honeypot-shodan-internetdb/1.0",
                },
                endpoint_id="shodan_internetdb_v1",
            )
            _, _, finding, _, _, _ = normalize_provider_extension(self.name, data)
            if finding == "NO_ADDITIONAL_CONTEXT":
                return self._result(
                    "malformed_response",
                    error="provider response contained no bounded Shodan context",
                    ttl_seconds=min(self.ttl_seconds, 3600),
                )
            return self._result("ok", data, ttl_seconds=self.ttl_seconds)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return self._result(
                    "not_found",
                    ttl_seconds=self.ttl_seconds,
                )
            return self._error(exc)
        except Exception as exc:
            return self._error(exc)


class VirusTotalProvider(HTTPProvider):
    name = "virustotal"
    supported_types = {"ip", "domain", "url", "hash"}

    def enrich(self, observable_type: str, observable_value: str) -> ProviderResult:
        if not self.enabled:
            return self._disabled()
        endpoint = {
            "ip": f"ip_addresses/{observable_value}",
            "domain": f"domains/{observable_value}",
            "hash": f"files/{observable_value}",
        }.get(observable_type)
        if observable_type == "url":
            encoded = base64.urlsafe_b64encode(observable_value.encode("utf-8")).decode("ascii").rstrip("=")
            endpoint = f"urls/{encoded}"
        if not endpoint:
            return self._result("unsupported")
        url = f"https://www.virustotal.com/api/v3/{endpoint}"
        try:
            return self._result(
                "ok",
                self._json_get(url, headers={"x-apikey": self.api_key}),
                ttl_seconds=self.ttl_seconds,
            )
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return self._result("not_found", ttl_seconds=self.ttl_seconds)
            return self._error(exc)
        except Exception as exc:
            return self._error(exc)


class CensysProvider(HTTPProvider):
    name = "censys"
    supported_types = {"ip"}

    def __init__(
        self,
        api_id: str = "",
        api_secret: str = "",
        platform_token: str = "",
        organization_id: str = "",
        timeout: int = 20,
        ttl_seconds: int = 86400,
        max_response_bytes: int = 1024 * 1024,
        retries: int = 1,
        retry_delay_seconds: float = 0.25,
        endpoint_id: str = "",
        provider_mode: str = "lookup",
        activation_enabled: bool = True,
        transport: Optional[Callable[..., Any]] = None,
        normalizer_identity: str = EXTERNAL_TI_EVIDENCE_SCHEMA,
        privacy_policy_identity: str = "external_ti_non_ip.v1",
        provider_config_identity_value: str = "",
    ) -> None:
        super().__init__(
            api_key=api_secret,
            timeout=timeout,
            ttl_seconds=ttl_seconds,
            max_response_bytes=max_response_bytes,
            retries=retries,
            retry_delay_seconds=retry_delay_seconds,
            endpoint_id=endpoint_id,
            provider_mode=provider_mode,
            activation_enabled=activation_enabled,
            transport=transport,
            normalizer_identity=normalizer_identity,
            privacy_policy_identity=privacy_policy_identity,
            provider_config_identity_value=provider_config_identity_value,
        )
        self.api_id = api_id
        self.platform_token = platform_token
        self.organization_id = organization_id

    @property
    def enabled(self) -> bool:
        return self.activation_enabled and bool(
            self.platform_token or (self.api_id and self.api_key)
        )

    def enrich(self, observable_type: str, observable_value: str) -> ProviderResult:
        if not self.enabled:
            return self._disabled()
        if self.platform_token:
            return self._enrich_platform(observable_value)
        return self._enrich_legacy(observable_value)

    def _enrich_platform(self, observable_value: str) -> ProviderResult:
        query = ""
        if self.organization_id:
            query = "?" + urllib.parse.urlencode({"organization_id": self.organization_id})
        url = f"https://api.platform.censys.io/v3/global/asset/host/{urllib.parse.quote(observable_value)}{query}"
        try:
            data = self._json_get(
                url,
                headers={
                    "Authorization": f"Bearer {self.platform_token}",
                    "Accept": "application/json",
                    "User-Agent": "honeypot-censys-enrichment/1.0",
                },
            )
            data["_censys_api"] = "platform"
            return self._result("ok", data, ttl_seconds=self.ttl_seconds)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return self._result("not_found", ttl_seconds=self.ttl_seconds)
            return self._error(exc)
        except Exception as exc:
            return self._error(exc)

    def _enrich_legacy(self, observable_value: str) -> ProviderResult:
        token = base64.b64encode(f"{self.api_id}:{self.api_key}".encode("utf-8")).decode("ascii")
        url = f"https://search.censys.io/api/v2/hosts/{urllib.parse.quote(observable_value)}"
        try:
            data = self._json_get(url, headers={"Authorization": f"Basic {token}"})
            data["_censys_api"] = "legacy"
            return self._result("ok", data, ttl_seconds=self.ttl_seconds)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return self._result("not_found", ttl_seconds=self.ttl_seconds)
            return self._error(exc)
        except Exception as exc:
            return self._error(exc)


def build_default_providers(config: ProductionConfig) -> List[EnrichmentProvider]:
    ttl = int(config.enrichment_ttl_seconds)
    provider_options = {
        "timeout": config.enrichment_provider_timeout_seconds,
        "ttl_seconds": ttl,
        "max_response_bytes": config.enrichment_provider_max_response_bytes,
        "retries": config.enrichment_provider_http_retries,
        "retry_delay_seconds": config.enrichment_provider_retry_delay_seconds,
    }
    configured = getattr(config, "external_ti_provider_configs", {}) or {}
    policy_identity = getattr(config, "external_ti_policy_identity", "external_ti_non_ip.v1")
    normalizer_identity = getattr(config, "external_ti_normalizer_identity", EXTERNAL_TI_EVIDENCE_SCHEMA)
    globally_enabled = bool(getattr(config, "external_ti_enabled", False)) and str(
        getattr(config, "external_enrichment_profile", "disabled") or ""
    ).strip().lower() in {"non_ip_observables", SOURCE_IP_PROFILE}

    def options(name: str) -> Dict[str, Any]:
        settings = provider_config(name, configured.get(name))
        settings.setdefault("provider", name)
        settings.setdefault("mode", "lookup")
        settings.setdefault("endpoint_id", "")
        settings.setdefault("enabled", False)
        settings.setdefault("normalizer_identity", normalizer_identity)
        settings.setdefault("policy_identity", policy_identity)
        settings["provider_config_identity"] = provider_config_identity(name, settings)
        return {
            **provider_options,
            "endpoint_id": settings["endpoint_id"],
            "provider_mode": settings["mode"],
            # A key alone is never enough to activate a built-in adapter.
            "activation_enabled": bool(settings.get("enabled", False)) and globally_enabled,
            "normalizer_identity": settings["normalizer_identity"],
            "privacy_policy_identity": settings["policy_identity"],
            "provider_config_identity_value": settings["provider_config_identity"],
            "retries": min(
                int(provider_options["retries"]),
                max(int(settings.get("max_attempts") or 1) - 1, 0),
            ),
        }

    return [
        OTXProvider(config.otx_api_key, **options("otx")),
        AbuseIPDBProvider(config.abuseipdb_api_key, **options("abuseipdb")),
        ShodanOfficialProvider(config.shodan_api_key, **options("shodan_official")),
        ShodanInternetDBProvider(**options("shodan_internetdb")),
        CensysProvider(
            config.censys_api_id,
            config.censys_api_secret,
            platform_token=config.censys_platform_token,
            organization_id=config.censys_organization_id,
            **options("censys"),
        ),
        VirusTotalProvider(config.virustotal_api_key, **options("virustotal")),
    ]


def _merge_tags(*values: Iterable[Any]) -> List[str]:
    seen, out = set(), []
    for group in values:
        if isinstance(group, str):
            group = [group]
        elif not isinstance(group, (list, tuple, set)):
            continue
        for item in group:
            if item is None:
                continue
            text = str(item).strip()[:256]
            if text and text not in seen:
                seen.add(text)
                out.append(text)
                if len(out) >= 256:
                    return out
    return out


def _bounded_value(value: Any, depth: int = 0) -> Any:
    if depth >= 8:
        return "[TRUNCATED]"
    if isinstance(value, str):
        return value[:4096]
    if isinstance(value, dict):
        return {
            str(key)[:128]: _bounded_value(item, depth + 1)
            for key, item in list(value.items())[:128]
        }
    if isinstance(value, (list, tuple, set)):
        return [_bounded_value(item, depth + 1) for item in list(value)[:256]]
    return value


def _set_if_value(payload: Dict[str, Any], key: str, value: Any) -> None:
    if key not in payload or payload[key] is None or payload[key] == "":
        if value is not None and value != "":
            payload[key] = value


def _vt_stats(data: Dict[str, Any]) -> Dict[str, Any]:
    attrs = data.get("data", {}).get("attributes", {}) if "data" in data else data.get("attributes", data)
    stats = attrs.get("last_analysis_stats", {}) or {}
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    total = sum(int(v or 0) for v in stats.values()) if stats else 0
    label = (
        attrs.get("popular_threat_classification", {}).get("suggested_threat_label")
        or attrs.get("meaningful_name")
        or attrs.get("type_description")
    )
    return {
        "vt_hit": malicious + suspicious > 0,
        "vt_detection_ratio": f"{malicious + suspicious}/{total}" if total else None,
        "vt_malware_family": label,
    }


def _censys_host_resource(data: Dict[str, Any]) -> Dict[str, Any]:
    """Return the host object from either Censys Platform or Legacy responses."""
    result = data.get("result", data)
    if isinstance(result, dict):
        resource = result.get("resource")
        if isinstance(resource, dict):
            return resource
        host = result.get("host")
        if isinstance(host, dict):
            return host
        return result
    return data


def _service_name(service: Dict[str, Any]) -> Optional[str]:
    name = service.get("service_name") or service.get("extended_service_name") or service.get("protocol")
    if not name:
        return None
    port = service.get("port") or (service.get("representative_info") or {}).get("sampled_port")
    transport = service.get("transport_protocol")
    suffix = f"/{transport}" if transport else ""
    return f"{name} {port}{suffix}" if port else str(name)


def _label_values(labels: Iterable[Any]) -> List[str]:
    values: List[str] = []
    for label in labels or []:
        if isinstance(label, dict):
            value = label.get("value") or label.get("name")
        else:
            value = label
        if value:
            values.append(str(value))
    return values


def _string_values(values: Iterable[Any]) -> List[str]:
    out: List[str] = []
    if isinstance(values, str) or not isinstance(values, (list, tuple, set)):
        return out
    for value in values:
        if value:
            out.append(str(value)[:256])
            if len(out) >= 256:
                break
    return out


def merge_provider_results(
    observable_type: str,
    observable_value: str,
    results: List[ProviderResult],
    default_ttl_seconds: int = 86400,
    *,
    existing_payload: Optional[Dict[str, Any]] = None,
    existing_provider_status: Optional[Dict[str, Any]] = None,
) -> tuple[Dict[str, Any], Dict[str, Any], str]:
    """Merge bounded provider results without losing a successful subrecord.

    A provider failure is a property of that provider attempt, not a reason to
    discard another provider's durable result.  The optional existing values
    are used by the worker on retries; legacy callers can continue to pass
    only the current result list.
    """
    payload: Dict[str, Any] = dict(existing_payload or {})
    payload.update({
        "observable_type": observable_type,
        "observable_value": observable_value,
    })
    payload["provider_status"] = dict(
        existing_provider_status
        or (existing_payload or {}).get("provider_status")
        or {}
    )
    payload["provider_evidence"] = dict(
        (existing_payload or {}).get("provider_evidence") or {}
    )
    payload["provider_cache"] = dict(
        (existing_payload or {}).get("provider_cache") or {}
    )
    ttl_seconds = default_ttl_seconds

    for result in results:
        existing_status = payload["provider_status"].get(result.provider)
        if result.status == "cached" and isinstance(existing_status, dict):
            # A cache hit is a control-plane outcome, not a new provider
            # response. Preserve the previously normalized evidence and its
            # expiry while recording the hit in the provider status/cache.
            cached_status = dict(existing_status)
            cached_status["status"] = "cached"
            existing_evidence = payload["provider_evidence"].get(result.provider)
            if isinstance(existing_evidence, dict):
                cached_status["provider_evidence"] = existing_evidence
            payload["provider_status"][result.provider] = cached_status
            cache_key = "|".join(
                (
                    str(result.provider).strip().lower(),
                    str(cached_status.get("provider_mode") or "lookup"),
                    str(cached_status.get("provider_config_identity") or ""),
                )
            )
            payload["provider_cache"][cache_key] = cached_status
            if not isinstance(existing_evidence, dict):
                payload["provider_evidence"][result.provider] = cached_status.get(
                    "provider_evidence", {}
                )
            continue
        result_status = result.to_status()
        payload["provider_status"][result.provider] = result_status
        cache_key = "|".join(
            (
                str(result.provider).strip().lower(),
                str(result_status.get("provider_mode") or "lookup"),
                str(result_status.get("provider_config_identity") or ""),
            )
        )
        payload["provider_cache"][cache_key] = result_status
        payload["provider_evidence"][result.provider] = payload["provider_status"][result.provider][
            "provider_evidence"
        ]
        if result.status != "ok":
            ttl_seconds = min(ttl_seconds, max(result.ttl_seconds, 3600))
            continue
        ttl_seconds = min(ttl_seconds, result.ttl_seconds)
        data = result.data or {}

        if result.provider == "static":
            bounded = redact_for_api(_bounded_value(data))
            if isinstance(bounded, dict):
                payload.update(bounded)

        elif result.provider == "otx":
            pulses = data.get("pulse_info", {}).get("pulses", []) or []
            if pulses:
                _set_if_value(payload, "raw_otx_pulse", str(pulses[0].get("name") or "")[:4096])
                payload["otx_tags"] = _merge_tags(
                    payload.get("otx_tags", []),
                    *(pulse.get("tags", []) for pulse in pulses),
                )
            payload["otx_tags"] = _merge_tags(payload.get("otx_tags", []), data.get("tags", []))

        elif result.provider == "abuseipdb":
            _set_if_value(payload, "country", data.get("countryCode"))
            _set_if_value(payload, "isp", data.get("isp"))
            _set_if_value(
                payload,
                "abuse_confidence_score",
                data.get("abuseConfidenceScore"),
            )
            payload["total_reports"] = data.get("totalReports", payload.get("total_reports", 0)) or 0
            categories = []
            for report in data.get("reports", []) or []:
                categories.extend(report.get("categories", []) or [])
            payload["abuseipdb_categories"] = sorted(set(categories))
            payload["abuse_tags"] = _merge_tags(payload.get("abuse_tags", []), [data.get("usageType"), data.get("domain")])

        elif result.provider in {"shodan", "shodan_official", "shodan_internetdb"}:
            shodan_provider = str(result.provider).strip().lower()
            evidence = result_status.get("provider_evidence")
            normalized = evidence.get("normalized_extension") if isinstance(evidence, dict) else {}
            normalized = normalized if isinstance(normalized, dict) else {}
            payload["shodan_provider"] = shodan_provider
            payload["shodan_api"] = (
                "official_host"
                if shodan_provider in {"shodan", "shodan_official"}
                else "internetdb"
            )
            payload["shodan_context_source"] = shodan_provider
            _set_if_value(payload, "asn", normalized.get("asn"))
            _set_if_value(payload, "country", normalized.get("country"))
            _set_if_value(payload, "isp", normalized.get("isp") or normalized.get("organization"))
            ports = normalized.get("ports")
            payload["open_ports"] = list(ports)[:256] if isinstance(ports, list) else []
            payload["shodan_tags"] = _merge_tags(
                payload.get("shodan_tags", []), normalized.get("tags", [])
            )
            payload["shodan_hostnames"] = _merge_tags(
                payload.get("shodan_hostnames", []), normalized.get("hostnames", [])
            )
            payload["shodan_cpes"] = _merge_tags(
                payload.get("shodan_cpes", []), normalized.get("cpe", [])
            )
            payload["shodan_vulns"] = _merge_tags(
                payload.get("shodan_vulns", []), normalized.get("vulnerabilities", [])
            )
            payload["running_services"] = _merge_tags(
                payload.get("running_services", []),
                normalized.get("service_product_summary", normalized.get("services", [])),
            )

        elif result.provider == "censys":
            result_block = _censys_host_resource(data)
            payload["censys_api"] = data.get("_censys_api", payload.get("censys_api", "unknown"))
            services = result_block.get("services", []) or []
            payload["open_ports"] = sorted(set(payload.get("open_ports", []) + [svc.get("port") for svc in services if svc.get("port")]))[:256]
            payload["running_services"] = _merge_tags(
                payload.get("running_services", []),
                [_service_name(svc) for svc in services],
            )
            location = result_block.get("location", {}) or {}
            autonomous_system = result_block.get("autonomous_system", {}) or {}
            _set_if_value(payload, "country", location.get("country_code") or location.get("country"))
            _set_if_value(payload, "asn", autonomous_system.get("asn"))
            _set_if_value(payload, "isp", autonomous_system.get("name") or autonomous_system.get("description"))
            payload["censys_labels"] = _merge_tags(
                payload.get("censys_labels", []),
                _label_values(result_block.get("labels", [])),
                *(_label_values(service.get("labels", [])) for service in services),
            )

        elif result.provider == "virustotal":
            payload.update({k: v for k, v in _vt_stats(data).items() if v is not None})

    infra_tags = set(payload.get("infrastructure_tags", []))
    all_tags = set(str(t).lower() for t in payload.get("shodan_tags", []) + payload.get("otx_tags", []) + payload.get("abuse_tags", []))
    if "tor" in all_tags or "tor-exit" in all_tags:
        payload["is_tor_exit"] = True
        infra_tags.add("tor")
    if "vpn" in all_tags or "proxy" in all_tags or "open-proxy" in all_tags:
        payload["is_vpn"] = True
        infra_tags.add("vpn")
    if payload.get("open_ports"):
        infra_tags.add("exposed_services")
    payload["infrastructure_tags"] = sorted(infra_tags)
    payload.setdefault("is_tor_exit", False)
    payload.setdefault("is_vpn", False)

    status = payload["provider_status"]
    statuses = {
        str(item.get("status") or "").strip().lower()
        for item in status.values()
        if isinstance(item, dict)
    }
    if not statuses:
        statuses = {result.status for result in results}
    successes = statuses & {"ok", "not_found", "cached"}
    temporary = statuses & {"error", "temporary_error", "rate_limited"}
    permanent = statuses & {"permanent_error"}
    if successes and not (temporary or permanent or statuses & {"not_configured"}):
        overall_status = "complete_success"
    elif successes:
        overall_status = "partial_success"
    elif temporary:
        overall_status = "temporary_failure"
    elif permanent:
        overall_status = "permanent_failure"
    else:
        overall_status = "unavailable"
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=max(ttl_seconds, 3600))).isoformat()
    payload["enrichment_cache"] = {
        "source": "storage",
        "status": "fresh",
        "fetched_at": utc_now(),
        "expires_at": expires_at,
        "overall_status": overall_status,
    }
    # ``risk_score`` was an ambiguous legacy alias and is not part of the
    # provider-neutral Phase 0 evidence contract.
    payload.pop("risk_score", None)
    return payload, status, expires_at
