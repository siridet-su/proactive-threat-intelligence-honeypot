"""External enrichment provider adapters and normalization logic.

These adapters are used only by the background enrichment worker. Real-time
ingest/session processing reads cached records and never waits on these APIs.
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

from production.utils.config import ProductionConfig
from production.utils.serialization import utc_now


@dataclass
class ProviderResult:
    provider: str
    status: str
    data: Dict[str, Any] = field(default_factory=dict)
    ttl_seconds: int = 86400
    error: str = ""
    fetched_at: str = field(default_factory=utc_now)

    def to_status(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "error": self.error,
            "fetched_at": self.fetched_at,
            "ttl_seconds": self.ttl_seconds,
        }


class EnrichmentProvider:
    name = "base"
    supported_types: set[str] = set()

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

    def __init__(self, api_key: str = "", timeout: int = 20, ttl_seconds: int = 86400) -> None:
        self.api_key = api_key
        self.timeout = timeout
        self.ttl_seconds = ttl_seconds

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def _json_get(self, url: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        request = urllib.request.Request(url, headers=headers or {}, method="GET")
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            body = response.read().decode("utf-8")
        return json.loads(body)

    def _disabled(self) -> ProviderResult:
        return ProviderResult(self.name, "not_configured", ttl_seconds=min(self.ttl_seconds, 3600))

    def _error(self, exc: Exception) -> ProviderResult:
        return ProviderResult(
            self.name,
            "error",
            ttl_seconds=min(self.ttl_seconds, 3600),
            error=f"{type(exc).__name__}: {exc}",
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
            return ProviderResult(self.name, "unsupported")
        encoded = urllib.parse.quote(observable_value, safe="")
        url = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{encoded}/general"
        try:
            data = self._json_get(url, headers={"X-OTX-API-KEY": self.api_key})
            return ProviderResult(self.name, "ok", data, self.ttl_seconds)
        except Exception as exc:
            return self._error(exc)


class AbuseIPDBProvider(HTTPProvider):
    name = "abuseipdb"
    supported_types = {"ip"}

    def enrich(self, observable_type: str, observable_value: str) -> ProviderResult:
        if not self.enabled:
            return self._disabled()
        query = urllib.parse.urlencode({"ipAddress": observable_value, "maxAgeInDays": 90, "verbose": ""})
        url = f"https://api.abuseipdb.com/api/v2/check?{query}"
        try:
            data = self._json_get(url, headers={"Key": self.api_key, "Accept": "application/json"})
            return ProviderResult(self.name, "ok", data.get("data", data), self.ttl_seconds)
        except Exception as exc:
            return self._error(exc)


class ShodanProvider(HTTPProvider):
    name = "shodan"
    supported_types = {"ip"}

    def enrich(self, observable_type: str, observable_value: str) -> ProviderResult:
        if not self.enabled:
            return self._disabled()
        url = f"https://api.shodan.io/shodan/host/{urllib.parse.quote(observable_value)}?key={urllib.parse.quote(self.api_key)}"
        try:
            data = self._json_get(url)
            data["_shodan_api"] = "host"
            return ProviderResult(self.name, "ok", data, self.ttl_seconds)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return ProviderResult(self.name, "not_found", ttl_seconds=self.ttl_seconds)
            return self._enrich_internetdb(observable_value, primary_error=exc)
        except Exception as exc:
            return self._enrich_internetdb(observable_value, primary_error=exc)

    def _enrich_internetdb(self, observable_value: str, primary_error: Exception) -> ProviderResult:
        url = f"https://internetdb.shodan.io/{urllib.parse.quote(observable_value)}"
        try:
            data = self._json_get(url, headers={"Accept": "application/json", "User-Agent": "honeypot-shodan-internetdb/1.0"})
            data["_shodan_api"] = "internetdb"
            data["_shodan_primary_error"] = f"{type(primary_error).__name__}: {primary_error}"
            return ProviderResult(self.name, "ok", data, self.ttl_seconds)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return ProviderResult(
                    self.name,
                    "not_found",
                    data={"_shodan_api": "internetdb"},
                    ttl_seconds=self.ttl_seconds,
                    error=f"primary lookup failed; InternetDB has no record: {type(primary_error).__name__}: {primary_error}",
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
            return ProviderResult(self.name, "unsupported")
        url = f"https://www.virustotal.com/api/v3/{endpoint}"
        try:
            return ProviderResult(self.name, "ok", self._json_get(url, headers={"x-apikey": self.api_key}), self.ttl_seconds)
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
    ) -> None:
        super().__init__(api_key=api_secret, timeout=timeout, ttl_seconds=ttl_seconds)
        self.api_id = api_id
        self.platform_token = platform_token
        self.organization_id = organization_id

    @property
    def enabled(self) -> bool:
        return bool(self.platform_token or (self.api_id and self.api_key))

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
            return ProviderResult(self.name, "ok", data, self.ttl_seconds)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return ProviderResult(self.name, "not_found", ttl_seconds=self.ttl_seconds)
            return self._error(exc)
        except Exception as exc:
            return self._error(exc)

    def _enrich_legacy(self, observable_value: str) -> ProviderResult:
        token = base64.b64encode(f"{self.api_id}:{self.api_key}".encode("utf-8")).decode("ascii")
        url = f"https://search.censys.io/api/v2/hosts/{urllib.parse.quote(observable_value)}"
        try:
            data = self._json_get(url, headers={"Authorization": f"Basic {token}"})
            data["_censys_api"] = "legacy"
            return ProviderResult(self.name, "ok", data, self.ttl_seconds)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return ProviderResult(self.name, "not_found", ttl_seconds=self.ttl_seconds)
            return self._error(exc)
        except Exception as exc:
            return self._error(exc)


def build_default_providers(config: ProductionConfig) -> List[EnrichmentProvider]:
    ttl = int(config.enrichment_ttl_seconds)
    return [
        OTXProvider(config.otx_api_key, ttl_seconds=ttl),
        AbuseIPDBProvider(config.abuseipdb_api_key, ttl_seconds=ttl),
        ShodanProvider(config.shodan_api_key, ttl_seconds=ttl),
        CensysProvider(
            config.censys_api_id,
            config.censys_api_secret,
            platform_token=config.censys_platform_token,
            organization_id=config.censys_organization_id,
            ttl_seconds=ttl,
        ),
        VirusTotalProvider(config.virustotal_api_key, ttl_seconds=ttl),
    ]


def _merge_tags(*values: Iterable[Any]) -> List[str]:
    seen, out = set(), []
    for group in values:
        for item in group or []:
            if item is None:
                continue
            text = str(item).strip()
            if text and text not in seen:
                seen.add(text)
                out.append(text)
    return out


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
    for value in values or []:
        if value:
            out.append(str(value))
    return out


def merge_provider_results(
    observable_type: str,
    observable_value: str,
    results: List[ProviderResult],
    default_ttl_seconds: int = 86400,
) -> tuple[Dict[str, Any], Dict[str, Any], str]:
    """Normalize provider outputs into the existing enrichment_mapping_1b format."""
    payload: Dict[str, Any] = {
        "observable_type": observable_type,
        "observable_value": observable_value,
        "provider_status": {},
    }
    ttl_seconds = default_ttl_seconds

    for result in results:
        payload["provider_status"][result.provider] = result.to_status()
        if result.status != "ok":
            ttl_seconds = min(ttl_seconds, max(result.ttl_seconds, 3600))
            continue
        ttl_seconds = min(ttl_seconds, result.ttl_seconds)
        data = result.data or {}

        if result.provider == "static":
            payload.update(data)

        elif result.provider == "otx":
            pulses = data.get("pulse_info", {}).get("pulses", []) or []
            if pulses:
                payload.setdefault("raw_otx_pulse", pulses[0].get("name"))
                payload["otx_tags"] = _merge_tags(
                    payload.get("otx_tags", []),
                    *(pulse.get("tags", []) for pulse in pulses),
                )
            payload["otx_tags"] = _merge_tags(payload.get("otx_tags", []), data.get("tags", []))

        elif result.provider == "abuseipdb":
            payload.setdefault("country", data.get("countryCode"))
            payload.setdefault("isp", data.get("isp"))
            payload["risk_score"] = data.get("abuseConfidenceScore", payload.get("risk_score", 0)) or 0
            payload["total_reports"] = data.get("totalReports", payload.get("total_reports", 0)) or 0
            categories = []
            for report in data.get("reports", []) or []:
                categories.extend(report.get("categories", []) or [])
            payload["abuseipdb_categories"] = sorted(set(categories))
            payload["abuse_tags"] = _merge_tags(payload.get("abuse_tags", []), [data.get("usageType"), data.get("domain")])

        elif result.provider == "shodan":
            payload["shodan_api"] = data.get("_shodan_api", payload.get("shodan_api", "host"))
            payload.setdefault("asn", data.get("asn"))
            payload.setdefault("country", data.get("country_code") or data.get("country_name"))
            payload.setdefault("isp", data.get("isp") or data.get("org"))
            payload["open_ports"] = sorted(set(data.get("ports", []) or []))
            payload["shodan_tags"] = _merge_tags(payload.get("shodan_tags", []), data.get("tags", []))
            payload["shodan_hostnames"] = _merge_tags(payload.get("shodan_hostnames", []), data.get("hostnames", []))
            payload["shodan_cpes"] = _merge_tags(payload.get("shodan_cpes", []), _string_values(data.get("cpes", [])))
            payload["shodan_vulns"] = _merge_tags(payload.get("shodan_vulns", []), _string_values(data.get("vulns", [])))
            services = []
            for service in data.get("data", []) or []:
                product = service.get("product") or service.get("_shodan", {}).get("module")
                port = service.get("port")
                if product and port:
                    services.append(f"{product} {port}")
                elif product:
                    services.append(product)
            payload["running_services"] = _merge_tags(payload.get("running_services", []), services)

        elif result.provider == "censys":
            result_block = _censys_host_resource(data)
            payload["censys_api"] = data.get("_censys_api", payload.get("censys_api", "unknown"))
            services = result_block.get("services", []) or []
            payload["open_ports"] = sorted(set(payload.get("open_ports", []) + [svc.get("port") for svc in services if svc.get("port")]))
            payload["running_services"] = _merge_tags(
                payload.get("running_services", []),
                [_service_name(svc) for svc in services],
            )
            location = result_block.get("location", {}) or {}
            autonomous_system = result_block.get("autonomous_system", {}) or {}
            payload.setdefault("country", location.get("country_code") or location.get("country"))
            payload.setdefault("asn", autonomous_system.get("asn"))
            payload.setdefault("isp", autonomous_system.get("name") or autonomous_system.get("description"))
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
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=max(ttl_seconds, 3600))).isoformat()
    payload["enrichment_cache"] = {
        "source": "storage",
        "status": "fresh",
        "fetched_at": utc_now(),
        "expires_at": expires_at,
    }
    return payload, status, expires_at
