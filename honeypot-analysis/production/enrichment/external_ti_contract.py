"""Provider-neutral external Threat Intelligence contracts.

This module contains the Phase 0 safety boundary shared by the background
worker, provider adapters, storage projection and API.  It deliberately has
no network client and no configuration-secret dependency.  Real provider
traffic is fail-closed until every explicit activation condition is true.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlsplit

from production.utils.serialization import stable_id, stable_json, utc_now


EXTERNAL_TI_EVIDENCE_SCHEMA = "external_ti_evidence.v1"
EXTERNAL_TI_PROVIDER_EVIDENCE_SCHEMA = "external_ti_provider_evidence.v1"
EXTERNAL_TI_AUTHORITY = "NON_AUTHORITATIVE_CONTEXT_ONLY"
EXTERNAL_TI_PROFILE = "non_ip_observables"
SOURCE_IP_PROFILE = "source_ip_observables"
SOURCE_IP_POLICY_ID = "honeypot-thesis-data-lifecycle.source-ip.external-ti"
SOURCE_IP_POLICY_VERSION = "1.0.0"
SOURCE_IP_AMENDMENT_SCHEMA = "external_ti_source_ip_governance_amendment.v1"
SOURCE_IP_PRODUCTION_POLICY_VERSION = "2.1.0"
SOURCE_IP_PRODUCTION_SCHEMA = "external_ti_source_ip_governance.v2"
SOURCE_IP_AMENDMENT_SHA256 = "b8e292d9eeb80e10af8695fe4b3e0a74216894191eca9790c8e75182203beace"
SOURCE_IP_ENRICHMENT_MODE = "NEW_ELIGIBLE_SIGHTINGS_ONLY"
SOURCE_IP_CUTOFF_TIMESTAMP_FIELD = "timestamp"
SOURCE_IP_PROVIDER_NAMES = frozenset(
    {"abuseipdb", "shodan_official", "shodan_internetdb"}
)
_SOURCE_IP_POLICY_PROVIDER = {
    "abuseipdb": "abuseipdb",
    "shodan_official": "shodan",
    "shodan_internetdb": "shodan",
}
KNOWN_PROVIDERS = frozenset(
    {"virustotal", "otx", "shodan_official", "shodan_internetdb", "abuseipdb", "censys"}
)
KNOWN_ENDPOINTS = {
    "virustotal": frozenset({"virustotal_lookup_v3"}),
    "otx": frozenset({"otx_general_v1"}),
    "shodan_official": frozenset({"shodan_host_v1"}),
    "shodan_internetdb": frozenset({"shodan_internetdb_v1"}),
    "abuseipdb": frozenset({"abuseipdb_check_v2"}),
    "censys": frozenset({"censys_host_v3"}),
}
ENDPOINT_HOSTS = {
    "virustotal_lookup_v3": ("www.virustotal.com", "/api/v3/"),
    "otx_general_v1": ("otx.alienvault.com", "/api/v1/indicators/"),
    "shodan_host_v1": ("api.shodan.io", "/shodan/host/"),
    "shodan_internetdb_v1": ("internetdb.shodan.io", "/"),
    "abuseipdb_check_v2": ("api.abuseipdb.com", "/api/v2/check"),
    "censys_host_v3": ("api.platform.censys.io", "/v3/global/asset/host/"),
}
ALLOWED_OBSERVABLE_TYPES = frozenset({"hash", "domain", "ip", "url"})
ALLOWED_OBSERVABLE_ROLES = frozenset({"file_hash", "public_hostname", "source_ip"})
ALLOWED_HASH_ALGORITHMS = frozenset({"md5", "sha1", "sha256"})
PROVIDER_STATUS_VALUES = frozenset(
    {
        "ok",
        "not_found",
        "not_configured",
        "disabled",
        "unsupported",
        "policy_prohibited",
        "invalid_observable",
        "error",
        "temporary_error",
        "permanent_error",
        "rate_limited",
        "auth_disabled",
        "budget_exhausted",
        "malformed_response",
        "cached",
    }
)
LOOKUP_STATUS_MAP = {
    "ok": "OK",
    "cached": "OK",
    "not_found": "NOT_FOUND",
    "not_configured": "DISABLED",
    "disabled": "DISABLED",
    "policy_prohibited": "DISABLED",
    "unsupported": "INVALID_OBSERVABLE",
    "invalid_observable": "INVALID_OBSERVABLE",
    "error": "PROVIDER_ERROR",
    "temporary_error": "PROVIDER_ERROR",
    "permanent_error": "PROVIDER_ERROR",
    "rate_limited": "RATE_LIMITED",
    "auth_disabled": "AUTH_DISABLED",
    "budget_exhausted": "BUDGET_EXHAUSTED",
    "malformed_response": "PROVIDER_ERROR",
}
FINDING_STATES = frozenset(
    {
        "DETECTIONS_PRESENT",
        "NO_PROVIDER_DETECTION",
        "NO_DETECTIONS_REPORTED",
        "NO_ADDITIONAL_CONTEXT",
        "NOT_FOUND",
        "CONTEXT_PRESENT",
        "PENDING",
        "STALE",
        "RATE_LIMITED",
        "UNAVAILABLE",
        "ERROR",
        "AUTH_DISABLED",
        "BUDGET_EXHAUSTED",
    }
)
UNCERTAINTY_STATES = frozenset(
    {"SUPPORTING_CONTEXT", "CONTRADICTING_CONTEXT", "CONTEXT_ONLY", "UNKNOWN"}
)
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
MAX_RETRY_AFTER_SECONDS = 30 * 24 * 60 * 60


def default_external_ti_provider_configs() -> Dict[str, Dict[str, Any]]:
    """Return secret-free, disabled provider configuration placeholders."""

    common = {
        "enabled": False,
        "mode": "lookup",
        "minute_limit": 0,
        "daily_budget": 0,
        "credential_ref": "",
        "policy_identity": "external_ti_non_ip.v1",
        "normalizer_identity": EXTERNAL_TI_EVIDENCE_SCHEMA,
        "cache_ttl_seconds": 86400,
        "error_ttl_seconds": 3600,
        "max_attempts": 2,
        "max_new_requests": 1,
        "refresh_window_seconds": 86400,
        "negative_cache_seconds": 86400,
    }

    def item(
        provider: str,
        endpoint_id: str,
        observable_types: Sequence[str],
        observable_roles: Sequence[str],
        algorithms: Sequence[str],
        **overrides: Any,
    ) -> Dict[str, Any]:
        result = dict(common)
        result.update(
            {
                "provider": provider,
                "endpoint_id": endpoint_id,
                "observable_types": list(observable_types),
                "observable_roles": list(observable_roles),
                "allowed_hash_algorithms": list(algorithms),
            }
        )
        result.update(overrides)
        return result

    return {
        "virustotal": item(
            "virustotal",
            "virustotal_lookup_v3",
            ["hash"],
            ["file_hash"],
            ["sha256"],
            credential_ref="VIRUSTOTAL_API_KEY_FILE",
        ),
        "otx": item(
            "otx",
            "otx_general_v1",
            ["hash"],
            ["file_hash"],
            ["sha256"],
            credential_ref="OTX_API_KEY_FILE",
        ),
        "shodan_official": item(
            "shodan_official",
            "shodan_host_v1",
            ["ip"],
            ["source_ip"],
            [],
            mode="official_lookup",
            policy_identity=SOURCE_IP_POLICY_ID,
            max_attempts=1,
            credential_ref="SHODAN_API_KEY_FILE",
        ),
        "shodan_internetdb": item(
            "shodan_internetdb",
            "shodan_internetdb_v1",
            ["ip"],
            ["source_ip"],
            [],
            mode="internetdb_lookup",
            policy_identity=SOURCE_IP_POLICY_ID,
            max_attempts=1,
            credential_ref="",
        ),
        "abuseipdb": item(
            "abuseipdb",
            "abuseipdb_check_v2",
            ["ip"],
            ["source_ip"],
            [],
            policy_identity=SOURCE_IP_POLICY_ID,
            max_attempts=1,
            credential_ref="ABUSEIPDB_API_KEY_FILE",
        ),
        "censys": item(
            "censys",
            "censys_host_v3",
            ["ip"],
            ["source_ip"],
            [],
            credential_ref="CENSYS_PLATFORM_TOKEN_FILE",
        ),
    }


@dataclass(frozen=True)
class SourceIPGovernance:
    """Validated, secret-free source-IP amendment metadata."""

    policy_id: str
    version: str
    sha256: str
    authorized_providers: Tuple[str, ...]
    allowed_outbound_fields: Tuple[str, ...]
    canonical_mongodb_enrichment_record_write: bool = False
    continuous_processing: bool = False
    minimum_refresh_interval_seconds: int = 86_400
    max_distinct_source_ips_per_utc_day: int = 1

    def authorizes_provider(self, provider: str = "") -> bool:
        name = str(provider or "").strip().lower()
        if not name:
            return True
        return (
            name in self.authorized_providers
            or _SOURCE_IP_POLICY_PROVIDER.get(name, name) in self.authorized_providers
        )


def load_source_ip_governance_amendment(
    path: str,
    *,
    expected_sha256: str = SOURCE_IP_AMENDMENT_SHA256,
) -> SourceIPGovernance:
    """Load and validate the reviewed source-IP amendment without secrets."""

    raw_path = str(path or "").strip()
    if not raw_path:
        raise ValueError("source-IP governance amendment path is required")
    selected = Path(raw_path)
    try:
        raw = selected.read_bytes()
    except OSError as exc:
        raise ValueError("source-IP governance amendment is unavailable") from exc
    digest = hashlib.sha256(raw).hexdigest()
    expected = str(expected_sha256 or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or digest != expected:
        raise ValueError("source-IP governance amendment hash mismatch")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("source-IP governance amendment is malformed") from exc
    if not isinstance(document, Mapping):
        raise ValueError("source-IP governance amendment must be an object")
    schema_version = str(document.get("schema_version") or "")
    policy_version = str(document.get("version") or "")
    is_preflight = (
        schema_version == SOURCE_IP_AMENDMENT_SCHEMA
        and policy_version == SOURCE_IP_POLICY_VERSION
    )
    is_production = (
        schema_version == SOURCE_IP_PRODUCTION_SCHEMA
        and policy_version == SOURCE_IP_PRODUCTION_POLICY_VERSION
    )
    if document.get("policy_id") != SOURCE_IP_POLICY_ID or not (
        is_preflight or is_production
    ):
        raise ValueError("source-IP governance amendment identity mismatch")
    scope = document.get("amendment_scope")
    if not isinstance(scope, Mapping):
        raise ValueError("source-IP governance amendment scope is missing")
    authorized = scope.get("authorized_providers")
    expected_providers = (
        {"shodan", "abuseipdb"}
        if is_preflight
        else {"shodan_official", "abuseipdb"}
    )
    if not isinstance(authorized, list) or {
        str(item).strip().lower() for item in authorized
    } != expected_providers:
        raise ValueError("source-IP governance provider scope is invalid")
    fields = scope.get("allowed_outbound_fields")
    if fields != ["normalized_source_ip"]:
        raise ValueError("source-IP outbound field scope is invalid")
    required_scope = {
        "lookup_only": True,
        "active_scanning": False,
        "reporting_or_submission": False,
        "continuous_processing": is_production,
        "arbitrary_external_ip_input": False,
    }
    if any(scope.get(key) is not value for key, value in required_scope.items()):
        raise ValueError("source-IP governance action scope is invalid")
    eligibility = document.get("eligibility")
    if not isinstance(eligibility, Mapping):
        raise ValueError("source-IP eligibility scope is missing")
    required_eligibility = {
        "requires_existing_canonical_event": True,
        "requires_source_event_provenance": True,
        "requires_session_or_sensor_link": True,
        "requires_syntactically_valid_ip": True,
        "requires_ipv4_or_ipv6_global_routability": True,
        "exclude_private_rfc1918": True,
        "exclude_loopback": True,
        "exclude_link_local": True,
        "exclude_multicast": True,
        "exclude_unspecified_reserved": True,
        "exclude_carrier_grade_nat": True,
        "exclude_overlay_or_internal_addresses": True,
        "exclude_lab_controlled_fixture_addresses": True,
        "exclude_operator_owned_test_infrastructure": True,
        "destination_addresses_are_never_eligible": True,
    }
    if any(eligibility.get(key) is not value for key, value in required_eligibility.items()):
        raise ValueError("source-IP eligibility controls are invalid")
    lifecycle = document.get("privacy_and_data_lifecycle")
    if not isinstance(lifecycle, Mapping) or lifecycle.get("outbound_payload_minimization") != "normalized_source_ip_only" or lifecycle.get("raw_provider_response_persisted") is not False or lifecycle.get("normalized_bounded_fields_only") is not True or lifecycle.get("canonical_mongodb_enrichment_record_write") is not False:
        raise ValueError("source-IP data lifecycle controls are invalid")
    authority = document.get("authority")
    if not isinstance(authority, Mapping) or authority.get("eti_authority") != EXTERNAL_TI_AUTHORITY or any(authority.get(key) != 0 for key in ("trusted_attck_writes", "trusted_history_writes", "canonical_classification_overrides", "response_actions")):
        raise ValueError("source-IP authority controls are invalid")
    minimum_refresh = 86_400
    max_daily_targets = 1
    if is_production:
        budgets = document.get("request_budgets")
        if not isinstance(budgets, Mapping):
            raise ValueError("source-IP production request budget is missing")
        minimum_refresh = int(budgets.get("minimum_refresh_interval_seconds") or 0)
        max_daily_targets = int(
            budgets.get("max_distinct_source_ips_per_utc_day") or 0
        )
        if minimum_refresh < 86_400:
            raise ValueError("source-IP production refresh interval is too short")
        if max_daily_targets < 1 or max_daily_targets > 100:
            raise ValueError("source-IP production daily target limit is invalid")
        if document.get("status") != "ACTIVE_BOUNDED_PRODUCTION":
            raise ValueError("source-IP production policy is not active")
    return SourceIPGovernance(
        policy_id=SOURCE_IP_POLICY_ID,
        version=policy_version,
        sha256=digest,
        authorized_providers=tuple(sorted({str(item).strip().lower() for item in authorized})),
        allowed_outbound_fields=("normalized_source_ip",),
        continuous_processing=is_production,
        minimum_refresh_interval_seconds=minimum_refresh,
        max_distinct_source_ips_per_utc_day=max_daily_targets,
    )


def _as_string_list(value: Any, field_name: str) -> List[str]:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{field_name} must be a list")
    result = [str(item).strip().lower() for item in value]
    if any(not item for item in result) or len(set(result)) != len(result):
        raise ValueError(f"{field_name} must contain unique non-empty strings")
    return result


def validate_external_ti_config(
    *,
    enabled: bool,
    profile: str,
    provider_allowlist: Any,
    provider_configs: Any,
    policy_identity: str,
    normalizer_identity: str,
    source_ip_enrichment_mode: str = "disabled",
    source_ip_enrichment_not_before_utc: str = "",
    source_ip_enrichment_cutoff_operator: str = "",
    source_ip_governance_path: str = "",
    source_ip_governance_sha256: str = SOURCE_IP_AMENDMENT_SHA256,
    proof_campaign_id: str = "",
    proof_guard_mode: str = "DISABLED",
) -> None:
    """Validate the secret-free enablement contract.

    Disabled placeholders may have zero limits and no credential reference.
    Enabled providers must still pass every runtime gate; validation never
    treats a key or credential reference as activation.
    """

    if not isinstance(enabled, bool):
        raise ValueError("external_ti_enabled must be boolean")
    normalized_profile = str(profile or "").strip().lower()
    if normalized_profile not in {"disabled", EXTERNAL_TI_PROFILE, SOURCE_IP_PROFILE}:
        raise ValueError(
            "external_enrichment_profile must be disabled, non_ip_observables, "
            "or source_ip_observables"
        )
    allowlist = _as_string_list(provider_allowlist or [], "external_ti_provider_allowlist")
    unknown_allowlist = sorted(set(allowlist) - KNOWN_PROVIDERS)
    if unknown_allowlist:
        raise ValueError(f"external_ti_provider_allowlist contains unknown providers: {unknown_allowlist}")
    if not isinstance(provider_configs, Mapping):
        raise ValueError("external_ti_provider_configs must be an object")
    unknown_configs = sorted(set(str(key).lower() for key in provider_configs) - KNOWN_PROVIDERS)
    if unknown_configs:
        raise ValueError(f"external_ti_provider_configs contains unknown providers: {unknown_configs}")
    if not str(policy_identity or "").strip() or not str(normalizer_identity or "").strip():
        raise ValueError("external TI policy and normalizer identities must be non-empty")

    defaults = default_external_ti_provider_configs()
    allowed_provider_fields = {
        "provider",
        "enabled",
        "mode",
        "endpoint_id",
        "credential_ref",
        "observable_types",
        "observable_roles",
        "allowed_hash_algorithms",
        "minute_limit",
        "daily_budget",
        "cache_ttl_seconds",
        "error_ttl_seconds",
        "policy_identity",
        "normalizer_identity",
        "max_attempts",
        "max_new_requests",
        "refresh_window_seconds",
        "negative_cache_seconds",
    }
    for provider, raw in provider_configs.items():
        name = str(provider).strip().lower()
        if not isinstance(raw, Mapping):
            raise ValueError(f"external TI provider config for {name} must be an object")
        item = dict(defaults[name])
        item.update(raw)
        unknown_fields = sorted(set(str(key) for key in raw) - allowed_provider_fields)
        if unknown_fields:
            raise ValueError(f"external TI provider {name} has unknown fields: {unknown_fields}")
        if any(
            any(token in str(key).lower() for token in ("secret", "password", "api_key", "token", "uri"))
            for key in raw
        ):
            raise ValueError(f"external TI provider {name} config must not contain credential material")
        if not isinstance(item.get("enabled"), bool):
            raise ValueError(f"external TI provider {name}.enabled must be boolean")
        endpoint_id = str(item.get("endpoint_id") or "").strip()
        if endpoint_id not in KNOWN_ENDPOINTS[name]:
            raise ValueError(f"external TI provider {name} has an unknown endpoint_id")
        for key in ("observable_types", "observable_roles", "allowed_hash_algorithms"):
            values = _as_string_list(item.get(key, []), f"{name}.{key}")
            if key == "observable_types" and any(value not in ALLOWED_OBSERVABLE_TYPES for value in values):
                raise ValueError(f"{name}.{key} contains an unknown observable type")
            if key == "observable_roles" and any(value not in ALLOWED_OBSERVABLE_ROLES for value in values):
                raise ValueError(f"{name}.{key} contains an unknown observable role")
            if key == "allowed_hash_algorithms" and any(value not in ALLOWED_HASH_ALGORITHMS for value in values):
                raise ValueError(f"{name}.{key} contains an unknown hash algorithm")
        for key in (
            "minute_limit",
            "daily_budget",
            "cache_ttl_seconds",
            "error_ttl_seconds",
            "max_attempts",
            "max_new_requests",
            "refresh_window_seconds",
            "negative_cache_seconds",
        ):
            value = item.get(key)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name}.{key} must be a non-negative integer")
        if item.get("enabled") and name not in allowlist:
            raise ValueError(f"enabled provider {name} must be in the explicit provider allowlist")
        if name in SOURCE_IP_PROVIDER_NAMES and str(item.get("policy_identity") or "") != SOURCE_IP_POLICY_ID:
            raise ValueError(f"source-IP provider {name} must bind the source-IP policy identity")
        if name in SOURCE_IP_PROVIDER_NAMES and item.get("enabled"):
            if normalized_profile != SOURCE_IP_PROFILE:
                raise ValueError(f"source-IP provider {name} requires source_ip_observables profile")
            if item.get("max_attempts") != 1 or item.get("max_new_requests") != 1:
                raise ValueError(f"source-IP provider {name} must use one bounded attempt/request")
            if item.get("refresh_window_seconds") < 86400 or item.get("negative_cache_seconds") < 86400:
                raise ValueError(f"source-IP provider {name} requires a 24-hour cache window")
        if item.get("enabled") and normalized_profile == "disabled":
            # This is legal as a fail-closed configuration, but makes the
            # intended contradiction explicit to operators/tests.
            continue

    source_ip_selected = any(
        name in SOURCE_IP_PROVIDER_NAMES
        for name in allowlist
    ) or any(
        name in SOURCE_IP_PROVIDER_NAMES
        and isinstance(raw, Mapping)
        and bool(raw.get("enabled"))
        for name, raw in provider_configs.items()
    )
    mode = str(source_ip_enrichment_mode or "disabled").strip()
    if mode not in {"disabled", SOURCE_IP_ENRICHMENT_MODE}:
        raise ValueError("source_ip_enrichment_mode is unsupported")
    if source_ip_enrichment_not_before_utc:
        parse_source_ip_cutoff_utc(source_ip_enrichment_not_before_utc)
    if source_ip_selected:
        if normalized_profile != SOURCE_IP_PROFILE or mode != SOURCE_IP_ENRICHMENT_MODE:
            raise ValueError("source-IP providers require NEW_ELIGIBLE_SIGHTINGS_ONLY mode")
        if not str(source_ip_enrichment_not_before_utc or "").strip():
            raise ValueError("source-IP enrichment cutoff is required")
        if not str(source_ip_enrichment_cutoff_operator or "").strip():
            raise ValueError("source-IP enrichment cutoff operator is required")
        if not str(source_ip_governance_path or "").strip():
            raise ValueError("source-IP governance amendment path is required")
        source_hash = str(source_ip_governance_sha256 or "").strip().lower()
        if not _SHA256_RE.fullmatch(source_hash):
            raise ValueError("source-IP governance amendment hash must be SHA-256")
        guard_mode = str(proof_guard_mode or "").strip().upper()
        if guard_mode != "REAL_PROOF":
            raise ValueError("source-IP providers require REAL_PROOF durable guard mode")
        campaign = str(proof_campaign_id or "").strip()
        if not campaign or len(campaign) > 128 or any(
            character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-"
            for character in campaign
        ):
            raise ValueError("source-IP proof campaign identity is invalid")
    else:
        guard_mode = str(proof_guard_mode or "DISABLED").strip().upper()
        if guard_mode not in {"DISABLED", "PRE_FLIGHT_ONLY", "REAL_PROOF"}:
            raise ValueError("proof guard mode is unsupported")
        if len(str(proof_campaign_id or "").strip()) > 128:
            raise ValueError("proof campaign identity is oversized")


def provider_config(
    provider: str,
    configured: Optional[Mapping[str, Any]],
) -> Dict[str, Any]:
    name = str(provider or "").strip().lower()
    defaults = default_external_ti_provider_configs().get(name, {})
    result = dict(defaults)
    if isinstance(configured, Mapping):
        result.update(configured)
    result["provider"] = name
    return result


@dataclass(frozen=True)
class EligibilityDecision:
    eligible: bool
    code: str
    observable_type: str
    observable_value: str
    role: str
    source: str
    algorithm: str
    observable_id: str = ""
    sighting_id: str = ""
    safe_display_kind: str = ""
    safe_display_value: str = ""
    reason: str = ""


def _sighting_metadata(sighting: Mapping[str, Any]) -> Dict[str, Any]:
    payload = sighting.get("payload")
    metadata = payload.get("metadata") if isinstance(payload, Mapping) else {}
    result = dict(metadata) if isinstance(metadata, Mapping) else {}
    for key in ("algorithm", "hash_algorithm", "hash_type", "field"):
        if key in sighting and sighting.get(key) not in (None, ""):
            result[key] = sighting.get(key)
    if isinstance(payload, Mapping):
        for key in ("algorithm", "hash_algorithm", "hash_type", "field"):
            if key in payload and payload.get(key) not in (None, ""):
                result[key] = payload.get(key)
    return result


def _base_decision(sighting: Mapping[str, Any]) -> Tuple[str, str, str, str, str]:
    observable_type = str(sighting.get("observable_type") or "").strip().lower()
    value = str(sighting.get("observable_value") or "").strip()
    role = str(sighting.get("role") or "").strip().lower()
    source = str(sighting.get("source") or "").strip().lower()
    algorithm = str(_sighting_metadata(sighting).get("algorithm") or _sighting_metadata(sighting).get("hash_algorithm") or _sighting_metadata(sighting).get("hash_type") or "").strip().lower().replace("-", "")
    return observable_type, value, role, source, algorithm


def parse_source_ip_cutoff_utc(value: Any) -> datetime:
    """Parse the operator-bound cutoff as a strict UTC ISO-8601 value."""

    text = str(value or "").strip()
    if not text or not text.endswith("Z"):
        raise ValueError("source-IP cutoff must be an explicit UTC timestamp")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except (TypeError, ValueError) as exc:
        raise ValueError("source-IP cutoff is malformed") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("source-IP cutoff must be UTC")
    return parsed.astimezone(timezone.utc)


def _source_ip_observation_timestamp(sighting: Mapping[str, Any]) -> Optional[datetime]:
    """Read only the canonical sighting timestamp; never job/processing time."""

    raw = sighting.get(SOURCE_IP_CUTOFF_TIMESTAMP_FIELD)
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        parsed = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _sighting_field(sighting: Mapping[str, Any], *names: str) -> str:
    payload = sighting.get("payload")
    for name in names:
        value = sighting.get(name)
        if value in (None, "") and isinstance(payload, Mapping):
            value = payload.get(name)
        if value not in (None, ""):
            return str(value).strip()
    return ""


def _source_ip_policy_authorized(
    governance: Any,
    provider: str,
) -> bool:
    if isinstance(governance, SourceIPGovernance):
        return governance.authorizes_provider(provider)
    if not isinstance(governance, Mapping):
        return False
    policy_id = str(governance.get("policy_id") or "").strip()
    version = str(governance.get("version") or "").strip()
    if policy_id != SOURCE_IP_POLICY_ID or version != SOURCE_IP_POLICY_VERSION:
        return False
    providers = governance.get("authorized_providers")
    if not isinstance(providers, (list, tuple, set)):
        return False
    normalized = {str(item).strip().lower() for item in providers}
    if not {"shodan", "abuseipdb"}.issubset(normalized):
        return False
    selected = _SOURCE_IP_POLICY_PROVIDER.get(
        str(provider or "").strip().lower(),
        str(provider or "").strip().lower(),
    )
    return not provider or selected in normalized


def evaluate_outbound_sighting(
    sighting: Mapping[str, Any],
    *,
    provider: str = "",
    source_ip_governance: Any = None,
    source_ip_cutoff_utc: Any = None,
    source_ip_mode: str = SOURCE_IP_ENRICHMENT_MODE,
) -> EligibilityDecision:
    """Evaluate a hash or policy-bound source-IP outbound eligibility role."""

    observable_type, value, role, source, algorithm = _base_decision(sighting)
    common = {
        "observable_type": observable_type,
        "observable_value": value.lower() if observable_type == "hash" else value,
        "role": role,
        "source": source,
        "algorithm": algorithm,
        "observable_id": str(sighting.get("observable_id") or ""),
        "sighting_id": str(sighting.get("sighting_id") or ""),
    }
    if observable_type == "ip":
        if not _source_ip_policy_authorized(source_ip_governance, provider):
            return EligibilityDecision(
                False,
                "source_ip_policy_prohibited",
                **common,
                reason="reviewed source-IP amendment is missing or provider is not authorized",
            )
        if str(source_ip_mode or "").strip() != SOURCE_IP_ENRICHMENT_MODE:
            return EligibilityDecision(
                False,
                "source_ip_mode_prohibited",
                **common,
                reason="source-IP enrichment is limited to new eligible sightings",
            )
        if source_ip_cutoff_utc is None:
            return EligibilityDecision(
                False,
                "source_ip_cutoff_missing",
                **common,
                reason="source-IP activation cutoff is required",
            )
        try:
            cutoff = (
                source_ip_cutoff_utc
                if isinstance(source_ip_cutoff_utc, datetime)
                else parse_source_ip_cutoff_utc(source_ip_cutoff_utc)
            )
            if cutoff.tzinfo is None or cutoff.utcoffset() != timedelta(0):
                raise ValueError
            cutoff = cutoff.astimezone(timezone.utc)
        except (TypeError, ValueError):
            return EligibilityDecision(
                False,
                "source_ip_cutoff_malformed",
                **common,
                reason="source-IP activation cutoff is malformed",
            )
        if role != "source_ip":
            return EligibilityDecision(False, "role_prohibited", **common, reason="only source_ip may leave the system")
        if source != "cowrie_event":
            return EligibilityDecision(False, "source_prohibited", **common, reason="source is not an approved Cowrie event")
        session_id = _sighting_field(sighting, "session_id")
        event_id = _sighting_field(sighting, "event_id", "eventid")
        sensor_id = _sighting_field(sighting, "sensor_id", "sensor")
        if not session_id or session_id.lower() == "unknown" or not event_id or not sensor_id:
            return EligibilityDecision(
                False,
                "source_ip_provenance_missing",
                **common,
                reason="canonical session, event, and sensor provenance are required",
            )
        try:
            normalized_ip = str(ipaddress.ip_address(value))
        except ValueError:
            return EligibilityDecision(False, "invalid_source_ip", **common, reason="source IP is syntactically invalid")
        parsed_ip = ipaddress.ip_address(normalized_ip)
        if not parsed_ip.is_global:
            return EligibilityDecision(False, "source_ip_not_public", **common, reason="source IP is not globally routable")
        observed_at = _source_ip_observation_timestamp(sighting)
        if observed_at is None:
            return EligibilityDecision(
                False,
                "source_ip_timestamp_missing_or_malformed",
                **common,
                reason="canonical sighting timestamp is required",
            )
        if observed_at < cutoff:
            return EligibilityDecision(
                False,
                "source_ip_before_cutoff",
                **common,
                reason="source sighting predates the operator-bound activation cutoff",
            )
        return EligibilityDecision(
            True,
            "eligible_source_ip",
            observable_type="ip",
            observable_value=normalized_ip,
            role=role,
            source=source,
            algorithm="",
            observable_id=common["observable_id"],
            sighting_id=common["sighting_id"],
            safe_display_kind="normalized_source_ip",
            safe_display_value=normalized_ip,
        )
    if observable_type != "hash":
        return EligibilityDecision(False, "observable_type_disabled", **common, reason="only approved file SHA-256 and source-IP paths are eligible")
    if role != "file_hash":
        return EligibilityDecision(False, "role_prohibited", **common, reason="only file_hash may leave the system")
    if source != "cowrie_event":
        return EligibilityDecision(False, "source_prohibited", **common, reason="source is not an approved Cowrie event")
    metadata = _sighting_metadata(sighting)
    field = str(metadata.get("field") or "").strip().lower()
    if algorithm != "sha256" and not (field in {"sha256", "shasum"} and len(value) == 64):
        return EligibilityDecision(False, "algorithm_prohibited", **common, reason="SHA-256 algorithm evidence is required")
    if len(value) != 64 or not _SHA256_RE.fullmatch(value):
        return EligibilityDecision(False, "invalid_sha256", **common, reason="value must be exactly 64 hexadecimal characters")
    normalized = value.lower()
    return EligibilityDecision(
        True,
        "eligible_file_sha256",
        observable_type="hash",
        observable_value=normalized,
        role=role,
        source=source,
        algorithm="sha256",
        observable_id=common["observable_id"],
        sighting_id=common["sighting_id"],
        safe_display_kind="sha256",
        safe_display_value=normalized,
    )


def provider_activation_gate(
    *,
    provider: str,
    config: Any,
    provider_config_value: Optional[Mapping[str, Any]],
    sighting: Optional[Mapping[str, Any]],
    credential_present: bool,
    credential_required: bool,
    source_ip_governance: Any = None,
    source_ip_cutoff_utc: Any = None,
    source_ip_mode: str = SOURCE_IP_ENRICHMENT_MODE,
) -> EligibilityDecision:
    """Return a single fail-closed decision for one provider request."""

    name = str(provider or "").strip().lower()
    if name not in KNOWN_PROVIDERS:
        decision = evaluate_outbound_sighting(sighting or {})
        return EligibilityDecision(False, "unknown_provider", decision.observable_type, decision.observable_value, decision.role, decision.source, decision.algorithm, reason="unknown provider")
    decision = evaluate_outbound_sighting(
        sighting or {},
        provider=name,
        source_ip_governance=source_ip_governance,
        source_ip_cutoff_utc=source_ip_cutoff_utc,
        source_ip_mode=source_ip_mode,
    )
    settings = provider_config(name, provider_config_value)
    if not bool(getattr(config, "external_ti_enabled", False)):
        return EligibilityDecision(False, "global_disabled", decision.observable_type, decision.observable_value, decision.role, decision.source, decision.algorithm, reason="global external TI is disabled")
    profile = str(getattr(config, "external_enrichment_profile", "disabled") or "").strip().lower()
    if profile not in {EXTERNAL_TI_PROFILE, SOURCE_IP_PROFILE}:
        return EligibilityDecision(False, "profile_disabled", decision.observable_type, decision.observable_value, decision.role, decision.source, decision.algorithm, reason="profile does not permit external TI")
    if decision.observable_type == "ip" and profile != SOURCE_IP_PROFILE:
        return EligibilityDecision(False, "source_ip_profile_required", decision.observable_type, decision.observable_value, decision.role, decision.source, decision.algorithm, reason="source-IP providers require the source-IP profile")
    allowlist = {str(item).strip().lower() for item in (getattr(config, "external_ti_provider_allowlist", []) or [])}
    if name not in allowlist:
        return EligibilityDecision(False, "provider_not_allowlisted", decision.observable_type, decision.observable_value, decision.role, decision.source, decision.algorithm, reason="provider is not explicitly allowlisted")
    if not bool(settings.get("enabled", False)):
        return EligibilityDecision(False, "provider_disabled", decision.observable_type, decision.observable_value, decision.role, decision.source, decision.algorithm, reason="provider enabled flag is false")
    if not decision.eligible:
        return decision
    endpoint_id = str(settings.get("endpoint_id") or "").strip()
    if endpoint_id not in KNOWN_ENDPOINTS.get(name, set()):
        return EligibilityDecision(False, "endpoint_unknown", decision.observable_type, decision.observable_value, decision.role, decision.source, decision.algorithm, reason="endpoint identity is not allowlisted")
    types = {str(item).strip().lower() for item in settings.get("observable_types", []) or []}
    roles = {str(item).strip().lower() for item in settings.get("observable_roles", []) or []}
    algorithms = {str(item).strip().lower().replace("-", "") for item in settings.get("allowed_hash_algorithms", []) or []}
    if decision.observable_type not in types:
        return EligibilityDecision(False, "type_not_allowlisted", decision.observable_type, decision.observable_value, decision.role, decision.source, decision.algorithm, reason="observable type is not allowlisted for provider")
    if decision.role not in roles:
        return EligibilityDecision(False, "role_not_allowlisted", decision.observable_type, decision.observable_value, decision.role, decision.source, decision.algorithm, reason="observable role is not allowlisted for provider")
    if decision.algorithm and algorithms and decision.algorithm not in algorithms:
        return EligibilityDecision(False, "algorithm_not_allowlisted", decision.observable_type, decision.observable_value, decision.role, decision.source, decision.algorithm, reason="hash algorithm is not allowlisted for provider")
    if credential_required and not credential_present:
        return EligibilityDecision(False, "credential_missing", decision.observable_type, decision.observable_value, decision.role, decision.source, decision.algorithm, reason="required credential is unavailable")
    if int(settings.get("minute_limit") or 0) <= 0:
        return EligibilityDecision(False, "minute_budget_zero", decision.observable_type, decision.observable_value, decision.role, decision.source, decision.algorithm, reason="provider minute limit is zero")
    if int(settings.get("daily_budget") or 0) <= 0:
        return EligibilityDecision(False, "daily_budget_zero", decision.observable_type, decision.observable_value, decision.role, decision.source, decision.algorithm, reason="provider daily budget is zero")
    expected_policy_identity = (
        SOURCE_IP_POLICY_ID
        if decision.observable_type == "ip" and name in SOURCE_IP_PROVIDER_NAMES
        else str(getattr(config, "external_ti_policy_identity", "") or "")
    )
    if str(settings.get("policy_identity") or "") != expected_policy_identity:
        return EligibilityDecision(False, "policy_identity_mismatch", decision.observable_type, decision.observable_value, decision.role, decision.source, decision.algorithm, reason="provider policy identity is not approved")
    if str(settings.get("normalizer_identity") or "") != str(getattr(config, "external_ti_normalizer_identity", "") or ""):
        return EligibilityDecision(False, "normalizer_identity_mismatch", decision.observable_type, decision.observable_value, decision.role, decision.source, decision.algorithm, reason="provider normalizer identity is not approved")
    return decision


def parse_retry_after(value: Any, now: Optional[datetime] = None) -> Optional[float]:
    """Parse Retry-After delta-seconds or HTTP-date with a safe upper bound."""

    text = str(value or "").strip()
    if not text:
        return None
    if re.fullmatch(r"\d+", text):
        return min(float(int(text)), float(MAX_RETRY_AFTER_SECONDS))
    try:
        parsed = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    reference = now or datetime.now(timezone.utc)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)
    seconds = max((parsed - reference).total_seconds(), 0.0)
    return min(seconds, float(MAX_RETRY_AFTER_SECONDS))


def validate_fixed_endpoint_url(provider: str, endpoint_id: str, url: str) -> None:
    """Reject arbitrary provider URLs and unsafe redirect targets."""

    expected = ENDPOINT_HOSTS.get(str(endpoint_id or "").strip())
    if not expected or str(endpoint_id) not in KNOWN_ENDPOINTS.get(str(provider or "").lower(), set()):
        raise ValueError("provider endpoint identity is not allowlisted")
    parsed = urlsplit(str(url or ""))
    host, path_prefix = expected
    if parsed.scheme != "https" or parsed.hostname != host or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("provider endpoint must be the fixed HTTPS host")
    if parsed.port not in (None, 443):
        raise ValueError("provider endpoint port is not allowlisted")
    if not parsed.path.startswith(path_prefix):
        raise ValueError("provider endpoint path is not allowlisted")
    if endpoint_id == "shodan_host_v1":
        query = parse_qsl(parsed.query, keep_blank_values=True)
        if len(query) != 1 or query[0][0] != "key" or not query[0][1]:
            raise ValueError("official Shodan endpoint requires exactly one key query parameter")
    elif endpoint_id == "shodan_internetdb_v1" and parsed.query:
        raise ValueError("Shodan InternetDB endpoint must not carry a query")


def _iso_datetime(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _safe_text(value: Any, maximum: int = 256) -> str:
    if value is None or isinstance(value, (dict, list, tuple, set)):
        return ""
    return str(value).strip()[:maximum]


def _bounded_strings(values: Any, maximum_items: int, maximum_chars: int = 256) -> List[str]:
    if not isinstance(values, (list, tuple, set)):
        return []
    output: List[str] = []
    seen = set()
    for value in values:
        text = _safe_text(value, maximum_chars)
        if text and text not in seen:
            seen.add(text)
            output.append(text)
        if len(output) >= maximum_items:
            break
    return output


def _normalization_diagnostic(diagnostics: Optional[List[str]], field: str, reason: str) -> None:
    """Append only a fixed, bounded diagnostic; never include provider data."""

    if diagnostics is None:
        return
    token = f"{field}:{reason}"[:96]
    if token not in diagnostics and len(diagnostics) < 16:
        diagnostics.append(token)


def _bounded_sequence(
    value: Any,
    maximum_items: int,
    *,
    field: str,
    diagnostics: Optional[List[str]] = None,
) -> List[Any]:
    """Return a bounded list for a provider field or omit an invalid shape."""

    if value is None:
        return []
    if not isinstance(value, (list, tuple, set)):
        _normalization_diagnostic(diagnostics, field, "unsupported_type")
        return []
    values = sorted(value, key=lambda item: repr(item)) if isinstance(value, set) else list(value)
    if len(values) > maximum_items:
        _normalization_diagnostic(diagnostics, field, "items_truncated")
    return values[:maximum_items]


def _safe_optional_text(
    mapping: Mapping[str, Any],
    keys: Sequence[str],
    maximum_chars: int,
    *,
    field: str,
    diagnostics: Optional[List[str]] = None,
) -> Optional[str]:
    """Read the first scalar alias without allowing malformed aliases to mask valid ones."""

    for key in keys:
        if key not in mapping:
            continue
        value = mapping.get(key)
        if value is None or value == "":
            continue
        text = _safe_text(value, maximum_chars)
        if text:
            return text
        _normalization_diagnostic(diagnostics, field, "unsupported_type")
    return None


def _safe_port(value: Any) -> Optional[int]:
    """Accept only an integer or decimal-string TCP/UDP port."""

    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        port = value
    elif isinstance(value, str) and re.fullmatch(r"\d{1,5}", value.strip()):
        port = int(value.strip())
    else:
        return None
    return port if 1 <= port <= 65535 else None


def _bounded_ports(
    value: Any,
    *,
    field: str = "ports",
    diagnostics: Optional[List[str]] = None,
) -> List[int]:
    values = _bounded_sequence(value, 256, field=field, diagnostics=diagnostics)
    output: List[int] = []
    for item in values:
        port = _safe_port(item)
        if port is None:
            _normalization_diagnostic(diagnostics, field, "item_omitted")
            continue
        if port not in output:
            output.append(port)
    return sorted(output)


def _bounded_shodan_strings(
    value: Any,
    maximum_items: int,
    maximum_chars: int,
    *,
    field: str,
    diagnostics: Optional[List[str]] = None,
) -> List[str]:
    values = _bounded_sequence(value, maximum_items, field=field, diagnostics=diagnostics)
    output: List[str] = []
    seen = set()
    for item in values:
        if isinstance(item, (Mapping, list, tuple, set)):
            _normalization_diagnostic(diagnostics, field, "item_omitted")
            continue
        text = _safe_text(item, maximum_chars)
        if not text:
            _normalization_diagnostic(diagnostics, field, "item_omitted")
            continue
        if text not in seen:
            seen.add(text)
            output.append(text)
    return output


def _bounded_service_product_summary(
    value: Any,
    *,
    field: str = "services",
    diagnostics: Optional[List[str]] = None,
) -> List[str]:
    """Extract short product/service labels and never copy banner fields."""

    values = _bounded_sequence(value, 256, field=field, diagnostics=diagnostics)
    output: List[str] = []
    seen = set()
    for item in values:
        if isinstance(item, Mapping):
            nested = item.get("_shodan")
            nested_mapping = nested if isinstance(nested, Mapping) else {}
            product = _safe_optional_text(
                item,
                ("product", "service_name", "extended_service_name", "service", "protocol"),
                96,
                field=field,
                diagnostics=diagnostics,
            ) or _safe_optional_text(
                nested_mapping,
                ("module", "product", "service"),
                96,
                field=field,
                diagnostics=diagnostics,
            )
            port = _safe_port(item.get("port"))
            if port is None and isinstance(item.get("representative_info"), Mapping):
                port = _safe_port(item["representative_info"].get("sampled_port"))
            if not product:
                _normalization_diagnostic(diagnostics, field, "service_without_product")
                continue
            label = f"{product} {port}" if port is not None else product
        elif isinstance(item, str) and "\n" not in item and "\r" not in item:
            # Compatibility with an already-normalized short service label.
            text = item.strip()[:128]
            if not text or len(text.split()) > 4:
                _normalization_diagnostic(diagnostics, field, "scalar_service_omitted")
                continue
            label = text
        else:
            _normalization_diagnostic(diagnostics, field, "item_omitted")
            continue
        label = label[:128]
        if label not in seen:
            seen.add(label)
            output.append(label)
        if len(output) >= 64:
            _normalization_diagnostic(diagnostics, field, "items_truncated")
            break
    return output


def _bounded_integer_values(value: Any, maximum: int, *, field: str, diagnostics: Optional[List[str]] = None) -> List[int]:
    values = _bounded_sequence(value, 32, field=field, diagnostics=diagnostics)
    output: List[int] = []
    for item in values:
        if isinstance(item, bool):
            _normalization_diagnostic(diagnostics, field, "item_omitted")
            continue
        try:
            parsed = int(item)
        except (TypeError, ValueError, OverflowError):
            _normalization_diagnostic(diagnostics, field, "item_omitted")
            continue
        parsed = max(0, min(parsed, maximum))
        if parsed and parsed not in output:
            output.append(parsed)
    return sorted(output)


def _bounded_int(value: Any, maximum: int = 10_000_000) -> int:
    try:
        parsed = int(value or 0)
    except (TypeError, ValueError, OverflowError):
        return 0
    return max(0, min(parsed, maximum))


def _provider_data_root(data: Mapping[str, Any]) -> Mapping[str, Any]:
    root = data.get("data")
    if isinstance(root, Mapping):
        attrs = root.get("attributes")
        if isinstance(attrs, Mapping):
            return attrs
    attrs = data.get("attributes")
    return attrs if isinstance(attrs, Mapping) else data


def normalize_provider_extension(provider: str, data: Any) -> Tuple[str, Dict[str, Any], str, str, Optional[str], Optional[str]]:
    """Return bounded extension, categorical finding and provider times."""

    name = str(provider or "").strip().lower()
    root = data if isinstance(data, Mapping) else {}
    observed_at: Optional[str] = None
    updated_at: Optional[str] = None
    if name == "virustotal":
        attrs = _provider_data_root(root)
        stats = attrs.get("last_analysis_stats") if isinstance(attrs.get("last_analysis_stats"), Mapping) else {}
        extension = {
            "malicious": _bounded_int(stats.get("malicious")),
            "suspicious": _bounded_int(stats.get("suspicious")),
            "harmless": _bounded_int(stats.get("harmless")),
            "undetected": _bounded_int(stats.get("undetected")),
            "timeout": _bounded_int(stats.get("timeout")),
            "detection_numerator": _bounded_int(stats.get("malicious")) + _bounded_int(stats.get("suspicious")),
            "detection_denominator": sum(_bounded_int(value) for value in stats.values()) if stats else 0,
            "meaningful_name": _safe_text(attrs.get("meaningful_name"), 256) or None,
            "meaningful_type": _safe_text(attrs.get("type_description"), 128) or None,
            "reputation_label": _safe_text((attrs.get("popular_threat_classification") or {}).get("suggested_threat_label") if isinstance(attrs.get("popular_threat_classification"), Mapping) else "", 128) or None,
        }
        finding = "DETECTIONS_PRESENT" if extension["detection_numerator"] else "NO_DETECTIONS_REPORTED"
        summary = f"{extension['detection_numerator']}/{extension['detection_denominator']} aggregate detections"
        observed_at = _safe_text(attrs.get("last_analysis_date"), 64) or None
        updated_at = _safe_text(attrs.get("last_modification_date"), 64) or None
        return "virustotal.v1", extension, finding, summary, observed_at, updated_at
    if name == "otx":
        pulse_info = root.get("pulse_info") if isinstance(root.get("pulse_info"), Mapping) else {}
        raw_pulses = pulse_info.get("pulses") if isinstance(pulse_info.get("pulses"), list) else []
        pulses: List[Dict[str, Any]] = []
        for pulse in raw_pulses[:20]:
            if not isinstance(pulse, Mapping):
                continue
            references = []
            for reference in _bounded_sequence(
                pulse.get("references"),
                5,
                field="otx.references",
            ):
                validated = _safe_http_reference(reference)
                if validated:
                    references.append(validated)
            pulses.append(
                {
                    "pulse_id": _safe_text(pulse.get("id") or pulse.get("pulse_id"), 128),
                    "name": _safe_text(pulse.get("name"), 256),
                    "created_at": _safe_text(pulse.get("created"), 64) or None,
                    "modified_at": _safe_text(pulse.get("modified"), 64) or None,
                    "tags": _bounded_strings(pulse.get("tags"), 32, 96),
                    "references": references,
                }
            )
        pulses = [pulse for pulse in pulses if pulse["pulse_id"] or pulse["name"]]
        extension = {"pulses": pulses, "truncated": len(raw_pulses) > len(pulses)}
        finding = "CONTEXT_PRESENT" if pulses else "NO_ADDITIONAL_CONTEXT"
        summary = f"{len(pulses)} bounded OTX pulse context records"
        return "otx.v1", extension, finding, summary, observed_at, updated_at
    if name in {"shodan", "shodan_official", "shodan_internetdb"}:
        diagnostics: List[str] = []
        ports = _bounded_ports(root.get("ports"), diagnostics=diagnostics)
        services = _bounded_service_product_summary(
            root.get("services"),
            field="services",
            diagnostics=diagnostics,
        )
        raw_services = root.get("data")
        if raw_services is not None:
            services = _bounded_service_product_summary(
                list(services)
                + _bounded_sequence(
                    raw_services,
                    256,
                    field="data",
                    diagnostics=diagnostics,
                ),
                field="services",
                diagnostics=diagnostics,
            )
        extension = {
            "asn": _safe_optional_text(root, ("asn",), 32, field="asn", diagnostics=diagnostics),
            "organization": _safe_optional_text(
                root,
                ("org", "organization"),
                256,
                field="organization",
                diagnostics=diagnostics,
            ),
            "isp": _safe_optional_text(root, ("isp",), 256, field="isp", diagnostics=diagnostics),
            "country": _safe_optional_text(
                root,
                ("country_code", "country_name", "country"),
                64,
                field="country",
                diagnostics=diagnostics,
            ),
            "ports": ports,
            "services": services,
            "service_product_summary": services,
            "cpe": _bounded_shodan_strings(
                root.get("cpes"), 64, 256, field="cpes", diagnostics=diagnostics
            ),
            "vulnerabilities": _bounded_shodan_strings(
                root.get("vulns"), 128, 64, field="vulns", diagnostics=diagnostics
            ),
            "tags": _bounded_shodan_strings(
                root.get("tags"), 32, 256, field="tags", diagnostics=diagnostics
            ),
            "hostnames": _bounded_shodan_strings(
                root.get("hostnames"), 32, 253, field="hostnames", diagnostics=diagnostics
            ),
            "last_update": _safe_optional_text(
                root,
                ("last_update", "last_seen"),
                64,
                field="last_update",
                diagnostics=diagnostics,
            ),
            "truncated": False,
        }
        if diagnostics:
            extension["normalization_diagnostics"] = diagnostics[:16]
        context_keys = (
            "asn",
            "organization",
            "isp",
            "country",
            "ports",
            "services",
            "service_product_summary",
            "cpe",
            "vulnerabilities",
            "tags",
            "hostnames",
            "last_update",
        )
        finding = "CONTEXT_PRESENT" if any(extension[key] for key in context_keys) else "NO_ADDITIONAL_CONTEXT"
        extension["provider_mode"] = name
        return f"{name}.v1", extension, finding, f"bounded {name} infrastructure context", observed_at, updated_at
    if name == "abuseipdb":
        source = root.get("data") if isinstance(root.get("data"), Mapping) else root
        extension = {
            "abuse_confidence_score": min(max(_bounded_int(source.get("abuseConfidenceScore"), 100), 0), 100),
            "total_reports": _bounded_int(source.get("totalReports")),
            "categories": _bounded_integer_values(
                source.get("categories"),
                10000,
                field="abuseipdb.categories",
            ),
            "usage_type": _safe_text(source.get("usageType"), 128) or None,
            "isp": _safe_text(source.get("isp"), 256) or None,
            "country_code": _safe_text(source.get("countryCode"), 2).upper() or None,
            "last_reported_at": _safe_text(source.get("lastReportedAt"), 64) or None,
        }
        finding = "CONTEXT_PRESENT" if extension["total_reports"] or extension["abuse_confidence_score"] else "NO_ADDITIONAL_CONTEXT"
        return "abuseipdb.v1", extension, finding, "bounded AbuseIPDB source reputation context", observed_at, updated_at
    return f"{name or 'provider'}.v1", {}, "UNKNOWN", "provider extension is unavailable", observed_at, updated_at


def _safe_digest(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text if re.fullmatch(r"[0-9a-f]{64}", text) else ""


def _safe_http_reference(value: Any) -> str:
    text = _safe_text(value, 1024)
    try:
        parsed = urlsplit(text)
        port = parsed.port
    except ValueError:
        return ""
    if (
        not text
        or parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or port not in (None, 80, 443)
    ):
        return ""
    return text


def _sanitize_provider_extension(provider: str, extension: Any) -> Dict[str, Any]:
    """Re-validate stored extension data before exposing it in a session view."""

    name = str(provider or "").strip().lower()
    source = extension if isinstance(extension, Mapping) else {}
    if name == "virustotal":
        counts = {
            key: _bounded_int(source.get(key))
            for key in ("malicious", "suspicious", "harmless", "undetected", "timeout")
        }
        numerator = counts["malicious"] + counts["suspicious"]
        denominator = sum(counts.values())
        return {
            **counts,
            "detection_numerator": numerator,
            "detection_denominator": denominator,
            "meaningful_name": _safe_text(source.get("meaningful_name"), 256) or None,
            "meaningful_type": _safe_text(source.get("meaningful_type"), 128) or None,
            "reputation_label": _safe_text(source.get("reputation_label"), 128) or None,
        }
    if name == "otx":
        pulses: List[Dict[str, Any]] = []
        raw_pulses = source.get("pulses") if isinstance(source.get("pulses"), list) else []
        for item in raw_pulses[:20]:
            if not isinstance(item, Mapping):
                continue
            references = [
                reference
                for reference in (
                    _safe_http_reference(value)
                    for value in _bounded_sequence(
                        item.get("references"),
                        5,
                        field="otx.references",
                    )
                )
                if reference
            ]
            pulse = {
                "pulse_id": _safe_text(item.get("pulse_id"), 128),
                "name": _safe_text(item.get("name"), 256),
                "created_at": _safe_text(item.get("created_at"), 64) or None,
                "modified_at": _safe_text(item.get("modified_at"), 64) or None,
                "tags": _bounded_strings(item.get("tags"), 32, 96),
                "references": references,
            }
            if pulse["pulse_id"] or pulse["name"]:
                pulses.append(pulse)
        return {"pulses": pulses, "truncated": bool(source.get("truncated"))}
    if name in {"shodan", "shodan_official", "shodan_internetdb"}:
        ports = _bounded_ports(source.get("ports"))
        services = _bounded_service_product_summary(source.get("services"))
        if not services:
            services = _bounded_strings(source.get("service_product_summary"), 64, 128)
        return {
            "asn": _safe_text(source.get("asn"), 32) or None,
            "organization": _safe_text(source.get("organization"), 256) or None,
            "isp": _safe_text(source.get("isp"), 256) or None,
            "country": _safe_text(source.get("country"), 64) or None,
            "ports": ports,
            "services": services,
            "service_product_summary": services,
            "cpe": _bounded_strings(source.get("cpe"), 64, 256),
            "vulnerabilities": _bounded_strings(source.get("vulnerabilities"), 128, 64),
            "tags": _bounded_strings(source.get("tags"), 32, 256),
            "hostnames": _bounded_strings(source.get("hostnames"), 32, 253),
            "last_update": _safe_text(source.get("last_update"), 64) or None,
            "truncated": bool(source.get("truncated")),
            "normalization_diagnostics": _bounded_strings(
                source.get("normalization_diagnostics"), 16, 96
            ),
        }
    if name == "abuseipdb":
        return {
            "abuse_confidence_score": min(max(_bounded_int(source.get("abuse_confidence_score"), 100), 0), 100),
            "total_reports": _bounded_int(source.get("total_reports")),
            "categories": _bounded_integer_values(
                source.get("categories"), 10000, field="abuseipdb.categories"
            ),
            "usage_type": _safe_text(source.get("usage_type"), 128) or None,
            "isp": _safe_text(source.get("isp"), 256) or None,
            "country_code": _safe_text(source.get("country_code"), 2).upper() or None,
            "last_reported_at": _safe_text(source.get("last_reported_at"), 64) or None,
        }
    return {}


def sanitize_provider_extension(provider: str, extension: Any) -> Dict[str, Any]:
    """Return the public bounded form used by durable non-authoritative caches.

    Provider adapters and storage projections share the same sanitizer.  Keep
    the private implementation behind this small public wrapper so a cache
    backend cannot accidentally persist an adapter-specific raw response.
    """

    return _sanitize_provider_extension(provider, extension)


def _safe_timestamp(value: Any) -> Optional[str]:
    parsed = _iso_datetime(value)
    return parsed.isoformat() if parsed is not None else None


def _provider_extension_type(provider: str) -> str:
    return {
        "virustotal": "virustotal.v1",
        "otx": "otx.v1",
        "shodan": "shodan.v1",
        "shodan_official": "shodan_official.v1",
        "shodan_internetdb": "shodan_internetdb.v1",
        "abuseipdb": "abuseipdb.v1",
    }.get(str(provider or "").strip().lower(), "")


def _safe_provider_summary(
    provider: str,
    finding_state: str,
    extension: Mapping[str, Any],
) -> str:
    if finding_state == "NOT_FOUND":
        return "provider reported no record"
    if finding_state == "DETECTIONS_PRESENT":
        return (
            f"{_bounded_int(extension.get('detection_numerator'))}/"
            f"{_bounded_int(extension.get('detection_denominator'))} aggregate detections"
        )
    if finding_state == "NO_DETECTIONS_REPORTED":
        return (
            f"{_bounded_int(extension.get('detection_numerator'))}/"
            f"{_bounded_int(extension.get('detection_denominator'))} aggregate detections"
        )
    if finding_state == "CONTEXT_PRESENT":
        if provider == "otx":
            return f"{len(extension.get('pulses') or [])} bounded OTX pulse context records"
        if provider in {"shodan", "shodan_official", "shodan_internetdb"}:
            return f"bounded {provider} infrastructure context"
        if provider == "abuseipdb":
            return "bounded AbuseIPDB source reputation context"
        return "bounded provider context"
    return {
        "NO_ADDITIONAL_CONTEXT": "provider reported no additional context",
        "PENDING": "provider lookup is disabled or not eligible",
        "STALE": "stored provider context is stale",
        "RATE_LIMITED": "provider lookup is rate limited",
        "AUTH_DISABLED": "provider authorization is disabled",
        "BUDGET_EXHAUSTED": "provider lookup budget is exhausted",
        "ERROR": "provider lookup failed",
        "UNAVAILABLE": "provider context is unavailable",
    }.get(finding_state, "provider context is unavailable")


def provider_config_identity(provider: str, settings: Mapping[str, Any]) -> str:
    """Hash only secret-free provider configuration metadata."""

    safe = {
        key: settings.get(key)
        for key in (
            "provider", "enabled", "mode", "endpoint_id", "observable_types", "observable_roles",
            "allowed_hash_algorithms", "minute_limit", "daily_budget", "policy_identity",
        "normalizer_identity", "cache_ttl_seconds", "error_ttl_seconds", "credential_ref",
            "max_attempts", "max_new_requests", "refresh_window_seconds", "negative_cache_seconds",
    )
    }
    return hashlib.sha256(stable_json(safe).encode("utf-8")).hexdigest()


def provider_evidence_from_result(result: Any, settings: Mapping[str, Any]) -> Dict[str, Any]:
    status = str(getattr(result, "status", "error") or "error").strip().lower()
    provider_name = str(getattr(result, "provider", "") or "").strip().lower()
    normalized_override = getattr(result, "normalized_extension", None)
    if isinstance(normalized_override, Mapping):
        extension_type = _provider_extension_type(provider_name)
        extension = _sanitize_provider_extension(provider_name, normalized_override)
        finding = str(getattr(result, "normalized_finding", "") or "").strip()
        if finding not in FINDING_STATES:
            finding = (
                "CONTEXT_PRESENT"
                if any(value for value in extension.values())
                else "NO_ADDITIONAL_CONTEXT"
            )
        summary = _safe_provider_summary(provider_name, finding, extension)
        observed_at = None
        updated_at = None
    else:
        extension_type, extension, finding, summary, observed_at, updated_at = normalize_provider_extension(
            provider_name, getattr(result, "data", {})
        )
    fetched_at = str(getattr(result, "fetched_at", "") or utc_now())
    ttl = max(int(getattr(result, "ttl_seconds", 0) or 0), 0)
    fetched = _iso_datetime(fetched_at) or datetime.now(timezone.utc)
    expires_at = (fetched + timedelta(seconds=ttl)).isoformat()
    cached_lookup_status = str(
        getattr(result, "cached_lookup_status", "") or ""
    ).strip().upper()
    lookup_status = (
        cached_lookup_status
        if status == "cached" and cached_lookup_status in set(LOOKUP_STATUS_MAP.values())
        else LOOKUP_STATUS_MAP.get(status, "UNAVAILABLE")
    )
    if status == "not_found":
        finding, summary = "NOT_FOUND", "provider reported no record"
    elif status in {"not_configured", "disabled", "policy_prohibited", "unsupported", "invalid_observable"}:
        finding, summary = "PENDING", "provider lookup is disabled or not eligible"
    elif status in {"rate_limited", "budget_exhausted"}:
        finding, summary = "RATE_LIMITED" if status == "rate_limited" else "BUDGET_EXHAUSTED", "provider lookup is deferred"
    elif status == "auth_disabled":
        finding, summary = "AUTH_DISABLED", "provider authorization is disabled until configuration changes"
    elif status not in {"ok", "cached"}:
        finding, summary = "ERROR", "provider lookup failed"
    raw_digest = hashlib.sha256(
        stable_json(getattr(result, "data", {}) or {}).encode("utf-8")
    ).hexdigest()
    normalized_digest = hashlib.sha256(stable_json(extension).encode("utf-8")).hexdigest()
    policy_identity = str(
        getattr(result, "privacy_policy_identity", "")
        or settings.get("policy_identity")
        or "external_ti_non_ip.v1"
    )
    normalizer_identity = str(
        getattr(result, "normalizer_identity", "")
        or settings.get("normalizer_identity")
        or EXTERNAL_TI_EVIDENCE_SCHEMA
    )
    return {
        "schema_version": EXTERNAL_TI_PROVIDER_EVIDENCE_SCHEMA,
        "provider": str(getattr(result, "provider", "") or "").strip().lower(),
        "provider_mode": str(getattr(result, "provider_mode", "") or settings.get("mode") or "lookup")[:64],
        "endpoint_id": str(getattr(result, "endpoint_id", "") or settings.get("endpoint_id") or "")[:96],
        "api_version": str(getattr(result, "api_version", "") or "")[:32],
        "lookup_status": lookup_status,
        "status": status if status in PROVIDER_STATUS_VALUES else "error",
        "finding_state": finding if finding in FINDING_STATES else "UNKNOWN",
        "summary": summary[:512],
        "normalized_extension_type": extension_type[:64],
        "normalized_extension": extension,
        "provider_observed_at": observed_at,
        "provider_updated_at": updated_at,
        "retrieved_at": fetched_at,
        "expires_at": expires_at,
        "freshness_state": "FRESH" if fetched + timedelta(seconds=ttl) > datetime.now(timezone.utc) else "EXPIRED",
        "raw_response_digest": raw_digest,
        "normalized_payload_sha256": normalized_digest,
        "normalizer_identity": normalizer_identity[:128],
        "normalizer_version": normalizer_identity[:128],
        "privacy_policy_identity": policy_identity[:128],
        "privacy_policy_id": policy_identity[:128],
        "privacy_policy_sha256": hashlib.sha256(policy_identity.encode("utf-8")).hexdigest(),
        "provider_config_identity": str(getattr(result, "provider_config_identity", "") or provider_config_identity(str(getattr(result, "provider", "") or ""), settings)),
        "authority": EXTERNAL_TI_AUTHORITY,
        "uncertainty": {"classification": "CONTEXT_ONLY", "limitations": ["external provider context is not authoritative project truth"]},
        "normalized_result": {
            "finding_state": finding,
            "summary": summary[:512],
            "extension_type": extension_type[:64],
            "extension": extension,
        },
        "attempt_count": max(int(getattr(result, "attempt_count", 1) or 1), 0),
        "budget_consumed": max(int(getattr(result, "budget_consumed", 0) or 0), 0),
        "next_eligible_at": str(getattr(result, "next_eligible_at", "") or "") or None,
    }


def evidence_id_for(session_id: str, sighting_ids: Iterable[str], provider: str, payload_digest: str) -> str:
    return stable_id(
        "external-ti-evidence",
        {
            "schema_version": EXTERNAL_TI_EVIDENCE_SCHEMA,
            "session_id": str(session_id),
            "sighting_ids": sorted({str(item) for item in sighting_ids if str(item)}),
            "provider": str(provider),
            "payload_digest": str(payload_digest),
        },
    )


def build_external_ti_evidence(
    *,
    session_id: str,
    observable_type: str,
    observable_value: str,
    sightings: Sequence[Mapping[str, Any]],
    provider: str,
    provider_evidence: Mapping[str, Any],
    record: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the safe, provider-neutral session evidence projection.

    The stored provider extension is already bounded by
    ``provider_evidence_from_result``.  This wrapper binds it to the local
    sighting and durable record without copying raw provider responses,
    commands, source IPs, URLs, credentials, or payloads.
    """

    normalized_value = str(observable_value or "").strip().lower()
    provider_name = str(provider or "").strip().lower()
    if provider_name not in KNOWN_PROVIDERS:
        provider_name = "unknown"
    sighting_ids = sorted(
        {
            str(item.get("sighting_id") or "").strip()
            for item in sightings
            if str(item.get("sighting_id") or "").strip()
        }
    )[:32]
    payload_digest = _safe_digest((record or {}).get("payload_sha256")) or hashlib.sha256(
        stable_json((record or {}).get("payload") or {}).encode("utf-8")
    ).hexdigest()
    evidence = dict(provider_evidence)
    normalized_extension = _sanitize_provider_extension(
        provider_name,
        evidence.get("normalized_extension"),
    )
    finding_state = str(evidence.get("finding_state") or "UNKNOWN")
    if finding_state not in FINDING_STATES:
        finding_state = "UNKNOWN"
    lookup_status = str(evidence.get("lookup_status") or "UNAVAILABLE")
    if lookup_status not in {
        "OK",
        "NOT_FOUND",
        "DISABLED",
        "INVALID_OBSERVABLE",
        "PROVIDER_ERROR",
        "RATE_LIMITED",
        "AUTH_DISABLED",
        "BUDGET_EXHAUSTED",
        "UNAVAILABLE",
    }:
        lookup_status = "UNAVAILABLE"
    summary = _safe_provider_summary(provider_name, finding_state, normalized_extension)
    extension_type = _provider_extension_type(provider_name)
    endpoint_id = str(evidence.get("endpoint_id") or "").strip()
    if endpoint_id not in KNOWN_ENDPOINTS.get(provider_name, set()):
        endpoint_id = ""
    normalized_result = {
        "finding_state": finding_state,
        "summary": summary,
        "extension_type": extension_type,
        "extension": normalized_extension,
    }
    safe_reference = {
        "kind": "sha256" if observable_type == "hash" else observable_type,
        "value": normalized_value,
        "display_kind": "sha256" if observable_type == "hash" else observable_type,
        "display_value": normalized_value,
        "value_digest": hashlib.sha256(normalized_value.encode("utf-8")).hexdigest(),
    }
    central_record_id = str((record or {}).get("record_id") or "").strip()
    if not central_record_id:
        central_record_id = stable_id(
            "enrichment",
            {"observable_type": observable_type, "observable_value": normalized_value},
        )
    evidence_id = evidence_id_for(
        session_id,
        sighting_ids,
        provider_name,
        _safe_digest(evidence.get("normalized_payload_sha256")) or payload_digest,
    )
    return {
        "schema_version": EXTERNAL_TI_EVIDENCE_SCHEMA,
        "evidence_id": evidence_id,
        "session_id": str(session_id),
        "observable_id": stable_id(
            "observable",
            {"observable_type": observable_type, "observable_value": normalized_value},
        ),
        "observable_type": observable_type,
        "observable_role": "source_ip" if observable_type == "ip" else "file_hash",
        "safe_observable_reference": safe_reference,
        "sighting_ids": sighting_ids,
        "sighting_id": sighting_ids[0] if sighting_ids else "",
        "central_record_id": central_record_id[:256],
        "central_payload_sha256": payload_digest,
        "enrichment_record_id": central_record_id[:128],
        "enrichment_payload_sha256": payload_digest,
        "provider": provider_name,
        "provider_mode": "lookup",
        "endpoint_id": endpoint_id,
        "api_version": _safe_text(evidence.get("api_version"), 32),
        "lookup_status": lookup_status,
        "finding_state": finding_state,
        "summary": summary,
        "normalized_extension_type": extension_type,
        "normalized_extension": normalized_extension,
        "normalized_result": normalized_result,
        "provider_observed_at": _safe_timestamp(evidence.get("provider_observed_at")),
        "provider_updated_at": _safe_timestamp(evidence.get("provider_updated_at")),
        "retrieved_at": _safe_timestamp(evidence.get("retrieved_at")),
        "expires_at": _safe_timestamp(evidence.get("expires_at")),
        "freshness_state": (
            str(evidence.get("freshness_state") or "UNKNOWN").strip().upper()
            if str(evidence.get("freshness_state") or "UNKNOWN").strip().upper()
            in {"FRESH", "EXPIRED", "STALE", "UNKNOWN"}
            else "UNKNOWN"
        ),
        "raw_response_digest": _safe_digest(evidence.get("raw_response_digest")),
        "normalized_payload_sha256": _safe_digest(evidence.get("normalized_payload_sha256")),
        "normalizer_identity": EXTERNAL_TI_EVIDENCE_SCHEMA,
        "normalizer_version": EXTERNAL_TI_EVIDENCE_SCHEMA,
        "privacy_policy_identity": "external_ti_non_ip.v1",
        "privacy_policy_id": "external_ti_non_ip.v1",
        "privacy_policy_sha256": hashlib.sha256(b"external_ti_non_ip.v1").hexdigest(),
        "provider_config_identity": _safe_digest(evidence.get("provider_config_identity")),
        "authority": EXTERNAL_TI_AUTHORITY,
        "uncertainty": {
            "classification": "CONTEXT_ONLY",
            "limitations": [
                "external provider context is not authoritative project truth",
                "source evidence eligibility does not establish maliciousness",
            ],
        },
    }


@dataclass(frozen=True)
class BudgetDecision:
    allowed: bool
    status: str
    next_eligible_at: Optional[str] = None
    attempts_today: int = 0
    minute_attempts: int = 0


class ProviderPacingBudget:
    """Thread-safe in-process provider/mode pacing and daily budget guard.

    The enrichment service is the single dispatcher for this state in the
    current deployment. State is also persisted into provider subrecords for
    provenance; a future multi-dispatcher deployment must replace this with a
    durable shared limiter before enabling traffic.
    """

    def __init__(self, clock: Optional[Callable[[], float]] = None) -> None:
        self._clock = clock or time.time
        self._lock = threading.Lock()
        self._state: Dict[str, Dict[str, Any]] = {}

    @staticmethod
    def _iso(epoch: float) -> str:
        return datetime.fromtimestamp(epoch, timezone.utc).isoformat()

    def reserve(
        self,
        provider: str,
        *,
        minute_limit: int,
        daily_budget: int,
        now: Optional[float] = None,
    ) -> BudgetDecision:
        current = float(self._clock() if now is None else now)
        name = str(provider or "").strip().lower()
        with self._lock:
            state = self._state.setdefault(name, {"day": "", "attempts_today": 0, "timestamps": [], "next_eligible": 0.0})
            day = datetime.fromtimestamp(current, timezone.utc).date().isoformat()
            if state["day"] != day:
                state.update({"day": day, "attempts_today": 0, "timestamps": [], "next_eligible": 0.0})
            state["timestamps"] = [stamp for stamp in state["timestamps"] if current - stamp < 60.0]
            if int(minute_limit) <= 0 or int(daily_budget) <= 0:
                next_epoch = current + 60.0 if int(minute_limit) <= 0 else current
                if int(daily_budget) <= 0:
                    next_epoch = (datetime.fromtimestamp(current, timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)).timestamp()
                return BudgetDecision(False, "budget_exhausted", self._iso(next_epoch), state["attempts_today"], len(state["timestamps"]))
            if current < float(state.get("next_eligible") or 0.0):
                return BudgetDecision(False, "rate_limited", self._iso(float(state["next_eligible"])), state["attempts_today"], len(state["timestamps"]))
            if state["attempts_today"] >= int(daily_budget):
                next_epoch = (datetime.fromtimestamp(current, timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)).timestamp()
                return BudgetDecision(False, "budget_exhausted", self._iso(next_epoch), state["attempts_today"], len(state["timestamps"]))
            if len(state["timestamps"]) >= int(minute_limit):
                next_epoch = min(state["timestamps"]) + 60.0
                state["next_eligible"] = next_epoch
                return BudgetDecision(False, "rate_limited", self._iso(next_epoch), state["attempts_today"], len(state["timestamps"]))
            state["timestamps"].append(current)
            state["attempts_today"] += 1
            state["next_eligible"] = 0.0
            return BudgetDecision(True, "reserved", None, state["attempts_today"], len(state["timestamps"]))

    def defer(self, provider: str, seconds: float, now: Optional[float] = None) -> str:
        current = float(self._clock() if now is None else now)
        target = current + max(float(seconds or 0.0), 0.0)
        name = str(provider or "").strip().lower()
        with self._lock:
            state = self._state.setdefault(name, {"day": "", "attempts_today": 0, "timestamps": [], "next_eligible": 0.0})
            state["next_eligible"] = max(float(state.get("next_eligible") or 0.0), target)
        return self._iso(target)

    def snapshot(self, provider: str) -> Dict[str, Any]:
        name = str(provider or "").strip().lower()
        with self._lock:
            state = dict(self._state.get(name) or {})
        return {
            "provider": name,
            "attempts_today": int(state.get("attempts_today") or 0),
            "minute_attempts": len(state.get("timestamps") or []),
            "next_eligible_at": self._iso(float(state["next_eligible"])) if state.get("next_eligible") else None,
        }


@dataclass
class ExternalTIMetrics:
    """Bounded aggregate metrics with no indicator/session labels."""

    counters: Dict[str, int] = field(default_factory=dict)

    def increment(self, name: str, amount: int = 1) -> None:
        key = str(name or "").strip()[:96]
        if not key:
            return
        self.counters[key] = max(0, int(self.counters.get(key, 0)) + int(amount))

    def snapshot(self) -> Dict[str, int]:
        return dict(sorted(self.counters.items()))
