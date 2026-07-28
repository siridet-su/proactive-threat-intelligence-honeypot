"""Standalone HTML monitor for the cloud honeypot analysis pipeline."""

from __future__ import annotations

import argparse
import copy
import ipaddress
import json
import os
from dataclasses import dataclass
from html import escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse

from production.api.dashboard_api import (
    TABLES as DASHBOARD_TABLES,
    _current_decision_payload,
    _current_prediction_payload,
    _external_seed_health_payload,
)
from production.api.security import (
    api_row_view,
    authorize_read,
    authorize_write,
    event_views,
    log_payload,
    public_payload,
    sanitize_request_target,
    session_detail_view,
    validate_configured_bearer_tokens,
)
from production.classification.classification_evaluation import classification_metrics
from production.utils.config import ProductionConfig
from production.prediction.prediction_health import infer_prediction_paths, load_prediction_health
from production.reporting.feedback_review import FEEDBACK_FILTERS, build_feedback_review, filter_feedback_rows
from production.utils.feedback import normalize_submitted_feedback_payload
from production.utils.http_security import (
    BoundedThreadingHTTPServer,
    HTTPBodyError,
    decode_strict_json_body,
    is_loopback_host,
    read_bounded_http_body,
    safe_request_id,
    single_header_value,
    validate_bind_auth,
)
from production.utils.serialization import html_script_json, stable_id, utc_now
from production.utils.service_lifecycle import serve_http_until_stopped
from production.reporting.response_guidance_v3 import (
    read_legacy_response_guidance,
    validate_response_guidance_v3,
)
from production.storage import open_storage, safe_database_descriptor


DEFAULT_REPORTS_DIR = "./runtime/reports"
DEFAULT_REFRESH_SECONDS = 5
DEFAULT_SESSION_LIMIT = 500
MAX_SESSIONS = 5000
MAX_EVENTS = 50
MAX_SESSION_EVENTS = 500
MONITOR_SUMMARY_SCAN_LIMIT = 100_000
MONITOR_DETAIL_SCAN_LIMIT = 10_000
MAX_FEEDBACK_JSON_BYTES = 1_000_000
MAX_FEEDBACK_FORM_BYTES = 100_000
FEEDBACK_REQUEST_TIMEOUT_SECONDS = 15.0
STATIC_MONITOR_HTML = Path(__file__).with_name("static") / "monitor.html"


@dataclass
class MonitorConfig:
    db_path: str
    reports_dir: str
    bind_host: str = "127.0.0.1"
    database_url: str = ""
    external_seed_model_path: str = ""
    external_seed_validation_path: str = ""
    external_seed_review_path: str = ""
    external_seed_health_path: str = ""
    mitre_attack_path: str = ""
    response_guidance_policy_path: str = ""
    response_guidance_asset_profile_path: str = ""
    threat_hypothesis_behavior_policy_path: str = ""
    enable_response_guidance: bool = True
    refresh_seconds: int = DEFAULT_REFRESH_SECONDS
    production_config: Optional[ProductionConfig] = None


def _sqlite_path(database_url: str) -> str:
    if database_url.startswith("sqlite:///"):
        return database_url.replace("sqlite:///", "", 1)
    return ""


def _load_monitor_config(config_path: Optional[str] = None) -> MonitorConfig:
    cfg = ProductionConfig.from_env(config_path)
    external_seed_paths = infer_prediction_paths(cfg.prediction_policy)
    return MonitorConfig(
        database_url=cfg.database_url,
        db_path=_sqlite_path(cfg.database_url),
        reports_dir=cfg.reports_dir or DEFAULT_REPORTS_DIR,
        external_seed_model_path=external_seed_paths["model"],
        external_seed_validation_path=external_seed_paths["validation"],
        external_seed_review_path=external_seed_paths["review"],
        external_seed_health_path=external_seed_paths["health"],
        mitre_attack_path=cfg.mitre_attack_path,
        response_guidance_policy_path=cfg.response_guidance_policy_path,
        response_guidance_asset_profile_path=cfg.response_guidance_asset_profile_path,
        threat_hypothesis_behavior_policy_path=(
            cfg.threat_hypothesis_behavior_policy_path
        ),
        enable_response_guidance=cfg.enable_response_guidance,
        production_config=cfg,
    )


def _json_loads(value: Any, default: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if value is None:
        return default
    try:
        return json.loads(str(value))
    except (TypeError, ValueError):
        return default


def _sanitize_public(value: Any, key: str = "") -> Any:
    """Compatibility shim delegating legacy HTML paths to the central policy."""

    if key:
        wrapped = public_payload({str(key): value})
        return wrapped.get(str(key)) if isinstance(wrapped, dict) else wrapped
    return public_payload(value)


def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _short(value: Any, limit: int = 120) -> str:
    text = _text(value)
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "..."


def _monitor_database_url(config: MonitorConfig) -> str:
    if config.database_url:
        return config.database_url
    if config.db_path:
        # Deprecated compatibility for callers that explicitly provide only a
        # SQLite path. Ordinary configuration always supplies database_url.
        return f"sqlite:///{config.db_path}"
    raise ValueError(
        "monitor database configuration is missing; configure DATABASE_BACKEND "
        "or use the deprecated explicit --db-path SQLite override"
    )


def _monitor_database_descriptor(config: MonitorConfig) -> Dict[str, str]:
    return safe_database_descriptor(_monitor_database_url(config))


def _monitor_database_display(config: MonitorConfig) -> str:
    try:
        descriptor = _monitor_database_descriptor(config)
    except Exception:
        return "unavailable"
    if descriptor.get("backend") == "sqlite":
        return descriptor.get("database_path") or "sqlite"
    endpoint = descriptor.get("endpoint") or "private"
    database = descriptor.get("database") or "default"
    return f"{descriptor.get('backend')}://{endpoint}/{database}"


def _open_monitor_storage(config: MonitorConfig) -> Any:
    return open_storage(_monitor_database_url(config))


def _monitor_runtime_config(config: MonitorConfig) -> ProductionConfig:
    cfg = copy.copy(config.production_config or ProductionConfig())
    cfg.database_url = _monitor_database_url(config)
    cfg.reports_dir = config.reports_dir
    cfg.mitre_attack_path = config.mitre_attack_path or cfg.mitre_attack_path
    cfg.response_guidance_policy_path = (
        config.response_guidance_policy_path or cfg.response_guidance_policy_path
    )
    cfg.response_guidance_asset_profile_path = (
        config.response_guidance_asset_profile_path
        or cfg.response_guidance_asset_profile_path
    )
    cfg.enable_response_guidance = config.enable_response_guidance
    return cfg


def _monitor_read_token(config: MonitorConfig) -> str:
    return str(
        getattr(config.production_config, "dashboard_read_token", "") or ""
    )


def _monitor_write_token(config: MonitorConfig) -> str:
    return str(
        getattr(config.production_config, "dashboard_write_token", "") or ""
    )


def _monitor_feedback_enabled(config: MonitorConfig) -> bool:
    return bool(
        getattr(config.production_config, "monitor_allow_feedback", False)
    )


def _parse_limit(query: Dict[str, List[str]], default: int = 100, maximum: int = 1000) -> int:
    try:
        return min(max(int(query.get("limit", [str(default)])[0]), 1), maximum)
    except (TypeError, ValueError):
        return default


def _decode_dashboard_row(row: Dict[str, Any]) -> Dict[str, Any]:
    item = dict(row)
    for source_key, target_key, default in (
        ("payload_json", "payload", {}),
        ("result_json", "result", {}),
        ("provider_status_json", "provider_status", {}),
        ("confirmed_tactics_json", "confirmed_tactics", []),
        ("match_reasons_json", "match_reasons", []),
    ):
        if source_key in item and target_key not in item:
            item[target_key] = _json_loads(item.get(source_key), default)
    return item


def _dashboard_get_payload(config: MonitorConfig, path: str, query: Dict[str, List[str]]) -> Tuple[HTTPStatus, Optional[Dict[str, Any]]]:
    runtime_config = _monitor_runtime_config(config)
    storage = _open_monitor_storage(config)

    if path == "/predictions/current":
        session_id = query.get("session_id", [""])[0].strip()
        if not session_id:
            return HTTPStatus.BAD_REQUEST, {"error": "session_id is required"}
        snapshot = storage.get_latest_prediction_snapshot(session_id)
        if not snapshot:
            return HTTPStatus.NOT_FOUND, {"error": "prediction not found", "session_id": session_id, "timestamp": utc_now()}
        feedback_rows = [
            row for row in storage.list_rows("analyst_feedback", limit=1000)
            if str(row.get("session_id") or "") == session_id
        ]
        return HTTPStatus.OK, {
            "item": api_row_view("prediction_snapshots", snapshot),
            "current_prediction": _current_prediction_payload(snapshot, feedback_rows),
            "response_guidance": _current_decision_payload(runtime_config, storage, session_id, snapshot),
            "session_id": session_id,
            "timestamp": utc_now(),
        }

    if path == "/decisions/current":
        session_id = query.get("session_id", [""])[0].strip()
        if not session_id:
            return HTTPStatus.BAD_REQUEST, {"error": "session_id is required"}
        snapshot = storage.get_latest_prediction_snapshot(session_id) or {"session_id": session_id, "payload": {}}
        return HTTPStatus.OK, {
            "response_guidance": _current_decision_payload(runtime_config, storage, session_id, snapshot),
            "session_id": session_id,
            "timestamp": utc_now(),
        }

    if path == "/feedback-review":
        limit = _parse_limit(query, default=1000, maximum=5000)
        feedback_filter = str(query.get("filter", ["all"])[0] or "all").strip().lower()
        if feedback_filter not in FEEDBACK_FILTERS:
            feedback_filter = "all"
        rows = storage.list_rows("analyst_feedback", limit=limit)
        filtered_rows = filter_feedback_rows(rows, feedback_filter)[:100]
        return HTTPStatus.OK, {
            "filter": feedback_filter,
            "items": [
                api_row_view("analyst_feedback", row)
                for row in filtered_rows
            ],
            "review": build_feedback_review(rows),
            "timestamp": utc_now(),
        }

    if path == "/classification-evaluation":
        limit = _parse_limit(query, default=1000, maximum=5000)
        return HTTPStatus.OK, {
            "report": classification_metrics(storage.list_classification_review_labels(limit=limit)),
            "timestamp": utc_now(),
        }

    if path == "/external-seed-health":
        return HTTPStatus.OK, {
            "external_seed_health": _external_seed_health_payload(runtime_config),
            "timestamp": utc_now(),
        }

    table = DASHBOARD_TABLES.get(path)
    if table:
        limit = _parse_limit(query, default=100, maximum=1000)
        return HTTPStatus.OK, {
            "items": [
                api_row_view(table, _decode_dashboard_row(row))
                for row in storage.list_rows(table, limit=limit)
            ],
            "limit": limit,
            "table": table,
            "timestamp": utc_now(),
        }

    return HTTPStatus.NOT_FOUND, None


def _read_static_monitor_html() -> Optional[str]:
    try:
        return STATIC_MONITOR_HTML.read_text(encoding="utf-8")
    except OSError:
        return None


def _html(value: Any) -> str:
    return escape(_text(value))


def _format_list(values: Iterable[Any], limit: int = 8) -> str:
    clean = []
    for value in values:
        text = _text(value).strip()
        if text and text not in clean:
            clean.append(text)
    if not clean:
        return "-"
    display = clean[:limit]
    suffix = f" +{len(clean) - limit}" if len(clean) > limit else ""
    return ", ".join(display) + suffix


def _storage_error(label: str, exc: BaseException) -> str:
    return f"{label} failed: {type(exc).__name__}"


def _storage_list_rows(
    storage: Any,
    table: str,
    limit: int,
) -> Tuple[List[Dict[str, Any]], str]:
    try:
        rows = storage.list_rows(table, limit=max(int(limit), 1))
        return [dict(row) for row in rows or []], ""
    except Exception as exc:  # Monitor degrades individual panels independently.
        return [], _storage_error(f"{table} query", exc)


def _row_session_id(row: Dict[str, Any]) -> str:
    payload = _payload_from_row(row)
    return _text(
        row.get("session_id")
        or payload.get("session_id")
        or payload.get("session")
    )


def _storage_session_rows(
    storage: Any,
    table: str,
    session_id: str,
    limit: int,
) -> Tuple[List[Dict[str, Any]], str]:
    session_loader = getattr(storage, "list_rows_for_session", None)
    if session_loader is not None:
        try:
            rows = session_loader(table, session_id, limit=limit)
        except Exception as exc:
            return [], _storage_error(f"{table} session query", exc)
        return [dict(row) for row in rows or []], ""

    # Bounded compatibility for injected legacy test doubles. Runtime adapters
    # implement list_rows_for_session and do not scan unrelated records.
    if table == "sessions":
        try:
            row = storage.get_session(session_id)
        except Exception as exc:
            return [], _storage_error("session query", exc)
        return ([dict(row)] if row else []), (
            "" if row else f"session not found: {session_id}"
        )
    rows, error = _storage_list_rows(
        storage,
        table,
        max(int(limit), MONITOR_DETAIL_SCAN_LIMIT),
    )
    if error:
        return [], error
    filtered = [row for row in rows if _row_session_id(row) == session_id]
    return filtered[:limit], ""


def _storage_enrichment_rows(
    storage: Any,
    session_id: str,
    observables: Iterable[Tuple[str, str]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], str]:
    normalized = [(str(t), str(v)) for t, v in observables if t and v]
    records: List[Dict[str, Any]] = []
    errors: List[str] = []
    for observable_type, observable_value in normalized:
        try:
            record = storage.get_enrichment_record(
                observable_type,
                observable_value,
                allow_stale=True,
            )
        except Exception as exc:
            errors.append(
                _storage_error(
                    f"enrichment record {observable_type}",
                    exc,
                )
            )
            continue
        if record:
            records.append(dict(record))

    session_jobs, session_jobs_error = _storage_session_rows(
        storage,
        "enrichment_jobs",
        session_id,
        100,
    )
    if session_jobs_error:
        errors.append(session_jobs_error)
    job_rows, jobs_error = _storage_list_rows(
        storage,
        "enrichment_jobs",
        MONITOR_DETAIL_SCAN_LIMIT,
    )
    if jobs_error:
        errors.append(jobs_error)
    observable_set = set(normalized)
    observable_jobs = [
        row
        for row in job_rows
        if (
            _text(row.get("observable_type")),
            _text(row.get("observable_value")),
        )
        in observable_set
    ]
    jobs = session_jobs + observable_jobs

    def dedupe(rows: List[Dict[str, Any]], keys: Tuple[str, ...]) -> List[Dict[str, Any]]:
        seen = set()
        output = []
        for row in rows:
            marker = tuple(row.get(key) for key in keys)
            if marker in seen:
                continue
            seen.add(marker)
            output.append(row)
        return output

    return (
        dedupe(records, ("observable_type", "observable_value", "updated_at")),
        dedupe(jobs, ("job_id",))[:100],
        "; ".join(errors),
    )


def _storage_observable_sightings(
    storage: Any,
    session_id: str,
    observables: Iterable[Tuple[str, str]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], str]:
    session_rows, session_error = _storage_session_rows(
        storage,
        "observable_sightings",
        session_id,
        200,
    )
    rows, error = _storage_list_rows(
        storage,
        "observable_sightings",
        MONITOR_DETAIL_SCAN_LIMIT,
    )
    errors = [message for message in (session_error, error) if message]
    observable_set = {(str(t), str(v)) for t, v in observables if t and v}
    related_rows = [
        row
        for row in rows
        if _row_session_id(row) != session_id
        and (
            _text(row.get("observable_type")),
            _text(row.get("observable_value")),
        )
        in observable_set
    ][:200]
    return session_rows, related_rows, "; ".join(errors)


def _storage_session_links_and_jobs(
    storage: Any,
    session_id: str,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], str]:
    errors: List[str] = []
    try:
        links = [
            dict(row)
            for row in storage.list_session_links(session_id, limit=100) or []
        ]
    except Exception as exc:
        links = []
        errors.append(_storage_error("session links query", exc))
    jobs, jobs_error = _storage_session_rows(
        storage,
        "threat_hunt_jobs",
        session_id,
        100,
    )
    if jobs_error:
        errors.append(jobs_error)
    return links, jobs, "; ".join(errors)


def _storage_campaign_rows(
    storage: Any,
    session_id: str,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], str]:
    try:
        memberships = [
            dict(row)
            for row in storage.list_session_campaigns(session_id, limit=50) or []
        ]
    except Exception as exc:
        return [], [], _storage_error("campaign memberships query", exc)
    campaigns: List[Dict[str, Any]] = []
    errors: List[str] = []
    seen = set()
    for membership in memberships:
        campaign_id = _text(membership.get("campaign_id"))
        if not campaign_id or campaign_id in seen:
            continue
        seen.add(campaign_id)
        try:
            campaign = storage.get_campaign(campaign_id)
        except Exception as exc:
            errors.append(_storage_error(f"campaign {campaign_id} query", exc))
            continue
        if campaign:
            campaigns.append(dict(campaign))
    return memberships, campaigns, "; ".join(errors)


def _storage_ip_enrichment_contexts(
    storage: Any,
    ips: Iterable[str],
) -> Tuple[Dict[str, Dict[str, Any]], str]:
    try:
        cache = storage.load_enrichment_cache("ip", allow_stale=True)
    except Exception as exc:
        return {}, _storage_error("IP enrichment cache query", exc)
    contexts: Dict[str, Dict[str, Any]] = {}
    for ip in sorted({str(item).strip() for item in ips if _is_public_ip(item)}):
        payload = cache.get(ip)
        if not isinstance(payload, dict):
            continue
        context = _extract_geo_context(payload)
        if context:
            contexts[ip] = _merge_geo_contexts(
                context,
                {
                    "observable_type": "ip",
                    "observable_value": ip,
                    "source": context.get("source") or "enrichment_records",
                },
            )
    return contexts, ""


def _session_payload(row: Dict[str, Any]) -> Dict[str, Any]:
    payload = _payload_from_row(row)
    if not isinstance(payload, dict):
        payload = {}
    payload.setdefault("session_id", row.get("session_id", "unknown"))
    payload.setdefault("src_ip", row.get("src_ip", "unknown"))
    payload.setdefault("updated_at", row.get("updated_at", ""))
    return payload


def _report_payload(row: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not row:
        return {}
    payload = _payload_from_row(row)
    return payload if isinstance(payload, dict) else {}


def _event_payload(row: Dict[str, Any]) -> Dict[str, Any]:
    payload = _payload_from_row(row)
    return payload if isinstance(payload, dict) else {}


def _ip_scope(value: Any) -> Dict[str, Any]:
    text = str(value or "").strip()
    if not text:
        return {"is_public": False, "scope": "missing"}
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return {"is_public": False, "scope": "invalid"}
    documentation_networks = (
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
    )
    benchmarking_networks = (
        ipaddress.ip_network("198.18.0.0/15"),
    )
    if any(ip in network for network in documentation_networks):
        return {"is_public": False, "scope": "documentation"}
    if any(ip in network for network in benchmarking_networks):
        return {"is_public": False, "scope": "benchmarking"}
    if ip.is_global:
        return {"is_public": True, "scope": "public"}
    if ip.is_private:
        return {"is_public": False, "scope": "private"}
    if ip.is_loopback:
        return {"is_public": False, "scope": "loopback"}
    if ip.is_link_local:
        return {"is_public": False, "scope": "link_local"}
    if ip.is_multicast:
        return {"is_public": False, "scope": "multicast"}
    if ip.is_reserved:
        return {"is_public": False, "scope": "reserved"}
    if ip.is_unspecified:
        return {"is_public": False, "scope": "unspecified"}
    return {"is_public": False, "scope": "non_public"}


def _is_public_ip(value: Any) -> bool:
    return bool(_ip_scope(value).get("is_public"))


def _float_or_none(value: Any) -> Optional[float]:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        number = float(value)
    else:
        text = str(value).strip()
        if not text:
            return None
        try:
            number = float(text)
        except ValueError:
            return None
    return number


def _first_text(source: Dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = source.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _geo_from_candidate(candidate: Dict[str, Any], source_name: str) -> Dict[str, Any]:
    lat = _float_or_none(
        candidate.get("latitude")
        if candidate.get("latitude") is not None
        else candidate.get("lat")
        if candidate.get("lat") is not None
        else candidate.get("geolocation_data/latitude")
    )
    lon = _float_or_none(
        candidate.get("longitude")
        if candidate.get("longitude") is not None
        else candidate.get("lon")
        if candidate.get("lon") is not None
        else candidate.get("lng")
        if candidate.get("lng") is not None
        else candidate.get("geolocation_data/longitude")
    )
    if lat is None or lon is None or not (-90.0 <= lat <= 90.0) or not (-180.0 <= lon <= 180.0):
        return {}
    return {
        "latitude": lat,
        "longitude": lon,
        "city": _first_text(candidate, "city_name", "city", "geolocation_data/city_name"),
        "region": _first_text(candidate, "region_name", "region", "region_code", "geolocation_data/region_name"),
        "country": _first_text(candidate, "country_name", "country", "geolocation_data/country_name"),
        "country_code": _first_text(
            candidate,
            "country_code2",
            "country_code3",
            "country_code",
            "geolocation_data/country_code2",
            "geolocation_data/country_code3",
        ),
        "postal_code": _first_text(candidate, "postal_code", "geolocation_data/postal_code"),
        "timezone": _first_text(candidate, "timezone", "geolocation_data/timezone"),
        "asn": _first_text(candidate, "asn", "as_number"),
        "isp": _first_text(candidate, "isp", "org", "organization"),
        "source": source_name,
    }


def _truthy_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"true", "1", "yes", "y"}:
        return True
    if text in {"false", "0", "no", "n"}:
        return False
    return None


def _list_values(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        output: List[str] = []
        for item in value:
            text = str(item or "").strip()
            if text and text not in output:
                output.append(text)
        return output
    text = str(value or "").strip()
    return [text] if text else []


def _merge_geo_contexts(*contexts: Dict[str, Any]) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    for context in contexts:
        if not isinstance(context, dict):
            continue
        for key, value in context.items():
            if value in ("", None, [], {}):
                continue
            if isinstance(value, list):
                existing = merged.get(key)
                if not isinstance(existing, list):
                    existing = []
                for item in value:
                    text = str(item or "").strip()
                    if text and text not in existing:
                        existing.append(text)
                if existing:
                    merged[key] = existing
                continue
            if isinstance(value, dict):
                existing_dict = merged.get(key)
                if isinstance(existing_dict, dict):
                    merged[key] = {**existing_dict, **value}
                else:
                    merged[key] = value
                continue
            if key not in merged or merged.get(key) in ("", None):
                merged[key] = value
    if "latitude" in merged and "longitude" in merged:
        merged["has_coordinates"] = True
    elif merged:
        merged["has_coordinates"] = False
    return merged


def _geo_context_from_candidate(candidate: Dict[str, Any], source_name: str) -> Dict[str, Any]:
    if not isinstance(candidate, dict):
        return {}
    context = _geo_from_candidate(candidate, source_name)
    text_fields = {
        "city": ("city_name", "city", "geolocation_data/city_name"),
        "region": ("region_name", "region", "region_code", "geolocation_data/region_name"),
        "country": ("country_name", "country", "geolocation_data/country_name"),
        "country_code": (
            "country_code2",
            "country_code3",
            "country_code",
            "countryCode",
            "geolocation_data/country_code2",
            "geolocation_data/country_code3",
        ),
        "asn": ("asn", "as_number", "asn_number"),
        "isp": ("isp", "org", "organization", "domain"),
        "timezone": ("timezone", "geolocation_data/timezone"),
        "postal_code": ("postal_code", "geolocation_data/postal_code"),
        "fetched_at": ("fetched_at", "updated_at", "last_seen"),
        "expires_at": ("expires_at", "expires"),
    }
    for target, keys in text_fields.items():
        value = _first_text(candidate, *keys)
        if value:
            context.setdefault(target, value)
    for target, keys in {
        "is_tor_exit": ("is_tor_exit", "tor", "tor_exit"),
        "is_vpn": ("is_vpn", "vpn"),
    }.items():
        for key in keys:
            parsed = _truthy_bool(candidate.get(key))
            if parsed is not None:
                context.setdefault(target, parsed)
                break
    tag_values: List[str] = []
    for key in ("infrastructure_tags", "abuse_tags", "otx_tags", "tags", "threat_tags"):
        tag_values.extend(_list_values(candidate.get(key)))
    if tag_values:
        context["tags"] = sorted(set(tag_values))
    provider_status = candidate.get("provider_status") or candidate.get("providers")
    if isinstance(provider_status, dict):
        context.setdefault("provider_status", provider_status)
    if context:
        context.setdefault("source", source_name)
        context["has_coordinates"] = "latitude" in context and "longitude" in context
    return context


def _extract_geo(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    direct = _geo_from_candidate(value, "payload")
    if direct:
        return direct
    for key in (
        "geolocation_data",
        "geo",
        "geoip",
        "source_geo",
        "src_geo",
        "ip_location",
        "location",
    ):
        nested = value.get(key)
        if isinstance(nested, dict):
            found = _geo_from_candidate(nested, key)
            if found:
                return found
    for event in value.get("raw_events") or []:
        if isinstance(event, dict):
            found = _extract_geo(event)
            if found:
                return found
    return {}


def _extract_geo_context(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    context = _geo_context_from_candidate(value, "payload")
    for key in (
        "geolocation_data",
        "geo",
        "geoip",
        "source_geo",
        "src_geo",
        "ip_location",
        "location",
        "data",
        "result",
        "payload",
    ):
        nested = value.get(key)
        if isinstance(nested, dict):
            context = _merge_geo_contexts(context, _geo_context_from_candidate(nested, key))
    providers = value.get("providers") or value.get("provider_results")
    if isinstance(providers, dict):
        for provider, provider_value in providers.items():
            if not isinstance(provider_value, dict):
                continue
            provider_context = _geo_context_from_candidate(provider_value, str(provider))
            for key in ("data", "result", "payload"):
                nested = provider_value.get(key)
                if isinstance(nested, dict):
                    provider_context = _merge_geo_contexts(
                        provider_context,
                        _geo_context_from_candidate(nested, f"{provider}.{key}"),
                    )
            context = _merge_geo_contexts(context, provider_context)
    for event in value.get("raw_events") or []:
        if isinstance(event, dict):
            context = _merge_geo_contexts(context, _extract_geo_context(event))
    return context


def _geo_from_context(context: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(context, dict):
        return {}
    source = str(context.get("source") or "geo_context")
    return _geo_from_candidate(context, source)


def _public_geo_context(payload: Dict[str, Any], src_ip: Any) -> Dict[str, Any]:
    if not _is_public_ip(src_ip):
        return {}
    return _extract_geo_context(payload)


def _public_ips_from_rows(rows: Iterable[Dict[str, Any]], payload_loader) -> List[str]:
    ips: List[str] = []
    for row in rows:
        payload = payload_loader(row)
        candidates = [
            payload.get("src_ip") if isinstance(payload, dict) else "",
            row.get("src_ip"),
            row.get("observable_value") if row.get("observable_type") == "ip" else "",
        ]
        for candidate in candidates:
            text = str(candidate or "").strip()
            if text and _is_public_ip(text) and text not in ips:
                ips.append(text)
    return ips


def _row_with_payload(row: Dict[str, Any]) -> Dict[str, Any]:
    item = dict(row)
    payload = (
        item.get("payload")
        if isinstance(item.get("payload"), dict)
        else _json_loads(item.get("payload_json"), {})
    )
    item.pop("payload_json", None)
    if isinstance(payload, dict):
        item["payload"] = payload
        src_ip = payload.get("src_ip") or item.get("src_ip")
        if not src_ip and item.get("observable_type") == "ip":
            src_ip = item.get("observable_value")
        scope = _ip_scope(src_ip)
        item["src_ip_is_public"] = scope["is_public"]
        item["src_ip_scope"] = scope["scope"]
        geo_context = _public_geo_context(payload, src_ip)
        geo = _extract_geo(payload) if scope["is_public"] else {}
        if geo_context:
            item["geo_context"] = geo_context
        if geo:
            item["geo"] = geo
        elif geo_context:
            geo_from_context = _geo_from_context(geo_context)
            if geo_from_context:
                item["geo"] = geo_from_context
    result = (
        item.get("result")
        if isinstance(item.get("result"), dict)
        else _json_loads(item.get("result_json"), {})
    )
    item.pop("result_json", None)
    if isinstance(result, dict):
        item["result"] = result
    provider_status = (
        item.get("provider_status")
        if isinstance(item.get("provider_status"), dict)
        else _json_loads(item.get("provider_status_json"), {})
    )
    item.pop("provider_status_json", None)
    if isinstance(provider_status, dict):
        item["provider_status"] = provider_status
    match_reasons = (
        item.get("match_reasons")
        if isinstance(item.get("match_reasons"), list)
        else _json_loads(item.get("match_reasons_json"), [])
    )
    item.pop("match_reasons_json", None)
    if isinstance(match_reasons, list):
        item["match_reasons"] = match_reasons
    confirmed_tactics = (
        item.get("confirmed_tactics")
        if isinstance(item.get("confirmed_tactics"), list)
        else _json_loads(item.get("confirmed_tactics_json"), [])
    )
    item.pop("confirmed_tactics_json", None)
    if isinstance(confirmed_tactics, list):
        item["confirmed_tactics"] = confirmed_tactics
    return item


def _payload_from_row(row: Dict[str, Any]) -> Dict[str, Any]:
    payload = row.get("payload")
    if isinstance(payload, dict):
        return payload
    loaded = _json_loads(row.get("payload_json"), {})
    return loaded if isinstance(loaded, dict) else {}


def _latest_payload_row(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not rows:
        return {}
    return _payload_from_row(rows[0])


def _summarize_feedback_rows(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    labels: Dict[str, int] = {}
    feedback_types: Dict[str, int] = {}
    operator_signals: Dict[str, int] = {}
    action_statuses: Dict[str, int] = {}
    weight_eligible = 0
    high_confidence_wrong = 0
    low_confidence_useful = 0
    missing_actual = 0
    for row in rows:
        payload = _payload_from_row(row)
        label = str(row.get("label") or payload.get("label") or "unknown")
        labels[label] = labels.get(label, 0) + 1
        feedback_type = str(row.get("feedback_type") or payload.get("feedback_type") or "legacy")
        feedback_types[feedback_type] = feedback_types.get(feedback_type, 0) + 1
        operator_signal = str(row.get("operator_signal") or payload.get("operator_signal") or "")
        if operator_signal:
            operator_signals[operator_signal] = operator_signals.get(operator_signal, 0) + 1
        action_status = str(row.get("action_status") or payload.get("action_status") or "")
        if action_status:
            action_statuses[action_status] = action_statuses.get(action_status, 0) + 1
        if bool(row.get("weight_eligible") or payload.get("weight_eligible")):
            weight_eligible += 1
        actual = str(row.get("final_actual_next_tactic") or payload.get("final_actual_next_tactic") or row.get("correct_next_tactic") or payload.get("correct_next_tactic") or "")
        if not actual:
            missing_actual += 1
        ranking_raw = row.get("predicted_ranking") or payload.get("predicted_ranking") or []
        ranking = _json_loads(ranking_raw, []) if isinstance(ranking_raw, str) else ranking_raw
        top = ranking[0] if isinstance(ranking, list) and ranking and isinstance(ranking[0], dict) else {}
        confidence = str(top.get("confidence") or "")
        try:
            score = float(top.get("score") or 0.0)
        except (TypeError, ValueError):
            score = 0.0
        if label in {"wrong", "not_useful", "false_positive"} and (confidence == "high" or score >= 0.70):
            high_confidence_wrong += 1
        if label in {"useful", "correct"} and (confidence == "low" or score < 0.40):
            low_confidence_useful += 1
    return {
        "count": len(rows),
        "labels": labels,
        "feedback_types": feedback_types,
        "operator_signals": operator_signals,
        "action_statuses": action_statuses,
        "weight_eligible": weight_eligible,
        "high_confidence_wrong": high_confidence_wrong,
        "low_confidence_useful": low_confidence_useful,
        "missing_actual": missing_actual,
    }


def _compact_prediction_ranking(ranking: Any) -> List[Dict[str, Any]]:
    if not isinstance(ranking, list):
        return []
    compact: List[Dict[str, Any]] = []
    for item in ranking[:8]:
        if not isinstance(item, dict):
            continue
        sources = []
        for source in item.get("sources") or []:
            if not isinstance(source, dict):
                continue
            sources.append(
                {
                    "name": source.get("name") or source.get("source") or "unknown",
                    "source_type": source.get("source_type") or "",
                    "rule_id": source.get("rule_id") or "",
                    "weighted_score": source.get("weighted_score"),
                    "damping_factor": source.get("damping_factor"),
                }
            )
        compact.append(
            {
                "tactic": item.get("tactic"),
                "score": item.get("score"),
                "confidence": item.get("confidence"),
                "source_types": item.get("source_types") or [],
                "sources": sources,
                "reasons": list((item.get("reasons") or [])[:4]) if isinstance(item.get("reasons"), list) else [],
            }
        )
    return compact


def _summarize_classification_review_rows(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    reviewed = 0
    tactic_correct = 0
    ttp_correct = 0
    by_source: Dict[str, int] = {}
    latest = ""
    for row in rows:
        payload = _payload_from_row(row)
        predicted_tactic = str(row.get("predicted_tactic") or payload.get("predicted_tactic") or "")
        reviewed_tactic = str(row.get("reviewed_tactic") or payload.get("reviewed_tactic") or "")
        predicted_ttp = str(row.get("predicted_ttp") or payload.get("predicted_ttp") or "")
        reviewed_ttp = str(row.get("reviewed_ttp") or payload.get("reviewed_ttp") or "")
        source = str(row.get("predicted_source") or payload.get("predicted_source") or "unknown")
        by_source[source] = by_source.get(source, 0) + 1
        created_at = str(row.get("created_at") or payload.get("created_at") or "")
        if created_at > latest:
            latest = created_at
        if reviewed_tactic or reviewed_ttp:
            reviewed += 1
        if reviewed_tactic and predicted_tactic == reviewed_tactic:
            tactic_correct += 1
        if reviewed_ttp and predicted_ttp == reviewed_ttp:
            ttp_correct += 1
    return {
        "reviewed_cases": reviewed,
        "stored_labels": len(rows),
        "tactic_accuracy": round(tactic_correct / reviewed, 4) if reviewed else 0.0,
        "ttp_accuracy": round(ttp_correct / reviewed, 4) if reviewed else 0.0,
        "source_counts": by_source,
        "latest_reviewed_at": latest or "-",
    }


def _summarize_backtest_rows(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    payload = _latest_payload_row(rows)
    metrics = payload.get("metrics") or {}
    calibration = payload.get("confidence_label_calibration") or payload.get("calibration") or {}
    return {
        "count": len(rows),
        "run_id": payload.get("run_id") or rows[0].get("run_id") if rows else "",
        "generated_at": payload.get("generated_at") or rows[0].get("created_at") if rows else "",
        "completed_sessions": payload.get("completed_sessions", 0),
        "evaluated_sessions": payload.get("evaluated_sessions", 0),
        "total_cases": metrics.get("total_cases", 0),
        "coverage": metrics.get("coverage", 0.0),
        "top1_accuracy": metrics.get("top1_accuracy", 0.0),
        "top3_accuracy": metrics.get("top3_accuracy", 0.0),
        "mrr": metrics.get("mean_reciprocal_rank", 0.0),
        "disagreement_rate": metrics.get("scorer_disagreement_rate", 0.0),
        "low_bucket_cases": (calibration.get("low") or {}).get("cases", 0) if isinstance(calibration, dict) else 0,
        "medium_bucket_cases": (calibration.get("medium") or {}).get("cases", 0) if isinstance(calibration, dict) else 0,
        "high_bucket_cases": (calibration.get("high") or {}).get("cases", 0) if isinstance(calibration, dict) else 0,
    }


def _summarize_calibration_rows(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    payload = _latest_payload_row(rows)
    inputs = payload.get("inputs") or {}
    adjustments = payload.get("adjustments") or {}
    changed = [
        f"{name}:{item.get('delta')}"
        for name, item in sorted(adjustments.items())
        if isinstance(item, dict) and float(item.get("delta") or 0.0) != 0.0
    ]
    return {
        "count": len(rows),
        "run_id": payload.get("run_id") or rows[0].get("run_id") if rows else "",
        "generated_at": payload.get("generated_at") or rows[0].get("created_at") if rows else "",
        "status": payload.get("status") or rows[0].get("status") if rows else "missing",
        "applied": bool(payload.get("applied") or payload.get("apply")),
        "reason": payload.get("reason") or "",
        "feedback_cases": inputs.get("feedback_cases", 0),
        "min_feedback_rows": inputs.get("min_feedback_rows", 0),
        "backtest_cases": inputs.get("backtest_cases", 0),
        "min_backtest_cases": inputs.get("min_backtest_cases", 0),
        "changed_weights": changed,
    }


def _load_external_seed_health(config: MonitorConfig) -> Dict[str, Any]:
    try:
        health = load_prediction_health(
            config.external_seed_health_path,
            model_path=config.external_seed_model_path,
            validation_path=config.external_seed_validation_path,
            review_path=config.external_seed_review_path,
            include_review=False,
            mode=str(
                (config.production_config.prediction_policy or {}).get(
                    "prediction_mode"
                )
                if config.production_config
                else ""
            ),
        )
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        return {
            "schema_version": "external_seed_health.v1",
            "generated_at": utc_now(),
            "available": False,
            "warnings": [f"External seed health load failed: {type(exc).__name__}"],
        }
    return health if isinstance(health, dict) else {}


def record_analyst_feedback(config: MonitorConfig, feedback: Dict[str, Any]) -> str:
    payload = normalize_submitted_feedback_payload(
        feedback,
        source="monitor_web",
    )
    feedback_id = stable_id("feedback", payload)
    payload["feedback_id"] = feedback_id
    stored_id = _open_monitor_storage(config).record_analyst_feedback(payload)
    return str(stored_id or feedback_id)


def _index_by_latest(rows: List[Dict[str, Any]], key: str, time_key: str) -> Dict[str, Dict[str, Any]]:
    indexed: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        value = _text(row.get(key))
        if not value:
            continue
        current = indexed.get(value)
        if not current or _text(row.get(time_key)) > _text(current.get(time_key)):
            indexed[value] = row
    return indexed


def _artifact_paths(report_payload: Dict[str, Any], reports_dir: str) -> Dict[str, str]:
    artifacts = report_payload.get("artifacts") or {}
    if not isinstance(artifacts, dict):
        artifacts = {}
    paths = {str(k): str(v) for k, v in artifacts.items() if isinstance(v, str) and v}
    session_id = _text(report_payload.get("session_id"))
    if session_id and "json" not in paths:
        candidate = Path(reports_dir) / f"{session_id}_report.json"
        if candidate.exists():
            paths["json"] = str(candidate)
    return paths


def _path_under(path: str, root: str) -> bool:
    try:
        resolved = Path(path).resolve()
        base = Path(root).resolve()
        return os.path.commonpath([str(resolved), str(base)]) == str(base)
    except (OSError, ValueError):
        return False


def _load_report_json_from_artifact(paths: Dict[str, str], reports_dir: str) -> Dict[str, Any]:
    json_path = paths.get("json")
    if not json_path or not _path_under(json_path, reports_dir):
        return {}
    path = Path(json_path)
    if not path.exists() or not path.is_file():
        return {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
        return loaded if isinstance(loaded, dict) else {}
    except (OSError, ValueError):
        return {}


def _report_summary(report_payload: Dict[str, Any], artifact_payload: Dict[str, Any]) -> Dict[str, str]:
    merged = _merged_report_payload(report_payload, artifact_payload)
    if merged.get("schema_version") == "session_assessment.v4":
        findings = [
            item for item in merged.get("behavioral_findings") or [] if isinstance(item, dict)
        ]
        hypothesis_sets = [
            item for item in merged.get("hypothesis_sets") or [] if isinstance(item, dict)
        ]
        return {
            "schema_version": "session_assessment.v4",
            "campaign_name": "",
            "confidence": "Unscored",
            "confidence_source": "no_global_scoring_in_v4",
            "analytical_evidence_strength": _text(merged.get("status") or ""),
            "evidence_strength_reason": (
                f"{len(findings)} canonical behavioral findings; "
                f"{len(hypothesis_sets)} falsifiable hypothesis sets"
            ),
            "ai_enriched": "false",
            "analysis_mode": "deterministic_session_assessment_v4",
            "post_session_follow_on_hypothesis": "; ".join(
                _text(hypothesis.get("statement"))
                for hypothesis_set in hypothesis_sets
                for hypothesis in hypothesis_set.get("hypotheses") or []
                if isinstance(hypothesis, dict) and _text(hypothesis.get("statement"))
            ),
            "summary": "; ".join(
                _text(item.get("statement")) for item in findings if _text(item.get("statement"))
            ) or "No policy-supported behavioral finding.",
        }
    assessment = merged.get("supported_assessment") or {}
    follow_on = merged.get("follow_on_hypothesis") or {}
    presentation = merged.get("presentation") or {}
    claim_summary = merged.get("claim_evidence_summary") or {}
    is_v2 = merged.get("schema_version") == "threat_hypothesis.v2"
    threat = merged.get("threat_hypothesis") or {}
    if not isinstance(threat, dict):
        threat = {}
    evidence_strength = threat.get("analytical_evidence_strength") or threat.get("analytical_confidence") or {}
    if not isinstance(evidence_strength, dict):
        evidence_strength = {}
    canonical_follow_on = "; ".join(
        _text(item.get("text"))
        for item in follow_on.get("claims") or []
        if isinstance(item, dict) and _text(item.get("text"))
    )
    return {
        "schema_version": _text(merged.get("schema_version") or "legacy"),
        "campaign_name": _text(merged.get("campaign_name") or merged.get("title") or ""),
        "confidence": "Unscored" if is_v2 else _text(merged.get("confidence") or ""),
        "confidence_source": _text(merged.get("confidence_source") or ""),
        "analytical_evidence_strength": _text(
            assessment.get("assessment_status")
            if is_v2 else evidence_strength.get("level") or ""
        ),
        "evidence_strength_reason": _text(
            claim_summary.get("description")
            if is_v2 else evidence_strength.get("reason") or ""
        ),
        "ai_enriched": _text(merged.get("ai_enriched") if "ai_enriched" in merged else ""),
        "analysis_mode": _text(merged.get("analysis_mode") or ""),
        "post_session_follow_on_hypothesis": _text(
            canonical_follow_on
            or follow_on.get("abstention_reason")
            or threat.get("post_session_follow_on_hypothesis")
            or merged.get("post_session_follow_on_hypothesis")
            or threat.get("predicted_next_action")
            or merged.get("predicted_next_action")
            or ""
        ),
        "summary": _text(
            presentation.get("summary")
            or assessment.get("behavior_summary")
            or merged.get("executive_summary")
            or merged.get("summary")
            or merged.get("threat_hypothesis")
            or merged.get("hypothesis")
            or ""
        ),
    }


def _render_ai_validation_warnings(report_payload: Dict[str, Any], artifact_payload: Dict[str, Any]) -> str:
    merged = _merged_report_payload(report_payload, artifact_payload)
    warnings = merged.get("ai_validation_warnings") or []
    presentation = merged.get("presentation") or {}
    vertex_validation = presentation.get("vertex_validation") if isinstance(presentation, dict) else {}
    if not warnings and isinstance(vertex_validation, dict) and vertex_validation.get("status") == "rejected":
        return (
            '<div class="warning-box"><strong>Vertex presentation rejected.</strong> '
            f'{_html(vertex_validation.get("reason") or "grounding validation failed")}. '
            'Deterministic canonical claims were retained unchanged.</div>'
        )
    if not isinstance(warnings, list) or not warnings:
        return '<div class="empty">No unsupported AI narrative claims were accepted.</div>'
    rows = []
    for warning in warnings[:20]:
        if not isinstance(warning, dict):
            continue
        dropped = (
            warning.get("dropped_unobserved_ips")
            or warning.get("dropped_unobserved_commands")
            or warning.get("dropped_completed_action_claims")
            or []
        )
        rows.append(
            "<tr><td>{field}</td><td>{reason}</td><td>{dropped}</td></tr>".format(
                field=_html(warning.get("field") or "-"),
                reason=_html(warning.get("reason") or "-"),
                dropped=_html(_short(", ".join(str(x) for x in dropped), 220)),
            )
        )
    if not rows:
        return '<div class="empty">AI validation warnings were present but could not be displayed.</div>'
    return (
        '<div class="warning-box">'
        '<strong>AI validation guardrail activated.</strong> These claims were removed or replaced with deterministic fallback text.'
        '</div>'
        '<table><thead><tr><th>field</th><th>reason</th><th>removed claim</th></tr></thead><tbody>'
        + "\n".join(rows)
        + "</tbody></table>"
    )


def _render_report_evidence_layers(report_payload: Dict[str, Any], artifact_payload: Dict[str, Any]) -> str:
    merged = _merged_report_payload(report_payload, artifact_payload)
    layers = merged.get("threat_evidence_layers") or {}
    if not isinstance(layers, dict):
        return '<div class="empty">Evidence layers are not available in this report yet.</div>'
    summary = layers.get("summary") or {}
    if not isinstance(summary, dict):
        summary = {}
    summary_html = "".join(
        f"<div class=\"kv\"><span>{_html(label)}</span><strong>{_html(value)}</strong></div>"
        for label, value in (
            ("direct command TTPs", summary.get("direct_command_ttp_count", 0)),
            ("audit-only classifier candidates", summary.get("audit_only_classification_count", 0)),
            ("session-correlated TTPs", summary.get("session_correlated_ttp_count", 0)),
            ("prediction hypotheses", summary.get("prediction_hypothesis_count", 0)),
        )
    )

    def _layer_items(name: str) -> List[Dict[str, Any]]:
        layer = layers.get(name) or {}
        if not isinstance(layer, dict):
            return []
        return [item for item in layer.get("items") or [] if isinstance(item, dict)]

    direct_rows = []
    for item in _layer_items("direct_command_ttps")[:12]:
        confidence = item.get("confidence") if isinstance(item.get("confidence"), dict) else {}
        direct_rows.append(
            "<tr><td>{ttp}</td><td>{tactic}</td><td>{source}</td><td>{conf}</td><td>{evidence}</td></tr>".format(
                ttp=_html(item.get("main_ttp") or "-"),
                tactic=_html(item.get("tactic") or "-"),
                source=_html(", ".join(item.get("sources") or []) or item.get("source_type") or "-"),
                conf=_html(confidence.get("average", "-")),
                evidence=_html(_short("; ".join(item.get("commands") or []), 140)),
            )
        )
    audit_rows = []
    for item in _layer_items("audit_only_classification_candidates")[:20]:
        audit_rows.append(
            "<tr><td><code>{command}</code></td><td>{ttp}</td><td>{tactic}</td><td>{source}</td><td>{conf}</td><td>{reason}</td></tr>".format(
                command=_html(_short(item.get("command") or "-", 120)),
                ttp=_html(item.get("candidate_ttp") or "-"),
                tactic=_html(item.get("candidate_tactic") or "-"),
                source=_html(item.get("source") or "-"),
                conf=_html(item.get("confidence", "-")),
                reason=_html(_short(item.get("reason") or "audit only", 180)),
            )
        )
    correlated_rows = []
    for item in _layer_items("session_correlated_ttps")[:12]:
        predicted = item.get("predicted_technique") if isinstance(item.get("predicted_technique"), dict) else {}
        evidence = item.get("evidence") or []
        correlated_rows.append(
            "<tr><td>{ttp}</td><td>{rule}</td><td>{stype}</td><td>{conf}</td><td>{evidence}</td></tr>".format(
                ttp=_html(item.get("main_ttp") or predicted.get("main_ttp") or "-"),
                rule=_html(item.get("rule_id") or item.get("correlation_rule_fired") or "-"),
                stype=_html(item.get("source_type") or "-"),
                conf=_html(item.get("confidence", "-")),
                evidence=_html(_short("; ".join(str(x) for x in evidence), 160)),
            )
        )
    prediction_rows = []
    for item in _layer_items("prediction_only_hypotheses")[:8]:
        prediction_rows.append(
            "<tr><td>{tactic}</td><td>{stype}</td><td>{conf}</td><td>{score}</td><td>{reason}</td></tr>".format(
                tactic=_html(item.get("predicted_tactic") or "-"),
                stype=_html(", ".join(item.get("source_types") or []) or item.get("source_type") or "-"),
                conf=_html(item.get("confidence") or "-"),
                score=_html(item.get("score", "-")),
                reason=_html(_short("; ".join(item.get("reasons") or []), 180)),
            )
        )
    parts = [
        "<p>Facts, session correlations, and forecasts are separated here so the report does not mix direct evidence with hypotheses.</p>",
        summary_html,
    ]
    if direct_rows:
        parts.append(
            "<h3>Direct Command TTPs</h3>"
            "<table><thead><tr><th>main_ttp</th><th>tactic</th><th>source</th><th>avg confidence</th><th>evidence</th></tr></thead><tbody>"
            + "\n".join(direct_rows)
            + "</tbody></table>"
        )
    if audit_rows:
        parts.append(
            "<h3>Audit-Only Classification Candidates</h3>"
            "<p>These weak candidates and shell-noise records are retained for review. They are excluded from observed ATT&CK facts, tactic sequences, predictions, and threat-hypothesis evidence.</p>"
            "<table><thead><tr><th>command</th><th>candidate TTP</th><th>candidate tactic</th><th>source</th><th>confidence</th><th>reason</th></tr></thead><tbody>"
            + "\n".join(audit_rows)
            + "</tbody></table>"
        )
    if correlated_rows:
        parts.append(
            "<h3>Session-Correlated TTPs</h3>"
            "<table><thead><tr><th>main_ttp</th><th>rule</th><th>source_type</th><th>confidence</th><th>evidence</th></tr></thead><tbody>"
            + "\n".join(correlated_rows)
            + "</tbody></table>"
        )
    if prediction_rows:
        parts.append(
            "<h3>Prediction-Only Hypotheses</h3>"
            "<table><thead><tr><th>predicted tactic</th><th>source_type</th><th>confidence</th><th>score</th><th>reason</th></tr></thead><tbody>"
            + "\n".join(prediction_rows)
            + "</tbody></table>"
        )
    return "\n".join(parts)


def _merged_report_payload(report_payload: Dict[str, Any], artifact_payload: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(report_payload or {})
    merged.update({k: v for k, v in (artifact_payload or {}).items() if v and not merged.get(k)})
    return merged


def _as_text_list(value: Any) -> List[str]:
    if value is None or value == "":
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [json.dumps(_sanitize_public(value), sort_keys=True)]
    if isinstance(value, list):
        output: List[str] = []
        for item in value:
            if isinstance(item, str):
                text = item.strip()
            elif isinstance(item, dict):
                text = (
                    item.get("action")
                    or item.get("recommendation")
                    or item.get("summary")
                    or item.get("description")
                    or json.dumps(_sanitize_public(item), sort_keys=True)
                )
                text = str(text).strip()
            else:
                text = str(item).strip()
            if text and text not in output:
                output.append(text)
        return output
    return [str(value)]


def _rule_based_operator_actions(session_payload: Dict[str, Any]) -> List[str]:
    commands = session_payload.get("commands") or []
    tactics = {str(t).lower() for t in session_payload.get("tactics") or [] if t}
    actions = []
    if not commands:
        return ["Keep the session for scan-volume tracking; no post-compromise analyst action is needed unless the source repeats or escalates."]
    if "credential-access" in tactics:
        actions.append("Review captured usernames and credential metadata; confirm raw passwords remain redacted and watch for repeated attempts against the same account.")
    if "command-and-control" in tactics:
        actions.append("Extract downloaded URLs, domains, and hashes from the session and add them to enrichment/watchlist review.")
    if "execution" in tactics:
        actions.append("Inspect downloaded or executed artifacts in an isolated malware-analysis workflow before allowing any sample handling outside the lab.")
    if "defense-evasion" in tactics:
        actions.append("Preserve raw Cowrie events and report artifacts before log-cleanup commands age out of short-term views.")
    if not actions:
        actions.append("Continue monitoring this source for download, persistence, credential, or cleanup commands before escalating.")
    return actions


def _report_recommendations(
    report_payload: Dict[str, Any],
    artifact_payload: Dict[str, Any],
    session_payload: Dict[str, Any],
) -> Dict[str, Any]:
    merged = _merged_report_payload(report_payload, artifact_payload)
    response_guidance = merged.get("response_guidance_v3") or {}
    if (
        not isinstance(response_guidance, dict)
        or response_guidance.get("schema_version") != "response_guidance.v3"
        or validate_response_guidance_v3(response_guidance)
    ):
        response_guidance = {}
    structured_actions = [
        item for item in response_guidance.get("advisory_actions") or []
        if isinstance(item, dict)
    ]
    canonical_recommendations = merged.get("recommendations") or {}
    context_notes = (
        _as_text_list(canonical_recommendations.get("context_notes"))
        if isinstance(canonical_recommendations, dict) else []
    )
    policy_authoritative = response_guidance.get("authority") == "deterministic_observed_evidence_policy"
    recommended_actions = [
        str(item.get("description") or "").strip()
        for item in structured_actions
        if str(item.get("description") or "").strip()
    ]
    hypothesis_alternatives = [
        _text(hypothesis.get("statement"))
        for hypothesis_set in merged.get("hypothesis_sets") or []
        if isinstance(hypothesis_set, dict)
        for hypothesis in hypothesis_set.get("hypotheses") or []
        if isinstance(hypothesis, dict) and _text(hypothesis.get("statement"))
    ]
    falsification = [
        _text(item)
        for hypothesis_set in merged.get("hypothesis_sets") or []
        if isinstance(hypothesis_set, dict)
        for hypothesis in hypothesis_set.get("hypotheses") or []
        if isinstance(hypothesis, dict)
        for item in hypothesis.get("falsification_conditions") or []
        if _text(item)
    ]
    source = response_guidance.get("authority") or "policy_unavailable"
    return {
        "source": source,
        "hypothesis_alternatives": hypothesis_alternatives,
        "recommended_actions": recommended_actions,
        "recommended_actions_structured": structured_actions,
        "response_guidance": copy.deepcopy(response_guidance),
        "policy_authoritative": policy_authoritative,
        "policy_action_count": len(structured_actions),
        "context_notes": context_notes,
        "falsification_conditions": falsification,
        "evidence_gaps": [],
        "external_validation_suggestions": [],
    }


def _historical_response_guidance_payload(report_payload: Any) -> Dict[str, Any]:
    """Return stored v3 guidance without recomputation.

    Old v1/v2 records are adapted as non-actionable, read-only historical
    evidence rather than being re-evaluated or promoted to v3 tasks.
    """

    if not isinstance(report_payload, dict):
        return {}
    stored = report_payload.get("response_guidance_v3")
    if isinstance(stored, dict) and stored.get("schema_version") == "response_guidance.v3":
        validation_errors = validate_response_guidance_v3(stored)
        if validation_errors:
            return {
                "schema_version": "response_guidance_legacy_adapter.v1",
                "status": "invalid_stored_guidance",
                "semantics": (
                    "Stored response guidance failed current whole-contract "
                    "validation and is non-actionable."
                ),
                "source_schema_version": "response_guidance.v3",
                "advisory_actions": [],
                "validation_error_count": len(validation_errors),
                "recomputed": False,
                "authoritative_for_new_actions": False,
            }
        guidance = copy.deepcopy(stored)
    else:
        legacy = report_payload.get("response_guidance_v2") or report_payload.get("trusted_recommendation_decision")
        if not isinstance(legacy, dict):
            return {}
        guidance = read_legacy_response_guidance(legacy)
    guidance["presentation_semantics"] = {
        "mode": "point_in_time_stored_decision",
        "historical_record": True,
        "replaces_stored_historical_guidance": False,
        "description": (
            "Stored with the historical report and displayed without current-policy recomputation."
        ),
    }
    return guidance


def _historical_decision_payload(report_payload: Any) -> Dict[str, Any]:
    """Compatibility reader for callers using the former helper name.

    It returns the same read-only v3/legacy-adapter payload and performs no
    decision evaluation.
    """

    return _historical_response_guidance_payload(report_payload)


def _summarize_session(
    row: Dict[str, Any],
    latest_jobs: Dict[str, Dict[str, Any]],
    latest_reports: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    payload = _session_payload(row)
    session_id = _text(payload.get("session_id") or row.get("session_id") or "unknown")
    commands = payload.get("commands") or []
    tactics = payload.get("tactics") or []
    latest_job = latest_jobs.get(session_id, {})
    latest_report = latest_reports.get(session_id, {})
    analysis_status = _text(latest_job.get("status") or payload.get("analysis_status") or "")
    src_ip = _text(payload.get("src_ip") or row.get("src_ip") or "unknown")
    scope = _ip_scope(src_ip)
    geo_context = _public_geo_context(payload, src_ip)
    geo = _extract_geo(payload) if scope["is_public"] else {}
    if not geo and geo_context:
        geo = _geo_from_context(geo_context)
    return {
        "session_id": session_id,
        "updated_at": _text(row.get("updated_at") or payload.get("updated_at")),
        "sensor": _text(payload.get("sensor") or payload.get("sensor_id") or ""),
        "src_ip": src_ip,
        "src_ip_is_public": scope["is_public"],
        "src_ip_scope": scope["scope"],
        "geo": geo,
        "source_geo": geo,
        "geo_context": geo_context,
        "source_geo_context": geo_context,
        "command_count": len(commands),
        "tactics": tactics,
        "analysis_status": analysis_status or _text(payload.get("status") or ""),
        "analysis_skip_reason": _text(payload.get("analysis_skip_reason") or ""),
        "job_status": _text(latest_job.get("status") or ""),
        "job_error": _text(latest_job.get("error") or ""),
        "report_id": _text(latest_job.get("report_id") or latest_report.get("report_id") or ""),
        "payload": payload,
        "job": latest_job,
        "report_row": latest_report,
    }


def _session_overview(session: Dict[str, Any]) -> Dict[str, Any]:
    payload = session.get("payload") or {}
    src_ip = payload.get("src_ip") or session.get("src_ip") or "unknown"
    scope = _ip_scope(src_ip)
    geo_context = session.get("geo_context") or _public_geo_context(payload, src_ip)
    geo = (session.get("geo") or _extract_geo(payload)) if scope["is_public"] else {}
    if not geo and geo_context:
        geo = _geo_from_context(geo_context)
    return {
        "session_id": session.get("session_id") or payload.get("session_id") or "unknown",
        "sensor": payload.get("sensor") or payload.get("sensor_id") or session.get("sensor") or "",
        "src_ip": src_ip,
        "src_ip_is_public": scope["is_public"],
        "src_ip_scope": scope["scope"],
        "geo": geo,
        "source_geo": geo,
        "geo_context": geo_context,
        "source_geo_context": geo_context,
        "src_port": payload.get("src_port") or "",
        "dst_ip": payload.get("dst_ip") or "",
        "dst_port": payload.get("dst_port") or "",
        "protocol": payload.get("protocol") or "ssh",
        "start_time": payload.get("start_time") or "",
        "updated_at": session.get("updated_at") or "",
        "duration": payload.get("duration") or "",
        "login_username": payload.get("login_username") or "",
        "login_success": payload.get("login_success"),
        "client_version": payload.get("client_version") or "",
        "hassh": payload.get("hassh") or "",
        "ja3": payload.get("ja3") or "",
        "command_count": len(payload.get("commands") or []),
        "commands": payload.get("commands") or [],
        "tactics": payload.get("tactics") or [],
        "ttps": payload.get("ttps") or [],
        "analysis_status": session.get("analysis_status") or "",
        "analysis_skip_reason": payload.get("analysis_skip_reason") or "",
        "job_status": session.get("job_status") or "",
        "report_id": session.get("report_id") or "",
    }


def _session_observables(payload: Dict[str, Any], session_id: str) -> List[Tuple[str, str]]:
    observables: List[Tuple[str, str]] = []

    def add(observable_type: str, value: Any) -> None:
        text = str(value or "").strip()
        if text:
            marker = (observable_type, text)
            if marker not in observables:
                observables.append(marker)

    add("ip", payload.get("src_ip"))
    for event in payload.get("raw_events") or []:
        if isinstance(event, dict):
            add("ip", event.get("src_ip"))
            add("hassh", event.get("hassh"))
            add("ja3", event.get("ja3"))
    add("hassh", payload.get("hassh"))
    add("ja3", payload.get("ja3"))

    ioc_summary = payload.get("ioc_summary") or {}
    for item in ioc_summary.get("ips") or []:
        if isinstance(item, dict):
            add("ip", item.get("value"))
    for item in ioc_summary.get("domains") or []:
        if isinstance(item, dict):
            add("domain", item.get("value"))
    for item in ioc_summary.get("urls") or []:
        if isinstance(item, dict):
            add("url", item.get("value"))
    for item in ioc_summary.get("hashes") or []:
        if isinstance(item, dict):
            add("hash", item.get("value"))
    return observables


def load_session_detail(
    config: MonitorConfig,
    session_id: str,
    *,
    _storage: Any = None,
) -> Dict[str, Any]:
    if not session_id:
        return {"ok": False, "error": "session_id is required", "timestamp": utc_now()}
    try:
        storage = _storage or _open_monitor_storage(config)
    except Exception as exc:
        return {
            "ok": False,
            "error": _storage_error("storage open", exc),
            "session_id": session_id,
            "timestamp": utc_now(),
        }

    session_rows, session_error = _storage_session_rows(
        storage,
        "sessions",
        session_id,
        1,
    )
    payload_for_observables = _session_payload(session_rows[0]) if session_rows else {}
    observables = _session_observables(payload_for_observables, session_id)
    job_rows, jobs_error = _storage_session_rows(
        storage,
        "analysis_jobs",
        session_id,
        50,
    )
    report_rows, reports_error = _storage_session_rows(
        storage,
        "reports",
        session_id,
        50,
    )
    event_rows, events_error = _storage_session_rows(
        storage,
        "events",
        session_id,
        MAX_SESSION_EVENTS,
    )
    alert_rows, alerts_error = _storage_session_rows(
        storage,
        "alerts",
        session_id,
        50,
    )
    prediction_rows, predictions_error = _storage_session_rows(
        storage,
        "prediction_snapshots",
        session_id,
        50,
    )
    feedback_rows, feedback_error = _storage_session_rows(
        storage,
        "analyst_feedback",
        session_id,
        50,
    )
    (
        sighting_rows,
        related_sighting_rows,
        sightings_error,
    ) = _storage_observable_sightings(storage, session_id, observables)
    (
        session_link_rows,
        threat_hunt_job_rows,
        threat_hunt_error,
    ) = _storage_session_links_and_jobs(storage, session_id)
    (
        campaign_membership_rows,
        campaign_rows,
        campaigns_error,
    ) = _storage_campaign_rows(storage, session_id)
    (
        enrichment_record_rows,
        enrichment_job_rows,
        enrichment_error,
    ) = _storage_enrichment_rows(storage, session_id, observables)

    if not session_rows:
        return {
            "ok": False,
            "error": session_error or f"session not found: {session_id}",
            "session_id": session_id,
            "timestamp": utc_now(),
        }

    latest_jobs = _index_by_latest(job_rows, "session_id", "updated_at")
    latest_reports = _index_by_latest(report_rows, "session_id", "created_at")
    selected = _summarize_session(session_rows[0], latest_jobs, latest_reports)
    payload = selected["payload"]
    decoded_enrichment_records = [_row_with_payload(row) for row in enrichment_record_rows]
    src_ip = payload.get("src_ip") or selected.get("src_ip")
    enrichment_contexts = [
        row.get("geo_context")
        for row in decoded_enrichment_records
        if row.get("observable_type") == "ip"
        and str(row.get("observable_value") or "").strip() == str(src_ip or "").strip()
    ]
    source_geo_context = _merge_geo_contexts(selected.get("geo_context") or {}, *enrichment_contexts)
    if source_geo_context:
        selected["geo_context"] = source_geo_context
        selected["source_geo_context"] = source_geo_context
        if not selected.get("geo"):
            selected_geo = _geo_from_context(source_geo_context)
            if selected_geo:
                selected["geo"] = selected_geo
                selected["source_geo"] = selected_geo
    report_payload = _report_payload(selected.get("report_row"))
    artifact_paths = _artifact_paths(report_payload, config.reports_dir)
    artifact_payload = _load_report_json_from_artifact(artifact_paths, config.reports_dir)
    latest_prediction = _row_with_payload(prediction_rows[0]) if prediction_rows else {}
    report_recommendations = _report_recommendations(report_payload, artifact_payload, payload)
    current_policy_reevaluation: Dict[str, Any] = {}
    if config.enable_response_guidance:
        current_policy_reevaluation = _current_decision_payload(
            config,
            storage,
            session_id,
            latest_prediction,
            report_recommendations=report_recommendations,
        )
    historical_response_guidance = _historical_response_guidance_payload(
        _merged_report_payload(report_payload, artifact_payload)
    )
    primary_response_guidance = historical_response_guidance or current_policy_reevaluation
    detail = {
        "ok": True,
        "timestamp": utc_now(),
        "session_id": session_id,
        "overview": _session_overview(selected),
        "source_geo": selected.get("geo") or (_extract_geo(payload) if selected.get("src_ip_is_public") else {}),
        "source_geo_context": selected.get("source_geo_context") or selected.get("geo_context") or {},
        "observables": [{"type": t, "value": v} for t, v in _session_observables(payload, session_id)],
        "commands": payload.get("commands") or [],
        "classification_events": payload.get("classification_events") or [],
        "session_ttp_correlations": payload.get("session_ttp_correlations") or [],
        "session_ttp_correlation_summary": payload.get("session_ttp_correlation_summary") or {},
        "tactics": payload.get("tactics") or [],
        "ttps": payload.get("ttps") or [],
        "ttp_command_map": payload.get("ttp_command_map") or {},
        "enrichment_status": payload.get("enrichment_status") or {},
        "credential_metadata": payload.get("credential_metadata") or {},
        "session_payload": payload,
        "raw_events_from_session_payload": payload.get("raw_events") or [],
        "events_table_rows": [_row_with_payload(row) for row in event_rows],
        "alerts": [_row_with_payload(row) for row in alert_rows],
        "prediction_snapshots": [_row_with_payload(row) for row in prediction_rows],
        "latest_prediction_snapshot": latest_prediction,
        "analyst_feedback": [_row_with_payload(row) for row in feedback_rows],
        "observable_sightings": [_row_with_payload(row) for row in sighting_rows],
        "related_observable_sightings": [_row_with_payload(row) for row in related_sighting_rows],
        "session_links": [_row_with_payload(row) for row in session_link_rows],
        "threat_hunt_jobs": [_row_with_payload(row) for row in threat_hunt_job_rows],
        "campaign_memberships": [_row_with_payload(row) for row in campaign_membership_rows],
        "campaigns": [_row_with_payload(row) for row in campaign_rows],
        "enrichment_records": decoded_enrichment_records,
        "enrichment_jobs": [_row_with_payload(row) for row in enrichment_job_rows],
        "analysis_jobs": [_row_with_payload(row) for row in job_rows],
        "reports": [_row_with_payload(row) for row in report_rows],
        "report_summary": _report_summary(report_payload, artifact_payload),
        "report_recommendations": report_recommendations,
        "response_guidance": primary_response_guidance,
        "historical_response_guidance": historical_response_guidance,
        "current_policy_reevaluation": current_policy_reevaluation,
        "response_guidance_semantics": {
            "primary": (
                "point_in_time_stored_guidance"
                if historical_response_guidance
                else "current_policy_reevaluation"
            ),
            "historical_available": bool(historical_response_guidance),
            "current_reevaluation_available": bool(current_policy_reevaluation),
            "current_reevaluation_replaces_historical": False,
        },
        "report_artifacts": artifact_paths,
        "errors": {
            "jobs": jobs_error,
            "reports": reports_error,
            "events": events_error,
            "alerts": alerts_error,
            "predictions": predictions_error,
            "analyst_feedback": feedback_error,
            "observable_sightings": sightings_error,
            "threat_hunting": threat_hunt_error,
            "campaigns": campaigns_error,
            "enrichment": enrichment_error,
        },
    }
    return _sanitize_public(detail)


def load_snapshot(
    config: MonitorConfig,
    selected_session_id: str = "",
    session_limit: int = DEFAULT_SESSION_LIMIT,
    session_offset: int = 0,
) -> Dict[str, Any]:
    try:
        storage = _open_monitor_storage(config)
    except Exception as exc:
        return {
            "ok": False,
            "error": _storage_error("storage open", exc),
            "sessions": [],
            "selected": None,
            "events": [],
            "events_error": "events table not available",
            "summary": {},
            "timestamp": utc_now(),
        }

    session_limit = min(max(int(session_limit), 1), MAX_SESSIONS)
    session_offset = max(int(session_offset), 0)
    try:
        all_session_rows = [
            dict(row)
            for row in storage.list_session_rows(
                limit=max(
                    MONITOR_SUMMARY_SCAN_LIMIT,
                    session_offset + session_limit,
                ),
                session_source=None,
                external_only=False,
            )
            or []
        ]
        sessions_error = ""
    except Exception as exc:
        all_session_rows = []
        sessions_error = _storage_error("sessions query", exc)
    session_rows = all_session_rows[
        session_offset : session_offset + session_limit
    ]
    all_job_rows, _jobs_error = _storage_list_rows(
        storage,
        "analysis_jobs",
        MONITOR_SUMMARY_SCAN_LIMIT,
    )
    job_rows = all_job_rows[:500]
    all_report_rows, _reports_error = _storage_list_rows(
        storage,
        "reports",
        MONITOR_SUMMARY_SCAN_LIMIT,
    )
    report_rows = all_report_rows[:500]
    event_rows, events_error = _storage_list_rows(
        storage,
        "events",
        MAX_EVENTS,
    )
    backtest_rows, backtests_error = _storage_list_rows(
        storage,
        "prediction_backtest_runs",
        10,
    )
    calibration_rows, calibration_error = _storage_list_rows(
        storage,
        "prediction_calibration_runs",
        10,
    )
    feedback_rows, feedback_error = _storage_list_rows(
        storage,
        "analyst_feedback",
        500,
    )
    (
        classification_review_rows,
        classification_review_error,
    ) = _storage_list_rows(
        storage,
        "classification_review_labels",
        500,
    )
    public_ips = _public_ips_from_rows(session_rows, _session_payload)
    for ip in _public_ips_from_rows(event_rows, _event_payload):
        if ip not in public_ips:
            public_ips.append(ip)
    (
        ip_geo_contexts,
        ip_geo_context_error,
    ) = _storage_ip_enrichment_contexts(storage, public_ips)
    total_sessions = len(all_session_rows)
    succeeded_reports = len(all_report_rows)
    queued_jobs = sum(
        1
        for row in all_job_rows
        if _text(row.get("status")).lower() in {"queued", "running", "retry"}
    )

    latest_jobs = _index_by_latest(job_rows, "session_id", "updated_at")
    latest_reports = _index_by_latest(report_rows, "session_id", "created_at")
    sessions = [_summarize_session(row, latest_jobs, latest_reports) for row in session_rows]

    skipped_no_commands = sum(
        1
        for item in sessions
        if item["payload"].get("analysis_skip_reason") == "no_commands"
        or item["analysis_status"] == "skipped"
    )
    active_sessions = sum(1 for item in sessions if not bool(item["payload"].get("is_ended")))
    latest_updated = max([item["updated_at"] for item in sessions if item["updated_at"]] or [""])

    events = []
    session_geo_by_id: Dict[str, Dict[str, Any]] = {}
    session_geo_context_by_id: Dict[str, Dict[str, Any]] = {}
    for row in event_rows:
        payload = _event_payload(row)
        session_ref = _text(row.get("session_id") or payload.get("session"))
        src_ip = _text(row.get("src_ip") or payload.get("src_ip"))
        scope = _ip_scope(src_ip)
        geo_context = _merge_geo_contexts(
            _public_geo_context(payload, src_ip),
            ip_geo_contexts.get(src_ip, {}),
        ) if scope["is_public"] else {}
        geo = _extract_geo(payload) if scope["is_public"] else {}
        if not geo and geo_context:
            geo = _geo_from_context(geo_context)
        if session_ref and geo and session_ref not in session_geo_by_id:
            session_geo_by_id[session_ref] = geo
        if session_ref and geo_context and session_ref not in session_geo_context_by_id:
            session_geo_context_by_id[session_ref] = geo_context
        events.append(
            {
                "timestamp": _text(payload.get("timestamp") or row.get("timestamp")),
                "sensor": _text(payload.get("sensor") or payload.get("sensor_id") or row.get("sensor_id")),
                "session": session_ref,
                "src_ip": src_ip,
                "src_ip_is_public": scope["is_public"],
                "src_ip_scope": scope["scope"],
                "eventid": _text(row.get("eventid") or payload.get("eventid")),
                "detail": _text(payload.get("input") or payload.get("username") or ""),
                "geo": geo,
                "geo_context": geo_context,
            }
        )

    for item in sessions:
        src_ip = item.get("src_ip") or ""
        session_id = item.get("session_id", "")
        geo_context = _merge_geo_contexts(
            item.get("geo_context") or {},
            ip_geo_contexts.get(src_ip, {}),
            session_geo_context_by_id.get(session_id, {}),
        )
        geo = session_geo_by_id.get(session_id) or _geo_from_context(geo_context)
        if geo and not item.get("geo"):
            item["geo"] = geo
            item["source_geo"] = geo
        if geo_context:
            item["geo_context"] = geo_context
            item["source_geo_context"] = geo_context

    sessions_by_id = {item["session_id"]: item for item in sessions}
    selected = None
    if selected_session_id:
        selected = sessions_by_id.get(selected_session_id)
    if not selected:
        for event in events:
            selected = sessions_by_id.get(event.get("session", ""))
            if selected:
                break
    if not selected and sessions:
        selected = sessions[0]
    selected_detail = (
        load_session_detail(
            config,
            selected["session_id"],
            _storage=storage,
        )
        if selected
        else {}
    )
    feedback_decoded = [_row_with_payload(row) for row in feedback_rows]
    feedback_review = build_feedback_review(feedback_decoded)

    return {
        "ok": True,
        "error": sessions_error,
        "sessions": sessions,
        "selected": selected,
        "selected_detail": selected_detail,
        "events": events,
        "events_error": events_error,
        "evidence": {
            "backtest": _summarize_backtest_rows([_row_with_payload(row) for row in backtest_rows]),
            "calibration": _summarize_calibration_rows([_row_with_payload(row) for row in calibration_rows]),
            "external_seed_health": _load_external_seed_health(config),
            "feedback": _summarize_feedback_rows(feedback_decoded),
            "feedback_review": feedback_review,
            "feedback_rows": feedback_decoded[:200],
            "classification_review": _summarize_classification_review_rows([_row_with_payload(row) for row in classification_review_rows]),
            "errors": {
                "backtests": backtests_error,
                "calibration": calibration_error,
                "feedback": feedback_error,
                "classification_review": classification_review_error,
                "geo_context": ip_geo_context_error,
            },
        },
        "summary": {
            "total_sessions": total_sessions,
            "shown_sessions": len(sessions),
            "session_limit": session_limit,
            "session_offset": session_offset,
            "active_sessions": active_sessions,
            "queued_jobs": queued_jobs,
            "succeeded_reports": succeeded_reports,
            "skipped_no_command_sessions": skipped_no_commands,
            "latest_updated": latest_updated or "-",
        },
        "timestamp": utc_now(),
    }


def _badge(value: str) -> str:
    normalized = value.lower()
    class_name = "muted"
    if normalized in {"succeeded", "queued"}:
        class_name = normalized
    elif normalized in {"running", "retry"}:
        class_name = "running"
    elif normalized in {"failed", "error"}:
        class_name = "failed"
    elif normalized == "skipped":
        class_name = "skipped"
    elif normalized in {"high", "medium", "low"}:
        class_name = normalized
    return f'<span class="badge {class_name}">{_html(value or "-")}</span>'


def _render_summary(summary: Dict[str, Any]) -> str:
    cards = [
        ("Total sessions", summary.get("total_sessions", 0)),
        ("Active sessions", summary.get("active_sessions", 0)),
        ("Queued/running jobs", summary.get("queued_jobs", 0)),
        ("Succeeded reports", summary.get("succeeded_reports", 0)),
        ("Skipped no-command", summary.get("skipped_no_command_sessions", 0)),
        ("Latest updated", summary.get("latest_updated", "-")),
    ]
    return "\n".join(
        f'<div class="metric"><div class="metric-label">{_html(label)}</div><div class="metric-value">{_html(value)}</div></div>'
        for label, value in cards
    )


def _render_latest_activity(snapshot: Dict[str, Any]) -> str:
    events = snapshot.get("events", [])
    sessions = {item["session_id"]: item for item in snapshot.get("sessions", [])}
    if not events:
        return '<div class="empty">No recent events yet.</div>'

    latest = events[0]
    session_id = _text(latest.get("session") or "unknown")
    session = sessions.get(session_id)
    if session:
        status = session.get("analysis_status") or session.get("job_status") or "-"
        tactics = _format_list(session.get("tactics") or [], limit=6)
        report = session.get("report_id") or "-"
        found = "yes"
        command_count = session.get("command_count", 0)
        hint = "This latest event is already represented in Recent Sessions."
    else:
        status = "pending"
        tactics = "-"
        report = "-"
        found = "not yet"
        command_count = "-"
        hint = "The event is visible, but the session row has not been built yet. Wait for session_worker."

    rows = [
        ("latest event session", session_id),
        ("in Recent Sessions", found),
        ("sensor", latest.get("sensor") or "-"),
        ("source IP", latest.get("src_ip") or "-"),
        ("latest event", latest.get("eventid") or "-"),
        ("latest input/user", latest.get("detail") or "-"),
        ("command count", command_count),
        ("tactics", tactics),
        ("pipeline status", status),
        ("report id", report),
    ]
    return (
        '<div class="activity">'
        + "\n".join(
            f'<div class="kv"><span>{_html(label)}</span><strong>{_html(value)}</strong></div>'
            for label, value in rows
        )
        + f'<p class="hint">{_html(hint)}</p>'
        + "</div>"
    )


def _render_prediction_evidence(snapshot: Dict[str, Any]) -> str:
    evidence = snapshot.get("evidence") or {}
    backtest = evidence.get("backtest") or {}
    calibration = evidence.get("calibration") or {}
    feedback = evidence.get("feedback") or {}
    classification = evidence.get("classification_review") or {}
    errors = evidence.get("errors") or {}
    cards = [
        ("latest backtest", backtest.get("generated_at") or "-"),
        ("backtest cases", backtest.get("total_cases", 0)),
        ("top-1 / top-3", f"{backtest.get('top1_accuracy', 0)} / {backtest.get('top3_accuracy', 0)}"),
        ("MRR", backtest.get("mrr", 0)),
        ("disagreement rate", backtest.get("disagreement_rate", 0)),
        ("calibration buckets", f"L:{backtest.get('low_bucket_cases', 0)} M:{backtest.get('medium_bucket_cases', 0)} H:{backtest.get('high_bucket_cases', 0)}"),
        ("weight calibration", calibration.get("status") or "missing"),
        ("calibration feedback cases", f"{calibration.get('feedback_cases', 0)}/{calibration.get('min_feedback_rows', 0)}"),
        ("calibration backtest cases", f"{calibration.get('backtest_cases', 0)}/{calibration.get('min_backtest_cases', 0)}"),
        ("feedback records", feedback.get("count", 0)),
        ("high-conf wrong", feedback.get("high_confidence_wrong", 0)),
        ("low-conf useful", feedback.get("low_confidence_useful", 0)),
        ("classification reviews", classification.get("reviewed_cases", 0)),
        ("classification tactic accuracy", classification.get("tactic_accuracy", 0)),
        ("classification TTP accuracy", classification.get("ttp_accuracy", 0)),
    ]
    labels = feedback.get("labels") or {}
    source_counts = classification.get("source_counts") or {}
    warnings = []
    if errors.get("backtests"):
        warnings.append(errors["backtests"])
    if errors.get("calibration"):
        warnings.append(errors["calibration"])
    if errors.get("feedback"):
        warnings.append(errors["feedback"])
    if errors.get("classification_review"):
        warnings.append(errors["classification_review"])
    if not classification.get("reviewed_cases"):
        warnings.append("Classification validation baseline is still missing; export and review command labels before trusting classifier accuracy.")
    if int(backtest.get("total_cases") or 0) < 200:
        warnings.append("Backtest sample size is below the default calibration threshold of 200 completed prediction cases.")
    if calibration.get("status") not in {"applied"}:
        reason = calibration.get("reason") or "weight calibration has not produced an applied overlay yet."
        warnings.append(f"Prediction weight calibration is not active: {reason}")
    warning_html = "".join(f'<div class="warning">{_html(item)}</div>' for item in warnings)
    detail_html = (
        '<div class="overview-grid">'
        + "\n".join(
            f'<div class="kv"><span>{_html(label)}</span><strong>{_html(value)}</strong></div>'
            for label, value in cards
        )
        + f'<div class="kv"><span>feedback labels</span><strong>{_html(_format_list([f"{k}:{v}" for k, v in labels.items()], limit=8))}</strong></div>'
        + f'<div class="kv"><span>classifier sources</span><strong>{_html(_format_list([f"{k}:{v}" for k, v in source_counts.items()], limit=8))}</strong></div>'
        + f'<div class="kv"><span>weight changes</span><strong>{_html(_format_list(calibration.get("changed_weights") or [], limit=8))}</strong></div>'
        + "</div>"
    )
    return warning_html + detail_html


def _render_external_seed_health(snapshot: Dict[str, Any]) -> str:
    health = ((snapshot.get("evidence") or {}).get("external_seed_health") or {})
    if not health:
        return '<div class="empty">External seed health is not available.</div>'

    model = health.get("model") or {}
    quality = health.get("classification_quality") or {}
    validation = health.get("validation") or {}
    review = health.get("review_queue") or {}
    warnings = health.get("warnings") or []
    cards = [
        ("model_id", model.get("model_id") or "-"),
        ("source", model.get("dataset_handle") or model.get("source_type") or "-"),
        ("securebert_used", model.get("securebert_used")),
        ("usable_sessions", model.get("usable_sessions", 0)),
        ("transitions", model.get("transition_count", 0)),
        ("accepted_commands", quality.get("accepted_command_events", 0)),
        ("accepted_labels", quality.get("accepted_classification_events", 0)),
        ("unused_commands", quality.get("unused_command_events", 0)),
        ("acceptance_rate", quality.get("acceptance_rate", 0)),
        ("low_confidence_skipped", quality.get("low_confidence_commands_skipped", 0)),
        ("shell_noise_skipped", quality.get("noise_commands_skipped", 0)),
        ("disagreement_skipped", quality.get("disagreement_commands_skipped", 0)),
        ("validation_cases", validation.get("total_cases", 0)),
        ("top1/top3", f"{validation.get('top1_accuracy', 0)} / {validation.get('top3_accuracy', 0)}"),
        ("MRR", validation.get("mean_reciprocal_rank", 0)),
        ("review_queue", review.get("review_count", 0)),
    ]
    warning_html = "".join(f'<div class="warning">{_html(item)}</div>' for item in warnings)
    card_html = (
        '<div class="overview-grid">'
        + "\n".join(
            f'<div class="kv"><span>{_html(label)}</span><strong>{_html(value)}</strong></div>'
            for label, value in cards
        )
        + f'<div class="kv"><span>source mix</span><strong>{_html(_format_list([f"{k}:{v}" for k, v in (quality.get("source_counts") or {}).items()], limit=10))}</strong></div>'
        + "</div>"
    )

    tactic_rows = []
    for tactic, metrics in sorted((validation.get("accuracy_by_tactic") or {}).items()):
        if not isinstance(metrics, dict):
            continue
        tactic_rows.append(
            "<tr>"
            f"<td>{_html(tactic)}</td>"
            f"<td class=\"num\">{_html(metrics.get('cases', 0))}</td>"
            f"<td class=\"num\">{_html(metrics.get('top1_accuracy', 0))}</td>"
            f"<td class=\"num\">{_html(metrics.get('top3_accuracy', 0))}</td>"
            f"<td class=\"num\">{_html(metrics.get('mean_reciprocal_rank', 0))}</td>"
            "</tr>"
        )
    tactic_table = ""
    if tactic_rows:
        tactic_table = (
            "<h3>External Seed Holdout Accuracy By Tactic</h3>"
            "<table><thead><tr><th>tactic</th><th>cases</th><th>top1</th><th>top3</th><th>MRR</th></tr></thead><tbody>"
            + "\n".join(tactic_rows)
            + "</tbody></table>"
        )

    reason_rows = []
    for reason, count in sorted((review.get("reason_counts") or {}).items()):
        examples = (review.get("top_commands_by_reason") or {}).get(reason) or []
        example_text = _format_list(
            [f"{item.get('value')} ({item.get('count')})" for item in examples if isinstance(item, dict)],
            limit=5,
        )
        reason_rows.append(
            "<tr>"
            f"<td>{_html(reason)}</td>"
            f"<td class=\"num\">{_html(count)}</td>"
            f"<td>{_html(example_text)}</td>"
            "</tr>"
        )
    review_table = ""
    if reason_rows:
        review_table = (
            "<h3>Skipped Command Review Queue</h3>"
            "<table><thead><tr><th>reason</th><th>count</th><th>common examples</th></tr></thead><tbody>"
            + "\n".join(reason_rows)
            + "</tbody></table>"
        )

    hint = (
        '<p class="hint">External seed evidence is a cold-start prior. It is kept separate from local honeypot history; '
        "high top-3 validation means it can suggest candidates, but low accepted-command coverage means it should not be treated as ground truth.</p>"
    )
    return warning_html + card_html + tactic_table + review_table + hint


def _feedback_value(row: Dict[str, Any], key: str) -> Any:
    value = row.get(key)
    if value not in (None, ""):
        return value
    payload = _payload_from_row(row)
    return payload.get(key)


def _feedback_top(row: Dict[str, Any]) -> Dict[str, Any]:
    ranking_raw = _feedback_value(row, "predicted_ranking") or []
    ranking = _json_loads(ranking_raw, []) if isinstance(ranking_raw, str) else ranking_raw
    if isinstance(ranking, list) and ranking and isinstance(ranking[0], dict):
        return ranking[0]
    return {}


def _feedback_diagnostic_categories(row: Dict[str, Any]) -> List[str]:
    label = str(_feedback_value(row, "label") or "")
    top = _feedback_top(row)
    confidence = str(top.get("confidence") or "")
    try:
        score = float(top.get("score") or 0.0)
    except (TypeError, ValueError):
        score = 0.0
    predicted = str(_feedback_value(row, "predicted_top_tactic") or "")
    actual = str(_feedback_value(row, "final_actual_next_tactic") or _feedback_value(row, "correct_next_tactic") or "")
    source_types = set(top.get("source_types") or [])
    source_names = set()
    for source in top.get("sources") or []:
        if not isinstance(source, dict):
            continue
        if source.get("name"):
            source_names.add(str(source["name"]))
        if source.get("source_type"):
            source_types.add(str(source["source_type"]))
    categories: List[str] = []
    if not actual:
        categories.append("missing_actual_next_tactic")
    if label in {"wrong", "not_useful", "false_positive"}:
        if predicted and actual and predicted != actual:
            categories.append("prediction_mismatch")
        if confidence == "high" or score >= 0.70:
            categories.append("calibration_or_weighting_review")
        if "local_transition" not in source_names and "empirical_local" not in source_types:
            categories.append("missing_local_transition_evidence")
        if source_types.intersection({"heuristic_prior", "human_curated_attck_prior", "detection_correlation"}):
            categories.append("policy_rule_review")
    if label in {"useful", "correct"} and (confidence == "low" or score < 0.40):
        categories.append("useful_low_confidence_case")
    return sorted(set(categories))


def _render_feedback_review_panel(snapshot: Dict[str, Any], selected_session_id: str, feedback_filter: str) -> str:
    evidence = snapshot.get("evidence") or {}
    review = evidence.get("feedback_review") or {}
    rows = evidence.get("feedback_rows") or []
    errors = evidence.get("errors") or {}
    normalized_filter = str(feedback_filter or "all").strip().lower()
    if normalized_filter not in FEEDBACK_FILTERS:
        normalized_filter = "all"
    filtered_rows = filter_feedback_rows(rows, normalized_filter)[:25]
    counts = review.get("filter_counts") or {}
    filter_labels = [
        ("all", "All"),
        ("wrong", "Wrong"),
        ("useful", "Useful"),
        ("high_confidence_wrong", "High-conf wrong"),
        ("low_confidence_useful", "Low-conf useful"),
        ("missing_actual", "Missing actual"),
        ("classification_error", "Classification error"),
        ("missing_transition_evidence", "No local evidence"),
        ("policy_review", "Policy review"),
        ("needs_review", "Needs review"),
    ]
    chips = []
    for name, label in filter_labels:
        params = {"feedback_filter": name}
        if selected_session_id:
            params["session_id"] = selected_session_id
        active = " active" if name == normalized_filter else ""
        chips.append(
            f'<a class="filter-chip{active}" href="/?{urlencode(params)}">{_html(label)} '
            f'<span>{_html(counts.get(name, 0))}</span></a>'
        )

    if errors.get("feedback"):
        table_html = f'<div class="empty">{_html(errors["feedback"])}</div>'
    elif filtered_rows:
        rendered_rows = []
        for row in filtered_rows:
            top = _feedback_top(row)
            source_types = top.get("source_types") or []
            if not source_types and isinstance(top.get("sources"), list):
                source_types = sorted(
                    {
                        str(source.get("source_type") or "")
                        for source in top["sources"]
                        if isinstance(source, dict) and source.get("source_type")
                    }
                )
            categories = _feedback_diagnostic_categories(row)
            rendered_rows.append(
                "<tr>"
                f"<td>{_html(_short(_feedback_value(row, 'created_at') or '-', 32))}</td>"
                f"<td><a href=\"/?{urlencode({'session_id': _feedback_value(row, 'session_id') or ''})}\">{_html(_feedback_value(row, 'session_id') or '-')}</a></td>"
                f"<td>{_html(_feedback_value(row, 'label') or '-')}</td>"
                f"<td>{_html(_feedback_value(row, 'predicted_top_tactic') or '-')}</td>"
                f"<td>{_html(_feedback_value(row, 'final_actual_next_tactic') or _feedback_value(row, 'correct_next_tactic') or '-')}</td>"
                f"<td>{_html(top.get('confidence') or '-')}</td>"
                f"<td>{_html(_format_list(source_types, limit=5))}</td>"
                f"<td>{_html(_format_list(categories, limit=5))}</td>"
                f"<td>{_html(_short(_feedback_value(row, 'notes') or '', 120))}</td>"
                "</tr>"
            )
        table_html = (
            "<table><thead><tr><th>created_at</th><th>session</th><th>label</th><th>predicted</th>"
            "<th>actual/corrected</th><th>confidence</th><th>source types</th><th>diagnostic</th><th>notes</th></tr></thead><tbody>"
            + "\n".join(rendered_rows)
            + "</tbody></table>"
        )
    else:
        table_html = '<div class="empty">No feedback rows match this filter yet.</div>'

    weak_sources = review.get("weak_scorer_sources") or {}
    weak_types = review.get("weak_source_types") or {}
    categories = review.get("failure_categories") or {}
    recommendations = review.get("recommendations") or []
    diagnostics = (
        '<div class="overview-grid">'
        f'<div class="kv"><span>failure categories</span><strong>{_html(_format_list([f"{k}:{v}" for k, v in categories.items()], limit=8))}</strong></div>'
        f'<div class="kv"><span>weak scorer sources</span><strong>{_html(_format_list([f"{k}:{v}" for k, v in weak_sources.items()], limit=8))}</strong></div>'
        f'<div class="kv"><span>weak source types</span><strong>{_html(_format_list([f"{k}:{v}" for k, v in weak_types.items()], limit=8))}</strong></div>'
        f'<div class="kv"><span>active filter</span><strong>{_html(normalized_filter)}</strong></div>'
        "</div>"
    )
    recommendation_html = _render_list_items(recommendations)
    return (
        '<div class="filter-bar">'
        + "\n".join(chips)
        + "</div>"
        + diagnostics
        + "<h3>Feedback Review Recommendations</h3>"
        + recommendation_html
        + "<h3>Filtered Feedback Cases</h3>"
        + table_html
    )


def _render_sessions(sessions: List[Dict[str, Any]], selected_session_id: str) -> str:
    if not sessions:
        return '<div class="empty">No sessions found yet.</div>'
    rows = []
    for item in sessions:
        query = urlencode({"session_id": item["session_id"]})
        selected = " selected" if item["session_id"] == selected_session_id else ""
        tactics = _format_list(item["tactics"], limit=4)
        status = item["analysis_status"] or item["job_status"] or "-"
        rows.append(
            "<tr class=\"{selected}\">"
            "<td>{updated}</td>"
            "<td><a href=\"/?{query}\">{session_id}</a></td>"
            "<td>{sensor}</td>"
            "<td>{src_ip}</td>"
            "<td class=\"num\">{command_count}</td>"
            "<td>{tactics}</td>"
            "<td>{analysis_status}</td>"
            "<td>{job_status}</td>"
            "</tr>".format(
                selected=selected,
                updated=_html(_short(item["updated_at"], 32)),
                query=query,
                session_id=_html(item["session_id"]),
                sensor=_html(item["sensor"] or "-"),
                src_ip=_html(item["src_ip"]),
                command_count=item["command_count"],
                tactics=_html(tactics),
                analysis_status=_badge(status),
                job_status=_badge(item["job_status"] or "-"),
            )
        )
    return (
        "<table><thead><tr>"
        "<th>updated_at</th><th>session_id</th><th>sensor</th><th>src_ip</th>"
        "<th>commands</th><th>tactics</th><th>analysis_status</th><th>job/report</th>"
        "</tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )


def _render_commands(selected: Optional[Dict[str, Any]]) -> str:
    if not selected:
        return '<div class="empty">No selected session.</div>'
    commands = selected["payload"].get("commands") or []
    if not commands:
        return '<div class="empty">No commands observed for this session.</div>'
    return "<ol class=\"commands\">" + "\n".join(f"<li><code>{_html(cmd)}</code></li>" for cmd in commands) + "</ol>"


def _render_overview(detail: Dict[str, Any]) -> str:
    if not detail or not detail.get("ok"):
        return f'<div class="empty">{_html((detail or {}).get("error") or "No detail available.")}</div>'
    overview = detail.get("overview") or {}
    keys = [
        "session_id",
        "sensor",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "protocol",
        "start_time",
        "updated_at",
        "duration",
        "login_username",
        "login_success",
        "client_version",
        "hassh",
        "command_count",
        "analysis_status",
        "job_status",
        "report_id",
    ]
    return '<div class="overview-grid">' + "\n".join(
        f'<div class="kv"><span>{_html(key)}</span><strong>{_html(overview.get(key) if overview.get(key) not in (None, "") else "-")}</strong></div>'
        for key in keys
    ) + "</div>"


def _render_session_events(detail: Dict[str, Any]) -> str:
    rows = detail.get("events_table_rows") or []
    if not rows:
        fallback = detail.get("raw_events_from_session_payload") or []
        if not fallback:
            return '<div class="empty">No stored events found for this session.</div>'
        rows = [{"payload": item} for item in fallback if isinstance(item, dict)]
    rendered = []
    for row in rows[:MAX_SESSION_EVENTS]:
        payload = row.get("payload") or _event_payload(row)
        rendered.append(
            "<tr><td>{timestamp}</td><td>{eventid}</td><td>{input}</td><td>{username}</td><td>{src}</td><td>{raw}</td></tr>".format(
                timestamp=_html(_short(payload.get("timestamp") or row.get("timestamp"), 32)),
                eventid=_html(payload.get("eventid") or row.get("eventid") or "-"),
                input=_html(_short(payload.get("input") or "", 80)),
                username=_html(_short(payload.get("username") or "", 80)),
                src=_html(payload.get("src_ip") or row.get("src_ip") or "-"),
                raw=f'<details><summary>JSON</summary><pre>{_html(json.dumps(_sanitize_public(payload), indent=2, sort_keys=True))}</pre></details>',
            )
        )
    return (
        "<table><thead><tr><th>timestamp</th><th>eventid</th><th>input</th><th>username</th><th>src_ip</th><th>raw</th></tr></thead><tbody>"
        + "\n".join(rendered)
        + "</tbody></table>"
    )


def _compact_enrichment_value(value: Any, limit: int = 6) -> str:
    if isinstance(value, list):
        return _format_list(value, limit=limit)
    if isinstance(value, dict):
        return _short(json.dumps(_sanitize_public(value), sort_keys=True), 160)
    if value in (None, "", []):
        return "-"
    return _text(value)


def _provider_status_text(provider_status: Dict[str, Any]) -> str:
    if not provider_status:
        return "-"
    parts = []
    for provider, info in sorted(provider_status.items()):
        if isinstance(info, dict):
            status = info.get("status") or "-"
        else:
            status = str(info)
        parts.append(f"{provider}:{status}")
    return ", ".join(parts)


def _enrichment_findings_row(row: Dict[str, Any]) -> str:
    payload = row.get("payload") or {}
    provider_status = row.get("provider_status") or payload.get("provider_status") or {}
    network = []
    for key in ("country", "asn", "isp"):
        value = payload.get(key)
        if value not in (None, "", []):
            network.append(f"{key}={value}")
    risk = []
    for key in ("risk_score", "total_reports", "vt_detection_ratio", "vt_malware_family"):
        value = payload.get(key)
        if value not in (None, "", []):
            risk.append(f"{key}={value}")
    if payload.get("vt_hit") not in (None, ""):
        risk.append(f"vt_hit={payload.get('vt_hit')}")
    exposure = []
    for key in ("open_ports", "running_services", "infrastructure_tags"):
        value = payload.get(key)
        if value not in (None, "", []):
            exposure.append(f"{key}={_compact_enrichment_value(value)}")
    source_specific = []
    for key in (
        "shodan_api",
        "shodan_hostnames",
        "shodan_tags",
        "shodan_vulns",
        "censys_api",
        "censys_labels",
        "otx_tags",
        "abuseipdb_categories",
    ):
        value = payload.get(key)
        if value not in (None, "", []):
            source_specific.append(f"{key}={_compact_enrichment_value(value)}")

    return (
        "<tr>"
        f"<td>{_html(row.get('observable_type') or '-')}</td>"
        f"<td><code>{_html(row.get('observable_value') or '-')}</code></td>"
        f"<td>{_html(_provider_status_text(provider_status))}</td>"
        f"<td>{_html('; '.join(network) or '-')}</td>"
        f"<td>{_html('; '.join(risk) or '-')}</td>"
        f"<td>{_html('; '.join(exposure) or '-')}</td>"
        f"<td>{_html('; '.join(source_specific) or '-')}</td>"
        "</tr>"
    )


def _render_enrichment_findings(records: List[Dict[str, Any]]) -> str:
    if not records:
        return '<div class="empty">No fetched enrichment values are available yet.</div>'
    rows = [_enrichment_findings_row(row) for row in records]
    return (
        "<table><thead><tr>"
        "<th>type</th><th>value</th><th>providers</th><th>network</th><th>risk</th><th>exposure</th><th>source-specific values</th>"
        "</tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )


def _render_enrichment(detail: Dict[str, Any]) -> str:
    if not detail or not detail.get("ok"):
        return '<div class="empty">No enrichment detail available.</div>'
    status = detail.get("enrichment_status") or {}
    observables = detail.get("observables") or []
    records = detail.get("enrichment_records") or []
    jobs = detail.get("enrichment_jobs") or []
    error = (detail.get("errors") or {}).get("enrichment") or ""

    parts = [
        "<h3>Session Enrichment Status</h3>",
        '<div class="overview-grid">'
        + "\n".join(
            f'<div class="kv"><span>{_html(key)}</span><strong>{_html(value if value not in (None, "") else "-")}</strong></div>'
            for key, value in (status.items() if isinstance(status, dict) else [])
        )
        + "</div>" if status else '<div class="empty">No enrichment status stored on the session.</div>',
        "<h3>Observed Enrichment Keys</h3>",
    ]
    if observables:
        parts.append(
            "<table><thead><tr><th>type</th><th>value</th></tr></thead><tbody>"
            + "\n".join(
                f"<tr><td>{_html(item.get('type'))}</td><td><code>{_html(item.get('value'))}</code></td></tr>"
                for item in observables
            )
            + "</tbody></table>"
        )
    else:
        parts.append('<div class="empty">No observables extracted for enrichment lookup.</div>')

    parts.append("<h3>Fetched Enrichment Values</h3>")
    parts.append(_render_enrichment_findings(records))

    parts.append("<h3>Cached Enrichment Records</h3>")
    if records:
        rows = []
        for row in records:
            payload = row.get("payload") or {}
            provider_status = row.get("provider_status") or payload.get("provider_status") or {}
            summary = {
                "asn": payload.get("asn") or payload.get("as_owner") or "",
                "country": payload.get("country") or "",
                "isp": payload.get("isp") or "",
                "otx_tags": payload.get("otx_tags") or payload.get("tags") or [],
                "vt_hit": payload.get("vt_hit") or "",
                "risk_score": payload.get("risk_score") or "",
            }
            rows.append(
                "<tr>"
                f"<td>{_html(row.get('observable_type'))}</td>"
                f"<td><code>{_html(row.get('observable_value'))}</code></td>"
                f"<td>{_html(row.get('updated_at') or '-')}</td>"
                f"<td>{_html(row.get('expires_at') or '-')}</td>"
                f"<td><details><summary>summary</summary><pre>{_html(json.dumps(_sanitize_public(summary), indent=2, sort_keys=True))}</pre></details></td>"
                f"<td><details><summary>providers</summary><pre>{_html(json.dumps(_sanitize_public(provider_status), indent=2, sort_keys=True))}</pre></details></td>"
                f"<td><details><summary>payload</summary><pre>{_html(json.dumps(_sanitize_public(payload), indent=2, sort_keys=True))}</pre></details></td>"
                "</tr>"
            )
        parts.append(
            "<table><thead><tr><th>type</th><th>value</th><th>updated</th><th>expires</th><th>summary</th><th>providers</th><th>payload</th></tr></thead><tbody>"
            + "\n".join(rows)
            + "</tbody></table>"
        )
    else:
        msg = "No cached enrichment record matched this session's observables."
        if error:
            msg += f" ({error})"
        parts.append(f'<div class="empty">{_html(msg)}</div>')

    parts.append("<h3>Enrichment Jobs</h3>")
    if jobs:
        rows = []
        for row in jobs:
            rows.append(
                "<tr>"
                f"<td>{_html(row.get('status') or '-')}</td>"
                f"<td>{_html(row.get('priority') or 'normal')}</td>"
                f"<td>{_html(row.get('observable_type') or '-')}</td>"
                f"<td><code>{_html(row.get('observable_value') or '-')}</code></td>"
                f"<td>{_html(row.get('attempts') or 0)}</td>"
                f"<td>{_html(row.get('updated_at') or '-')}</td>"
                f"<td>{_html(row.get('priority_reason') or '')}</td>"
                f"<td>{_html(row.get('error') or '')}</td>"
                "</tr>"
            )
        parts.append(
            "<table><thead><tr><th>status</th><th>priority</th><th>type</th><th>value</th><th>attempts</th><th>updated</th><th>priority reason</th><th>error</th></tr></thead><tbody>"
            + "\n".join(rows)
            + "</tbody></table>"
        )
    else:
        parts.append('<div class="empty">No enrichment jobs matched this session.</div>')
    return "\n".join(parts)


def _render_observable_sightings(detail: Dict[str, Any]) -> str:
    if not detail or not detail.get("ok"):
        return '<div class="empty">No selected session.</div>'
    error = (detail.get("errors") or {}).get("observable_sightings") or ""
    rows = detail.get("observable_sightings") or []
    related = detail.get("related_observable_sightings") or []
    parts: List[str] = []
    if error and not rows:
        parts.append(f'<div class="empty">{_html(error)}</div>')
    elif rows:
        rendered = []
        for row in rows[:200]:
            payload = row.get("payload") or {}
            rendered.append(
                "<tr>"
                f"<td>{_html(_short(row.get('timestamp') or row.get('created_at'), 32))}</td>"
                f"<td>{_html(row.get('observable_type') or '-')}</td>"
                f"<td><code>{_html(row.get('observable_value') or '-')}</code></td>"
                f"<td>{_html(row.get('role') or '-')}</td>"
                f"<td>{_html(row.get('source') or '-')}</td>"
                f"<td>{_html(row.get('eventid') or '-')}</td>"
                f"<td>{_html(_short((payload.get('metadata') or {}), 120))}</td>"
                "</tr>"
            )
        parts.append(
            "<table><thead><tr><th>timestamp</th><th>type</th><th>value</th><th>role</th><th>source</th><th>eventid</th><th>metadata</th></tr></thead><tbody>"
            + "\n".join(rendered)
            + "</tbody></table>"
        )
    else:
        parts.append('<div class="empty">No observable sightings recorded for this session yet.</div>')

    if related:
        grouped: Dict[Tuple[str, str], List[str]] = {}
        for row in related:
            key = (str(row.get("observable_type") or ""), str(row.get("observable_value") or ""))
            session_id = str(row.get("session_id") or "")
            if not key[0] or not key[1] or not session_id:
                continue
            grouped.setdefault(key, [])
            if session_id not in grouped[key]:
                grouped[key].append(session_id)
        related_rows = []
        for (observable_type, observable_value), sessions in sorted(grouped.items()):
            links = ", ".join(
                f'<a href="/?{urlencode({"session_id": session_id})}">{_html(session_id)}</a>'
                for session_id in sessions[:8]
            )
            related_rows.append(
                f"<tr><td>{_html(observable_type)}</td><td><code>{_html(observable_value)}</code></td><td>{links}</td></tr>"
            )
        if related_rows:
            parts.append("<h3>Related Sessions Sharing These Observables</h3>")
            parts.append(
                "<table><thead><tr><th>type</th><th>value</th><th>other sessions</th></tr></thead><tbody>"
                + "\n".join(related_rows)
                + "</tbody></table>"
            )
    return "\n".join(parts)


def _render_cross_session_hunting(detail: Dict[str, Any]) -> str:
    if not detail or not detail.get("ok"):
        return '<div class="empty">No selected session.</div>'
    error = (detail.get("errors") or {}).get("threat_hunting") or ""
    links = detail.get("session_links") or []
    jobs = detail.get("threat_hunt_jobs") or []
    parts: List[str] = []
    if error and not links and not jobs:
        parts.append(f'<div class="empty">{_html(error)}</div>')

    parts.append("<h3>Session Links</h3>")
    if links:
        rows = []
        current = str(detail.get("session_id") or "")
        for row in links[:100]:
            other = row.get("session_id_b") if row.get("session_id_a") == current else row.get("session_id_a")
            payload = row.get("payload") or {}
            rows.append(
                "<tr>"
                f"<td>{_html(row.get('created_at') or '-')}</td>"
                f"<td><a href=\"/?{urlencode({'session_id': str(other or '')})}\">{_html(other or '-')}</a></td>"
                f"<td>{_html(row.get('link_type') or '-')}</td>"
                f"<td>{_html(row.get('observable_type') or '-')}</td>"
                f"<td><code>{_html(row.get('observable_value') or '-')}</code></td>"
                f"<td>{_html(row.get('confidence') or '-')}</td>"
                f"<td>{_html(_short(payload.get('related_roles') or [], 120))}</td>"
                "</tr>"
            )
        parts.append(
            "<table><thead><tr><th>created</th><th>related session</th><th>type</th><th>observable type</th><th>observable value</th><th>confidence</th><th>evidence roles</th></tr></thead><tbody>"
            + "\n".join(rows)
            + "</tbody></table>"
        )
    else:
        parts.append('<div class="empty">No durable session links recorded yet.</div>')

    parts.append("<h3>Threat Hunt Jobs From This Session</h3>")
    if jobs:
        rows = []
        for row in jobs[:100]:
            result = row.get("result") or {}
            rows.append(
                "<tr>"
                f"<td>{_html(row.get('status') or '-')}</td>"
                f"<td>{_html(row.get('observable_type') or '-')}</td>"
                f"<td><code>{_html(row.get('observable_value') or '-')}</code></td>"
                f"<td>{_html(row.get('attempts') or 0)}</td>"
                f"<td>{_html(result.get('related_session_count') if result else '-')}</td>"
                f"<td>{_html(result.get('links_created') if result else '-')}</td>"
                f"<td>{_html(result.get('alerts_created') if result else '-')}</td>"
                f"<td>{_html(row.get('updated_at') or '-')}</td>"
                f"<td>{_html(row.get('error') or '')}</td>"
                "</tr>"
            )
        parts.append(
            "<table><thead><tr><th>status</th><th>type</th><th>value</th><th>attempts</th><th>related</th><th>links</th><th>alerts</th><th>updated</th><th>error</th></tr></thead><tbody>"
            + "\n".join(rows)
            + "</tbody></table>"
        )
    else:
        parts.append('<div class="empty">No threat-hunt jobs were created from this session yet.</div>')
    return "\n".join(parts)


def _render_campaign_panel(detail: Dict[str, Any]) -> str:
    if not detail or not detail.get("ok"):
        return '<div class="empty">No selected session.</div>'
    error = (detail.get("errors") or {}).get("campaigns") or ""
    memberships = detail.get("campaign_memberships") or []
    campaigns = detail.get("campaigns") or []
    summary = (detail.get("session_payload") or {}).get("campaign_summary") or {}
    parts: List[str] = []
    if error and not memberships and not campaigns and not summary:
        parts.append(f'<div class="empty">{_html(error)}</div>')
    if summary:
        fingerprint = summary.get("fingerprint") or {}
        parts.append('<div class="overview-grid">')
        for label, value in (
            ("status", summary.get("status")),
            ("campaign_id", summary.get("campaign_id")),
            ("matched_existing", summary.get("matched_existing_campaign")),
            ("session_count", summary.get("campaign_session_count")),
            ("prior_other_sessions", summary.get("prior_other_session_count")),
            ("max_severity", summary.get("max_confirmed_severity")),
            ("primary_fingerprint", f"{fingerprint.get('primary_fingerprint_type') or '-'}:{fingerprint.get('primary_fingerprint_value') or '-'}"),
            ("known_actor_alert", summary.get("known_actor_return_alert_id") or "-"),
        ):
            parts.append(f'<div class="kv"><span>{_html(label)}</span><strong>{_html(value if value not in (None, "") else "-")}</strong></div>')
        parts.append("</div>")
        reasons = []
        for match in summary.get("matches") or []:
            if isinstance(match, dict):
                reasons.extend(str(item) for item in match.get("match_reasons") or [])
        if reasons:
            parts.append("<p><strong>Why it matched:</strong> " + _html(_format_list(reasons, limit=8)) + "</p>")
    if campaigns:
        rows = []
        for campaign in campaigns:
            payload = campaign.get("payload") or {}
            confirmed_tactics = campaign.get("confirmed_tactics") or payload.get("confirmed_tactics") or []
            fingerprint = payload.get("fingerprint") or {}
            rows.append(
                "<tr>"
                f"<td><code>{_html(campaign.get('campaign_id') or payload.get('campaign_id') or '-')}</code></td>"
                f"<td>{_html(campaign.get('session_count') or payload.get('session_count') or 0)}</td>"
                f"<td>{_html(campaign.get('max_confirmed_severity') or payload.get('max_confirmed_severity') or '-')}</td>"
                f"<td>{_html(campaign.get('primary_fingerprint_type') or payload.get('primary_fingerprint_type') or '-')}</td>"
                f"<td><code>{_html(_short(campaign.get('primary_fingerprint_value') or payload.get('primary_fingerprint_value') or '-', 64))}</code></td>"
                f"<td>{_html(_format_list(confirmed_tactics, limit=8))}</td>"
                f"<td>{_html(campaign.get('updated_at') or payload.get('last_seen') or '-')}</td>"
                f"<td><details><summary>fingerprint</summary><pre>{_html(json.dumps(_sanitize_public(fingerprint), indent=2, sort_keys=True))}</pre></details></td>"
                "</tr>"
            )
        parts.append(
            "<table><thead><tr><th>campaign_id</th><th>sessions</th><th>severity</th><th>primary type</th><th>primary value</th><th>confirmed tactics</th><th>updated</th><th>details</th></tr></thead><tbody>"
            + "\n".join(rows)
            + "</tbody></table>"
        )
    if memberships:
        rows = []
        for row in memberships:
            rows.append(
                "<tr>"
                f"<td>{_html(row.get('created_at') or '-')}</td>"
                f"<td><code>{_html(row.get('campaign_id') or '-')}</code></td>"
                f"<td>{_html(row.get('confidence') if row.get('confidence') is not None else '-')}</td>"
                f"<td>{_html(_format_list(row.get('match_reasons') or [], limit=8))}</td>"
                "</tr>"
            )
        parts.append("<h3>Campaign Membership Evidence</h3>")
        parts.append(
            "<table><thead><tr><th>created</th><th>campaign</th><th>confidence</th><th>match reasons</th></tr></thead><tbody>"
            + "\n".join(rows)
            + "</tbody></table>"
        )
    if not parts:
        return '<div class="empty">No campaign cluster has been recorded for this session yet.</div>'
    return "\n".join(parts)


def _render_raw_api_panel(detail: Dict[str, Any]) -> str:
    if not detail or not detail.get("ok"):
        return '<div class="empty">No API detail available.</div>'
    session_id = detail.get("session_id", "")
    api_url = f"/api/session?{urlencode({'session_id': session_id})}"
    payload = json.dumps(public_payload(detail), indent=2, sort_keys=True)
    return (
        f'<p>JSON API: <a href="{_html(api_url)}">{_html(api_url)}</a></p>'
        f'<details><summary>Full sanitized session detail JSON</summary><pre>{_html(payload)}</pre></details>'
    )


def _render_classifications(selected: Optional[Dict[str, Any]]) -> str:
    if not selected:
        return '<div class="empty">No selected session.</div>'
    events = selected["payload"].get("classification_events") or []
    if not events:
        return '<div class="empty">No classification events recorded.</div>'
    rows = []
    for item in events:
        if not isinstance(item, dict):
            continue
        confidence = item.get("confidence", "")
        try:
            confidence_text = f"{float(confidence):.2f}"
        except (TypeError, ValueError):
            confidence_text = _text(confidence)
        rows.append(
            "<tr><td><code>{command}</code></td><td>{ttp}</td><td>{source_ttp}</td><td>{tactic}</td><td>{source}</td><td>{confidence}</td><td>{error}</td></tr>".format(
                command=_html(_short(item.get("command"), 120)),
                ttp=_html(item.get("ttp") or "-"),
                source_ttp=_html(item.get("source_ttp") or item.get("source_subtechnique") or "-"),
                tactic=_html(item.get("tactic") or "-"),
                source=_html(item.get("source") or "-"),
                confidence=_html(confidence_text or "-"),
                error=_html(_short(item.get("error") or "", 80)),
            )
        )
    if not rows:
        return '<div class="empty">No parseable classification events recorded.</div>'
    return (
        "<table><thead><tr><th>command</th><th>main ttp</th><th>source ttp</th><th>tactic</th><th>source</th><th>confidence</th><th>error</th></tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )


def _render_session_ttp_correlations(selected: Optional[Dict[str, Any]]) -> str:
    if not selected:
        return '<div class="empty">No selected session.</div>'
    payload = selected.get("payload") or {}
    correlations = [
        item
        for item in (payload.get("session_ttp_correlations") or [])
        if isinstance(item, dict)
    ]
    summary = payload.get("session_ttp_correlation_summary") or {}
    if not correlations:
        status = summary.get("status") or "not available"
        return f'<div class="empty">No session-level TTP correlations recorded. Status: {_html(status)}.</div>'

    import_status = summary.get("import_status") or {}
    import_text = ", ".join(
        f"{name}:{(value or {}).get('status', value) if isinstance(value, dict) else value}"
        for name, value in import_status.items()
    )
    rule_source_counts = summary.get("rule_source_counts") or {}
    rule_source_text = ", ".join(f"{name}:{count}" for name, count in sorted(rule_source_counts.items()))
    document_counts = summary.get("source_document_counts") or {}
    document_text = ", ".join(f"{name}:{count}" for name, count in sorted(document_counts.items()))
    graph_summary = summary.get("session_evidence_graph_summary") or {}
    summary_html = (
        '<div class="overview-grid">'
        f'<div class="kv"><span>policy</span><strong>{_html(summary.get("policy_id") or "-")}</strong></div>'
        f'<div class="kv"><span>version</span><strong>{_html(summary.get("policy_version") or "-")}</strong></div>'
        f'<div class="kv"><span>policies</span><strong>{_html(_format_list(summary.get("policy_ids") or [], limit=4))}</strong></div>'
        f'<div class="kv"><span>knowledge packs</span><strong>{_html(_format_list(summary.get("knowledge_pack_ids") or [], limit=4))}</strong></div>'
        f'<div class="kv"><span>correlations</span><strong>{_html(summary.get("correlation_count"))}</strong></div>'
        f'<div class="kv"><span>prediction inputs</span><strong>{_html(summary.get("prediction_input_count"))}</strong></div>'
        f'<div class="kv"><span>manual/generated rules</span><strong>{_html(summary.get("manual_rule_count", 0))}/{_html(summary.get("generated_rule_count", 0))}</strong></div>'
        f'<div class="kv"><span>source types</span><strong>{_html(_format_list(summary.get("source_types") or [], limit=6))}</strong></div>'
        f'<div class="kv"><span>rule source counts</span><strong>{_html(rule_source_text or "-")}</strong></div>'
        f'<div class="kv"><span>document counts</span><strong>{_html(document_text or "-")}</strong></div>'
        f'<div class="kv"><span>import status</span><strong>{_html(import_text or "-")}</strong></div>'
        f'<div class="kv"><span>evidence graph</span><strong>{_html(graph_summary.get("graph_id") or "-")}</strong></div>'
        "</div>"
    )

    rows = []
    details = []
    for item in correlations:
        confidence = item.get("confidence", "")
        try:
            confidence_text = f"{float(confidence):.2f}"
        except (TypeError, ValueError):
            confidence_text = _text(confidence)
        refs = item.get("references") or []
        ref_links = _render_reference_links(refs, limit=4)
        evidence = item.get("evidence") or []
        provenance = item.get("provenance") or {}
        rows.append(
            "<tr>"
            f"<td>{_html(item.get('ttp') or '-')}</td>"
            f"<td>{_html(item.get('source_subtechnique') or '-')}</td>"
            f"<td>{_html(item.get('technique_name') or '-')}</td>"
            f"<td>{_html(item.get('tactic') or '-')}</td>"
            f"<td>{_html(confidence_text or '-')}</td>"
            f"<td>{_html(item.get('evidence_type') or '-')}</td>"
            f"<td>{_html(item.get('source_type') or '-')}</td>"
            f"<td>{_html(item.get('rule_id') or '-')}</td>"
            f"<td>{_html('yes' if item.get('apply_to_prediction') else 'no')}</td>"
            "</tr>"
        )
        details.append(
            f'<details class="scorer"><summary>{_html(item.get("rule_id") or item.get("ttp") or "correlation")}</summary>'
            f'<p>{_html(item.get("reason") or "")}</p>'
            f'<p><strong>Temporal claim:</strong> {_html(item.get("temporal_claim"))} | '
            f'<strong>Granularity:</strong> {_html(item.get("technique_granularity") or "parent")} | '
            f'<strong>Source TTP:</strong> {_html(item.get("source_ttp") or item.get("ttp") or "-")} | '
            f'<strong>Policy:</strong> {_html(item.get("policy_id") or "-")} {_html(item.get("policy_version") or "")}</p>'
            "<h4>References</h4>"
            + ref_links
            + "<h4>Evidence</h4>"
            + f"<pre>{_html(json.dumps(_sanitize_public(evidence), indent=2, sort_keys=True))}</pre>"
            + "<h4>Provenance</h4>"
            + f"<pre>{_html(json.dumps(_sanitize_public(provenance), indent=2, sort_keys=True))}</pre>"
            + "</details>"
        )

    table = (
        "<table><thead><tr><th>main TTP</th><th>source sub-technique</th><th>technique</th><th>tactic</th><th>confidence</th>"
        "<th>evidence type</th><th>source type</th><th>rule</th><th>prediction input</th></tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )
    return summary_html + table + "<h4>Correlation Evidence</h4>" + "\n".join(details)


def _render_list_items(values: Iterable[Any]) -> str:
    items = _as_text_list(list(values) if not isinstance(values, str) else values)
    if not items:
        return '<div class="empty">No items recorded yet.</div>'
    return "<ul>" + "\n".join(f"<li>{_html(item)}</li>" for item in items) + "</ul>"


def _render_alerts_panel(detail: Dict[str, Any]) -> str:
    if not detail or not detail.get("ok"):
        return '<div class="empty">No selected session.</div>'
    error = (detail.get("errors") or {}).get("alerts") or ""
    if error:
        return f'<div class="empty">{_html(error)}</div>'
    alerts = [item for item in detail.get("alerts") or [] if isinstance(item, dict)]
    if not alerts:
        return '<div class="empty">No alerts recorded for this session yet.</div>'
    rows = []
    details = []
    for alert in alerts:
        payload = alert.get("payload") if isinstance(alert.get("payload"), dict) else {}
        nested = payload.get("payload") if isinstance(payload.get("payload"), dict) else {}
        alert_type = alert.get("alert_type") or payload.get("alert_type") or nested.get("alert_type") or "-"
        severity = alert.get("severity") or payload.get("severity") or "-"
        reason = alert.get("reason") or payload.get("reason") or "-"
        predicted_tactic = (
            alert.get("predicted_tactic")
            or payload.get("predicted_tactic")
            or nested.get("predicted_tactic")
            or "-"
        )
        snapshot_id = alert.get("snapshot_id") or payload.get("snapshot_id") or nested.get("snapshot_id") or "-"
        rows.append(
            "<tr>"
            f"<td>{_html(alert.get('created_at') or payload.get('created_at') or '-')}</td>"
            f"<td>{_html(alert_type)}</td>"
            f"<td>{_badge(str(severity).lower())}</td>"
            f"<td>{_html(predicted_tactic)}</td>"
            f"<td>{_html(_short(reason, 160))}</td>"
            f"<td>{_html(snapshot_id)}</td>"
            "</tr>"
        )
        details.append(
            f'<details class="scorer"><summary>{_html(alert_type)} | {_html(severity)} | {_html(predicted_tactic)}</summary>'
            f"<pre>{_html(json.dumps(_sanitize_public(payload or alert), indent=2, sort_keys=True))}</pre>"
            "</details>"
        )
    return (
        "<table><thead><tr><th>created_at</th><th>type</th><th>severity</th><th>predicted tactic</th><th>reason</th><th>snapshot</th></tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
        + "<h3>Alert Payloads</h3>"
        + "\n".join(details)
    )


def _render_source_chips(sources: Iterable[Any]) -> str:
    chips = []
    for source in sources or []:
        if not isinstance(source, dict):
            continue
        name = source.get("name") or "unknown"
        source_type = source.get("source_type") or ""
        rule_id = source.get("rule_id") or ""
        score = source.get("weighted_score")
        support = ((source.get("metadata") or {}).get("transition_support_level") if isinstance(source.get("metadata"), dict) else "")
        parts = [str(name)]
        if source_type:
            parts.append(str(source_type))
        if rule_id:
            parts.append(str(rule_id))
        if score not in (None, ""):
            parts.append(f"weighted={score}")
        if support:
            parts.append(f"support={support}")
        chips.append(f'<span class="chip">{_html(" | ".join(parts))}</span>')
    return " ".join(chips) if chips else "-"


def _classification_quality_warnings(classification_quality: Dict[str, Any]) -> List[str]:
    warnings: List[str] = []
    validation = str(classification_quality.get("validation_status") or "unvalidated")
    event_count = int(classification_quality.get("event_count") or 0)
    unknown_count = int(classification_quality.get("unknown_count") or 0)
    shell_noise_count = int(classification_quality.get("shell_noise_count") or 0)
    min_confidence = float(classification_quality.get("confidence_min") or 0.0)
    geomean = float(classification_quality.get("confidence_geomean") or 0.0)
    if validation in {"", "unvalidated"}:
        warnings.append("Classifier validation baseline is missing; prediction trust is limited.")
    if event_count and unknown_count:
        warnings.append(f"{unknown_count}/{event_count} classified command(s) are unknown.")
    if event_count and shell_noise_count >= max(event_count // 2, 1):
        warnings.append(f"{shell_noise_count}/{event_count} classification event(s) are shell noise.")
    if event_count and min_confidence and min_confidence < 0.55:
        warnings.append(f"Minimum classification confidence is low ({min_confidence:.2f}).")
    if event_count and geomean and geomean < 0.70:
        warnings.append(f"Classification chain confidence is weak ({geomean:.2f}); tactic-dependent scores were damped.")
    return warnings


def _render_prediction_panel(detail: Dict[str, Any]) -> str:
    if not detail or not detail.get("ok"):
        return '<div class="empty">No selected session.</div>'
    detail = public_payload(detail)
    latest = detail.get("latest_prediction_snapshot") or {}
    payload = latest.get("payload") or {}
    if not payload:
        error = (detail.get("errors") or {}).get("predictions") or ""
        suffix = f" {_html(error)}" if error else ""
        return f'<div class="empty">No prediction snapshot recorded for this session yet.{suffix}</div>'

    if payload.get("prediction_mode") == "professor_approved_corrected_target_transformer_poc":
        model = payload.get("active_model") or {}
        output = payload.get("next_behavior_output") or {}
        runtime = payload.get("runtime") or {}
        status = payload.get("prediction_status") or "model_unavailable"
        rows = [
            ("snapshot_role", "primary experimental PoC forecast"),
            (
                "snapshot_id",
                payload.get("snapshot_id") or latest.get("snapshot_id") or "-",
            ),
            ("snapshot_sha256", payload.get("snapshot_sha256") or "-"),
            ("target_contract", payload.get("prediction_contract") or "-"),
            ("status", status),
            ("status_reason", payload.get("prediction_status_reason") or "-"),
            ("model_type", model.get("model_type") or "-"),
            ("checkpoint_sha256", model.get("checkpoint_sha256") or "-"),
            ("seed", model.get("seed")),
            ("vocabulary_sha256", model.get("vocabulary_sha256") or "-"),
            ("preprocessing_sha256", model.get("preprocessing_sha256") or "-"),
            ("outcome_type", output.get("outcome_type") or "-"),
            ("prediction_set", _format_list(output.get("prediction_set") or [], limit=14)),
            ("inference_latency_ms", runtime.get("inference_latency_ms")),
            ("authority", "advisory / non-authoritative"),
            ("original_selection_status", payload.get("original_selection_status") or "-"),
        ]
        meta = '<div class="overview-grid prediction-meta">' + "\n".join(
            f'<div class="kv"><span>{_html(label)}</span><strong>{_html(value if value not in (None, "") else "-")}</strong></div>'
            for label, value in rows
        ) + "</div>"
        warning = (
            '<div class="warning"><strong>Experimental PoC:</strong> '
            + _html(
                payload.get("deployment_decision")
                or "This statistical forecast is advisory and cannot authorize alerts, hypotheses, guidance, recommendations, or actions."
            )
            + "</div>"
        )
        ranked = output.get("ranked_tactics") or []
        if ranked and status == "predicted":
            table_rows = "\n".join(
                "<tr>"
                f"<td class=\"num\">{_html(item.get('rank'))}</td>"
                f"<td><strong>{_html(item.get('tactic'))}</strong></td>"
                f"<td class=\"num\">{_html(item.get('calibrated_probability'))}</td>"
                f"<td class=\"num\">{_html(item.get('raw_score'))}</td>"
                "</tr>"
                for item in ranked
                if isinstance(item, dict)
            )
            body = (
                "<table><thead><tr><th>#</th><th>tactic</th>"
                "<th>calibrated probability</th><th>raw logit</th></tr></thead><tbody>"
                + table_rows
                + "</tbody></table>"
            )
        else:
            body = (
                f'<div class="empty">Transformer forecast {_html(status)}: '
                f'{_html(payload.get("prediction_status_reason") or "unavailable")}</div>'
            )
        return warning + meta + body

    ranking = payload.get("final_ranking") or []
    prediction_status = str(payload.get("prediction_status") or ("predicted" if ranking else "abstained"))
    prediction_status_reason = str(payload.get("prediction_status_reason") or "")
    features = payload.get("features") or {}
    engine = payload.get("engine") or {}
    weights = payload.get("weights") or {}
    effective_weights = payload.get("effective_weights") or {}
    weight_influence_scope = str(payload.get("weight_influence_scope") or "")
    active_weights = payload.get("active_weights") or {}
    external_weight_policy = payload.get("external_seed_weight_policy") or {}
    coverage = payload.get("coverage") or {}
    damping = payload.get("confidence_damping") or {}
    maturity = payload.get("model_maturity") or {}
    local_maturity = maturity.get("local_shadow") if isinstance(maturity.get("local_shadow"), dict) else maturity
    authority_maturity = maturity.get("authority") if isinstance(maturity.get("authority"), dict) else {}
    local_model = payload.get("local_transition_model") or {}
    external_seed = payload.get("external_seed_model") or {}
    classification_quality = payload.get("classification_quality") or {}
    calibration_status = payload.get("calibration_status") or {}
    weight_calibration = payload.get("weight_calibration") or {}
    trust_status = payload.get("trust_status") or {}
    agreement = payload.get("agreement") or {}
    trigger = payload.get("prediction_trigger") or {}
    predictive_alert = payload.get("predictive_alert") or {}
    external_artifact = payload.get("external_artifact") or {}
    generic_prior = payload.get("generic_progression_prior") or {}
    local_shadow = payload.get("local_shadow_prediction") or {}
    rows = [
        ("snapshot_role", "current prediction"),
        ("snapshot_id", payload.get("snapshot_id") or latest.get("snapshot_id") or "-"),
        ("generated_at", payload.get("generated_at") or latest.get("created_at") or "-"),
        ("prediction_status", prediction_status),
        ("prediction_status_reason", prediction_status_reason or "-"),
        ("engine", f"{engine.get('name', 'unknown')} {engine.get('version', '')}".strip()),
        ("session_status", payload.get("session_status") or "-"),
        ("event_id", payload.get("event_id") or "-"),
        ("trigger_eventid", trigger.get("eventid") or "-"),
        ("trigger_reason", trigger.get("reason") or "-"),
        ("predictive_alert_status", predictive_alert.get("status") or "-"),
        ("predictive_alert_reason", predictive_alert.get("reason") or "-"),
        ("features_hash", payload.get("features_hash") or "-"),
        ("observed_tactics", _format_list(features.get("observed_tactics") or [], limit=8)),
        ("last_tactic", features.get("last_tactic") or "-"),
        ("classification_chain_confidence", features.get("classification_chain_confidence_geomean")),
        ("active_scorers", f"{coverage.get('active_scorer_count', len(payload.get('active_scorers') or []))}/{coverage.get('min_active_scorers', '-')}"),
        ("coverage_warning", coverage.get("reason") or "-"),
        ("trust_status", trust_status.get("status") or "-"),
        ("evidence_posture", trust_status.get("evidence_posture") or "-"),
        ("dominant_source", trust_status.get("dominant_source") or "-"),
        ("authority_model_maturity", authority_maturity.get("maturity") or "-"),
        ("local_shadow_maturity", local_maturity.get("maturity") or "-"),
        ("local_transition_sessions", local_maturity.get("local_transition_sessions")),
        ("local_transition_transitions", local_maturity.get("local_transition_transitions")),
        ("local_model_id", local_model.get("model_id") or "-"),
        (
            "local_model_source",
            _sanitize_public(
                local_model.get("source_database") or "-",
                "source_database",
            ),
        ),
        ("local_recency_decay_half_life", local_model.get("recency_decay_half_life_sessions")),
        ("local_prior_dominated", local_maturity.get("prior_dominated")),
        ("external_seed_enabled", external_seed.get("enabled")),
        ("external_seed_sessions", external_seed.get("usable_sessions")),
        ("external_seed_transitions", external_seed.get("transition_count")),
        ("external_seed_source", external_seed.get("dataset_handle") or external_seed.get("source_type") or "-"),
        ("external_seed_model_id", external_seed.get("model_id") or "-"),
        ("external_artifact_status", external_artifact.get("status") or "-"),
        ("external_artifact_model_id", external_artifact.get("model_id") or "-"),
        ("external_artifact_manifest_id", external_artifact.get("manifest_id") or "-"),
        ("external_artifact_sha256", external_artifact.get("artifact_sha256") or "-"),
        ("external_artifact_context", payload.get("transition_context") or "-"),
        ("external_artifact_support", payload.get("evidence_count")),
        ("local_shadow_status", local_shadow.get("status") or "-"),
        ("generic_progression_prior", "offline planning only" if generic_prior else "-"),
        ("external_seed_decay", f"{external_weight_policy.get('maturity', '-')} x{external_weight_policy.get('multiplier', '-')}"),
        ("external_seed_effective_weight", external_weight_policy.get("effective_weight")),
        ("classification_validation", classification_quality.get("validation_status") or "-"),
        ("classification_sources", _format_list([f"{k}:{v}" for k, v in (classification_quality.get("source_counts") or {}).items()], limit=8)),
        ("classification_unknowns", classification_quality.get("unknown_count")),
        ("classification_shell_noise", classification_quality.get("shell_noise_count")),
        ("classification_min_confidence", classification_quality.get("confidence_min")),
        ("classification_geomean", classification_quality.get("confidence_geomean")),
        ("calibration", calibration_status.get("status") or "-"),
        ("calibration_ready_bins", f"{calibration_status.get('ready_bin_count', 0)}/{calibration_status.get('bin_count', 0)}"),
        ("weight_calibration", weight_calibration.get("status") or "-"),
        ("weight_influence_scope", weight_influence_scope or "-"),
        ("weight_calibration_run", weight_calibration.get("run_id") or "-"),
        ("scorer_disagreement", agreement.get("disagreement")),
        ("divergent_scorers", _format_list(agreement.get("divergent_scorers") or [], limit=8)),
        ("damping", f"{damping.get('mode', 'geometric_mean')} factor={damping.get('factor', '-')}"),
    ]

    meta = '<div class="overview-grid prediction-meta">' + "\n".join(
        f'<div class="kv"><span>{_html(label)}</span><strong>{_html(value if value not in (None, "") else "-")}</strong></div>'
        for label, value in rows
    ) + "</div>"
    warning_parts = []
    if local_maturity.get("warning"):
        warning_parts.append(f'<div class="warning"><strong>Local shadow model:</strong> {_html(local_maturity.get("warning"))}</div>')
    if external_seed.get("warning"):
        warning_parts.append(f'<div class="warning"><strong>External seed:</strong> {_html(external_seed.get("warning"))}</div>')
    if agreement.get("warning"):
        warning_parts.append(f'<div class="warning"><strong>Scorer disagreement:</strong> {_html(agreement.get("warning"))}</div>')
    if predictive_alert.get("status") == "alert_created":
        warning_parts.append(
            f'<div class="warning"><strong>Predictive alert:</strong> {_html(predictive_alert.get("reason") or "alert created")}</div>'
        )
    if weight_calibration.get("status") not in {None, "", "applied"}:
        warning_parts.append(
            f'<div class="warning"><strong>Weight calibration:</strong> {_html(weight_calibration.get("reason") or weight_calibration.get("status") or "not applied")}</div>'
        )
    for warning in _classification_quality_warnings(classification_quality):
        warning_parts.append(f'<div class="warning"><strong>Classification quality:</strong> {_html(warning)}</div>')
    for warning in trust_status.get("warnings") or []:
        warning_parts.append(f'<div class="warning"><strong>Trust status:</strong> {_html(warning)}</div>')
    warnings_html = "\n".join(warning_parts)

    if ranking:
        rank_rows = []
        for index, item in enumerate(ranking, start=1):
            reasons = item.get("reasons") or []
            rank_rows.append(
                "<tr>"
                f"<td class=\"num\">{index}</td>"
                f"<td><strong>{_html(item.get('tactic') or '-')}</strong></td>"
                f"<td>{_badge(item.get('confidence') or 'low')}</td>"
                f"<td class=\"num\">{_html(item.get('score'))}</td>"
                f"<td>{_render_source_chips(item.get('sources') or [])}</td>"
                f"<td>{_render_list_items(reasons[:3])}</td>"
                "</tr>"
            )
        ranking_html = (
            "<table><thead><tr><th>#</th><th>predicted tactic</th><th>confidence</th><th>score</th>"
            "<th>scorers</th><th>reasons</th></tr></thead><tbody>"
            + "\n".join(rank_rows)
            + "</tbody></table>"
        )
    else:
        label = "model unavailable" if prediction_status == "model_unavailable" else "explicitly abstained"
        ranking_html = f'<div class="empty">External hard-backoff VOMM {label}: {_html(prediction_status_reason or "no empirically supported context")}</div>'

    scorer_outputs = payload.get("scorer_outputs") or {}
    scorer_sections = []
    for scorer, outputs in sorted(scorer_outputs.items()):
        if not outputs:
            scorer_sections.append(
                f'<details class="scorer"><summary>{_html(scorer)}: no signal</summary><div class="empty">No hypotheses from this scorer.</div></details>'
            )
            continue
        lines = []
        for output in outputs:
            if not isinstance(output, dict):
                continue
            reason = "; ".join(output.get("reasons") or [])
            lines.append(
                "<tr>"
                f"<td>{_html(output.get('tactic') or '-')}</td>"
                f"<td>{_html(output.get('source_type') or '-')}</td>"
                f"<td>{_html(output.get('rule_id') or '-')}</td>"
                f"<td class=\"num\">{_html(output.get('score'))}</td>"
                f"<td>{_html(_short(reason, 220))}</td>"
                "</tr>"
            )
        scorer_sections.append(
            f'<details class="scorer"><summary>{_html(scorer)}: {len(outputs)} hypothesis(es)</summary>'
            "<table><thead><tr><th>tactic</th><th>source type</th><th>rule</th><th>raw score</th><th>reason</th></tr></thead><tbody>"
            + "\n".join(lines)
            + "</tbody></table></details>"
        )
    weights_html = '<div class="weights">' + " ".join(
        f'<span class="chip">{_html(name)}={_html(weight)}</span>'
        for name, weight in sorted(weights.items())
    ) + "</div>"
    active_weights_html = '<div class="weights">' + " ".join(
        f'<span class="chip">{_html(name)}={_html(weight)}</span>'
        for name, weight in sorted(active_weights.items())
    ) + "</div>"
    effective_weights_html = '<div class="weights">' + " ".join(
        f'<span class="chip">{_html(name)}={_html(weight)}</span>'
        for name, weight in sorted(effective_weights.items())
    ) + "</div>"
    prior_items = generic_prior.get("tactics") if isinstance(generic_prior, dict) else []
    prior_html = (
        '<div class="empty">No generic progression prior applies.</div>'
        if not prior_items else
        '<div class="weights">' + " ".join(
            f'<span class="chip">{_html(item.get("ordinal"))}. {_html(item.get("tactic"))}</span>'
            for item in prior_items if isinstance(item, dict)
        ) + '</div>'
    )

    commands = features.get("commands") or []
    command_rows = "\n".join(
        "<tr>"
        f"<td class=\"num\">{index}</td>"
        f"<td><code>{_html(command)}</code></td>"
        "</tr>"
        for index, command in enumerate(commands[:20], start=1)
    )
    commands_html = (
        "<table><thead><tr><th>#</th><th>command</th></tr></thead><tbody>"
        + (command_rows or '<tr><td colspan="2" class="empty">No commands in feature snapshot.</td></tr>')
        + "</tbody></table>"
    )
    classification_rows = []
    for event in features.get("classification_events") or []:
        if not isinstance(event, dict):
            continue
        classification_rows.append(
            "<tr>"
            f"<td><code>{_html(event.get('command') or '-')}</code></td>"
            f"<td>{_html(event.get('ttp') or '-')}</td>"
            f"<td>{_html(event.get('tactic') or '-')}</td>"
            f"<td>{_html(event.get('source') or '-')}</td>"
            f"<td class=\"num\">{_html(event.get('confidence') if event.get('confidence') not in (None, '') else '-')}</td>"
            "</tr>"
        )
    classifications_html = (
        "<table><thead><tr><th>command</th><th>TTP</th><th>tactic</th><th>source</th><th>confidence</th></tr></thead><tbody>"
        + ("\n".join(classification_rows) or '<tr><td colspan="5" class="empty">No command classifications in feature snapshot.</td></tr>')
        + "</tbody></table>"
    )
    why_html = (
        "<h3>Why This Prediction?</h3>"
        "<details open><summary>Observed command sequence</summary>"
        + commands_html
        + "</details>"
        "<details open><summary>Raw classification audit trail</summary>"
        + classifications_html
        + "</details>"
    )

    return (
        meta
        + warnings_html
        + "<h3>Ranked Next-Step Hypotheses</h3>"
        + ranking_html
        + "<h3>Generic Progression Prior (Non-empirical, Offline Planning Only)</h3>"
        + prior_html
        + why_html
        + (
            "<h3>Configured Weights (Diagnostic Baseline Only)</h3>"
            if weight_influence_scope == "diagnostic_only"
            else "<h3>Configured Production Weights</h3>"
            if weight_influence_scope == "production_ranking"
            else "<h3>Weights (Not Applicable to External-Only Authority)</h3>"
        )
        + weights_html
        + (
            "<h3>Effective Diagnostic Weights After Maturity Policy</h3>"
            if weight_influence_scope == "diagnostic_only"
            else "<h3>Effective Production Weights After Maturity Policy</h3>"
        )
        + effective_weights_html
        + "<h3>Normalized Active Weights</h3>"
        + active_weights_html
        + "<h3>Scorer Outputs</h3>"
        + "\n".join(scorer_sections)
    )


def _render_feedback_panel(
    detail: Dict[str, Any],
    allow_feedback: bool = True,
) -> str:
    if not detail or not detail.get("ok"):
        return '<div class="empty">No selected session.</div>'
    session_id = detail.get("session_id") or ""
    latest = detail.get("latest_prediction_snapshot") or {}
    payload = latest.get("payload") or {}
    snapshot_id = payload.get("snapshot_id") or latest.get("snapshot_id") or ""
    features = payload.get("features") or {}
    ranking = payload.get("final_ranking") or []
    observed_prefix = json.dumps(features.get("tactic_sequence") or [], sort_keys=True)
    predicted_top_tactic = str((ranking[0] or {}).get("tactic") or "") if ranking else ""
    predicted_ranking = json.dumps(_compact_prediction_ranking(ranking), sort_keys=True)
    rows = detail.get("analyst_feedback") or []
    response_guidance = detail.get("response_guidance") or {}
    guidance_priority = (response_guidance.get("triage") or {}).get("review_priority") or ""
    guidance_actions = json.dumps(
        [
            item.get("action_id")
            for item in (response_guidance.get("advisory_actions") or [])[:5]
            if isinstance(item, dict)
        ],
        sort_keys=True,
    )
    error = (detail.get("errors") or {}).get("analyst_feedback") or ""
    common_hidden = f"""
  <input type="hidden" name="session_id" value="{_html(session_id)}">
  <input type="hidden" name="snapshot_id" value="{_html(snapshot_id)}">
  <input type="hidden" name="observed_prefix" value="{_html(observed_prefix)}">
  <input type="hidden" name="predicted_top_tactic" value="{_html(predicted_top_tactic)}">
  <input type="hidden" name="predicted_ranking" value="{_html(predicted_ranking)}">
  <input type="hidden" name="response_guidance_id" value="{_html(response_guidance.get('guidance_id') or '')}">
  <input type="hidden" name="response_guidance_priority" value="{_html(guidance_priority)}">
  <input type="hidden" name="response_guidance_actions" value="{_html(guidance_actions)}">
"""
    history = ""
    if error:
        history = f'<div class="empty">{_html(error)}</div>'
    elif rows:
        high_confidence_wrong = []
        low_confidence_useful = []
        rendered = []
        for row in rows:
            payload_row = row.get("payload") or {}
            label = str(row.get("label") or payload_row.get("label") or "")
            ranking_raw = row.get("predicted_ranking") or payload_row.get("predicted_ranking") or ""
            confidence = ""
            try:
                ranking_items = json.loads(ranking_raw) if isinstance(ranking_raw, str) else ranking_raw
            except json.JSONDecodeError:
                ranking_items = []
            if isinstance(ranking_items, list) and ranking_items:
                first = ranking_items[0] if isinstance(ranking_items[0], dict) else {}
                confidence = str(first.get("confidence") or "")
            if label in {"wrong", "not_useful", "false_positive"} and confidence == "high":
                high_confidence_wrong.append(row)
            if label in {"useful", "correct"} and confidence == "low":
                low_confidence_useful.append(row)
            rendered.append(
                "<tr>"
                f"<td>{_html(row.get('created_at') or payload_row.get('created_at') or '-')}</td>"
                f"<td>{_html(row.get('feedback_type') or payload_row.get('feedback_type') or '-')}</td>"
                f"<td>{_html(row.get('label') or payload_row.get('label') or '-')}</td>"
                f"<td>{_html(row.get('operator_signal') or payload_row.get('operator_signal') or '-')}</td>"
                f"<td>{_html(row.get('action_status') or payload_row.get('action_status') or '-')}</td>"
                f"<td>{_html('yes' if bool(row.get('weight_eligible') or payload_row.get('weight_eligible')) else 'no')}</td>"
                f"<td>{_html(row.get('final_actual_next_tactic') or payload_row.get('final_actual_next_tactic') or '-')}</td>"
                f"<td>{_html(_short(row.get('observed_prefix') or payload_row.get('observed_prefix') or '', 80))}</td>"
                f"<td>{_html(_short(row.get('notes') or payload_row.get('notes') or '', 160))}</td>"
                "</tr>"
            )
        history = (
            '<div class="overview-grid">'
            f'<div class="kv"><span>wrong predictions</span><strong>{sum(1 for row in rows if str(row.get("label") or (row.get("payload") or {}).get("label") or "") in {"wrong", "not_useful", "false_positive"})}</strong></div>'
            f'<div class="kv"><span>useful predictions</span><strong>{sum(1 for row in rows if str(row.get("label") or (row.get("payload") or {}).get("label") or "") in {"useful", "correct"})}</strong></div>'
            f'<div class="kv"><span>high-confidence wrong</span><strong>{len(high_confidence_wrong)}</strong></div>'
            f'<div class="kv"><span>low-confidence useful</span><strong>{len(low_confidence_useful)}</strong></div>'
            '</div>'
            "<table><thead><tr><th>created_at</th><th>type</th><th>label</th><th>usefulness</th><th>action</th><th>weight eligible</th><th>auto/expert actual</th><th>observed_prefix</th><th>notes</th></tr></thead><tbody>"
            + "\n".join(rendered)
            + "</tbody></table>"
        )
    else:
        history = '<div class="empty">No analyst feedback recorded for this session yet.</div>'

    forms = ""
    if allow_feedback:
        forms = f"""
<form class="feedback-form" method="post" action="/feedback">
  {common_hidden}
  <input type="hidden" name="feedback_type" value="operator_usefulness">
  <div class="feedback-button-row" aria-label="Prediction usefulness">
    <button type="submit" name="operator_signal" value="useful">Useful</button>
    <button type="submit" name="operator_signal" value="not_useful">Not useful</button>
    <button type="submit" name="operator_signal" value="not_sure">Not sure</button>
  </div>
  <label>Notes
    <textarea name="notes" rows="2" placeholder="Optional note for later review"></textarea>
  </label>
</form>
<form class="feedback-form" method="post" action="/feedback">
  {common_hidden}
  <input type="hidden" name="feedback_type" value="operator_action">
  <div class="feedback-button-row" aria-label="Operator action status">
    <button type="submit" name="action_status" value="done">Done</button>
    <button type="submit" name="action_status" value="ignored">Ignored</button>
    <button type="submit" name="action_status" value="need_help">Need help</button>
  </div>
  <label>Notes
    <textarea name="notes" rows="2" placeholder="Optional action note"></textarea>
  </label>
</form>
"""
    else:
        forms = (
            '<div class="empty">Monitor feedback is disabled; this deployment '
            "is operating in read-only mode.</div>"
        )
    return f"""
{forms}
<h3>Feedback History</h3>
{history}
"""


def _render_reference_links(references: Iterable[Any], limit: int = 6) -> str:
    refs = []
    for ref in references:
        if not isinstance(ref, dict):
            continue
        name = ref.get("name") or ref.get("source_id") or ref.get("url") or "source"
        url = ref.get("url") or ""
        if url:
            refs.append(f'<li><a href="{_html(url)}">{_html(name)}</a></li>')
        else:
            refs.append(f"<li>{_html(name)}</li>")
        if len(refs) >= limit:
            break
    if not refs:
        return '<div class="empty">No source references recorded.</div>'
    return "<ul>" + "\n".join(refs) + "</ul>"


def _render_response_guidance(decision: Dict[str, Any]) -> str:
    """Render only the v3 response-guidance contract.

    It renders no v1 immediate actions or v2 adapters.
    """

    if not decision:
        return ""
    guidance = decision
    if isinstance(guidance, dict) and guidance.get("schema_version") == "response_guidance.v3":
        findings = [item for item in guidance.get("findings") or [] if isinstance(item, dict)]
        finding = findings[0] if findings else {}
        triage = guidance.get("triage") or {}
        actions = [item for item in guidance.get("advisory_actions") or [] if isinstance(item, dict)]
        rendered_actions = []
        for action in actions[:8]:
            refs = ", ".join(str(ref) for ref in action.get("evidence_refs") or [])
            rendered_actions.append(
                "<li>"
                f"<strong>{_html(action.get('description') or '-')}</strong>"
                f"<br><span class=\"muted\">{_html(action.get('rationale') or '')}</span>"
                f"<div class=\"muted\">rule: {_html(action.get('rule_id') or '-')} | "
                f"canonical evidence: {_html(refs or '-')} | manual approval: required</div>"
                f"<details><summary>Preconditions</summary>{_render_list_items(action.get('preconditions') or [])}</details>"
                f"<details><summary>Verification</summary>{_render_list_items(action.get('verification_steps') or [])}</details>"
                f"<details><summary>Rollback guidance</summary><p>{_html(action.get('rollback_guidance') or '')}</p></details>"
                "</li>"
            )
        action_html = (
            "<ol>" + "\n".join(rendered_actions) + "</ol>"
            if rendered_actions
            else '<div class="empty">No policy-approved advisory action matched this session.</div>'
        )
        policy = (guidance.get("provenance") or {}).get("policy") or {}
        return (
            '<div class="decision-panel">'
            '<div class="overview-grid">'
            f'<div class="kv"><span>finding</span><strong>{_html(finding.get("severity") or "-")}</strong></div>'
            f'<div class="kv"><span>review urgency</span><strong>{_html(triage.get("urgency") or "-")}</strong></div>'
            f'<div class="kv"><span>guidance status</span><strong>{_html(guidance.get("status") or "-")}</strong></div>'
            f'<div class="kv"><span>policy</span><strong>{_html(policy.get("policy_id") or "-")}</strong></div>'
            "</div>"
            f'<p>{_html(finding.get("statement") or "")}</p>'
            "<h3>Advisory Actions</h3>"
            + action_html
            + '<p class="muted">This guidance has no execution authority; a human must approve and verify any action.</p>'
            + "</div>"
        )
    if guidance.get("schema_version") == "response_guidance_legacy_adapter.v1":
        return (
            '<div class="decision-panel"><div class="empty">'
            f'{_html(guidance.get("semantics") or "Historical guidance is read-only.")}'
            "</div></div>"
        )
    return (
        '<div class="decision-panel"><div class="empty">Response guidance is unavailable.</div></div>'
    )


def _render_mitre_reference_guidance(items: List[Dict[str, Any]]) -> str:
    rows = []
    for item in items[:8]:
        mitigations = item.get("mitigations") or []
        rows.append(
            "<li>"
            f"<strong>{_html(item.get('technique') or '-')} {_html(item.get('technique_name') or '')}</strong>"
            f"<br><span class=\"muted\">{_html(item.get('reason') or '')}</span>"
            + (
                f"<details><summary>MITRE mitigations</summary>{_render_list_items(mitigations[:5])}</details>"
                if mitigations else ""
            )
            + (
                f"<details><summary>References</summary>{_render_reference_links(item.get('references') or [], limit=3)}</details>"
                if item.get("references") else ""
            )
            + "</li>"
        )
    return "<ol>" + "\n".join(rows) + "</ol>" if rows else ""


def _render_structured_report_actions(actions: List[Dict[str, Any]]) -> str:
    if not actions:
        return ""
    items = []
    for action in actions[:8]:
        if not isinstance(action, dict):
            continue
        refs = action.get("references") or []
        evidence = action.get("evidence") or []
        safety = action.get("automation_safety") or {}
        refs_html = _render_reference_links(refs, limit=3) if refs else ""
        evidence_html = _render_list_items(evidence[:4]) if evidence else ""
        approval = (
            "manual approval required"
            if action.get("requires_manual_approval") or safety.get("requires_manual_approval")
            else "automation allowed by policy"
        )
        safety_bits = [
            f"severity: {action.get('severity') or '-'}",
            f"confidence: {action.get('confidence') or '-'}",
            approval,
            f"safety: {safety.get('level') or '-'}",
        ]
        items.append(
            "<li>"
            f"<strong>{_html(action.get('action') or '-')}</strong>"
            + (f"<br><span class=\"muted\">{_html(action.get('why') or '')}</span>" if action.get("why") else "")
            + (f"<div class=\"muted\">source: {_html(action.get('source_type') or '-')} | rule: {_html(action.get('rule_id') or '-')} | {' | '.join(_html(bit) for bit in safety_bits)}</div>")
            + (f"<div class=\"muted\">{_html(safety.get('rationale') or '')}</div>" if safety.get("rationale") else "")
            + (f"<details><summary>Evidence</summary>{evidence_html}</details>" if evidence_html else "")
            + (f"<details><summary>References</summary>{refs_html}</details>" if refs_html else "")
            + "</li>"
        )
    if not items:
        return ""
    return "<ol>" + "\n".join(items) + "</ol>"


def _render_next_steps(selected: Optional[Dict[str, Any]], detail: Optional[Dict[str, Any]] = None) -> str:
    if not selected and not detail:
        return '<div class="empty">No selected session.</div>'
    payload = selected["payload"] if selected else (detail or {}).get("session_payload", {})
    response_guidance = (detail or {}).get("response_guidance") or {}
    historical_decision = (
        (detail or {}).get("historical_response_guidance")
        # Read-only compatibility with callers holding the pre-v3 key.  New
        # detail responses expose only historical_response_guidance.
        or (detail or {}).get("historical_smb_decision")
        or {}
    )
    reevaluated_decision = (detail or {}).get("current_policy_reevaluation") or {}
    recommendations = (detail or {}).get("report_recommendations") or {}
    latest_prediction = (detail or {}).get("latest_prediction_snapshot") or {}
    prediction_payload = latest_prediction.get("payload") or {}
    realtime_ranking = prediction_payload.get("final_ranking") or []
    source = recommendations.get("source") or "policy_unavailable"
    hypothesis_alternatives = recommendations.get("hypothesis_alternatives") or []
    operator_actions = recommendations.get("recommended_actions") or []
    context_notes = recommendations.get("context_notes") or []
    falsification = recommendations.get("falsification_conditions") or []
    evidence_gaps = recommendations.get("evidence_gaps") or []
    external_suggestions = recommendations.get("external_validation_suggestions") or []
    parts = []
    if historical_decision:
        parts.extend([
            "<h3>Point-in-Time Stored Advisory Response Guidance</h3>",
            '<p class="muted">Historical report decision; it is not recomputed under the current policy.</p>',
            _render_response_guidance(historical_decision),
        ])
        if reevaluated_decision:
            parts.extend([
                "<h3>Current Policy Reevaluation</h3>",
                '<p class="muted">Recomputed from current policy and context; it does not replace the stored historical guidance.</p>',
                _render_response_guidance(reevaluated_decision),
            ])
        parts.append("<h3>Technical Prediction / Report Detail</h3>")
    elif reevaluated_decision:
        parts.extend([
            "<h3>Current Policy Reevaluation</h3>",
            '<p class="muted">No stored report decision is available. This guidance was recomputed from current policy and context.</p>',
            _render_response_guidance(reevaluated_decision),
            "<h3>Technical Prediction / Report Detail</h3>",
        ])
    elif response_guidance:
        parts.extend(["<h3>Advisory Response Guidance</h3>", _render_response_guidance(response_guidance)])
        parts.append("<h3>Technical Prediction / Report Detail</h3>")
    parts.extend([
        '<div class="overview-grid">',
        f'<div class="kv"><span>source</span><strong>{_html(source)}</strong></div>',
        f'<div class="kv"><span>hypothesis alternatives</span><strong>{_html(len(hypothesis_alternatives))}</strong></div>',
        "</div>",
        '<p class="muted">Hypothesis alternatives are falsifiable analytical questions, not attacker intent or predicted next actions.</p>',
        "<h3>Response Guidance Actions</h3>",
        '<p class="muted">Actions, when present, are rendered only in the v3 response-guidance panel above.</p>',
    ])
    if hypothesis_alternatives:
        parts.extend([
            "<h3>Falsifiable Hypothesis Alternatives</h3>",
            _render_list_items(hypothesis_alternatives),
        ])
    if realtime_ranking and not response_guidance:
        parts.extend([
            "<h3>Statistical Next-Tactic Forecast</h3>",
            '<p class="muted">Advisory model output; not observed evidence or factual confidence.</p>',
            _render_list_items([
                f"{item.get('tactic', 'unknown')} ({item.get('confidence', 'low')}): "
                + "; ".join((item.get("reasons") or [])[:2])
                for item in realtime_ranking
            ]),
        ])
    if context_notes:
        parts.extend(["<h3>Non-Authoritative Context Notes</h3>", _render_list_items(context_notes)])
    if falsification:
        parts.extend(["<h3>What To Check Next</h3>", _render_list_items(falsification)])
    if evidence_gaps:
        parts.extend(["<h3>Evidence Gaps Within Cowrie Visibility</h3>", _render_list_items(evidence_gaps)])
    if external_suggestions:
        parts.extend(["<h3>External Validation Suggestions</h3>", _render_list_items(external_suggestions)])
    return "\n".join(parts)


def _render_report_panel(selected: Optional[Dict[str, Any]], reports_dir: str) -> str:
    if not selected:
        return '<div class="empty">No selected session.</div>'
    report_payload = _report_payload(selected.get("report_row"))
    paths = _artifact_paths(report_payload, reports_dir)
    artifact_payload = _load_report_json_from_artifact(paths, reports_dir)
    summary = _report_summary(report_payload, artifact_payload)
    job = selected.get("job") or {}
    is_v2 = summary.get("schema_version") == "threat_hypothesis.v2"
    lines = [
        ("job status", job.get("status") or selected.get("analysis_status") or "pending"),
        ("report_id", job.get("report_id") or selected.get("report_id") or ""),
        ("error", job.get("error") or selected.get("job_error") or ""),
        ("updated_at", job.get("updated_at") or selected.get("updated_at") or ""),
        ("ai_enriched", summary.get("ai_enriched")),
        ("confidence_source", summary.get("confidence_source")),
        (
            "claim evidence status" if is_v2 else "analytical evidence strength",
            summary.get("analytical_evidence_strength") or summary.get("confidence"),
        ),
        (
            "evidence semantics",
            "per-claim categorical status; no global probability"
            if is_v2 else "heuristic, not a calibrated probability",
        ),
        ("analysis_mode", summary.get("analysis_mode")),
        ("campaign", summary.get("campaign_name")),
    ]
    meta = "\n".join(
        f"<div class=\"kv\"><span>{_html(label)}</span><strong>{_html(value or '-')}</strong></div>"
        for label, value in lines
    )
    if paths:
        artifacts = "<ul class=\"artifacts\">" + "\n".join(
            f"<li><span>{_html(kind)}</span><code>{_html(path)}</code></li>" for kind, path in sorted(paths.items())
        ) + "</ul>"
    else:
        artifacts = '<div class="empty">No report artifact paths recorded yet.</div>'
    summary_text = summary.get("summary") or "No compact report summary available yet."
    merged = _merged_report_payload(report_payload, artifact_payload)
    v4_detail = ""
    if merged.get("schema_version") == "session_assessment.v4":
        finding_items = [
            (
                f"[{item.get('status', '')}] {item.get('statement', '')} "
                f"(finding {item.get('finding_id', '')}; evidence "
                f"{', '.join(item.get('evidence_refs') or [])})"
            )
            for item in merged.get("behavioral_findings") or []
            if isinstance(item, dict)
        ]
        hypothesis_items = [
            (
                f"{hypothesis.get('statement', '')} "
                f"(hypothesis {hypothesis.get('hypothesis_id', '')}; evidence "
                f"{', '.join(hypothesis.get('supporting_evidence_refs') or []) or 'none'})"
            )
            for hypothesis_set in merged.get("hypothesis_sets") or []
            if isinstance(hypothesis_set, dict)
            for hypothesis in hypothesis_set.get("hypotheses") or []
            if isinstance(hypothesis, dict)
        ]
        provenance = merged.get("provenance") or {}
        v4_detail = (
            "<h3>Canonical Behavioral Findings</h3>"
            + _render_list_items(finding_items)
            + "<h3>Falsifiable Hypothesis Alternatives</h3>"
            + _render_list_items(hypothesis_items)
            + "<h3>Canonical Provenance</h3>"
            + _render_list_items([
                f"Evidence SHA-256: {provenance.get('evidence_sha256', '')}",
                "Behavior policy SHA-256: "
                f"{(provenance.get('behavior_policy') or {}).get('sha256', '')}",
                "Classification policy SHA-256: "
                f"{(provenance.get('classification_policy') or {}).get('sha256', '')}",
                f"Evaluator Git revision: {provenance.get('evaluator_git_revision', '')}",
            ])
        )
    return (
        meta
        + f"<h3>Session assessment summary</h3><p>{_html(summary_text)}</p>"
        + v4_detail
        + "<h3>AI Validation Warnings</h3>"
        + _render_ai_validation_warnings(report_payload, artifact_payload)
        + "<h3>Evidence Layers</h3>"
        + _render_report_evidence_layers(report_payload, artifact_payload)
        + "<h3>Artifacts</h3>"
        + artifacts
    )


def _render_events(events: List[Dict[str, Any]], error: str) -> str:
    if error:
        return f'<div class="empty">{_html(error)}</div>'
    if not events:
        return '<div class="empty">No events found yet.</div>'
    rows = []
    for event in events:
        rows.append(
            "<tr><td>{timestamp}</td><td>{sensor}</td><td>{session}</td><td>{src_ip}</td><td>{eventid}</td><td>{detail}</td></tr>".format(
                timestamp=_html(_short(event.get("timestamp"), 32)),
                sensor=_html(event.get("sensor") or "-"),
                session=_html(event.get("session") or "-"),
                src_ip=_html(event.get("src_ip") or "-"),
                eventid=_html(event.get("eventid") or "-"),
                detail=_html(_short(event.get("detail") or "", 100)),
            )
        )
    return (
        "<table><thead><tr><th>timestamp</th><th>sensor</th><th>session</th><th>src_ip</th><th>eventid</th><th>input/username</th></tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )


class MonitorHandler(BaseHTTPRequestHandler):
    monitor_config: MonitorConfig

    def _request_id(self) -> str:
        current = getattr(self, "_monitor_request_id", "")
        if current:
            return str(current)
        headers = getattr(self, "headers", None)
        request_id = safe_request_id(
            headers.get("X-Request-ID") if headers is not None else None
        )
        self._monitor_request_id = request_id
        return request_id

    def _send(self, status: HTTPStatus, body: str, content_type: str = "text/html; charset=utf-8") -> None:
        data = body.encode("utf-8")
        self.send_response(status.value)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
            "object-src 'none'; form-action 'self'; img-src 'self' data: https:; "
            "font-src 'self' data: https://fonts.gstatic.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com; "
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com "
            "https://unpkg.com https://cdn.jsdelivr.net; connect-src 'self'",
        )
        self.send_header("X-Request-ID", self._request_id())
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, status: HTTPStatus, payload: Dict[str, Any]) -> None:
        self._send(
            status,
            json.dumps(public_payload(payload), ensure_ascii=False, sort_keys=True),
            "application/json",
        )

    def _require_read(self) -> bool:
        read_token = _monitor_read_token(self.monitor_config)
        decision = authorize_read(
            single_header_value(self.headers, "Authorization"),
            read_token,
            allow_anonymous=(
                not read_token
                and is_loopback_host(self.monitor_config.bind_host)
            ),
        )
        if decision.allowed:
            return True
        self._send_json(
            decision.status,
            {"error": decision.error, "request_id": self._request_id()},
        )
        return False

    def _require_feedback_write(self) -> bool:
        if not _monitor_feedback_enabled(self.monitor_config):
            self._send_json(
                HTTPStatus.FORBIDDEN,
                {
                    "error": "monitor feedback is disabled",
                    "request_id": self._request_id(),
                },
            )
            return False
        decision = authorize_write(
            single_header_value(self.headers, "Authorization"),
            _monitor_read_token(self.monitor_config),
            _monitor_write_token(self.monitor_config),
        )
        if decision.allowed:
            return True
        self._send_json(
            decision.status,
            {"error": decision.error, "request_id": self._request_id()},
        )
        return False

    def _redirect(self, location: str) -> None:
        self.send_response(HTTPStatus.SEE_OTHER.value)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def do_POST(self) -> None:
        try:
            MonitorHandler._do_POST(self)
        except Exception as exc:
            MonitorHandler._handle_unexpected_error(self, "post_failed", exc)

    def _do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path not in {"/analyst-feedback", "/feedback"}:
            self._send(HTTPStatus.NOT_FOUND, "not found", "text/plain; charset=utf-8")
            return
        if not self._require_feedback_write():
            return
        connection = getattr(self, "connection", None)
        if connection is not None and hasattr(connection, "settimeout"):
            connection.settimeout(FEEDBACK_REQUEST_TIMEOUT_SECONDS)
        if parsed.path == "/analyst-feedback":
            try:
                raw = read_bounded_http_body(
                    self.headers,
                    self.rfile,
                    max_body_bytes=MAX_FEEDBACK_JSON_BYTES,
                    expected_content_type="application/json",
                    timeout_seconds=FEEDBACK_REQUEST_TIMEOUT_SECONDS,
                    timeout_setter=getattr(connection, "settimeout", None),
                )
            except HTTPBodyError as exc:
                self._send_json(
                    exc.status,
                    {"error": exc.public_message, "error_code": exc.code},
                )
                return
            try:
                payload = decode_strict_json_body(raw)
            except HTTPBodyError as exc:
                self._send_json(
                    exc.status,
                    {"error": exc.public_message, "error_code": exc.code},
                )
                return
            if not isinstance(payload, dict):
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "request body must contain a JSON object", "error_code": "invalid_json_object"},
                )
                return
            try:
                feedback_id = record_analyst_feedback(
                    self.monitor_config,
                    payload,
                )
            except ValueError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid feedback payload"})
                return
            self._send_json(HTTPStatus.CREATED, {"feedback_id": feedback_id, "status": "recorded", "timestamp": utc_now()})
            return
        try:
            raw_form = read_bounded_http_body(
                self.headers,
                self.rfile,
                max_body_bytes=MAX_FEEDBACK_FORM_BYTES,
                expected_content_type="application/x-www-form-urlencoded",
                timeout_seconds=FEEDBACK_REQUEST_TIMEOUT_SECONDS,
                timeout_setter=getattr(connection, "settimeout", None),
            )
        except HTTPBodyError as exc:
            self._send_json(
                exc.status,
                {"error": exc.public_message, "error_code": exc.code},
            )
            return
        try:
            form = parse_qs(
                raw_form.decode("utf-8"),
                max_num_fields=200,
            )
        except (UnicodeDecodeError, ValueError):
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "invalid feedback form", "error_code": "invalid_form"},
            )
            return
        feedback = {key: values[0] for key, values in form.items() if values}
        try:
            record_analyst_feedback(self.monitor_config, feedback)
        except ValueError:
            self._send(
                HTTPStatus.BAD_REQUEST,
                "invalid feedback payload",
                "text/plain; charset=utf-8",
            )
            return
        except Exception as exc:
            print(
                json.dumps(
                    log_payload(
                        {
                            "service": "monitor_web",
                            "event": "feedback_write_failed",
                            "exception": exc,
                            "request_id": self._request_id(),
                            "timestamp": utc_now(),
                        }
                    ),
                    sort_keys=True,
                ),
                flush=True,
            )
            self._send(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "feedback storage failed",
                "text/plain; charset=utf-8",
            )
            return
        session_id = str(feedback.get("session_id") or "")
        target = "/"
        if session_id:
            target = "/?" + urlencode({"session_id": session_id})
        self._redirect(target)

    def do_GET(self) -> None:
        try:
            MonitorHandler._do_GET(self)
        except Exception as exc:
            MonitorHandler._handle_unexpected_error(self, "get_failed", exc)

    def _do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path in {"/health", "/health/live", "/live"}:
            self._send_json(
                HTTPStatus.OK,
                {"ok": True, "service": "monitor_web", "timestamp": utc_now()},
            )
            return
        if parsed.path in {"/health/ready", "/ready"}:
            try:
                ready = bool(
                    _open_monitor_storage(self.monitor_config)
                    .health_check()
                    .get("ok")
                )
            except Exception:
                ready = False
            self._send_json(
                HTTPStatus.OK if ready else HTTPStatus.SERVICE_UNAVAILABLE,
                {
                    "ok": ready,
                    "service": "monitor_web",
                    "timestamp": utc_now(),
                },
            )
            return
        if not self._require_read():
            return
        if parsed.path == "/api/session":
            query = parse_qs(parsed.query)
            session_id = query.get("session_id", [""])[0]
            detail = load_session_detail(self.monitor_config, session_id=session_id)
            self._send_json(
                HTTPStatus.OK if detail.get("ok") else HTTPStatus.NOT_FOUND,
                session_detail_view(detail),
            )
            return
        if parsed.path == "/api/sessions":
            query = parse_qs(parsed.query)
            selected_session_id = query.get("session_id", [""])[0]
            session_limit = _parse_limit(query, default=DEFAULT_SESSION_LIMIT, maximum=MAX_SESSIONS)
            try:
                session_offset = max(int(query.get("offset", ["0"])[0]), 0)
            except (TypeError, ValueError):
                session_offset = 0
            snapshot = load_snapshot(
                self.monitor_config,
                selected_session_id=selected_session_id,
                session_limit=session_limit,
                session_offset=session_offset,
            )
            sessions = snapshot.get("sessions") or []
            sessions = [
                _session_overview(item)
                for item in sessions
                if isinstance(item, dict)
            ]
            payload = {
                "ok": snapshot.get("ok"),
                "timestamp": snapshot.get("timestamp"),
                "summary": snapshot.get("summary"),
                "sessions": sessions,
                "selected_session_id": (snapshot.get("selected") or {}).get("session_id"),
                "error": snapshot.get("error") or "",
            }
            self._send_json(HTTPStatus.OK if snapshot.get("ok") else HTTPStatus.INTERNAL_SERVER_ERROR, payload)
            return
        if parsed.path == "/api/events":
            query = parse_qs(parsed.query)
            session_id = query.get("session_id", [""])[0]
            if session_id:
                detail = load_session_detail(self.monitor_config, session_id=session_id)
                payload = {
                    "ok": detail.get("ok"),
                    "session_id": session_id,
                    "events": event_views(
                        detail.get("events_table_rows")
                        or detail.get("raw_events_from_session_payload")
                        or []
                    ),
                    "error": (detail.get("errors") or {}).get("events") or detail.get("error") or "",
                    "timestamp": utc_now(),
                }
                self._send_json(HTTPStatus.OK if detail.get("ok") else HTTPStatus.NOT_FOUND, payload)
                return
            snapshot = load_snapshot(self.monitor_config)
            payload = {
                "ok": snapshot.get("ok"),
                "events": event_views(snapshot.get("events") or []),
                "error": snapshot.get("events_error") or snapshot.get("error") or "",
                "timestamp": snapshot.get("timestamp"),
            }
            self._send_json(HTTPStatus.OK if snapshot.get("ok") else HTTPStatus.INTERNAL_SERVER_ERROR, payload)
            return
        query = parse_qs(parsed.query)
        dashboard_paths = {
            "/predictions/current",
            "/decisions/current",
            "/feedback-review",
            "/classification-evaluation",
            "/external-seed-health",
            *DASHBOARD_TABLES.keys(),
        }
        if parsed.path in dashboard_paths:
            status, dashboard_payload = _dashboard_get_payload(self.monitor_config, parsed.path, query)
            self._send_json(status, dashboard_payload or {"error": "not found"})
            return
        if parsed.path not in {"", "/", "/monitor.html"}:
            self._send(HTTPStatus.NOT_FOUND, "not found", "text/plain; charset=utf-8")
            return
        static_html = _read_static_monitor_html()
        if static_html:
            self._send(HTTPStatus.OK, static_html)
            return
        self._send(
            HTTPStatus.SERVICE_UNAVAILABLE,
            "canonical monitor asset unavailable",
            "text/plain; charset=utf-8",
        )

    def _handle_unexpected_error(self, event: str, exc: BaseException) -> None:
        print(
            json.dumps(
                log_payload(
                    {
                        "service": "monitor_web",
                        "event": event,
                        "exception": exc,
                        "request_id": self._request_id(),
                        "timestamp": utc_now(),
                    }
                ),
                sort_keys=True,
            ),
            flush=True,
        )
        self._send_json(
            HTTPStatus.SERVICE_UNAVAILABLE,
            {
                "error": "service temporarily unavailable",
                "request_id": self._request_id(),
            },
        )

    def log_message(self, fmt: str, *args: Any) -> None:
        del fmt
        status = ""
        if len(args) > 1 and str(args[1]).isdigit():
            status = str(args[1])
        print(
            json.dumps(
                log_payload({
                    "service": "monitor_web",
                    "client": str(self.client_address[0]) if self.client_address else "",
                    "method": str(getattr(self, "command", "") or ""),
                    "path": sanitize_request_target(str(getattr(self, "path", "") or "")),
                    "status": status,
                    "request_id": self._request_id(),
                    "timestamp": utc_now(),
                }),
                sort_keys=True,
            ),
            flush=True,
        )


def build_server(host: str, port: int, config: MonitorConfig) -> BoundedThreadingHTTPServer:
    validate_configured_bearer_tokens(
        read_token=_monitor_read_token(config),
        write_token=_monitor_write_token(config),
        service_name="monitor_web",
    )
    validate_bind_auth(
        host,
        auth_configured=bool(_monitor_read_token(config)),
        service_name="monitor_web",
    )
    config.bind_host = host
    MonitorHandler.monitor_config = config
    return BoundedThreadingHTTPServer(
        (host, port),
        MonitorHandler,
        request_timeout_seconds=FEEDBACK_REQUEST_TIMEOUT_SECONDS,
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the read-only cloud pipeline monitor web page.")
    parser.add_argument("--config", help="Path to production JSON config.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host. Default: 127.0.0.1")
    parser.add_argument("--port", type=int, default=8090, help="Bind port. Default: 8090")
    parser.add_argument(
        "--db-path",
        help="Deprecated: explicitly override the configured backend with a SQLite database path.",
    )
    parser.add_argument("--reports-dir", help="Override reports directory.")
    parser.add_argument("--refresh-seconds", type=int, default=DEFAULT_REFRESH_SECONDS)
    parser.add_argument("--check", action="store_true", help="Load one snapshot and print a compact health summary.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    config = _load_monitor_config(args.config)
    config.bind_host = args.host
    if args.db_path:
        config.db_path = args.db_path
        config.database_url = f"sqlite:///{args.db_path}"
    if args.reports_dir:
        config.reports_dir = args.reports_dir
        if config.production_config:
            config.production_config.reports_dir = args.reports_dir
    config.refresh_seconds = max(int(args.refresh_seconds), 2)

    if args.check:
        snapshot = load_snapshot(config)
        print(
            json.dumps(
                {
                    "ok": bool(snapshot.get("ok")),
                    "service": "monitor_web",
                    "db_path": config.db_path,
                    "database": _monitor_database_descriptor(config),
                    "sessions": len(snapshot.get("sessions", [])),
                    "selected_session": (snapshot.get("selected") or {}).get("session_id"),
                    "events": len(snapshot.get("events", [])),
                    "error": snapshot.get("error") or "",
                    "timestamp": utc_now(),
                },
                sort_keys=True,
            ),
            flush=True,
        )
        return 0 if snapshot.get("ok") else 1

    server = build_server(args.host, args.port, config)
    print(
        json.dumps(
            {
                "service": "monitor_web",
                "host": args.host,
                "port": args.port,
                "db_path": config.db_path,
                "database": _monitor_database_descriptor(config),
                "reports_dir": config.reports_dir,
            },
            sort_keys=True,
        ),
        flush=True,
    )
    serve_http_until_stopped(server)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
