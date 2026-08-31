from __future__ import annotations

import json
import math
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from numbers import Integral, Real
from pathlib import Path
from typing import Any, Dict, List, Optional

from production.storage.contract import DatabaseSettings
from production.ai_advisory.security import (
    load_provider_alias_key,
    read_secure_utf8,
    validate_activation_receipt,
    validate_https_endpoint,
)
from production.ai_advisory.google_vertex_provider import (
    ADAPTER_REVISION as GOOGLE_VERTEX_ADAPTER_REVISION,
    PROVIDER_ID as GOOGLE_VERTEX_PROVIDER_ID,
    REVIEWED_API_VERSION as GOOGLE_VERTEX_API_VERSION,
    REVIEWED_ENDPOINT as GOOGLE_VERTEX_ENDPOINT,
    REVIEWED_LOCATION as GOOGLE_VERTEX_LOCATION,
    REVIEWED_MODEL_ID as GOOGLE_VERTEX_MODEL_ID,
    load_google_adc_credentials,
    normalize_vertex_request_options,
    validate_vertex_project,
)
from production.storage.session_provenance import (
    SESSION_SOURCE_PRODUCTION_LIVE,
    normalize_session_source,
)
from production.prediction.evidence_cutoff import require_valid_evidence_cutoff
from production.utils.http_security import parse_bearer_token


def _validate_ai_request_options(value: Any) -> Dict[str, Any]:
    """Validate provider request options without accepting secret material."""
    if not isinstance(value, Mapping):
        raise ValueError("ai_advisory_request_options must be a JSON object")
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("ai_advisory_request_options must be JSON-safe") from exc
    if len(encoded.encode("utf-8")) > 8192:
        raise ValueError("ai_advisory_request_options exceeds 8192 bytes")

    def walk(item: Any) -> None:
        if isinstance(item, Mapping):
            for key, child in item.items():
                text = str(key).strip().lower().replace("-", "_")
                parts = set(text.split("_"))
                if (
                    "api_key" in text
                    or "apikey" in text
                    or parts
                    & {"authorization", "credential", "password", "secret", "token"}
                ):
                    raise ValueError(
                        "ai_advisory_request_options must not contain secret or credential keys"
                    )
                walk(child)
        elif isinstance(item, list):
            for child in item:
                walk(child)

    walk(value)
    return dict(value)


def _apply_ai_environment_overrides(values: Mapping[str, Any]) -> Dict[str, Any]:
    """Apply AI environment overrides before dataclass validation.

    ``ProductionConfig.__post_init__`` validates direct construction.  The
    environment-aware constructor must therefore merge AI overrides before
    constructing the dataclass, otherwise an enabled file configuration cannot
    supply its provider/model/key through the environment.
    """
    result = dict(values)
    result["enable_ai_advisory"] = _env_bool(
        "ENABLE_AI_ADVISORY", bool(result.get("enable_ai_advisory", False))
    )
    result["ai_advisory_provider"] = os.getenv(
        "AI_ADVISORY_PROVIDER", str(result.get("ai_advisory_provider") or "disabled")
    ).strip().lower()
    for env_name, field_name in (
        ("AI_ADVISORY_MODEL", "ai_advisory_model"),
        ("AI_ADVISORY_PROJECT", "ai_advisory_project"),
        ("AI_ADVISORY_LOCATION", "ai_advisory_location"),
        ("AI_ADVISORY_POLICY_PATH", "ai_advisory_policy_path"),
        ("AI_ADVISORY_API_KEY_FILE", "ai_advisory_api_key_file"),
        ("AI_ADVISORY_FIXTURE_RESPONSE_PATH", "ai_advisory_fixture_response_path"),
        ("AI_ADVISORY_ENDPOINT", "ai_advisory_endpoint"),
        ("AI_ADVISORY_API_VERSION", "ai_advisory_api_version"),
        ("AI_ADVISORY_ADAPTER_REVISION", "ai_advisory_adapter_revision"),
        ("AI_ADVISORY_ACTIVATION_RECEIPT_PATH", "ai_advisory_activation_receipt_path"),
        ("AI_ADVISORY_ALIAS_KEY_FILE", "ai_advisory_alias_key_file"),
    ):
        if env_name in os.environ:
            result[field_name] = os.environ[env_name]
    for env_name, field_name in (
        ("AI_ADVISORY_BATCH_SIZE", "ai_advisory_batch_size"),
        ("AI_ADVISORY_MAX_ATTEMPTS", "ai_advisory_max_attempts"),
        ("AI_ADVISORY_MAX_RESPONSE_BYTES", "ai_advisory_max_response_bytes"),
        ("AI_ADVISORY_MAX_REQUEST_BYTES", "ai_advisory_max_request_bytes"),
        ("AI_ADVISORY_MAX_REQUEST_TOKENS", "ai_advisory_max_request_tokens"),
        ("AI_ADVISORY_RETENTION_DAYS", "ai_advisory_retention_days"),
        ("AI_ADVISORY_MAX_QUEUE_RECORDS", "ai_advisory_max_queue_records"),
        ("AI_ADVISORY_MAX_RECORDS", "ai_advisory_max_records"),
        ("AI_ADVISORY_MAX_STORAGE_BYTES", "ai_advisory_max_storage_bytes"),
        ("AI_ADVISORY_RECONCILE_BATCH_SIZE", "ai_advisory_reconcile_batch_size"),
    ):
        if env_name in os.environ:
            result[field_name] = int(os.environ[env_name])
    for env_name, field_name in (
        ("AI_ADVISORY_POLL_SECONDS", "ai_advisory_poll_seconds"),
        ("AI_ADVISORY_LEASE_SECONDS", "ai_advisory_lease_seconds"),
        ("AI_ADVISORY_LEASE_HEARTBEAT_SECONDS", "ai_advisory_lease_heartbeat_seconds"),
        ("AI_ADVISORY_TIMEOUT_SECONDS", "ai_advisory_timeout_seconds"),
        ("AI_ADVISORY_RETRY_BASE_SECONDS", "ai_advisory_retry_base_seconds"),
        ("AI_ADVISORY_RETRY_MAX_SECONDS", "ai_advisory_retry_max_seconds"),
    ):
        if env_name in os.environ:
            result[field_name] = float(os.environ[env_name])
    if "AI_ADVISORY_REQUEST_OPTIONS_JSON" in os.environ:
        result["ai_advisory_request_options"] = _env_json(
            "AI_ADVISORY_REQUEST_OPTIONS_JSON",
            result.get("ai_advisory_request_options") or {},
        )
    if "AI_ADVISORY_ALLOWED_HOSTS_JSON" in os.environ:
        result["ai_advisory_allowed_hosts"] = _env_json_string_list(
            "AI_ADVISORY_ALLOWED_HOSTS_JSON",
            result.get("ai_advisory_allowed_hosts") or [],
        )
    if "AI_ADVISORY_RECONCILIATION_CUTOFF_JSON" in os.environ:
        result["ai_advisory_reconciliation_cutoff"] = _env_json(
            "AI_ADVISORY_RECONCILIATION_CUTOFF_JSON",
            result.get("ai_advisory_reconciliation_cutoff") or {},
        )
    return result


def _read_secret_file(path_text: str, name: str) -> str:
    path = Path(path_text)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError(f"{name}_FILE is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{name}_FILE must name a regular non-symlink file")
    if metadata.st_mode & 0o077:
        raise ValueError(f"{name}_FILE must not grant group or other permissions")
    if metadata.st_size > 1024 * 1024:
        raise ValueError(f"{name}_FILE exceeds the 1 MiB limit")
    try:
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"{name}_FILE cannot be read as UTF-8") from exc
    if not value:
        raise ValueError(f"{name}_FILE must not be empty")
    return value


def _env_secret(name: str, default: str = "") -> str:
    file_variable = f"{name}_FILE"
    path_text = os.getenv(file_variable, "").strip()
    if path_text:
        if name in os.environ:
            raise ValueError(f"{name} and {file_variable} cannot both be set")
        return _read_secret_file(path_text, name)
    return os.getenv(name, default)


def _env_secret_json(name: str, default: Dict[str, Any]) -> Dict[str, Any]:
    raw = _env_secret(name, "")
    if not raw:
        return dict(default)
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError(f"{name} must be a JSON object")
    return parsed


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(
        f"{name} must be one of true/false, 1/0, yes/no, or on/off"
    )


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    return int(raw)


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    return float(raw)


def _env_json(name: str, default: Dict[str, Any]) -> Dict[str, Any]:
    raw = os.getenv(name)
    if not raw:
        return dict(default)
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError(f"{name} must be a JSON object")
    return parsed


def _env_json_list(name: str, default: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    raw = os.getenv(name)
    if not raw:
        return [dict(item) for item in default]
    parsed = json.loads(raw)
    if not isinstance(parsed, list) or not all(isinstance(item, dict) for item in parsed):
        raise ValueError(f"{name} must be a JSON list of objects")
    return [dict(item) for item in parsed]


def _env_json_string_list(name: str, default: List[str]) -> List[str]:
    raw = os.getenv(name)
    if not raw:
        return [str(item) for item in default]
    parsed = json.loads(raw)
    if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
        raise ValueError(f"{name} must be a JSON list of strings")
    return list(parsed)


def _token_mapping(value: Dict[str, Any], name: str) -> Dict[str, str]:
    normalized: Dict[str, str] = {}
    for raw_identity, raw_token in value.items():
        identity = str(raw_identity).strip()
        token = raw_token if isinstance(raw_token, str) else ""
        if (
            not identity
            or not token
            or parse_bearer_token(f"Bearer {token}") != token
        ):
            raise ValueError(
                f"{name} must map non-empty identities to valid Bearer token strings"
            )
        if identity in normalized:
            raise ValueError(f"{name} contains duplicate normalized identities")
        normalized[identity] = token
    return normalized


def _split_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, tuple):
        return [str(item).strip() for item in value if str(item).strip()]
    raw = str(value or "").strip()
    if not raw:
        return []
    separator = "," if "," in raw else ";"
    return [item.strip() for item in raw.split(separator) if item.strip()]


def _env_list(name: str, default: Any) -> List[str]:
    raw = os.getenv(name)
    if raw is None:
        return _split_list(default)
    if not raw.strip():
        return []
    if raw.strip().startswith("["):
        parsed = json.loads(raw)
        if not isinstance(parsed, list):
            raise ValueError(f"{name} must be a JSON list or separated string")
        return [str(item).strip() for item in parsed if str(item).strip()]
    return _split_list(raw)


def _merge_dict(base: Dict[str, Any], overrides: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base)
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_dict(merged[key], value)
        else:
            merged[key] = value
    return merged


def _load_prediction_policy_file(path_text: str, current: Dict[str, Any]) -> Dict[str, Any]:
    if not path_text:
        return dict(current)
    path = Path(path_text)
    if not path.exists():
        raise FileNotFoundError(f"prediction policy file not found: {path}")
    with path.open("r", encoding="utf-8") as f:
        loaded = json.load(f)
    if not isinstance(loaded, dict):
        raise ValueError("prediction policy file must contain a JSON object")
    policy = loaded.get("policy", loaded)
    if not isinstance(policy, dict):
        raise ValueError("prediction policy file field 'policy' must be a JSON object")
    merged = _merge_dict(current, policy)
    metadata = {
        "source": str(path),
        "schema_version": loaded.get("schema_version", ""),
        "policy_id": loaded.get("policy_id", ""),
        "version": loaded.get("version", ""),
        "updated_at": loaded.get("updated_at", ""),
        "owner": loaded.get("owner", ""),
    }
    merged["policy_metadata"] = {k: v for k, v in metadata.items() if v}
    return merged


@dataclass
class ProductionConfig:
    """Single runtime config object for production services."""

    environment: str = "pilot"
    sensor_id: str = "demo-sensor"
    session_source: str = SESSION_SOURCE_PRODUCTION_LIVE
    api_token: str = ""
    ingest_sensor_tokens: Dict[str, str] = field(default_factory=dict)

    # MongoDB activation is fail-closed behind owner-only URI, rollback mirror,
    # and reviewed epoch-receipt paths. ``database_url`` remains SQLite-only.
    database_backend: str = ""
    sqlite_database_path: str = ""
    database_url: str = ""
    mongodb_uri_file: str = ""
    rollback_sqlite_database_path: str = ""
    storage_epoch_receipt_path: str = ""
    ingest_host: str = "127.0.0.1"
    ingest_port: int = 8080
    ingest_max_body_bytes: int = 5 * 1024 * 1024
    ingest_max_batch_events: int = 500
    ingest_max_event_bytes: int = 256 * 1024
    ingest_request_timeout_seconds: float = 15.0
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 8081
    dashboard_read_token: str = ""
    dashboard_write_token: str = ""
    # Separate administrator credential for the private monitor command view.
    # It is intentionally not shared with public/read or feedback credentials.
    monitor_raw_commands_token: str = ""
    monitor_allow_feedback: bool = False

    cowrie_log_path: str = "data/samples/demo_cowrie_realistic.json"
    spool_path: str = "sensor_spool.ndjson"
    ingest_url: str = "http://127.0.0.1:8080/events"
    forwarder_batch_size: int = 50
    forwarder_poll_seconds: float = 2.0
    forwarder_timeout_seconds: int = 15
    forwarder_max_spool_bytes: int = 64 * 1024 * 1024
    forwarder_min_free_bytes: int = 32 * 1024 * 1024
    forwarder_max_line_bytes: int = 256 * 1024
    forwarder_quarantine_path: str = ""
    forwarder_max_quarantine_bytes: int = 16 * 1024 * 1024
    forwarder_max_quarantine_events: int = 1_000

    worker_batch_size: int = 100
    worker_poll_seconds: float = 2.0
    active_session_recovery_limit: int = 10_000
    campaign_profile_cache_limit: int = 10_000
    session_event_history_limit: int = 10_000
    canonical_evidence_max_events: int = 100_000
    event_lease_seconds: float = 60.0
    event_lease_heartbeat_seconds: float = 20.0
    event_max_attempts: int = 5
    event_retry_base_seconds: float = 5.0
    event_retry_max_seconds: float = 300.0
    worker_leader_lease_seconds: float = 90.0
    worker_leader_heartbeat_seconds: float = 10.0
    job_lease_seconds: float = 600.0
    job_lease_heartbeat_seconds: float = 60.0
    job_retry_base_seconds: float = 30.0
    job_retry_max_seconds: float = 1800.0
    prediction_outbox_batch_size: int = 20
    prediction_outbox_lease_seconds: float = 60.0
    prediction_outbox_max_attempts: int = 5
    prediction_outbox_retry_base_seconds: float = 10.0
    prediction_outbox_retry_max_seconds: float = 600.0
    threat_hunt_batch_size: int = 20
    threat_hunt_poll_seconds: float = 10.0
    threat_hunt_max_attempts: int = 3
    analysis_batch_size: int = 1
    analysis_max_attempts: int = 3
    analysis_max_tokens: int = 4000
    analysis_fallback_on_failure: bool = True
    analysis_skip_empty_sessions: bool = True
    analysis_suppress_stdout: bool = True

    # Optional post-persistence AI advisory.  No provider is selected by
    # default and this path never participates in canonical analysis.
    enable_ai_advisory: bool = False
    ai_advisory_provider: str = "disabled"
    ai_advisory_model: str = ""
    ai_advisory_project: str = ""
    ai_advisory_location: str = ""
    ai_advisory_policy_path: str = "configs/ai_advisory_policy.v1.json"
    ai_advisory_api_key_file: str = ""
    ai_advisory_fixture_response_path: str = ""
    ai_advisory_endpoint: str = ""
    ai_advisory_api_version: str = ""
    ai_advisory_adapter_revision: str = "provider-neutral.v1"
    ai_advisory_activation_receipt_path: str = ""
    ai_advisory_alias_key_file: str = ""
    ai_advisory_allowed_hosts: List[str] = field(default_factory=list)
    ai_advisory_request_options: Dict[str, Any] = field(default_factory=dict)
    ai_advisory_batch_size: int = 5
    ai_advisory_poll_seconds: float = 5.0
    ai_advisory_lease_seconds: float = 60.0
    ai_advisory_lease_heartbeat_seconds: float = 20.0
    ai_advisory_max_attempts: int = 3
    ai_advisory_timeout_seconds: float = 20.0
    ai_advisory_retry_base_seconds: float = 30.0
    ai_advisory_retry_max_seconds: float = 900.0
    ai_advisory_max_response_bytes: int = 65536
    ai_advisory_max_request_bytes: int = 65536
    ai_advisory_max_request_tokens: int = 16384
    ai_advisory_retention_days: int = 30
    ai_advisory_max_queue_records: int = 10_000
    ai_advisory_max_records: int = 50_000
    ai_advisory_max_storage_bytes: int = 256 * 1024 * 1024
    ai_advisory_reconcile_batch_size: int = 100
    ai_advisory_reconciliation_cutoff: Dict[str, str] = field(default_factory=dict)

    webhook_url: str = ""
    webhook_targets: List[Dict[str, Any]] = field(default_factory=list)
    webhook_signing_key_file: str = ""
    webhook_timeout_seconds: int = 15
    webhook_dns_timeout_seconds: float = 5.0
    webhook_max_attempts: int = 5
    webhook_retry_seconds: float = 30.0
    webhook_lease_seconds: float = 60.0
    webhook_max_response_bytes: int = 4096
    webhook_allowed_schemes: List[str] = field(default_factory=lambda: ["https"])
    webhook_allow_private_networks: bool = False
    webhook_policy: Dict[str, Any] = field(default_factory=lambda: {
        "min_severity": "high",
        "alert_type_min_severity": {
            "threat_hunt_match": "medium",
        },
    })

    enrichment_db_path: str = ""
    local_enrichment_max_bytes: int = 16 * 1024 * 1024
    local_enrichment_max_records: int = 100_000
    enable_enrichment_jobs: bool = True
    external_enrichment_profile: str = "disabled"
    enrichment_batch_size: int = 20
    enrichment_max_attempts: int = 3
    enrichment_retry_seconds: float = 300.0
    enrichment_ttl_seconds: int = 86400
    enrichment_allow_stale: bool = False
    enrichment_provider_timeout_seconds: float = 20.0
    enrichment_provider_workers: int = 4
    enrichment_provider_http_retries: int = 1
    enrichment_provider_retry_delay_seconds: float = 0.25
    enrichment_provider_max_response_bytes: int = 1024 * 1024
    otx_api_key: str = ""
    abuseipdb_api_key: str = ""
    shodan_api_key: str = ""
    virustotal_api_key: str = ""
    censys_api_id: str = ""
    censys_api_secret: str = ""
    censys_platform_token: str = ""
    censys_organization_id: str = ""
    response_guidance_policy_path: str = "configs/response_guidance_policy.v3.json"
    response_guidance_asset_profile_path: str = ""
    enable_response_guidance: bool = True
    cisa_cache_path: str = ""
    sigma_cache_path: str = ""
    mitre_attack_path: str = ""
    runtime_feed_provenance_path: str = ""
    enable_feed_loading: bool = True
    enable_securebert: bool = True
    securebert_model_path: str = "models/securebert_ttp"
    securebert_checkpoint_path: str = ""
    securebert_device: str = "auto"
    securebert_max_length: int = 128
    reports_dir: str = "reports"
    enable_artifacts: bool = True
    enable_pdf_export: bool = True
    enable_stix_export: bool = True
    actor_db_path: str = ""
    enable_actor_attribution: bool = False
    classification_policy: Dict[str, Any] = field(default_factory=lambda: {
        "strategy": "notebook_merge",
        "bert_min_confidence": 0.55,
        "keyword_fallback_on_low_confidence": True,
        "keyword_fallback_on_error": True,
        "rule_review_mode": "reviewed_only",
        # Optional frozen S1 LinearSVC metadata.  Disabled by default so the
        # established deterministic/legacy classifier path is unchanged.
        "s1_advisory_enabled": False,
        "s1_advisory_model_path": "",
    })
    classification_rules_path: str = "configs/classification_rules.trusted.json"
    classifier_environment_path: str = "configs/next_behavior_classifier_environment.v1.json"
    threat_hypothesis_behavior_policy_path: str = "configs/threat_hypothesis_behavior.trusted.json"
    prediction_policy_path: str = "configs/prediction_policy.trusted.json"
    data_lifecycle_policy_path: str = "configs/data_lifecycle_policy.v1.json"
    alert_authority_policy_path: str = "configs/alert_authority_policy.v1.json"
    prediction_snapshot_retention_days: int = 90
    prediction_snapshot_keep_latest_per_session: bool = True
    enable_session_ttp_correlation: bool = True
    session_ttp_correlation_policy_path: str = "configs/session_ttp_correlation.trusted.json"
    session_ttp_knowledge_pack_paths: List[str] = field(default_factory=list)
    calibration_policy: Dict[str, Any] = field(default_factory=lambda: {
        "enabled": True,
        "output_path": "configs/calibration_output.json",
        "min_feedback_rows": 200,
        "min_backtest_cases": 50,
        "max_weight_step": 0.05,
        "feedback_limit": 500,
        "allowed_weight_feedback_types": ["auto_evidence", "expert_review"],
        "allowed_calibration_evidence_origins": ["live_cowrie", "expert_review"],
        "min_auto_evidence_confidence": 0.9,
        "operator_feedback_affects_weights": False,
        "feedback_case_weight": 2.0,
        "backtest_case_weight": 1.0,
        "apply_output": False,
    })
    threat_hunt_policy: Dict[str, Any] = field(default_factory=lambda: {
        "enabled": True,
        "enqueue_on_session_close": True,
        "signal_active_sessions": True,
        "max_jobs_per_session": 50,
        "max_related_sessions_per_job": 100,
        "observable_types": ["ip", "url", "domain", "hash", "hassh", "ja3"],
        "include_private_ips": True,
        "include_source_ip_without_activity": False,
        "min_commands_for_source_ip": 1,
        "confidence_by_observable_type": {
            "hash": 0.95,
            "url": 0.90,
            "domain": 0.80,
            "hassh": 0.75,
            "ja3": 0.75,
            "ip": 0.65,
        },
        "severity_by_observable_type": {
            "hash": "high",
            "url": "high",
            "domain": "medium",
            "hassh": "medium",
            "ja3": "medium",
            "ip": "medium",
        },
        "tactic_severity": {
            "credential-access": "medium",
            "defense-evasion": "medium",
            "command-and-control": "high",
            "persistence": "high",
            "privilege-escalation": "high",
            "lateral-movement": "critical",
            "exfiltration": "critical",
            "impact": "critical",
        },
    })
    campaign_policy: Dict[str, Any] = field(default_factory=lambda: {
        "enabled": True,
        "cluster_active_sessions": True,
        "cluster_closed_sessions": True,
        "min_commands_active": 1,
        "min_commands_closed": 1,
        "min_match_score": 0.35,
        "min_match_raw_score": 0.25,
        "min_independent_evidence_classes": 1,
        "allow_source_ip_only_match": False,
        "source_ip_only_confidence": 0.2,
        "max_matches": 10,
        "command_pattern_command_limit": 6,
        "command_pattern_token_limit": 3,
        "emit_observational_signals": True,
        "confidence_semantics": "developer_defined_heuristic_policy_strength_not_probability",
        "strength_semantics": "developer_defined_heuristic_policy_strength_not_probability",
        "numeric_provenance": "PROJECT_LOCAL_HEURISTIC",
        "field_weights": {
            "hassh_fingerprint": 0.45,
            "ja3_fingerprint": 0.35,
            "command_pattern_hash": 0.30,
            "tactic_sequence_hash": 0.25,
            "source_ip": 0.20,
        },
        "tactic_severity": {
            "credential-access": "medium",
            "defense-evasion": "medium",
            "command-and-control": "high",
            "persistence": "high",
            "privilege-escalation": "high",
            "lateral-movement": "critical",
            "exfiltration": "critical",
            "impact": "critical",
        },
    })
    prediction_policy: Dict[str, Any] = field(default_factory=lambda: {
        "enabled": True,
        "prediction_mode": "external_hard_backoff_vomm",
        "compute_weighted_ensemble_baseline": False,
        "weight_influence_scope": "not_applicable_external_authority",
        "primary_transition": {
            "primary_model": "external_hard_backoff_vomm",
            "source_order": ["external_seed_transition"],
            "fallback_scorer": "",
            "min_transition_score": 0.01,
        },
        "max_hypotheses": 5,
        "min_score": 0.01,
        "min_sessions_for_local": 50,
        "min_transition_count": 2,
        "transition_history_limit": 500,
        "external_transition_model_path": "",
        "external_min_sessions": 50,
        "external_min_transition_count": 2,
        "recency_decay_half_life_sessions": 0,
        "technique_to_tactic_aggregation": "max",
        "technique_tactic_map": {},
        "min_prefix_transition_count": 2,
        "min_technique_transition_count": 2,
        "min_tactic_transition_count": 2,
        "min_active_scorers": 1,
        "below_minimum_behavior": "low_confidence_flag",
        "confidence_damping": {
            "enabled": True,
            "mode": "geometric_mean",
            "damped_scorers": [
                "local_transition",
                "external_seed_transition",
                "actor_fingerprint_transition",
                "fallback_progression",
                "tactic_combination",
                "mitre_association",
            ],
        },
        "weights": {
            "local_transition": 0.30,
            "external_seed_transition": 0.20,
            "actor_fingerprint_transition": 0.0,
            "fallback_progression": 0.10,
            "tactic_combination": 0.12,
            "mitre_association": 0.13,
            "sigma_correlation": 0.05,
            "enrichment_context": 0.10,
        },
        "enrichment_context_mode": "scorer",
        "enrichment_context_multiplier": {
            "max_multiplier": 1.15,
            "min_enrichment_score": 0.01,
        },
        "external_seed_weight_decay": {
            "enabled": True,
            "method": "maturity_multiplier",
            "cold": 1.0,
            "warming": 0.5,
            "stable": 0.2,
            "shrinkage_count_source": "transitions",
            "shrinkage_k": 200.0,
            "min_multiplier": 0.0,
            "max_multiplier": 1.0,
        },
        "actor_fingerprint_prior": {
            "enabled": False,
            "match_fields": ["hassh_fingerprint", "ja3_fingerprint", "command_pattern_hash"],
            "min_sessions": 2,
            "min_transition_count": 1,
            "min_prefix_transition_count": 1,
            "min_tactic_transition_count": 1,
            "prefix_max_length": 3,
            "smoothing": 0.05,
            "history_limit": 500,
            "model_path": "",
            "comparison_weight": 0.15,
        },
        "behavior_regime_classifier": {
            "enabled": True,
            "min_commands": 2,
            "automated_command_rate_per_minute": 8.0,
            "human_command_rate_per_minute": 1.5,
            "low_delay_variance_seconds2": 4.0,
            "high_delay_variance_seconds2": 900.0,
            "high_entropy_bits_per_char": 4.2,
            "low_entropy_bits_per_char": 2.5,
            "low_payload_diversity": 0.40,
            "high_payload_diversity": 0.80,
            "automated_threshold": 0.65,
            "human_threshold": 0.35,
            "feature_weights": {
                "command_frequency": 0.35,
                "delay_regularity": 0.25,
                "command_entropy": 0.20,
                "payload_repetition": 0.20,
            },
        },
        "confidence_controls": {
            "enabled": True,
            "single_active_scorer_cap": "medium",
            "single_supporting_scorer_cap": "medium",
            "external_seed_only_cap": "low",
            "external_seed_dominated_cap": "medium",
            "context_only_cap": "low",
            "medium_divergence_ratio": 0.5,
            "medium_divergence_cap": "medium",
            "high_divergence_ratio": 0.75,
            "high_divergence_cap": "low",
            "low_classification_geomean": 0.65,
            "unknown_or_noise_ratio": 0.4,
            "low_classification_cap": "low",
        },
        "prediction_triggers": {
            "enabled": True,
            "eventids": [
                "cowrie.login.success",
                "cowrie.login.failed",
                "cowrie.session.file_download",
                "cowrie.session.file_upload",
                "cowrie.session.closed",
            ],
            "eventid_prefixes": ["cowrie.command."],
        },
        "predictive_alerts": {
            "enabled": True,
            "min_confidence": "medium",
            "min_score": 0.50,
            "min_severity": "high",
            "min_active_scorers": 1,
            "min_supporting_scorers": 1,
            "block_on_coverage_below_minimum": True,
            "max_divergence_ratio": 0.5,
            "block_external_seed_only": True,
            "block_context_only": True,
            "alert_on_session_status": ["active"],
            "max_alerts_per_snapshot": 1,
            "risk_annotation_severity_boost": {
                "enabled": False,
                "min_risk_level": "high",
                "boost_high_to_critical": False,
            },
            "tactic_severity": {
                "credential-access": "medium",
                "defense-evasion": "medium",
                "command-and-control": "high",
                "persistence": "high",
                "privilege-escalation": "high",
                "lateral-movement": "critical",
                "exfiltration": "critical",
                "impact": "critical",
            },
        },
        "mitre_association_rules": [],
        "sigma_correlation_rules": [],
        "rule_prior_deduplication": {
            "enabled": True,
            "method": "max_contribution",
            "scorers": ["tactic_combination", "mitre_association"],
            "require_shared_evidence_key": True,
        },
        "risk_annotators": {
            "vulnerability_risk": {
                "enabled": True,
            },
        },
    })
    credential_policy: Dict[str, Any] = field(default_factory=lambda: {
        "store_raw_credentials": False,
        "redaction": "[REDACTED]",
        "hash_algorithm": "hmac-sha256-v1",
        "sanitize_raw_events": True,
        "redact_fields": ["password", "passwd"],
    })
    credential_hmac_keyring_file: str = ""

    def __post_init__(self) -> None:
        self._apply_database_settings(self.database_settings())
        self.validate_event_processing()

    def validate_event_processing(self) -> None:
        """Reject unsafe event-processing lease and retry configuration."""
        positive_durations = {
            "forwarder_poll_seconds": self.forwarder_poll_seconds,
            "forwarder_timeout_seconds": self.forwarder_timeout_seconds,
            "webhook_timeout_seconds": self.webhook_timeout_seconds,
            "webhook_dns_timeout_seconds": self.webhook_dns_timeout_seconds,
            "webhook_retry_seconds": self.webhook_retry_seconds,
            "webhook_lease_seconds": self.webhook_lease_seconds,
            "event_lease_seconds": self.event_lease_seconds,
            "event_lease_heartbeat_seconds": self.event_lease_heartbeat_seconds,
            "event_retry_base_seconds": self.event_retry_base_seconds,
            "event_retry_max_seconds": self.event_retry_max_seconds,
            "worker_leader_lease_seconds": self.worker_leader_lease_seconds,
            "worker_leader_heartbeat_seconds": self.worker_leader_heartbeat_seconds,
            "job_lease_seconds": self.job_lease_seconds,
            "job_lease_heartbeat_seconds": self.job_lease_heartbeat_seconds,
            "job_retry_base_seconds": self.job_retry_base_seconds,
            "job_retry_max_seconds": self.job_retry_max_seconds,
            "prediction_outbox_lease_seconds": self.prediction_outbox_lease_seconds,
            "prediction_outbox_retry_base_seconds": self.prediction_outbox_retry_base_seconds,
            "prediction_outbox_retry_max_seconds": self.prediction_outbox_retry_max_seconds,
            "enrichment_provider_timeout_seconds": self.enrichment_provider_timeout_seconds,
            "ai_advisory_poll_seconds": self.ai_advisory_poll_seconds,
            "ai_advisory_lease_seconds": self.ai_advisory_lease_seconds,
            "ai_advisory_lease_heartbeat_seconds": self.ai_advisory_lease_heartbeat_seconds,
            "ai_advisory_timeout_seconds": self.ai_advisory_timeout_seconds,
            "ai_advisory_retry_base_seconds": self.ai_advisory_retry_base_seconds,
            "ai_advisory_retry_max_seconds": self.ai_advisory_retry_max_seconds,
        }
        for name, value in positive_durations.items():
            if (
                isinstance(value, bool)
                or not isinstance(value, Real)
                or not math.isfinite(float(value))
                or value <= 0
            ):
                raise ValueError(f"{name} must be a positive finite number")

        positive_forwarder_integers = {
            "forwarder_batch_size": self.forwarder_batch_size,
            "forwarder_max_spool_bytes": self.forwarder_max_spool_bytes,
            "forwarder_max_line_bytes": self.forwarder_max_line_bytes,
            "forwarder_max_quarantine_bytes": self.forwarder_max_quarantine_bytes,
            "forwarder_max_quarantine_events": self.forwarder_max_quarantine_events,
        }
        for name, value in positive_forwarder_integers.items():
            if isinstance(value, bool) or not isinstance(value, Integral) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if self.forwarder_max_line_bytes > 1024 * 1024:
            raise ValueError("forwarder_max_line_bytes must not exceed 1048576 bytes")
        if self.forwarder_max_quarantine_bytes < 1024:
            raise ValueError(
                "forwarder_max_quarantine_bytes must be at least 1024 bytes"
            )
        if self.forwarder_max_quarantine_events > 100_000:
            raise ValueError(
                "forwarder_max_quarantine_events must not exceed 100000"
            )
        if self.forwarder_quarantine_path and (
            os.path.abspath(os.path.expanduser(self.forwarder_quarantine_path))
            == os.path.abspath(os.path.expanduser(self.spool_path))
        ):
            raise ValueError("forwarder quarantine path must differ from spool path")
        if (
            isinstance(self.forwarder_min_free_bytes, bool)
            or not isinstance(self.forwarder_min_free_bytes, Integral)
            or self.forwarder_min_free_bytes < 0
        ):
            raise ValueError("forwarder_min_free_bytes must be a non-negative integer")
        if (
            isinstance(self.webhook_max_attempts, bool)
            or not isinstance(self.webhook_max_attempts, Integral)
            or not 1 <= self.webhook_max_attempts <= 100
        ):
            raise ValueError("webhook_max_attempts must be an integer between 1 and 100")
        if (
            isinstance(self.enrichment_provider_workers, bool)
            or not isinstance(self.enrichment_provider_workers, Integral)
            or not 1 <= self.enrichment_provider_workers <= 16
        ):
            raise ValueError(
                "enrichment_provider_workers must be an integer between 1 and 16"
            )
        if (
            isinstance(self.enrichment_provider_http_retries, bool)
            or not isinstance(self.enrichment_provider_http_retries, Integral)
            or not 0 <= self.enrichment_provider_http_retries <= 5
        ):
            raise ValueError(
                "enrichment_provider_http_retries must be an integer between 0 and 5"
            )
        if (
            isinstance(self.enrichment_provider_max_response_bytes, bool)
            or not isinstance(self.enrichment_provider_max_response_bytes, Integral)
            or not 1024 <= self.enrichment_provider_max_response_bytes <= 16 * 1024 * 1024
        ):
            raise ValueError(
                "enrichment_provider_max_response_bytes must be between 1024 and 16777216"
            )
        for name, value, maximum in (
            ("local_enrichment_max_bytes", self.local_enrichment_max_bytes, 256 * 1024 * 1024),
            ("local_enrichment_max_records", self.local_enrichment_max_records, 1_000_000),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, Integral)
                or not 1 <= value <= maximum
            ):
                raise ValueError(
                    f"{name} must be an integer between 1 and {maximum}"
                )
        if self.external_enrichment_profile not in {
            "disabled",
            "non_ip_observables",
        }:
            raise ValueError(
                "external_enrichment_profile must be disabled or "
                "non_ip_observables"
            )
        if (
            isinstance(self.enrichment_provider_retry_delay_seconds, bool)
            or not isinstance(self.enrichment_provider_retry_delay_seconds, Real)
            or not math.isfinite(float(self.enrichment_provider_retry_delay_seconds))
            or self.enrichment_provider_retry_delay_seconds < 0
        ):
            raise ValueError(
                "enrichment_provider_retry_delay_seconds must be non-negative and finite"
            )
        if (
            isinstance(self.webhook_max_response_bytes, bool)
            or not isinstance(self.webhook_max_response_bytes, Integral)
            or not 0 <= self.webhook_max_response_bytes <= 65536
        ):
            raise ValueError(
                "webhook_max_response_bytes must be an integer between 0 and 65536"
            )
        if not isinstance(self.webhook_targets, list) or not all(
            isinstance(item, dict) for item in self.webhook_targets
        ):
            raise ValueError("webhook_targets must be a list of objects")
        if (
            not isinstance(self.webhook_allowed_schemes, list)
            or not self.webhook_allowed_schemes
            or any(
                not isinstance(item, str) or item.strip().lower() not in {"http", "https"}
                for item in self.webhook_allowed_schemes
            )
        ):
            raise ValueError("webhook_allowed_schemes must contain only http or https")
        if self.webhook_lease_seconds <= (
            self.webhook_timeout_seconds + self.webhook_dns_timeout_seconds
        ):
            raise ValueError(
                "webhook_lease_seconds must exceed the combined DNS and request timeouts"
            )

        if (
            isinstance(self.event_max_attempts, bool)
            or not isinstance(self.event_max_attempts, Integral)
            or self.event_max_attempts < 1
        ):
            raise ValueError("event_max_attempts must be an integer of at least 1")
        if (
            isinstance(self.active_session_recovery_limit, bool)
            or not isinstance(self.active_session_recovery_limit, Integral)
            or self.active_session_recovery_limit < 1
        ):
            raise ValueError(
                "active_session_recovery_limit must be an integer of at least 1"
            )
        if (
            isinstance(self.campaign_profile_cache_limit, bool)
            or not isinstance(self.campaign_profile_cache_limit, Integral)
            or self.campaign_profile_cache_limit < 1
        ):
            raise ValueError(
                "campaign_profile_cache_limit must be an integer of at least 1"
            )
        if (
            isinstance(self.session_event_history_limit, bool)
            or not isinstance(self.session_event_history_limit, Integral)
            or self.session_event_history_limit < 1
        ):
            raise ValueError(
                "session_event_history_limit must be an integer of at least 1"
            )
        if (
            isinstance(self.canonical_evidence_max_events, bool)
            or not isinstance(self.canonical_evidence_max_events, Integral)
            or not 1 <= self.canonical_evidence_max_events <= 1_000_000
        ):
            raise ValueError(
                "canonical_evidence_max_events must be between 1 and 1000000"
            )
        if (
            not isinstance(self.classification_policy, Mapping)
            or self.classification_policy.get("strategy") != "notebook_merge"
        ):
            raise ValueError(
                "classification_policy.strategy must use the canonical "
                "notebook_merge classifier"
            )
        if self.event_lease_heartbeat_seconds >= self.event_lease_seconds:
            raise ValueError(
                "event_lease_heartbeat_seconds must be less than event_lease_seconds"
            )
        if self.worker_leader_heartbeat_seconds >= self.worker_leader_lease_seconds:
            raise ValueError(
                "worker_leader_heartbeat_seconds must be less than "
                "worker_leader_lease_seconds"
            )
        minimum_leader_lease = self.event_lease_seconds + max(
            self.event_lease_heartbeat_seconds,
            self.worker_leader_heartbeat_seconds,
        )
        if self.worker_leader_lease_seconds < minimum_leader_lease:
            raise ValueError(
                "worker_leader_lease_seconds must be at least event_lease_seconds "
                "plus the larger event or leader heartbeat interval"
            )
        if self.event_retry_max_seconds < self.event_retry_base_seconds:
            raise ValueError(
                "event_retry_max_seconds must be greater than or equal to "
                "event_retry_base_seconds"
            )
        if self.job_lease_heartbeat_seconds >= self.job_lease_seconds:
            raise ValueError(
                "job_lease_heartbeat_seconds must be less than job_lease_seconds"
            )
        if self.job_retry_max_seconds < self.job_retry_base_seconds:
            raise ValueError(
                "job_retry_max_seconds must be greater than or equal to "
                "job_retry_base_seconds"
            )
        if self.prediction_outbox_retry_max_seconds < (
            self.prediction_outbox_retry_base_seconds
        ):
            raise ValueError(
                "prediction_outbox_retry_max_seconds must be greater than or "
                "equal to prediction_outbox_retry_base_seconds"
            )
        if self.ai_advisory_lease_heartbeat_seconds >= self.ai_advisory_lease_seconds:
            raise ValueError(
                "ai_advisory_lease_heartbeat_seconds must be less than "
                "ai_advisory_lease_seconds"
            )
        if self.ai_advisory_timeout_seconds >= self.ai_advisory_lease_seconds:
            raise ValueError(
                "ai_advisory_timeout_seconds must be less than ai_advisory_lease_seconds"
            )
        if self.ai_advisory_retry_max_seconds < self.ai_advisory_retry_base_seconds:
            raise ValueError(
                "ai_advisory_retry_max_seconds must be greater than or equal to "
                "ai_advisory_retry_base_seconds"
            )
        for name, value in {
            "ai_advisory_batch_size": self.ai_advisory_batch_size,
            "ai_advisory_max_attempts": self.ai_advisory_max_attempts,
            "ai_advisory_max_response_bytes": self.ai_advisory_max_response_bytes,
            "ai_advisory_max_request_bytes": self.ai_advisory_max_request_bytes,
            "ai_advisory_max_request_tokens": self.ai_advisory_max_request_tokens,
            "ai_advisory_max_queue_records": self.ai_advisory_max_queue_records,
            "ai_advisory_max_records": self.ai_advisory_max_records,
            "ai_advisory_max_storage_bytes": self.ai_advisory_max_storage_bytes,
            "ai_advisory_reconcile_batch_size": self.ai_advisory_reconcile_batch_size,
        }.items():
            if isinstance(value, bool) or not isinstance(value, Integral) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if self.ai_advisory_max_response_bytes > 1024 * 1024:
            raise ValueError("ai_advisory_max_response_bytes must not exceed 1048576")
        if self.ai_advisory_max_request_bytes > 1024 * 1024:
            raise ValueError("ai_advisory_max_request_bytes must not exceed 1048576")
        if self.ai_advisory_max_request_tokens > 262_144:
            raise ValueError("ai_advisory_max_request_tokens must not exceed 262144")
        if isinstance(self.ai_advisory_retention_days, bool) or not isinstance(
            self.ai_advisory_retention_days, Integral
        ) or not 1 <= self.ai_advisory_retention_days <= 3650:
            raise ValueError(
                "ai_advisory_retention_days must be between 1 and 3650"
            )
        _validate_ai_request_options(self.ai_advisory_request_options)
        if self.ai_advisory_api_version and not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}",
            str(self.ai_advisory_api_version),
        ):
            raise ValueError("ai_advisory_api_version must be a safe identifier")
        if not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}",
            str(self.ai_advisory_adapter_revision or ""),
        ):
            raise ValueError("ai_advisory_adapter_revision must be a safe identifier")
        endpoint = str(self.ai_advisory_endpoint or "").strip()
        if endpoint:
            validate_https_endpoint(endpoint, self.ai_advisory_allowed_hosts)
        ai_provider = str(self.ai_advisory_provider or "").strip().lower()
        if not re.fullmatch(
            r"[a-z][a-z0-9_-]{0,63}",
            ai_provider,
        ):
            raise ValueError("ai_advisory_provider must be a safe provider identifier")
        reconciliation_cutoff: Dict[str, str] | None = None
        if self.ai_advisory_reconciliation_cutoff:
            reconciliation_cutoff = require_valid_evidence_cutoff(
                self.ai_advisory_reconciliation_cutoff
            )
            self.ai_advisory_reconciliation_cutoff = reconciliation_cutoff
        if self.enable_ai_advisory:
            if ai_provider == "disabled":
                raise ValueError(
                    "enable_ai_advisory requires an explicitly configured provider"
                )
            if not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}",
                str(self.ai_advisory_model or "").strip(),
            ):
                raise ValueError(
                    "enabled AI advisory requires a safe explicit model identifier"
                )
            if not str(self.ai_advisory_policy_path or "").strip():
                raise ValueError("enabled AI advisory requires an explicit policy path")
            if reconciliation_cutoff is None:
                raise ValueError(
                    "enabled AI advisory requires a reconciliation cutoff"
                )
            if ai_provider not in {"fixture", GOOGLE_VERTEX_PROVIDER_ID}:
                raise ValueError(
                    "configured AI advisory provider adapter is not installed and reviewed"
                )
            if ai_provider == "fixture" and not str(
                self.ai_advisory_fixture_response_path or ""
            ).strip():
                raise ValueError(
                    "fixture AI advisory provider requires a response path"
                )
            alias_key_path = str(self.ai_advisory_alias_key_file or "").strip()
            if not alias_key_path:
                raise ValueError("enabled AI advisory requires an alias key file")
            load_provider_alias_key(alias_key_path)
            receipt_path = str(self.ai_advisory_activation_receipt_path or "").strip()
            if not receipt_path:
                raise ValueError("enabled AI advisory requires an activation receipt")
            if ai_provider == GOOGLE_VERTEX_PROVIDER_ID:
                project_id = validate_vertex_project(self.ai_advisory_project)
                if str(self.ai_advisory_location or "").strip() != GOOGLE_VERTEX_LOCATION:
                    raise ValueError("Vertex AI advisory location is not reviewed")
                if str(self.ai_advisory_model or "").strip() != GOOGLE_VERTEX_MODEL_ID:
                    raise ValueError("Vertex AI advisory model is not reviewed")
                if str(self.ai_advisory_adapter_revision or "") != GOOGLE_VERTEX_ADAPTER_REVISION:
                    raise ValueError("Vertex AI advisory adapter revision is not reviewed")
                if str(self.ai_advisory_api_version or "") != GOOGLE_VERTEX_API_VERSION:
                    raise ValueError("Vertex AI advisory API version is not reviewed")
                if endpoint != GOOGLE_VERTEX_ENDPOINT:
                    raise ValueError("Vertex AI advisory endpoint is not reviewed")
                allowed_hosts = [
                    str(item or "").strip().rstrip(".").lower()
                    for item in self.ai_advisory_allowed_hosts
                ]
                if allowed_hosts != ["aiplatform.googleapis.com"]:
                    raise ValueError("Vertex AI advisory host allowlist is not exact")
                if str(self.ai_advisory_api_key_file or "").strip():
                    raise ValueError("Vertex AI ADC adapter does not accept an API key file")
                normalize_vertex_request_options(self.ai_advisory_request_options)
                load_google_adc_credentials(project_id)
            elif ai_provider != "fixture":
                secret_path = str(self.ai_advisory_api_key_file or "").strip()
                if not secret_path:
                    raise ValueError(
                        "hosted AI advisory provider requires an API key file"
                    )
                read_secure_utf8(secret_path, name="AI_ADVISORY_API_KEY")
            validate_activation_receipt(
                receipt_path,
                provider_id=ai_provider,
                model_id=str(self.ai_advisory_model or "").strip(),
                adapter_revision=str(self.ai_advisory_adapter_revision or ""),
                endpoint=endpoint,
                hosted=ai_provider != "fixture",
                reconciliation_cutoff=reconciliation_cutoff,
            )
        for name, value in {
            "prediction_outbox_batch_size": self.prediction_outbox_batch_size,
            "prediction_outbox_max_attempts": self.prediction_outbox_max_attempts,
        }.items():
            if (
                isinstance(value, bool)
                or not isinstance(value, Integral)
                or value < 1
            ):
                raise ValueError(f"{name} must be a positive integer")
        if (
            isinstance(self.threat_hunt_max_attempts, bool)
            or not isinstance(self.threat_hunt_max_attempts, Integral)
            or self.threat_hunt_max_attempts < 1
        ):
            raise ValueError("threat_hunt_max_attempts must be an integer of at least 1")
        if (
            isinstance(self.prediction_snapshot_retention_days, bool)
            or not isinstance(self.prediction_snapshot_retention_days, Integral)
            or not 0 <= self.prediction_snapshot_retention_days <= 36_500
        ):
            raise ValueError(
                "prediction_snapshot_retention_days must be between 0 and 36500"
            )

    def database_settings(self) -> DatabaseSettings:
        """Validate and return the selected storage backend settings."""
        return DatabaseSettings.from_values(
            database_backend=self.database_backend,
            database_url=self.database_url,
            sqlite_database_path=self.sqlite_database_path,
            mongodb_uri_file=self.mongodb_uri_file,
            rollback_sqlite_database_path=self.rollback_sqlite_database_path,
            storage_epoch_receipt_path=self.storage_epoch_receipt_path,
        )

    def safe_database_descriptor(self) -> Dict[str, str]:
        """Describe the selected backend without credentials or URI options."""
        return self.database_settings().safe_descriptor()

    def _apply_database_settings(self, settings: DatabaseSettings) -> None:
        self.database_backend = settings.backend
        self.database_url = settings.database_url
        self.sqlite_database_path = settings.sqlite_database_path
        self.mongodb_uri_file = settings.mongodb_uri_file
        self.rollback_sqlite_database_path = settings.rollback_sqlite_database_path
        self.storage_epoch_receipt_path = settings.storage_epoch_receipt_path

    @classmethod
    def from_env(cls, config_path: Optional[str] = None) -> "ProductionConfig":
        file_values: Dict[str, Any] = {}
        selected_path = config_path or os.getenv("HONEYPOT_CONFIG_FILE", "")
        if selected_path:
            path = Path(selected_path)
            if not path.exists():
                raise FileNotFoundError(f"production config file not found: {path}")
            with path.open("r", encoding="utf-8") as f:
                loaded = json.load(f)
            if not isinstance(loaded, dict):
                raise ValueError("production config file must contain a JSON object")
            file_values = loaded
            unknown_keys = sorted(
                set(file_values) - set(cls.__dataclass_fields__)
            )
            if unknown_keys:
                raise ValueError(
                    f"production config file contains unknown keys: {unknown_keys}"
                )

        database_backend_from_env = "DATABASE_BACKEND" in os.environ
        database_url_from_env = (
            "DATABASE_URL" in os.environ or "DATABASE_URL_FILE" in os.environ
        )
        raw_database_backend = (
            os.getenv("DATABASE_BACKEND", "")
            if database_backend_from_env
            else str(file_values.get("database_backend") or "")
        )
        raw_database_url = (
            _env_secret("DATABASE_URL", "")
            if database_url_from_env
            else (
                ""
                if database_backend_from_env
                else str(file_values.get("database_url") or "")
            )
        )
        database_settings = DatabaseSettings.from_values(
            database_backend=raw_database_backend,
            database_url=raw_database_url,
            sqlite_database_path=os.getenv(
                "SQLITE_DATABASE_PATH",
                str(file_values.get("sqlite_database_path") or ""),
            ),
            mongodb_uri_file=os.getenv(
                "MONGODB_URI_FILE", str(file_values.get("mongodb_uri_file") or "")
            ),
            rollback_sqlite_database_path=os.getenv(
                "ROLLBACK_SQLITE_DATABASE_PATH",
                str(file_values.get("rollback_sqlite_database_path") or ""),
            ),
            storage_epoch_receipt_path=os.getenv(
                "STORAGE_EPOCH_RECEIPT_PATH",
                str(file_values.get("storage_epoch_receipt_path") or ""),
            ),
        )
        config_values = {
            k: v for k, v in file_values.items() if k in cls.__dataclass_fields__
        }
        config_values.update(
            {
                "database_backend": database_settings.backend,
                "database_url": database_settings.database_url,
                "sqlite_database_path": database_settings.sqlite_database_path,
                "mongodb_uri_file": database_settings.mongodb_uri_file,
                "rollback_sqlite_database_path": database_settings.rollback_sqlite_database_path,
                "storage_epoch_receipt_path": database_settings.storage_epoch_receipt_path,
            }
        )
        config_values = _apply_ai_environment_overrides(config_values)
        cfg = cls(**config_values)
        cfg.environment = os.getenv("HONEYPOT_ENV", cfg.environment)
        cfg.sensor_id = os.getenv("SENSOR_ID", cfg.sensor_id)
        cfg.session_source = normalize_session_source(
            os.getenv("HONEYPOT_SESSION_SOURCE") or os.getenv("SESSION_SOURCE") or cfg.session_source,
            SESSION_SOURCE_PRODUCTION_LIVE,
        )
        cfg.api_token = _env_secret("HONEYPOT_API_TOKEN", cfg.api_token)
        cfg.ingest_sensor_tokens = _token_mapping(
            _env_secret_json(
                "INGEST_SENSOR_TOKENS_JSON",
                cfg.ingest_sensor_tokens,
            ),
            "INGEST_SENSOR_TOKENS_JSON",
        )
        cfg.ingest_host = os.getenv("INGEST_HOST", cfg.ingest_host)
        cfg.ingest_port = _env_int("INGEST_PORT", cfg.ingest_port)
        cfg.ingest_max_body_bytes = _env_int(
            "INGEST_MAX_BODY_BYTES",
            cfg.ingest_max_body_bytes,
        )
        cfg.ingest_max_batch_events = _env_int(
            "INGEST_MAX_BATCH_EVENTS",
            cfg.ingest_max_batch_events,
        )
        cfg.ingest_max_event_bytes = _env_int(
            "INGEST_MAX_EVENT_BYTES",
            cfg.ingest_max_event_bytes,
        )
        cfg.ingest_request_timeout_seconds = _env_float(
            "INGEST_REQUEST_TIMEOUT_SECONDS",
            cfg.ingest_request_timeout_seconds,
        )
        cfg.dashboard_host = os.getenv("DASHBOARD_HOST", cfg.dashboard_host)
        cfg.dashboard_port = _env_int("DASHBOARD_PORT", cfg.dashboard_port)
        cfg.dashboard_read_token = _env_secret(
            "DASHBOARD_READ_TOKEN",
            cfg.dashboard_read_token,
        )
        cfg.dashboard_write_token = _env_secret(
            "DASHBOARD_WRITE_TOKEN",
            cfg.dashboard_write_token,
        )
        cfg.monitor_raw_commands_token = _env_secret(
            "MONITOR_RAW_COMMANDS_TOKEN",
            cfg.monitor_raw_commands_token,
        )
        cfg.monitor_allow_feedback = _env_bool(
            "MONITOR_ALLOW_FEEDBACK",
            cfg.monitor_allow_feedback,
        )
        cfg.cowrie_log_path = os.getenv("COWRIE_LOG_PATH", cfg.cowrie_log_path)
        cfg.spool_path = os.getenv("FORWARDER_SPOOL_PATH", cfg.spool_path)
        cfg.ingest_url = os.getenv("INGEST_URL", cfg.ingest_url)
        cfg.forwarder_batch_size = _env_int("FORWARDER_BATCH_SIZE", cfg.forwarder_batch_size)
        cfg.forwarder_poll_seconds = _env_float(
            "FORWARDER_POLL_SECONDS",
            _env_float("FORWARDER_POLL_INTERVAL_SECONDS", cfg.forwarder_poll_seconds),
        )
        cfg.forwarder_timeout_seconds = _env_int("FORWARDER_TIMEOUT_SECONDS", cfg.forwarder_timeout_seconds)
        cfg.forwarder_max_spool_bytes = _env_int(
            "FORWARDER_MAX_SPOOL_BYTES", cfg.forwarder_max_spool_bytes
        )
        cfg.forwarder_min_free_bytes = _env_int(
            "FORWARDER_MIN_FREE_BYTES", cfg.forwarder_min_free_bytes
        )
        cfg.forwarder_max_line_bytes = _env_int(
            "FORWARDER_MAX_LINE_BYTES", cfg.forwarder_max_line_bytes
        )
        cfg.forwarder_quarantine_path = os.getenv(
            "FORWARDER_QUARANTINE_PATH",
            cfg.forwarder_quarantine_path,
        )
        cfg.forwarder_max_quarantine_bytes = _env_int(
            "FORWARDER_MAX_QUARANTINE_BYTES",
            cfg.forwarder_max_quarantine_bytes,
        )
        cfg.forwarder_max_quarantine_events = _env_int(
            "FORWARDER_MAX_QUARANTINE_EVENTS",
            cfg.forwarder_max_quarantine_events,
        )
        cfg.worker_batch_size = _env_int("WORKER_BATCH_SIZE", cfg.worker_batch_size)
        cfg.worker_poll_seconds = _env_float("WORKER_POLL_SECONDS", cfg.worker_poll_seconds)
        cfg.event_lease_seconds = _env_float(
            "EVENT_LEASE_SECONDS",
            cfg.event_lease_seconds,
        )
        cfg.active_session_recovery_limit = _env_int(
            "ACTIVE_SESSION_RECOVERY_LIMIT",
            cfg.active_session_recovery_limit,
        )
        cfg.campaign_profile_cache_limit = _env_int(
            "CAMPAIGN_PROFILE_CACHE_LIMIT",
            cfg.campaign_profile_cache_limit,
        )
        cfg.session_event_history_limit = _env_int(
            "SESSION_EVENT_HISTORY_LIMIT",
            cfg.session_event_history_limit,
        )
        cfg.canonical_evidence_max_events = _env_int(
            "CANONICAL_EVIDENCE_MAX_EVENTS",
            cfg.canonical_evidence_max_events,
        )
        cfg.event_lease_heartbeat_seconds = _env_float(
            "EVENT_LEASE_HEARTBEAT_SECONDS",
            cfg.event_lease_heartbeat_seconds,
        )
        cfg.event_max_attempts = _env_int(
            "EVENT_MAX_ATTEMPTS",
            cfg.event_max_attempts,
        )
        cfg.event_retry_base_seconds = _env_float(
            "EVENT_RETRY_BASE_SECONDS",
            cfg.event_retry_base_seconds,
        )
        cfg.event_retry_max_seconds = _env_float(
            "EVENT_RETRY_MAX_SECONDS",
            cfg.event_retry_max_seconds,
        )
        cfg.worker_leader_lease_seconds = _env_float(
            "WORKER_LEADER_LEASE_SECONDS",
            cfg.worker_leader_lease_seconds,
        )
        cfg.worker_leader_heartbeat_seconds = _env_float(
            "WORKER_LEADER_HEARTBEAT_SECONDS",
            cfg.worker_leader_heartbeat_seconds,
        )
        cfg.job_lease_seconds = _env_float("JOB_LEASE_SECONDS", cfg.job_lease_seconds)
        cfg.job_lease_heartbeat_seconds = _env_float(
            "JOB_LEASE_HEARTBEAT_SECONDS",
            cfg.job_lease_heartbeat_seconds,
        )
        cfg.job_retry_base_seconds = _env_float(
            "JOB_RETRY_BASE_SECONDS",
            cfg.job_retry_base_seconds,
        )
        cfg.job_retry_max_seconds = _env_float(
            "JOB_RETRY_MAX_SECONDS",
            cfg.job_retry_max_seconds,
        )
        cfg.prediction_outbox_batch_size = _env_int(
            "PREDICTION_OUTBOX_BATCH_SIZE",
            cfg.prediction_outbox_batch_size,
        )
        cfg.prediction_outbox_lease_seconds = _env_float(
            "PREDICTION_OUTBOX_LEASE_SECONDS",
            cfg.prediction_outbox_lease_seconds,
        )
        cfg.prediction_outbox_max_attempts = _env_int(
            "PREDICTION_OUTBOX_MAX_ATTEMPTS",
            cfg.prediction_outbox_max_attempts,
        )
        cfg.prediction_outbox_retry_base_seconds = _env_float(
            "PREDICTION_OUTBOX_RETRY_BASE_SECONDS",
            cfg.prediction_outbox_retry_base_seconds,
        )
        cfg.prediction_outbox_retry_max_seconds = _env_float(
            "PREDICTION_OUTBOX_RETRY_MAX_SECONDS",
            cfg.prediction_outbox_retry_max_seconds,
        )
        cfg.threat_hunt_batch_size = _env_int("THREAT_HUNT_BATCH_SIZE", cfg.threat_hunt_batch_size)
        cfg.threat_hunt_poll_seconds = _env_float("THREAT_HUNT_POLL_SECONDS", cfg.threat_hunt_poll_seconds)
        cfg.threat_hunt_max_attempts = _env_int(
            "THREAT_HUNT_MAX_ATTEMPTS",
            cfg.threat_hunt_max_attempts,
        )
        cfg.analysis_batch_size = _env_int("ANALYSIS_BATCH_SIZE", cfg.analysis_batch_size)
        cfg.analysis_max_attempts = _env_int("ANALYSIS_MAX_ATTEMPTS", cfg.analysis_max_attempts)
        cfg.analysis_max_tokens = _env_int("ANALYSIS_MAX_TOKENS", cfg.analysis_max_tokens)
        cfg.analysis_fallback_on_failure = _env_bool("ANALYSIS_FALLBACK_ON_FAILURE", cfg.analysis_fallback_on_failure)
        cfg.analysis_skip_empty_sessions = _env_bool("ANALYSIS_SKIP_EMPTY_SESSIONS", cfg.analysis_skip_empty_sessions)
        cfg.analysis_suppress_stdout = _env_bool("ANALYSIS_SUPPRESS_STDOUT", cfg.analysis_suppress_stdout)
        cfg.enable_ai_advisory = _env_bool(
            "ENABLE_AI_ADVISORY", cfg.enable_ai_advisory
        )
        cfg.ai_advisory_provider = os.getenv(
            "AI_ADVISORY_PROVIDER", cfg.ai_advisory_provider
        ).strip().lower()
        cfg.ai_advisory_model = os.getenv(
            "AI_ADVISORY_MODEL", cfg.ai_advisory_model
        )
        cfg.ai_advisory_project = os.getenv(
            "AI_ADVISORY_PROJECT", cfg.ai_advisory_project
        )
        cfg.ai_advisory_location = os.getenv(
            "AI_ADVISORY_LOCATION", cfg.ai_advisory_location
        )
        cfg.ai_advisory_policy_path = os.getenv(
            "AI_ADVISORY_POLICY_PATH", cfg.ai_advisory_policy_path
        )
        cfg.ai_advisory_api_key_file = os.getenv(
            "AI_ADVISORY_API_KEY_FILE", cfg.ai_advisory_api_key_file
        )
        cfg.ai_advisory_fixture_response_path = os.getenv(
            "AI_ADVISORY_FIXTURE_RESPONSE_PATH",
            cfg.ai_advisory_fixture_response_path,
        )
        cfg.ai_advisory_endpoint = os.getenv(
            "AI_ADVISORY_ENDPOINT", cfg.ai_advisory_endpoint
        )
        cfg.ai_advisory_api_version = os.getenv(
            "AI_ADVISORY_API_VERSION", cfg.ai_advisory_api_version
        )
        cfg.ai_advisory_adapter_revision = os.getenv(
            "AI_ADVISORY_ADAPTER_REVISION", cfg.ai_advisory_adapter_revision
        )
        cfg.ai_advisory_activation_receipt_path = os.getenv(
            "AI_ADVISORY_ACTIVATION_RECEIPT_PATH",
            cfg.ai_advisory_activation_receipt_path,
        )
        cfg.ai_advisory_alias_key_file = os.getenv(
            "AI_ADVISORY_ALIAS_KEY_FILE", cfg.ai_advisory_alias_key_file
        )
        cfg.ai_advisory_allowed_hosts = _env_json_string_list(
            "AI_ADVISORY_ALLOWED_HOSTS_JSON", cfg.ai_advisory_allowed_hosts
        )
        cfg.ai_advisory_request_options = _env_json(
            "AI_ADVISORY_REQUEST_OPTIONS_JSON", cfg.ai_advisory_request_options
        )
        cfg.ai_advisory_batch_size = _env_int(
            "AI_ADVISORY_BATCH_SIZE", cfg.ai_advisory_batch_size
        )
        cfg.ai_advisory_poll_seconds = _env_float(
            "AI_ADVISORY_POLL_SECONDS", cfg.ai_advisory_poll_seconds
        )
        cfg.ai_advisory_lease_seconds = _env_float(
            "AI_ADVISORY_LEASE_SECONDS", cfg.ai_advisory_lease_seconds
        )
        cfg.ai_advisory_lease_heartbeat_seconds = _env_float(
            "AI_ADVISORY_LEASE_HEARTBEAT_SECONDS",
            cfg.ai_advisory_lease_heartbeat_seconds,
        )
        cfg.ai_advisory_max_attempts = _env_int(
            "AI_ADVISORY_MAX_ATTEMPTS", cfg.ai_advisory_max_attempts
        )
        cfg.ai_advisory_timeout_seconds = _env_float(
            "AI_ADVISORY_TIMEOUT_SECONDS", cfg.ai_advisory_timeout_seconds
        )
        cfg.ai_advisory_retry_base_seconds = _env_float(
            "AI_ADVISORY_RETRY_BASE_SECONDS",
            cfg.ai_advisory_retry_base_seconds,
        )
        cfg.ai_advisory_retry_max_seconds = _env_float(
            "AI_ADVISORY_RETRY_MAX_SECONDS",
            cfg.ai_advisory_retry_max_seconds,
        )
        cfg.ai_advisory_max_response_bytes = _env_int(
            "AI_ADVISORY_MAX_RESPONSE_BYTES",
            cfg.ai_advisory_max_response_bytes,
        )
        cfg.ai_advisory_max_request_bytes = _env_int(
            "AI_ADVISORY_MAX_REQUEST_BYTES",
            cfg.ai_advisory_max_request_bytes,
        )
        cfg.ai_advisory_max_request_tokens = _env_int(
            "AI_ADVISORY_MAX_REQUEST_TOKENS",
            cfg.ai_advisory_max_request_tokens,
        )
        cfg.ai_advisory_retention_days = _env_int(
            "AI_ADVISORY_RETENTION_DAYS",
            cfg.ai_advisory_retention_days,
        )
        cfg.ai_advisory_max_queue_records = _env_int(
            "AI_ADVISORY_MAX_QUEUE_RECORDS", cfg.ai_advisory_max_queue_records
        )
        cfg.ai_advisory_max_records = _env_int(
            "AI_ADVISORY_MAX_RECORDS", cfg.ai_advisory_max_records
        )
        cfg.ai_advisory_max_storage_bytes = _env_int(
            "AI_ADVISORY_MAX_STORAGE_BYTES", cfg.ai_advisory_max_storage_bytes
        )
        cfg.ai_advisory_reconcile_batch_size = _env_int(
            "AI_ADVISORY_RECONCILE_BATCH_SIZE",
            cfg.ai_advisory_reconcile_batch_size,
        )
        cfg.ai_advisory_reconciliation_cutoff = _env_json(
            "AI_ADVISORY_RECONCILIATION_CUTOFF_JSON",
            cfg.ai_advisory_reconciliation_cutoff,
        )
        cfg.webhook_url = os.getenv("WEBHOOK_URL", cfg.webhook_url)
        cfg.webhook_targets = _env_json_list(
            "WEBHOOK_TARGETS_JSON", cfg.webhook_targets
        )
        cfg.webhook_signing_key_file = os.getenv(
            "WEBHOOK_SIGNING_KEY_FILE", cfg.webhook_signing_key_file
        )
        cfg.webhook_timeout_seconds = _env_int("WEBHOOK_TIMEOUT_SECONDS", cfg.webhook_timeout_seconds)
        cfg.webhook_dns_timeout_seconds = _env_float(
            "WEBHOOK_DNS_TIMEOUT_SECONDS", cfg.webhook_dns_timeout_seconds
        )
        cfg.webhook_max_attempts = _env_int("WEBHOOK_MAX_ATTEMPTS", cfg.webhook_max_attempts)
        cfg.webhook_retry_seconds = _env_float("WEBHOOK_RETRY_SECONDS", cfg.webhook_retry_seconds)
        cfg.webhook_lease_seconds = _env_float(
            "WEBHOOK_LEASE_SECONDS", cfg.webhook_lease_seconds
        )
        cfg.webhook_max_response_bytes = _env_int(
            "WEBHOOK_MAX_RESPONSE_BYTES", cfg.webhook_max_response_bytes
        )
        cfg.webhook_allowed_schemes = _env_list(
            "WEBHOOK_ALLOWED_SCHEMES", cfg.webhook_allowed_schemes
        )
        cfg.webhook_allow_private_networks = _env_bool(
            "WEBHOOK_ALLOW_PRIVATE_NETWORKS", cfg.webhook_allow_private_networks
        )
        cfg.webhook_policy = _env_json("WEBHOOK_POLICY_JSON", cfg.webhook_policy)
        cfg.enrichment_db_path = os.getenv("ENRICHMENT_DB_PATH", cfg.enrichment_db_path)
        cfg.local_enrichment_max_bytes = _env_int(
            "LOCAL_ENRICHMENT_MAX_BYTES",
            cfg.local_enrichment_max_bytes,
        )
        cfg.local_enrichment_max_records = _env_int(
            "LOCAL_ENRICHMENT_MAX_RECORDS",
            cfg.local_enrichment_max_records,
        )
        cfg.enable_enrichment_jobs = _env_bool("ENABLE_ENRICHMENT_JOBS", cfg.enable_enrichment_jobs)
        cfg.external_enrichment_profile = os.getenv(
            "EXTERNAL_ENRICHMENT_PROFILE",
            cfg.external_enrichment_profile,
        ).strip().lower()
        cfg.enrichment_batch_size = _env_int("ENRICHMENT_BATCH_SIZE", cfg.enrichment_batch_size)
        cfg.enrichment_max_attempts = _env_int("ENRICHMENT_MAX_ATTEMPTS", cfg.enrichment_max_attempts)
        cfg.enrichment_retry_seconds = _env_float("ENRICHMENT_RETRY_SECONDS", cfg.enrichment_retry_seconds)
        cfg.enrichment_ttl_seconds = _env_int("ENRICHMENT_TTL_SECONDS", cfg.enrichment_ttl_seconds)
        cfg.enrichment_allow_stale = _env_bool("ENRICHMENT_ALLOW_STALE", cfg.enrichment_allow_stale)
        cfg.enrichment_provider_timeout_seconds = _env_float(
            "ENRICHMENT_PROVIDER_TIMEOUT_SECONDS",
            cfg.enrichment_provider_timeout_seconds,
        )
        cfg.enrichment_provider_workers = _env_int(
            "ENRICHMENT_PROVIDER_WORKERS", cfg.enrichment_provider_workers
        )
        cfg.enrichment_provider_http_retries = _env_int(
            "ENRICHMENT_PROVIDER_HTTP_RETRIES",
            cfg.enrichment_provider_http_retries,
        )
        cfg.enrichment_provider_retry_delay_seconds = _env_float(
            "ENRICHMENT_PROVIDER_RETRY_DELAY_SECONDS",
            cfg.enrichment_provider_retry_delay_seconds,
        )
        cfg.enrichment_provider_max_response_bytes = _env_int(
            "ENRICHMENT_PROVIDER_MAX_RESPONSE_BYTES",
            cfg.enrichment_provider_max_response_bytes,
        )
        cfg.otx_api_key = _env_secret("OTX_API_KEY", cfg.otx_api_key)
        cfg.abuseipdb_api_key = _env_secret(
            "ABUSEIPDB_API_KEY", cfg.abuseipdb_api_key
        )
        cfg.shodan_api_key = _env_secret("SHODAN_API_KEY", cfg.shodan_api_key)
        cfg.virustotal_api_key = _env_secret(
            "VIRUSTOTAL_API_KEY", cfg.virustotal_api_key
        )
        cfg.censys_api_id = _env_secret("CENSYS_API_ID", cfg.censys_api_id)
        cfg.censys_api_secret = _env_secret(
            "CENSYS_API_SECRET", cfg.censys_api_secret
        )
        cfg.censys_platform_token = _env_secret(
            "CENSYS_PLATFORM_TOKEN", cfg.censys_platform_token
        )
        cfg.censys_organization_id = (
            os.getenv("CENSYS_ORGANIZATION_ID")
            or os.getenv("CENSYS_PLATFORM_ORG_ID")
            or os.getenv("CENSYS_PLATFORM_ORGANIZATION_ID")
            or cfg.censys_organization_id
        )
        cfg.response_guidance_policy_path = os.getenv(
            "RESPONSE_GUIDANCE_POLICY_PATH", cfg.response_guidance_policy_path
        )
        cfg.response_guidance_asset_profile_path = os.getenv(
            "RESPONSE_GUIDANCE_ASSET_PROFILE_PATH", cfg.response_guidance_asset_profile_path
        )
        cfg.enable_response_guidance = _env_bool(
            "ENABLE_RESPONSE_GUIDANCE", cfg.enable_response_guidance
        )
        cfg.cisa_cache_path = os.getenv("CISA_CACHE_PATH", cfg.cisa_cache_path)
        cfg.sigma_cache_path = os.getenv("SIGMA_CACHE_PATH", cfg.sigma_cache_path)
        cfg.mitre_attack_path = os.getenv("MITRE_ATTACK_PATH", cfg.mitre_attack_path)
        cfg.runtime_feed_provenance_path = os.getenv(
            "RUNTIME_FEED_PROVENANCE_PATH",
            cfg.runtime_feed_provenance_path,
        )
        cfg.enable_feed_loading = _env_bool("ENABLE_FEED_LOADING", cfg.enable_feed_loading)
        cfg.enable_securebert = _env_bool("ENABLE_SECUREBERT", cfg.enable_securebert)
        cfg.securebert_model_path = os.getenv("SECUREBERT_PATH", cfg.securebert_model_path)
        cfg.securebert_checkpoint_path = os.getenv("SECUREBERT_CHECKPOINT_PATH", cfg.securebert_checkpoint_path)
        cfg.securebert_device = os.getenv("SECUREBERT_DEVICE", cfg.securebert_device)
        cfg.securebert_max_length = _env_int("SECUREBERT_MAX_LENGTH", cfg.securebert_max_length)
        cfg.reports_dir = os.getenv("REPORTS_DIR", cfg.reports_dir)
        cfg.enable_artifacts = _env_bool("ENABLE_ARTIFACTS", cfg.enable_artifacts)
        cfg.enable_pdf_export = _env_bool("ENABLE_PDF_EXPORT", cfg.enable_pdf_export)
        cfg.enable_stix_export = _env_bool("ENABLE_STIX_EXPORT", cfg.enable_stix_export)
        cfg.actor_db_path = os.getenv("ACTOR_DB_PATH", cfg.actor_db_path)
        cfg.enable_actor_attribution = _env_bool("ENABLE_ACTOR_ATTRIBUTION", cfg.enable_actor_attribution)
        cfg.classification_policy = _env_json("CLASSIFICATION_POLICY_JSON", cfg.classification_policy)
        cfg.classification_rules_path = os.getenv("CLASSIFICATION_RULES_PATH", cfg.classification_rules_path)
        cfg.classifier_environment_path = os.getenv(
            "CLASSIFIER_ENVIRONMENT_PATH",
            cfg.classifier_environment_path,
        )
        cfg.threat_hypothesis_behavior_policy_path = os.getenv(
            "THREAT_HYPOTHESIS_BEHAVIOR_POLICY_PATH",
            cfg.threat_hypothesis_behavior_policy_path,
        )
        cfg.prediction_policy_path = os.getenv("PREDICTION_POLICY_PATH", cfg.prediction_policy_path)
        cfg.data_lifecycle_policy_path = os.getenv(
            "DATA_LIFECYCLE_POLICY_PATH",
            cfg.data_lifecycle_policy_path,
        )
        cfg.alert_authority_policy_path = os.getenv(
            "ALERT_AUTHORITY_POLICY_PATH",
            cfg.alert_authority_policy_path,
        )
        cfg.prediction_snapshot_retention_days = _env_int(
            "PREDICTION_SNAPSHOT_RETENTION_DAYS",
            cfg.prediction_snapshot_retention_days,
        )
        cfg.prediction_snapshot_keep_latest_per_session = _env_bool(
            "PREDICTION_SNAPSHOT_KEEP_LATEST_PER_SESSION",
            cfg.prediction_snapshot_keep_latest_per_session,
        )
        cfg.enable_session_ttp_correlation = _env_bool(
            "ENABLE_SESSION_TTP_CORRELATION",
            cfg.enable_session_ttp_correlation,
        )
        cfg.session_ttp_correlation_policy_path = os.getenv(
            "SESSION_TTP_CORRELATION_POLICY_PATH",
            cfg.session_ttp_correlation_policy_path,
        )
        cfg.session_ttp_knowledge_pack_paths = _env_list(
            "SESSION_TTP_KNOWLEDGE_PACK_PATHS",
            cfg.session_ttp_knowledge_pack_paths,
        )
        cfg.calibration_policy = _env_json("CALIBRATION_POLICY_JSON", cfg.calibration_policy)
        cfg.threat_hunt_policy = _env_json("THREAT_HUNT_POLICY_JSON", cfg.threat_hunt_policy)
        cfg.campaign_policy = _env_json("CAMPAIGN_POLICY_JSON", cfg.campaign_policy)
        cfg.prediction_policy = _env_json("PREDICTION_POLICY_JSON", cfg.prediction_policy)
        cfg.prediction_policy = _load_prediction_policy_file(cfg.prediction_policy_path, cfg.prediction_policy)
        cfg.credential_policy = _env_json("CREDENTIAL_POLICY_JSON", cfg.credential_policy)
        cfg.credential_hmac_keyring_file = os.getenv(
            "CREDENTIAL_HMAC_KEYRING_FILE",
            cfg.credential_hmac_keyring_file,
        )
        cfg.validate_event_processing()
        return cfg

    def apply_environment(self) -> None:
        """Expose selected config to libraries that still resolve from env vars."""
        if self.threat_hypothesis_behavior_policy_path:
            os.environ.setdefault(
                "THREAT_HYPOTHESIS_BEHAVIOR_POLICY_PATH",
                self.threat_hypothesis_behavior_policy_path,
            )
