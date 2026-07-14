from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from production.storage.session_provenance import (
    SESSION_SOURCE_PRODUCTION_LIVE,
    normalize_session_source,
)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


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

    database_url: str = "sqlite:///production_state.db"
    ingest_host: str = "0.0.0.0"
    ingest_port: int = 8080
    dashboard_host: str = "0.0.0.0"
    dashboard_port: int = 8081

    cowrie_log_path: str = "data/samples/demo_cowrie_realistic.json"
    spool_path: str = "sensor_spool.ndjson"
    ingest_url: str = "http://127.0.0.1:8080/events"
    forwarder_batch_size: int = 50
    forwarder_poll_seconds: float = 2.0
    forwarder_timeout_seconds: int = 15

    worker_batch_size: int = 100
    worker_poll_seconds: float = 2.0
    threat_hunt_batch_size: int = 20
    threat_hunt_poll_seconds: float = 10.0
    analysis_batch_size: int = 1
    analysis_max_attempts: int = 3
    analysis_max_tokens: int = 4000
    analysis_fallback_on_failure: bool = True
    analysis_skip_empty_sessions: bool = True
    analysis_suppress_stdout: bool = True

    webhook_url: str = ""
    webhook_timeout_seconds: int = 15
    webhook_max_attempts: int = 5
    webhook_retry_seconds: float = 30.0
    webhook_policy: Dict[str, Any] = field(default_factory=lambda: {
        "min_severity": "high",
        "alert_type_min_severity": {
            "threat_hunt_match": "medium",
        },
    })

    enrichment_db_path: str = ""
    enable_enrichment_jobs: bool = True
    enrichment_batch_size: int = 20
    enrichment_max_attempts: int = 3
    enrichment_retry_seconds: float = 300.0
    enrichment_ttl_seconds: int = 86400
    enrichment_allow_stale: bool = True
    otx_api_key: str = ""
    abuseipdb_api_key: str = ""
    shodan_api_key: str = ""
    virustotal_api_key: str = ""
    censys_api_id: str = ""
    censys_api_secret: str = ""
    censys_platform_token: str = ""
    censys_organization_id: str = ""
    threat_intel_config_path: str = "configs/threat_intel_config.json"
    smb_asset_profile_path: str = "configs/smb_asset_profile.example.json"
    smb_action_policy_path: str = "configs/smb_action_playbooks.trusted.json"
    enable_smb_decisions: bool = True
    enable_smb_decision_alerts: bool = True
    smb_alert_min_severity: str = "high"
    cisa_cache_path: str = ""
    sigma_cache_path: str = ""
    mitre_attack_path: str = ""
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
    enable_actor_attribution: bool = True

    vertex_project_id: str = ""
    vertex_location: str = "us-central1"
    vertex_model: str = "gemini-2.5-pro"

    classification_policy: Dict[str, Any] = field(default_factory=lambda: {
        "strategy": "notebook_merge",
        "bert_min_confidence": 0.55,
        "keyword_fallback_on_low_confidence": True,
        "keyword_fallback_on_error": True,
        "rule_review_mode": "reviewed_only",
    })
    classification_rules_path: str = "configs/classification_rules.trusted.json"
    prediction_policy_path: str = "configs/prediction_policy.trusted.json"
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
        "alert_active_sessions": True,
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
        "max_matches": 10,
        "command_pattern_command_limit": 6,
        "command_pattern_token_limit": 3,
        "known_actor_return_alerts": True,
        "known_actor_min_prior_severity": "high",
        "known_actor_alert_on_status": ["active", "closed"],
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
        "prediction_mode": "primary_transition_with_fallback",
        "compute_weighted_ensemble_baseline": True,
        "primary_transition": {
            "primary_model": "transition_frequency",
            "source_order": ["local_transition", "external_seed_transition"],
            "fallback_scorer": "fallback_progression",
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
        "hash_algorithm": "sha256",
        "hash_salt": "",
        "sanitize_raw_events": True,
        "redact_fields": ["password", "passwd"],
    })

    @classmethod
    def from_env(cls, config_path: Optional[str] = None) -> "ProductionConfig":
        file_values: Dict[str, Any] = {}
        selected_path = config_path or os.getenv("HONEYPOT_CONFIG_FILE", "")
        if selected_path:
            path = Path(selected_path)
            if path.exists():
                with path.open("r", encoding="utf-8") as f:
                    loaded = json.load(f)
                if not isinstance(loaded, dict):
                    raise ValueError("production config file must contain a JSON object")
                file_values = loaded

        cfg = cls(**{k: v for k, v in file_values.items() if k in cls.__dataclass_fields__})
        cfg.environment = os.getenv("HONEYPOT_ENV", cfg.environment)
        cfg.sensor_id = os.getenv("SENSOR_ID", cfg.sensor_id)
        cfg.session_source = normalize_session_source(
            os.getenv("HONEYPOT_SESSION_SOURCE") or os.getenv("SESSION_SOURCE") or cfg.session_source,
            SESSION_SOURCE_PRODUCTION_LIVE,
        )
        cfg.api_token = os.getenv("HONEYPOT_API_TOKEN", cfg.api_token)
        cfg.database_url = os.getenv("DATABASE_URL", cfg.database_url)
        cfg.ingest_host = os.getenv("INGEST_HOST", cfg.ingest_host)
        cfg.ingest_port = _env_int("INGEST_PORT", cfg.ingest_port)
        cfg.dashboard_host = os.getenv("DASHBOARD_HOST", cfg.dashboard_host)
        cfg.dashboard_port = _env_int("DASHBOARD_PORT", cfg.dashboard_port)
        cfg.cowrie_log_path = os.getenv("COWRIE_LOG_PATH", cfg.cowrie_log_path)
        cfg.spool_path = os.getenv("FORWARDER_SPOOL_PATH", cfg.spool_path)
        cfg.ingest_url = os.getenv("INGEST_URL", cfg.ingest_url)
        cfg.forwarder_batch_size = _env_int("FORWARDER_BATCH_SIZE", cfg.forwarder_batch_size)
        cfg.forwarder_poll_seconds = _env_float(
            "FORWARDER_POLL_SECONDS",
            _env_float("FORWARDER_POLL_INTERVAL_SECONDS", cfg.forwarder_poll_seconds),
        )
        cfg.forwarder_timeout_seconds = _env_int("FORWARDER_TIMEOUT_SECONDS", cfg.forwarder_timeout_seconds)
        cfg.worker_batch_size = _env_int("WORKER_BATCH_SIZE", cfg.worker_batch_size)
        cfg.worker_poll_seconds = _env_float("WORKER_POLL_SECONDS", cfg.worker_poll_seconds)
        cfg.threat_hunt_batch_size = _env_int("THREAT_HUNT_BATCH_SIZE", cfg.threat_hunt_batch_size)
        cfg.threat_hunt_poll_seconds = _env_float("THREAT_HUNT_POLL_SECONDS", cfg.threat_hunt_poll_seconds)
        cfg.analysis_batch_size = _env_int("ANALYSIS_BATCH_SIZE", cfg.analysis_batch_size)
        cfg.analysis_max_attempts = _env_int("ANALYSIS_MAX_ATTEMPTS", cfg.analysis_max_attempts)
        cfg.analysis_max_tokens = _env_int("ANALYSIS_MAX_TOKENS", cfg.analysis_max_tokens)
        cfg.analysis_fallback_on_failure = _env_bool("ANALYSIS_FALLBACK_ON_FAILURE", cfg.analysis_fallback_on_failure)
        cfg.analysis_skip_empty_sessions = _env_bool("ANALYSIS_SKIP_EMPTY_SESSIONS", cfg.analysis_skip_empty_sessions)
        cfg.analysis_suppress_stdout = _env_bool("ANALYSIS_SUPPRESS_STDOUT", cfg.analysis_suppress_stdout)
        cfg.webhook_url = os.getenv("WEBHOOK_URL", cfg.webhook_url)
        cfg.webhook_timeout_seconds = _env_int("WEBHOOK_TIMEOUT_SECONDS", cfg.webhook_timeout_seconds)
        cfg.webhook_max_attempts = _env_int("WEBHOOK_MAX_ATTEMPTS", cfg.webhook_max_attempts)
        cfg.webhook_retry_seconds = _env_float("WEBHOOK_RETRY_SECONDS", cfg.webhook_retry_seconds)
        cfg.webhook_policy = _env_json("WEBHOOK_POLICY_JSON", cfg.webhook_policy)
        cfg.enrichment_db_path = os.getenv("ENRICHMENT_DB_PATH", cfg.enrichment_db_path)
        cfg.enable_enrichment_jobs = _env_bool("ENABLE_ENRICHMENT_JOBS", cfg.enable_enrichment_jobs)
        cfg.enrichment_batch_size = _env_int("ENRICHMENT_BATCH_SIZE", cfg.enrichment_batch_size)
        cfg.enrichment_max_attempts = _env_int("ENRICHMENT_MAX_ATTEMPTS", cfg.enrichment_max_attempts)
        cfg.enrichment_retry_seconds = _env_float("ENRICHMENT_RETRY_SECONDS", cfg.enrichment_retry_seconds)
        cfg.enrichment_ttl_seconds = _env_int("ENRICHMENT_TTL_SECONDS", cfg.enrichment_ttl_seconds)
        cfg.enrichment_allow_stale = _env_bool("ENRICHMENT_ALLOW_STALE", cfg.enrichment_allow_stale)
        cfg.otx_api_key = os.getenv("OTX_API_KEY", cfg.otx_api_key)
        cfg.abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY", cfg.abuseipdb_api_key)
        cfg.shodan_api_key = os.getenv("SHODAN_API_KEY", cfg.shodan_api_key)
        cfg.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY", cfg.virustotal_api_key)
        cfg.censys_api_id = os.getenv("CENSYS_API_ID", cfg.censys_api_id)
        cfg.censys_api_secret = os.getenv("CENSYS_API_SECRET", cfg.censys_api_secret)
        cfg.censys_platform_token = os.getenv("CENSYS_PLATFORM_TOKEN", cfg.censys_platform_token)
        cfg.censys_organization_id = (
            os.getenv("CENSYS_ORGANIZATION_ID")
            or os.getenv("CENSYS_PLATFORM_ORG_ID")
            or os.getenv("CENSYS_PLATFORM_ORGANIZATION_ID")
            or cfg.censys_organization_id
        )
        cfg.threat_intel_config_path = os.getenv("THREAT_INTEL_CONFIG_PATH", cfg.threat_intel_config_path)
        cfg.smb_asset_profile_path = os.getenv("SMB_ASSET_PROFILE_PATH", cfg.smb_asset_profile_path)
        cfg.smb_action_policy_path = os.getenv("SMB_ACTION_POLICY_PATH", cfg.smb_action_policy_path)
        cfg.enable_smb_decisions = _env_bool("ENABLE_SMB_DECISIONS", cfg.enable_smb_decisions)
        cfg.enable_smb_decision_alerts = _env_bool("ENABLE_SMB_DECISION_ALERTS", cfg.enable_smb_decision_alerts)
        cfg.smb_alert_min_severity = os.getenv("SMB_ALERT_MIN_SEVERITY", cfg.smb_alert_min_severity)
        cfg.cisa_cache_path = os.getenv("CISA_CACHE_PATH", cfg.cisa_cache_path)
        cfg.sigma_cache_path = os.getenv("SIGMA_CACHE_PATH", cfg.sigma_cache_path)
        cfg.mitre_attack_path = os.getenv("MITRE_ATTACK_PATH", cfg.mitre_attack_path)
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
        cfg.vertex_project_id = os.getenv("VERTEX_PROJECT_ID", cfg.vertex_project_id)
        cfg.vertex_location = os.getenv("VERTEX_LOCATION", cfg.vertex_location)
        cfg.vertex_model = os.getenv("VERTEX_MODEL", cfg.vertex_model)
        cfg.classification_policy = _env_json("CLASSIFICATION_POLICY_JSON", cfg.classification_policy)
        cfg.classification_rules_path = os.getenv("CLASSIFICATION_RULES_PATH", cfg.classification_rules_path)
        cfg.prediction_policy_path = os.getenv("PREDICTION_POLICY_PATH", cfg.prediction_policy_path)
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
        return cfg

    def apply_environment(self) -> None:
        """Expose selected config to libraries that still resolve from env vars."""
        if self.vertex_project_id:
            os.environ.setdefault("VERTEX_PROJECT_ID", self.vertex_project_id)
        if self.vertex_location:
            os.environ.setdefault("VERTEX_LOCATION", self.vertex_location)
        if self.vertex_model:
            os.environ.setdefault("VERTEX_MODEL", self.vertex_model)
