from __future__ import annotations

import json
from pathlib import Path

from production.utils.config import ProductionConfig


ROOT = Path(__file__).resolve().parents[1]
SYSTEMD_DIR = ROOT / "deployment" / "systemd"


def test_credential_hmac_keyring_is_worker_only_systemd_credential() -> None:
    service_documents = {
        path.name: path.read_text(encoding="utf-8")
        for path in SYSTEMD_DIR.glob("*.service")
    }
    session_worker = service_documents["honeypot-session-worker.service"]

    assert (
        "LoadCredential=credential-hmac-keyring.json:"
        "/etc/honeypot/credential-hmac-keyring.json"
    ) in session_worker
    assert "SetCredential=" not in session_worker
    for name, document in service_documents.items():
        if name != "honeypot-session-worker.service":
            assert "credential-hmac-keyring" not in document
            assert "SetCredential=" not in document


def test_capstone_storage_services_receive_only_the_protected_mongodb_uri() -> None:
    expected = {
        "honeypot-ai-advisory-worker.service",
        "honeypot-analysis-worker.service",
        "honeypot-dashboard-api.service",
        "honeypot-enrichment-worker.service",
        "honeypot-feed-refresh.service",
        "honeypot-ingest-api.service",
        "honeypot-monitor-web.service",
        "honeypot-next-distinct-shadow-feeder.service",
        "honeypot-session-count-monitor.service",
        "honeypot-session-worker.service",
        "honeypot-threat-hunt-worker.service",
        "honeypot-webhook-dispatcher.service",
    }
    selected = set()
    for path in SYSTEMD_DIR.glob("*.service"):
        document = path.read_text(encoding="utf-8")
        if "LoadCredential=mongodb-uri" in document:
            selected.add(path.name)
            if path.name == "honeypot-next-distinct-shadow-feeder.service":
                feeder_source = (
                    ROOT
                    / "production"
                    / "prediction_next_distinct_poc"
                    / "mongodb_shadow_feeder.py"
                ).read_text(encoding="utf-8")
                assert 'os.environ.get("CREDENTIALS_DIRECTORY")' in feeder_source
                assert 'Path(credential_dir) / "mongodb-uri"' in feeder_source
                assert "ReadOnlyPaths=/var/lib/honeypot" in document
            else:
                assert "Environment=MONGODB_URI_FILE=%d/mongodb-uri" in document
    assert selected == expected
    assert "mongodb-uri" not in (
        SYSTEMD_DIR / "honeypot-sensor-forwarder.service"
    ).read_text(encoding="utf-8")


def test_common_environment_and_pi_template_contain_no_hmac_secret_setting() -> None:
    environment_example = (SYSTEMD_DIR / "common.env.example").read_text(
        encoding="utf-8"
    )
    pi_service = (SYSTEMD_DIR / "honeypot-sensor-forwarder.service").read_text(
        encoding="utf-8"
    )

    assert "CREDENTIAL_HMAC_KEY" not in environment_example
    assert "CREDENTIAL_HMAC_KEYRING_FILE=" not in environment_example
    assert "credential-hmac-keyring" not in pi_service


def test_common_environment_selects_transformer_without_implicit_vomm_fallback() -> None:
    environment_example = (SYSTEMD_DIR / "common.env.example").read_text(
        encoding="utf-8"
    )

    assert (
        "PREDICTION_POLICY_PATH=/opt/honeypot/configs/"
        "prediction_policy.transformer_poc.trusted.json"
    ) in environment_example
    assert "PREDICTION_POLICY_PATH=/opt/honeypot/configs/prediction_policy.trusted.json" not in environment_example


def test_example_config_selects_hmac_without_embedding_key_material() -> None:
    config = json.loads(
        (ROOT / "configs" / "production_config.example.json").read_text(
            encoding="utf-8"
        )
    )

    assert config["credential_policy"]["hash_algorithm"] == "hmac-sha256-v1"
    assert "hash_salt" not in config["credential_policy"]
    assert config["credential_hmac_keyring_file"] == ""
    assert "keys" not in config["credential_policy"]


def test_analysis_artifact_directory_contract_is_private_and_absolute() -> None:
    analysis_unit = (
        SYSTEMD_DIR / "honeypot-analysis-worker.service"
    ).read_text(encoding="utf-8")
    environment_example = (
        SYSTEMD_DIR / "common.env.example"
    ).read_text(encoding="utf-8")
    deployment_readme = (
        SYSTEMD_DIR / "README.md"
    ).read_text(encoding="utf-8")
    config = json.loads(
        (ROOT / "configs" / "production_config.example.json").read_text(
            encoding="utf-8"
        )
    )

    assert "UMask=0077" in analysis_unit
    assert "REPORTS_DIR=/var/lib/honeypot/reports" in environment_example
    assert config["reports_dir"] == "/var/lib/honeypot/reports"
    assert ProductionConfig().reports_dir == "reports"
    assert (
        "install -d -o honeypot -g honeypot -m 0700 "
        "/var/lib/honeypot/reports"
    ) in deployment_readme
    assert "install -d -o root -g honeypot -m 0750 /etc/honeypot" in (
        deployment_readme
    )
    assert (
        "install -o root -g honeypot -m 0640 "
        "configs/production_config.example.json "
        "/etc/honeypot/production_config.json"
    ) in deployment_readme
    assert (
        "find /var/lib/honeypot/reports -xdev -type f -exec chmod 0600"
        in deployment_readme
    )
    assert "chown -R honeypot:honeypot /var/lib/honeypot/reports" in (
        deployment_readme
    )


def test_session_worker_has_bounded_graceful_stop_settings() -> None:
    session_worker = (
        SYSTEMD_DIR / "honeypot-session-worker.service"
    ).read_text(encoding="utf-8")

    assert "TimeoutStopSec=120" in session_worker
    assert "KillSignal=SIGTERM" in session_worker


def test_ingest_service_exposes_owner_only_startup_diagnostics_path() -> None:
    ingest_unit = (
        SYSTEMD_DIR / "honeypot-ingest-api.service"
    ).read_text(encoding="utf-8")
    assert (
        "Environment=STARTUP_DIAGNOSTICS_PATH="
        "/var/lib/honeypot/startup/ingest-api.json"
    ) in ingest_unit
    assert "ReadWritePaths=/var/lib/honeypot" in ingest_unit
    assert "UMask=0077" in ingest_unit


def test_all_long_running_units_have_bounded_graceful_stop_settings() -> None:
    services = (
        "honeypot-ai-advisory-worker.service",
        "honeypot-analysis-worker.service",
        "honeypot-dashboard-api.service",
        "honeypot-enrichment-worker.service",
        "honeypot-ingest-api.service",
        "honeypot-monitor-web.service",
        "honeypot-sensor-forwarder.service",
        "honeypot-session-worker.service",
        "honeypot-threat-hunt-worker.service",
        "honeypot-webhook-dispatcher.service",
    )
    for name in services:
        unit = (SYSTEMD_DIR / name).read_text(encoding="utf-8")
        assert "TimeoutStopSec=120" in unit, name
        assert "KillSignal=SIGTERM" in unit, name


def test_ai_worker_is_managed_but_static_and_disabled_by_default() -> None:
    unit = (SYSTEMD_DIR / "honeypot-ai-advisory-worker.service").read_text(
        encoding="utf-8"
    )
    environment = (
        SYSTEMD_DIR / "services" / "ai-advisory-worker.env.example"
    ).read_text(encoding="utf-8")
    common = (SYSTEMD_DIR / "common.env.example").read_text(encoding="utf-8")
    assert "[Install]" not in unit
    assert "ENABLE_AI_ADVISORY=false" in environment
    assert "ENABLE_AI_ADVISORY=false" in common
    assert "AI_ADVISORY_ACTIVATION_RECEIPT_PATH=" in environment
    assert "AI_ADVISORY_ALIAS_KEY_FILE=" in environment
    assert "AI_ADVISORY_RECONCILIATION_CUTOFF_JSON={}" in environment
    assert "AI_ADVISORY_PROVIDER=google_vertex_gemini" in environment
    assert "AI_ADVISORY_PROJECT=project-dff4b23a-3010-4936-a02" in environment
    assert "AI_ADVISORY_LOCATION=global" in environment
    assert "AI_ADVISORY_MODEL=gemini-2.5-flash" in environment
    assert not any(
        line.startswith("AI_ADVISORY_API_KEY_FILE=")
        for line in environment.splitlines()
    )
    assert "ProtectHome=true" in unit
    assert "PrivateDevices=true" in unit
    assert "CapabilityBoundingSet=" in unit
    assert "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6" in unit
    assert "MemoryMax=512M" in unit
    assert "CPUQuota=50%" in unit
    assert "TasksMax=64" in unit

    config = json.loads(
        (ROOT / "configs" / "production_config.example.json").read_text(
            encoding="utf-8"
        )
    )
    assert config["ai_advisory_reconciliation_cutoff"] == {}


def test_example_config_documents_event_processing_defaults() -> None:
    config = json.loads(
        (ROOT / "configs" / "production_config.example.json").read_text(
            encoding="utf-8"
        )
    )

    assert config["event_lease_seconds"] == 60.0
    assert config["event_lease_heartbeat_seconds"] == 20.0
    assert config["event_max_attempts"] == 5
    assert config["event_retry_base_seconds"] == 5.0
    assert config["event_retry_max_seconds"] == 300.0
    assert config["worker_leader_lease_seconds"] == 90.0
    assert config["worker_leader_heartbeat_seconds"] == 10.0
    assert config["active_session_recovery_limit"] == 10_000
    assert config["campaign_profile_cache_limit"] == 10_000
    assert config["session_event_history_limit"] == 10_000
    assert config["job_lease_seconds"] == 600.0
    assert config["job_lease_heartbeat_seconds"] == 60.0
    assert config["job_retry_base_seconds"] == 30.0
    assert config["job_retry_max_seconds"] == 1800.0
    assert config["threat_hunt_max_attempts"] == 3
