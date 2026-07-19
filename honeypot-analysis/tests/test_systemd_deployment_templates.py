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
            assert "LoadCredential=" not in document
            assert "SetCredential=" not in document


def test_common_environment_and_pi_template_contain_no_hmac_secret_setting() -> None:
    environment_example = (SYSTEMD_DIR / "honeypot.env.example").read_text(
        encoding="utf-8"
    )
    pi_service = (SYSTEMD_DIR / "honeypot-sensor-forwarder.service").read_text(
        encoding="utf-8"
    )

    assert "CREDENTIAL_HMAC_KEY" not in environment_example
    assert "CREDENTIAL_HMAC_KEYRING_FILE=" not in environment_example
    assert "credential-hmac-keyring" not in pi_service


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
        SYSTEMD_DIR / "honeypot.env.example"
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


def test_all_long_running_units_have_bounded_graceful_stop_settings() -> None:
    services = (
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
