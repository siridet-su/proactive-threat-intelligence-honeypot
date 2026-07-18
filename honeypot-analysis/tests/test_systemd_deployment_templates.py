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
