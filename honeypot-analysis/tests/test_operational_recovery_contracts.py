from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from production.policies.data_lifecycle_policy import load_data_lifecycle_policy
from production.storage import open_storage
from production.tools.sqlite_backup_restore import create_backup, restore_backup


ROOT = Path(__file__).resolve().parents[1]


def test_sqlite_connections_are_private_bounded_and_durable(tmp_path) -> None:
    storage = open_storage(f"sqlite:///{tmp_path / 'private-state.db'}")
    with storage.connection() as connection:
        assert connection.execute("PRAGMA busy_timeout").fetchone()[0] == 30_000
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert connection.execute("PRAGMA synchronous").fetchone()[0] == 2
    assert storage.path.stat().st_mode & 0o077 == 0


def test_migration_backup_restore_preserve_sanitized_events_and_ledger(
    tmp_path,
) -> None:
    storage = open_storage(f"sqlite:///{tmp_path / 'source.db'}")
    event = {
        "eventid": "cowrie.login.success",
        "session": "backup-privacy",
        "src_ip": "203.0.113.70",
        "username": "root",
        "password": "must-not-enter-backup",
    }
    storage.store_event("sensor-phase7", event)
    with storage.connection() as connection:
        source_ledger = [
            tuple(row)
            for row in connection.execute(
                "SELECT version, name, checksum FROM schema_migrations ORDER BY version"
            ).fetchall()
        ]

    backup = tmp_path / "backups" / "phase7.db"
    manifest = create_backup(storage.path, backup)
    restored = tmp_path / "restored" / "phase7.db"
    restore_backup(backup, Path(manifest["manifest_path"]), restored)

    with sqlite3.connect(restored) as connection:
        payload = connection.execute(
            "SELECT payload_json FROM events WHERE session_id = ?",
            ("backup-privacy",),
        ).fetchone()[0]
        restored_ledger = connection.execute(
            "SELECT version, name, checksum FROM schema_migrations ORDER BY version"
        ).fetchall()
    assert "must-not-enter-backup" not in payload
    assert json.loads(payload)["password"] == "[REDACTED]"
    assert restored_ledger == source_ledger


def test_systemd_units_apply_private_umask_and_common_sandbox() -> None:
    units = sorted((ROOT / "deployment" / "systemd").glob("*.service"))
    assert units
    for unit in units:
        text = unit.read_text(encoding="utf-8")
        assert "UMask=0077" in text, unit.name
        assert "NoNewPrivileges=true" in text, unit.name
        assert "PrivateTmp=true" in text, unit.name
        assert "ProtectSystem=full" in text, unit.name
        assert "User=" in text and "Group=" in text, unit.name


def test_monitor_contract_uses_advisory_wording_and_bounded_connect_csp() -> None:
    html = (ROOT / "production" / "api" / "static" / "monitor.html").read_text(
        encoding="utf-8"
    )
    server = (ROOT / "production" / "api" / "monitor_web.py").read_text(
        encoding="utf-8"
    )
    assert ">Authoritative Next-Tactic Forecast<" not in html
    assert "Predictive Alert ·" not in html
    assert "Non-Authoritative Next-Tactic Forecast" in html
    assert "Model context only; it cannot create findings, alerts, guidance, or actions." in html
    assert "Historical Prediction Evaluation" in html
    assert "Historical Calibration Record" in html
    assert "AI Validation Warnings" not in server
    assert "Generated Narrative Validation" in server
    assert "connect-src 'self' https:" not in server
    assert "connect-src 'self'" in server


def test_current_lifecycle_contract_retains_history_and_prohibits_authority() -> None:
    policy = load_data_lifecycle_policy(
        str(ROOT / "configs" / "data_lifecycle_policy.v1.json")
    )
    assert policy.document["privacy"]["credential_plaintext_storage_allowed"] is False
    assert policy.document["privacy"]["source_ip_external_sharing_allowed"] is False
    assert policy.document["authority"]["manual_approval_required"] is True
    assert policy.document["authority"]["automatic_deletion_authorized"] is False
    assert policy.document["entities"]["events"]["mode"] == "retain"
    assert policy.document["entities"]["enrichment_records"]["mode"] == (
        "retain_expired_for_provenance"
    )
