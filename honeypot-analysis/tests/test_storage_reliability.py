from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from production.policies.data_lifecycle_policy import (
    load_data_lifecycle_policy,
    validate_data_lifecycle_policy,
)
from production.storage.backend import (
    SQLITE_SCHEMA_VERSION,
    SQLiteStorage,
    StorageError,
    open_existing_storage,
)
from production.tools.sqlite_backup_restore import (
    create_backup,
    restore_backup,
    verify_backup,
)
from production.utils.config import ProductionConfig


def _storage(root: Path) -> SQLiteStorage:
    return SQLiteStorage(f"sqlite:///{root / 'phase3.db'}")


def test_sqlite_migrations_are_checksummed_and_idempotent(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    storage.initialize()
    storage.initialize()

    with sqlite3.connect(storage.path) as conn:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        rows = conn.execute(
            "SELECT version, name, checksum FROM schema_migrations ORDER BY version"
        ).fetchall()
        quick_check = conn.execute("PRAGMA quick_check").fetchone()[0]
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }

    assert version == SQLITE_SCHEMA_VERSION
    assert [row[0] for row in rows] == list(range(1, SQLITE_SCHEMA_VERSION + 1))
    assert all(len(row[2]) == 64 for row in rows)
    assert quick_check == "ok"
    assert {"prediction_outbox", "data_lifecycle_policy_ledger"} <= tables


def test_sqlite_migrations_reject_future_and_tampered_ledgers(
    tmp_path: Path,
) -> None:
    future = _storage(tmp_path / "future")
    future.initialize()
    with sqlite3.connect(future.path) as conn:
        conn.execute(f"PRAGMA user_version={SQLITE_SCHEMA_VERSION + 1}")
    with pytest.raises(StorageError, match="newer than this release"):
        future.initialize()

    tampered = _storage(tmp_path / "tampered")
    tampered.initialize()
    with sqlite3.connect(tampered.path) as conn:
        conn.execute(
            "UPDATE schema_migrations SET checksum = ? WHERE version = 2",
            ("0" * 64,),
        )
    with pytest.raises(StorageError, match="checksum mismatch"):
        tampered.initialize()


def test_existing_storage_readiness_is_bounded_and_checks_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    storage = _storage(tmp_path)
    storage.initialize()
    statements: list[str] = []
    original_connect = sqlite3.connect

    def traced_connect(*args, **kwargs):  # type: ignore[no-untyped-def]
        connection = original_connect(*args, **kwargs)
        connection.set_trace_callback(statements.append)
        return connection

    monkeypatch.setattr(sqlite3, "connect", traced_connect)
    selected = open_existing_storage(f"sqlite:///{storage.path}")

    assert isinstance(selected, SQLiteStorage)
    assert not any("quick_check" in statement.lower() for statement in statements)
    assert len(statements) == 4
    assert any("schema_migrations" in statement for statement in statements)

    with original_connect(storage.path) as connection:
        connection.execute(
            "UPDATE schema_migrations SET checksum=? WHERE version=2",
            ("0" * 64,),
        )
    with pytest.raises(StorageError, match="migration ledger is not ready"):
        open_existing_storage(f"sqlite:///{storage.path}")


def test_existing_storage_readiness_rejects_unsafe_path(
    tmp_path: Path,
) -> None:
    storage = _storage(tmp_path)
    storage.initialize()
    alias = tmp_path / "database-link.db"
    alias.symlink_to(storage.path)

    with pytest.raises(StorageError, match="not a regular file"):
        open_existing_storage(f"sqlite:///{alias}")


def test_prediction_outbox_is_deduplicated_retried_and_completed(
    tmp_path: Path,
) -> None:
    storage = _storage(tmp_path)
    storage.initialize()
    task = {
        "schema_version": "prediction_outbox_task.v1",
        "event_id": "event-1",
        "session_id": "session-1",
        "prediction_mode": "transformer_advisory",
        "trigger_event": {"eventid": "cowrie.command.input"},
    }

    outbox_id = storage.enqueue_prediction_outbox(task)
    assert storage.enqueue_prediction_outbox(task) == outbox_id
    assert len(storage.list_rows("prediction_outbox")) == 1

    first = storage.claim_prediction_outbox(
        owner="worker-a",
        limit=1,
        lease_seconds=30,
        max_attempts=2,
        now="2026-07-01T00:00:00+00:00",
    )
    assert len(first) == 1
    assert first[0]["task"] == task
    assert storage.fail_prediction_outbox(
        outbox_id,
        owner="worker-a",
        token=first[0]["claim_token"],
        error_code="inference_failed",
        error_type="RuntimeError",
        retryable=True,
        retry_delay_seconds=10,
        max_attempts=2,
        now="2026-07-01T00:00:01+00:00",
    ) == "retry"

    assert storage.claim_prediction_outbox(
        owner="worker-b",
        limit=1,
        lease_seconds=30,
        max_attempts=2,
        now="2026-07-01T00:00:05+00:00",
    ) == []
    second = storage.claim_prediction_outbox(
        owner="worker-b",
        limit=1,
        lease_seconds=30,
        max_attempts=2,
        now="2026-07-01T00:00:11+00:00",
    )
    assert len(second) == 1
    assert second[0]["attempts"] == 2
    assert storage.complete_prediction_outbox(
        outbox_id,
        owner="worker-b",
        token=second[0]["claim_token"],
        snapshot_id="prediction-1",
        now="2026-07-01T00:00:12+00:00",
    )
    row = storage.list_rows("prediction_outbox")[0]
    assert row["status"] == "completed"
    assert row["snapshot_id"] == "prediction-1"
    assert storage.claim_prediction_outbox(
        owner="worker-c",
        limit=1,
        lease_seconds=30,
        max_attempts=2,
        now="2026-07-01T00:00:13+00:00",
    ) == []


def test_failed_migration_rolls_back_its_ledger_entry(tmp_path: Path) -> None:
    db_path = tmp_path / "partial.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "CREATE TABLE prediction_outbox (outbox_id TEXT PRIMARY KEY)"
        )

    storage = SQLiteStorage(f"sqlite:///{db_path}")
    with pytest.raises(sqlite3.OperationalError, match="no such column"):
        storage.initialize()

    with sqlite3.connect(db_path) as conn:
        versions = [
            row[0]
            for row in conn.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()
        ]
        columns = [
            row[1]
            for row in conn.execute("PRAGMA table_info(prediction_outbox)").fetchall()
        ]

    assert versions == [1]
    assert columns == ["outbox_id"]


def test_lifecycle_policy_is_exact_and_prohibits_automatic_deletion() -> None:
    loaded = load_data_lifecycle_policy(
        "configs/data_lifecycle_policy.v1.json"
    )
    assert len(loaded.sha256) == 64
    assert loaded.document["authority"]["automatic_deletion_authorized"] is False
    assert loaded.document["privacy"]["credential_plaintext_storage_allowed"] is False

    unsafe = json.loads(json.dumps(loaded.document))
    unsafe["authority"]["automatic_deletion_authorized"] = True
    with pytest.raises(ValueError, match="manual and recoverable"):
        validate_data_lifecycle_policy(unsafe)


def test_session_worker_lifecycle_policy_is_recorded_by_exact_hash(
    tmp_path: Path,
) -> None:
    storage = _storage(tmp_path)
    storage.initialize()
    loaded = load_data_lifecycle_policy(
        "configs/data_lifecycle_policy.v1.json"
    )
    storage.record_data_lifecycle_policy(
        policy_id=loaded.policy_id,
        policy_version=loaded.version,
        policy_sha256=loaded.sha256,
        effective_path=loaded.path,
    )
    with sqlite3.connect(storage.path) as conn:
        row = conn.execute(
            """
            SELECT policy_id, policy_version, policy_sha256, effective_path
            FROM data_lifecycle_policy_ledger
            """
        ).fetchone()
    assert row == (
        loaded.policy_id,
        loaded.version,
        loaded.sha256,
        loaded.path,
    )


def test_sqlite_online_backup_verify_and_restore_are_non_overwriting(
    tmp_path: Path,
) -> None:
    storage = _storage(tmp_path)
    storage.initialize()
    storage.store_event(
        "sensor-1",
        {
            "eventid": "cowrie.session.connect",
            "session": "backup-session",
            "src_ip": "192.0.2.10",
            "timestamp": "2026-07-01T00:00:00Z",
        },
    )
    backup = tmp_path / "backups" / "state.sqlite3"
    manifest = create_backup(storage.path, backup)
    manifest_path = Path(manifest["manifest_path"])
    verified = verify_backup(backup, manifest_path)
    assert verified["verified"] is True
    assert verified["table_counts"]["events"] == 1
    assert backup.stat().st_mode & 0o077 == 0
    assert manifest_path.stat().st_mode & 0o077 == 0
    with pytest.raises(FileExistsError):
        create_backup(storage.path, backup)

    restored = tmp_path / "restored" / "state.sqlite3"
    result = restore_backup(backup, manifest_path, restored)
    assert result["restored"] is True
    assert result["table_counts"] == verified["table_counts"]
    with pytest.raises(FileExistsError):
        restore_backup(backup, manifest_path, restored)


def test_secret_files_are_private_service_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database_secret = tmp_path / "database-url"
    database_secret.write_text(
        f"sqlite:///{tmp_path / 'secret.db'}\n", encoding="utf-8"
    )
    database_secret.chmod(0o600)
    tokens_secret = tmp_path / "sensor-tokens.json"
    tokens_secret.write_text(
        json.dumps({"pi-1": "unit-test-sensor-token-123456"}),
        encoding="utf-8",
    )
    tokens_secret.chmod(0o600)
    monkeypatch.setenv("DATABASE_URL_FILE", str(database_secret))
    monkeypatch.setenv("INGEST_SENSOR_TOKENS_JSON_FILE", str(tokens_secret))

    config = ProductionConfig.from_env()
    assert config.database_url.endswith("/secret.db")
    assert config.ingest_sensor_tokens == {
        "pi-1": "unit-test-sensor-token-123456"
    }

    monkeypatch.setenv("DATABASE_URL", "sqlite:////tmp/conflict.db")
    with pytest.raises(ValueError, match="cannot both be set"):
        ProductionConfig.from_env()


def test_secret_files_reject_weak_permissions_and_symlinks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    weak = tmp_path / "weak"
    weak.write_text("sqlite:////tmp/weak.db", encoding="utf-8")
    weak.chmod(0o644)
    monkeypatch.setenv("DATABASE_URL_FILE", str(weak))
    with pytest.raises(ValueError, match="group or other"):
        ProductionConfig.from_env()

    weak.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(weak)
    monkeypatch.setenv("DATABASE_URL_FILE", str(link))
    with pytest.raises(ValueError, match="non-symlink"):
        ProductionConfig.from_env()


def test_systemd_units_use_service_specific_environment_files() -> None:
    service_dir = Path("deployment/systemd")
    units = sorted(service_dir.glob("*.service"))
    assert units
    for unit in units:
        text = unit.read_text(encoding="utf-8")
        assert "/etc/honeypot/honeypot.env" not in text
        assert "EnvironmentFile=-/etc/honeypot/common.env" in text
        expected = unit.name.removeprefix("honeypot-").removesuffix(".service")
        assert f"/etc/honeypot/services/{expected}.env" in text

    enrichment = (service_dir / "services/enrichment-worker.env.example").read_text(
        encoding="utf-8"
    )
    ingest = (service_dir / "services/ingest-api.env.example").read_text(
        encoding="utf-8"
    )
    forwarder = (service_dir / "services/sensor-forwarder.env.example").read_text(
        encoding="utf-8"
    )
    assert "OTX_API_KEY_FILE=" in enrichment
    assert "INGEST_SENSOR_TOKENS_JSON_FILE=" in ingest
    assert "HONEYPOT_API_TOKEN_FILE=" in forwarder
    assert "DATABASE_URL_FILE=" not in forwarder
