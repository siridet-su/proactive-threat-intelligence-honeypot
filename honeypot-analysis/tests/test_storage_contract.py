from __future__ import annotations

import json
from pathlib import Path

import pytest

from production.storage import (
    DatabaseConfigurationError,
    DatabaseSettings,
    SQLiteStorage,
    StorageBackend,
    StorageError,
    open_storage,
    safe_database_descriptor,
)
from production.utils.config import ProductionConfig


DATABASE_ENVIRONMENT_KEYS = (
    "DATABASE_BACKEND",
    "DATABASE_URL",
    "SQLITE_DATABASE_PATH",
    "MONGODB_URI",
    "MONGODB_DATABASE",
    "HONEYPOT_CONFIG_FILE",
)


def _clear_database_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in DATABASE_ENVIRONMENT_KEYS:
        monkeypatch.delenv(name, raising=False)


def test_default_config_selects_sqlite_safely(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_database_environment(monkeypatch)
    config = ProductionConfig.from_env()

    assert config.database_backend == "sqlite"
    assert config.sqlite_database_path == "production_state.db"
    assert config.database_url == "sqlite:///production_state.db"
    assert config.safe_database_descriptor() == {
        "backend": "sqlite",
        "database_path": "production_state.db",
    }


def test_explicit_sqlite_environment_overrides_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_database_environment(monkeypatch)
    database_path = tmp_path / "state.db"
    monkeypatch.setenv("DATABASE_BACKEND", "sqlite")
    monkeypatch.setenv("SQLITE_DATABASE_PATH", str(database_path))

    config = ProductionConfig.from_env()

    assert config.database_backend == "sqlite"
    assert config.sqlite_database_path == str(database_path)
    assert config.database_url == f"sqlite:///{database_path}"


def test_legacy_database_url_still_selects_backend(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_database_environment(monkeypatch)
    database_path = tmp_path / "legacy.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{database_path}")

    config = ProductionConfig.from_env()

    assert config.database_backend == "sqlite"
    assert config.sqlite_database_path == str(database_path)


def test_explicit_backend_conflict_with_legacy_url_fails() -> None:
    with pytest.raises(
        DatabaseConfigurationError,
        match="database_backend conflicts",
    ):
        DatabaseSettings.from_values(
            database_backend="sqlite",
            database_url="mongodb://database.internal/honeypot",
            sqlite_database_path="state.db",
        )


def test_explicit_sqlite_path_conflict_with_legacy_url_fails() -> None:
    with pytest.raises(
        DatabaseConfigurationError,
        match="SQLITE_DATABASE_PATH conflicts",
    ):
        DatabaseSettings.from_values(
            database_backend="sqlite",
            database_url="sqlite:///one.db",
            sqlite_database_path="two.db",
        )


def test_mongodb_backend_requires_uri_and_database() -> None:
    with pytest.raises(DatabaseConfigurationError, match="requires MONGODB_URI"):
        DatabaseSettings.from_values(
            database_backend="mongodb",
            mongodb_database="honeypot",
        )

    with pytest.raises(
        DatabaseConfigurationError,
        match="requires MONGODB_DATABASE",
    ):
        DatabaseSettings.from_values(
            database_backend="mongodb",
            mongodb_uri="mongodb://database.internal:27017/",
        )


def test_mongodb_file_backend_can_receive_secret_uri_from_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_database_environment(monkeypatch)
    config_path = tmp_path / "production.json"
    config_path.write_text(
        json.dumps(
            {
                "database_backend": "mongodb",
                "mongodb_database": "honeypot",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv(
        "MONGODB_URI",
        "mongodb://unit-user:unit-password@database.internal:27017/"
        "?authSource=admin&token=unit-secret",
    )

    config = ProductionConfig.from_env(str(config_path))

    assert config.database_backend == "mongodb"
    assert config.mongodb_database == "honeypot"
    descriptor = config.safe_database_descriptor()
    assert descriptor == {
        "backend": "mongodb",
        "endpoint": "database.internal:27017",
        "database": "honeypot",
    }
    assert "unit-user" not in str(descriptor)
    assert "unit-password" not in str(descriptor)
    assert "unit-secret" not in str(descriptor)
    assert "authSource" not in str(descriptor)


def test_safe_descriptor_redacts_postgresql_credentials_and_options() -> None:
    descriptor = safe_database_descriptor(
        "postgresql://unit-user:unit-password@database.internal:5432/honeypot"
        "?sslpassword=unit-secret"
    )

    assert descriptor == {
        "backend": "postgresql",
        "endpoint": "database.internal:5432",
        "database": "honeypot",
    }
    assert "unit-user" not in str(descriptor)
    assert "unit-password" not in str(descriptor)
    assert "unit-secret" not in str(descriptor)


def test_unsupported_url_error_does_not_echo_credentials() -> None:
    database_url = "mysql://unit-user:unit-password@database.internal/honeypot"

    with pytest.raises(StorageError) as raised:
        safe_database_descriptor(database_url)

    assert "mysql" in str(raised.value)
    assert "unit-user" not in str(raised.value)
    assert "unit-password" not in str(raised.value)


def test_specifically_configured_missing_file_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_database_environment(monkeypatch)
    missing = tmp_path / "missing.json"

    with pytest.raises(FileNotFoundError, match="production config file not found"):
        ProductionConfig.from_env(str(missing))


def test_sqlite_adapter_implements_contract_and_health_check(
    tmp_path: Path,
) -> None:
    storage = open_storage(
        DatabaseSettings.from_values(
            database_backend="sqlite",
            sqlite_database_path=str(tmp_path / "contract.db"),
        )
    )

    assert isinstance(storage, SQLiteStorage)
    assert isinstance(storage, StorageBackend)
    assert storage.health_check() == {"ok": True, "backend": "sqlite"}


def test_sqlite_list_rows_for_session_matches_list_rows_shape_and_order(
    tmp_path: Path,
) -> None:
    storage = open_storage(f"sqlite:///{tmp_path / 'session-rows.db'}")
    first_id, _ = storage.store_event(
        "sensor",
        {
            "eventid": "cowrie.login.failed",
            "session": "session-a",
            "src_ip": "8.8.8.8",
            "timestamp": "2026-07-16T00:00:01Z",
        },
    )
    storage.store_event(
        "sensor",
        {
            "eventid": "cowrie.login.failed",
            "session": "session-b",
            "src_ip": "1.1.1.1",
            "timestamp": "2026-07-16T00:00:02Z",
        },
    )
    latest_id, _ = storage.store_event(
        "sensor",
        {
            "eventid": "cowrie.command.input",
            "session": "session-a",
            "src_ip": "8.8.8.8",
            "timestamp": "2026-07-16T00:00:03Z",
            "input": "id",
        },
    )

    expected = [
        row
        for row in storage.list_rows("events", limit=10)
        if row["session_id"] == "session-a"
    ]
    actual = storage.list_rows_for_session("events", "session-a", limit=10)

    assert actual == expected
    assert [row["event_id"] for row in actual] == [latest_id, first_id]
    assert storage.list_rows_for_session("events", "session-a", limit=1) == [
        expected[0]
    ]


def test_sqlite_list_rows_for_session_supports_explicit_table_allowlist(
    tmp_path: Path,
) -> None:
    storage = open_storage(f"sqlite:///{tmp_path / 'allowed-session-rows.db'}")
    allowed_tables = (
        "events",
        "sessions",
        "alerts",
        "analysis_jobs",
        "reports",
        "enrichment_jobs",
        "prediction_snapshots",
        "analyst_feedback",
        "classification_review_labels",
        "observable_sightings",
        "threat_hunt_jobs",
        "campaign_sessions",
    )

    for table in allowed_tables:
        assert storage.list_rows_for_session(table, "missing-session") == []


@pytest.mark.parametrize(
    "table",
    [
        "feed_status",
        "observables",
        "webhook_deliveries",
        "events WHERE session_id = 'session-a'",
    ],
)
def test_sqlite_list_rows_for_session_rejects_non_allowlisted_tables(
    tmp_path: Path,
    table: str,
) -> None:
    storage = open_storage(f"sqlite:///{tmp_path / 'rejected-session-rows.db'}")

    with pytest.raises(ValueError, match="unsupported session-scoped table"):
        storage.list_rows_for_session(table, "session-a")


def test_example_config_uses_explicit_backend_contract() -> None:
    values = json.loads(
        Path("configs/production_config.example.json").read_text(encoding="utf-8")
    )
    config = ProductionConfig(**values)

    assert config.database_backend == "sqlite"
    assert config.sqlite_database_path == "production_state.db"
    assert "database_url" not in values
