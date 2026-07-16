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


def test_example_config_uses_explicit_backend_contract() -> None:
    values = json.loads(
        Path("configs/production_config.example.json").read_text(encoding="utf-8")
    )
    config = ProductionConfig(**values)

    assert config.database_backend == "sqlite"
    assert config.sqlite_database_path == "production_state.db"
    assert "database_url" not in values
