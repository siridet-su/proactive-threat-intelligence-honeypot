from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest

from production.api import ingest_api
from production.utils.startup_diagnostics import (
    STARTUP_DIAGNOSTICS_SCHEMA,
    StartupDiagnostics,
    closed_error_category,
)


def test_startup_diagnostics_is_atomic_bounded_and_owner_only(tmp_path: Path) -> None:
    marker_root = tmp_path / "release"
    marker_root.mkdir()
    (marker_root / "DEPLOYED_COMMIT").write_text("a" * 40 + "\n", encoding="utf-8")
    path = tmp_path / "state" / "ingest.json"
    diagnostics = StartupDiagnostics("ingest_api", path=path, release_root=marker_root)
    diagnostics.enter("PROCESS_STARTED")
    diagnostics.complete("PROCESS_STARTED")
    diagnostics.enter("CONFIG_LOADED")
    diagnostics.complete("CONFIG_LOADED")
    diagnostics.enter("SERVICE_READY")
    diagnostics.complete("SERVICE_READY")
    diagnostics.ready()

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == STARTUP_DIAGNOSTICS_SCHEMA
    assert payload["service"] == "ingest_api"
    assert payload["release_revision"] == "a" * 40
    assert payload["status"] == "ready"
    assert [item["stage"] for item in payload["stages"]] == [
        "PROCESS_STARTED",
        "CONFIG_LOADED",
        "SERVICE_READY",
    ]
    assert "DATABASE_URL" not in path.read_text(encoding="utf-8")
    assert not list(path.parent.glob("*.tmp"))
    assert os.stat(path).st_mode & 0o777 == 0o600
    assert os.stat(path.parent).st_mode & 0o777 == 0o700


def test_startup_diagnostics_rejects_out_of_order_and_unknown_stages(tmp_path: Path) -> None:
    diagnostics = StartupDiagnostics("ingest", path=tmp_path / "state.json")
    with pytest.raises(ValueError):
        diagnostics.enter("NOT_A_STAGE")
    diagnostics.enter("PROCESS_STARTED")
    with pytest.raises(ValueError):
        diagnostics.enter("CONFIG_LOADED")
    diagnostics.complete("PROCESS_STARTED")
    with pytest.raises(ValueError):
        diagnostics.complete("DATABASE_OPEN_COMPLETED")


def test_startup_diagnostics_tolerates_precreated_shared_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "shared"
    parent.mkdir(mode=0o770)
    path = parent / "ingest.json"
    chmod = os.chmod

    def deny_parent(path_value: str | os.PathLike[str], mode: int) -> None:
        if Path(path_value) == parent:
            raise PermissionError("shared runtime directory is root-owned")
        chmod(path_value, mode)

    monkeypatch.setattr(os, "chmod", deny_parent)
    diagnostics = StartupDiagnostics("ingest", path=path)
    diagnostics.enter("PROCESS_STARTED")
    diagnostics.complete("PROCESS_STARTED")
    assert json.loads(path.read_text(encoding="utf-8"))["status"] == "running"
    assert os.stat(path).st_mode & 0o777 == 0o600


def test_startup_failure_is_closed_and_does_not_retain_exception_text(tmp_path: Path) -> None:
    diagnostics = StartupDiagnostics("ingest", path=tmp_path / "state.json")
    diagnostics.enter("DATABASE_OPEN_STARTED")
    diagnostics.fail(sqlite3.OperationalError("secret database password 123"))
    payload = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    assert payload["status"] == "failed"
    failure = payload["stages"][-1]
    assert failure["stage"] == "STARTUP_FAILED"
    assert failure["error_category"] == "DATABASE_UNAVAILABLE"
    text = (tmp_path / "state.json").read_text(encoding="utf-8")
    assert "secret" not in text
    assert "password" not in text


@pytest.mark.parametrize(
    ("exc", "category"),
    [
        (FileNotFoundError("missing"), "CREDENTIALS_UNAVAILABLE"),
        (PermissionError("denied"), "PERMISSION_DENIED"),
        (sqlite3.OperationalError("database is locked"), "DATABASE_LOCKED"),
        (ImportError("module"), "DEPENDENCY_IMPORT_FAILED"),
        (ValueError("invalid"), "CONFIGURATION_INVALID"),
    ],
)
def test_closed_error_category_registry(exc: BaseException, category: str) -> None:
    assert closed_error_category(exc) == category


def test_ingest_main_records_stage_progression_without_changing_runtime_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = ingest_api.ProductionConfig(
        sensor_id="sensor-a",
        api_token="token-a",
        ingest_host="127.0.0.1",
        ingest_port=8080,
    )
    fake_server = object()
    monkeypatch.setenv(
        "STARTUP_DIAGNOSTICS_PATH", str(tmp_path / "ingest-startup.json")
    )
    monkeypatch.setattr(ingest_api.ProductionConfig, "from_env", lambda _path: config)
    monkeypatch.setattr(ingest_api, "_validate_ingest_config", lambda _config: {})
    monkeypatch.setattr(ingest_api, "open_storage", lambda _settings: object())
    monkeypatch.setattr(
        ingest_api, "build_server", lambda _config, storage=None: fake_server
    )
    monkeypatch.setattr(ingest_api, "serve_http_until_stopped", lambda _server: None)

    assert ingest_api.main([]) == 0
    payload = json.loads((tmp_path / "ingest-startup.json").read_text(encoding="utf-8"))
    assert payload["status"] == "ready"
    assert payload["stages"][-1]["stage"] == "SERVICE_READY"
    assert payload["stages"][-1]["status"] == "completed"


def test_ingest_main_records_closed_missing_config_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "ingest-startup.json"
    monkeypatch.setenv("STARTUP_DIAGNOSTICS_PATH", str(path))
    monkeypatch.setattr(
        ingest_api.ProductionConfig,
        "from_env",
        lambda _path: (_ for _ in ()).throw(FileNotFoundError("secret path")),
    )
    with pytest.raises(FileNotFoundError):
        ingest_api.main([])
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["status"] == "failed"
    assert payload["stages"][-1]["error_category"] == "CREDENTIALS_UNAVAILABLE"
