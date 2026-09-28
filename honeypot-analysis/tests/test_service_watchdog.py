from __future__ import annotations

import importlib.util
import json
import stat
import subprocess
from pathlib import Path

import pytest


SOURCE = (
    Path(__file__).resolve().parents[1]
    / "production"
    / "tools"
    / "service_watchdog.py"
)
SPEC = importlib.util.spec_from_file_location("service_watchdog", SOURCE)
assert SPEC and SPEC.loader
watchdog = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(watchdog)


def config(*, maintenance_file: str = "/run/honeypot-maintenance.lock") -> dict:
    return {
        "schema_version": watchdog.SCHEMA,
        "node_id": "test-node",
        "maintenance_file": maintenance_file,
        "defaults": {
            "failure_threshold": 3,
            "max_restarts": 3,
            "restart_window_seconds": 900,
            "probe_timeout_seconds": 3,
            "recovery_wait_seconds": 0,
        },
        "targets": [
            {
                "kind": "systemd",
                "name": "example-worker",
                "identity": "systemd:example-worker",
                "probe": None,
                "failure_threshold": 3,
            }
        ],
    }


def state() -> dict:
    return {
        "schema_version": watchdog.STATE_SCHEMA,
        "node_id": "test-node",
        "targets": {},
    }


def test_load_config_accepts_local_probes_and_rejects_remote_http(tmp_path: Path) -> None:
    value = {
        "schema_version": watchdog.SCHEMA,
        "node_id": "gcp",
        "defaults": {},
        "targets": [{
            "kind": "systemd",
            "name": "monitor",
            "probe": {"type": "http", "url": "http://127.0.0.1:8090/health/live"},
        }],
    }
    path = tmp_path / "watchdog.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    loaded = watchdog.load_config(path)
    assert loaded["targets"][0]["probe"]["type"] == "http"

    value["targets"][0]["probe"]["url"] = "https://example.com/health"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(watchdog.WatchdogError, match="loopback"):
        watchdog.load_config(path)


@pytest.mark.parametrize("profile", ["gcp", "pi"])
def test_repository_profile_is_valid_and_never_manages_activation_gated_ai(
    profile: str,
) -> None:
    path = (
        Path(__file__).resolve().parents[1]
        / "deployment"
        / "systemd"
        / f"service-watchdog.{profile}.json"
    )
    loaded = watchdog.load_config(path)
    identities = {target["identity"] for target in loaded["targets"]}
    assert "systemd:honeypot-service-watchdog" not in identities
    assert "systemd:honeypot-ai-advisory-worker" not in identities


def test_systemd_state_parses_named_properties_in_any_order(monkeypatch) -> None:
    completed = subprocess.CompletedProcess(
        [], 0, "SubState=running\nResult=success\nLoadState=loaded\nActiveState=active\n", ""
    )
    monkeypatch.setattr(watchdog, "run", lambda *_args, **_kwargs: completed)
    assert watchdog.systemd_state("example-worker") == (
        True,
        "loaded:active:running:success",
    )


def test_three_failures_trigger_one_bounded_restart_and_recovery(monkeypatch, tmp_path: Path) -> None:
    outcomes = iter([(False, "failed"), (True, "healthy")])
    monkeypatch.setattr(watchdog, "inspect_target", lambda _target: next(outcomes))
    restarted: list[str] = []
    monkeypatch.setattr(
        watchdog,
        "restart_target",
        lambda target: (restarted.append(target["identity"]) is None, "restart_command_ok"),
    )
    selected = state()
    selected["targets"]["systemd:example-worker"] = {
        "consecutive_failures": 2,
        "restart_history": [],
    }

    result = watchdog.check(
        config(maintenance_file=str(tmp_path / "maintenance")),
        selected,
        dry_run=False,
    )

    row = result["targets"]["systemd:example-worker"]
    assert row["status"] == "RECOVERED"
    assert row["consecutive_failures"] == 0
    assert row["restart_count_in_window"] == 1
    assert restarted == ["systemd:example-worker"]


def test_restart_rate_limit_marks_crash_loop_without_restart(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(watchdog, "inspect_target", lambda _target: (False, "failed"))
    monkeypatch.setattr(
        watchdog,
        "restart_target",
        lambda _target: (_ for _ in ()).throw(AssertionError("must not restart")),
    )
    now = watchdog.time.time()
    selected = state()
    selected["targets"]["systemd:example-worker"] = {
        "consecutive_failures": 2,
        "restart_history": [now - 30, now - 20, now - 10],
    }

    result = watchdog.check(
        config(maintenance_file=str(tmp_path / "maintenance")),
        selected,
        dry_run=False,
    )

    row = result["targets"]["systemd:example-worker"]
    assert row["status"] == "CRASH_LOOP"
    assert row["action"] == "restart_rate_limited"


def test_maintenance_lock_suppresses_restart(monkeypatch, tmp_path: Path) -> None:
    lock = tmp_path / "maintenance"
    lock.touch()
    monkeypatch.setattr(watchdog, "inspect_target", lambda _target: (False, "failed"))
    monkeypatch.setattr(
        watchdog,
        "restart_target",
        lambda _target: (_ for _ in ()).throw(AssertionError("must not restart")),
    )
    selected = state()
    selected["targets"]["systemd:example-worker"] = {
        "consecutive_failures": 2,
        "restart_history": [],
    }

    result = watchdog.check(config(maintenance_file=str(lock)), selected, dry_run=False)
    row = result["targets"]["systemd:example-worker"]
    assert row["status"] == "MAINTENANCE"
    assert row["action"] == "restart_suppressed"


def test_state_write_is_atomic_and_not_world_readable(tmp_path: Path) -> None:
    path = tmp_path / "state" / "status.json"
    watchdog.save_state(path, state())
    assert json.loads(path.read_text(encoding="utf-8"))["node_id"] == "test-node"
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
