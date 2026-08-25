from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest

import production.tools.activation_guard as guard_module
from production.tools.activation_guard import ActivationGuard


REVISION = "a" * 40
RECOVERY = "b" * 40
SERVICES = ("one.service", "two.service")


def _guard(
    tmp_path: Path,
    *,
    initial_health_deadline: int = 2,
    recovery_health_deadline: int = 2,
    integrity_deadline: int = 2,
) -> ActivationGuard:
    candidate = tmp_path / REVISION
    recovery = tmp_path / RECOVERY
    candidate.mkdir()
    recovery.mkdir()
    (candidate / "DEPLOYED_COMMIT").write_text(REVISION, encoding="utf-8")
    (recovery / "DEPLOYED_COMMIT").write_text(RECOVERY, encoding="utf-8")
    active = tmp_path / "current"
    os.symlink(recovery, active)
    marker = active / "DEPLOYED_COMMIT"
    return ActivationGuard(
        candidate=str(candidate),
        recovery=str(recovery),
        active_link=str(active),
        marker=str(marker),
        services=SERVICES,
        health={"ingest": "http://127.0.0.1:1/health"},
        database=str(tmp_path / "database.db"),
        receipt=str(tmp_path / "receipt.json"),
        initial_health_deadline=initial_health_deadline,
        recovery_health_deadline=recovery_health_deadline,
        integrity_deadline=integrity_deadline,
        poll_seconds=0.1,
    )


def _facts(instance: ActivationGuard, expected: str, *, ready: bool = True, failed: bool = False):
    state = "failed" if failed else ("active" if ready else "activating")
    return {
        "symlink_verified": os.path.realpath(instance.active_link) == expected,
        "marker_verified": Path(instance.marker).read_text() == Path(expected).name,
        "services_active": ready,
        "health_ready": ready,
        "database_verified": True,
        "queues_verified": True,
        "service_states": {service: state for service in SERVICES},
        "health": {"ingest": ready},
    }


def _install_successful_checks(instance: ActivationGuard, monkeypatch) -> None:
    monkeypatch.setattr(instance, "_restart", lambda: None)
    monkeypatch.setattr(instance, "_integrity_gate", lambda: True)
    monkeypatch.setattr(instance, "_lightweight_verification", lambda expected: _facts(instance, expected))


def test_candidate_ready_receipt_records_separated_gates(tmp_path, monkeypatch) -> None:
    instance = _guard(tmp_path)
    _install_successful_checks(instance, monkeypatch)

    assert instance.activate() is True
    assert os.path.realpath(instance.active_link) == str(tmp_path / REVISION)
    payload = json.loads(Path(instance.receipt).read_text(encoding="utf-8"))
    assert payload["schema_version"] == "honeypot_activation_guard_receipt.v3"
    assert payload["state"] == "CANDIDATE_READY"
    assert [event["state"] for event in payload["events"]] == [
        "GUARD_ARMED",
        "PRE_CUTOVER_DATABASE_VERIFIED",
        "CANDIDATE_STARTING",
        "CANDIDATE_PENDING",
        "CANDIDATE_SERVICE_READY",
        "CANDIDATE_DATABASE_VERIFIED",
        "CANDIDATE_READY",
    ]
    assert payload["initial_health_deadline_seconds"] == 2
    assert payload["recovery_health_deadline_seconds"] == 2
    assert payload["integrity_deadline_seconds"] == 2
    assert os.stat(instance.receipt).st_mode & 0o777 == 0o600


def test_slow_integrity_and_service_after_old_boundary_succeed_with_separate_budgets(
    tmp_path, monkeypatch
) -> None:
    instance = _guard(tmp_path, initial_health_deadline=300, integrity_deadline=300)
    monkeypatch.setattr(instance, "_restart", lambda: None)
    clock = {"now": 0.0}
    candidate_checks = {"count": 0}
    integrity_calls = {"count": 0}

    monkeypatch.setattr(guard_module.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(
        guard_module.time,
        "sleep",
        lambda _seconds: clock.__setitem__("now", clock["now"] + 220.0),
    )

    def verification(expected: str):
        if expected.endswith(RECOVERY):
            return _facts(instance, expected)
        candidate_checks["count"] += 1
        return _facts(instance, expected, ready=candidate_checks["count"] > 1)

    def integrity():
        integrity_calls["count"] += 1
        clock["now"] += 230.0
        return True

    monkeypatch.setattr(instance, "_lightweight_verification", verification)
    monkeypatch.setattr(instance, "_integrity_gate", integrity)

    assert instance.activate() is True
    # Two health polls plus one post-integrity lightweight confirmation.
    assert candidate_checks["count"] == 3
    assert integrity_calls["count"] == 2


def test_health_never_ready_still_falls_back(tmp_path, monkeypatch) -> None:
    instance = _guard(tmp_path, initial_health_deadline=1)
    monkeypatch.setattr(instance, "_restart", lambda: None)
    monkeypatch.setattr(instance, "_integrity_gate", lambda: True)
    clock = {"now": 0.0}
    monkeypatch.setattr(guard_module.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(
        guard_module.time,
        "sleep",
        lambda seconds: clock.__setitem__("now", clock["now"] + max(seconds, 0.5)),
    )
    monkeypatch.setattr(
        instance,
        "_lightweight_verification",
        lambda expected: _facts(instance, expected, ready=expected.endswith(RECOVERY)),
    )

    assert instance.activate() is False
    payload = json.loads(Path(instance.receipt).read_text(encoding="utf-8"))
    states = [event["state"] for event in payload["events"]]
    assert "CANDIDATE_HEALTH_FAILED" in states
    assert states[-1] == "FALLBACK_COMPLETED"
    assert os.path.realpath(instance.active_link) == str(tmp_path / RECOVERY)


def test_candidate_integrity_failure_rolls_back(tmp_path, monkeypatch) -> None:
    instance = _guard(tmp_path)
    monkeypatch.setattr(instance, "_restart", lambda: None)
    monkeypatch.setattr(instance, "_lightweight_verification", lambda expected: _facts(instance, expected))
    results = iter((True, False, True))
    monkeypatch.setattr(instance, "_integrity_gate", lambda: next(results))

    assert instance.activate() is False
    payload = json.loads(Path(instance.receipt).read_text(encoding="utf-8"))
    assert "CANDIDATE_DATABASE_FAILED" in [event["state"] for event in payload["events"]]
    assert payload["state"] == "FALLBACK_COMPLETED"


def test_explicit_candidate_service_failure_falls_back_without_waiting(tmp_path, monkeypatch) -> None:
    instance = _guard(tmp_path)
    monkeypatch.setattr(instance, "_restart", lambda: None)
    monkeypatch.setattr(instance, "_integrity_gate", lambda: True)
    sleeps = []
    monkeypatch.setattr(guard_module.time, "sleep", lambda seconds: sleeps.append(seconds))
    monkeypatch.setattr(
        instance,
        "_lightweight_verification",
        lambda expected: _facts(
            instance,
            expected,
            ready=expected.endswith(RECOVERY),
            failed=expected.endswith(REVISION),
        ),
    )

    assert instance.activate() is False
    assert sleeps == []
    payload = json.loads(Path(instance.receipt).read_text(encoding="utf-8"))
    failure = next(event for event in payload["events"] if event["state"] == "CANDIDATE_HEALTH_FAILED")
    assert failure["reason"] == "service_failed"


def test_recovery_health_failure_is_never_reported_as_complete(tmp_path, monkeypatch) -> None:
    instance = _guard(tmp_path, initial_health_deadline=1, recovery_health_deadline=1)
    monkeypatch.setattr(instance, "_restart", lambda: None)
    monkeypatch.setattr(instance, "_integrity_gate", lambda: True)
    clock = {"now": 0.0}
    monkeypatch.setattr(guard_module.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(guard_module.time, "sleep", lambda seconds: clock.__setitem__("now", clock["now"] + 0.5))
    calls = {"recovery": 0}

    def verification(expected: str):
        if expected.endswith(RECOVERY):
            calls["recovery"] += 1
            return _facts(instance, expected, ready=calls["recovery"] <= 2)
        return _facts(instance, expected, ready=False)

    monkeypatch.setattr(instance, "_lightweight_verification", verification)
    assert instance.activate() is False
    payload = json.loads(Path(instance.receipt).read_text(encoding="utf-8"))
    assert payload["state"] == "FALLBACK_INCOMPLETE"
    assert payload["events"][-1]["reason"] == "recovery_health_deadline_expired"


def test_recovery_integrity_failure_is_never_reported_as_complete(tmp_path, monkeypatch) -> None:
    instance = _guard(tmp_path)
    monkeypatch.setattr(instance, "_restart", lambda: None)
    monkeypatch.setattr(instance, "_lightweight_verification", lambda expected: _facts(instance, expected))
    results = iter((True, False, False))
    monkeypatch.setattr(instance, "_integrity_gate", lambda: next(results))

    assert instance.activate() is False
    payload = json.loads(Path(instance.receipt).read_text(encoding="utf-8"))
    assert payload["state"] == "FALLBACK_INCOMPLETE"
    assert payload["events"][-1]["reason"] == "recovery_integrity_verification_failed"


def test_monotonic_deadline_controls_health_polling(tmp_path, monkeypatch) -> None:
    instance = _guard(tmp_path, initial_health_deadline=3)
    clock = {"monotonic": 100.0}
    checks = {"count": 0}
    monkeypatch.setattr(guard_module.time, "monotonic", lambda: clock["monotonic"])
    monkeypatch.setattr(
        guard_module.time,
        "sleep",
        lambda _seconds: clock.__setitem__("monotonic", clock["monotonic"] + 1.0),
    )

    def verification(expected: str):
        checks["count"] += 1
        return _facts(instance, expected, ready=False)

    monkeypatch.setattr(instance, "_lightweight_verification", verification)
    ready, reason = instance._wait_for_health(instance.recovery, 3, "RECOVERY_PENDING")
    assert (ready, reason) == (False, "health_deadline_expired")
    assert checks["count"] == 3


def test_integrity_is_not_repeated_per_health_poll(tmp_path, monkeypatch) -> None:
    instance = _guard(tmp_path)
    monkeypatch.setattr(instance, "_restart", lambda: None)
    counts = {"candidate": 0, "integrity": 0}

    def verification(expected: str):
        if expected.endswith(RECOVERY):
            return _facts(instance, expected)
        counts["candidate"] += 1
        return _facts(instance, expected, ready=counts["candidate"] >= 4)

    def integrity():
        counts["integrity"] += 1
        return True

    monkeypatch.setattr(instance, "_lightweight_verification", verification)
    monkeypatch.setattr(instance, "_integrity_gate", integrity)
    monkeypatch.setattr(guard_module.time, "sleep", lambda _seconds: None)

    assert instance.activate() is True
    assert counts == {"candidate": 5, "integrity": 2}


def test_finalize_requires_recorded_candidate_integrity(tmp_path, monkeypatch) -> None:
    instance = _guard(tmp_path)
    _install_successful_checks(instance, monkeypatch)
    assert instance.activate() is True
    loaded = ActivationGuard.from_receipt(instance.receipt, health=instance.health)
    monkeypatch.setattr(loaded, "_lightweight_verification", lambda expected: _facts(loaded, expected))
    assert loaded.finalize() is True
    payload = json.loads(Path(instance.receipt).read_text(encoding="utf-8"))
    assert payload["state"] == "ACTIVATION_COMPLETED"


def test_finalize_failure_automatically_falls_back(tmp_path, monkeypatch) -> None:
    instance = _guard(tmp_path)
    _install_successful_checks(instance, monkeypatch)
    assert instance.activate() is True
    loaded = ActivationGuard.from_receipt(instance.receipt, health=instance.health)
    monkeypatch.setattr(loaded, "_restart", lambda: None)
    monkeypatch.setattr(loaded, "_integrity_gate", lambda: True)
    calls = {"candidate": 0}

    def verification(expected: str):
        if expected.endswith(RECOVERY):
            return _facts(loaded, expected)
        calls["candidate"] += 1
        return _facts(loaded, expected, ready=False)

    monkeypatch.setattr(loaded, "_lightweight_verification", verification)
    assert loaded.finalize() is False
    assert os.path.realpath(loaded.active_link) == str(tmp_path / RECOVERY)
    payload = json.loads(Path(loaded.receipt).read_text(encoding="utf-8"))
    assert payload["state"] == "FALLBACK_COMPLETED"


def test_legacy_cli_deadlines_remain_supported_and_new_deadlines_are_optional() -> None:
    args = guard_module._parser().parse_args(
        [
            "activate",
            "--candidate",
            "/tmp/" + REVISION,
            "--recovery",
            "/tmp/" + RECOVERY,
            "--services",
            ",".join(SERVICES),
            "--health",
            "ingest=http://127.0.0.1/health",
            "--database",
            "/tmp/database.db",
            "--receipt",
            "/tmp/receipt.json",
            "--initial-deadline",
            "600",
            "--recovery-deadline",
            "240",
        ]
    )
    assert args.initial_deadline == 600
    assert args.recovery_deadline == 240
    assert args.initial_health_deadline is None
    assert args.recovery_health_deadline is None
    assert args.integrity_deadline == guard_module.DEFAULT_INTEGRITY_DEADLINE_SECONDS


def test_deadlines_have_a_hard_upper_bound(tmp_path) -> None:
    with pytest.raises(ValueError, match="between 1 and 900"):
        _guard(tmp_path, integrity_deadline=901)


def test_restart_uses_exactly_the_configured_allowlist(tmp_path, monkeypatch) -> None:
    instance = _guard(tmp_path)
    commands = []
    monkeypatch.setattr(guard_module, "_run", lambda command, timeout=30.0: commands.append((command, timeout)) or True)
    instance._restart()
    assert commands == [
        (["systemctl", "stop", *SERVICES], 120),
        (["systemctl", "start", *SERVICES], 120),
    ]


def test_actual_database_checks_are_read_only_and_integrity_bounded(tmp_path) -> None:
    database = tmp_path / "database.db"
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA user_version = 3")
        for table in ("analysis_jobs", "enrichment_jobs", "threat_hunt_jobs", "prediction_outbox"):
            connection.execute(f"CREATE TABLE {table} (status TEXT)")
    assert guard_module._database_readiness(database) == {
        "database_verified": True,
        "queues_verified": True,
    }
    assert guard_module._database_integrity_ok(database, deadline_seconds=2) is True


def test_integrity_check_aborts_when_monotonic_budget_expires(tmp_path, monkeypatch) -> None:
    database = tmp_path / "database.db"
    database.touch()
    clock = {"now": 10.0}

    class SlowConnection:
        progress = None

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def set_progress_handler(self, callback, _steps):
            self.progress = callback

        def execute(self, _statement):
            clock["now"] += 3.0
            if self.progress and self.progress():
                raise sqlite3.OperationalError("interrupted")
            return self

        def fetchone(self):
            return ("ok",)

    monkeypatch.setattr(guard_module.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(guard_module.sqlite3, "connect", lambda *args, **kwargs: SlowConnection())
    assert guard_module._database_integrity_ok(database, deadline_seconds=2) is False


def test_pre_cutover_failure_does_not_switch_or_restart(tmp_path, monkeypatch) -> None:
    instance = _guard(tmp_path)
    restarts = []
    monkeypatch.setattr(instance, "_restart", lambda: restarts.append(True))
    monkeypatch.setattr(instance, "_lightweight_verification", lambda expected: _facts(instance, expected))
    monkeypatch.setattr(instance, "_integrity_gate", lambda: False)
    assert instance.activate() is False
    assert restarts == []
    assert os.path.realpath(instance.active_link) == str(tmp_path / RECOVERY)
    payload = json.loads(Path(instance.receipt).read_text(encoding="utf-8"))
    assert payload["state"] == "PRE_CUTOVER_DATABASE_FAILED"


def test_pre_cutover_queue_state_is_rechecked_after_integrity(tmp_path, monkeypatch) -> None:
    instance = _guard(tmp_path)
    restarts = []
    checks = {"count": 0}
    monkeypatch.setattr(instance, "_restart", lambda: restarts.append(True))
    monkeypatch.setattr(instance, "_integrity_gate", lambda: True)

    def verification(expected: str):
        checks["count"] += 1
        facts = _facts(instance, expected)
        if checks["count"] == 2:
            facts["queues_verified"] = False
        return facts

    monkeypatch.setattr(instance, "_lightweight_verification", verification)
    assert instance.activate() is False
    assert restarts == []
    assert os.path.realpath(instance.active_link) == str(tmp_path / RECOVERY)
    payload = json.loads(Path(instance.receipt).read_text(encoding="utf-8"))
    assert payload["state"] == "PRE_CUTOVER_DATABASE_FAILED"
    assert payload["events"][-1]["reason"] == "pre_cutover_post_integrity_readiness_failed"
