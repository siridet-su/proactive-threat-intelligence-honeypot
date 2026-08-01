from __future__ import annotations

import json
import os
from pathlib import Path

import production.tools.activation_guard as guard_module
from production.tools.activation_guard import ActivationGuard


REVISION = "a" * 40
RECOVERY = "b" * 40


def _guard(tmp_path: Path, *, recovery_deadline: int = 2) -> ActivationGuard:
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
        services=("one.service", "two.service"),
        health={"ingest": "http://127.0.0.1:1/health"},
        database=str(tmp_path / "database.db"),
        receipt=str(tmp_path / "receipt.json"),
        initial_deadline=2,
        recovery_deadline=recovery_deadline,
        poll_seconds=0.001,
    )


def test_candidate_ready_receipt_is_atomic_and_pointer_safe(tmp_path, monkeypatch) -> None:
    instance = _guard(tmp_path)
    monkeypatch.setattr(instance, "_restart", lambda: None)
    monkeypatch.setattr(
        instance,
        "_verification",
        lambda expected: {
            "symlink_verified": os.path.realpath(instance.active_link) == expected,
            "marker_verified": Path(instance.marker).read_text() == Path(expected).name,
            "services_active": True,
            "health_ready": True,
            "database_verified": True,
            "queues_verified": True,
            "service_states": {},
            "health": {},
        },
    )
    assert instance.activate() is True
    assert os.path.realpath(instance.active_link) == str(tmp_path / REVISION)
    payload = json.loads(Path(instance.receipt).read_text(encoding="utf-8"))
    assert payload["state"] == "CANDIDATE_READY"
    assert [event["state"] for event in payload["events"]] == [
        "GUARD_ARMED",
        "CANDIDATE_STARTING",
        "CANDIDATE_PENDING",
        "CANDIDATE_READY",
    ]
    assert os.stat(instance.receipt).st_mode & 0o777 == 0o600


def test_delayed_recovery_endpoint_remains_pending_then_completes(tmp_path, monkeypatch) -> None:
    instance = _guard(tmp_path, recovery_deadline=2)
    monkeypatch.setattr(instance, "_restart", lambda: None)
    calls = {"count": 0}

    def verification(expected: str):
        calls["count"] += 1
        ready = expected.endswith(RECOVERY) and calls["count"] > 2
        return {
            "symlink_verified": os.path.realpath(instance.active_link) == expected,
            "marker_verified": Path(instance.marker).read_text() == Path(expected).name,
            "services_active": ready,
            "health_ready": ready,
            "database_verified": ready,
            "queues_verified": ready,
            "service_states": {},
            "health": {},
        }

    monkeypatch.setattr(instance, "_verification", verification)
    assert instance.activate() is False
    payload = json.loads(Path(instance.receipt).read_text(encoding="utf-8"))
    states = [event["state"] for event in payload["events"]]
    assert "RECOVERY_PENDING" in states
    assert states[-1] == "FALLBACK_COMPLETED"
    assert "FALLBACK_INCOMPLETE" not in states


def test_recovery_deadline_is_the_only_incomplete_transition(tmp_path, monkeypatch) -> None:
    instance = _guard(tmp_path, recovery_deadline=1)
    monkeypatch.setattr(instance, "_restart", lambda: None)
    monkeypatch.setattr(
        instance,
        "_verification",
        lambda expected: {
            "symlink_verified": os.path.realpath(instance.active_link) == expected,
            "marker_verified": Path(instance.marker).read_text() == Path(expected).name,
            "services_active": False,
            "health_ready": False,
            "database_verified": True,
            "queues_verified": True,
            "service_states": {},
            "health": {},
        },
    )
    assert instance.activate() is False
    payload = json.loads(Path(instance.receipt).read_text(encoding="utf-8"))
    assert payload["state"] == "FALLBACK_INCOMPLETE"
    assert payload["events"][-1]["reason"] == "recovery_verification_deadline_expired"
