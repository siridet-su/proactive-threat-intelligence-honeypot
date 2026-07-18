from __future__ import annotations

import json

import pytest

from production.utils.config import ProductionConfig


def test_event_processing_config_defaults_are_safe() -> None:
    config = ProductionConfig()

    assert config.event_lease_seconds == 60.0
    assert config.event_lease_heartbeat_seconds == 20.0
    assert config.event_max_attempts == 5
    assert config.event_retry_base_seconds == 5.0
    assert config.event_retry_max_seconds == 300.0
    assert config.worker_leader_lease_seconds == 90.0
    assert config.worker_leader_heartbeat_seconds == 10.0


def test_event_processing_config_loads_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {
        "EVENT_LEASE_SECONDS": "90.5",
        "EVENT_LEASE_HEARTBEAT_SECONDS": "30.5",
        "EVENT_MAX_ATTEMPTS": "7",
        "EVENT_RETRY_BASE_SECONDS": "2.5",
        "EVENT_RETRY_MAX_SECONDS": "45.5",
        "WORKER_LEADER_LEASE_SECONDS": "150.5",
        "WORKER_LEADER_HEARTBEAT_SECONDS": "15.5",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)

    config = ProductionConfig.from_env()

    assert config.event_lease_seconds == 90.5
    assert config.event_lease_heartbeat_seconds == 30.5
    assert config.event_max_attempts == 7
    assert config.event_retry_base_seconds == 2.5
    assert config.event_retry_max_seconds == 45.5
    assert config.worker_leader_lease_seconds == 150.5
    assert config.worker_leader_heartbeat_seconds == 15.5


def test_event_processing_config_loads_config_file(tmp_path) -> None:
    config_path = tmp_path / "production.json"
    config_path.write_text(
        json.dumps(
            {
                "event_lease_seconds": 80.0,
                "event_lease_heartbeat_seconds": 25.0,
                "event_max_attempts": 9,
                "event_retry_base_seconds": 3.0,
                "event_retry_max_seconds": 90.0,
                "worker_leader_lease_seconds": 120.0,
                "worker_leader_heartbeat_seconds": 12.0,
            }
        ),
        encoding="utf-8",
    )

    config = ProductionConfig.from_env(str(config_path))

    assert config.event_lease_seconds == 80.0
    assert config.event_lease_heartbeat_seconds == 25.0
    assert config.event_max_attempts == 9
    assert config.event_retry_base_seconds == 3.0
    assert config.event_retry_max_seconds == 90.0
    assert config.worker_leader_lease_seconds == 120.0
    assert config.worker_leader_heartbeat_seconds == 12.0


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("event_lease_seconds", 0),
        ("event_lease_heartbeat_seconds", -1),
        ("event_max_attempts", 0),
        ("event_retry_base_seconds", 0),
        ("event_retry_max_seconds", -1),
        ("worker_leader_lease_seconds", 0),
        ("worker_leader_heartbeat_seconds", -1),
        ("event_lease_heartbeat_seconds", 60.0),
        ("worker_leader_heartbeat_seconds", 90.0),
        ("worker_leader_lease_seconds", 79.0),
        ("event_retry_base_seconds", 301.0),
    ],
)
def test_event_processing_config_rejects_invalid_file_values(
    tmp_path,
    field: str,
    value: object,
) -> None:
    config_path = tmp_path / "production.json"
    config_path.write_text(json.dumps({field: value}), encoding="utf-8")

    with pytest.raises(ValueError):
        ProductionConfig.from_env(str(config_path))


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("EVENT_LEASE_SECONDS", "0"),
        ("EVENT_LEASE_HEARTBEAT_SECONDS", "60"),
        ("EVENT_MAX_ATTEMPTS", "0"),
        ("EVENT_RETRY_BASE_SECONDS", "301"),
        ("EVENT_RETRY_MAX_SECONDS", "0"),
        ("WORKER_LEADER_LEASE_SECONDS", "0"),
        ("WORKER_LEADER_HEARTBEAT_SECONDS", "90"),
        ("WORKER_LEADER_LEASE_SECONDS", "79"),
    ],
)
def test_event_processing_config_rejects_invalid_environment_values(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    value: str,
) -> None:
    monkeypatch.setenv(name, value)

    with pytest.raises(ValueError):
        ProductionConfig.from_env()
