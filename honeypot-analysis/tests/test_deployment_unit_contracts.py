from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
UNITS = ROOT / "deployment" / "systemd"


def test_session_count_monitor_uses_explicit_hardened_runtime_state() -> None:
    text = (UNITS / "honeypot-session-count-monitor.service").read_text(
        encoding="utf-8"
    )

    assert (
        "Environment=SESSION_COUNT_MONITOR_STATE_PATH="
        "/var/lib/honeypot/session_count_monitor_state.json"
    ) in text
    assert "ReadWritePaths=/var/lib/honeypot" in text
    assert "UMask=0077" in text
    assert "NoNewPrivileges=true" in text
    assert "PrivateTmp=true" in text
    assert "ProtectSystem=full" in text


def test_archived_prediction_unit_templates_are_not_reintroduced() -> None:
    for name in (
        "honeypot-calibration-worker.service",
        "honeypot-calibration-worker.timer",
        "honeypot-prediction-retention.service",
        "honeypot-prediction-retention.timer",
    ):
        assert not (UNITS / name).exists()
