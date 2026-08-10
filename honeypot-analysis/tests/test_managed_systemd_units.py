from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from production.tools.managed_systemd_units import (
    load_managed_unit_policy,
    validate_managed_unit_policy,
    validate_unit_inventory,
)


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "deployment" / "systemd" / "managed_units.v1.json"


def _loaded():
    return load_managed_unit_policy(str(POLICY_PATH))


def _valid_gcp_inventory() -> tuple[dict[str, str], set[str]]:
    profile = _loaded().document["profiles"]["gcp_backend"]
    enabled = set(profile["required_enabled_units"])
    unit_files = {
        unit: "enabled" if unit in enabled else "static"
        for unit in profile["managed_installed_units"]
    }
    return unit_files, set(profile["required_active_units"])


def test_managed_unit_policy_is_strict_and_hash_bound() -> None:
    loaded = _loaded()
    assert len(loaded.sha256) == 64
    source = json.loads(POLICY_PATH.read_text(encoding="utf-8"))

    extra = copy.deepcopy(source)
    extra["profiles"]["gcp_backend"]["invented"] = []
    with pytest.raises(ValueError):
        validate_managed_unit_policy(extra)

    enabled_obsolete = copy.deepcopy(source)
    enabled_obsolete["profiles"]["gcp_backend"][
        "required_enabled_units"
    ].append("honeypot-prediction-backtest.timer")
    enabled_obsolete["profiles"]["gcp_backend"]["required_enabled_units"].sort()
    with pytest.raises(ValueError):
        validate_managed_unit_policy(enabled_obsolete)

    unsorted = copy.deepcopy(source)
    unsorted["profiles"]["gcp_backend"]["required_active_units"].reverse()
    with pytest.raises(ValueError):
        validate_managed_unit_policy(unsorted)


def test_gcp_profile_accepts_only_the_exact_reviewed_enabled_set() -> None:
    loaded = _loaded()
    unit_files, active = _valid_gcp_inventory()
    valid = validate_unit_inventory(
        loaded,
        "gcp_backend",
        unit_files=unit_files,
        active_units=active,
    )
    assert valid["status"] == "valid"
    assert not any(valid["errors"].values())

    unit_files["honeypot-unreviewed-writer.timer"] = "enabled"
    drift = validate_unit_inventory(
        loaded,
        "gcp_backend",
        unit_files=unit_files,
        active_units=active | {"honeypot-unreviewed-writer.timer"},
    )
    assert drift["status"] == "invalid"
    assert drift["errors"]["unknown_enabled_units"] == [
        "honeypot-unreviewed-writer.timer"
    ]


def test_obsolete_backtest_is_invalid_even_when_disabled() -> None:
    loaded = _loaded()
    unit_files, active = _valid_gcp_inventory()
    unit_files["honeypot-prediction-backtest.service"] = "static"
    unit_files["honeypot-prediction-backtest.timer"] = "disabled"
    result = validate_unit_inventory(
        loaded,
        "gcp_backend",
        unit_files=unit_files,
        active_units=active,
    )
    assert result["status"] == "invalid"
    assert result["errors"]["present_prohibited_units"] == [
        "honeypot-prediction-backtest.service",
        "honeypot-prediction-backtest.timer",
    ]


def test_missing_required_unit_or_active_state_fails_closed() -> None:
    loaded = _loaded()
    unit_files, active = _valid_gcp_inventory()
    unit_files.pop("honeypot-session-worker.service")
    active.remove("honeypot-session-worker.service")
    result = validate_unit_inventory(
        loaded,
        "gcp_backend",
        unit_files=unit_files,
        active_units=active,
    )
    assert result["status"] == "invalid"
    assert result["errors"]["missing_installed_units"] == [
        "honeypot-session-worker.service"
    ]
    assert result["errors"]["missing_enabled_units"] == [
        "honeypot-session-worker.service"
    ]
    assert result["errors"]["missing_active_units"] == [
        "honeypot-session-worker.service"
    ]


def test_gcp_inventory_refuses_missing_managed_ai_worker() -> None:
    loaded = _loaded()
    unit_files, active = _valid_gcp_inventory()
    unit_files.pop("honeypot-ai-advisory-worker.service")
    result = validate_unit_inventory(
        loaded,
        "gcp_backend",
        unit_files=unit_files,
        active_units=active,
    )
    assert result["status"] == "invalid"
    assert result["errors"]["missing_installed_units"] == [
        "honeypot-ai-advisory-worker.service"
    ]


def test_pi_profile_bounds_management_to_forwarder_and_cowrie_dependency() -> None:
    loaded = _loaded()
    result = validate_unit_inventory(
        loaded,
        "pi_sensor",
        unit_files={
            "honeypot-sensor-forwarder.service": "enabled",
            # Retained Pi services are outside this deployment profile.
            "honeypot-collector.service": "enabled",
        },
        active_units={
            "cowrie.service",
            "honeypot-sensor-forwarder.service",
            "honeypot-collector.service",
        },
    )
    assert result["status"] == "valid"
    assert result["errors"]["unknown_enabled_units"] == []


def test_gcp_managed_inventory_matches_repository_templates() -> None:
    loaded = _loaded()
    expected = set(
        loaded.document["profiles"]["gcp_backend"]["managed_installed_units"]
    )
    templates = {
        path.name
        for path in (ROOT / "deployment" / "systemd").glob("honeypot-*")
        if path.suffix in {".service", ".timer"}
        and path.name != "honeypot-sensor-forwarder.service"
    }
    assert templates == expected


def test_obsolete_unit_reconciler_is_exact_and_does_not_reenable_on_restore() -> None:
    text = (
        ROOT / "deployment" / "systemd" / "reconcile-obsolete-units.sh"
    ).read_text(encoding="utf-8")
    assert "honeypot-prediction-backtest.service" in text
    assert "honeypot-prediction-backtest.timer" in text
    assert "systemctl disable --now" in text
    assert "restore-files" in text
    assert "intentionally remains disabled" in text
    assert "systemctl enable" not in text
