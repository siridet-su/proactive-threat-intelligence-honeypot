from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


SCHEMA_VERSION = "managed_systemd_units.v1"
PROFILE_NAMES = frozenset({"gcp_backend", "pi_sensor"})
UNIT_PATTERN = re.compile(r"^[a-zA-Z0-9_.@-]+\.(?:service|timer|socket|path)$")
ENABLED_STATES = frozenset({"enabled", "enabled-runtime", "linked", "linked-runtime"})


@dataclass(frozen=True)
class LoadedManagedUnitPolicy:
    path: str
    sha256: str
    document: Mapping[str, Any]

    @property
    def policy_id(self) -> str:
        return str(self.document["policy_id"])

    @property
    def version(self) -> str:
        return str(self.document["version"])


def _exact_keys(value: Mapping[str, Any], expected: set[str], context: str) -> None:
    actual = set(value)
    if actual != expected:
        raise ValueError(
            f"{context} keys invalid; "
            f"missing={sorted(expected - actual)}, extra={sorted(actual - expected)}"
        )


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{context} must be an object")
    return value


def _unit_list(value: Any, context: str) -> list[str]:
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) or not UNIT_PATTERN.fullmatch(item) for item in value)
        or len(value) != len(set(value))
        or value != sorted(value)
    ):
        raise ValueError(f"{context} must be a sorted unique list of systemd units")
    return list(value)


def validate_managed_unit_policy(document: Any) -> None:
    policy = _mapping(document, "managed unit policy")
    _exact_keys(
        policy,
        {"schema_version", "policy_id", "version", "profiles"},
        "policy",
    )
    if policy["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"schema_version must be {SCHEMA_VERSION}")
    for field in ("policy_id", "version"):
        if not isinstance(policy[field], str) or not policy[field].strip():
            raise ValueError(f"{field} must be a non-empty string")
    profiles = _mapping(policy["profiles"], "profiles")
    if set(profiles) != PROFILE_NAMES:
        raise ValueError("profiles must exactly define gcp_backend and pi_sensor")
    for profile_name, raw_profile in profiles.items():
        profile = _mapping(raw_profile, f"profiles.{profile_name}")
        _exact_keys(
            profile,
            {
                "managed_installed_units",
                "required_enabled_units",
                "required_active_units",
                "allowed_external_enabled_units",
                "prohibited_units",
                "enabled_unit_prefix",
            },
            f"profiles.{profile_name}",
        )
        installed = set(
            _unit_list(
                profile["managed_installed_units"],
                f"profiles.{profile_name}.managed_installed_units",
            )
        )
        enabled = set(
            _unit_list(
                profile["required_enabled_units"],
                f"profiles.{profile_name}.required_enabled_units",
            )
        )
        _unit_list(
            profile["required_active_units"],
            f"profiles.{profile_name}.required_active_units",
        )
        external = set(
            _unit_list(
                profile["allowed_external_enabled_units"],
                f"profiles.{profile_name}.allowed_external_enabled_units",
            )
        )
        prohibited = set(
            _unit_list(
                profile["prohibited_units"],
                f"profiles.{profile_name}.prohibited_units",
            )
        )
        prefix = profile["enabled_unit_prefix"]
        if not isinstance(prefix, str) or not prefix or any(
            character.isspace() for character in prefix
        ):
            raise ValueError(
                f"profiles.{profile_name}.enabled_unit_prefix is invalid"
            )
        if not enabled <= installed:
            raise ValueError(
                f"profiles.{profile_name} enables a unit outside its managed inventory"
            )
        if (installed | external) & prohibited:
            raise ValueError(
                f"profiles.{profile_name} allows a prohibited unit"
            )
        if enabled & external:
            raise ValueError(
                f"profiles.{profile_name} duplicates managed and external enabled units"
            )


def load_managed_unit_policy(path_text: str) -> LoadedManagedUnitPolicy:
    path = Path(path_text)
    try:
        raw = path.read_bytes()
        document = json.loads(raw)
    except OSError as exc:
        raise ValueError(f"managed unit policy unavailable: {path}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"managed unit policy is invalid JSON: {path}") from exc
    validate_managed_unit_policy(document)
    return LoadedManagedUnitPolicy(
        path=str(path.resolve()),
        sha256=hashlib.sha256(raw).hexdigest(),
        document=document,
    )


def validate_unit_inventory(
    loaded: LoadedManagedUnitPolicy,
    profile_name: str,
    *,
    unit_files: Mapping[str, str],
    active_units: set[str] | frozenset[str],
) -> dict[str, Any]:
    if profile_name not in PROFILE_NAMES:
        raise ValueError("unknown managed-unit profile")
    profile = loaded.document["profiles"][profile_name]
    installed = set(profile["managed_installed_units"])
    required_enabled = set(profile["required_enabled_units"])
    required_active = set(profile["required_active_units"])
    external = set(profile["allowed_external_enabled_units"])
    prohibited = set(profile["prohibited_units"])
    prefix = str(profile["enabled_unit_prefix"])

    missing_installed = sorted(installed - set(unit_files))
    enabled_now = {
        unit
        for unit, state in unit_files.items()
        if str(state).strip().lower() in ENABLED_STATES
    }
    missing_enabled = sorted(required_enabled - enabled_now)
    unknown_enabled = sorted(
        unit
        for unit in enabled_now
        if unit.startswith(prefix) and unit not in required_enabled | external
    )
    missing_active = sorted(required_active - set(active_units))
    present_prohibited = sorted(prohibited & set(unit_files))
    active_prohibited = sorted(prohibited & set(active_units))
    errors = {
        "missing_installed_units": missing_installed,
        "missing_enabled_units": missing_enabled,
        "unknown_enabled_units": unknown_enabled,
        "missing_active_units": missing_active,
        "present_prohibited_units": present_prohibited,
        "active_prohibited_units": active_prohibited,
    }
    valid = not any(errors.values())
    return {
        "schema_version": "managed_systemd_unit_validation.v1",
        "status": "valid" if valid else "invalid",
        "profile": profile_name,
        "policy_id": loaded.policy_id,
        "policy_version": loaded.version,
        "policy_sha256": loaded.sha256,
        "required_enabled_units": sorted(required_enabled),
        "required_active_units": sorted(required_active),
        "observed_enabled_units": sorted(enabled_now),
        "observed_active_units": sorted(active_units),
        "errors": errors,
    }


def _systemctl(*arguments: str) -> str:
    completed = subprocess.run(
        ["systemctl", *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return completed.stdout


def collect_live_inventory(prefix: str) -> tuple[dict[str, str], set[str]]:
    unit_files: dict[str, str] = {}
    for line in _systemctl(
        "list-unit-files", "--no-legend", "--no-pager", f"{prefix}*"
    ).splitlines():
        fields = line.split()
        if len(fields) >= 2 and UNIT_PATTERN.fullmatch(fields[0]):
            unit_files[fields[0]] = fields[1]
    active_units: set[str] = set()
    for line in _systemctl(
        "list-units",
        "--all",
        "--no-legend",
        "--no-pager",
        "--type=service",
        "--type=timer",
        "--type=socket",
        "--type=path",
    ).splitlines():
        fields = line.split()
        if (
            len(fields) >= 4
            and UNIT_PATTERN.fullmatch(fields[0])
            and fields[2] == "active"
        ):
            active_units.add(fields[0])
    return unit_files, active_units


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fail closed on managed systemd-unit drift"
    )
    parser.add_argument("--policy", required=True)
    parser.add_argument("--profile", required=True, choices=sorted(PROFILE_NAMES))
    args = parser.parse_args()
    loaded = load_managed_unit_policy(args.policy)
    profile = loaded.document["profiles"][args.profile]
    unit_files, active_units = collect_live_inventory(
        str(profile["enabled_unit_prefix"])
    )
    result = validate_unit_inventory(
        loaded,
        args.profile,
        unit_files=unit_files,
        active_units=active_units,
    )
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "valid" else 2


if __name__ == "__main__":
    raise SystemExit(main())
