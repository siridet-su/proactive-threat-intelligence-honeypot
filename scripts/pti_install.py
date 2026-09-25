#!/usr/bin/env python3
"""Read-only PTI installation profile planner and host preflight.

This milestone supports `plan` and `preflight` only. Both read a JSON profile
and non-secret local host facts; neither installs packages, creates files,
contacts a network service, or changes service state.
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROFILE = (
    REPO_ROOT / "deploy" / "profiles" / "pi-host-foundation-ubuntu-2404-arm64.json"
)
SCHEMA_VERSION = "pti.install-profile.v1"


class ProfileError(ValueError):
    """Raised when a profile is malformed or unsafe for the plan-only tool."""


def read_os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    """Read the simple KEY=VALUE format without invoking a shell."""
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key] = value
    return values


def collect_host_facts() -> dict[str, Any]:
    """Collect only basic, non-secret facts using read-only standard-library APIs."""
    os_release = read_os_release()
    try:
        free_disk_bytes = shutil.disk_usage("/").free
    except OSError:
        free_disk_bytes = None

    return {
        "os_id": os_release.get("ID", "unknown").lower(),
        "os_version": os_release.get("VERSION_ID", "unknown"),
        "architecture": platform.machine().lower(),
        "free_disk_bytes": free_disk_bytes,
        "systemd_detected": Path("/run/systemd/system").exists(),
        "available_tools": {
            name: shutil.which(name) is not None
            for name in (
                "apt-get",
                "dpkg-query",
                "systemctl",
                "ss",
                "docker",
                "go",
                "redis-cli",
            )
        },
    }


def validate_profile(profile: dict[str, Any]) -> None:
    if profile.get("schema_version") != SCHEMA_VERSION:
        raise ProfileError(f"schema_version must be {SCHEMA_VERSION!r}")

    metadata = profile.get("profile")
    if not isinstance(metadata, dict):
        raise ProfileError("profile must be an object")
    if not isinstance(metadata.get("id"), str) or not metadata["id"]:
        raise ProfileError("profile.id must be a non-empty string")
    if metadata.get("execution_mode") != "plan-only":
        raise ProfileError("this tool accepts plan-only profiles only")
    if metadata.get("install_enabled") is not False:
        raise ProfileError("install_enabled must remain false until apply mode is reviewed")

    target = metadata.get("target")
    if not isinstance(target, dict):
        raise ProfileError("profile.target must be an object")
    if not isinstance(target.get("supported_os_ids"), list):
        raise ProfileError("target.supported_os_ids must be a list")
    if not isinstance(target.get("supported_os_versions"), list):
        raise ProfileError("target.supported_os_versions must be a list")
    if not isinstance(target.get("supported_architectures"), list):
        raise ProfileError("target.supported_architectures must be a list")
    for key in ("supported_os_ids", "supported_os_versions", "supported_architectures"):
        values = target[key]
        if not values or any(not isinstance(value, str) or not value for value in values):
            raise ProfileError(f"target.{key} must contain non-empty strings")
    if target.get("release_matrix_status") not in {"selected", "approved"}:
        raise ProfileError("target.release_matrix_status must be 'selected' or 'approved'")

    modules = profile.get("modules")
    if not isinstance(modules, list) or not modules:
        raise ProfileError("modules must be a non-empty list")

    seen: dict[str, int] = {}
    previous_order = -1
    for module in modules:
        if not isinstance(module, dict):
            raise ProfileError("each module must be an object")
        module_id = module.get("id")
        order = module.get("order")
        if not isinstance(module_id, str) or not module_id:
            raise ProfileError("each module needs a non-empty id")
        if module_id in seen:
            raise ProfileError(f"duplicate module id: {module_id}")
        if not isinstance(order, int) or order <= previous_order:
            raise ProfileError("module order values must be strictly increasing integers")
        previous_order = order
        seen[module_id] = order

    for module in modules:
        dependencies = module.get("depends_on", [])
        if not isinstance(dependencies, list):
            raise ProfileError(f"{module['id']}.depends_on must be a list")
        for dependency in dependencies:
            if dependency not in seen:
                raise ProfileError(f"{module['id']} has unknown dependency {dependency!r}")
            if seen[dependency] >= module["order"]:
                raise ProfileError(
                    f"{module['id']} must be ordered after dependency {dependency!r}"
                )

    for key in ("blockers", "excluded_modules", "separate_targets"):
        if not isinstance(profile.get(key), list):
            raise ProfileError(f"{key} must be a list")

    host_dependencies = profile.get("host_dependencies", [])
    if not isinstance(host_dependencies, list):
        raise ProfileError("host_dependencies must be a list")
    dependency_ids: set[str] = set()
    for dependency in host_dependencies:
        if not isinstance(dependency, dict):
            raise ProfileError("each host dependency group must be an object")
        dependency_id = dependency.get("id")
        if not isinstance(dependency_id, str) or not dependency_id:
            raise ProfileError("each host dependency group needs a non-empty id")
        if dependency_id in dependency_ids:
            raise ProfileError(f"duplicate host dependency id: {dependency_id}")
        dependency_ids.add(dependency_id)
        if not isinstance(dependency.get("status"), str) or not dependency["status"]:
            raise ProfileError(f"{dependency_id}.status must be a non-empty string")
        if not isinstance(dependency.get("items"), list) or any(
            not isinstance(item, str) or not item for item in dependency["items"]
        ):
            raise ProfileError(f"{dependency_id}.items must be a list of non-empty strings")
        if not isinstance(dependency.get("reason"), str) or not dependency["reason"]:
            raise ProfileError(f"{dependency_id}.reason must be a non-empty string")

    package_audit = profile.get("package_audit", {"candidate_apt_packages": []})
    if not isinstance(package_audit, dict):
        raise ProfileError("package_audit must be an object")
    candidate_packages = package_audit.get("candidate_apt_packages", [])
    if not isinstance(candidate_packages, list):
        raise ProfileError("package_audit.candidate_apt_packages must be a list")
    for package_name in candidate_packages:
        if not isinstance(package_name, str) or not re.fullmatch(
            r"[a-z0-9][a-z0-9+.-]*", package_name
        ):
            raise ProfileError(f"invalid candidate apt package name: {package_name!r}")
    if len(candidate_packages) != len(set(candidate_packages)):
        raise ProfileError("package_audit.candidate_apt_packages must not contain duplicates")


def load_profile(path: Path) -> dict[str, Any]:
    try:
        profile = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ProfileError(f"cannot read profile {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ProfileError(f"invalid JSON in profile {path}: {exc}") from exc

    if not isinstance(profile, dict):
        raise ProfileError("profile document must be a JSON object")
    validate_profile(profile)
    return profile


def build_plan(profile: dict[str, Any], host: dict[str, Any]) -> dict[str, Any]:
    validate_profile(profile)
    metadata = profile["profile"]
    target = metadata["target"]
    os_match = host.get("os_id", "unknown") in target["supported_os_ids"]
    version_match = host.get("os_version", "unknown") in target["supported_os_versions"]
    arch_match = host.get("architecture", "unknown") in target["supported_architectures"]
    target_match = os_match and version_match and arch_match

    if target_match and target.get("release_matrix_status") == "selected":
        target_assessment = "selected-target-host-match-install-blocked"
    elif target_match:
        target_assessment = "approved-target-host-match"
    else:
        target_assessment = "host-does-not-match-profile"

    return {
        "plan_only": True,
        "mutations_performed": False,
        "profile_id": metadata["id"],
        "profile_title": metadata.get("title", metadata["id"]),
        "install_enabled": metadata["install_enabled"],
        "target_assessment": target_assessment,
        "target_match": target_match,
        "host": host,
        "modules": profile["modules"],
        "host_dependencies": profile.get("host_dependencies", []),
        "separate_targets": profile["separate_targets"],
        "excluded_modules": profile["excluded_modules"],
        "blockers": profile["blockers"],
    }


def build_preflight(profile: dict[str, Any], host: dict[str, Any]) -> dict[str, Any]:
    """Check target compatibility and basic host prerequisites without mutation."""
    plan = build_plan(profile, host)
    tools = host.get("available_tools", {})
    checks = [
        {
            "id": "target-os",
            "passed": host.get("os_id") in profile["profile"]["target"]["supported_os_ids"],
            "observed": host.get("os_id", "unknown"),
            "expected": profile["profile"]["target"]["supported_os_ids"],
        },
        {
            "id": "target-os-version",
            "passed": host.get("os_version") in profile["profile"]["target"]["supported_os_versions"],
            "observed": host.get("os_version", "unknown"),
            "expected": profile["profile"]["target"]["supported_os_versions"],
        },
        {
            "id": "target-architecture",
            "passed": host.get("architecture") in profile["profile"]["target"]["supported_architectures"],
            "observed": host.get("architecture", "unknown"),
            "expected": profile["profile"]["target"]["supported_architectures"],
        },
        {
            "id": "systemd",
            "passed": bool(host.get("systemd_detected")),
            "observed": bool(host.get("systemd_detected")),
            "expected": "systemd runtime detected",
        },
        {
            "id": "apt-get",
            "passed": bool(tools.get("apt-get")),
            "observed": bool(tools.get("apt-get")),
            "expected": "apt-get available",
        },
        {
            "id": "dpkg-query",
            "passed": bool(tools.get("dpkg-query")),
            "observed": bool(tools.get("dpkg-query")),
            "expected": "dpkg-query available",
        },
    ]
    return {
        "read_only": True,
        "mutations_performed": False,
        "install_enabled": plan["install_enabled"],
        "profile_id": plan["profile_id"],
        "target_assessment": plan["target_assessment"],
        "preflight_passed": all(check["passed"] for check in checks),
        "checks": checks,
        "deployment_blockers": plan["blockers"],
    }


def collect_package_statuses(profile: dict[str, Any]) -> dict[str, str | None]:
    """Read candidate package states from dpkg without invoking apt or network access."""
    packages = profile.get("package_audit", {}).get("candidate_apt_packages", [])
    if not shutil.which("dpkg-query"):
        return {package: None for package in packages}

    statuses: dict[str, str | None] = {}
    for package in packages:
        try:
            result = subprocess.run(
                ["dpkg-query", "--show", "--showformat=${db:Status-Status}", package],
                check=False,
                capture_output=True,
                text=True,
            )
        except OSError:
            return {candidate: None for candidate in packages}
        status = result.stdout.strip() if result.returncode == 0 else "not-installed"
        statuses[package] = status
    return statuses


def build_package_audit(
    profile: dict[str, Any], statuses: dict[str, str | None]
) -> dict[str, Any]:
    """Report candidate package status; missing candidates do not trigger installation."""
    validate_profile(profile)
    candidates = profile.get("package_audit", {}).get("candidate_apt_packages", [])
    rows = [
        {"name": package, "status": statuses.get(package) or "unknown"}
        for package in candidates
    ]
    return {
        "read_only": True,
        "mutations_performed": False,
        "profile_id": profile["profile"]["id"],
        "audit_completed": all(row["status"] != "unknown" for row in rows),
        "package_source": "local dpkg status database only; no apt update or network access",
        "candidate_packages": rows,
        "scope_note": profile.get("package_audit", {}).get("scope_note", ""),
    }


def format_plan(plan: dict[str, Any]) -> str:
    host = plan["host"]
    lines = [
        "PTI installation plan (read-only)",
        f"Profile: {plan['profile_id']} — {plan['profile_title']}",
        "Execution: PLAN ONLY; install_enabled=false; no changes were made.",
        (
            "Detected host: "
            f"{host.get('os_id', 'unknown')} {host.get('os_version', 'unknown')} "
            f"on {host.get('architecture', 'unknown')}"
        ),
        f"Target assessment: {plan['target_assessment']}",
    ]
    if plan["host_dependencies"]:
        lines.extend(["", "Host dependency inventory (no installation performed):"])
        for dependency in plan["host_dependencies"]:
            items = ", ".join(dependency["items"])
            lines.append(f"  - {dependency['id']} [{dependency['status']}]: {items}")
            lines.append(f"       {dependency['reason']}")

    lines.extend(["", "Ordered modules:"])
    for module in plan["modules"]:
        required = "required" if module["required"] else "optional"
        dependencies = ", ".join(module.get("depends_on", [])) or "none"
        lines.append(
            f"  {module['order']:>3}  {module['id']} [{required}; {module['lifecycle']}]"
        )
        lines.append(f"       Automation: {module['automation_status']}")
        lines.append(f"       Depends on: {dependencies}")
        lines.append(f"       {module['summary']}")

    lines.extend(["", "Separate deployment targets:"])
    for target in plan["separate_targets"]:
        lines.append(f"  - {target['id']}: {target['title']} — {target['reason']}")

    lines.extend(["", "Not included in this profile:"])
    for module in plan["excluded_modules"]:
        lines.append(f"  - {module['id']}: {module['reason']}")

    lines.extend(["", "Apply blockers:"])
    for blocker in plan["blockers"]:
        lines.append(f"  - {blocker}")

    return "\n".join(lines)


def format_preflight(preflight: dict[str, Any]) -> str:
    lines = [
        "PTI host preflight (read-only)",
        f"Profile: {preflight['profile_id']}",
        "No packages, files, services, or network state were changed.",
        f"Target assessment: {preflight['target_assessment']}",
        f"Host preflight: {'PASS' if preflight['preflight_passed'] else 'FAIL'}",
        "",
        "Checks:",
    ]
    for check in preflight["checks"]:
        status = "PASS" if check["passed"] else "FAIL"
        lines.append(
            f"  {status} {check['id']}: observed={check['observed']!r}; "
            f"expected={check['expected']!r}"
        )
    lines.extend(["", "Deployment blockers (still prevent apply):"])
    for blocker in preflight["deployment_blockers"]:
        lines.append(f"  - {blocker}")
    return "\n".join(lines)


def format_package_audit(audit: dict[str, Any]) -> str:
    lines = [
        "PTI host package audit (read-only)",
        f"Profile: {audit['profile_id']}",
        "No apt update/install, network access, or host changes were performed.",
        f"Audit readable: {'YES' if audit['audit_completed'] else 'NO'}",
        f"Source: {audit['package_source']}",
        "",
        "Candidate package state:",
    ]
    for package in audit["candidate_packages"]:
        lines.append(f"  - {package['name']}: {package['status']}")
    if audit["scope_note"]:
        lines.extend(["", audit["scope_note"]])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only planner for PTI installation profiles."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    plan_parser = commands.add_parser("plan", help="validate and print an installation plan")
    preflight_parser = commands.add_parser(
        "preflight", help="read-only host compatibility and prerequisite checks"
    )
    package_audit_parser = commands.add_parser(
        "package-audit", help="read-only status check for profile candidate apt packages"
    )
    for command_parser in (plan_parser, preflight_parser, package_audit_parser):
        command_parser.add_argument(
            "--profile", type=Path, default=DEFAULT_PROFILE, help="JSON profile path"
        )
        command_parser.add_argument(
            "--json", action="store_true", help="emit machine-readable JSON"
        )
    args = parser.parse_args(argv)

    try:
        profile = load_profile(args.profile)
        host = collect_host_facts()
        if args.command == "plan":
            result = build_plan(profile, host)
        elif args.command == "preflight":
            result = build_preflight(profile, host)
        else:
            result = build_package_audit(profile, collect_package_statuses(profile))
    except ProfileError as exc:
        print(f"profile error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.command == "plan":
        print(format_plan(result))
    elif args.command == "preflight":
        print(format_preflight(result))
    else:
        print(format_package_audit(result))
    if args.command == "preflight" and not result["preflight_passed"]:
        return 1
    if args.command == "package-audit" and not result["audit_completed"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
