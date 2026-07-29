"""Validation for the deterministic ``response_guidance_policy.v3`` format.

The v3 policy deliberately has a much smaller surface than the legacy SMB
decision policy.  Its rules may inspect only canonical observed-behaviour
facts.  Forecasts, reputation/enrichment, command regexes, defaults, and
automatic execution are invalid policy constructs rather than optional runtime
conventions.
"""

from __future__ import annotations

import argparse
import json
from datetime import date
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


SCHEMA_VERSION = "response_guidance_policy.v3"
ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical"}
ALLOWED_SOURCE_TYPES = {"trusted_control_guidance"}
ALLOWED_CONDITION_KEYS = {
    "all_tactics",
    "any_tactics",
    "all_ttps",
    "any_ttps",
    "all_claim_types",
    "any_claim_types",
    "any_action_types",
    "required_flags",
    "absent_flags",
    "min_command_count",
    "activated_semantic_families",
}
LIST_CONDITION_KEYS = ALLOWED_CONDITION_KEYS - {"min_command_count"}
OBSERVED_CONDITION_KEYS = frozenset(ALLOWED_CONDITION_KEYS)
ALLOWED_BEHAVIOR_FLAGS = {"has_commands", "has_cowrie_transfer_event"}
ACTIVATED_SEMANTIC_FAMILIES = {"sensitive_read", "transfer"}
REQUIRED_PROVENANCE_FIELDS = {
    "method",
    "basis",
    "author",
    "reviewer",
    "reviewed",
    "generated",
    "created",
    "last_reviewed",
    "review_expires_at",
    "version",
}


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def validate_response_guidance_asset_profile(
    profile: Dict[str, Any],
) -> List[str]:
    """Validate the optional, context-only asset profile.

    The historical schema label remains accepted so existing reviewed profile
    documents can be hashed and displayed without rewriting them. Asset data
    is never an action-selection input in response_guidance.v3.
    """

    errors: List[str] = []
    if profile.get("schema_version") != "smb_asset_profile.v1":
        errors.append(
            "asset profile: schema_version must be smb_asset_profile.v1"
        )
    assets = _as_list(profile.get("assets"))
    if not assets:
        errors.append("asset profile: at least one asset should be defined")
    for index, asset in enumerate(assets):
        if not isinstance(asset, dict):
            errors.append(f"assets[{index}]: asset must be an object")
            continue
        for key in (
            "asset_id",
            "display_name",
            "service_category",
            "criticality",
        ):
            if not asset.get(key):
                errors.append(f"assets[{index}]: missing {key}")
    return errors


def _date(value: Any) -> Optional[date]:
    try:
        return date.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


def _nonempty_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _validate_provenance(item: Any, path: str, errors: List[str]) -> None:
    if not isinstance(item, dict):
        errors.append(f"{path}: provenance is required")
        return
    missing = sorted(field for field in REQUIRED_PROVENANCE_FIELDS if field not in item)
    if missing:
        errors.append(f"{path}: provenance missing {', '.join(missing)}")
    for field in ("method", "author", "reviewer", "created", "last_reviewed", "review_expires_at", "version"):
        if not _nonempty_text(item.get(field)):
            errors.append(f"{path}: provenance.{field} must be non-empty")
    for field in ("created", "last_reviewed", "review_expires_at"):
        if _nonempty_text(item.get(field)) and _date(item.get(field)) is None:
            errors.append(f"{path}: provenance.{field} must be ISO-8601 date")
    expires = _date(item.get("review_expires_at"))
    if expires is not None and expires < date.today():
        errors.append(f"{path}: policy review has expired")
    if item.get("reviewed") is not True:
        errors.append(f"{path}: provenance.reviewed must be true")
    if not isinstance(item.get("generated"), bool):
        errors.append(f"{path}: provenance.generated must be boolean")
    basis = item.get("basis")
    if not isinstance(basis, list) or not any(_nonempty_text(value) for value in basis):
        errors.append(f"{path}: provenance.basis must be a non-empty list")


def _validate_references(rule: Dict[str, Any], sources: Dict[str, Any], path: str, errors: List[str]) -> None:
    refs = _as_list(rule.get("references"))
    if not refs:
        errors.append(f"{path}: references are required")
        return
    for source_id in refs:
        if not _nonempty_text(source_id) or source_id not in sources:
            errors.append(f"{path}: unknown trusted source reference {source_id!r}")


def _validate_condition(condition: Any, path: str, errors: List[str]) -> None:
    if not isinstance(condition, dict) or not condition:
        errors.append(f"{path}: applies_when must be a non-empty object")
        return
    unknown = sorted(str(key) for key in set(condition) - ALLOWED_CONDITION_KEYS)
    for key in unknown:
        errors.append(f"{path}: unsupported or non-canonical applies_when field {key!r}")
    if not set(condition).intersection(OBSERVED_CONDITION_KEYS):
        errors.append(f"{path}: action eligibility requires canonical observed evidence")
    for key in LIST_CONDITION_KEYS.intersection(condition):
        values = condition.get(key)
        if not isinstance(values, list) or not values or not all(_nonempty_text(value) for value in values):
            errors.append(f"{path}: applies_when.{key} must be a non-empty list of text")
    for family in _as_list(
        condition.get("activated_semantic_families")
    ):
        if family not in ACTIVATED_SEMANTIC_FAMILIES:
            errors.append(
                f"{path}: semantic family {family!r} is not activated"
            )
    count = condition.get("min_command_count")
    if "min_command_count" in condition and (
        isinstance(count, bool) or not isinstance(count, int) or count < 1
    ):
        errors.append(f"{path}: applies_when.min_command_count must be a positive integer")
    required = {str(value) for value in _as_list(condition.get("required_flags"))}
    absent = {str(value) for value in _as_list(condition.get("absent_flags"))}
    for flag in sorted(required | absent):
        if flag not in ALLOWED_BEHAVIOR_FLAGS:
            errors.append(f"{path}: unsupported observed behavior flag {flag!r}")
    for flag in sorted(required & absent):
        errors.append(f"{path}: observed behavior flag {flag!r} is both required and absent")


def _validate_action(action: Any, sources: Dict[str, Any], path: str, seen: set[str], errors: List[str]) -> None:
    if not isinstance(action, dict):
        errors.append(f"{path}: action must be an object")
        return
    action_id = action.get("action_id")
    if not _nonempty_text(action_id):
        errors.append(f"{path}: action_id is required")
    elif action_id in seen:
        errors.append(f"{path}: duplicate action_id {action_id!r}")
    else:
        seen.add(action_id)
    for key in ("action", "rationale"):
        if not _nonempty_text(action.get(key)):
            errors.append(f"{path}: {key} is required")
    if not isinstance(action.get("priority"), int) or action["priority"] < 1:
        errors.append(f"{path}: priority must be a positive integer")
    if action.get("source_type") not in ALLOWED_SOURCE_TYPES:
        errors.append(f"{path}: source_type must be trusted_control_guidance")
    _validate_references(action, sources, path, errors)
    _validate_provenance(action.get("provenance"), path, errors)
    if action.get("requires_manual_approval") is not True:
        errors.append(f"{path}: requires_manual_approval must be true")
    if action.get("safe_to_auto_execute") is not False:
        errors.append(f"{path}: safe_to_auto_execute must be false")
    if action.get("execution_integration") not in {None, "not_implemented"}:
        errors.append(f"{path}: execution integration is prohibited")


def validate_response_guidance_policy(policy: Any) -> List[str]:
    """Return all validation errors for a v3 response-guidance policy."""

    errors: List[str] = []
    if not isinstance(policy, dict):
        return ["policy: root must be an object"]
    if policy.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"policy: schema_version must be {SCHEMA_VERSION}")
    for key in ("policy_id", "version", "updated_at", "owner", "review_expires_at"):
        if not _nonempty_text(policy.get(key)):
            errors.append(f"policy: {key} is required")
    if _nonempty_text(policy.get("review_expires_at")):
        expires = _date(policy.get("review_expires_at"))
        if expires is None:
            errors.append("policy: review_expires_at must be ISO-8601 date")
        elif expires < date.today():
            errors.append("policy: review has expired")
    if policy.get("automatic_execution") is not False:
        errors.append("policy: automatic_execution must be false")

    sources = policy.get("trusted_sources")
    if not isinstance(sources, dict) or not sources:
        errors.append("policy: trusted_sources must be a non-empty object")
        sources = {}
    for source_id, source in sources.items():
        path = f"trusted_sources.{source_id}"
        if not isinstance(source, dict):
            errors.append(f"{path}: source must be an object")
            continue
        for key in ("name", "type", "url", "source_version", "accessed_at"):
            if not _nonempty_text(source.get(key)):
                errors.append(f"{path}: {key} is required")
        if _nonempty_text(source.get("accessed_at")) and _date(source.get("accessed_at")) is None:
            errors.append(f"{path}: accessed_at must be ISO-8601 date")

    seen_rules: set[str] = set()
    seen_actions: set[str] = set()
    for group in ("finding_rules", "action_playbooks"):
        rules = policy.get(group)
        if not isinstance(rules, list):
            errors.append(f"policy: {group} must be a list")
            continue
        for index, rule in enumerate(rules):
            path = f"{group}[{index}]"
            if not isinstance(rule, dict):
                errors.append(f"{path}: rule must be an object")
                continue
            rule_id = rule.get("rule_id")
            if not _nonempty_text(rule_id):
                errors.append(f"{path}: rule_id is required")
            elif rule_id in seen_rules:
                errors.append(f"{path}: duplicate rule_id {rule_id!r}")
            else:
                seen_rules.add(rule_id)
            if rule.get("source_type") not in ALLOWED_SOURCE_TYPES:
                errors.append(f"{path}: source_type must be trusted_control_guidance")
            _validate_references(rule, sources, path, errors)
            _validate_provenance(rule.get("provenance"), path, errors)
            _validate_condition(rule.get("applies_when"), path, errors)
            condition = rule.get("applies_when")
            semantic_family = rule.get("semantic_family")
            if semantic_family is not None:
                if semantic_family not in ACTIVATED_SEMANTIC_FAMILIES:
                    errors.append(
                        f"{path}: semantic_family is not activated"
                    )
                expected_condition = {
                    "activated_semantic_families": [semantic_family]
                }
                if condition != expected_condition:
                    errors.append(
                        f"{path}: semantic-family rules must use only their "
                        "activated semantic family condition"
                    )
            elif (
                isinstance(condition, dict)
                and "activated_semantic_families" in condition
            ):
                errors.append(
                    f"{path}: activated semantic condition requires "
                    "semantic_family"
                )
            if (
                isinstance(condition, dict)
                and {"all_tactics", "any_tactics"}.intersection(condition)
                and "any_action_types" not in condition
            ):
                errors.append(
                    f"{path}: broad ATT&CK tactics cannot be the sole semantic "
                    "support for specialized guidance"
                )
            if group == "finding_rules":
                if rule.get("severity") not in ALLOWED_SEVERITIES:
                    errors.append(f"{path}: severity must be one of the allowed values")
                if not _nonempty_text(rule.get("statement")):
                    errors.append(f"{path}: statement is required")
            else:
                actions = rule.get("actions")
                if not isinstance(actions, list) or not actions:
                    errors.append(f"{path}: actions must be a non-empty list")
                    continue
                for action_index, action in enumerate(actions):
                    _validate_action(action, sources, f"{path}.actions[{action_index}]", seen_actions, errors)
    return errors


def _load_json(path_text: str) -> Dict[str, Any]:
    loaded = json.loads(Path(path_text).read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError("policy JSON root must be an object")
    return loaded


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Validate response_guidance_policy.v3 JSON.")
    parser.add_argument("--policy", required=True, help="Path to response guidance policy JSON.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable output.")
    args = parser.parse_args(list(argv) if argv is not None else None)
    errors = validate_response_guidance_policy(_load_json(args.policy))
    result = {"ok": not errors, "errors": errors}
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif errors:
        print("Response guidance policy validation failed:")
        for error in errors:
            print(f"- {error}")
    else:
        print("Response guidance policy validation passed.")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
