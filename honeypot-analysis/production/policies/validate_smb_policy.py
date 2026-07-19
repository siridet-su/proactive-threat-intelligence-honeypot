"""Validate SMB asset and action policy files."""

from __future__ import annotations

import argparse
import json
import math
import re
from pathlib import Path
from typing import Any, Dict, List, Optional


ALLOWED_SOURCE_TYPES = {
    "trusted_control_guidance",
    "context_modifier",
    "policy_default",
}
ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical"}
ALLOWED_CONFIDENCE = {"low", "possible", "medium", "likely", "high"}
ALLOWED_CONDITION_KEYS = {
    "all_tactics",
    "any_tactics",
    "all_ttps",
    "any_ttps",
    "all_claim_types",
    "any_claim_types",
    "any_action_types",
    "any_predicted_tactics",
    "required_flags",
    "absent_flags",
    "any_asset_categories",
    "internet_exposed_asset",
    "any_enrichment_tags",
    "min_command_count",
    "max_command_count",
    "required_enrichment_flags",
    "min_reputation_risk_score",
    "any_command_regex",
}
LIST_CONDITION_KEYS = ALLOWED_CONDITION_KEYS - {
    "internet_exposed_asset",
    "min_command_count",
    "max_command_count",
    "min_reputation_risk_score",
}
BEHAVIOR_FLAG_KEYS = {
    "has_commands",
    "has_login_success",
    "has_downloader",
    "has_transfer_attempt",
    "has_confirmed_transfer",
    "has_execution_attempt",
    "has_connected_behavior_chain",
    "has_persistence_attempt",
    "has_cleanup_attempt",
    "has_credential_access_candidate",
    "has_credential_paths",
    "has_hashes",
}
ENRICHMENT_FLAG_KEYS = {
    "is_tor_exit",
    "is_vpn",
    "has_high_reputation_risk",
    "has_elevated_reputation_risk",
    "has_vt_hit",
    "has_malware_family",
    "has_open_ports",
}
REQUIRED_PROVENANCE_FIELDS = {
    "method",
    "basis",
    "author",
    "reviewer",
    "reviewed",
    "generated",
    "created",
    "last_reviewed",
    "version",
}


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _load_json(path_text: str) -> Dict[str, Any]:
    path = Path(path_text)
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return loaded


def _validate_refs(rule: Dict[str, Any], trusted_sources: Dict[str, Any], path: str, errors: List[str]) -> None:
    refs = _as_list(rule.get("references"))
    if not refs:
        errors.append(f"{path}: missing references")
        return
    for ref in refs:
        if isinstance(ref, dict):
            if not ref.get("url"):
                errors.append(f"{path}: inline reference missing url")
            continue
        ref_id = str(ref or "")
        if ref_id not in trusted_sources:
            errors.append(f"{path}: unknown trusted source reference {ref_id!r}")


def _validate_provenance(item: Dict[str, Any], path: str, errors: List[str]) -> None:
    provenance = item.get("provenance")
    if not isinstance(provenance, dict):
        errors.append(f"{path}: provenance is required")
        return
    missing = sorted(field for field in REQUIRED_PROVENANCE_FIELDS if field not in provenance)
    if missing:
        errors.append(f"{path}: provenance missing {', '.join(missing)}")
    for field in ("method", "author", "reviewer", "created", "last_reviewed", "version"):
        if not str(provenance.get(field) or "").strip():
            errors.append(f"{path}: provenance.{field} must be non-empty")
    basis = provenance.get("basis")
    if not isinstance(basis, list) or not any(str(item or "").strip() for item in basis):
        errors.append(f"{path}: provenance.basis must be a non-empty list")
    if provenance.get("reviewed") is not True:
        errors.append(f"{path}: provenance.reviewed must be true for operator-action policy")
    if not isinstance(provenance.get("generated"), bool):
        errors.append(f"{path}: provenance.generated must be boolean")
    if provenance.get("generated") is True and provenance.get("reviewed") is not True:
        errors.append(f"{path}: generated operator-action policy must be reviewed before use")


def _validate_rule(rule: Dict[str, Any], trusted_sources: Dict[str, Any], path: str, errors: List[str]) -> None:
    if not isinstance(rule, dict):
        errors.append(f"{path}: rule must be an object")
        return
    if not str(rule.get("rule_id") or rule.get("action_id") or "").strip():
        errors.append(f"{path}: missing rule_id/action_id")
    source_type = str(rule.get("source_type") or "")
    if source_type not in ALLOWED_SOURCE_TYPES:
        errors.append(f"{path}: unsupported source_type {source_type!r}")
    if source_type in {"trusted_control_guidance", "context_modifier"}:
        _validate_refs(rule, trusted_sources, path, errors)
    if source_type in ALLOWED_SOURCE_TYPES:
        _validate_provenance(rule, path, errors)


def _validate_condition(condition: Any, path: str, errors: List[str]) -> None:
    if not isinstance(condition, dict) or not condition:
        errors.append(f"{path}: applies_when must be a non-empty object")
        return
    unknown = sorted(str(key) for key in set(condition) - ALLOWED_CONDITION_KEYS)
    for key in unknown:
        errors.append(f"{path}: unsupported applies_when field {key!r}")
    for key in LIST_CONDITION_KEYS.intersection(condition):
        value = condition.get(key)
        if (
            not isinstance(value, list)
            or not value
            or not all(isinstance(item, str) and item.strip() for item in value)
        ):
            errors.append(f"{path}: applies_when.{key} must be a list of non-empty values")
    if "internet_exposed_asset" in condition and not isinstance(
        condition.get("internet_exposed_asset"), bool
    ):
        errors.append(f"{path}: applies_when.internet_exposed_asset must be boolean")
    for key in ("min_command_count", "max_command_count"):
        if key not in condition:
            continue
        value = condition.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            errors.append(f"{path}: applies_when.{key} must be a non-negative integer")
    if "min_reputation_risk_score" in condition:
        value = condition.get("min_reputation_risk_score")
        try:
            risk = -1.0 if isinstance(value, bool) else float(value)
        except (TypeError, ValueError):
            risk = -1.0
        if not math.isfinite(risk) or risk < 0.0 or risk > 100.0:
            errors.append(
                f"{path}: applies_when.min_reputation_risk_score must be between 0 and 100"
            )
    minimum = condition.get("min_command_count")
    maximum = condition.get("max_command_count")
    if (
        isinstance(minimum, int)
        and not isinstance(minimum, bool)
        and isinstance(maximum, int)
        and not isinstance(maximum, bool)
        and minimum > maximum
    ):
        errors.append(f"{path}: applies_when min_command_count exceeds max_command_count")
    required_flags = {
        str(item) for item in _as_list(condition.get("required_flags")) if isinstance(item, str)
    }
    absent_flags = {
        str(item) for item in _as_list(condition.get("absent_flags")) if isinstance(item, str)
    }
    for flag in sorted(required_flags.intersection(absent_flags)):
        errors.append(f"{path}: applies_when flag {flag!r} is both required and absent")
    for flag in sorted(required_flags.union(absent_flags)):
        if flag not in BEHAVIOR_FLAG_KEYS:
            errors.append(f"{path}: unsupported behavior flag {flag!r}")
    for flag in sorted(
        str(item)
        for item in _as_list(condition.get("required_enrichment_flags"))
        if isinstance(item, str)
    ):
        if flag not in ENRICHMENT_FLAG_KEYS:
            errors.append(f"{path}: unsupported enrichment flag {flag!r}")
    for pattern in _as_list(condition.get("any_command_regex")):
        try:
            re.compile(str(pattern))
        except re.error:
            errors.append(f"{path}: applies_when.any_command_regex contains an invalid pattern")


def _validate_recommendation_contract(
    rule: Dict[str, Any],
    action: Dict[str, Any],
    path: str,
    errors: List[str],
) -> None:
    severity = str(action.get("severity") or rule.get("severity") or "")
    if severity not in ALLOWED_SEVERITIES:
        errors.append(f"{path}: missing or invalid severity")
    confidence = str(action.get("confidence") or rule.get("confidence") or "")
    if confidence not in ALLOWED_CONFIDENCE:
        errors.append(f"{path}: missing or invalid confidence")
    safety = action.get("automation_safety")
    if not isinstance(safety, dict):
        safety = rule.get("automation_safety")
    if not isinstance(safety, dict):
        errors.append(f"{path}: missing automation_safety")
        return
    for key in ("level", "safe_to_auto_execute", "requires_manual_approval", "rationale"):
        if key not in safety or safety.get(key) in ("", None):
            errors.append(f"{path}: automation_safety missing {key}")
    for key in ("safe_to_auto_execute", "requires_manual_approval"):
        if key in safety and not isinstance(safety.get(key), bool):
            errors.append(f"{path}: automation_safety.{key} must be boolean")
    safe = safety.get("safe_to_auto_execute")
    manual = safety.get("requires_manual_approval")
    if isinstance(safe, bool) and isinstance(manual, bool):
        if safe and manual:
            errors.append(
                f"{path}: automation_safety cannot allow auto-execution and require manual approval"
            )
        if not safe and not manual:
            errors.append(
                f"{path}: automation_safety must require manual approval when auto-execution is disabled"
            )


def validate_action_policy(policy: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    if not isinstance(policy, dict):
        return ["policy: root must be an object"]
    if policy.get("schema_version") != "smb_action_policy.v1":
        errors.append("policy: schema_version must be smb_action_policy.v1")
    for key in ("policy_id", "version", "updated_at", "owner"):
        if not isinstance(policy.get(key), str) or not policy[key].strip():
            errors.append(f"policy: {key} is required")
    trusted_sources = policy.get("trusted_sources")
    if not isinstance(trusted_sources, dict) or not trusted_sources:
        errors.append("policy: trusted_sources must be a non-empty object")
        trusted_sources = {}
    for source_id, source in trusted_sources.items():
        if not isinstance(source, dict):
            errors.append(f"trusted_sources.{source_id}: source must be an object")
            continue
        for key in ("name", "type", "url"):
            if not source.get(key):
                errors.append(f"trusted_sources.{source_id}: missing {key}")

    seen_rule_ids: Dict[str, str] = {}
    seen_action_ids: Dict[str, str] = {}
    for group in ("risk_rules", "goal_rules", "action_playbooks"):
        raw_rules = policy.get(group)
        if not isinstance(raw_rules, list):
            errors.append(f"policy: {group} must be a list")
            continue
        for index, rule in enumerate(raw_rules):
            path = f"{group}[{index}]"
            _validate_rule(rule, trusted_sources, path, errors)
            if not isinstance(rule, dict):
                continue
            if not isinstance(rule.get("enabled"), bool):
                errors.append(f"{path}: enabled must be boolean")
            if rule.get("source_type") == "policy_default":
                errors.append(f"{path}: policy_default is reserved for default guidance")
            rule_id = str(rule.get("rule_id") or "").strip()
            if rule_id:
                if rule_id in seen_rule_ids:
                    errors.append(
                        f"{path}: duplicate rule_id {rule_id!r}; first defined at {seen_rule_ids[rule_id]}"
                    )
                else:
                    seen_rule_ids[rule_id] = path
            _validate_condition(rule.get("applies_when"), path, errors)
            if group == "risk_rules":
                if str(rule.get("severity") or "") not in ALLOWED_SEVERITIES:
                    errors.append(f"{path}: missing or invalid severity")
                if not str(rule.get("reason") or "").strip():
                    errors.append(f"{path}: missing reason")
            elif group == "goal_rules":
                if str(rule.get("confidence") or "") not in ALLOWED_CONFIDENCE:
                    errors.append(f"{path}: missing or invalid confidence")
                if not str(rule.get("likely_goal") or "").strip():
                    errors.append(f"{path}: missing likely_goal")
            elif group == "action_playbooks":
                if not _as_list(rule.get("actions")):
                    errors.append(f"{path}: action playbook must contain actions")
                _validate_recommendation_contract(rule, {}, path, errors)
                for action_index, action in enumerate(_as_list(rule.get("actions"))):
                    action_path = f"{path}.actions[{action_index}]"
                    if not isinstance(action, dict):
                        errors.append(f"{action_path}: action must be an object")
                        continue
                    if not action.get("action"):
                        errors.append(f"{action_path}: missing action text")
                    if not action.get("why"):
                        errors.append(f"{action_path}: missing why")
                    action_id = str(action.get("action_id") or "").strip()
                    if not action_id:
                        errors.append(f"{action_path}: missing action_id")
                    elif action_id in seen_action_ids:
                        errors.append(
                            f"{action_path}: duplicate action_id {action_id!r}; "
                            f"first defined at {seen_action_ids[action_id]}"
                        )
                    else:
                        seen_action_ids[action_id] = action_path
                    _validate_provenance(action, action_path, errors)
                    _validate_recommendation_contract(rule, action, action_path, errors)

    default_guidance = policy.get("default_guidance")
    if not isinstance(default_guidance, dict):
        errors.append("policy: default_guidance must be an object")
        default_guidance = {}
    default_actions = default_guidance.get("actions")
    if not isinstance(default_actions, list) or not default_actions:
        errors.append("policy: default_guidance.actions must be a non-empty list")
        default_actions = []
    for index, action in enumerate(default_actions):
        if not isinstance(action, dict):
            errors.append(f"default_guidance.actions[{index}]: action must be an object")
            continue
        path = f"default_guidance.actions[{index}]"
        _validate_rule(action, trusted_sources, path, errors)
        _validate_recommendation_contract({}, action, path, errors)
        if not action.get("why"):
            errors.append(f"{path}: missing why")
        action_id = str(action.get("action_id") or "").strip()
        if not action_id:
            errors.append(f"{path}: missing action_id")
        elif action_id in seen_action_ids:
            errors.append(
                f"{path}: duplicate action_id {action_id!r}; first defined at {seen_action_ids[action_id]}"
            )
        else:
            seen_action_ids[action_id] = path
    return errors


def validate_asset_profile(profile: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    if profile.get("schema_version") != "smb_asset_profile.v1":
        errors.append("asset profile: schema_version must be smb_asset_profile.v1")
    assets = _as_list(profile.get("assets"))
    if not assets:
        errors.append("asset profile: at least one asset should be defined")
    for index, asset in enumerate(assets):
        if not isinstance(asset, dict):
            errors.append(f"assets[{index}]: asset must be an object")
            continue
        for key in ("asset_id", "display_name", "service_category", "criticality"):
            if not asset.get(key):
                errors.append(f"assets[{index}]: missing {key}")
    return errors


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate SMB decision policy files.")
    parser.add_argument("--action-policy", required=True, help="Path to smb_action_playbooks JSON.")
    parser.add_argument("--asset-profile", help="Optional path to smb_asset_profile JSON.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    errors = validate_action_policy(_load_json(args.action_policy))
    if args.asset_profile:
        errors.extend(validate_asset_profile(_load_json(args.asset_profile)))
    if args.json:
        print(json.dumps({"ok": not errors, "errors": errors}, indent=2, sort_keys=True))
    elif errors:
        print("SMB policy validation failed:")
        for error in errors:
            print(f"- {error}")
    else:
        print("SMB policy validation passed.")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
