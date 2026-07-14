"""Validate SMB asset and action policy files."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional


ALLOWED_SOURCE_TYPES = {
    "trusted_control_guidance",
    "context_modifier",
    "policy_default",
}
ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical"}
ALLOWED_CONFIDENCE = {"low", "possible", "medium", "likely", "high"}
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
    if not rule.get("rule_id") and "action_id" not in rule:
        errors.append(f"{path}: missing rule_id/action_id")
    source_type = str(rule.get("source_type") or "")
    if source_type not in ALLOWED_SOURCE_TYPES:
        errors.append(f"{path}: unsupported source_type {source_type!r}")
    if source_type in {"trusted_control_guidance", "context_modifier"}:
        _validate_refs(rule, trusted_sources, path, errors)
        _validate_provenance(rule, path, errors)


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


def validate_action_policy(policy: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    if policy.get("schema_version") != "smb_action_policy.v1":
        errors.append("policy: schema_version must be smb_action_policy.v1")
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

    for group in ("risk_rules", "goal_rules", "action_playbooks"):
        for index, rule in enumerate(_as_list(policy.get(group))):
            path = f"{group}[{index}]"
            _validate_rule(rule, trusted_sources, path, errors)
            if isinstance(rule, dict) and group == "action_playbooks":
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
                    _validate_provenance(action, action_path, errors)
                    _validate_recommendation_contract(rule, action, action_path, errors)

    default_guidance = policy.get("default_guidance") or {}
    for index, action in enumerate(_as_list(default_guidance.get("actions"))):
        if not isinstance(action, dict):
            errors.append(f"default_guidance.actions[{index}]: action must be an object")
            continue
        _validate_rule(action, trusted_sources, f"default_guidance.actions[{index}]", errors)
        _validate_recommendation_contract({}, action, f"default_guidance.actions[{index}]", errors)
        if not action.get("why"):
            errors.append(f"default_guidance.actions[{index}]: missing why")
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
