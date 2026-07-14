"""Validate command classification rule policy files."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional


SCHEMA_VERSION = "classification_rule_policy.v1"
TTP_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
ALLOWED_SOURCE_TYPES = {
    "human_curated_command_rule",
    "researcher_ai_assisted_command_rule",
    "generated_command_rule",
    "external_validated_command_rule",
    "emergency_python_fallback",
}
ALLOWED_EVIDENCE_TYPES = {
    "command_regex",
    "command_example",
    "external_dataset_command_pattern",
}
ALLOWED_RULE_REVIEW_MODES = {
    "reviewed_only",
    "all_enabled",
    "all",
    "include_unreviewed",
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


def _rules(policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    body = policy.get("policy", policy)
    if not isinstance(body, dict):
        return []
    return [dict(rule) for rule in body.get("rules") or [] if isinstance(rule, dict)]


def _validate_references(rule: Dict[str, Any], path: str, errors: List[str]) -> None:
    refs = _as_list(rule.get("references"))
    if not refs:
        errors.append(f"{path}: missing references")
        return
    for index, ref in enumerate(refs):
        ref_path = f"{path}.references[{index}]"
        if not isinstance(ref, dict):
            errors.append(f"{ref_path}: reference must be an object")
            continue
        if not ref.get("name"):
            errors.append(f"{ref_path}: missing name")
        if not ref.get("url"):
            errors.append(f"{ref_path}: missing url")


def _validate_provenance(rule: Dict[str, Any], path: str, errors: List[str]) -> None:
    provenance = rule.get("provenance")
    if not isinstance(provenance, dict):
        errors.append(f"{path}: missing provenance")
        return
    for key in ("method", "basis", "author", "reviewed", "generated", "created", "version"):
        if key not in provenance or provenance.get(key) in ("", None, []):
            errors.append(f"{path}.provenance: missing {key}")
    if not isinstance(provenance.get("basis"), list) or not provenance.get("basis"):
        errors.append(f"{path}.provenance.basis: must be a non-empty list")
    if not isinstance(provenance.get("reviewed"), bool):
        errors.append(f"{path}.provenance.reviewed: must be boolean")
    if not isinstance(provenance.get("generated"), bool):
        errors.append(f"{path}.provenance.generated: must be boolean")
    if provenance.get("reviewed") is True:
        for key in ("reviewer", "last_reviewed", "review_status"):
            if not provenance.get(key):
                errors.append(f"{path}.provenance: reviewed rules must include {key}")
    if provenance.get("generated") and provenance.get("reviewed") and not provenance.get("reviewer"):
        errors.append(f"{path}.provenance: generated reviewed rules must include reviewer")


def validate_classification_rule_policy(policy: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    if policy.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"policy: schema_version must be {SCHEMA_VERSION}")
    if not policy.get("policy_id"):
        errors.append("policy: missing policy_id")
    if not policy.get("version"):
        errors.append("policy: missing version")
    body = policy.get("policy", policy)
    if isinstance(body, dict):
        review_mode = body.get("rule_review_mode", policy.get("rule_review_mode", "reviewed_only"))
        if str(review_mode or "").lower() not in ALLOWED_RULE_REVIEW_MODES:
            errors.append(f"policy: unsupported rule_review_mode {review_mode!r}")
    rules = _rules(policy)
    if not rules:
        errors.append("policy: at least one rule is required")
    seen_ids = set()
    for index, rule in enumerate(rules):
        path = f"rules[{index}]"
        rule_id = str(rule.get("rule_id") or "").strip()
        if not rule_id:
            errors.append(f"{path}: missing rule_id")
        elif rule_id in seen_ids:
            errors.append(f"{path}: duplicate rule_id {rule_id!r}")
        seen_ids.add(rule_id)
        pattern = str(rule.get("pattern") or "")
        if not pattern:
            errors.append(f"{path}: missing pattern")
        else:
            try:
                re.compile(pattern, re.IGNORECASE)
            except re.error as exc:
                errors.append(f"{path}: invalid regex: {exc}")
        ttp = str(rule.get("ttp") or "").strip().upper()
        if not TTP_RE.match(ttp):
            errors.append(f"{path}: invalid ttp {ttp!r}")
        if not rule.get("technique_name"):
            errors.append(f"{path}: missing technique_name")
        source_type = str(rule.get("source_type") or "")
        if source_type not in ALLOWED_SOURCE_TYPES:
            errors.append(f"{path}: unsupported source_type {source_type!r}")
        evidence_type = str(rule.get("evidence_type") or "")
        if evidence_type not in ALLOWED_EVIDENCE_TYPES:
            errors.append(f"{path}: unsupported evidence_type {evidence_type!r}")
        confidence = rule.get("confidence")
        try:
            confidence_value = float(confidence)
        except (TypeError, ValueError):
            errors.append(f"{path}: confidence must be numeric")
        else:
            if not 0.0 <= confidence_value <= 1.0:
                errors.append(f"{path}: confidence must be between 0 and 1")
        _validate_references(rule, path, errors)
        _validate_provenance(rule, path, errors)
    return errors


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate command classification rule policy.")
    parser.add_argument("--policy", required=True, help="Path to classification_rules JSON.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    errors = validate_classification_rule_policy(_load_json(args.policy))
    if args.json:
        print(json.dumps({"ok": not errors, "errors": errors}, indent=2, sort_keys=True))
    elif errors:
        print("Classification rule policy validation failed:")
        for error in errors:
            print(f"- {error}")
    else:
        print("Classification rule policy validation passed.")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
