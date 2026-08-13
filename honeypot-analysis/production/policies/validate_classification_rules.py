"""Validate command classification rule policy files."""

from __future__ import annotations

import argparse
import json
import re
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional


SCHEMA_VERSION = "classification_rule_policy.v4"
AUTHORITY_DECISION_SCHEMA = "command_authority_decision.v2"
TTP_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
ALLOWED_SOURCE_TYPES = {
    "human_curated_command_rule",
    "researcher_ai_assisted_command_rule",
    "generated_command_rule",
    "external_validated_command_rule",
    "emergency_python_fallback",
}
ALLOWED_EVIDENCE_TYPES = {
    "command_operation",
    "command_regex",
    "command_example",
    "external_dataset_command_pattern",
}
ALLOWED_OPERATION_PREDICATE_KEYS = {
    "command_families",
    "required_operation_types",
    "operand_paths_any",
}
ALLOWED_RULE_REVIEW_MODES = {
    "reviewed_only",
    "all_enabled",
    "all",
    "include_unreviewed",
}
ALLOWED_REGEX_PROMOTION_CLASSES = {
    "audit_only",
    "trusted_literal_fallback",
}
TACTIC_RE = re.compile(r"^[a-z]+(?:-[a-z]+)*$")


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
        authority = body.get("runtime_authority")
        if not isinstance(authority, dict):
            errors.append("policy: missing runtime_authority metadata")
        else:
            if authority.get("schema_version") != AUTHORITY_DECISION_SCHEMA:
                errors.append(
                    "policy.runtime_authority.schema_version must be "
                    f"{AUTHORITY_DECISION_SCHEMA}"
                )
            if authority.get("regex_default_promotion") != "audit_only":
                errors.append(
                    "policy.runtime_authority.regex_default_promotion must be audit_only"
                )
            ids = authority.get("trusted_literal_fallback_rule_ids")
            if not isinstance(ids, list) or any(not str(item).strip() for item in ids):
                errors.append(
                    "policy.runtime_authority.trusted_literal_fallback_rule_ids "
                    "must be a list of rule IDs"
                )
            if authority.get("trusted_regex_operation_class") != "reviewed_operation_context":
                errors.append(
                    "policy.runtime_authority.trusted_regex_operation_class must be "
                    "reviewed_operation_context"
                )
    rules = _rules(policy)
    if not rules:
        errors.append("policy: at least one rule is required")
    seen_ids = set()
    rule_by_id: Dict[str, Dict[str, Any]] = {}
    for index, rule in enumerate(rules):
        path = f"rules[{index}]"
        rule_id = str(rule.get("rule_id") or "").strip()
        if not rule_id:
            errors.append(f"{path}: missing rule_id")
        elif rule_id in seen_ids:
            errors.append(f"{path}: duplicate rule_id {rule_id!r}")
        seen_ids.add(rule_id)
        if rule_id:
            rule_by_id[rule_id] = rule
        evidence_type = str(rule.get("evidence_type") or "")
        pattern = str(rule.get("pattern") or "")
        predicate = rule.get("operation_predicate")
        if evidence_type == "command_operation":
            if pattern:
                errors.append(f"{path}: structural rules must not include pattern")
            if not isinstance(predicate, dict) or not predicate:
                errors.append(f"{path}: structural rule requires operation_predicate")
            else:
                unknown = set(predicate) - ALLOWED_OPERATION_PREDICATE_KEYS
                if unknown:
                    errors.append(f"{path}: unsupported operation predicate fields")
                for key, values in predicate.items():
                    if (
                        not isinstance(values, list)
                        or not values
                        or any(not isinstance(value, str) or not value.strip() for value in values)
                    ):
                        errors.append(f"{path}.operation_predicate.{key} must be a non-empty string list")
        elif not pattern:
            errors.append(f"{path}: regex rule is missing pattern")
        else:
            try:
                re.compile(pattern, re.IGNORECASE)
            except re.error:
                errors.append(f"{path}: invalid regex")
            rule_authority = rule.get("runtime_authority")
            configured_ids = set()
            if isinstance(body, dict) and isinstance(body.get("runtime_authority"), dict):
                configured_ids = {
                    str(item).strip()
                    for item in body["runtime_authority"].get(
                        "trusted_literal_fallback_rule_ids", []
                    )
                    if str(item).strip()
                }
            if rule_authority is not None:
                if not isinstance(rule_authority, dict):
                    errors.append(f"{path}.runtime_authority must be an object")
                else:
                    promotion = str(rule_authority.get("promotion_class") or "")
                    if promotion not in ALLOWED_REGEX_PROMOTION_CLASSES:
                        errors.append(
                            f"{path}.runtime_authority.promotion_class is unsupported"
                        )
                    if promotion == "trusted_literal_fallback":
                        if rule_authority.get("reviewed") is not True:
                            errors.append(
                                f"{path}.runtime_authority reviewed promotion must be true"
                            )
                        if rule_authority.get("safety_class") != "literal_unambiguous":
                            errors.append(
                                f"{path}.runtime_authority trusted promotion must be literal_unambiguous"
                            )
                        if rule_authority.get("operation_class") != "reviewed_operation_context":
                            errors.append(
                                f"{path}.runtime_authority trusted promotion must use "
                                "reviewed_operation_context"
                            )
            elif rule_id not in configured_ids:
                # The policy-level allow-list is explicit metadata for the
                # reviewed rules.  Every other regex is intentionally audit-only.
                # No error is needed for an omitted rule-level object.
                pass
        ttp = str(rule.get("ttp") or "").strip().upper()
        if not TTP_RE.match(ttp):
            errors.append(f"{path}: invalid ttp {ttp!r}")
        if not rule.get("technique_name"):
            errors.append(f"{path}: missing technique_name")
        reviewed_tactic = str(rule.get("reviewed_tactic") or "").strip().lower()
        if (rule.get("provenance") or {}).get("reviewed") is True:
            if not TACTIC_RE.fullmatch(reviewed_tactic):
                errors.append(f"{path}: reviewed rule requires reviewed_tactic")
            if rule.get("observation_semantics") != "submitted_command_attempt_not_outcome":
                errors.append(f"{path}: reviewed rule requires bounded observation_semantics")
        source_type = str(rule.get("source_type") or "")
        if source_type not in ALLOWED_SOURCE_TYPES:
            errors.append(f"{path}: unsupported source_type {source_type!r}")
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

    authority = body.get("runtime_authority") if isinstance(body, dict) else {}
    allowlist = authority.get("trusted_literal_fallback_rule_ids", []) if isinstance(authority, dict) else []
    if isinstance(allowlist, list):
        if len(allowlist) != len(set(allowlist)):
            errors.append("policy.runtime_authority trusted allowlist contains duplicates")
        for rule_id in allowlist:
            rule = rule_by_id.get(str(rule_id))
            if not rule:
                errors.append(f"policy.runtime_authority unknown trusted rule {rule_id!r}")
                continue
            if rule.get("evidence_type") != "command_regex":
                errors.append(f"policy.runtime_authority trusted rule {rule_id!r} is not command_regex")
            if (rule.get("provenance") or {}).get("reviewed") is not True:
                errors.append(f"policy.runtime_authority trusted rule {rule_id!r} is not reviewed")
            rule_authority = rule.get("runtime_authority") or {}
            if rule_authority.get("promotion_class") != "trusted_literal_fallback" or rule_authority.get("reviewed") is not True:
                errors.append(f"policy.runtime_authority trusted rule {rule_id!r} metadata disagrees")

    cache_binding = policy.get("mitre_cache_binding")
    if not isinstance(cache_binding, dict):
        errors.append("policy: missing mitre_cache_binding")
    else:
        cache_path = Path(__file__).resolve().parents[2] / str(cache_binding.get("path") or "")
        expected_hash = str(cache_binding.get("sha256") or "").lower()
        try:
            raw = cache_path.read_bytes()
            cache = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            errors.append("policy: bound MITRE cache is unavailable or invalid")
        else:
            if hashlib.sha256(raw).hexdigest() != expected_hash:
                errors.append("policy: bound MITRE cache SHA-256 mismatch")
            techniques = cache.get("techniques") if isinstance(cache, dict) else {}
            techniques = techniques if isinstance(techniques, dict) else {}
            for index, rule in enumerate(rules):
                if (rule.get("provenance") or {}).get("reviewed") is not True:
                    continue
                ttp = str(rule.get("ttp") or "").strip().upper()
                record = techniques.get(ttp)
                if not isinstance(record, dict):
                    errors.append(f"rules[{index}]: reviewed TTP is absent from bound MITRE cache")
                    continue
                available = {
                    str(value).strip().lower().replace(" ", "-")
                    for value in record.get("tactics") or []
                }
                if str(rule.get("reviewed_tactic") or "").strip().lower() not in available:
                    errors.append(f"rules[{index}]: reviewed_tactic is not valid for bound TTP")
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
