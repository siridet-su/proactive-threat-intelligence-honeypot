"""Lightweight validation for generated STIX 2.1-style threat bundles.

This validator is intentionally narrower than a full STIX schema validator. It
checks the safety and interoperability contracts that matter for this project:
object IDs, reference integrity, required fields for emitted object types, and
the rule that remediation courses of action must come from the trusted policy
engine.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


ID_RE = re.compile(r"^[a-z0-9-]+--[0-9a-fA-F-]{36}$")
REQUIRED_REF_FIELDS = {
    "relationship": ("source_ref", "target_ref"),
    "sighting": ("sighting_of_ref",),
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


def _path(index: int, obj: Dict[str, Any]) -> str:
    return f"objects[{index}]({obj.get('type', 'unknown')}:{obj.get('id', 'missing-id')})"


def _validate_object_basics(index: int, obj: Any, ids: set[str], errors: List[str]) -> None:
    if not isinstance(obj, dict):
        errors.append(f"objects[{index}]: object must be a JSON object")
        return
    object_type = str(obj.get("type") or "")
    object_id = str(obj.get("id") or "")
    path = _path(index, obj)
    if not object_type:
        errors.append(f"{path}: missing type")
    if not object_id:
        errors.append(f"{path}: missing id")
    elif not ID_RE.match(object_id):
        errors.append(f"{path}: id is not STIX-style type--uuid")
    elif object_type and not object_id.startswith(f"{object_type}--"):
        errors.append(f"{path}: id prefix does not match object type")
    if object_id in ids:
        errors.append(f"{path}: duplicate object id")
    if object_id:
        ids.add(object_id)
    if object_type not in {"bundle"} and object_type and not obj.get("spec_version"):
        errors.append(f"{path}: missing spec_version")


def _validate_references(index: int, obj: Dict[str, Any], object_ids: set[str], errors: List[str]) -> None:
    path = _path(index, obj)
    object_type = str(obj.get("type") or "")
    for field in REQUIRED_REF_FIELDS.get(object_type, ()):
        ref = str(obj.get(field) or "")
        if not ref:
            errors.append(f"{path}: missing {field}")
        elif ref not in object_ids:
            errors.append(f"{path}: {field} references unknown object {ref!r}")
    for field in ("object_refs", "where_sighted_refs"):
        refs = [str(ref) for ref in _as_list(obj.get(field)) if str(ref)]
        if field in obj and not refs:
            errors.append(f"{path}: {field} must not be empty")
        for ref in refs:
            if ref not in object_ids:
                errors.append(f"{path}: {field} references unknown object {ref!r}")


def _validate_type_contract(index: int, obj: Dict[str, Any], errors: List[str]) -> None:
    object_type = str(obj.get("type") or "")
    path = _path(index, obj)
    if object_type == "report":
        if not obj.get("name"):
            errors.append(f"{path}: report missing name")
        if not _as_list(obj.get("object_refs")):
            errors.append(f"{path}: report missing object_refs")
    elif object_type == "attack-pattern":
        refs = obj.get("external_references") or []
        has_mitre = any(
            isinstance(ref, dict)
            and ref.get("source_name") == "mitre-attack"
            and ref.get("external_id")
            for ref in refs
        )
        if not has_mitre:
            errors.append(f"{path}: attack-pattern missing MITRE external reference")
    elif object_type == "indicator":
        if not obj.get("pattern"):
            errors.append(f"{path}: indicator missing pattern")
        if obj.get("pattern_type") != "stix":
            errors.append(f"{path}: indicator pattern_type must be stix")
    elif object_type == "course-of-action":
        if obj.get("x_honeypot_authority") != "trusted_policy_engine":
            errors.append(f"{path}: course-of-action must be trusted_policy_engine-authorized")
        if "x_honeypot_requires_manual_approval" not in obj:
            errors.append(f"{path}: course-of-action missing manual approval flag")
        if "x_honeypot_safe_to_auto_execute" not in obj:
            errors.append(f"{path}: course-of-action missing automation safety flag")
    elif object_type == "observed-data":
        if not _as_list(obj.get("object_refs")):
            errors.append(f"{path}: observed-data missing object_refs")
        if not obj.get("first_observed") or not obj.get("last_observed"):
            errors.append(f"{path}: observed-data missing first/last observed timestamp")
    elif object_type == "sighting":
        if not obj.get("sighting_of_ref"):
            errors.append(f"{path}: sighting missing sighting_of_ref")
    elif object_type == "campaign":
        if not obj.get("x_honeypot_campaign_id"):
            errors.append(f"{path}: campaign missing x_honeypot_campaign_id")
        description = str(obj.get("description") or "").lower()
        if "not confirmed" not in description or "attribution" not in description:
            errors.append(f"{path}: campaign must warn that clustering is not confirmed attribution")
    elif object_type == "identity":
        if not obj.get("identity_class"):
            errors.append(f"{path}: identity missing identity_class")
    elif object_type == "x-honeypot-command-sequence":
        if not obj.get("x_honeypot_session_id"):
            errors.append(f"{path}: command sequence missing session id")
        if not _as_list(obj.get("x_honeypot_commands")):
            errors.append(f"{path}: command sequence missing commands")


def validate_stix_bundle_document(bundle: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    if bundle.get("type") != "bundle":
        errors.append("bundle: type must be bundle")
    if not str(bundle.get("id") or "").startswith("bundle--"):
        errors.append("bundle: id must start with bundle--")
    objects = bundle.get("objects")
    if not isinstance(objects, list) or not objects:
        errors.append("bundle: objects must be a non-empty list")
        return errors

    ids: set[str] = set()
    object_items: List[Dict[str, Any]] = []
    for index, obj in enumerate(objects):
        _validate_object_basics(index, obj, ids, errors)
        if isinstance(obj, dict):
            object_items.append(obj)

    if not any(obj.get("type") == "report" for obj in object_items):
        errors.append("bundle: missing report object")

    for index, obj in enumerate(object_items):
        _validate_references(index, obj, ids, errors)
        _validate_type_contract(index, obj, errors)
    return errors


def run_external_stix_validation(
    bundle_path: str,
    *,
    required: bool = False,
    module_name: str = "stix2validator",
) -> Dict[str, Any]:
    """Run the optional external STIX validator when it is installed.

    The project-level validator above is intentionally focused on the safety
    contracts this system owns. This hook lets operators add a full STIX schema
    check without making production deployments depend on an optional package.
    """

    result: Dict[str, Any] = {
        "available": False,
        "status": "skipped",
        "errors": [],
        "stdout": "",
        "stderr": "",
    }
    if importlib.util.find_spec(module_name) is None:
        reason = f"{module_name} package is not installed"
        result["reason"] = reason
        if required:
            result["status"] = "failed"
            result["errors"] = [reason]
        return result

    result["available"] = True
    try:
        completed = subprocess.run(
            [sys.executable, "-m", module_name, bundle_path],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except Exception as exc:  # pragma: no cover - defensive around optional tool
        result["status"] = "failed"
        result["errors"] = [f"external STIX validator failed to run: {exc}"]
        return result

    result["stdout"] = completed.stdout.strip()
    result["stderr"] = completed.stderr.strip()
    if completed.returncode == 0:
        result["status"] = "passed"
    else:
        result["status"] = "failed"
        details = result["stderr"] or result["stdout"] or f"exit code {completed.returncode}"
        result["errors"] = [f"external STIX validator failed: {details}"]
    return result


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate generated STIX threat bundle structure.")
    parser.add_argument("bundle", help="Path to *_threat_bundle.json")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    parser.add_argument(
        "--external-schema",
        action="store_true",
        help="Also run stix2validator when the optional package is installed.",
    )
    parser.add_argument(
        "--external-required",
        action="store_true",
        help="Fail if the optional external STIX validator is unavailable or fails.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    errors = validate_stix_bundle_document(_load_json(args.bundle))
    external = None
    if args.external_schema or args.external_required:
        external = run_external_stix_validation(args.bundle, required=bool(args.external_required))
        errors.extend(str(error) for error in external.get("errors", []))
    if args.json:
        payload = {"ok": not errors, "errors": errors}
        if external is not None:
            payload["external_schema"] = external
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif errors:
        print("STIX bundle validation failed:")
        for error in errors:
            print(f"- {error}")
    else:
        print("STIX bundle validation passed.")
    if external is not None and not args.json:
        status = external.get("status")
        if status == "skipped":
            print(f"External STIX schema validation skipped: {external.get('reason')}")
        elif status == "passed":
            print("External STIX schema validation passed.")
        else:
            print("External STIX schema validation failed.")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
