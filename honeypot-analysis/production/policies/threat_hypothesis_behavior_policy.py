"""Load and validate the declarative Threat Hypothesis behavior policy."""

from __future__ import annotations

import json
import hashlib
import os
import re
from copy import deepcopy
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from production.utils.sensitive_data import redact_exception_for_log


SCHEMA_VERSION = "threat_hypothesis_behavior_policy.v1"
DEFAULT_POLICY_PATH = "configs/threat_hypothesis_behavior.trusted.json"
ENV_POLICY_PATH = "THREAT_HYPOTHESIS_BEHAVIOR_POLICY_PATH"
EVIDENCE_STATUSES = {"supported", "partially_supported", "insufficient_evidence"}
ACTION_TYPE_RE = re.compile(r"^[a-z][a-z0-9_]*$")
UNSAFE_CLAIM_TEXT_RE = re.compile(
    r"\b(?:confirmed\s+(?:compromise|intent|attribution)|definitive(?:ly)?|"
    r"successfully\s+(?:compromised|persisted|exfiltrated|stole|harvested)|"
    r"attributed\s+to|the\s+actor\s+is|real[- ]world\s+compromise)\b",
    re.IGNORECASE,
)


FAIL_CLOSED_POLICY: Dict[str, Any] = {
    "schema_version": SCHEMA_VERSION,
    "policy_id": "fail-closed-threat-hypothesis-behavior",
    "version": "1",
    "provenance": {
        "method": "built-in fail-closed fallback",
        "basis": ["No valid trusted behavior policy could be loaded"],
        "reviewed": True,
        "reviewer": "production runtime",
        "last_reviewed": "2026-07-16",
        "review_status": "fail closed",
    },
    "policy": {
        "enabled": False,
        "event_types": {"command": [], "transfer": [], "confirmed_download": []},
        "extraction": {
            "command_wrappers": [],
            "shell_interpreters": [],
            "script_interpreters": [],
            "remote_content_executables": {},
            "permission_modification": {"executables": [], "path_argument_start": 0, "action_type": "permission_modification_attempt"},
            "deletion": {"executables": [], "path_argument_start": 0, "action_type": "deletion_attempt"},
            "account": {
                "authorized_keys_marker": "",
                "creation_pattern": r"(?!)",
                "authorized_keys_account_pattern": r"(?!)",
                "action_type": "account_modification_attempt",
                "relationship_type": "account_modified",
            },
            "patterns": {
                "url": r"(?!)",
                "hash": r"(?!)",
                "path_token": r"(?!)",
                "credential_path": r"(?!)",
            },
        },
        "relationships": {
            "path_action_roles": {},
            "allowed_predecessors": {},
            "relationship_types": {},
        },
        "claims": {
            "connected": [],
            "independent": {},
            "follow_on": {
                "progress_action_types": [],
                "completion_action_types": [],
                "claim_type": "possible_follow_on_activity",
                "text": "",
                "evidence_status": "insufficient_evidence",
                "limitations": [],
            },
        },
    },
}


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def policy_body(document: Dict[str, Any]) -> Dict[str, Any]:
    body = document.get("policy", document)
    return body if isinstance(body, dict) else {}


def _validate_string_list(value: Any, path: str, errors: List[str], *, allow_empty: bool = False) -> None:
    if not isinstance(value, list) or (not value and not allow_empty):
        errors.append(f"{path}: must be {'a' if not allow_empty else 'a possibly empty'} list")
        return
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            errors.append(f"{path}[{index}]: must be a non-empty string")


def _validate_pattern(value: Any, path: str, errors: List[str]) -> None:
    if not isinstance(value, str) or not value:
        errors.append(f"{path}: missing regex pattern")
        return
    try:
        re.compile(value, re.IGNORECASE)
    except re.error:
        errors.append(f"{path}: invalid regex")


def _validate_action_types(values: Any, path: str, errors: List[str], *, allow_empty: bool = False) -> None:
    _validate_string_list(values, path, errors, allow_empty=allow_empty)
    for index, value in enumerate(values if isinstance(values, list) else []):
        if isinstance(value, str) and not ACTION_TYPE_RE.fullmatch(value):
            errors.append(f"{path}[{index}]: invalid action type {value!r}")


def _validate_claim(rule: Dict[str, Any], path: str, errors: List[str]) -> None:
    if not str(rule.get("claim_type") or "").strip():
        errors.append(f"{path}: missing claim_type")
    text = str(rule.get("text") or "").strip()
    if not text:
        errors.append(f"{path}: missing text")
    elif UNSAFE_CLAIM_TEXT_RE.search(text):
        errors.append(f"{path}: text contains an unsupported high-impact claim")
    status = str(rule.get("evidence_status_override") or rule.get("evidence_status") or "").strip()
    if status and status not in EVIDENCE_STATUSES:
        errors.append(f"{path}: unsupported evidence status {status!r}")
    limitations = rule.get("limitations", [])
    _validate_string_list(limitations, f"{path}.limitations", errors, allow_empty=True)


def validate_behavior_policy(document: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    if document.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"policy: schema_version must be {SCHEMA_VERSION}")
    for key in ("policy_id", "version"):
        if not str(document.get(key) or "").strip():
            errors.append(f"policy: missing {key}")
    provenance = document.get("provenance")
    if not isinstance(provenance, dict):
        errors.append("policy: missing provenance")
    else:
        for key in ("method", "basis", "reviewed", "reviewer", "last_reviewed", "review_status"):
            if provenance.get(key) in (None, "", []):
                errors.append(f"policy.provenance: missing {key}")
        if provenance.get("reviewed") is not True:
            errors.append("policy.provenance.reviewed: trusted policy must be reviewed")
        _validate_string_list(provenance.get("basis"), "policy.provenance.basis", errors)

    body = policy_body(document)
    if not isinstance(body.get("enabled"), bool):
        errors.append("policy.enabled: must be boolean")
    event_types = body.get("event_types") or {}
    for key in ("command", "transfer", "confirmed_download"):
        _validate_string_list(event_types.get(key), f"policy.event_types.{key}", errors)

    extraction = body.get("extraction") or {}
    for key in ("command_wrappers", "shell_interpreters", "script_interpreters"):
        _validate_string_list(extraction.get(key), f"policy.extraction.{key}", errors)
    remotes = extraction.get("remote_content_executables")
    if not isinstance(remotes, dict) or not remotes:
        errors.append("policy.extraction.remote_content_executables: must be a non-empty object")
    else:
        for executable, settings in remotes.items():
            path = f"policy.extraction.remote_content_executables.{executable}"
            if not ACTION_TYPE_RE.fullmatch(str(executable or "")):
                errors.append(f"{path}: invalid executable name")
            if not isinstance(settings, dict):
                errors.append(f"{path}: settings must be an object")
                continue
            _validate_string_list(settings.get("output_options"), f"{path}.output_options", errors, allow_empty=True)
            for key in ("transfer_without_output", "pipe_source"):
                if not isinstance(settings.get(key), bool):
                    errors.append(f"{path}.{key}: must be boolean")

    for name in ("permission_modification", "deletion"):
        definition = extraction.get(name) or {}
        _validate_string_list(definition.get("executables"), f"policy.extraction.{name}.executables", errors)
        _validate_action_types([definition.get("action_type")], f"policy.extraction.{name}.action_type", errors)
        try:
            if int(definition.get("path_argument_start")) < 0:
                raise ValueError
        except (TypeError, ValueError):
            errors.append(f"policy.extraction.{name}.path_argument_start: must be a non-negative integer")

    account = extraction.get("account") or {}
    if not str(account.get("authorized_keys_marker") or "").strip():
        errors.append("policy.extraction.account.authorized_keys_marker: missing value")
    for key in ("creation_pattern", "authorized_keys_account_pattern"):
        _validate_pattern(account.get(key), f"policy.extraction.account.{key}", errors)
    _validate_action_types([account.get("action_type")], "policy.extraction.account.action_type", errors)
    if not str(account.get("relationship_type") or "").strip():
        errors.append("policy.extraction.account.relationship_type: missing value")

    patterns = extraction.get("patterns") or {}
    for key in ("url", "hash", "path_token", "credential_path"):
        _validate_pattern(patterns.get(key), f"policy.extraction.patterns.{key}", errors)

    relationships = body.get("relationships") or {}
    roles = relationships.get("path_action_roles") or {}
    if not isinstance(roles, dict) or not roles:
        errors.append("policy.relationships.path_action_roles: must be a non-empty object")
    for role, action_type in roles.items() if isinstance(roles, dict) else []:
        if not str(role or "").strip():
            errors.append("policy.relationships.path_action_roles: empty role")
        _validate_action_types([action_type], f"policy.relationships.path_action_roles.{role}", errors)
    predecessors = relationships.get("allowed_predecessors") or {}
    if not isinstance(predecessors, dict):
        errors.append("policy.relationships.allowed_predecessors: must be an object")
    for action_type, values in predecessors.items() if isinstance(predecessors, dict) else []:
        _validate_action_types([action_type], f"policy.relationships.allowed_predecessors.{action_type}.target", errors)
        _validate_action_types(values, f"policy.relationships.allowed_predecessors.{action_type}", errors)
    relation_types = relationships.get("relationship_types") or {}
    if not isinstance(relation_types, dict):
        errors.append("policy.relationships.relationship_types: must be an object")
    for action_type in roles.values() if isinstance(roles, dict) else []:
        if action_type != "transfer_attempt" and not str(relation_types.get(action_type) or "").strip():
            errors.append(f"policy.relationships.relationship_types: missing mapping for {action_type!r}")

    claims = body.get("claims") or {}
    connected = claims.get("connected")
    if not isinstance(connected, list) or not connected:
        errors.append("policy.claims.connected: must be a non-empty list")
    seen_rule_ids = set()
    for index, rule in enumerate(connected if isinstance(connected, list) else []):
        path = f"policy.claims.connected[{index}]"
        if not isinstance(rule, dict):
            errors.append(f"{path}: must be an object")
            continue
        rule_id = str(rule.get("rule_id") or "").strip()
        if not rule_id:
            errors.append(f"{path}: missing rule_id")
        elif rule_id in seen_rule_ids:
            errors.append(f"{path}: duplicate rule_id {rule_id!r}")
        seen_rule_ids.add(rule_id)
        _validate_action_types(rule.get("required_action_types"), f"{path}.required_action_types", errors)
        _validate_action_types(rule.get("excluded_action_types", []), f"{path}.excluded_action_types", errors, allow_empty=True)
        _validate_claim(rule, path, errors)

    independent = claims.get("independent")
    if not isinstance(independent, dict):
        errors.append("policy.claims.independent: must be an object")
    else:
        for name in ("credential", "downloader", "execution", "persistence", "cleanup", "confirmed_download"):
            if not isinstance(independent.get(name), dict):
                errors.append(f"policy.claims.independent.{name}: missing object")
        for name in ("credential", "persistence", "cleanup"):
            definition = independent.get(name) or {}
            _validate_pattern(definition.get("trusted_command_pattern"), f"policy.claims.independent.{name}.trusted_command_pattern", errors)
            _validate_claim(definition, f"policy.claims.independent.{name}", errors)
        downloader = independent.get("downloader") or {}
        _validate_action_types(downloader.get("literal_action_types"), "policy.claims.independent.downloader.literal_action_types", errors)
        _validate_pattern(downloader.get("legacy_command_pattern"), "policy.claims.independent.downloader.legacy_command_pattern", errors)
        _validate_claim(downloader, "policy.claims.independent.downloader", errors)
        execution = independent.get("execution") or {}
        _validate_action_types(execution.get("literal_action_types"), "policy.claims.independent.execution.literal_action_types", errors)
        _validate_pattern(execution.get("legacy_command_pattern"), "policy.claims.independent.execution.legacy_command_pattern", errors)
        claim_types = execution.get("claim_types") or {}
        for key in ("success", "failure_or_unknown"):
            if not str(claim_types.get(key) or "").strip():
                errors.append(f"policy.claims.independent.execution.claim_types.{key}: missing value")
        _validate_claim(independent.get("confirmed_download") or {}, "policy.claims.independent.confirmed_download", errors)

    follow_on = claims.get("follow_on") or {}
    _validate_action_types(follow_on.get("progress_action_types"), "policy.claims.follow_on.progress_action_types", errors)
    _validate_action_types(follow_on.get("completion_action_types"), "policy.claims.follow_on.completion_action_types", errors)
    _validate_claim(follow_on, "policy.claims.follow_on", errors)
    return errors


def _candidate_paths(
    path_text: str = "",
    env_path: str = "",
    cwd_text: str = "",
) -> List[Path]:
    requested = path_text or env_path
    project_root = Path(__file__).resolve().parents[2]
    working_directory = Path(cwd_text) if cwd_text else Path.cwd()
    candidates: List[Path] = []
    if requested:
        candidates.append(Path(requested))
    else:
        candidates.extend([working_directory / DEFAULT_POLICY_PATH, project_root / DEFAULT_POLICY_PATH])
    unique: List[Path] = []
    for candidate in candidates:
        if candidate not in unique:
            unique.append(candidate)
    return unique


@lru_cache(maxsize=16)
def _load_cached(path_text: str, env_path: str, cwd_text: str) -> Dict[str, Any]:
    errors: List[str] = []
    requested = path_text or env_path
    for candidate in _candidate_paths(path_text, env_path, cwd_text):
        try:
            raw = candidate.read_bytes()
            loaded = json.loads(raw.decode("utf-8"))
            if not isinstance(loaded, dict):
                raise ValueError("JSON root must be an object")
            validation_errors = validate_behavior_policy(loaded)
            if validation_errors:
                errors.append("policy_validation_failed")
                continue
            document = deepcopy(loaded)
            document["load_status"] = {
                "status": "loaded",
                "source": candidate.name,
                "source_path": str(candidate.resolve()),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "fallback_used": False,
                "errors": errors,
            }
            return document
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(redact_exception_for_log(exc))
    document = deepcopy(FAIL_CLOSED_POLICY)
    document["load_status"] = {
        "status": "fail_closed",
        "source": "built_in_fail_closed",
        "fallback_used": True,
        "errors": errors,
    }
    return document


def load_behavior_policy(path_text: str = "") -> Dict[str, Any]:
    """Load a valid policy, falling back to the bundled policy or fail-closed."""

    return deepcopy(_load_cached(path_text, os.getenv(ENV_POLICY_PATH, ""), str(Path.cwd())))


def resolve_behavior_policy(
    policy_document: Optional[Dict[str, Any]] = None,
    path_text: str = "",
) -> Dict[str, Any]:
    """Resolve and validate either an in-memory policy or a configured file."""

    if not isinstance(policy_document, dict):
        return load_behavior_policy(path_text)
    errors = validate_behavior_policy(policy_document)
    if errors:
        document = deepcopy(FAIL_CLOSED_POLICY)
        document["load_status"] = {
            "status": "fail_closed",
            "source": "invalid_in_memory_policy",
            "fallback_used": True,
            "errors": errors,
        }
        return document
    document = deepcopy(policy_document)
    document.setdefault("load_status", {
        "status": "provided",
        "source": "in_memory",
        "sha256": hashlib.sha256(
            json.dumps(
                policy_document,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest(),
        "fallback_used": False,
        "errors": [],
    })
    return document


def policy_summary(
    document: Dict[str, Any],
    *,
    include_integrity: bool = False,
) -> Dict[str, Any]:
    status = document.get("load_status") or {}
    provenance = document.get("provenance") or {}
    load_status = str(status.get("status") or "unknown")
    fallback_used = bool(status.get("fallback_used"))
    enabled = bool(policy_body(document).get("enabled"))
    if not enabled:
        operating_mode = "fail_closed"
    elif fallback_used:
        operating_mode = "trusted_bundled_fallback"
    else:
        operating_mode = "trusted_selected_policy"
    summary = {
        "schema_version": str(document.get("schema_version") or ""),
        "policy_id": str(document.get("policy_id") or ""),
        "version": str(document.get("version") or ""),
        "enabled": enabled,
        "reviewed": bool(provenance.get("reviewed")),
        "review_status": str(provenance.get("review_status") or ""),
        "last_reviewed": str(provenance.get("last_reviewed") or ""),
        "method": str(provenance.get("method") or ""),
        "load_status": load_status,
        "source": str(status.get("source") or ""),
        "fallback_used": fallback_used,
        "operating_mode": operating_mode,
        "requested_policy_honored": not fallback_used,
        "load_error_count": len(_as_list(status.get("errors"))),
    }
    if include_integrity:
        summary["sha256"] = str(status.get("sha256") or "")
        summary["effective_path"] = str(status.get("source_path") or status.get("source") or "")
    return summary


def compile_pattern(document: Dict[str, Any], value: Any) -> re.Pattern[str]:
    """Compile a validated policy regex; fail closed if called with invalid input."""

    del document
    try:
        return re.compile(str(value or r"(?!)"), re.IGNORECASE | re.MULTILINE)
    except re.error:
        return re.compile(r"(?!)")
