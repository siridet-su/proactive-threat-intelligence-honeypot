"""Minimal pre-persistence credential sanitization for Cowrie events.

This module deliberately has no application or Cowrie dependency.  The Pi
output observers and the downstream persistence boundaries import the same
implementation so they cannot drift to separate credential policies.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections import deque
from collections.abc import Mapping
from dataclasses import replace
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "cowrie_credential_sanitizer.v1"
POLICY_SCHEMA_VERSION = "cowrie_output_privacy_policy.v1"
REDACTION_MARKER = "[REDACTED]"
OVERSIZED_JSON_MARKER = "[REDACTED: OVERSIZED JSON]"

_POLICY_KEYS = {
    "schema_version",
    "policy_id",
    "version",
    "redaction_marker",
    "redact_attacker_username",
    "credential_value_keys",
    "credential_container_keys",
    "login_event_prefixes",
    "login_summary_keys",
    "max_depth",
    "max_registry_values",
    "max_registered_value_chars",
}

DEFAULT_POLICY_DOCUMENT: dict[str, Any] = {
    "schema_version": POLICY_SCHEMA_VERSION,
    "policy_id": "cowrie_pre_persistence_credentials",
    "version": "1.0.0",
    "redaction_marker": REDACTION_MARKER,
    "redact_attacker_username": True,
    "credential_value_keys": [
        "auth_secret",
        "authentication_secret",
        "login_password",
        "login_username",
        "passphrase",
        "passwd",
        "password",
        "pwd",
        "user_name",
        "username",
    ],
    "credential_container_keys": [
        "credential",
        "credentials",
        "login_credentials",
    ],
    "login_event_prefixes": ["cowrie.login."],
    "login_summary_keys": ["log_text", "message"],
    "max_depth": 48,
    "max_registry_values": 256,
    "max_registered_value_chars": 16_384,
}


@dataclass(frozen=True)
class CowriePrivacyPolicy:
    policy_id: str
    version: str
    sha256: str
    redaction_marker: str
    redact_attacker_username: bool
    credential_value_keys: frozenset[str]
    credential_container_keys: frozenset[str]
    login_event_prefixes: tuple[str, ...]
    login_summary_keys: frozenset[str]
    max_depth: int
    max_registry_values: int
    max_registered_value_chars: int


def _canonical_json(document: Mapping[str, Any]) -> bytes:
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _closed_string_list(value: Any, field: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or item != item.strip().lower() or not item for item in value)
        or value != sorted(set(value))
    ):
        raise ValueError(f"{field} must be a sorted unique non-empty lowercase list")
    return list(value)


def validate_policy_document(document: Any) -> CowriePrivacyPolicy:
    if not isinstance(document, Mapping):
        raise ValueError("Cowrie privacy policy must be an object")
    if set(document) != _POLICY_KEYS:
        raise ValueError("Cowrie privacy policy keys do not match the closed contract")
    if document["schema_version"] != POLICY_SCHEMA_VERSION:
        raise ValueError(f"schema_version must be {POLICY_SCHEMA_VERSION}")
    for field in ("policy_id", "version"):
        if not isinstance(document[field], str) or not document[field].strip():
            raise ValueError(f"{field} must be a non-empty string")
    marker = document["redaction_marker"]
    if marker != REDACTION_MARKER:
        raise ValueError("redaction_marker must match the canonical marker")
    if document["redact_attacker_username"] is not True:
        raise ValueError("attacker username redaction must remain enabled")
    value_keys = _closed_string_list(
        document["credential_value_keys"], "credential_value_keys"
    )
    container_keys = _closed_string_list(
        document["credential_container_keys"], "credential_container_keys"
    )
    event_prefixes = _closed_string_list(
        document["login_event_prefixes"], "login_event_prefixes"
    )
    summary_keys = _closed_string_list(
        document["login_summary_keys"], "login_summary_keys"
    )
    if {"username", "password", "passwd", "pwd"} - set(value_keys):
        raise ValueError("required Cowrie credential keys are missing")
    for field, minimum, maximum in (
        ("max_depth", 8, 128),
        ("max_registry_values", 16, 4096),
        ("max_registered_value_chars", 64, 1_048_576),
    ):
        value = document[field]
        if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
            raise ValueError(f"{field} is outside the permitted bound")
    return CowriePrivacyPolicy(
        policy_id=str(document["policy_id"]),
        version=str(document["version"]),
        sha256=hashlib.sha256(_canonical_json(document)).hexdigest(),
        redaction_marker=marker,
        redact_attacker_username=True,
        credential_value_keys=frozenset(value_keys),
        credential_container_keys=frozenset(container_keys),
        login_event_prefixes=tuple(event_prefixes),
        login_summary_keys=frozenset(summary_keys),
        max_depth=int(document["max_depth"]),
        max_registry_values=int(document["max_registry_values"]),
        max_registered_value_chars=int(document["max_registered_value_chars"]),
    )


def load_policy(path: str | Path) -> CowriePrivacyPolicy:
    policy_path = Path(path)
    try:
        raw = policy_path.read_bytes()
        document = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Cowrie privacy policy is unavailable or invalid") from exc
    policy = validate_policy_document(document)
    return replace(policy, sha256=hashlib.sha256(raw).hexdigest())


DEFAULT_POLICY = validate_policy_document(DEFAULT_POLICY_DOCUMENT)


class CredentialValueRegistry:
    """Bounded registry used to scrub credentials from later diagnostics."""

    def __init__(self, policy: CowriePrivacyPolicy = DEFAULT_POLICY) -> None:
        self.policy = policy
        self._values: deque[str] = deque()
        self._membership: set[str] = set()

    def remember(self, value: Any) -> None:
        if not isinstance(value, str) or not value or value == self.policy.redaction_marker:
            return
        if len(value) > self.policy.max_registered_value_chars or value in self._membership:
            return
        self._values.append(value)
        self._membership.add(value)
        while len(self._values) > self.policy.max_registry_values:
            self._membership.discard(self._values.popleft())

    def scrub(self, text: str) -> str:
        sanitized = text
        for value in sorted(self._membership, key=len, reverse=True):
            sanitized = sanitized.replace(value, self.policy.redaction_marker)
        return sanitized


PROCESS_CREDENTIAL_REGISTRY = CredentialValueRegistry()


_DIAGNOSTIC_EVENT_CATEGORIES = {
    "cowrie.login.success": ("authentication", "success"),
    "cowrie.login.failed": ("authentication", "failed"),
    "cowrie.session.connect": ("session", "started"),
    "cowrie.session.closed": ("session", "closed"),
    "cowrie.session.file_download": ("transfer", "observed"),
    "cowrie.session.file_upload": ("transfer", "observed"),
    "cowrie.command.input": ("command", "observed"),
    "cowrie.command.failed": ("command", "failed"),
    "cowrie.log.closed": ("lifecycle", "closed"),
}
_DIAGNOSTIC_EVENT_PREFIXES = (
    ("cowrie.client.", "client"),
    ("cowrie.direct-tcpip.", "network"),
    ("cowrie.session.", "session"),
    ("cowrie.command.", "command"),
    ("cowrie.login.", "authentication"),
)


def _diagnostic_category(event: Mapping[str, Any]) -> tuple[str, str]:
    """Return closed diagnostic categories without retaining attacker text."""

    if "log_failure" in event or "failure" in event:
        return "operation", "failed"
    event_id = event.get("eventid")
    if not isinstance(event_id, str):
        return "diagnostic", "observed"
    normalized = event_id.strip().lower()
    exact = _DIAGNOSTIC_EVENT_CATEGORIES.get(normalized)
    if exact is not None:
        return exact
    for prefix, category in _DIAGNOSTIC_EVENT_PREFIXES:
        if normalized.startswith(prefix):
            return category, "observed"
    return "diagnostic", "observed"


def _diagnostic_session_reference(event: Mapping[str, Any]) -> str:
    """Pseudonymize a bounded canonical session value or explicitly abstain."""

    value = event.get("session")
    if isinstance(value, bytes):
        raw = value[:256]
    elif isinstance(value, str):
        raw = value.encode("utf-8", errors="replace")[:256]
    else:
        return "session_unavailable"
    if not raw:
        return "session_unavailable"
    return "session_" + hashlib.sha256(raw).hexdigest()[:16]


def sanitize_cowrie_event_for_persistence(
    event: Mapping[str, Any],
    *,
    policy: CowriePrivacyPolicy = DEFAULT_POLICY,
    registry: CredentialValueRegistry | None = None,
) -> dict[str, Any]:
    """Return an idempotent event with credentials removed before persistence."""

    if not isinstance(event, Mapping):
        raise ValueError("Cowrie event must be an object")
    registry = registry or PROCESS_CREDENTIAL_REGISTRY
    redacted_fields: set[str] = set()

    def redact_scalar(value: Any, field: str) -> Any:
        if value in (None, ""):
            return value
        if isinstance(value, str):
            registry.remember(value)
        redacted_fields.add(field)
        return policy.redaction_marker

    def sanitize(value: Any, depth: int = 0, *, credential_container: str = "") -> Any:
        if depth > policy.max_depth:
            if credential_container:
                redacted_fields.add(credential_container)
            return OVERSIZED_JSON_MARKER
        if credential_container:
            if isinstance(value, Mapping):
                return {
                    str(raw_key): sanitize(
                        item,
                        depth + 1,
                        credential_container=credential_container,
                    )
                    for raw_key, item in value.items()
                }
            if isinstance(value, (list, tuple)):
                return [
                    sanitize(item, depth + 1, credential_container=credential_container)
                    for item in value
                ]
            return redact_scalar(value, credential_container)
        if isinstance(value, Mapping):
            output: dict[str, Any] = {}
            for raw_key, item in value.items():
                key = str(raw_key)
                normalized = key.strip().lower()
                if normalized in policy.credential_value_keys:
                    output[key] = redact_scalar(item, normalized)
                elif normalized in policy.credential_container_keys:
                    output[key] = sanitize(
                        item,
                        depth + 1,
                        credential_container=normalized,
                    )
                else:
                    output[key] = sanitize(item, depth + 1)
            return output
        if isinstance(value, (list, tuple)):
            return [sanitize(item, depth + 1) for item in value]
        if isinstance(value, str):
            return registry.scrub(value)
        return value

    sanitized = sanitize(event)
    if not isinstance(sanitized, dict):  # pragma: no cover
        raise ValueError("sanitized Cowrie event must be an object")

    event_id = str(sanitized.get("eventid") or "").strip().lower()
    if any(event_id.startswith(prefix) for prefix in policy.login_event_prefixes):
        for key in policy.login_summary_keys:
            if key in sanitized:
                sanitized[key] = redact_scalar(sanitized[key], key)

    prior = event.get("_honeypot_privacy")
    prior_fields: set[str] = set()
    allowed_metadata = (
        policy.credential_value_keys
        | policy.credential_container_keys
        | policy.login_summary_keys
    )
    if isinstance(prior, Mapping):
        prior_fields = {
            str(item).strip().lower()
            for item in prior.get("credential_fields_redacted", []) or []
            if str(item).strip().lower() in allowed_metadata
        }
    fields = sorted(redacted_fields | prior_fields)
    if fields:
        sanitized["_honeypot_privacy"] = {
            "schema_version": SCHEMA_VERSION,
            "credential_plaintext_removed": True,
            "credential_fields_redacted": fields,
        }
    else:
        sanitized.pop("_honeypot_privacy", None)
    return sanitized


def sanitize_twisted_event(
    event: Mapping[str, Any],
    *,
    policy: CowriePrivacyPolicy = DEFAULT_POLICY,
    registry: CredentialValueRegistry | None = None,
) -> dict[str, Any]:
    """Project a Twisted event to closed, non-secret operational diagnostics.

    Cowrie and local extensions may send already-formatted authentication text
    without structured credential fields.  Replacement-based scrubbing cannot
    prove those strings safe, regardless of observer ordering.  The diagnostic
    sink therefore emits only categorical fields and a one-way session
    reference.  The lossless, sanitized JSON observer remains the evidence
    source.
    """

    registry = registry or PROCESS_CREDENTIAL_REGISTRY
    # Register structured credential values for defense in depth, but never
    # reuse arbitrary strings from this result in the diagnostic projection.
    sanitize_cowrie_event_for_persistence(
        event, policy=policy, registry=registry
    )
    category, outcome = _diagnostic_category(event)
    raw_time = event.get("log_time", 0.0)
    log_time = (
        float(raw_time)
        if isinstance(raw_time, (int, float))
        and not isinstance(raw_time, bool)
        and math.isfinite(float(raw_time))
        else 0.0
    )
    return {
        "log_format": (
            "cowrie_diagnostic category={diagnostic_category} "
            "outcome={diagnostic_outcome} session_ref={session_ref}"
        ),
        "diagnostic_category": category,
        "diagnostic_outcome": outcome,
        "session_ref": _diagnostic_session_reference(event),
        "log_time": log_time,
    }


def serialize_cowrie_event_for_persistence(
    event: Mapping[str, Any],
    *,
    policy: CowriePrivacyPolicy = DEFAULT_POLICY,
    registry: CredentialValueRegistry | None = None,
    epoch_timestamp: bool = False,
) -> bytes:
    """Serialize exactly one sanitized Cowrie JSON record."""

    sanitized = sanitize_cowrie_event_for_persistence(
        event, policy=policy, registry=registry
    )
    if epoch_timestamp:
        timestamp = sanitized.get("time")
        if not isinstance(timestamp, (int, float)) or isinstance(timestamp, bool):
            raise ValueError("Cowrie epoch timestamp requires numeric time")
        sanitized["epoch"] = int(timestamp * 1000000 / 1000)
    for key in list(sanitized):
        if key.startswith("log_") or key in {"time", "system"}:
            del sanitized[key]
    try:
        return (
            json.dumps(
                sanitized,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("Cowrie event is not safely serializable") from exc
