"""Keyed credential correlation without storing reusable credential material.

The keyring is deliberately loaded only by the session worker.  Raw telemetry
storage remains a separate trust boundary; derived session documents receive
only versioned HMAC values and non-secret key identifiers.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, Tuple


CREDENTIAL_HMAC_SCHEME = "hmac-sha256-v1"
CREDENTIAL_HMAC_KEYRING_SCHEMA = "credential_hmac_keyring.v1"
CREDENTIAL_METADATA_SCHEMA = "credential_metadata.v1"
_CREDENTIAL_HMAC_DOMAIN = b"honeypot-analysis/credential/v1\0"
_KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_CREDENTIAL_HMAC_DIGEST_PATTERN = re.compile(
    rf"^{re.escape(CREDENTIAL_HMAC_SCHEME)}:"
    r"[A-Za-z0-9._-]{1,64}:[0-9a-f]{64}$"
)
_MAX_KEYRING_BYTES = 64 * 1024
_MIN_KEY_BYTES = 32
_MAX_KEY_BYTES = 128
_MAX_CORRELATION_KEYS = 2
_SYSTEMD_CREDENTIAL_NAME = "credential-hmac-keyring.json"
_SYSTEMD_CREDENTIALS_ROOT = Path("/run/credentials")


class CredentialHMACError(ValueError):
    """Raised when credential-HMAC configuration cannot be used safely."""


class CredentialHasher:
    """Versioned, repr-safe credential HMAC helper with bounded rotation."""

    __slots__ = ("_active_key_id", "_correlation_key_ids", "_keys")

    def __init__(
        self,
        *,
        active_key_id: str,
        keys: Mapping[str, bytes],
        correlation_key_ids: Sequence[str] = (),
    ) -> None:
        active = _validate_key_id(active_key_id, "active_key_id")
        aliases = tuple(
            _validate_key_id(value, "correlation_key_ids")
            for value in correlation_key_ids
        )
        if len(aliases) > _MAX_CORRELATION_KEYS:
            raise CredentialHMACError(
                f"at most {_MAX_CORRELATION_KEYS} correlation keys are supported"
            )
        if len(set(aliases)) != len(aliases):
            raise CredentialHMACError("correlation key identifiers must be unique")
        if active in aliases:
            raise CredentialHMACError("the active key cannot also be a correlation key")

        expected_ids = {active, *aliases}
        actual_ids = set(keys)
        if actual_ids != expected_ids:
            raise CredentialHMACError(
                "the keyring must contain exactly the active and correlation keys"
            )

        validated_keys: Dict[str, bytes] = {}
        for key_id, raw_key in keys.items():
            normalized_id = _validate_key_id(key_id, "keys")
            if not isinstance(raw_key, bytes):
                raise CredentialHMACError("credential HMAC keys must decode to bytes")
            if not _MIN_KEY_BYTES <= len(raw_key) <= _MAX_KEY_BYTES:
                raise CredentialHMACError(
                    f"credential HMAC keys must be {_MIN_KEY_BYTES}-{_MAX_KEY_BYTES} bytes"
                )
            validated_keys[normalized_id] = bytes(raw_key)
        if len(set(validated_keys.values())) != len(validated_keys):
            raise CredentialHMACError(
                "active and correlation key identifiers must use distinct key material"
            )

        self._active_key_id = active
        self._correlation_key_ids = aliases
        self._keys = MappingProxyType(validated_keys)

    def __repr__(self) -> str:
        return (
            "CredentialHasher("
            f"scheme={CREDENTIAL_HMAC_SCHEME!r}, "
            f"active_key_id={self._active_key_id!r}, "
            f"correlation_key_ids={self._correlation_key_ids!r})"
        )

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> "CredentialHasher":
        """Validate a decoded keyring document and construct a hasher."""

        if not isinstance(document, Mapping):
            raise CredentialHMACError("credential HMAC keyring must be a JSON object")
        allowed_fields = {
            "schema_version",
            "active_key_id",
            "keys",
            "correlation_key_ids",
        }
        unknown_fields = set(document) - allowed_fields
        if unknown_fields:
            raise CredentialHMACError("credential HMAC keyring contains unknown fields")
        if document.get("schema_version") != CREDENTIAL_HMAC_KEYRING_SCHEMA:
            raise CredentialHMACError("unsupported credential HMAC keyring schema")

        active_key_id = _validate_key_id(
            document.get("active_key_id"),
            "active_key_id",
        )
        raw_aliases = document.get("correlation_key_ids", [])
        if (
            not isinstance(raw_aliases, list)
            or any(not isinstance(value, str) for value in raw_aliases)
        ):
            raise CredentialHMACError("correlation_key_ids must be a JSON string list")

        raw_keys = document.get("keys")
        if not isinstance(raw_keys, Mapping) or not raw_keys:
            raise CredentialHMACError("keys must be a non-empty JSON object")
        decoded_keys: Dict[str, bytes] = {}
        for raw_key_id, encoded_key in raw_keys.items():
            key_id = _validate_key_id(raw_key_id, "keys")
            if not isinstance(encoded_key, str):
                raise CredentialHMACError("credential HMAC keys must be base64 strings")
            try:
                decoded = base64.b64decode(encoded_key, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise CredentialHMACError(
                    "credential HMAC keys must use strict base64 encoding"
                ) from exc
            decoded_keys[key_id] = decoded

        return cls(
            active_key_id=active_key_id,
            keys=decoded_keys,
            correlation_key_ids=raw_aliases,
        )

    @property
    def active_key_id(self) -> str:
        return self._active_key_id

    @property
    def correlation_key_ids(self) -> Tuple[str, ...]:
        return self._correlation_key_ids

    def safe_summary(self) -> Dict[str, Any]:
        """Return non-secret metadata suitable for persisted session state."""

        return {
            "hash_algorithm": CREDENTIAL_HMAC_SCHEME,
            "hashing_enabled": True,
            "active_key_id": self._active_key_id,
            "correlation_key_ids": list(self._correlation_key_ids),
        }

    def digest(self, value: str, *, key_id: str | None = None) -> str:
        """Return one versioned HMAC value for ``value``."""

        selected_id = key_id or self._active_key_id
        if selected_id not in self._keys:
            raise CredentialHMACError("unknown credential HMAC key identifier")
        if not isinstance(value, str):
            raise CredentialHMACError("credential values must be strings")
        message = _CREDENTIAL_HMAC_DOMAIN + value.encode("utf-8", errors="surrogatepass")
        digest = hmac.new(self._keys[selected_id], message, hashlib.sha256).hexdigest()
        return f"{CREDENTIAL_HMAC_SCHEME}:{selected_id}:{digest}"

    def digests(self, value: str) -> Tuple[str, Tuple[str, ...]]:
        """Return the active digest followed by bounded prior-key aliases."""

        return (
            self.digest(value),
            tuple(self.digest(value, key_id=key_id) for key_id in self._correlation_key_ids),
        )


def _validate_key_id(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _KEY_ID_PATTERN.fullmatch(value):
        raise CredentialHMACError(
            f"{field_name} must use 1-64 letters, numbers, dots, underscores, or hyphens"
        )
    return value


def is_credential_hmac_digest(value: Any) -> bool:
    """Return whether a value is one canonical versioned credential digest."""

    return isinstance(value, str) and bool(
        _CREDENTIAL_HMAC_DIGEST_PATTERN.fullmatch(value)
    )


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON constants are not permitted")


def _reject_duplicate_json_keys(pairs: Sequence[tuple[str, Any]]) -> Dict[str, Any]:
    document: Dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate JSON object key")
        document[key] = value
    return document


def _is_protected_systemd_credential(
    path: Path,
    metadata: os.stat_result,
) -> bool:
    """Recognize systemd 257's read-only group-readable credential mount."""

    credentials_directory_value = os.getenv("CREDENTIALS_DIRECTORY", "").strip()
    if not credentials_directory_value:
        return False
    credentials_directory = Path(credentials_directory_value)
    if (
        not credentials_directory.is_absolute()
        or credentials_directory.parent != _SYSTEMD_CREDENTIALS_ROOT
        or path != credentials_directory / _SYSTEMD_CREDENTIAL_NAME
        or stat.S_IMODE(metadata.st_mode) != 0o440
    ):
        return False

    try:
        directory_metadata = os.lstat(credentials_directory)
    except OSError:
        return False
    if (
        not stat.S_ISDIR(directory_metadata.st_mode)
        or stat.S_ISLNK(directory_metadata.st_mode)
        or stat.S_IMODE(directory_metadata.st_mode) != 0o550
    ):
        return False

    return os.access(path, os.R_OK) and not os.access(path, os.W_OK)


def load_credential_hmac_keyring(path_value: str) -> CredentialHasher:
    """Load a small, non-symlinked, protected JSON keyring from disk."""

    if not isinstance(path_value, str) or not path_value.strip():
        raise CredentialHMACError("credential HMAC keyring file is required")
    path = Path(path_value)
    if not path.is_absolute():
        raise CredentialHMACError("credential HMAC keyring path must be absolute")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CredentialHMACError("credential HMAC keyring file cannot be opened") from exc

    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise CredentialHMACError("credential HMAC keyring must be a regular file")
        if metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO) and not (
            _is_protected_systemd_credential(path, metadata)
        ):
            raise CredentialHMACError(
                "credential HMAC keyring must not grant group or other permissions"
            )
        if metadata.st_size <= 0 or metadata.st_size > _MAX_KEYRING_BYTES:
            raise CredentialHMACError(
                f"credential HMAC keyring must be 1-{_MAX_KEYRING_BYTES} bytes"
            )
        chunks = []
        remaining = _MAX_KEYRING_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(remaining, 8192))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw_document = b"".join(chunks)
        if len(raw_document) > _MAX_KEYRING_BYTES:
            raise CredentialHMACError("credential HMAC keyring is too large")
    finally:
        os.close(descriptor)

    try:
        document = json.loads(
            raw_document.decode("utf-8"),
            parse_constant=_reject_json_constant,
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise CredentialHMACError("credential HMAC keyring is not valid UTF-8 JSON") from exc
    return CredentialHasher.from_document(document)


def resolve_credential_hmac_keyring_path(configured_path: str = "") -> str:
    """Resolve an explicit path or the worker's systemd credential path."""

    if isinstance(configured_path, str) and configured_path.strip():
        return configured_path.strip()
    credentials_directory = os.getenv("CREDENTIALS_DIRECTORY", "").strip()
    if not credentials_directory:
        return ""
    return str(Path(credentials_directory) / _SYSTEMD_CREDENTIAL_NAME)


def credential_metadata_for_provenance(value: Any) -> Dict[str, Any]:
    """Return the strict non-secret credential metadata schema for reports."""

    result: Dict[str, Any] = {
        "schema_version": CREDENTIAL_METADATA_SCHEMA,
        "metadata_status": "unavailable",
    }
    if not isinstance(value, Mapping):
        return result

    boolean_fields = (
        "credential_observed",
        "raw_password_stored",
        "password_hash_present",
        "raw_events_sanitized",
        "hashing_enabled",
    )
    if any(not isinstance(value.get(field_name), bool) for field_name in boolean_fields):
        return result
    parsed_booleans = {
        field_name: value[field_name]
        for field_name in boolean_fields
    }

    alias_count = value.get("password_hash_alias_count")
    if not (
        isinstance(alias_count, int)
        and not isinstance(alias_count, bool)
        and 0 <= alias_count <= _MAX_CORRELATION_KEYS
    ):
        return result

    algorithm = value.get("hash_algorithm")
    if not (isinstance(algorithm, str) and algorithm in {
        CREDENTIAL_HMAC_SCHEME,
        "disabled",
    }):
        return result

    active_key_id = value.get("active_key_id")
    if not (active_key_id == "" or (
        isinstance(active_key_id, str) and _KEY_ID_PATTERN.fullmatch(active_key_id)
    )):
        return result

    correlation_key_ids = value.get("correlation_key_ids")
    if not (
        isinstance(correlation_key_ids, (list, tuple))
        and len(correlation_key_ids) <= _MAX_CORRELATION_KEYS
        and all(
            isinstance(key_id, str) and _KEY_ID_PATTERN.fullmatch(key_id)
            for key_id in correlation_key_ids
        )
        and len(set(correlation_key_ids)) == len(correlation_key_ids)
    ):
        return result
    correlation_ids = list(correlation_key_ids)

    credential_observed = parsed_booleans["credential_observed"]
    password_hash_present = parsed_booleans["password_hash_present"]
    hashing_enabled = parsed_booleans["hashing_enabled"]
    if (
        parsed_booleans["raw_password_stored"]
        or not parsed_booleans["raw_events_sanitized"]
    ):
        return result
    if algorithm == CREDENTIAL_HMAC_SCHEME:
        if (
            not hashing_enabled
            or not active_key_id
            or active_key_id in correlation_ids
            or password_hash_present is not credential_observed
            or alias_count != (len(correlation_ids) if password_hash_present else 0)
        ):
            return result
    elif (
        hashing_enabled
        or active_key_id
        or correlation_ids
        or alias_count
        or password_hash_present
    ):
        return result

    return {
        "schema_version": CREDENTIAL_METADATA_SCHEMA,
        "metadata_status": "available",
        **parsed_booleans,
        "password_hash_alias_count": alias_count,
        "hash_algorithm": algorithm,
        "active_key_id": active_key_id,
        "correlation_key_ids": correlation_ids,
    }


def validate_production_credential_policy(policy: Mapping[str, Any]) -> Dict[str, Any]:
    """Normalize and fail closed on unsafe derived-credential settings."""

    if not isinstance(policy, Mapping):
        raise CredentialHMACError("credential_policy must be an object")
    allowed_fields = {
        "store_raw_credentials",
        "redaction",
        "hash_algorithm",
        "hash_salt",
        "sanitize_raw_events",
        "redact_fields",
    }
    if set(policy) - allowed_fields:
        raise CredentialHMACError("credential_policy contains unsupported fields")

    store_raw = policy.get("store_raw_credentials", False)
    sanitize_raw = policy.get("sanitize_raw_events", True)
    algorithm = str(policy.get("hash_algorithm", CREDENTIAL_HMAC_SCHEME)).strip().lower()
    redaction = policy.get("redaction", "[REDACTED]")
    redact_fields = policy.get("redact_fields", ["password", "passwd"])

    if store_raw is not False:
        raise CredentialHMACError(
            "session workers must not store plaintext credentials in derived sessions"
        )
    if sanitize_raw is not True:
        raise CredentialHMACError("session workers must sanitize derived raw events")
    if algorithm != CREDENTIAL_HMAC_SCHEME:
        raise CredentialHMACError(
            f"credential hash_algorithm must be {CREDENTIAL_HMAC_SCHEME}"
        )
    if policy.get("hash_salt") not in (None, ""):
        raise CredentialHMACError("legacy credential hash_salt is not supported")
    if redaction != "[REDACTED]":
        raise CredentialHMACError(
            "credential redaction marker must be the canonical [REDACTED] value"
        )
    if (
        not isinstance(redact_fields, list)
        or not redact_fields
        or len(redact_fields) > 32
        or any(not isinstance(value, str) or not value for value in redact_fields)
    ):
        raise CredentialHMACError("credential redact_fields must be a bounded string list")
    normalized_fields = list(dict.fromkeys(redact_fields))
    if set(normalized_fields) != {"password", "passwd"}:
        raise CredentialHMACError(
            "credential redact_fields must contain only password and passwd"
        )

    return {
        "store_raw_credentials": False,
        "redaction": redaction,
        "hash_algorithm": CREDENTIAL_HMAC_SCHEME,
        "sanitize_raw_events": True,
        "redact_fields": normalized_fields,
    }
