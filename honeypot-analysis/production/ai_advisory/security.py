"""Security primitives for the optional hosted AI advisory boundary."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence
from urllib.parse import SplitResult, unquote, urlsplit

from production.prediction.evidence_cutoff import require_valid_evidence_cutoff
from production.utils.serialization import stable_json


ACTIVATION_KEYS = {
    "schema_version",
    "status",
    "provider_id",
    "model_id",
    "adapter_revision",
    "endpoint_sha256",
    "provider_adapter_reviewed",
    "managed_worker_unit",
    "worker_status",
    "credentials_status",
    "reconciliation_mode",
    "reconciliation_cutoff",
    "health_checked_at",
    "expires_at",
}


def _open_absolute_no_symlink(path: Path) -> int:
    if not path.is_absolute():
        raise ValueError("secure file path must be absolute")
    parts = path.parts
    directory_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in parts[1:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
        return os.open(
            parts[-1],
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
    finally:
        os.close(directory_fd)


def read_secure_file(
    path_text: str,
    *,
    name: str,
    max_bytes: int = 65_536,
    minimum_bytes: int = 1,
    expected_owner_uid: int | None = None,
) -> bytes:
    """Read an owner-only file through no-follow descriptors and one fstat."""

    path = Path(str(path_text or ""))
    try:
        descriptor = _open_absolute_no_symlink(path)
    except OSError as exc:
        raise ValueError(f"{name} is unavailable or traverses a symlink") from exc
    try:
        metadata = os.fstat(descriptor)
        expected_uid = os.geteuid() if expected_owner_uid is None else int(expected_owner_uid)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{name} must be a regular file")
        if metadata.st_uid != expected_uid:
            raise ValueError(f"{name} must be owned by the service user")
        if metadata.st_mode & 0o077:
            raise ValueError(f"{name} must not grant group or other permissions")
        if metadata.st_size < minimum_bytes or metadata.st_size > max_bytes:
            raise ValueError(f"{name} has an invalid size")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(remaining, 8192))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        value = b"".join(chunks)
        if len(value) < minimum_bytes or len(value) > max_bytes:
            raise ValueError(f"{name} has an invalid size")
        return value
    finally:
        os.close(descriptor)


def read_secure_utf8(path_text: str, *, name: str, max_bytes: int = 65_536) -> str:
    try:
        value = read_secure_file(path_text, name=name, max_bytes=max_bytes).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{name} must contain UTF-8") from exc
    value = value.strip()
    if not value:
        raise ValueError(f"{name} must not be empty")
    return value


def validate_https_endpoint(endpoint: str, allowed_hosts: Sequence[str]) -> SplitResult:
    """Parse one exact HTTPS endpoint suitable for a no-redirect transport."""

    text = str(endpoint or "").strip()
    if not text or len(text) > 2048 or any(ord(char) < 0x20 for char in text):
        raise ValueError("AI advisory endpoint is invalid")
    parsed = urlsplit(text)
    if parsed.scheme.lower() != "https" or not parsed.netloc or not parsed.hostname:
        raise ValueError("AI advisory endpoint must be an absolute HTTPS URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("AI advisory endpoint must not contain userinfo")
    if parsed.query or parsed.fragment:
        raise ValueError("AI advisory endpoint must not contain query or fragment data")
    if parsed.port not in (None, 443):
        raise ValueError("AI advisory endpoint must use the expected HTTPS port")
    decoded_path = unquote(parsed.path)
    path_parts = decoded_path.split("/")
    if (
        "\\" in decoded_path
        or decoded_path.startswith("//")
        or re.search(r"%(?![0-9A-Fa-f]{2})", parsed.path) is not None
        or any(ord(char) < 0x20 for char in decoded_path)
        or any(part in {".", ".."} for part in path_parts)
    ):
        raise ValueError("AI advisory endpoint path is unsafe")
    host = parsed.hostname.rstrip(".").lower()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("AI advisory endpoint must use an allowlisted DNS host")
    allowed = {str(item or "").strip().rstrip(".").lower() for item in allowed_hosts}
    if not allowed or host not in allowed:
        raise ValueError("AI advisory endpoint host is not allowlisted")
    return parsed


def endpoint_sha256(endpoint: str) -> str:
    return hashlib.sha256(str(endpoint or "").encode("utf-8")).hexdigest()


def validate_activation_receipt(
    path_text: str,
    *,
    provider_id: str,
    model_id: str,
    adapter_revision: str,
    endpoint: str,
    hosted: bool,
    reconciliation_cutoff: Mapping[str, Any],
    now: datetime | None = None,
) -> Dict[str, Any]:
    """Require a short-lived, owner-only deployment/health attestation."""

    try:
        receipt = json.loads(
            read_secure_utf8(
                path_text,
                name="AI_ADVISORY_ACTIVATION_RECEIPT",
                max_bytes=16_384,
            )
        )
    except json.JSONDecodeError as exc:
        raise ValueError("AI advisory activation receipt is not valid JSON") from exc
    if not isinstance(receipt, dict) or set(receipt) != ACTIVATION_KEYS:
        raise ValueError("AI advisory activation receipt has an invalid shape")
    cutoff = require_valid_evidence_cutoff(reconciliation_cutoff)
    expected = {
        "schema_version": "ai_advisory_activation_receipt.v1",
        "status": "ready",
        "provider_id": provider_id,
        "model_id": model_id,
        "adapter_revision": adapter_revision,
        "endpoint_sha256": endpoint_sha256(endpoint) if endpoint else "",
        "provider_adapter_reviewed": True,
        "managed_worker_unit": "honeypot-ai-advisory-worker.service",
        "worker_status": "ready",
        "credentials_status": "ready" if hosted else "not_required",
        "reconciliation_mode": "new_sessions_only",
        "reconciliation_cutoff": cutoff,
    }
    for key, value in expected.items():
        if receipt.get(key) != value:
            raise ValueError(f"AI advisory activation receipt mismatch: {key}")
    reference = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    try:
        checked = datetime.fromisoformat(str(receipt["health_checked_at"]).replace("Z", "+00:00"))
        expires = datetime.fromisoformat(str(receipt["expires_at"]).replace("Z", "+00:00"))
        if checked.tzinfo is None or expires.tzinfo is None:
            raise ValueError
        checked = checked.astimezone(timezone.utc)
        expires = expires.astimezone(timezone.utc)
    except (TypeError, ValueError) as exc:
        raise ValueError("AI advisory activation receipt timestamps are invalid") from exc
    if checked > reference or expires <= reference or expires <= checked:
        raise ValueError("AI advisory activation receipt is stale or not yet valid")
    if (expires - checked).total_seconds() > 3600:
        raise ValueError("AI advisory activation receipt validity exceeds one hour")
    return dict(receipt)


@dataclass
class ProviderAliasScope:
    """Provider-scoped opaque aliases with an in-memory exact reverse map."""

    key: bytes
    scope: str
    reverse: Dict[str, Dict[str, str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if len(self.key) < 32:
            raise ValueError("AI advisory alias key must contain at least 32 bytes")
        if not self.scope:
            raise ValueError("AI advisory alias scope is required")

    def digest(self, kind: str, value: Any, *, length: int = 64) -> str:
        canonical = str(value or "")
        if not canonical:
            return ""
        material = stable_json(
            {"schema_version": "ai_provider_alias.v1", "scope": self.scope, "kind": kind, "value": canonical}
        ).encode("utf-8")
        return hmac.new(self.key, material, hashlib.sha256).hexdigest()[:length]

    def alias(self, kind: str, value: Any) -> str:
        canonical = str(value or "")
        if not canonical:
            return ""
        alias = f"{kind}_{self.digest(kind, canonical, length=32)}"
        mapping = self.reverse.setdefault(kind, {})
        existing = mapping.get(alias)
        if existing is not None and existing != canonical:
            raise ValueError("AI advisory alias collision")
        mapping[alias] = canonical
        return alias

    def restore(self, kind: str, alias: Any) -> str:
        value = str(alias or "")
        if not value:
            return ""
        try:
            return self.reverse[kind][value]
        except KeyError as exc:
            raise ValueError("AI advisory alias is not mapped locally") from exc


def load_provider_alias_key(path_text: str) -> bytes:
    value = read_secure_file(
        path_text,
        name="AI_ADVISORY_ALIAS_KEY",
        max_bytes=4096,
        minimum_bytes=32,
    ).strip()
    if len(value) < 32:
        raise ValueError("AI advisory alias key must contain at least 32 bytes")
    return value
