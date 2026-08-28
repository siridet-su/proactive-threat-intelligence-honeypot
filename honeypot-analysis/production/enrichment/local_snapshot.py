"""Strict loader for optional operator-provided local enrichment context."""

from __future__ import annotations

import hashlib
import json
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from production.utils.serialization import stable_json


SCHEMA_VERSION = "local_enrichment_snapshot.v1"
REQUIRED_KEYS = {
    "schema_version",
    "dataset_id",
    "version",
    "generated_at",
    "expires_at",
    "records_sha256",
    "records",
}


def _timestamp(value: Any, field: str) -> datetime:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"local enrichment {field} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"local enrichment {field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def load_local_enrichment_snapshot(
    path_text: str,
    *,
    max_bytes: int,
    max_records: int,
    allow_stale: bool,
    now: datetime | None = None,
) -> Dict[str, Dict[str, Any]]:
    """Load a bounded, content-addressed snapshot or fail closed."""

    path = Path(path_text)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError("local enrichment snapshot is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(
            "local enrichment snapshot must be a regular non-symlink file"
        )
    if metadata.st_size < 2 or metadata.st_size > int(max_bytes):
        raise ValueError("local enrichment snapshot exceeds configured size bounds")
    try:
        raw = path.read_bytes()
        document = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("local enrichment snapshot is invalid JSON") from exc
    if not isinstance(document, dict) or set(document) != REQUIRED_KEYS:
        raise ValueError("local enrichment snapshot contract is invalid")
    if document["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"local enrichment schema must be {SCHEMA_VERSION}")
    for field in ("dataset_id", "version"):
        if not isinstance(document[field], str) or not document[field].strip():
            raise ValueError(f"local enrichment {field} must be non-empty")
    generated_at = _timestamp(document["generated_at"], "generated_at")
    expires_at = _timestamp(document["expires_at"], "expires_at")
    if expires_at <= generated_at:
        raise ValueError("local enrichment expires_at must follow generated_at")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if expires_at <= current and not allow_stale:
        raise ValueError("local enrichment snapshot is expired")

    records = document["records"]
    if not isinstance(records, dict) or len(records) > int(max_records):
        raise ValueError("local enrichment records exceed configured bounds")
    if any(
        not isinstance(key, str) or not key.strip() or not isinstance(value, dict)
        for key, value in records.items()
    ):
        raise ValueError("local enrichment records must map strings to objects")
    records_sha256 = hashlib.sha256(
        stable_json(records).encode("utf-8")
    ).hexdigest()
    if document["records_sha256"] != records_sha256:
        raise ValueError("local enrichment records SHA-256 mismatch")
    file_sha256 = hashlib.sha256(raw).hexdigest()
    provenance = {
        "schema_version": SCHEMA_VERSION,
        "dataset_id": document["dataset_id"],
        "version": document["version"],
        "generated_at": document["generated_at"],
        "expires_at": document["expires_at"],
        "records_sha256": records_sha256,
        "file_sha256": file_sha256,
        "status": "stale" if expires_at <= current else "fresh",
        "authority": "non_authoritative_context_only",
    }
    return {
        key: {**value, "_local_snapshot": dict(provenance)}
        for key, value in records.items()
    }
