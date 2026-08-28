"""Content-addressed receipt for offline SQLite/MongoDB parity cases."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable

from production.utils.serialization import stable_id, stable_json


PARITY_RECEIPT_SCHEMA = "sqlite_mongodb_parity_receipt.v1"


def build_parity_receipt(
    cases: Iterable[Dict[str, Any]],
    *,
    source_revision: str,
    mongodb_version: str,
    manifest_sha256: str,
) -> Dict[str, Any]:
    normalized = []
    for case in cases:
        if set(case) != {"case_id", "sqlite_sha256", "mongodb_sha256", "matched"}:
            raise ValueError("parity case has invalid fields")
        item = {
            "case_id": str(case["case_id"]),
            "sqlite_sha256": str(case["sqlite_sha256"]),
            "mongodb_sha256": str(case["mongodb_sha256"]),
            "matched": bool(case["matched"]),
        }
        if item["matched"] != (item["sqlite_sha256"] == item["mongodb_sha256"]):
            raise ValueError("parity result is self-inconsistent")
        normalized.append(item)
    normalized.sort(key=lambda item: item["case_id"])
    if len({item["case_id"] for item in normalized}) != len(normalized):
        raise ValueError("parity case identifiers must be unique")
    basis = {
        "schema_version": PARITY_RECEIPT_SCHEMA,
        "source_revision": str(source_revision),
        "mongodb_version": str(mongodb_version),
        "manifest_sha256": str(manifest_sha256),
        "case_count": len(normalized),
        "all_matched": all(item["matched"] for item in normalized),
        "cases": normalized,
    }
    return {**basis, "receipt_id": stable_id("mongodbparity", basis)}


def write_parity_receipt(path: str | Path, receipt: Dict[str, Any]) -> str:
    destination = Path(path)
    if destination.exists():
        raise FileExistsError("parity receipt destination already exists")
    encoded = (stable_json(receipt) + "\n").encode()
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return hashlib.sha256(encoded).hexdigest()


def verify_parity_receipt(path: str | Path) -> Dict[str, Any]:
    selected = Path(path)
    if selected.is_symlink() or not selected.is_file():
        raise ValueError("parity receipt must be a regular non-symlink file")
    if selected.stat().st_mode & 0o077:
        raise ValueError("parity receipt permissions are unsafe")
    try:
        document = json.loads(selected.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("parity receipt is unreadable") from exc
    rebuilt = build_parity_receipt(
        document.get("cases", []),
        source_revision=str(document.get("source_revision") or ""),
        mongodb_version=str(document.get("mongodb_version") or ""),
        manifest_sha256=str(document.get("manifest_sha256") or ""),
    )
    if rebuilt != document or not rebuilt["all_matched"]:
        raise ValueError("parity receipt failed closed verification")
    return rebuilt
