"""Prepare an owner-reviewed patch-version receipt without changing its epoch.

This operator tool does not change a runtime guard, configuration, release
binding, MongoDB data or service. The approval reference is an audit reference,
not an authentication mechanism or permission to activate a prepared receipt.
"""

from __future__ import annotations

import argparse
import copy
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re

from production.storage.mongodb_epoch import load_storage_epoch
from production.tools.mongodb_epoch_receipt import finalize_epoch_receipt
from production.utils.serialization import stable_json, utc_now


SCHEMA = "storage_epoch_version_revision.v1"
RECEIPT_NAME = "canonical_storage_epoch.v2.json"
REVIEW_NAME = "REVIEWED_VERSION_REVISION.json"
CHANGED_FIELDS = ["deployment_identity.mongodb_server_version", "receipt_sha256"]
VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
SHA = re.compile(r"[0-9a-f]{64}")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _review_hash(review: dict) -> str:
    return _sha(stable_json({k: v for k, v in review.items()
                             if k != "review_sha256"}).encode())


def _source(path: Path, expected_sha256: str) -> tuple[bytes, dict]:
    if not SHA.fullmatch(expected_sha256):
        raise ValueError("source receipt requires an independently pinned SHA-256")
    # The canonical loader also enforces regular file, non-symlink, permissions
    # and every epoch/schema/mirror/provenance/content-addressed field.
    receipt = load_storage_epoch(path)
    data = path.read_bytes()
    if _sha(data) != expected_sha256:
        raise ValueError("source receipt SHA-256 mismatch")
    if json.loads(data) != receipt:
        raise ValueError("source receipt changed during read")
    return data, receipt


def _versions(old: str, new: str) -> None:
    before, after = VERSION.fullmatch(old), VERSION.fullmatch(new)
    if before is None or after is None:
        raise ValueError("reviewed versions must be exact numeric major.minor.patch")
    if before.group(1, 2) != after.group(1, 2):
        raise ValueError("this revision tool permits only same-major/minor patch changes")
    if int(after.group(3)) <= int(before.group(3)):
        raise ValueError("reviewed patch must be newer than the source receipt")


def _reference(value: str) -> None:
    if (not isinstance(value, str) or not value.strip() or len(value) > 255
            or any(ord(v) < 32 for v in value)):
        raise ValueError("approval reference must be a bounded single-line audit reference")


def _destination(directory: Path) -> None:
    if not directory.is_absolute():
        raise ValueError("revision directory must be absolute")
    for ancestor in (directory, *directory.parents):
        if ancestor.is_symlink():
            raise ValueError("revision directory must not traverse a symlink")
        metadata = ancestor / ".git"
        if metadata.is_file() or (metadata / "HEAD").is_file():
            raise ValueError("private receipts must stay outside Git checkouts")
    if directory.exists():
        raise FileExistsError("revision directory already exists")


def _same_epoch(source: dict, revised: dict, reviewed_version: str) -> None:
    expected = copy.deepcopy(source)
    expected["deployment_identity"]["mongodb_server_version"] = reviewed_version
    expected["receipt_sha256"] = revised["receipt_sha256"]
    if expected != revised:
        raise ValueError("revision changes fields beyond reviewed version and receipt hash")


def prepare_version_revision(
    *, source_path: Path, expected_source_sha256: str,
    expected_source_version: str, reviewed_version: str,
    approval_reference: str, output_dir: Path,
) -> dict:
    """Exclusively prepare a reviewed same-epoch receipt and an audit record."""
    source_data, source = _source(source_path, expected_source_sha256)
    if source["deployment_identity"]["mongodb_server_version"] != expected_source_version:
        raise ValueError("source receipt version does not match the reviewed predecessor")
    _versions(expected_source_version, reviewed_version)
    _reference(approval_reference)
    _destination(output_dir)
    candidate = copy.deepcopy(source)
    candidate["deployment_identity"]["mongodb_server_version"] = reviewed_version
    output_dir.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    output_dir.mkdir(mode=0o700)  # exclusive; retain failed preparation for inspection
    receipt_path = output_dir / RECEIPT_NAME
    revised = finalize_epoch_receipt(candidate, receipt_path)
    _same_epoch(source, revised, reviewed_version)
    if source_path.read_bytes() != source_data:
        raise ValueError("historical source receipt changed during preparation")
    review = {
        "schema_version": SCHEMA,
        "operation": "reviewed_same_epoch_server_patch_revision",
        "approval_reference": approval_reference,
        "prepared_at": utc_now(),
        "source_file_sha256": expected_source_sha256,
        "source_receipt_sha256": source["receipt_sha256"],
        "revised_file_sha256": _sha(receipt_path.read_bytes()),
        "revised_receipt_sha256": revised["receipt_sha256"],
        "source_server_version": expected_source_version,
        "reviewed_server_version": reviewed_version,
        "changed_fields": CHANGED_FIELDS,
        "runtime_guard_modified": False,
        "activated": False,
    }
    review["review_sha256"] = _review_hash(review)
    path = output_dir / REVIEW_NAME
    with path.open("xb") as stream:
        os.chmod(path, 0o600)
        stream.write((stable_json(review) + "\n").encode())
        stream.flush()
        os.fsync(stream.fileno())
    return verify_version_revision(
        source_path=source_path, expected_source_sha256=expected_source_sha256,
        expected_source_version=expected_source_version,
        reviewed_version=reviewed_version, output_dir=output_dir,
    )


def verify_version_revision(
    *, source_path: Path, expected_source_sha256: str,
    expected_source_version: str, reviewed_version: str, output_dir: Path,
) -> dict:
    _versions(expected_source_version, reviewed_version)
    _, source = _source(source_path, expected_source_sha256)
    if source["deployment_identity"]["mongodb_server_version"] != expected_source_version:
        raise ValueError("source receipt version does not match the reviewed predecessor")
    receipt_path = output_dir / RECEIPT_NAME
    revised = load_storage_epoch(receipt_path)
    _same_epoch(source, revised, reviewed_version)
    review_path = output_dir / REVIEW_NAME
    if review_path.is_symlink() or not review_path.is_file():
        raise ValueError("review must be a regular non-symlink file")
    if review_path.stat().st_mode & 0o022:
        raise ValueError("review permissions are unsafe")
    review = json.loads(review_path.read_text())
    expected = {
        "schema_version": SCHEMA,
        "operation": "reviewed_same_epoch_server_patch_revision",
        "source_file_sha256": expected_source_sha256,
        "source_receipt_sha256": source["receipt_sha256"],
        "revised_file_sha256": _sha(receipt_path.read_bytes()),
        "revised_receipt_sha256": revised["receipt_sha256"],
        "source_server_version": expected_source_version,
        "reviewed_server_version": reviewed_version,
        "changed_fields": CHANGED_FIELDS,
        "runtime_guard_modified": False,
        "activated": False,
    }
    if (not isinstance(review, dict)
            or set(review) != set(expected) | {"approval_reference", "prepared_at", "review_sha256"}
            or any(review.get(k) != v for k, v in expected.items())
            or review.get("runtime_guard_modified") is not False
            or review.get("activated") is not False
            or review["review_sha256"] != _review_hash(review)):
        raise ValueError("reviewed revision audit is inconsistent")
    _reference(review["approval_reference"])
    try:
        prepared = datetime.fromisoformat(review["prepared_at"].replace("Z", "+00:00"))
        if prepared.utcoffset() is None or prepared.utcoffset().total_seconds() != 0:
            raise ValueError("not UTC")
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("review preparation timestamp must be UTC") from exc
    return {
        "verified": True, "prepared_receipt": str(receipt_path),
        "source_version": expected_source_version, "reviewed_version": reviewed_version,
        "source_file_sha256": expected_source_sha256,
        "revised_file_sha256": review["revised_file_sha256"],
        "revised_receipt_sha256": revised["receipt_sha256"],
        "review_sha256": review["review_sha256"],
        "epoch_identity_preserved": True, "runtime_guard_modified": False,
        "activated": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "verify"))
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--source-version", required=True)
    parser.add_argument("--reviewed-version", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--approval-reference")
    args = parser.parse_args()
    kwargs = {
        "source_path": args.source, "expected_source_sha256": args.source_sha256,
        "expected_source_version": args.source_version,
        "reviewed_version": args.reviewed_version, "output_dir": args.output_dir,
    }
    if args.operation == "prepare":
        if not args.approval_reference:
            parser.error("prepare requires --approval-reference")
        result = prepare_version_revision(**kwargs, approval_reference=args.approval_reference)
    else:
        result = verify_version_revision(**kwargs)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
