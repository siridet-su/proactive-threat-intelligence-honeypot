"""Finalize and verify a deployment-supplied canonical MongoDB epoch receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict

from production.storage.mongodb_epoch import load_storage_epoch
from production.storage.rollback_mirror_identity import prepare_rollback_mirror
from production.utils.serialization import stable_json


def finalize_epoch_receipt(candidate: Dict[str, Any], output: str | Path) -> Dict[str, Any]:
    if not isinstance(candidate, dict):
        raise ValueError("storage epoch candidate must be an object")
    document = dict(candidate)
    document["receipt_sha256"] = hashlib.sha256(
        stable_json({key: value for key, value in document.items() if key != "receipt_sha256"}).encode("utf-8")
    ).hexdigest()
    selected = Path(output)
    selected.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(selected, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, (stable_json(document) + "\n").encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        verified = load_storage_epoch(selected)
    except Exception:
        selected.unlink(missing_ok=True)
        raise
    return verified


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate")
    parser.add_argument("--output")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--prepare-mirror")
    parser.add_argument("--epoch-id")
    parser.add_argument("--release-sha")
    parser.add_argument("--release-tree")
    args = parser.parse_args()
    if args.prepare_mirror:
        if not all((args.epoch_id, args.release_sha, args.release_tree, args.output)):
            parser.error("--prepare-mirror requires --epoch-id, --release-sha, --release-tree, and --output")
        selected = Path(args.output)
        if selected.exists() or selected.is_symlink():
            raise FileExistsError(selected)
        mirror_path = Path(args.prepare_mirror)
        if mirror_path.exists() or mirror_path.is_symlink():
            raise FileExistsError(mirror_path)
        selected.parent.mkdir(parents=True, exist_ok=True)
        try:
            identity = prepare_rollback_mirror(
                args.prepare_mirror,
                epoch_id=args.epoch_id,
                reviewed_release_sha=args.release_sha,
                reviewed_release_tree=args.release_tree,
            )
            descriptor = os.open(selected, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(descriptor, (stable_json(identity) + "\n").encode("utf-8"))
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except Exception:
            selected.unlink(missing_ok=True)
            for suffix in ("", "-wal", "-shm", "-journal"):
                Path(f"{args.prepare_mirror}{suffix}").unlink(missing_ok=True)
            raise
        print(identity["identity_id"])
    elif args.verify:
        if not args.candidate:
            parser.error("--candidate is required with --verify")
        receipt = load_storage_epoch(args.candidate)
    else:
        if not args.candidate or not args.output:
            parser.error("--candidate and --output are required")
        candidate = json.loads(Path(args.candidate).read_text(encoding="utf-8"))
        receipt = finalize_epoch_receipt(candidate, args.output)
    if not args.prepare_mirror:
        print(receipt["receipt_sha256"])


if __name__ == "__main__":
    main()
