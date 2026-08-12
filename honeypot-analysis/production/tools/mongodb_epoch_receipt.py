"""Finalize and verify a deployment-supplied canonical MongoDB epoch receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict

from production.storage.mongodb_epoch import load_storage_epoch
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
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--output")
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    if args.verify:
        receipt = load_storage_epoch(args.candidate)
    else:
        if not args.output:
            parser.error("--output is required unless --verify is used")
        candidate = json.loads(Path(args.candidate).read_text(encoding="utf-8"))
        receipt = finalize_epoch_receipt(candidate, args.output)
    print(receipt["receipt_sha256"])


if __name__ == "__main__":
    main()
