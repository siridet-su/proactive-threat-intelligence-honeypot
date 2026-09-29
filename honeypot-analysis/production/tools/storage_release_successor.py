"""Issue an exact, root-owned successor receipt after privileged release verification.

The canonical MongoDB epoch receipt is an immutable cutover record. This tool
binds a later source release to it without rewriting that historical receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from production.storage.mongodb_epoch import load_storage_epoch
from production.tools.release_manifest import verify_manifest
from production.utils.serialization import stable_json


def issue_successor_receipt(
    *, epoch_path: Path, release_root: Path, output_dir: Path
) -> Path:
    if os.geteuid() != 0:
        raise PermissionError("successor receipt issuance requires root")
    epoch = load_storage_epoch(epoch_path)
    root = release_root.resolve(strict=True)
    manifest_path = root / "DEPLOYMENT_MANIFEST.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("candidate release manifest is missing")
    verified = verify_manifest(manifest_path, root)
    if not verified["verified"]:
        raise ValueError("candidate release manifest did not verify")
    release_sha = verified["git_revision"]
    receipt = {
        "schema_version": "storage_release_successor.v1",
        "epoch_receipt_sha256": epoch["receipt_sha256"],
        "release_sha": release_sha,
        "release_tree_sha256": verified["release_tree_sha256"],
        "release_manifest_sha256": verified["manifest_sha256"],
    }
    receipt["receipt_sha256"] = hashlib.sha256(stable_json(receipt).encode("utf-8")).hexdigest()
    directory = output_dir.resolve(strict=True)
    directory_info = directory.stat()
    if directory_info.st_uid != 0 or directory_info.st_mode & 0o022:
        raise ValueError("successor receipt directory has unsafe ownership or mode")
    output = directory / f"{release_sha}.json"
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        os.write(descriptor, (stable_json(receipt) + "\n").encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--epoch", type=Path, required=True)
    parser.add_argument("--release-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    output = issue_successor_receipt(
        epoch_path=args.epoch, release_root=args.release_root, output_dir=args.output_dir
    )
    print(json.dumps({"receipt_path": str(output), "issued": True}, sort_keys=True))


if __name__ == "__main__":
    main()
