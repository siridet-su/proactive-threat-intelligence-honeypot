#!/usr/bin/env python3
"""Build a reviewable, patched Cowrie source archive from an exact clean checkout."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE_REVISION = "575146bc6b24d70082527d66cd805d9bae0e0db4"
PATCH = ROOT / "integrations/cowrie/patches/0001-authoritative-cwd-telemetry.patch"


def git(checkout: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(checkout), *args],
        check=True,
        text=True,
        capture_output=True,
    ).stdout.strip()


def build(checkout: Path, output: Path) -> tuple[str, str]:
    if git(checkout, "rev-parse", "HEAD") != BASE_REVISION:
        raise ValueError(f"Cowrie checkout must be at {BASE_REVISION}")
    if git(checkout, "status", "--porcelain"):
        raise ValueError("Cowrie checkout must be clean")
    if output.exists():
        raise ValueError("output already exists; use a new reviewed archive path")

    with tempfile.TemporaryDirectory(prefix="pti-cowrie-") as temp:
        staging = Path(temp) / "cowrie"
        shutil.copytree(checkout, staging, symlinks=True, ignore=shutil.ignore_patterns(".git"))
        subprocess.run(["git", "-C", str(staging), "apply", "--check", str(PATCH)], check=True)
        subprocess.run(["git", "-C", str(staging), "apply", str(PATCH)], check=True)
        for cache in staging.rglob("__pycache__"):
            raise ValueError(f"unexpected generated directory: {cache.relative_to(staging)}")
        files = sorted(staging.rglob("*"))
        for path in files:
            if path.is_symlink() or not (path.is_file() or path.is_dir()):
                raise ValueError(f"unsupported source entry: {path.relative_to(staging)}")
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("wb") as target:
            with gzip.GzipFile(fileobj=target, mode="wb", filename="", compresslevel=9, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w") as archive:
                    for path in [staging, *files]:
                        name = Path("cowrie") / path.relative_to(staging)
                        info = archive.gettarinfo(str(path), arcname=str(name))
                        info.uid = info.gid = 0
                        info.uname = info.gname = ""
                        info.mtime = 0
                        if path.is_dir():
                            info.mode = 0o755
                            archive.addfile(info)
                        else:
                            info.mode = 0o755 if os.access(path, os.X_OK) else 0o644
                            with path.open("rb") as source:
                                archive.addfile(info, source)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    return digest, hashlib.sha256(PATCH.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    digest, patch_digest = build(args.checkout.resolve(), args.output.resolve())
    print(f"Cowrie base: {BASE_REVISION}")
    print(f"Patch SHA-256: {patch_digest}")
    print(f"Archive SHA-256: {digest}")


if __name__ == "__main__":
    main()
