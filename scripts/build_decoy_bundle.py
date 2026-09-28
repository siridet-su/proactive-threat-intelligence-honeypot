#!/usr/bin/env python3
"""Package reviewed Docker decoy source from one clean Git commit."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import subprocess
import tarfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    "deploy/decoy-honeypot/compose.yaml",
    "deploy/decoy-honeypot/compose.public-web.yaml",
    "integrations/deception-core",
    "integrations/web-corp",
)


def git(*args: str) -> bytes:
    return subprocess.check_output(("git", "-C", str(ROOT), *args))


def build(output: Path) -> tuple[str, str]:
    if output.exists():
        raise ValueError("output already exists; refusing to overwrite a reviewed bundle")
    commit = git("rev-parse", "HEAD").decode().strip()
    if len(commit) != 40:
        raise ValueError("could not resolve a full Git commit")
    tracked = git("status", "--porcelain", "--", *SOURCES)
    if tracked:
        raise ValueError("decoy sources are dirty; commit them before bundling")
    archive = git("archive", "--format=tar", commit, *SOURCES)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as members:
        for member in members:
            if not (member.isfile() or member.isdir()):
                raise ValueError("decoy source contains a non-regular archive member")
            if member.name.startswith("/") or ".." in Path(member.name).parts:
                raise ValueError("decoy source contains an unsafe archive path")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as zipped:
            zipped.write(archive)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    return commit, digest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        commit, digest = build(args.output)
    except (OSError, subprocess.CalledProcessError, ValueError) as exc:
        parser.exit(2, f"decoy bundle rejected: {exc}\n")
    print(f"git_commit={commit}")
    print(f"sha256={digest}")
    print(f"bundle={args.output.resolve()}")


if __name__ == "__main__":
    main()
