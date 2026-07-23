#!/usr/bin/env python3
"""Build a next-behavior split manifest from privacy-safe records.

The tool never reads raw Cowrie commands and refuses to overwrite an existing
manifest. V1 remains the default; v2 is an explicit additive protocol. Private
partition payloads remain outside the repository.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Sequence

from production.prediction.next_behavior_partitions import (
    build_partition_manifest,
    build_partition_manifest_v2,
    require_historical_membership_independence,
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_object_array(path: Path, *, label: str) -> List[Dict[str, Any]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"{label} must be a JSON array of objects")
    return value


def _load_string_array(path: Path, *, label: str) -> List[str]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{label} must be a JSON array of strings")
    return value


def _load_object(path: Path, *, label: str) -> Dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _atomic_create_json(path: Path, value: Any) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite existing manifest: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--protocol-version",
        choices=("v1", "v2"),
        default="v1",
    )
    parser.add_argument("--sessions", type=Path, required=True)
    parser.add_argument("--source-members", type=Path, required=True)
    parser.add_argument("--historical-session-ids", type=Path)
    parser.add_argument("--historical-split-evidence", type=Path)
    parser.add_argument("--development-cutoff")
    parser.add_argument("--final-window-start")
    parser.add_argument("--corpus-receipt", type=Path)
    parser.add_argument("--build-receipt", type=Path)
    parser.add_argument("--preprocessing-config", type=Path, required=True)
    parser.add_argument("--label-policy", type=Path, required=True)
    parser.add_argument("--trust-policy", type=Path, required=True)
    parser.add_argument("--code-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if bool(args.corpus_receipt) != bool(args.build_receipt):
        raise ValueError(
            "--corpus-receipt and --build-receipt must be supplied together"
        )
    if args.protocol_version == "v2" and (
        args.corpus_receipt or args.build_receipt
    ):
        raise ValueError(
            "v1 aggregate corpus/build receipts cannot prove the role-aware "
            "v2 historical policy"
        )
    if args.protocol_version == "v1" and args.corpus_receipt and args.build_receipt:
        require_historical_membership_independence(
            _load_object(args.build_receipt, label="build receipt"),
            _load_object(args.corpus_receipt, label="corpus receipt"),
        )
    sessions = _load_object_array(args.sessions, label="sessions")
    source_members = _load_object_array(
        args.source_members,
        label="source members",
    )
    common = {
        "preprocessing_sha256": _sha256_file(args.preprocessing_config),
        "label_policy_sha256": _sha256_file(args.label_policy),
        "trust_policy_sha256": _sha256_file(args.trust_policy),
        "code_commit": args.code_commit,
    }
    if args.protocol_version == "v1":
        if args.historical_session_ids is None:
            raise ValueError("--historical-session-ids is required for v1")
        if (
            args.historical_split_evidence is not None
            or args.development_cutoff is not None
            or args.final_window_start is not None
        ):
            raise ValueError("v2 partition arguments are not valid for v1")
        manifest = build_partition_manifest(
            sessions,
            source_members,
            **common,
            forbidden_historical_session_ids=_load_string_array(
                args.historical_session_ids,
                label="historical session IDs",
            ),
        )
    else:
        if args.historical_session_ids is not None:
            raise ValueError("--historical-session-ids is only valid for v1")
        if args.historical_split_evidence is None:
            raise ValueError("--historical-split-evidence is required for v2")
        if args.development_cutoff is None:
            raise ValueError("--development-cutoff is required for v2")
        if args.final_window_start is None:
            raise ValueError("--final-window-start is required for v2")
        manifest = build_partition_manifest_v2(
            sessions,
            source_members,
            **common,
            historical_split_by_session=_load_object(
                args.historical_split_evidence,
                label="historical split evidence",
            ),
            development_cutoff=args.development_cutoff,
            final_window_start=args.final_window_start,
        )
    _atomic_create_json(args.output, manifest)
    print(
        json.dumps(
            {
                "manifest_id": manifest["manifest_id"],
                "output": str(args.output),
                "status": manifest["status"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
