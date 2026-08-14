#!/usr/bin/env python3
"""Run the fail-closed static next-behavior preparation preflight."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Sequence

from production.reproduction.next_behavior.preparation_preflight import (
    NextBehaviorPreparationPreflightError,
    load_preflight_request,
    run_static_preflight,
)
from production.utils.serialization import stable_json


def _write_new_file(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        encoded = (stable_json(value) + "\n").encode("utf-8")
        os.write(descriptor, encoded)
        os.fsync(descriptor)
    except OSError as exc:
        raise NextBehaviorPreparationPreflightError(
            "preflight receipt output must be a new writable file"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify static provenance, policy, frozen-input, runtime, and capacity "
            "requirements without opening a corpus database or source archive."
        )
    )
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        request = load_preflight_request(args.request)
        receipt = run_static_preflight(
            request,
            repository_root=args.repository_root,
        )
        if args.output is None:
            print(stable_json(receipt))
        else:
            workspace = Path(str(request["output_workspace"])).resolve()
            output = args.output.resolve()
            try:
                output.relative_to(workspace)
            except ValueError as exc:
                raise NextBehaviorPreparationPreflightError(
                    "receipt output must be inside output_workspace"
                ) from exc
            _write_new_file(output, receipt)
            print(
                json.dumps(
                    {
                        "status": receipt["status"],
                        "receipt_sha256": receipt["receipt_sha256"],
                        "output": str(output),
                    },
                    sort_keys=True,
                )
            )
    except NextBehaviorPreparationPreflightError as exc:
        print(f"static preflight failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
