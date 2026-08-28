"""Validate a Threat Hypothesis behavior policy file."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List, Optional

from production.policies.threat_hypothesis_behavior_policy import validate_behavior_policy


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True, help="Path to behavior-policy JSON.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    document = json.loads(Path(args.policy).read_text(encoding="utf-8"))
    errors = validate_behavior_policy(document)
    if args.json:
        print(json.dumps({"ok": not errors, "errors": errors}, indent=2, sort_keys=True))
    elif errors:
        print("Threat Hypothesis behavior policy validation failed:")
        for error in errors:
            print(f"- {error}")
    else:
        print("Threat Hypothesis behavior policy validation passed.")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
