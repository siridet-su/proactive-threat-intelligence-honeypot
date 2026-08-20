"""Validate the explicitly offline prediction ATT&CK Transformer PoC policy."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from production.prediction.prediction_attck_label_poc_v3 import (
    POLICY_PATH,
    load_prediction_attck_label_poc_policy,
    validate_prediction_attck_label_poc_freeze_receipt,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", default=None)
    parser.add_argument("--policy", default=POLICY_PATH)
    parser.add_argument(
        "--skip-external-receipts",
        action="store_true",
        help="validate structure and repository lineage without reading /mnt receipts",
    )
    parser.add_argument("--freeze-receipt", default=None)
    args = parser.parse_args(argv)
    root = Path(args.repository_root or Path(__file__).resolve().parents[2])
    policy_path = Path(args.policy)
    if not policy_path.is_absolute():
        policy_path = root / policy_path
    try:
        load_prediction_attck_label_poc_policy(
            policy_path,
            verify_external_receipts=not args.skip_external_receipts,
        )
    except Exception as exc:  # noqa: BLE001 - CLI is a fail-closed validator.
        print(f"ERROR: {exc}")
        return 1
    if args.freeze_receipt:
        receipt_path = Path(args.freeze_receipt)
        if not receipt_path.is_absolute():
            receipt_path = root / receipt_path
        try:
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            print(f"ERROR: freeze receipt cannot be loaded: {exc}")
            return 1
        errors = validate_prediction_attck_label_poc_freeze_receipt(
            receipt, repository_root=root
        )
        if errors:
            for error in errors:
                print(f"ERROR: {error}")
            return 1
    print("prediction ATT&CK experimental PoC policy v3 validation passed")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
