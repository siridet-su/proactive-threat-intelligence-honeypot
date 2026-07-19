"""Audit or explicitly apply the prediction snapshot retention policy.

The realtime engine stores one snapshot per processed event so analysts can
debug how a live prediction changed over time. This command keeps that useful
history bounded: old intermediate snapshots are deleted, while feedback-linked
snapshots and the latest snapshot per session can be preserved.
"""

from __future__ import annotations

import argparse
import json
from typing import List

from production.utils.config import ProductionConfig
from production.storage import open_storage
from production.utils.sensitive_data import redact_exception_for_log


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Prune old realtime prediction snapshots.")
    parser.add_argument("--config", help="Path to production JSON config.")
    parser.add_argument("--database-url", help="Override DATABASE_URL.")
    parser.add_argument("--retention-days", type=int, help="Days of full snapshot history to keep.")
    parser.add_argument("--now", help=argparse.SUPPRESS)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Delete eligible snapshots. Omit this flag for a no-write dry run.",
    )
    parser.add_argument(
        "--delete-latest-per-session",
        action="store_true",
        help="Allow deleting old latest-per-session snapshots. By default they are preserved.",
    )
    return parser


def main(argv: List[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    config = ProductionConfig.from_env(args.config)
    if args.database_url:
        config.database_url = args.database_url
    retention_days = (
        int(args.retention_days)
        if args.retention_days is not None
        else int(config.prediction_snapshot_retention_days)
    )
    keep_latest = (
        False
        if args.delete_latest_per_session
        else bool(config.prediction_snapshot_keep_latest_per_session)
    )
    try:
        storage = open_storage(config.database_url)
        storage.initialize()
        result = storage.prune_prediction_snapshots(
            retention_days=retention_days,
            keep_latest_per_session=keep_latest,
            now=args.now,
            dry_run=not args.apply,
        )
        output = {
            "schema_version": "prediction_snapshot_retention.v2",
            "scope": "prediction_snapshots",
            "reference_policy": {
                "analyst_feedback": "always_preserve",
                "latest_per_session": "preserve" if keep_latest else "eligible_by_age",
            },
            **result,
        }
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0
    except Exception as exc:
        print(
            json.dumps(
                {
                    "schema_version": "prediction_snapshot_retention.v2",
                    "status": "failed",
                    "dry_run": not args.apply,
                    "error": redact_exception_for_log(exc),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
