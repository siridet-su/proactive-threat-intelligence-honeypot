"""Inspect durable job queues and manually retry one terminal job."""

from __future__ import annotations

import argparse
import json
from typing import Any, Optional, Sequence

from production.storage import open_storage
from production.storage.contract import JOB_QUEUE_TABLES
from production.utils.config import ProductionConfig


def execute(
    storage: Any,
    queue: str,
    *,
    retry_job_id: str = "",
) -> tuple[int, dict[str, Any]]:
    """Run one bounded queue operation and return a machine-readable result."""

    retried: Optional[bool] = None
    job_id = str(retry_job_id or "").strip()
    if job_id:
        retried = bool(storage.retry_failed_job(queue, job_id))
    payload = {
        "queue": queue,
        "retry_job_id": job_id or None,
        "retried": retried,
        "metrics": storage.job_queue_metrics(queue),
    }
    return (0 if retried is not False else 2), payload


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", help="Path to production JSON config.")
    parser.add_argument(
        "--queue",
        required=True,
        choices=tuple(JOB_QUEUE_TABLES),
        help="Durable queue to inspect.",
    )
    parser.add_argument(
        "--retry-job",
        default="",
        metavar="JOB_ID",
        help="Reset one terminal failed job for immediate retry.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    config = ProductionConfig.from_env(args.config)
    storage = open_storage(config.database_url)
    exit_code, payload = execute(
        storage,
        args.queue,
        retry_job_id=args.retry_job,
    )
    print(json.dumps(payload, sort_keys=True), flush=True)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
