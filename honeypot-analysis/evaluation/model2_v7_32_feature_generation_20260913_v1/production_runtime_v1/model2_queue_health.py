#!/usr/bin/env python3
"""Read-only health probe for the Pi Model2 observer's durable outbound queue.

This probe deliberately does not open queued envelopes: they can contain
session evidence. A running systemd service is not proof of delivery, so the
oldest queued item's age is part of the health contract.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import time
from typing import Any


def inspect_queue(
    state_dir: pathlib.Path,
    *,
    now: float | None = None,
    stall_seconds: float = 120.0,
    max_queue_files: int = 512,
) -> dict[str, Any]:
    if stall_seconds <= 0 or max_queue_files <= 0:
        raise ValueError("health_threshold_invalid")
    queue = state_dir / "queue"
    if not queue.is_dir():
        return {"status": "UNAVAILABLE", "reason": "queue_directory_missing", "queued": 0}

    oldest: float | None = None
    queued = 0
    for path in queue.glob("*.json"):
        try:
            modified = path.stat().st_mtime
        except OSError:
            return {"status": "UNAVAILABLE", "reason": "queue_stat_failed", "queued": queued}
        queued += 1
        oldest = modified if oldest is None else min(oldest, modified)

    age = max(0.0, (time.time() if now is None else now) - oldest) if oldest is not None else 0.0
    if queued >= max_queue_files:
        status, reason = "CRITICAL", "queue_capacity_reached"
    elif queued and age >= stall_seconds:
        status, reason = "CRITICAL", "delivery_stalled"
    elif queued:
        status, reason = "PENDING", "awaiting_delivery"
    else:
        status, reason = "OK", "queue_empty"
    return {
        "status": status,
        "reason": reason,
        "queued": queued,
        "oldest_age_seconds": round(age, 1),
        "max_queue_files": max_queue_files,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=pathlib.Path, required=True)
    parser.add_argument("--stall-seconds", type=float, default=120.0)
    args = parser.parse_args()
    try:
        config = json.loads(args.config.read_text(encoding="utf-8"))
        if not isinstance(config, dict):
            raise ValueError("config_not_object")
        report = inspect_queue(
            pathlib.Path(str(config["state_dir"])),
            stall_seconds=args.stall_seconds,
            max_queue_files=int(config.get("max_queue_files", 512)),
        )
    except (OSError, KeyError, ValueError, TypeError, json.JSONDecodeError):
        report = {"status": "UNAVAILABLE", "reason": "health_config_unavailable", "queued": 0}
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["status"] in {"OK", "PENDING"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
