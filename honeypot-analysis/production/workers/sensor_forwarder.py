"""Raspberry Pi Cowrie log forwarder with a local disk spool."""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

if __package__ == "production":
    # The Pi uses a minimal flat package containing only this module and its
    # config/serialization dependencies.
    from .config import ProductionConfig
    from .serialization import utc_now
else:
    from production.utils.config import ProductionConfig
    from production.utils.serialization import utc_now


@dataclass
class ForwardResult:
    sent: int
    remaining: int
    duplicates: int = 0
    rejected: int = 0
    error: str = ""


class CowrieLogTailer:
    """Tails Cowrie's NDJSON log using a persistent byte offset."""

    def __init__(self, log_path: str, offset_path: str) -> None:
        self.log_path = Path(log_path)
        self.offset_path = Path(offset_path)

    def _load_offset(self) -> int:
        try:
            return int(self.offset_path.read_text(encoding="utf-8").strip() or "0")
        except (OSError, ValueError):
            return 0

    def _save_offset(self, offset: int) -> None:
        self.offset_path.parent.mkdir(parents=True, exist_ok=True)
        self.offset_path.write_text(str(offset), encoding="utf-8")

    def read_new_events(self) -> Tuple[List[Dict[str, Any]], int]:
        if not self.log_path.exists():
            return [], self._load_offset()

        offset = self._load_offset()
        size = self.log_path.stat().st_size
        if offset > size:
            offset = 0

        events: List[Dict[str, Any]] = []
        with self.log_path.open("rb") as handle:
            handle.seek(offset)
            for raw_line in handle:
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    event = {
                        "eventid": "forwarder.parse_error",
                        "timestamp": utc_now(),
                        "raw_line": line,
                    }
                events.append(event)
            new_offset = handle.tell()

        if new_offset != offset:
            self._save_offset(new_offset)
        return events, new_offset


class DiskSpool:
    """Small durable NDJSON queue for outbound-only sensors."""

    def __init__(self, path: str) -> None:
        self.path = Path(path)

    def append_many(self, events: Iterable[Dict[str, Any]]) -> int:
        materialized = list(events)
        if not materialized:
            return 0
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            for event in materialized:
                handle.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
        return len(materialized)

    def load_batch(self, limit: int) -> Tuple[List[Dict[str, Any]], List[str]]:
        if not self.path.exists():
            return [], []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        batch_lines = lines[:limit]
        remaining = lines[limit:]
        events: List[Dict[str, Any]] = []
        for line in batch_lines:
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                events.append(
                    {
                        "eventid": "forwarder.spool_parse_error",
                        "timestamp": utc_now(),
                        "raw_line": line,
                    }
                )
        return events, remaining

    def replace_remaining(self, remaining_lines: List[str]) -> None:
        if remaining_lines:
            self.path.write_text("\n".join(remaining_lines) + "\n", encoding="utf-8")
        elif self.path.exists():
            self.path.unlink()

    def count(self) -> int:
        if not self.path.exists():
            return 0
        return sum(1 for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip())


def post_events(config: ProductionConfig, events: List[Dict[str, Any]]) -> Dict[str, Any]:
    payload = {"sensor_id": config.sensor_id, "events": events}
    request = urllib.request.Request(
        config.ingest_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {config.api_token}",
            "Content-Type": "application/json",
            "X-Sensor-ID": config.sensor_id,
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=config.forwarder_timeout_seconds) as response:
        return json.loads(response.read().decode("utf-8"))


def forward_once(config: ProductionConfig) -> ForwardResult:
    tailer = CowrieLogTailer(config.cowrie_log_path, f"{config.spool_path}.offset")
    spool = DiskSpool(config.spool_path)
    new_events, _ = tailer.read_new_events()
    spool.append_many(new_events)

    events, remaining_lines = spool.load_batch(config.forwarder_batch_size)
    if not events:
        return ForwardResult(sent=0, remaining=0)

    try:
        response = post_events(config, events)
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        return ForwardResult(sent=0, remaining=spool.count(), error=str(exc))

    try:
        accepted = max(int(response.get("accepted", len(events))), 0)
        duplicates = max(int(response.get("duplicates", 0)), 0)
    except (TypeError, ValueError):
        return ForwardResult(
            sent=0,
            remaining=spool.count(),
            error="ingest returned invalid acknowledgement counts",
        )

    rejected_items = response.get("rejected", [])
    if not isinstance(rejected_items, list):
        return ForwardResult(
            sent=accepted,
            duplicates=duplicates,
            remaining=spool.count(),
            error="ingest returned an invalid rejected-event list",
        )

    rejected_count = len(rejected_items)
    accounted = accepted + duplicates + rejected_count
    if accounted != len(events):
        return ForwardResult(
            sent=accepted,
            duplicates=duplicates,
            rejected=rejected_count,
            remaining=spool.count(),
            error=(
                "ingest acknowledgement mismatch: "
                f"batch={len(events)} accepted={accepted} duplicates={duplicates} "
                f"rejected={rejected_count}"
            ),
        )

    if not rejected_items:
        spool.replace_remaining(remaining_lines)
    else:
        rejected_indexes: List[int] = []
        for item in rejected_items:
            if not isinstance(item, dict) or not isinstance(item.get("index"), int):
                return ForwardResult(
                    sent=accepted,
                    duplicates=duplicates,
                    rejected=rejected_count,
                    remaining=spool.count(),
                    error="ingest rejected events without usable batch indexes",
                )
            index = int(item["index"])
            if index < 0 or index >= len(events) or index in rejected_indexes:
                return ForwardResult(
                    sent=accepted,
                    duplicates=duplicates,
                    rejected=rejected_count,
                    remaining=spool.count(),
                    error="ingest returned invalid or duplicate rejected-event indexes",
                )
            rejected_indexes.append(index)

        rejected_events = [events[index] for index in sorted(rejected_indexes)]
        rewritten = [json.dumps(event, sort_keys=True, separators=(",", ":")) for event in rejected_events]
        rewritten.extend(remaining_lines)
        spool.replace_remaining(rewritten)
    return ForwardResult(
        sent=accepted,
        duplicates=duplicates,
        rejected=rejected_count,
        remaining=spool.count(),
        error=(f"{rejected_count} event(s) rejected by ingest and retained" if rejected_count else ""),
    )


def run_forever(config: ProductionConfig) -> None:
    while True:
        result = forward_once(config)
        print(
            json.dumps(
                {
                    "service": "sensor_forwarder",
                    "sent": result.sent,
                    "duplicates": result.duplicates,
                    "rejected": result.rejected,
                    "remaining": result.remaining,
                    "error": result.error,
                    "timestamp": utc_now(),
                },
                sort_keys=True,
            ),
            flush=True,
        )
        time.sleep(config.forwarder_poll_seconds)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Forward Cowrie NDJSON events to the cloud ingest API.")
    parser.add_argument("--config", help="Path to production JSON config.")
    parser.add_argument("--once", action="store_true", help="Run one poll/flush cycle and exit.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    config = ProductionConfig.from_env(args.config)
    if not config.api_token:
        raise SystemExit("HONEYPOT_API_TOKEN or api_token is required for sensor forwarding.")
    if args.once:
        result = forward_once(config)
        print(json.dumps(result.__dict__, sort_keys=True))
        return 0 if not result.error else 1
    run_forever(config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
