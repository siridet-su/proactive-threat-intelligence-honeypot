"""HTTP ingest API for Cowrie sensor events."""

from __future__ import annotations

import argparse
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple

from production.utils.config import ProductionConfig
from production.utils.serialization import utc_now
from production.storage import open_storage


def validate_event(event: Dict[str, Any]) -> Tuple[bool, str]:
    if not isinstance(event, dict):
        return False, "event must be an object"
    if not event.get("eventid"):
        return False, "eventid is required"
    return True, ""


def parse_events(payload: Any, default_sensor_id: str) -> Tuple[str, List[Dict[str, Any]]]:
    if isinstance(payload, list):
        return default_sensor_id, payload
    if isinstance(payload, dict):
        sensor_id = str(payload.get("sensor_id") or default_sensor_id)
        events = payload.get("events", payload.get("event"))
        if isinstance(events, dict):
            return sensor_id, [events]
        if isinstance(events, list):
            return sensor_id, events
    raise ValueError("expected a JSON event object, event list, or {'sensor_id','events'} payload")


class IngestHandler(BaseHTTPRequestHandler):
    config: ProductionConfig

    def _send_json(self, status: HTTPStatus, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        expected = self.config.api_token
        if not expected:
            return True
        return self.headers.get("Authorization", "") == f"Bearer {expected}"

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send_json(HTTPStatus.OK, {"ok": True, "service": "ingest_api", "timestamp": utc_now()})
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path.rstrip("/") != "/events":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        if not self._authorized():
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            sensor_id, events = parse_events(payload, self.headers.get("X-Sensor-ID", self.config.sensor_id))
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        storage = open_storage(self.config.database_url)
        accepted = 0
        duplicates = 0
        rejected: List[Dict[str, Any]] = []
        for index, event in enumerate(events):
            valid, error = validate_event(event)
            if not valid:
                rejected.append({"index": index, "error": error, "event": event})
                continue
            _, inserted = storage.store_event(sensor_id, event)
            if inserted:
                accepted += 1
            else:
                duplicates += 1

        self._send_json(
            HTTPStatus.ACCEPTED,
            {
                "accepted": accepted,
                "duplicates": duplicates,
                "rejected": rejected,
                "sensor_id": sensor_id,
                "timestamp": utc_now(),
            },
        )

    def log_message(self, fmt: str, *args: Any) -> None:
        print(
            json.dumps(
                {
                    "service": "ingest_api",
                    "client": self.address_string(),
                    "message": fmt % args,
                    "timestamp": utc_now(),
                },
                sort_keys=True,
            ),
            flush=True,
        )


def build_server(config: ProductionConfig) -> ThreadingHTTPServer:
    IngestHandler.config = config
    return ThreadingHTTPServer((config.ingest_host, config.ingest_port), IngestHandler)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the Cowrie event ingest API.")
    parser.add_argument("--config", help="Path to production JSON config.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    config = ProductionConfig.from_env(args.config)
    storage = open_storage(config.database_url)
    storage.initialize()
    server = build_server(config)
    print(
        json.dumps(
            {
                "service": "ingest_api",
                "host": config.ingest_host,
                "port": config.ingest_port,
                "database": config.safe_database_descriptor(),
            },
            sort_keys=True,
        ),
        flush=True,
    )
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
