"""Signed, per-target webhook alert delivery with durable leases."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import queue
import re
import socket
import stat
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple
from uuid import uuid4

from production.storage import open_storage
from production.utils.config import ProductionConfig
from production.utils.sensitive_data import redact_exception_for_log, redact_for_webhook
from production.utils.serialization import stable_id, stable_json, utc_now


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
WEBHOOK_SIGNATURE_VERSION = "v1"
WEBHOOK_CREDENTIAL_NAME = "webhook-signing-key"
MAX_SIGNING_KEY_BYTES = 4096
MIN_SIGNING_KEY_BYTES = 32
TARGET_ID_PATTERN = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}")
TARGET_KEYS = frozenset(
    {"target_id", "url", "enabled", "signing_key_file", "allow_private_networks"}
)
RETRYABLE_HTTP_STATUSES = frozenset({408, 425, 429})


class WebhookConfigurationError(ValueError):
    """Raised before delivery when a target or key configuration is unsafe."""


class WebhookEndpointError(ValueError):
    """Endpoint validation failure with explicit retry classification."""

    def __init__(self, code: str, *, retryable: bool) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


@dataclass(frozen=True)
class WebhookTarget:
    target_id: str
    url: str
    url_hash: str
    signing_key: bytes
    allow_private_networks: bool = False


@dataclass(frozen=True)
class WebhookPostResult:
    delivered: bool
    retryable: bool
    error_code: str = ""
    error: str = ""
    response_status: Optional[int] = None
    response_body_sha256: str = ""
    response_body_bytes: int = 0
    response_body_truncated: bool = False

    def __iter__(self) -> Iterator[Any]:
        # Compatibility for the earlier ``ok, error = post_webhook(...)`` API.
        yield self.delivered
        yield self.error


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def _open_no_redirect(
    request: urllib.request.Request, timeout_seconds: float
) -> Any:
    # Ignore ambient proxy variables: validation applies to the actual target,
    # and a service-specific proxy can be added only with a reviewed transport.
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirectHandler(),
    )
    return opener.open(request, timeout=timeout_seconds)


def target_hash(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def webhook_delivery_id(
    *, target_url_hash: str, alert_id: Optional[str] = None, report_id: Optional[str] = None
) -> str:
    return stable_id(
        "delivery",
        {"alert_id": alert_id, "report_id": report_id, "target": target_url_hash},
    )


def _normalize_endpoint(url: str, allowed_schemes: Sequence[str]) -> str:
    value = str(url or "").strip()
    if not value or len(value) > 4096:
        raise WebhookConfigurationError("webhook URL must be non-empty and bounded")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise WebhookConfigurationError("webhook URL is invalid") from exc
    schemes = {str(item).strip().lower() for item in allowed_schemes}
    if parsed.scheme.lower() not in schemes:
        raise WebhookConfigurationError("webhook URL scheme is not allowed")
    if not parsed.hostname:
        raise WebhookConfigurationError("webhook URL hostname is required")
    if parsed.username is not None or parsed.password is not None:
        raise WebhookConfigurationError("webhook URL must not contain user information")
    if parsed.fragment:
        raise WebhookConfigurationError("webhook URL must not contain a fragment")
    if port is not None and not 1 <= port <= 65535:
        raise WebhookConfigurationError("webhook URL port is invalid")
    normalized_host = parsed.hostname.lower()
    if ":" in normalized_host:
        normalized_host = f"[{normalized_host}]"
    netloc = normalized_host + (f":{port}" if port is not None else "")
    return urllib.parse.urlunsplit(
        (parsed.scheme.lower(), netloc, parsed.path, parsed.query, "")
    )


def _resolved_addresses(
    hostname: str,
    port: int,
    timeout_seconds: float,
) -> List[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        literal = ipaddress.ip_address(hostname)
        return [literal]
    except ValueError:
        pass
    result_queue: queue.Queue[Tuple[bool, Any]] = queue.Queue(maxsize=1)

    def resolve() -> None:
        try:
            records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
            result_queue.put_nowait((True, records))
        except BaseException as exc:  # contained and never rendered
            result_queue.put_nowait((False, exc))

    threading.Thread(
        target=resolve,
        name="webhook-dns-resolution",
        daemon=True,
    ).start()
    try:
        succeeded, value = result_queue.get(timeout=timeout_seconds)
    except queue.Empty as exc:
        raise WebhookEndpointError("webhook_dns_unavailable", retryable=True) from exc
    if not succeeded:
        raise WebhookEndpointError("webhook_dns_unavailable", retryable=True)
    records = value
    addresses: List[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for record in records:
        try:
            address = ipaddress.ip_address(record[4][0].split("%", 1)[0])
        except (ValueError, IndexError):
            continue
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise WebhookEndpointError("webhook_dns_no_addresses", retryable=True)
    return addresses


def validate_resolved_endpoint(
    url: str,
    *,
    allow_private_networks: bool,
    dns_timeout_seconds: float = 5.0,
) -> None:
    parsed = urllib.parse.urlsplit(url)
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    for address in _resolved_addresses(hostname, port, dns_timeout_seconds):
        if address.is_unspecified or address.is_multicast:
            raise WebhookEndpointError("webhook_endpoint_unsafe", retryable=False)
        if not allow_private_networks and not address.is_global:
            raise WebhookEndpointError("webhook_endpoint_internal", retryable=False)


def _resolve_signing_key_path(configured_path: str) -> str:
    value = str(configured_path or "").strip()
    if value:
        return value
    credentials_directory = os.getenv("CREDENTIALS_DIRECTORY", "").strip()
    if not credentials_directory:
        return ""
    return str(Path(credentials_directory) / WEBHOOK_CREDENTIAL_NAME)


def _load_signing_key(configured_path: str) -> bytes:
    resolved = _resolve_signing_key_path(configured_path)
    if not resolved:
        raise WebhookConfigurationError("webhook signing key file is required")
    path = Path(resolved)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise WebhookConfigurationError("webhook signing key file cannot be opened") from exc
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise WebhookConfigurationError("webhook signing key must be a regular file")
        if file_stat.st_mode & 0o077:
            raise WebhookConfigurationError("webhook signing key permissions are too broad")
        if file_stat.st_size > MAX_SIGNING_KEY_BYTES:
            raise WebhookConfigurationError("webhook signing key is too large")
        chunks: List[bytes] = []
        remaining = MAX_SIGNING_KEY_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(remaining, 4096))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        key = b"".join(chunks).strip()
    finally:
        os.close(descriptor)
    if not MIN_SIGNING_KEY_BYTES <= len(key) <= MAX_SIGNING_KEY_BYTES:
        raise WebhookConfigurationError("webhook signing key length is unsafe")
    return key


def _signature(
    signing_key: bytes,
    timestamp: str,
    idempotency_key: str,
    body: bytes,
) -> str:
    message = b"\n".join(
        [
            WEBHOOK_SIGNATURE_VERSION.encode("ascii"),
            timestamp.encode("utf-8"),
            idempotency_key.encode("ascii"),
            body,
        ]
    )
    digest = hmac.new(signing_key, message, hashlib.sha256).hexdigest()
    return f"{WEBHOOK_SIGNATURE_VERSION}={digest}"


def _capture_response_body(response: Any, limit: int) -> Tuple[str, int, bool]:
    encoded = response.read(limit + 1)
    truncated = len(encoded) > limit
    captured = encoded[:limit]
    return (
        hashlib.sha256(captured).hexdigest() if captured else "",
        len(captured),
        truncated,
    )


def _http_result(status: int, response: Any, max_response_bytes: int) -> WebhookPostResult:
    digest, body_bytes, truncated = _capture_response_body(response, max_response_bytes)
    delivered = 200 <= status < 300
    retryable = status in RETRYABLE_HTTP_STATUSES or 500 <= status < 600
    return WebhookPostResult(
        delivered=delivered,
        retryable=(False if delivered else retryable),
        error_code=("" if delivered else f"webhook_http_{status}"),
        error=("" if delivered else f"HTTP {status}"),
        response_status=status,
        response_body_sha256=digest,
        response_body_bytes=body_bytes,
        response_body_truncated=truncated,
    )


def post_webhook(
    url: str,
    payload: Dict[str, Any],
    timeout_seconds: float,
    *,
    signing_key: bytes,
    timestamp: str,
    idempotency_key: str,
    max_response_bytes: int = 4096,
) -> WebhookPostResult:
    try:
        body = stable_json(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "honeypot-webhook/1",
                "X-Honeypot-Timestamp": timestamp,
                "X-Honeypot-Idempotency-Key": idempotency_key,
                "X-Honeypot-Signature": _signature(
                    signing_key, timestamp, idempotency_key, body
                ),
            },
            method="POST",
        )
        with _open_no_redirect(request, timeout_seconds) as response:
            return _http_result(int(response.status), response, max_response_bytes)
    except urllib.error.HTTPError as exc:
        try:
            return _http_result(int(exc.code), exc, max_response_bytes)
        finally:
            exc.close()
    except Exception as exc:
        safe_error = redact_exception_for_log(exc)
        retryable = isinstance(
            exc,
            (TimeoutError, ConnectionError, OSError, urllib.error.URLError),
        )
        return WebhookPostResult(
            delivered=False,
            retryable=retryable,
            error_code=("webhook_transport_error" if retryable else "webhook_request_invalid"),
            error=safe_error,
        )


def _retry_timestamp(timestamp: str, delay_seconds: float) -> str:
    parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return (parsed.astimezone(timezone.utc) + timedelta(seconds=delay_seconds)).isoformat()


def _target_documents(config: ProductionConfig) -> List[Dict[str, Any]]:
    if config.webhook_targets:
        return [dict(item) for item in config.webhook_targets]
    if config.webhook_url:
        return [
            {
                "target_id": "default",
                "url": config.webhook_url,
                "signing_key_file": config.webhook_signing_key_file,
                "allow_private_networks": config.webhook_allow_private_networks,
                "enabled": True,
            }
        ]
    return []


def load_webhook_targets(config: ProductionConfig) -> List[WebhookTarget]:
    targets: List[WebhookTarget] = []
    seen_ids: set[str] = set()
    seen_hashes: set[str] = set()
    allowed_schemes = [item.lower() for item in config.webhook_allowed_schemes]
    for document in _target_documents(config):
        unknown = set(document) - TARGET_KEYS
        if unknown:
            raise WebhookConfigurationError("webhook target contains unsupported keys")
        if document.get("enabled", True) is not True:
            if document.get("enabled") is not False:
                raise WebhookConfigurationError("webhook target enabled must be boolean")
            continue
        target_id = str(document.get("target_id") or "").strip()
        if not TARGET_ID_PATTERN.fullmatch(target_id):
            raise WebhookConfigurationError("webhook target_id is invalid")
        if target_id in seen_ids:
            raise WebhookConfigurationError("webhook target_id must be unique")
        allow_private = document.get(
            "allow_private_networks", config.webhook_allow_private_networks
        )
        if not isinstance(allow_private, bool):
            raise WebhookConfigurationError(
                "webhook allow_private_networks must be boolean"
            )
        url = _normalize_endpoint(str(document.get("url") or ""), allowed_schemes)
        url_digest = target_hash(url)
        if url_digest in seen_hashes:
            raise WebhookConfigurationError("webhook target URL must be unique")
        key_path = str(
            document.get("signing_key_file") or config.webhook_signing_key_file or ""
        )
        targets.append(
            WebhookTarget(
                target_id=target_id,
                url=url,
                url_hash=url_digest,
                signing_key=_load_signing_key(key_path),
                allow_private_networks=allow_private,
            )
        )
        seen_ids.add(target_id)
        seen_hashes.add(url_digest)
    return targets


class WebhookDispatcher:
    def __init__(
        self,
        config: ProductionConfig,
        *,
        storage: Any = None,
        worker_id: str = "",
    ) -> None:
        self.config = config
        self.config.validate_event_processing()
        self.storage = storage or open_storage(config.database_url)
        self.worker_id = worker_id or f"webhook-{os.getpid()}-{uuid4()}"
        self.targets = load_webhook_targets(config)

    def _alert_should_send(self, alert: Dict[str, Any]) -> bool:
        policy = self.config.webhook_policy or {}
        alert_type = str(
            alert.get("alert_type")
            or (alert.get("payload") or {}).get("alert_type")
            or ""
        ).strip().lower()
        default_min = str(policy.get("min_severity") or "high").strip().lower()
        per_type = policy.get("alert_type_min_severity") or {}
        min_severity = str(per_type.get(alert_type) or default_min).strip().lower()
        severity = str(alert.get("severity") or "").strip().lower()
        return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(min_severity, 3)

    def _filtered_payload(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        redacted = redact_for_webhook(alert)
        return dict(redacted) if isinstance(redacted, dict) else {"redacted": True}

    def _complete_endpoint_failure(
        self,
        claim: Dict[str, Any],
        failure: WebhookEndpointError,
        timestamp: str,
    ) -> None:
        attempts = int(claim.get("attempts") or 0)
        retryable = failure.retryable and attempts < self.config.webhook_max_attempts
        self.storage.complete_webhook_delivery(
            claim["delivery_id"],
            self.worker_id,
            claim["claim_token"],
            "retryable" if retryable else "permanent_failure",
            error_code=failure.code,
            error=failure.code,
            next_retry_at=(
                _retry_timestamp(timestamp, self.config.webhook_retry_seconds)
                if retryable
                else None
            ),
            now=timestamp,
        )

    def dispatch_once(self) -> int:
        attempted = 0
        for target in self.targets:
            rows = self.storage.pending_webhooks(
                limit=100,
                target_url_hash=target.url_hash,
                max_attempts=self.config.webhook_max_attempts,
            )
            for row in rows:
                alert = dict(row["payload"])
                safe_alert = self._filtered_payload(alert)
                if not self._alert_should_send(alert):
                    self.storage.record_webhook_delivery(
                        {"type": "alert", "alert": safe_alert},
                        target.url_hash,
                        "filtered",
                        alert_id=row["alert_id"],
                    )
                    continue

                timestamp = utc_now()
                delivery_id = webhook_delivery_id(
                    alert_id=row["alert_id"], target_url_hash=target.url_hash
                )
                payload = {
                    "type": "alert",
                    "alert": safe_alert,
                    "timestamp": timestamp,
                    "idempotency_key": delivery_id,
                }
                claim = self.storage.claim_webhook_delivery(
                    payload,
                    target.url_hash,
                    self.worker_id,
                    self.config.webhook_lease_seconds,
                    self.config.webhook_max_attempts,
                    alert_id=row["alert_id"],
                    now=timestamp,
                )
                if claim is None:
                    continue

                try:
                    validate_resolved_endpoint(
                        target.url,
                        allow_private_networks=target.allow_private_networks,
                        dns_timeout_seconds=self.config.webhook_dns_timeout_seconds,
                    )
                except WebhookEndpointError as exc:
                    self._complete_endpoint_failure(claim, exc, timestamp)
                    continue

                result = post_webhook(
                    target.url,
                    payload,
                    self.config.webhook_timeout_seconds,
                    signing_key=target.signing_key,
                    timestamp=timestamp,
                    idempotency_key=delivery_id,
                    max_response_bytes=self.config.webhook_max_response_bytes,
                )
                attempts = int(claim.get("attempts") or 0)
                retryable = result.retryable and attempts < self.config.webhook_max_attempts
                outcome = (
                    "delivered"
                    if result.delivered
                    else ("retryable" if retryable else "permanent_failure")
                )
                error_code = result.error_code
                if result.retryable and not retryable:
                    error_code = "webhook_attempts_exhausted"
                self.storage.complete_webhook_delivery(
                    delivery_id,
                    self.worker_id,
                    claim["claim_token"],
                    outcome,
                    error_code=error_code,
                    error=result.error,
                    response_status=result.response_status,
                    response_body_sha256=result.response_body_sha256,
                    response_body_bytes=result.response_body_bytes,
                    response_body_truncated=result.response_body_truncated,
                    next_retry_at=(
                        _retry_timestamp(timestamp, self.config.webhook_retry_seconds)
                        if outcome == "retryable"
                        else None
                    ),
                    now=timestamp,
                )
                attempted += 1
        return attempted

    def run_forever(self) -> None:
        while True:
            attempted = self.dispatch_once()
            if attempted:
                print(
                    json.dumps(
                        {
                            "service": "webhook_dispatcher",
                            "attempted": attempted,
                            "targets": len(self.targets),
                            "timestamp": utc_now(),
                        },
                        sort_keys=True,
                    ),
                    flush=True,
                )
            time.sleep(self.config.webhook_retry_seconds)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run signed webhook alert dispatch.")
    parser.add_argument("--config", help="Path to production JSON config.")
    parser.add_argument("--once", action="store_true", help="Dispatch once and exit.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    config = ProductionConfig.from_env(args.config)
    dispatcher = WebhookDispatcher(config)
    if args.once:
        attempted = dispatcher.dispatch_once()
        print(json.dumps({"service": "webhook_dispatcher", "attempted": attempted}, sort_keys=True))
        return 0
    dispatcher.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
