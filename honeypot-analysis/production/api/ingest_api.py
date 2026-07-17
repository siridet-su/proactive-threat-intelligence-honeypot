"""Authenticated, bounded HTTP ingest API for Cowrie sensor events."""

from __future__ import annotations

import argparse
import json
import math
import re
import socket
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Mapping, Optional, Tuple
from urllib.parse import urlsplit

from production.storage import open_storage
from production.storage.contract import StorageBackend
from production.utils.config import ProductionConfig
from production.utils.http_security import (
    TokenAuthentication,
    authenticate_token,
    parse_bearer_token,
    safe_request_id,
    validate_bind_auth,
)
from production.utils.sensitive_data import redact_for_log
from production.utils.serialization import utc_now


_SENSOR_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class IngestRequestError(Exception):
    """A request error whose message is safe to return to an untrusted client."""

    def __init__(self, status: HTTPStatus, code: str, message: str) -> None:
        super().__init__(code)
        self.status = status
        self.code = code
        self.public_message = message


def validate_event(event: Dict[str, Any]) -> Tuple[bool, str]:
    if not isinstance(event, dict):
        return False, "event must be an object"
    event_id = event.get("eventid")
    if not isinstance(event_id, str) or not event_id.strip():
        return False, "eventid is required"
    return True, ""


def parse_event_envelope(payload: Any) -> Tuple[Optional[str], List[Any]]:
    """Return the optional envelope sensor identity and materialized events."""

    if isinstance(payload, list):
        return None, payload
    if isinstance(payload, dict):
        if "events" in payload or "event" in payload:
            sensor_value = payload.get("sensor_id")
            if sensor_value is not None and not isinstance(sensor_value, str):
                raise ValueError("sensor_id must be a string")
            if isinstance(sensor_value, str) and sensor_value != sensor_value.strip():
                raise ValueError("sensor_id must not contain surrounding whitespace")
            sensor_id = sensor_value if isinstance(sensor_value, str) else None
            events = payload.get("events", payload.get("event"))
            if isinstance(events, dict):
                return sensor_id or None, [events]
            if isinstance(events, list):
                return sensor_id or None, events
            raise ValueError("events must be an event object or event list")
        if "eventid" in payload:
            return None, [payload]
    raise ValueError("expected a JSON event object, event list, or event envelope")


def parse_events(payload: Any, default_sensor_id: str) -> Tuple[str, List[Dict[str, Any]]]:
    """Compatibility wrapper used by existing callers and tests."""

    sensor_id, events = parse_event_envelope(payload)
    return sensor_id or default_sensor_id, events


def _normalized_sensor_tokens(config: ProductionConfig) -> Dict[str, str]:
    raw_tokens = config.ingest_sensor_tokens
    if not isinstance(raw_tokens, Mapping):
        raise ValueError("ingest_sensor_tokens must be a mapping")

    normalized: Dict[str, str] = {}
    configured_values = set()
    for raw_sensor_id, raw_token in raw_tokens.items():
        if not isinstance(raw_sensor_id, str) or not isinstance(raw_token, str):
            raise ValueError("ingest_sensor_tokens keys and values must be strings")
        sensor_id = raw_sensor_id
        token = raw_token
        if not _SENSOR_ID_RE.fullmatch(sensor_id):
            raise ValueError("ingest_sensor_tokens contains an invalid sensor ID")
        if not token or token != token.strip():
            raise ValueError(
                f"ingest_sensor_tokens contains an empty or whitespace-padded token for {sensor_id!r}"
            )
        if token in configured_values:
            raise ValueError("ingest_sensor_tokens must not reuse a token across sensor IDs")
        configured_values.add(token)
        normalized[sensor_id] = token

    fallback_token = str(config.api_token or "")
    if fallback_token and fallback_token in configured_values:
        raise ValueError("api_token must not duplicate an identity-specific ingest token")
    return normalized


def _validate_ingest_config(config: ProductionConfig) -> Dict[str, str]:
    sensor_tokens = _normalized_sensor_tokens(config)
    if not isinstance(config.api_token, str):
        raise ValueError("api_token must be a string")
    fallback_token = config.api_token
    if fallback_token != fallback_token.strip():
        raise ValueError("api_token must not contain surrounding whitespace")

    integer_limits = {
        "ingest_max_body_bytes": config.ingest_max_body_bytes,
        "ingest_max_batch_events": config.ingest_max_batch_events,
        "ingest_max_event_bytes": config.ingest_max_event_bytes,
    }
    for field_name, value in integer_limits.items():
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{field_name} must be a positive integer")
    timeout = config.ingest_request_timeout_seconds
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError("ingest_request_timeout_seconds must be a positive finite number")

    if not _SENSOR_ID_RE.fullmatch(str(config.sensor_id or "")):
        raise ValueError("sensor_id must be a non-empty, bounded identifier")

    validate_bind_auth(
        config.ingest_host,
        auth_configured=bool(fallback_token or sensor_tokens),
        service_name="ingest_api",
    )
    return sensor_tokens


def _resolve_sensor_identity(
    *,
    configured_sensor_id: str,
    authenticated_sensor_id: Optional[str],
    header_sensor_id: Optional[str],
    body_sensor_id: Optional[str],
) -> str:
    identities = [
        identity
        for identity in (authenticated_sensor_id, header_sensor_id, body_sensor_id)
        if identity
    ]
    if authenticated_sensor_id and any(
        identity != authenticated_sensor_id
        for identity in (header_sensor_id, body_sensor_id)
        if identity
    ):
        raise IngestRequestError(
            HTTPStatus.BAD_REQUEST,
            "sensor_identity_mismatch",
            "authenticated, header, and body sensor identities must agree",
        )
    if header_sensor_id and body_sensor_id and header_sensor_id != body_sensor_id:
        raise IngestRequestError(
            HTTPStatus.BAD_REQUEST,
            "sensor_identity_mismatch",
            "header and body sensor identities must agree",
        )

    sensor_id = identities[0] if identities else configured_sensor_id
    if not _SENSOR_ID_RE.fullmatch(sensor_id):
        raise IngestRequestError(
            HTTPStatus.BAD_REQUEST,
            "invalid_sensor_id",
            "sensor identity is invalid",
        )
    return sensor_id


class IngestHTTPServer(ThreadingHTTPServer):
    """Threaded server carrying immutable runtime dependencies for handlers."""

    daemon_threads = True

    def __init__(
        self,
        address: Tuple[str, int],
        config: ProductionConfig,
        storage: StorageBackend,
        sensor_tokens: Mapping[str, str],
    ) -> None:
        self.config = config
        self.storage = storage
        self.sensor_tokens = dict(sensor_tokens)
        self.request_timeout_seconds = float(config.ingest_request_timeout_seconds)
        super().__init__(address, IngestHandler)

    def get_request(self) -> Tuple[socket.socket, Any]:
        request, client_address = super().get_request()
        request.settimeout(self.request_timeout_seconds)
        return request, client_address


class IngestHandler(BaseHTTPRequestHandler):
    server: IngestHTTPServer

    @property
    def config(self) -> ProductionConfig:
        return self.server.config

    @property
    def request_id(self) -> str:
        request_id = getattr(self, "_safe_request_id", "")
        if not request_id:
            request_ids = self.headers.get_all("X-Request-ID") or []
            request_id = safe_request_id(
                request_ids[0] if len(request_ids) == 1 else None
            )
            self._safe_request_id = request_id
        return request_id

    def _route_path(self) -> str:
        try:
            return urlsplit(self.path).path.rstrip("/") or "/"
        except ValueError:
            return ""

    def _send_json(
        self,
        status: HTTPStatus,
        payload: Dict[str, Any],
        *,
        headers: Optional[Mapping[str, str]] = None,
        close_connection: bool = False,
    ) -> None:
        response_payload = dict(payload)
        response_payload.setdefault("request_id", self.request_id)
        body = json.dumps(
            response_payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Request-ID", self.request_id)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        if close_connection:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            self.close_connection = True

    def _send_error(
        self,
        status: HTTPStatus,
        code: str,
        message: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        close_connection: bool = False,
    ) -> None:
        self._send_json(
            status,
            {
                "ok": False,
                "error": {
                    "code": code,
                    "message": message,
                },
                "timestamp": utc_now(),
            },
            headers=headers,
            close_connection=close_connection,
        )

    def _log_event(self, event: str, **fields: Any) -> None:
        payload = {
            "service": "ingest_api",
            "event": event,
            "request_id": self.request_id,
            "client_ip": self.client_address[0],
            "method": (
                self.command
                if re.fullmatch(r"[A-Z]{1,16}", str(self.command or ""))
                else "<invalid>"
            ),
            "path": self._route_path()
            if self._route_path() in {"/", "/events", "/health", "/health/live", "/health/ready"}
            else "<unmatched>",
            "timestamp": utc_now(),
        }
        payload.update(fields)
        print(json.dumps(redact_for_log(payload), sort_keys=True), flush=True)

    def _authenticate(self) -> TokenAuthentication:
        if not self.server.sensor_tokens and not self.config.api_token:
            return TokenAuthentication(True)
        authorization_headers = self.headers.get_all("Authorization") or []
        candidate = parse_bearer_token(
            authorization_headers[0]
            if len(authorization_headers) == 1
            else None
        )
        return authenticate_token(
            candidate,
            self.server.sensor_tokens,
            str(self.config.api_token or ""),
        )

    def _read_json_body(self) -> Any:
        transfer_encoding = self.headers.get("Transfer-Encoding")
        if transfer_encoding:
            raise IngestRequestError(
                HTTPStatus.BAD_REQUEST,
                "unsupported_transfer_encoding",
                "transfer encoding is not supported",
            )

        content_types = self.headers.get_all("Content-Type") or []
        if len(content_types) != 1 or self.headers.get_content_type().lower() != "application/json":
            raise IngestRequestError(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
                "Content-Type must be application/json",
            )

        content_lengths = self.headers.get_all("Content-Length") or []
        if not content_lengths:
            raise IngestRequestError(
                HTTPStatus.LENGTH_REQUIRED,
                "content_length_required",
                "Content-Length is required",
            )
        if len(content_lengths) != 1:
            raise IngestRequestError(
                HTTPStatus.BAD_REQUEST,
                "invalid_content_length",
                "exactly one Content-Length header is required",
            )
        raw_length = content_lengths[0]
        if not raw_length.isascii() or not raw_length.isdigit():
            raise IngestRequestError(
                HTTPStatus.BAD_REQUEST,
                "invalid_content_length",
                "Content-Length must be a non-negative decimal integer",
            )
        length = int(raw_length)
        if length <= 0:
            raise IngestRequestError(
                HTTPStatus.BAD_REQUEST,
                "empty_body",
                "request body must not be empty",
            )
        if length > int(self.config.ingest_max_body_bytes):
            raise IngestRequestError(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "body_too_large",
                "request body exceeds the configured limit",
            )

        try:
            raw_body = self.rfile.read(length)
        except (socket.timeout, TimeoutError) as exc:
            raise IngestRequestError(
                HTTPStatus.REQUEST_TIMEOUT,
                "request_timeout",
                "request body was not received before the timeout",
            ) from exc
        except OSError as exc:
            raise IngestRequestError(
                HTTPStatus.BAD_REQUEST,
                "body_read_failed",
                "request body could not be read",
            ) from exc
        if len(raw_body) != length:
            raise IngestRequestError(
                HTTPStatus.BAD_REQUEST,
                "incomplete_body",
                "request body ended before Content-Length bytes were received",
            )
        try:
            return json.loads(raw_body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise IngestRequestError(
                HTTPStatus.BAD_REQUEST,
                "invalid_json",
                "request body must contain valid UTF-8 JSON",
            ) from exc

    def _header_sensor_id(self) -> Optional[str]:
        sensor_headers = self.headers.get_all("X-Sensor-ID") or []
        if len(sensor_headers) > 1:
            raise IngestRequestError(
                HTTPStatus.BAD_REQUEST,
                "duplicate_sensor_header",
                "at most one X-Sensor-ID header is allowed",
            )
        if not sensor_headers:
            return None
        sensor_id = sensor_headers[0]
        if sensor_id != sensor_id.strip():
            raise IngestRequestError(
                HTTPStatus.BAD_REQUEST,
                "invalid_sensor_id",
                "sensor identity is invalid",
            )
        return sensor_id or None

    def do_GET(self) -> None:
        path = self._route_path()
        if path in {"/health", "/health/live"}:
            self._send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "service": "ingest_api",
                    "status": "live",
                    "timestamp": utc_now(),
                },
            )
            return
        if path == "/health/ready":
            try:
                health = self.server.storage.health_check()
                ready = isinstance(health, Mapping) and bool(health.get("ok"))
            except Exception as exc:
                self._log_event(
                    "readiness_check_failed",
                    exception_type=type(exc).__name__,
                )
                ready = False
            self._send_json(
                HTTPStatus.OK if ready else HTTPStatus.SERVICE_UNAVAILABLE,
                {
                    "ok": ready,
                    "service": "ingest_api",
                    "status": "ready" if ready else "not_ready",
                    "timestamp": utc_now(),
                },
            )
            return
        self._send_error(HTTPStatus.NOT_FOUND, "not_found", "resource not found")

    def do_POST(self) -> None:
        if self._route_path() != "/events":
            self._send_error(
                HTTPStatus.NOT_FOUND,
                "not_found",
                "resource not found",
                close_connection=True,
            )
            return

        authentication = self._authenticate()
        if not authentication.authorized:
            self._log_event("authentication_failed")
            self._send_error(
                HTTPStatus.UNAUTHORIZED,
                "unauthorized",
                "valid Bearer authentication is required",
                headers={"WWW-Authenticate": "Bearer"},
                close_connection=True,
            )
            return

        try:
            payload = self._read_json_body()
            body_sensor_id, events = parse_event_envelope(payload)
            if not events:
                raise IngestRequestError(
                    HTTPStatus.BAD_REQUEST,
                    "empty_batch",
                    "event batch must not be empty",
                )
            if len(events) > int(self.config.ingest_max_batch_events):
                raise IngestRequestError(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    "batch_too_large",
                    "event batch exceeds the configured limit",
                )
            sensor_id = _resolve_sensor_identity(
                configured_sensor_id=self.config.sensor_id,
                authenticated_sensor_id=(
                    authentication.identity
                    or (self.config.sensor_id if authentication.via_fallback else None)
                ),
                header_sensor_id=self._header_sensor_id(),
                body_sensor_id=body_sensor_id,
            )
        except IngestRequestError as exc:
            self._send_error(
                exc.status,
                exc.code,
                exc.public_message,
                close_connection=True,
            )
            return
        except ValueError:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "invalid_event_envelope",
                "request body has an invalid event envelope",
                close_connection=True,
            )
            return

        accepted = 0
        duplicates = 0
        rejected: List[Dict[str, Any]] = []
        for index, event in enumerate(events):
            encoded_event = json.dumps(
                event,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            if len(encoded_event) > int(self.config.ingest_max_event_bytes):
                rejected.append(
                    {
                        "index": index,
                        "error_code": "event_too_large",
                        "error": "event exceeds the configured size limit",
                    }
                )
                continue

            valid, error = validate_event(event)
            if not valid:
                rejected.append(
                    {
                        "index": index,
                        "error_code": "invalid_event",
                        "error": error,
                    }
                )
                continue
            try:
                _, inserted = self.server.storage.store_event(sensor_id, event)
            except Exception as exc:
                self._log_event(
                    "storage_write_failed",
                    exception_type=type(exc).__name__,
                    event_index=index,
                )
                self._send_error(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    "storage_unavailable",
                    "event storage is unavailable",
                    close_connection=True,
                )
                return
            if inserted:
                accepted += 1
            else:
                duplicates += 1

        if accepted and not duplicates and not rejected:
            http_status = HTTPStatus.ACCEPTED
            outcome = "accepted"
        elif accepted:
            http_status = HTTPStatus.ACCEPTED
            outcome = "partial"
        elif duplicates and not rejected:
            http_status = HTTPStatus.OK
            outcome = "duplicate"
        elif duplicates:
            http_status = HTTPStatus.MULTI_STATUS
            outcome = "partial"
        else:
            http_status = HTTPStatus.BAD_REQUEST
            outcome = "rejected"

        self._log_event(
            "batch_processed",
            outcome=outcome,
            accepted=accepted,
            duplicates=duplicates,
            rejected=len(rejected),
        )
        self._send_json(
            http_status,
            {
                "ok": outcome != "rejected",
                "status": outcome,
                "accepted": accepted,
                "duplicates": duplicates,
                "rejected": rejected,
                "total": len(events),
                "sensor_id": sensor_id,
                "timestamp": utc_now(),
            },
            close_connection=outcome == "rejected",
        )

    def log_message(self, fmt: str, *args: Any) -> None:
        status = args[1] if len(args) > 1 else ""
        self._log_event("http_access", status=str(status))


def build_server(
    config: ProductionConfig,
    *,
    storage: Optional[StorageBackend] = None,
) -> IngestHTTPServer:
    sensor_tokens = _validate_ingest_config(config)
    selected_storage = storage or open_storage(config.database_settings())
    return IngestHTTPServer(
        (config.ingest_host, config.ingest_port),
        config,
        selected_storage,
        sensor_tokens,
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the Cowrie event ingest API.")
    parser.add_argument("--config", help="Path to production JSON config.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    config = ProductionConfig.from_env(args.config)
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
