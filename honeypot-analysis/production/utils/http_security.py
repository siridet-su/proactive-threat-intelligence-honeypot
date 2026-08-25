"""Shared HTTP authentication and safe-request helpers.

The production HTTP services intentionally keep these primitives independent
of any particular handler implementation so their security decisions stay
consistent.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import math
import re
import socket
import threading
import time
import uuid
from dataclasses import dataclass
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from typing import Any, BinaryIO, Callable, List, Mapping, Optional


_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_BEARER_TOKEN_RE = re.compile(r"^[A-Za-z0-9\-._~+/]+={0,}$")
MAX_BEARER_TOKEN_CHARS = 4_096
DEFAULT_MAX_CONCURRENT_REQUESTS = 64
DEFAULT_REQUEST_DEADLINE_SECONDS = 60.0


@dataclass(frozen=True)
class TokenAuthentication:
    """Result of matching one presented token against configured credentials."""

    authorized: bool
    identity: Optional[str] = None
    via_fallback: bool = False


class HTTPBodyError(ValueError):
    """A bounded request-body error safe to translate into an HTTP response."""

    def __init__(self, status: HTTPStatus, code: str, message: str) -> None:
        super().__init__(code)
        self.status = status
        self.code = code
        self.public_message = message


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """HTTP server with bounded threads, inactivity, and wall-clock lifetime."""

    daemon_threads = True
    block_on_close = False

    def __init__(
        self,
        address: Any,
        handler_class: Any,
        *,
        request_timeout_seconds: float,
        request_deadline_seconds: float = DEFAULT_REQUEST_DEADLINE_SECONDS,
        max_concurrent_requests: int = DEFAULT_MAX_CONCURRENT_REQUESTS,
    ) -> None:
        timeout = float(request_timeout_seconds)
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("request_timeout_seconds must be positive and finite")
        deadline = float(request_deadline_seconds)
        if not math.isfinite(deadline) or deadline <= 0:
            raise ValueError("request_deadline_seconds must be positive and finite")
        if (
            isinstance(max_concurrent_requests, bool)
            or not isinstance(max_concurrent_requests, int)
            or max_concurrent_requests <= 0
        ):
            raise ValueError("max_concurrent_requests must be a positive integer")
        self.request_timeout_seconds = timeout
        self.request_deadline_seconds = deadline
        self.max_concurrent_requests = max_concurrent_requests
        self._request_slots = threading.BoundedSemaphore(max_concurrent_requests)
        super().__init__(address, handler_class)

    def get_request(self) -> Any:
        request, client_address = super().get_request()
        request.settimeout(self.request_timeout_seconds)
        return request, client_address

    @staticmethod
    def _expire_request(request: socket.socket) -> None:
        try:
            request.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def process_request(self, request: socket.socket, client_address: Any) -> None:
        if not self._request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._request_slots.release()
            raise

    def process_request_thread(
        self,
        request: socket.socket,
        client_address: Any,
    ) -> None:
        deadline = threading.Timer(
            self.request_deadline_seconds,
            self._expire_request,
            args=(request,),
        )
        deadline.daemon = True
        deadline.start()
        try:
            super().process_request_thread(request, client_address)
        finally:
            deadline.cancel()
            self._request_slots.release()


def _header_values(headers: Any, name: str) -> List[str]:
    getter = getattr(headers, "get_all", None)
    if callable(getter):
        values = getter(name) or []
        return [str(value) for value in values]
    value = headers.get(name) if hasattr(headers, "get") else None
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return [str(value)]


def single_header_value(headers: Any, name: str) -> Optional[str]:
    """Return one unambiguous header value, or ``None`` otherwise."""

    values = _header_values(headers, name)
    return values[0] if len(values) == 1 else None


def _preflight_json_structure(text: str, max_depth: int, max_nodes: int) -> None:
    """Bound nesting and token count before the JSON decoder allocates objects."""

    depth = 0
    tokens = 0
    in_string = False
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            tokens += 1
        elif char in "[{":
            depth += 1
            tokens += 1
            if depth > max_depth:
                raise ValueError("JSON structure exceeds the configured depth limit")
        elif char in "]}":
            depth -= 1
        elif char == "-" or char.isdigit():
            tokens += 1
            index += 1
            while index < len(text) and text[index] in "0123456789.eE+-":
                index += 1
            if tokens > max_nodes:
                raise ValueError("JSON structure exceeds the configured node limit")
            continue
        elif text.startswith("true", index):
            tokens += 1
            index += 4
            continue
        elif text.startswith("false", index):
            tokens += 1
            index += 5
            continue
        elif text.startswith("null", index):
            tokens += 1
            index += 4
            continue
        if tokens > max_nodes:
            raise ValueError("JSON structure exceeds the configured node limit")
        index += 1


def _validate_unicode_scalar(value: str) -> None:
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise ValueError("JSON strings must contain Unicode scalar values")


def decode_strict_json_body(
    body: bytes,
    *,
    max_depth: int = 64,
    max_nodes: int = 50_000,
) -> Any:
    """Decode bounded UTF-8 JSON with finite structural complexity."""

    def reject_constant(value: str) -> Any:
        raise ValueError(f"non-finite JSON number {value!r}")

    try:
        if max_depth <= 0 or max_nodes <= 0:
            raise ValueError("JSON complexity limits must be positive")
        text = body.decode("utf-8")
        _preflight_json_structure(text, max_depth, max_nodes)
        decoded = json.loads(text, parse_constant=reject_constant)
        stack = [(decoded, 0)]
        nodes = 0
        while stack:
            value, depth = stack.pop()
            nodes += 1
            if nodes > max_nodes or depth > max_depth:
                raise ValueError("JSON structure exceeds the configured complexity limit")
            if isinstance(value, float) and not math.isfinite(value):
                raise ValueError("JSON number must be finite")
            if isinstance(value, dict):
                for key in value:
                    _validate_unicode_scalar(key)
                stack.extend((item, depth + 1) for item in value.values())
            elif isinstance(value, list):
                stack.extend((item, depth + 1) for item in value)
            elif isinstance(value, str):
                _validate_unicode_scalar(value)
        return decoded
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise HTTPBodyError(
            HTTPStatus.BAD_REQUEST,
            "invalid_json",
            "request body must contain valid UTF-8 JSON",
        ) from exc


def read_bounded_http_body(
    headers: Any,
    stream: BinaryIO,
    *,
    max_body_bytes: int,
    expected_content_type: str,
    timeout_seconds: Optional[float] = None,
    timeout_setter: Optional[Callable[[float], Any]] = None,
) -> bytes:
    """Read exactly one fixed-length body with strict framing and media type.

    Chunked/other transfer encodings are rejected because the standard-library
    server does not provide a bounded decoder. Duplicate framing headers, a
    missing length, negative/non-decimal lengths, incomplete reads, and bodies
    over the configured cap fail before application parsing.
    """

    if isinstance(max_body_bytes, bool) or not isinstance(max_body_bytes, int) or max_body_bytes <= 0:
        raise ValueError("max_body_bytes must be a positive integer")

    if _header_values(headers, "Transfer-Encoding"):
        raise HTTPBodyError(
            HTTPStatus.BAD_REQUEST,
            "unsupported_transfer_encoding",
            "transfer encoding is not supported",
        )

    content_types = _header_values(headers, "Content-Type")
    if len(content_types) != 1:
        raise HTTPBodyError(
            HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            f"Content-Type must be {expected_content_type}",
        )
    media_type = content_types[0].split(";", 1)[0].strip().lower()
    if media_type != expected_content_type.lower():
        raise HTTPBodyError(
            HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            f"Content-Type must be {expected_content_type}",
        )

    content_lengths = _header_values(headers, "Content-Length")
    if not content_lengths:
        raise HTTPBodyError(
            HTTPStatus.LENGTH_REQUIRED,
            "content_length_required",
            "Content-Length is required",
        )
    if len(content_lengths) != 1:
        raise HTTPBodyError(
            HTTPStatus.BAD_REQUEST,
            "invalid_content_length",
            "exactly one Content-Length header is required",
        )
    raw_length = content_lengths[0]
    if not raw_length.isascii() or not raw_length.isdigit():
        raise HTTPBodyError(
            HTTPStatus.BAD_REQUEST,
            "invalid_content_length",
            "Content-Length must be a non-negative decimal integer",
        )
    if len(raw_length) > 20:
        raise HTTPBodyError(
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            "body_too_large",
            "request body exceeds the configured limit",
        )
    length = int(raw_length)
    if length <= 0:
        raise HTTPBodyError(
            HTTPStatus.BAD_REQUEST,
            "empty_body",
            "request body must not be empty",
        )
    if length > max_body_bytes:
        raise HTTPBodyError(
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            "body_too_large",
            "request body exceeds the configured limit",
        )

    if timeout_seconds is not None:
        if not math.isfinite(float(timeout_seconds)) or float(timeout_seconds) <= 0:
            raise ValueError("timeout_seconds must be positive and finite")
        deadline = time.monotonic() + float(timeout_seconds)
    else:
        deadline = None

    chunks: List[bytes] = []
    remaining_bytes = length
    try:
        while remaining_bytes:
            if deadline is not None:
                remaining_time = deadline - time.monotonic()
                if remaining_time <= 0:
                    raise socket.timeout("request body deadline exceeded")
                if timeout_setter is not None:
                    timeout_setter(remaining_time)
            reader = getattr(stream, "read1", None)
            if not callable(reader):
                reader = stream.read
            chunk = reader(min(remaining_bytes, 64 * 1024))
            if not chunk:
                break
            chunks.append(bytes(chunk))
            remaining_bytes -= len(chunk)
    except (socket.timeout, TimeoutError) as exc:
        raise HTTPBodyError(
            HTTPStatus.REQUEST_TIMEOUT,
            "request_timeout",
            "request body was not received before the timeout",
        ) from exc
    except OSError as exc:
        raise HTTPBodyError(
            HTTPStatus.BAD_REQUEST,
            "body_read_failed",
            "request body could not be read",
        ) from exc
    body = b"".join(chunks)
    if len(body) != length:
        raise HTTPBodyError(
            HTTPStatus.BAD_REQUEST,
            "incomplete_body",
            "request body ended before Content-Length bytes were received",
        )
    return body


def is_loopback_host(host: str) -> bool:
    """Return true only when every address represented by *host* is loopback."""

    normalized = str(host or "").strip()
    if not normalized:
        return False

    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        pass

    try:
        addresses = socket.getaddrinfo(
            normalized,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror:
        return False

    resolved = []
    for address in addresses:
        try:
            resolved.append(ipaddress.ip_address(address[4][0]))
        except (IndexError, ValueError):
            return False
    return bool(resolved) and all(address.is_loopback for address in resolved)


def parse_bearer_token(authorization_header: Optional[str]) -> Optional[str]:
    """Parse exactly one ``Bearer <token>`` credential.

    Whitespace-surrounded, empty, multi-part, or control-character-bearing
    credentials are rejected instead of being normalized into a valid token.
    """

    if not isinstance(authorization_header, str):
        return None
    if authorization_header != authorization_header.strip():
        return None
    parts = authorization_header.split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1]
    if len(token) > MAX_BEARER_TOKEN_CHARS or not _BEARER_TOKEN_RE.fullmatch(token):
        return None
    return token


def constant_time_token_match(candidate: Optional[str], expected: str) -> bool:
    """Compare a presented secret with a configured non-empty token."""

    if not isinstance(candidate, str) or not isinstance(expected, str) or not expected:
        return False
    return hmac.compare_digest(candidate.encode("utf-8"), expected.encode("utf-8"))


def authenticate_token(
    candidate: Optional[str],
    identity_tokens: Mapping[str, str],
    fallback_token: str = "",
) -> TokenAuthentication:
    """Match a token without returning early from configured comparisons.

    An identity-specific match takes precedence over the compatibility fallback
    token. Ambiguous identity-token mappings fail closed.
    """

    matched_identities = []
    for identity, expected in identity_tokens.items():
        if constant_time_token_match(candidate, expected):
            matched_identities.append(str(identity))
    fallback_matched = constant_time_token_match(candidate, fallback_token)

    if len(matched_identities) == 1:
        return TokenAuthentication(True, matched_identities[0], False)
    if len(matched_identities) > 1:
        return TokenAuthentication(False)
    if fallback_matched:
        return TokenAuthentication(True, None, True)
    return TokenAuthentication(False)


def safe_request_id(value: Optional[str] = None) -> str:
    """Return a bounded, log-safe request ID or generate a fresh one."""

    if isinstance(value, str) and _REQUEST_ID_RE.fullmatch(value):
        return value
    return uuid.uuid4().hex


def safe_correlation_id(value: Any, fallback: str) -> str:
    """Select a bounded identifier without ever logging an invalid candidate."""

    if isinstance(value, str) and _REQUEST_ID_RE.fullmatch(value):
        return value
    if isinstance(fallback, str) and _REQUEST_ID_RE.fullmatch(fallback):
        return fallback
    return uuid.uuid4().hex


def validate_bind_auth(
    host: str,
    *,
    auth_configured: bool,
    service_name: str,
) -> None:
    """Reject unauthenticated services bound beyond the loopback interface."""

    if not auth_configured and not is_loopback_host(host):
        raise ValueError(
            f"{service_name} cannot bind to non-loopback host {host!r} "
            "without authentication configured"
        )
