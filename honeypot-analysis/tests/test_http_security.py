from __future__ import annotations

import io
import socket
import threading
import time
from email.message import Message
from http import HTTPStatus
from http.server import ThreadingHTTPServer

import pytest

import production.utils.http_security as http_security
from production.utils.http_security import (
    BoundedThreadingHTTPServer,
    HTTPBodyError,
    decode_strict_json_body,
    read_bounded_http_body,
)


def _headers(*pairs: tuple[str, str]) -> Message:
    headers = Message()
    for name, value in pairs:
        headers.add_header(name, value)
    return headers


def _read(headers: Message, body: bytes = b"{}", *, maximum: int = 16) -> bytes:
    return read_bounded_http_body(
        headers,
        io.BytesIO(body),
        max_body_bytes=maximum,
        expected_content_type="application/json",
    )


def test_bounded_body_accepts_one_complete_fixed_length_body() -> None:
    headers = _headers(
        ("Content-Type", "application/json; charset=utf-8"),
        ("Content-Length", "2"),
    )

    assert _read(headers) == b"{}"


@pytest.mark.parametrize(
    ("headers", "expected_status", "expected_code"),
    [
        (
            _headers(("Content-Type", "application/json")),
            HTTPStatus.LENGTH_REQUIRED,
            "content_length_required",
        ),
        (
            _headers(
                ("Content-Type", "application/json"),
                ("Content-Length", "2"),
                ("Content-Length", "2"),
            ),
            HTTPStatus.BAD_REQUEST,
            "invalid_content_length",
        ),
        (
            _headers(
                ("Content-Type", "application/json"),
                ("Content-Length", "2"),
                ("Transfer-Encoding", "chunked"),
            ),
            HTTPStatus.BAD_REQUEST,
            "unsupported_transfer_encoding",
        ),
        (
            _headers(
                ("Content-Type", "application/json"),
                ("Content-Length", "2"),
                ("Transfer-Encoding", ""),
            ),
            HTTPStatus.BAD_REQUEST,
            "unsupported_transfer_encoding",
        ),
        (
            _headers(
                ("Content-Type", "text/plain"),
                ("Content-Length", "2"),
            ),
            HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
        ),
        (
            _headers(
                ("Content-Type", "application/json"),
                ("Content-Length", "17"),
            ),
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            "body_too_large",
        ),
        (
            _headers(
                ("Content-Type", "application/json"),
                ("Content-Length", "9" * 5_000),
            ),
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            "body_too_large",
        ),
    ],
)
def test_bounded_body_rejects_ambiguous_or_unsupported_framing(
    headers: Message,
    expected_status: HTTPStatus,
    expected_code: str,
) -> None:
    with pytest.raises(HTTPBodyError) as error:
        _read(headers)

    assert error.value.status == expected_status
    assert error.value.code == expected_code


def test_bounded_body_rejects_incomplete_reads_and_timeouts() -> None:
    headers = _headers(
        ("Content-Type", "application/json"),
        ("Content-Length", "2"),
    )
    with pytest.raises(HTTPBodyError) as incomplete:
        _read(headers, b"{")
    assert incomplete.value.code == "incomplete_body"

    class TimeoutStream:
        def read(self, _length: int) -> bytes:
            raise socket.timeout("unit timeout")

    with pytest.raises(HTTPBodyError) as timed_out:
        read_bounded_http_body(
            headers,
            TimeoutStream(),  # type: ignore[arg-type]
            max_body_bytes=16,
            expected_content_type="application/json",
        )
    assert timed_out.value.status == HTTPStatus.REQUEST_TIMEOUT
    assert timed_out.value.code == "request_timeout"


def test_bounded_body_enforces_an_absolute_read_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    headers = _headers(
        ("Content-Type", "application/json"),
        ("Content-Length", "2"),
    )
    clock = iter((0.0, 1.0, 20.0))
    monkeypatch.setattr(http_security.time, "monotonic", lambda: next(clock))

    class DribbleStream:
        def read1(self, _length: int) -> bytes:
            return b"{"

    with pytest.raises(HTTPBodyError) as error:
        read_bounded_http_body(
            headers,
            DribbleStream(),  # type: ignore[arg-type]
            max_body_bytes=16,
            expected_content_type="application/json",
            timeout_seconds=15.0,
            timeout_setter=lambda _seconds: None,
        )

    assert error.value.status == HTTPStatus.REQUEST_TIMEOUT
    assert error.value.code == "request_timeout"


@pytest.mark.parametrize(
    "body",
    [
        b'{"value": NaN}',
        b'{"value": Infinity}',
        ('{"value":' + ("9" * 5_000) + "}").encode(),
        ("[" * 2_000 + "]" * 2_000).encode(),
        b'{"detail":"\\ud800"}',
        b'{"\\udfff":"value"}',
        b"\xff",
    ],
)
def test_strict_json_decoder_returns_one_sanitized_error_class(body: bytes) -> None:
    with pytest.raises(HTTPBodyError) as error:
        decode_strict_json_body(body)

    assert error.value.status == HTTPStatus.BAD_REQUEST
    assert error.value.code == "invalid_json"


def test_strict_json_decoder_accepts_a_valid_surrogate_pair() -> None:
    assert decode_strict_json_body(b'{"emoji":"\\ud83d\\ude00"}') == {
        "emoji": "\U0001f600"
    }


def test_bounded_server_deadline_expires_and_releases_its_request_slot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expired = threading.Event()

    class FakeRequest:
        def shutdown(self, _how: int) -> None:
            expired.set()

    server = object.__new__(BoundedThreadingHTTPServer)
    server.request_deadline_seconds = 0.01
    server._request_slots = threading.BoundedSemaphore(1)
    assert server._request_slots.acquire(blocking=False)
    monkeypatch.setattr(
        ThreadingHTTPServer,
        "process_request_thread",
        lambda *_args: time.sleep(0.05),
    )

    server.process_request_thread(FakeRequest(), ("127.0.0.1", 1))  # type: ignore[arg-type]

    assert expired.is_set()
    assert server._request_slots.acquire(blocking=False)
