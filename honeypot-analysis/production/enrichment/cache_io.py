"""Crash-safe helpers for threat-intelligence cache files."""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


CHECKSUM_FIELD = "_checksum_sha256"


def _encoded_payload(data: dict[str, Any]) -> bytes:
    return json.dumps(
        data,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def add_checksum(data: dict[str, Any]) -> dict[str, Any]:
    """Return a copy carrying a checksum of every field except the checksum."""
    checked = dict(data)
    checked.pop(CHECKSUM_FIELD, None)
    checked[CHECKSUM_FIELD] = hashlib.sha256(_encoded_payload(checked)).hexdigest()
    return checked


def checksum_valid(data: dict[str, Any]) -> bool:
    """Accept legacy unsigned caches and verify newly signed cache payloads."""
    expected = data.get(CHECKSUM_FIELD)
    if expected is None:
        return True
    if not isinstance(expected, str) or len(expected) != 64:
        return False
    unsigned = dict(data)
    unsigned.pop(CHECKSUM_FIELD, None)
    actual = hashlib.sha256(_encoded_payload(unsigned)).hexdigest()
    return hmac.compare_digest(actual, expected)


def load_cache_json(path: str, expected_schema: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("feed cache must contain a JSON object")
    if data.get("_schema") != expected_schema:
        raise ValueError("unsupported feed cache schema")
    if not checksum_valid(data):
        raise ValueError("feed cache checksum mismatch")
    return data


def atomic_write_cache(path: str, data: dict[str, Any]) -> None:
    """Write a checksummed JSON cache using fsync and same-filesystem rename."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = _encoded_payload(add_checksum(data))
    fd, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=str(destination.parent)
    )
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        temporary = ""
        directory_fd = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


@contextmanager
def feed_refresh_lock(path: str, timeout_seconds: float = 5.0) -> Iterator[None]:
    """Serialize refreshes for one cache path without blocking indefinitely."""
    lock_path = Path(f"{path}.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(lock_path, "a+", encoding="utf-8")
    deadline = time.monotonic() + max(float(timeout_seconds), 0.0)
    try:
        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("feed refresh lock timed out")
                time.sleep(min(0.05, max(deadline - time.monotonic(), 0.0)))
        yield
    finally:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()
