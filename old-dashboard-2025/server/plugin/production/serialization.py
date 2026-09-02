"""Serialization utilities for sensor forwarder."""

from datetime import datetime, timezone


def utc_now() -> str:
    """Return current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()
