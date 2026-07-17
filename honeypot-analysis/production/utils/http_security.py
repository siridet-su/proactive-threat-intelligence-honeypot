"""Shared HTTP authentication and safe-request helpers.

The production HTTP services intentionally keep these primitives independent
of any particular handler implementation so their security decisions stay
consistent.
"""

from __future__ import annotations

import hmac
import ipaddress
import re
import socket
import uuid
from dataclasses import dataclass
from typing import Mapping, Optional


_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_BEARER_TOKEN_RE = re.compile(r"^[A-Za-z0-9\-._~+/]+={0,}$")


@dataclass(frozen=True)
class TokenAuthentication:
    """Result of matching one presented token against configured credentials."""

    authorized: bool
    identity: Optional[str] = None
    via_fallback: bool = False


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
    if not _BEARER_TOKEN_RE.fullmatch(token):
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
