"""Central sensitive-data redaction helpers.

The helpers in this module intentionally return JSON-safe data while preserving
the surrounding document shape.  They are suitable for API responses, logs,
artifacts and webhook payloads; raw telemetry storage remains a separate,
explicit trust boundary.
"""

from __future__ import annotations

import dataclasses
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote_plus, urlsplit, urlunsplit

from production.utils.serialization import to_jsonable


REDACTION_MARKER = "[REDACTED]"
URL_REDACTION_MARKER = "<redacted>"
OVERSIZED_JSON_MARKER = "[REDACTED: OVERSIZED JSON]"
TRUNCATION_MARKER = "...[TRUNCATED]"

MAX_EMBEDDED_JSON_CHARS = 65_536
MAX_API_STRING_CHARS = 65_536
MAX_LOG_STRING_CHARS = 4_096
MAX_ARTIFACT_STRING_CHARS = 262_144
MAX_WEBHOOK_STRING_CHARS = 32_768
MAX_REDACTION_DEPTH = 48


@dataclass(frozen=True)
class _RedactionPolicy:
    max_string_chars: int
    max_embedded_json_chars: int = MAX_EMBEDDED_JSON_CHARS
    max_depth: int = MAX_REDACTION_DEPTH


_METADATA_SUFFIXES = (
    "_configured",
    "_enabled",
    "_present",
    "_available",
    "_count",
    "_length",
    "_status",
    "_type",
    "_source",
    "_name",
    "_path",
    "_metadata",
)

_SENSITIVE_EXACT_KEYS = {
    "authorization",
    "proxy_authorization",
    "cookie",
    "cookies",
    "set_cookie",
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "login_password",
    "api_key",
    "apikey",
    "x_api_key",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "api_token",
    "auth_token",
    "bearer_token",
    "platform_token",
    "session_token",
    "csrf_token",
    "client_secret",
    "api_secret",
    "secret",
    "credentials",
    "credential",
    "private_key",
    "ssh_private_key",
    "hmac_key",
    "signing_key",
    "encryption_key",
}

_SENSITIVE_QUERY_KEYS = {
    "authorization",
    "auth",
    "api_key",
    "apikey",
    "key",
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "auth_token",
    "api_token",
    "bearer_token",
    "client_secret",
    "api_secret",
    "secret",
    "signature",
    "sig",
    "credential",
    "credentials",
    "cookie",
    "session",
    "session_id",
    "sessionid",
    "jwt",
    "code",
    "x_amz_credential",
    "x_amz_signature",
    "x_amz_security_token",
    "x_goog_signature",
    "x_goog_credential",
}

_URL_VALUE_KEYS = {
    "url",
    "uri",
    "href",
    "link",
    "endpoint",
    "database_url",
    "mongodb_uri",
    "ingest_url",
    "webhook_url",
    "target_url",
}

_DATABASE_URL_SCHEMES = {
    "mongodb",
    "mongodb+srv",
    "mysql",
    "postgres",
    "postgresql",
    "sqlite",
}

_URL_PATTERN = re.compile(
    r"\b[a-z][a-z0-9+.-]*://[^\s<>'\"]+",
    flags=re.IGNORECASE,
)
_HEADER_LINE_PATTERN = re.compile(
    r"(?im)\b(authorization|proxy-authorization|cookie|set-cookie)"
    r"(\s*:\s*)[^\r\n]*"
)
_AUTH_VALUE_PATTERN = re.compile(
    r"(?i)\b(authorization|proxy[_-]?authorization)"
    r"(\s*[:=]\s*)(?:(?:bearer|basic)\s+)?[^\s,;]+"
)
_BEARER_PATTERN = re.compile(
    r"(?i)\b(bearer|basic)(\s+)[a-z0-9._~+/=-]+"
)
_COOKIE_VALUE_PATTERN = re.compile(
    r"(?i)\b(cookie|cookies|set[_-]?cookie)(\s*[=:]\s*)[^\r\n]+"
)
_SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"""(?ix)
    \b(
        password|passwd|pwd|passphrase|login[_-]?password|
        api[_-]?key|apikey|x[_-]?api[_-]?key|
        access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?token|
        auth[_-]?token|bearer[_-]?token|platform[_-]?token|session[_-]?token|
        csrf[_-]?token|token|
        client[_-]?secret|api[_-]?secret|secret|
        credential(?:s)?|private[_-]?key|hmac[_-]?key|signing[_-]?key|
        encryption[_-]?key|
        password[_-]?(?:hash|hmac|digest)|
        credential[_-]?(?:hash|hmac|digest)
    )\b
    (\s*[:=]\s*)
    (
        "(?:\\.|[^"])*" |
        '(?:\\.|[^'])*' |
        [^\s,;&]+
    )
    """
)
_QUOTED_SECRET_ASSIGNMENT_PATTERN = re.compile(
    r'''(?ix)
    (["'])
    (
        authorization|proxy[_-]?authorization|cookie|set[_-]?cookie|
        password|passwd|pwd|passphrase|login[_-]?password|
        api[_-]?key|apikey|x[_-]?api[_-]?key|
        access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?token|
        auth[_-]?token|bearer[_-]?token|session[_-]?token|token|
        client[_-]?secret|api[_-]?secret|secret|credential(?:s)?|
        private[_-]?key|hmac[_-]?key|signing[_-]?key|encryption[_-]?key|
        password[_-]?(?:hash|hmac|digest)|credential[_-]?(?:hash|hmac|digest)
    )
    \1
    (\s*:\s*)
    (
        "(?:\\.|[^"])*" |
        '(?:\\.|[^'])*' |
        [^\s,;&}\]]+
    )
    '''
)


def _normalize_name(value: str) -> str:
    snake_case = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return re.sub(r"[^a-z0-9]+", "_", snake_case.lower()).strip("_")


def _is_credential_hash_key(normalized_key: str) -> bool:
    parts = set(normalized_key.split("_"))
    credential_terms = {
        "password",
        "passwd",
        "pwd",
        "credential",
        "credentials",
        "token",
        "secret",
    }
    hash_terms = {"hash", "hmac", "digest"}
    return bool(parts & credential_terms and parts & hash_terms)


def _is_sensitive_key(key: str) -> bool:
    normalized = _normalize_name(key)
    if not normalized:
        return False
    if normalized.endswith(_METADATA_SUFFIXES):
        return False
    if normalized in _SENSITIVE_EXACT_KEYS or _is_credential_hash_key(normalized):
        return True
    if normalized.endswith(
        (
            "_authorization",
            "_cookie",
            "_cookies",
            "_password",
            "_passwd",
            "_passphrase",
            "_api_key",
            "_token",
            "_secret",
            "_credential",
            "_credentials",
            "_private_key",
            "_hmac_key",
            "_signing_key",
            "_encryption_key",
        )
    ):
        return True
    return "api_key" in normalized


def _is_sensitive_query_key(key: str) -> bool:
    normalized = _normalize_name(unquote_plus(key))
    return (
        normalized in _SENSITIVE_QUERY_KEYS
        or _is_sensitive_key(normalized)
        or normalized.endswith(("_signature", "_credential"))
    )


def _sanitize_parameter_string(value: str) -> str:
    parts = re.split(r"([&;])", value)
    sanitized: list[str] = []
    for part in parts:
        if part in {"&", ";"} or not part:
            sanitized.append(part)
            continue
        name, separator, raw_value = part.partition("=")
        if _is_sensitive_query_key(name):
            sanitized.append(f"{name}={REDACTION_MARKER}")
        else:
            sanitized.append(part if separator else name)
    return "".join(sanitized)


def _sanitize_fragment(value: str) -> str:
    if not value:
        return value
    if any(separator in value for separator in ("=", "&", ";")):
        return _sanitize_parameter_string(value)
    return _scrub_plaintext(value)


def _fallback_sanitize_url(value: str) -> str:
    sanitized = re.sub(
        r"(?i)([a-z][a-z0-9+.-]*://)([^/@\s]+)@",
        rf"\1{URL_REDACTION_MARKER}@",
        value,
    )
    scheme = sanitized.partition("://")[0].lower()
    if scheme in _DATABASE_URL_SCHEMES:
        return sanitized.split("?", 1)[0].split("#", 1)[0]
    base_and_query, fragment_separator, fragment = sanitized.partition("#")
    base, query_separator, query = base_and_query.partition("?")
    if query_separator:
        base_and_query = f"{base}?{_sanitize_parameter_string(query)}"
    if fragment_separator:
        return f"{base_and_query}#{_sanitize_fragment(fragment)}"
    return base_and_query


def sanitize_url(value: str) -> str:
    """Remove URL user information and redact sensitive query/fragment values."""

    if not isinstance(value, str):
        raise TypeError("sanitize_url expects a string")
    if not value:
        return value
    try:
        parsed = urlsplit(value)
    except ValueError:
        return _fallback_sanitize_url(value)

    if parsed.scheme.lower() in _DATABASE_URL_SCHEMES:
        # Connection options can contain nested or provider-specific secrets
        # (for example MongoDB authMechanismProperties).  They are not useful
        # in logs or public provenance, so omit them rather than attempting to
        # maintain an inevitably incomplete option-name denylist.
        query = ""
        fragment = ""
    else:
        query = _sanitize_parameter_string(parsed.query)
        fragment = _sanitize_fragment(parsed.fragment)

    if not parsed.netloc:
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, fragment))

    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return _fallback_sanitize_url(value)
    if not hostname:
        return _fallback_sanitize_url(value)

    host = f"[{hostname}]" if ":" in hostname and not hostname.startswith("[") else hostname
    netloc = f"{host}:{port}" if port is not None else host
    if parsed.username is not None or parsed.password is not None:
        netloc = f"{URL_REDACTION_MARKER}@{netloc}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, query, fragment))


def _sanitize_urls_in_text(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        candidate = match.group(0)
        trailing = ""
        while candidate and candidate[-1] in ".,);]}":
            trailing = candidate[-1] + trailing
            candidate = candidate[:-1]
        return sanitize_url(candidate) + trailing

    return _URL_PATTERN.sub(replace, value)


def _scrub_plaintext(value: str) -> str:
    sanitized = _sanitize_urls_in_text(value)
    sanitized = _HEADER_LINE_PATTERN.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTION_MARKER}",
        sanitized,
    )
    sanitized = _AUTH_VALUE_PATTERN.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTION_MARKER}",
        sanitized,
    )
    sanitized = _BEARER_PATTERN.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTION_MARKER}",
        sanitized,
    )
    sanitized = _COOKIE_VALUE_PATTERN.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTION_MARKER}",
        sanitized,
    )
    sanitized = _QUOTED_SECRET_ASSIGNMENT_PATTERN.sub(
        lambda match: (
            f"{match.group(1)}{match.group(2)}{match.group(1)}"
            f"{match.group(3)}{REDACTION_MARKER}"
        ),
        sanitized,
    )
    return _SECRET_ASSIGNMENT_PATTERN.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTION_MARKER}",
        sanitized,
    )


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    if limit <= len(TRUNCATION_MARKER):
        return TRUNCATION_MARKER[:limit]
    return value[: limit - len(TRUNCATION_MARKER)] + TRUNCATION_MARKER


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON constant {value!r}")


def _mapping_key_text(key: Any) -> str:
    converted = to_jsonable(key)
    if converted is None:
        return "None"
    if isinstance(converted, (str, bool, int, float)):
        return str(converted)
    raise TypeError(
        "sensitive-data mapping keys must normalize to a JSON scalar, got "
        f"{converted.__class__.__module__}.{converted.__class__.__qualname__}"
    )


def _redact_string(
    value: str,
    *,
    key: str,
    policy: _RedactionPolicy,
    depth: int,
    active_container_ids: set[int],
) -> str:
    if _is_sensitive_key(key):
        return value if value == "" else REDACTION_MARKER

    stripped = value.strip()
    looks_like_json = stripped.startswith(("{", "["))
    if looks_like_json:
        if len(value) > policy.max_embedded_json_chars:
            return OVERSIZED_JSON_MARKER
        try:
            decoded = json.loads(value, parse_constant=_reject_json_constant)
        except (json.JSONDecodeError, ValueError, RecursionError):
            pass
        else:
            if isinstance(decoded, (Mapping, list)):
                redacted = _redact(
                    decoded,
                    key=key,
                    policy=policy,
                    depth=depth + 1,
                    active_container_ids=active_container_ids,
                )
                try:
                    rendered = json.dumps(
                        to_jsonable(redacted),
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    )
                except (TypeError, ValueError, RecursionError):
                    return _truncate(_scrub_plaintext(value), policy.max_string_chars)
                if len(rendered) > policy.max_string_chars:
                    return OVERSIZED_JSON_MARKER
                return rendered

    normalized_key = _normalize_name(key)
    if (
        normalized_key in _URL_VALUE_KEYS
        or normalized_key.endswith(("_url", "_uri", "_href", "_endpoint"))
    ):
        value = sanitize_url(value)
    value = _scrub_plaintext(value)
    return _truncate(value, policy.max_string_chars)


def _redact(
    value: Any,
    *,
    key: str,
    policy: _RedactionPolicy,
    depth: int,
    active_container_ids: set[int],
) -> Any:
    if depth > policy.max_depth:
        return REDACTION_MARKER
    if _is_sensitive_key(key):
        if value is None or (isinstance(value, str) and value == ""):
            return value
        return REDACTION_MARKER

    if isinstance(value, BaseException):
        try:
            text = str(value)
        except Exception:
            text = value.__class__.__name__
        return _redact_string(
            text,
            key=key,
            policy=policy,
            depth=depth,
            active_container_ids=active_container_ids,
        )

    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        identity = id(value)
        if identity in active_container_ids:
            return REDACTION_MARKER
        active_container_ids.add(identity)
        try:
            return {
                field.name: _redact(
                    getattr(value, field.name),
                    key=field.name,
                    policy=policy,
                    depth=depth + 1,
                    active_container_ids=active_container_ids,
                )
                for field in dataclasses.fields(value)
            }
        finally:
            active_container_ids.remove(identity)

    if isinstance(value, Mapping):
        identity = id(value)
        if identity in active_container_ids:
            return REDACTION_MARKER
        active_container_ids.add(identity)
        try:
            result: dict[str, Any] = {}
            collision_counts: dict[str, int] = {}
            for raw_key, item in value.items():
                original_key = _mapping_key_text(raw_key)
                safe_key = _truncate(_scrub_plaintext(original_key), 512)
                if safe_key in result:
                    collision_counts[safe_key] = collision_counts.get(safe_key, 1) + 1
                    safe_key = f"{safe_key}#{collision_counts[safe_key]}"
                result[safe_key] = _redact(
                    item,
                    key=original_key,
                    policy=policy,
                    depth=depth + 1,
                    active_container_ids=active_container_ids,
                )
            return result
        finally:
            active_container_ids.remove(identity)

    if isinstance(value, (list, tuple)):
        identity = id(value)
        if identity in active_container_ids:
            return REDACTION_MARKER
        active_container_ids.add(identity)
        try:
            return [
                _redact(
                    item,
                    key=key,
                    policy=policy,
                    depth=depth + 1,
                    active_container_ids=active_container_ids,
                )
                for item in value
            ]
        finally:
            active_container_ids.remove(identity)

    if isinstance(value, (set, frozenset)):
        redacted = [
            _redact(
                item,
                key=key,
                policy=policy,
                depth=depth + 1,
                active_container_ids=active_container_ids,
            )
            for item in value
        ]
        return sorted(
            redacted,
            key=lambda item: json.dumps(
                to_jsonable(item),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ),
        )

    converted = to_jsonable(value)
    if isinstance(converted, str):
        return _redact_string(
            converted,
            key=key,
            policy=policy,
            depth=depth,
            active_container_ids=active_container_ids,
        )
    return converted


def _redact_with_limit(value: Any, max_string_chars: int) -> Any:
    if isinstance(max_string_chars, bool) or not isinstance(max_string_chars, int):
        raise TypeError("max_string_chars must be an integer")
    if max_string_chars <= 0:
        raise ValueError("max_string_chars must be positive")
    return _redact(
        value,
        key="",
        policy=_RedactionPolicy(max_string_chars=max_string_chars),
        depth=0,
        active_container_ids=set(),
    )


def redact_for_api(
    value: Any,
    *,
    max_string_chars: int = MAX_API_STRING_CHARS,
) -> Any:
    """Return a redacted, JSON-safe API representation."""

    return _redact_with_limit(value, max_string_chars)


def redact_for_log(
    value: Any,
    *,
    max_string_chars: int = MAX_LOG_STRING_CHARS,
) -> Any:
    """Return a compact redacted representation suitable for structured logs."""

    return _redact_with_limit(value, max_string_chars)


def redact_for_artifact(
    value: Any,
    *,
    max_string_chars: int = MAX_ARTIFACT_STRING_CHARS,
) -> Any:
    """Return a redacted representation suitable for generated artifacts."""

    return _redact_with_limit(value, max_string_chars)


def redact_for_webhook(
    value: Any,
    *,
    max_string_chars: int = MAX_WEBHOOK_STRING_CHARS,
) -> Any:
    """Return a redacted representation suitable for outbound webhooks."""

    return _redact_with_limit(value, max_string_chars)


__all__ = [
    "MAX_API_STRING_CHARS",
    "MAX_ARTIFACT_STRING_CHARS",
    "MAX_EMBEDDED_JSON_CHARS",
    "MAX_LOG_STRING_CHARS",
    "MAX_WEBHOOK_STRING_CHARS",
    "OVERSIZED_JSON_MARKER",
    "REDACTION_MARKER",
    "redact_for_api",
    "redact_for_artifact",
    "redact_for_log",
    "redact_for_webhook",
    "sanitize_url",
]
