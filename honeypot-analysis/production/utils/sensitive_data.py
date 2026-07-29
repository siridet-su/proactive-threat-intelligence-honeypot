"""Central sensitive-data redaction helpers.

The helpers in this module intentionally return JSON-safe data while preserving
the surrounding document shape.  They are suitable for API responses, logs,
artifacts and webhook payloads; raw telemetry storage remains a separate,
explicit trust boundary.
"""

from __future__ import annotations

import dataclasses
import json
import posixpath
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote_plus, urlsplit, urlunsplit

from production.utils.credential_hmac import (
    credential_metadata_for_provenance,
    is_credential_hmac_digest,
)
from production.utils.serialization import stable_id, to_jsonable


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

COWRIE_CREDENTIAL_SANITIZER_SCHEMA = "cowrie_credential_sanitizer.v1"
_COWRIE_CREDENTIAL_KEYS = frozenset(
    {
        "username",
        "user_name",
        "login_username",
        "password",
        "passwd",
        "pwd",
        "login_password",
    }
)
# Cowrie login messages are human-readable summaries, not authoritative
# evidence.  Cowrie's stock format embeds ``[username/password]`` in this
# field, so redact the complete login message instead of attempting to parse a
# password format that could change between Cowrie versions.
_COWRIE_CREDENTIAL_METADATA_FIELDS = _COWRIE_CREDENTIAL_KEYS | {"message"}
_COWRIE_LOGIN_EVENT_PREFIX = "cowrie.login."


_SAFE_EXCEPTION_CATEGORIES = (
    TimeoutError,
    ConnectionError,
    PermissionError,
    FileNotFoundError,
    FileExistsError,
    NotADirectoryError,
    IsADirectoryError,
    ImportError,
    RuntimeError,
    TypeError,
    ValueError,
    OSError,
    Exception,
)
_SAFE_ERROR_SUMMARIES = frozenset(
    {f"{exception_type.__name__}: operation_failed" for exception_type in _SAFE_EXCEPTION_CATEGORIES}
    | {"BaseException: operation_failed"}
)


@dataclass(frozen=True)
class _RedactionPolicy:
    max_string_chars: int
    max_embedded_json_chars: int = MAX_EMBEDDED_JSON_CHARS
    max_depth: int = MAX_REDACTION_DEPTH
    preserve_credential_hmac: bool = False


_METADATA_SUFFIXES = (
    "_configured",
    "_enabled",
    "_present",
    "_available",
    "_count",
    "_length",
)

_SAFE_SENSITIVE_CONTAINER_KEYS = {
    "credential_metadata",
}

_SENSITIVE_KEY_TOKENS = {
    "auth",
    "authorization",
    "authorizations",
    "bearer",
    "cookie",
    "cookies",
    "credential",
    "credentials",
    "passphrase",
    "passphrases",
    "passwd",
    "password",
    "passwords",
    "pwd",
    "secret",
    "secrets",
    "token",
    "tokens",
}

_SENSITIVE_EXACT_KEYS = {
    "authorization",
    "proxy_authorization",
    "cookie",
    "cookies",
    "set_cookie",
    "password",
    "passwd",
    "pwd",
    "username",
    "user_name",
    "login_username",
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


def sanitize_cowrie_event_for_persistence(event: Mapping[str, Any]) -> Dict[str, Any]:
    """Return an idempotent Cowrie event with credential plaintext removed.

    This is intentionally narrower than the public-output redactor: it preserves
    the event shape needed by the durable worker while replacing only known
    login credential fields.  The metadata contains field names and presence
    only; it never contains attacker-supplied values.
    """

    if not isinstance(event, Mapping):
        raise ValueError("Cowrie event must be an object")

    redacted_fields: set[str] = set()

    def sanitize(value: Any, depth: int = 0) -> Any:
        if depth > MAX_REDACTION_DEPTH:
            return OVERSIZED_JSON_MARKER
        if isinstance(value, Mapping):
            output: Dict[str, Any] = {}
            for raw_key, item in value.items():
                key = str(raw_key)
                normalized = key.strip().lower()
                if normalized in _COWRIE_CREDENTIAL_KEYS:
                    if item not in (None, "", REDACTION_MARKER):
                        redacted_fields.add(normalized)
                    elif item == REDACTION_MARKER:
                        redacted_fields.add(normalized)
                    output[key] = REDACTION_MARKER if item not in (None, "") else item
                else:
                    output[key] = sanitize(item, depth + 1)
            return output
        if isinstance(value, list):
            return [sanitize(item, depth + 1) for item in value]
        if isinstance(value, tuple):
            return [sanitize(item, depth + 1) for item in value]
        return value

    sanitized = sanitize(event)
    if not isinstance(sanitized, dict):  # pragma: no cover - guarded above
        raise ValueError("sanitized Cowrie event must be an object")

    # A top-level ``message`` on Cowrie login events can contain plaintext
    # credentials even though it is not itself a credential-named key.  This
    # boundary is deliberately fail-closed: no login summary is needed by the
    # durable pipeline, while preserving it risks persisting a password.
    event_id = str(sanitized.get("eventid") or "").strip().lower()
    if event_id.startswith(_COWRIE_LOGIN_EVENT_PREFIX):
        message = sanitized.get("message")
        if isinstance(message, str):
            if message:
                redacted_fields.add("message")
            sanitized["message"] = REDACTION_MARKER if message else message

    prior = event.get("_honeypot_privacy")
    prior_fields = []
    if isinstance(prior, Mapping):
        prior_fields = [
            str(item).strip().lower()
            for item in prior.get("credential_fields_redacted", []) or []
            if str(item).strip().lower() in _COWRIE_CREDENTIAL_METADATA_FIELDS
        ]
    all_fields = sorted(redacted_fields | set(prior_fields))
    if all_fields:
        sanitized["_honeypot_privacy"] = {
            "schema_version": COWRIE_CREDENTIAL_SANITIZER_SCHEMA,
            "credential_plaintext_removed": True,
            "credential_fields_redacted": all_fields,
        }
    else:
        sanitized.pop("_honeypot_privacy", None)
    return sanitized

_URL_PATTERN = re.compile(
    r"\b[a-z][a-z0-9+.-]*://[^\s<>'\"]+",
    flags=re.IGNORECASE,
)
_HEADER_LINE_PATTERN = re.compile(
    r"(?im)^([ \t]*(?:authorization|proxy-authorization|cookie|set-cookie))"
    r"(\s*:\s*)[^\r\n]*"
)
_QUOTED_HEADER_VALUE_PATTERNS = (
    re.compile(
        r"(?i)(')(authorization|proxy-authorization|cookie|set-cookie)"
        r"(\s*:\s*)(?:(?:bearer|basic)\s+)?(?:\\.|[^'\\])*"
        r"(?:'|(?=[\r\n;&|]|\Z))"
    ),
    re.compile(
        r'(?i)(\")(authorization|proxy-authorization|cookie|set-cookie)'
        r'(\s*:\s*)(?:(?:bearer|basic)\s+)?(?:\\.|[^"\\])*'
        r'(?:"|(?=[\r\n;&|]|\Z))'
    ),
)
_AUTH_VALUE_PATTERN = re.compile(
    r"(?i)\b(authorization|proxy[_-]?authorization)"
    r"(\s*[:=]\s*)(?:(?:bearer|basic)\s+)?[^\s,;'\"]+"
)
_BEARER_PATTERN = re.compile(
    r"(?i)\b(bearer|basic)(\s+)[a-z0-9._~+/=-]+"
)
_COOKIE_VALUE_PATTERN = re.compile(
    r"(?i)\b(cookie|cookies|set[_-]?cookie)(\s*[=:]\s*)[^'\"\r\n]+"
)
_SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"""(?ix)
    \b(
        authorization|proxy[_-]?authorization|cookie|cookies|set[_-]?cookie|
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
    (?!['"](?=\s|[,;&}\]]|\Z))
    (
        "(?:\\.|[^"\\])*" |
        "(?:\\.|[^"\\])*(?=[\r\n,;&}\]]|\Z) |
        '(?:\\.|[^'\\])*' |
        '(?:\\.|[^'\\])*(?=[\r\n,;&}\]]|\Z) |
        [^\s,;&'\"]+
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
        \[REDACTED\] |
        "(?:\\.|[^"\\])*" |
        "(?:\\.|[^"\\])*(?=[\r\n,;&}\]]|\Z) |
        '(?:\\.|[^'\\])*' |
        '(?:\\.|[^'\\])*(?=[\r\n,;&}\]]|\Z) |
        [^\s,;&}\]'\"]+
    )
    '''
)
_SHELL_SECRET_VALUE_PATTERN = (
    r'''(?:(?:\\[^\r\n])|"(?:\\.|[^"\\])*(?:"|(?=[\r\n;&|]|\Z))|'''
    r'''(?:'(?:\\.|[^'\\])*(?:'|(?=[\r\n;&|]|\Z)))|[^\s;&|\\'\"]+)+'''
)
_GENERIC_SECRET_LONG_OPTIONS = {
    "api-key",
    "api-token",
    "auth-token",
    "authorization",
    "bearer-token",
    "client-secret",
    "credential",
    "credentials",
    "password",
    "passphrase",
    "private-key",
    "secret",
    "token",
}


def _is_generic_secret_long_option(option_name: str) -> bool:
    normalized = option_name.replace("-", "_").lower()
    if option_name.lower() in _GENERIC_SECRET_LONG_OPTIONS:
        return True
    return any(
        normalized == suffix or normalized.endswith(f"_{suffix}")
        for suffix in (
            "access_key",
            "api_key",
            "credential",
            "credentials",
            "password",
            "passphrase",
            "private_key",
            "secret",
            "secret_key",
            "token",
        )
    )
_ENV_SECRET_ASSIGNMENT_PATTERN = re.compile(
    rf"""(?ix)
    (\b(?:export\s+)?)
    ([A-Z_][A-Z0-9_]*)
    (\s*=\s*)
    ({_SHELL_SECRET_VALUE_PATTERN})
    """
)
_PRIVATE_KEY_BLOCK_PATTERN = re.compile(
    r"-----BEGIN (?P<label>PRIVATE KEY|"
    r"[A-Z0-9][A-Z0-9 -]{0,72} PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----.*?"
    r"(?:-----END (?P=label)-----|\Z)",
    flags=re.IGNORECASE | re.DOTALL,
)
_CREDENTIAL_HMAC_PLAINTEXT_PATTERN = re.compile(
    r"(?<![A-Za-z0-9._-])hmac-sha256-v1:"
    r"[A-Za-z0-9._-]{1,64}:[0-9a-fA-F]{64}"
    r"(?![0-9a-fA-F])"
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


def _has_sensitive_key_semantics(normalized: str) -> bool:
    if normalized in _SENSITIVE_EXACT_KEYS or _is_credential_hash_key(normalized):
        return True
    if any(
        compound in normalized
        for compound in (
            "access_key",
            "api_key",
            "encryption_key",
            "hmac_key",
            "private_key",
            "signing_key",
        )
    ):
        return True
    return bool(set(normalized.split("_")) & _SENSITIVE_KEY_TOKENS)


def _is_sensitive_key(key: str, value: Any = None) -> bool:
    normalized = _normalize_name(key)
    if not normalized:
        return False
    if normalized in _SAFE_SENSITIVE_CONTAINER_KEYS:
        return False
    if normalized == "credential_policy" and isinstance(value, Mapping):
        return False
    if normalized == "source_addresses_or_credentials_accepted" and isinstance(
        value, bool
    ):
        return False
    if normalized.startswith(("has_", "contains_", "is_")) and isinstance(
        value, bool
    ):
        return False
    if not _has_sensitive_key_semantics(normalized):
        return False
    if normalized.endswith(("_count", "_length", "_limit", "_budget", "_used")):
        return not (isinstance(value, int) and not isinstance(value, bool))
    if normalized.endswith(
        ("_available", "_configured", "_enabled", "_observed", "_present", "_stored")
    ):
        return not isinstance(value, bool)
    return True


def _is_sensitive_query_key(key: str) -> bool:
    normalized = _normalize_name(unquote_plus(key))
    return (
        normalized in _SENSITIVE_QUERY_KEYS
        or _has_sensitive_key_semantics(normalized)
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


@dataclass(frozen=True)
class _ShellToken:
    start: int
    end: int
    raw: str
    decoded: str


def _decode_shell_token(raw: str) -> str:
    decoded: list[str] = []
    quote = ""
    index = 0
    while index < len(raw):
        char = raw[index]
        if quote:
            if char == quote:
                quote = ""
            elif char == "\\" and quote == '"' and index + 1 < len(raw):
                index += 1
                if raw[index] not in "\r\n":
                    decoded.append(raw[index])
            else:
                decoded.append(char)
        elif char in {"'", '"'}:
            quote = char
        elif char == "\\" and index + 1 < len(raw):
            index += 1
            if raw[index] not in "\r\n":
                decoded.append(raw[index])
        else:
            decoded.append(char)
        index += 1
    return "".join(decoded)


def _shell_token_segments(value: str) -> list[list[_ShellToken]]:
    """Tokenize shell-like text while retaining source spans and quote state."""

    segments: list[list[_ShellToken]] = []
    current: list[_ShellToken] = []
    index = 0
    while index < len(value):
        while index < len(value) and value[index].isspace():
            if value[index] in "\r\n" and current:
                segments.append(current)
                current = []
            index += 1
        if index >= len(value):
            break
        if value[index] in ";&|()`":
            if current:
                segments.append(current)
                current = []
            index += 1
            continue

        start = index
        quote = ""
        while index < len(value):
            char = value[index]
            if quote:
                if char == quote:
                    quote = ""
                elif char == "\\" and quote == '"' and index + 1 < len(value):
                    index += 1
            elif char in {"'", '"'}:
                quote = char
            elif char == "\\" and index + 1 < len(value):
                index += 1
            elif char.isspace() or char in ";&|()`":
                break
            index += 1
        raw = value[start:index]
        current.append(
            _ShellToken(
                start=start,
                end=index,
                raw=raw,
                decoded=_decode_shell_token(raw),
            )
        )
    if current:
        segments.append(current)
    return segments


def _shell_command_name(token: _ShellToken) -> str:
    unwrapped = token.decoded.lstrip("(${")
    return unwrapped.rsplit("/", 1)[-1].lower()


def _redacted_shell_value(raw: str) -> str:
    if len(raw) >= 2 and raw[0] in {"'", '"'} and raw[-1] == raw[0]:
        return f"{raw[0]}{REDACTION_MARKER}{raw[0]}"
    return REDACTION_MARKER


def _scrub_shell_command_secrets(value: str) -> str:
    replacements: dict[tuple[int, int], str] = {}

    def replace_token(token: _ShellToken) -> None:
        replacements[(token.start, token.end)] = _redacted_shell_value(token.raw)

    def replace_attached(token: _ShellToken, value_offset: int) -> None:
        if value_offset >= len(token.raw):
            return
        raw_value = token.raw[value_offset:]
        replacements[(token.start + value_offset, token.end)] = (
            _redacted_shell_value(raw_value)
        )

    def replace_decoded_attached(token: _ShellToken, value_offset: int) -> None:
        if token.raw == token.decoded:
            replace_attached(token, value_offset)
        elif token.raw.startswith(token.decoded[:value_offset]):
            replace_attached(token, value_offset)
        elif (
            len(token.raw) >= 2
            and token.raw[0] in {"'", '"'}
            and token.raw[-1] == token.raw[0]
        ):
            replacements[(token.start, token.end)] = (
                f"{token.raw[0]}{token.decoded[:value_offset]}"
                f"{REDACTION_MARKER}{token.raw[0]}"
            )
        else:
            replace_token(token)

    for tokens in _shell_token_segments(value):
        command_names = [_shell_command_name(token) for token in tokens]

        for option_index, option in enumerate(tokens):
            raw_option = option.raw
            decoded_option = option.decoded
            long_match = re.fullmatch(
                r"--([A-Za-z0-9][A-Za-z0-9_-]*)(?:=(.*))?",
                decoded_option,
                flags=re.DOTALL,
            )
            if not long_match:
                continue
            option_name = long_match.group(1).replace("_", "-").lower()
            if not _is_generic_secret_long_option(option_name):
                continue
            has_attached_value = long_match.group(2) is not None
            mysql_before = bool(command_names) and command_names[0] in {
                "mysql",
                "mysqladmin",
                "mysqldump",
            }
            if option_name == "password" and mysql_before and not has_attached_value:
                continue
            if has_attached_value:
                replace_decoded_attached(option, long_match.start(2))
            elif option_index + 1 < len(tokens):
                replace_token(tokens[option_index + 1])

        for executable_index, executable_name in enumerate(command_names):
            if executable_name not in {
                "curl",
                "docker",
                "mysql",
                "mysqladmin",
                "mongosh",
                "mysqldump",
                "openssl",
                "redis-cli",
                "smbclient",
                "sshpass",
            }:
                continue
            docker_login_index = None
            if executable_name == "docker":
                docker_login_index = next(
                    (
                        index
                        for index in range(executable_index + 1, len(tokens))
                        if command_names[index] == "login"
                    ),
                    None,
                )
            for option_index in range(executable_index + 1, len(tokens)):
                option = tokens[option_index]
                raw_option = option.raw
                decoded_option = option.decoded
                lower_option = decoded_option.lower()

                if executable_name == "sshpass":
                    if decoded_option == "-p" or lower_option == "--password":
                        if option_index + 1 < len(tokens):
                            replace_token(tokens[option_index + 1])
                    elif decoded_option.startswith("-p="):
                        replace_decoded_attached(option, 3)
                    elif decoded_option.startswith("-p") and len(decoded_option) > 2:
                        replace_decoded_attached(option, 2)
                    elif lower_option.startswith("--password="):
                        replace_decoded_attached(
                            option, decoded_option.index("=") + 1
                        )

                elif executable_name in {"mysql", "mysqladmin", "mysqldump"}:
                    if decoded_option.startswith("-p") and len(decoded_option) > 2:
                        offset = 3 if decoded_option.startswith("-p=") else 2
                        replace_decoded_attached(option, offset)
                    elif lower_option.startswith("--password="):
                        replace_decoded_attached(
                            option, decoded_option.index("=") + 1
                        )

                elif executable_name == "redis-cli":
                    if decoded_option == "-a" or lower_option == "--pass":
                        if option_index + 1 < len(tokens):
                            replace_token(tokens[option_index + 1])
                    elif decoded_option.startswith("-a="):
                        replace_decoded_attached(option, 3)
                    elif decoded_option.startswith("-a") and len(decoded_option) > 2:
                        replace_decoded_attached(option, 2)
                    elif lower_option.startswith("--pass="):
                        replace_decoded_attached(
                            option, decoded_option.index("=") + 1
                        )

                elif executable_name in {"docker", "mongosh"}:
                    docker_login = executable_name != "docker" or (
                        docker_login_index is not None
                        and docker_login_index < option_index
                    )
                    if not docker_login:
                        continue
                    if decoded_option == "-p":
                        if option_index + 1 < len(tokens):
                            replace_token(tokens[option_index + 1])
                    elif decoded_option.startswith("-p="):
                        replace_decoded_attached(option, 3)
                    elif decoded_option.startswith("-p") and len(decoded_option) > 2:
                        replace_decoded_attached(option, 2)

                elif executable_name == "smbclient":
                    if decoded_option == "-U" and option_index + 1 < len(tokens):
                        candidate = tokens[option_index + 1]
                        if "%" in candidate.decoded:
                            replace_token(candidate)
                    elif decoded_option.startswith("-U") and len(decoded_option) > 2:
                        candidate = decoded_option[2:]
                        if "%" in candidate:
                            replace_decoded_attached(option, 2)

                elif executable_name == "openssl":
                    if lower_option in {"-passin", "-passout"} and option_index + 1 < len(tokens):
                        candidate = tokens[option_index + 1]
                        if candidate.decoded.lower().startswith("pass:"):
                            replace_token(candidate)

                elif executable_name == "curl":
                    is_user_option = decoded_option in {"-u", "-U"} or lower_option in {
                        "--user",
                        "--proxy-user",
                    }
                    if is_user_option and option_index + 1 < len(tokens):
                        candidate = tokens[option_index + 1]
                        if ":" in candidate.decoded:
                            replace_token(candidate)
                    else:
                        attached_prefix = next(
                            (
                                prefix
                                for prefix in (
                                    "-u=",
                                    "-U=",
                                    "-u",
                                    "-U",
                                    "--user=",
                                    "--proxy-user=",
                                )
                                if (
                                    decoded_option.startswith(prefix)
                                    if prefix.startswith("-") and not prefix.startswith("--")
                                    else lower_option.startswith(prefix.lower())
                                )
                                and len(decoded_option) > len(prefix)
                            ),
                            "",
                        )
                        if attached_prefix:
                            decoded_candidate = decoded_option[len(attached_prefix):]
                            if ":" in decoded_candidate:
                                replace_decoded_attached(option, len(attached_prefix))
            break

    sanitized = value
    for (start, end), replacement in sorted(
        replacements.items(),
        key=lambda item: item[0][0],
        reverse=True,
    ):
        sanitized = sanitized[:start] + replacement + sanitized[end:]
    return sanitized


def _scrub_plaintext(value: str) -> str:
    sanitized = _PRIVATE_KEY_BLOCK_PATTERN.sub(REDACTION_MARKER, value)
    sanitized = _CREDENTIAL_HMAC_PLAINTEXT_PATTERN.sub(
        REDACTION_MARKER,
        sanitized,
    )
    sanitized = _sanitize_urls_in_text(sanitized)
    sanitized = _HEADER_LINE_PATTERN.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTION_MARKER}",
        sanitized,
    )
    for pattern in _QUOTED_HEADER_VALUE_PATTERNS:
        sanitized = pattern.sub(
            lambda match: (
                f"{match.group(1)}{match.group(2)}{match.group(3)}"
                f"{REDACTION_MARKER}{match.group(1)}"
            ),
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
    sanitized = _scrub_shell_command_secrets(sanitized)
    sanitized = _ENV_SECRET_ASSIGNMENT_PATTERN.sub(
        _replace_env_secret,
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


def _replace_env_secret(match: re.Match[str]) -> str:
    name = match.group(2).upper()
    raw_value = match.group(4)
    decoded_value = _decode_shell_token(raw_value).strip()
    if name.endswith(("_COUNT", "_LENGTH")) and decoded_value.isdigit():
        return match.group(0)
    if name.endswith(("_AVAILABLE", "_CONFIGURED", "_ENABLED", "_PRESENT")):
        if decoded_value.lower() in {"0", "1", "false", "no", "off", "on", "true", "yes"}:
            return match.group(0)
    if name.endswith(("_FILE", "_PATH")) and decoded_value.startswith("/"):
        return match.group(0)
    if name.endswith("_POLICY") and decoded_value.lower() in {
        "default",
        "disabled",
        "enabled",
        "optional",
        "redact",
        "redacted",
        "required",
        "strict",
    }:
        return match.group(0)
    exact_sensitive_names = {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "MYSQL_PWD",
        "PGPASSWORD",
        "REDISCLI_AUTH",
        "SSHPASS",
    }
    sensitive_terms = (
        "PASSWORD",
        "PASSWD",
        "PASSPHRASE",
        "SECRET",
        "TOKEN",
        "API_KEY",
        "ACCESS_KEY",
        "CLIENT_SECRET",
        "PRIVATE_KEY",
        "CREDENTIAL",
        "CREDENTIALS",
    )
    is_sensitive = name in exact_sensitive_names or any(
        name == term
        or name.startswith(f"{term}_")
        or name.endswith(term)
        or f"_{term}_" in name
        for term in sensitive_terms
    )
    if not is_sensitive:
        return match.group(0)
    if (
        len(raw_value) >= 2
        and raw_value[0] in {"'", '"'}
        and raw_value[-1] == raw_value[0]
    ):
        replacement = f"{raw_value[0]}{REDACTION_MARKER}{raw_value[0]}"
    else:
        replacement = REDACTION_MARKER
    return f"{match.group(1)}{match.group(2)}{match.group(3)}{replacement}"


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    if limit <= len(TRUNCATION_MARKER):
        return TRUNCATION_MARKER[:limit]
    return value[: limit - len(TRUNCATION_MARKER)] + TRUNCATION_MARKER


_MAX_CREDENTIAL_EVIDENCE_ITEM_CHARS = 512
_CREDENTIAL_TARGET_TRAILING_PUNCTUATION = "'\"`,;]}"
_FIXED_CREDENTIAL_TARGETS = {
    ".aws/credentials",
    ".kube/config",
    ".netrc (FTP/HTTP credentials)",
    ".ssh/authorized_keys",
}
_GCLOUD_CREDENTIAL_TARGET = ".config/gcloud/<credential-file>"
_AZURE_CREDENTIAL_TARGET = ".azure/<credential-file>"
_SSH_PRIVATE_KEY_TARGET = ".ssh/<private-key>"


def _canonical_credential_target(value: str) -> str:
    if len(value) > _MAX_CREDENTIAL_EVIDENCE_ITEM_CHARS:
        return ""
    candidate = value.strip().rstrip(_CREDENTIAL_TARGET_TRAILING_PUNCTUATION)
    if candidate in _FIXED_CREDENTIAL_TARGETS:
        return candidate
    if candidate == _GCLOUD_CREDENTIAL_TARGET or (
        candidate.startswith(".config/gcloud/")
        and len(candidate) > len(".config/gcloud/")
    ):
        return _GCLOUD_CREDENTIAL_TARGET
    if candidate == _AZURE_CREDENTIAL_TARGET or (
        candidate.startswith(".azure/")
        and len(candidate) > len(".azure/")
    ):
        return _AZURE_CREDENTIAL_TARGET
    if candidate == _SSH_PRIVATE_KEY_TARGET or re.fullmatch(
        r"\.ssh/id_[^\s/]+",
        candidate,
    ):
        return _SSH_PRIVATE_KEY_TARGET
    return ""


def _credential_targets_for_report(
    value: Any,
    policy: _RedactionPolicy,
) -> Any:
    """Normalize the fixed, non-secret credential-target evidence vocabulary."""

    if not isinstance(value, (list, tuple)):
        return REDACTION_MARKER
    value = value[:_MAX_CREDENTIAL_PATH_ENTITIES]
    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            continue
        canonical = _canonical_credential_target(item)
        if not canonical:
            continue
        safe_item = _truncate(canonical, policy.max_string_chars)
        if safe_item not in seen:
            result.append(safe_item)
            seen.add(safe_item)
    return result


_ENTITY_ID_PATTERN = re.compile(r"entity_[0-9a-f]{32}")
_CREDENTIAL_PATH_VALUE_PATTERN = re.compile(
    r"(?:"
    r"/etc/(?:passwd|shadow)|"
    r"(?:/home/[A-Za-z0-9._-]{1,64}|/root)/(?:"
    r"\.ssh/id_(?:rsa|dsa|ecdsa|ed25519)|"
    r"\.aws/credentials|"
    r"\.config/gcloud(?:/application_default_credentials\.json)?|"
    r"\.env"
    r")|"
    r"(?:~[A-Za-z0-9._-]{0,64}/)?(?:"
    r"\.ssh/id_(?:rsa|dsa|ecdsa|ed25519)|"
    r"\.aws/credentials|"
    r"\.config/gcloud(?:/application_default_credentials\.json)?"
    r")|"
    r"(?:\.config/gcloud(?:/application_default_credentials\.json)?|"
    r"\.aws/credentials|\.ssh/id_(?:rsa|dsa|ecdsa|ed25519))|"
    r"application_default_credentials(?:\.json)?"
    r")"
)
_NORMALIZED_PATH_PATTERN = re.compile(
    r"(?:/|~[^/\r\n]*/|\.\.?/|\$[A-Za-z_][A-Za-z0-9_]*(?:/|$)|relative:)[^\r\n]+"
)
_CREDENTIAL_PATH_UNCERTAINTY_REASONS = {
    "home_directory_not_resolved",
    "shell_expansion_not_resolved",
    "wildcard_path_not_resolved",
    "working_directory_unknown",
}
_MAX_CREDENTIAL_PATH_ENTITIES = 128
_SESSION_CREDENTIAL_HMAC_KEYS = {
    "login_password_hash",
    "login_password_hash_aliases",
    "passwd_hash",
    "passwd_hash_aliases",
    "password_hash",
    "password_hash_aliases",
}
_DERIVED_EVENT_FIELDS = frozenset(
    {
        "CommandLine",
        "UtcTime",
        "_file_hash",
        "_is_shell_node",
        "_session_id",
        "_source_index",
        "_src_ip",
        "_success",
        "agreement_status",
        "arch",
        "command",
        "command_outcome",
        "compound_command_index",
        "confidence",
        "confidence_semantics",
        "cowrie_eventid",
        "cwd",
        "destfile",
        "dst_ip",
        "dst_port",
        "duration",
        "event_timestamp",
        "eventid",
        "evidence_id",
        "hassh",
        "high_confidence",
        "input",
        "ja3",
        "operator_after",
        "operator_before",
        "original_command",
        "outcome_scope",
        "outfile",
        "passwd",
        "password",
        "password_hash",
        "password_hash_aliases",
        "protocol",
        "rule_policy_id",
        "rule_policy_version",
        "sensor",
        "sensor_id",
        "session",
        "session_id",
        "shasum",
        "source",
        "source_subtechnique",
        "source_ttp",
        "src_ip",
        "src_port",
        "subcommand",
        "subcommand_count",
        "subcommand_index",
        "success",
        "tactic",
        "timestamp",
        "ttp",
        "url",
        "username",
        "version",
    }
)


def _credential_hmac_for_session_state(normalized_key: str, value: Any) -> Any:
    if value is None or value == "":
        return value
    if normalized_key.endswith("_aliases"):
        if (
            isinstance(value, (list, tuple))
            and len(value) <= 2
            and all(is_credential_hmac_digest(item) for item in value)
            and len(set(value)) == len(value)
        ):
            return list(value)
        return REDACTION_MARKER
    return value if is_credential_hmac_digest(value) else REDACTION_MARKER


def _derived_raw_events(
    value: Any,
    *,
    policy: _RedactionPolicy,
    depth: int,
    active_container_ids: set[int],
) -> Any:
    """Project raw telemetry onto the fields consumed by derived analytics."""

    if not isinstance(value, (list, tuple)):
        return REDACTION_MARKER
    identity = id(value)
    if identity in active_container_ids:
        return REDACTION_MARKER
    active_container_ids.add(identity)
    try:
        projected: list[dict[str, Any]] = []
        for event in value:
            if not isinstance(event, Mapping):
                continue
            event_identity = id(event)
            if event_identity in active_container_ids:
                continue
            active_container_ids.add(event_identity)
            try:
                projected.append(
                    {
                        field_name: _redact(
                            field_value,
                            key=field_name,
                            policy=policy,
                            depth=depth + 1,
                            active_container_ids=active_container_ids,
                        )
                        for field_name, field_value in event.items()
                        if isinstance(field_name, str)
                        and field_name in _DERIVED_EVENT_FIELDS
                    }
                )
            finally:
                active_container_ids.remove(event_identity)
        return projected
    finally:
        active_container_ids.remove(identity)


def _credential_path_entities_for_report(
    value: Any,
    policy: _RedactionPolicy,
) -> Any:
    """Preserve only canonical, non-secret credential-path evidence entities."""

    if not isinstance(value, (list, tuple)):
        return REDACTION_MARKER
    if len(value) > _MAX_CREDENTIAL_PATH_ENTITIES:
        value = value[:_MAX_CREDENTIAL_PATH_ENTITIES]
    if not value:
        return []
    if all(isinstance(item, str) for item in value):
        paths: list[str] = []
        for item in value:
            if (
                len(item) > _MAX_CREDENTIAL_EVIDENCE_ITEM_CHARS
                or not _CREDENTIAL_PATH_VALUE_PATTERN.fullmatch(item)
            ):
                continue
            safe_path = _truncate(
                _scrub_plaintext(item),
                min(policy.max_string_chars, 2_048),
            )
            if safe_path not in paths:
                paths.append(safe_path)
        return paths
    if not all(isinstance(item, Mapping) for item in value):
        return []
    result: list[dict[str, Any]] = []
    for item in value:
        entity_id = item.get("entity_id")
        entity_type = item.get("entity_type")
        normalized_value = item.get("normalized_value")
        original_value = item.get("original_value")
        uncertain = item.get("uncertain")
        linkable = item.get("linkable")
        if (
            not isinstance(entity_id, str)
            or not _ENTITY_ID_PATTERN.fullmatch(entity_id)
            or entity_type != "path"
            or not isinstance(normalized_value, str)
            or not normalized_value
            or len(normalized_value) > _MAX_CREDENTIAL_EVIDENCE_ITEM_CHARS
            or not _NORMALIZED_PATH_PATTERN.fullmatch(normalized_value)
            or not isinstance(original_value, str)
            or not original_value
            or len(original_value) > _MAX_CREDENTIAL_EVIDENCE_ITEM_CHARS
            or not _CREDENTIAL_PATH_VALUE_PATTERN.fullmatch(original_value)
            or not isinstance(uncertain, bool)
            or not isinstance(linkable, bool)
        ):
            continue
        uncertainty_reason = item.get("uncertainty_reason")
        if uncertainty_reason is not None and (
            not isinstance(uncertainty_reason, str)
            or uncertainty_reason not in _CREDENTIAL_PATH_UNCERTAINTY_REASONS
        ):
            continue
        if original_value.startswith("~"):
            expected_normalized = original_value
            expected_uncertain = True
            expected_linkable = False
            expected_reason = "home_directory_not_resolved"
        elif original_value.startswith("/"):
            expected_normalized = posixpath.normpath(original_value)
            expected_uncertain = False
            expected_linkable = True
            expected_reason = None
        else:
            expected_normalized = f"relative:{posixpath.normpath(original_value)}"
            expected_uncertain = True
            expected_linkable = False
            expected_reason = "working_directory_unknown"
        expected_entity_id = stable_id(
            "entity",
            {"type": "path", "value": expected_normalized},
        )
        if (
            normalized_value != expected_normalized
            or entity_id != expected_entity_id
            or uncertain is not expected_uncertain
            or linkable is not expected_linkable
            or uncertainty_reason != expected_reason
        ):
            continue
        safe_item: dict[str, Any] = {
            "entity_id": entity_id,
            "entity_type": "path",
            "normalized_value": _truncate(
                _scrub_plaintext(normalized_value),
                min(policy.max_string_chars, 2_048),
            ),
            "original_value": _truncate(
                _scrub_plaintext(original_value),
                min(policy.max_string_chars, 2_048),
            ),
            "uncertain": uncertain,
            "linkable": linkable,
        }
        if uncertainty_reason:
            safe_item["uncertainty_reason"] = uncertainty_reason
        result.append(safe_item)
    return result


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
    if _is_sensitive_key(key, value):
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
    # Only a bounded prefix can reach any output context.  Truncate before the
    # plaintext scanners as well, so adversarial padding cannot amplify regex
    # or shell-token processing cost.
    value = _truncate(value, policy.max_string_chars)
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
    normalized_key = _normalize_name(key)
    if (
        policy.preserve_credential_hmac
        and normalized_key in _SESSION_CREDENTIAL_HMAC_KEYS
    ):
        return _credential_hmac_for_session_state(normalized_key, value)
    if normalized_key == "raw_events":
        return _derived_raw_events(
            value,
            policy=policy,
            depth=depth,
            active_container_ids=active_container_ids,
        )
    if normalized_key == "credential_targets":
        return _credential_targets_for_report(value, policy)
    if normalized_key == "credential_paths":
        return _credential_path_entities_for_report(value, policy)
    is_credential_metadata = normalized_key == "credential_metadata"
    if is_credential_metadata:
        value = credential_metadata_for_provenance(value)
    if not is_credential_metadata and _is_sensitive_key(key, value):
        if value is None or (isinstance(value, str) and value == ""):
            return value
        return REDACTION_MARKER

    if isinstance(value, BaseException):
        return redact_exception_for_log(value)

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


def _redact_with_limit(
    value: Any,
    max_string_chars: int,
    *,
    preserve_credential_hmac: bool = False,
) -> Any:
    if isinstance(max_string_chars, bool) or not isinstance(max_string_chars, int):
        raise TypeError("max_string_chars must be an integer")
    if max_string_chars <= 0:
        raise ValueError("max_string_chars must be positive")
    return _redact(
        value,
        key="",
        policy=_RedactionPolicy(
            max_string_chars=max_string_chars,
            preserve_credential_hmac=preserve_credential_hmac,
        ),
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


def redact_exception_for_log(exc: BaseException) -> str:
    """Return a stable error summary without inspecting exception arguments.

    Exception messages can contain attacker-controlled input, credentials, or
    request details without any label that a plaintext redactor can recognize.
    Map subclasses to a small set of developer-controlled categories and never
    call ``str(exc)`` or serialize ``exc.args`` at a log/report boundary.
    """

    category = "BaseException"
    for exception_type in _SAFE_EXCEPTION_CATEGORIES:
        if isinstance(exc, exception_type):
            category = exception_type.__name__
            break
    return f"{category}: operation_failed"


def redact_error_for_log(value: Any) -> str:
    """Keep only error summaries produced by :func:`redact_exception_for_log`."""

    if isinstance(value, str) and value in _SAFE_ERROR_SUMMARIES:
        return value
    return "operation_failed"


def redact_for_artifact(
    value: Any,
    *,
    max_string_chars: int = MAX_ARTIFACT_STRING_CHARS,
) -> Any:
    """Return a redacted representation suitable for generated artifacts."""

    return _redact_with_limit(value, max_string_chars)


def redact_for_session_state(
    value: Any,
    *,
    max_string_chars: int = MAX_ARTIFACT_STRING_CHARS,
) -> Any:
    """Redact derived session state while retaining validated keyed HMACs."""

    return _redact_with_limit(
        value,
        max_string_chars,
        preserve_credential_hmac=True,
    )


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
    "redact_error_for_log",
    "redact_exception_for_log",
    "redact_for_api",
    "redact_for_artifact",
    "redact_for_log",
    "redact_for_session_state",
    "redact_for_webhook",
    "sanitize_url",
]
