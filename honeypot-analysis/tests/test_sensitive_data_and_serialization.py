from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from uuid import UUID

import pytest

from production.utils.sensitive_data import (
    MAX_EMBEDDED_JSON_CHARS,
    OVERSIZED_JSON_MARKER,
    REDACTION_MARKER,
    redact_for_api,
    redact_for_artifact,
    redact_for_log,
    redact_for_webhook,
    sanitize_url,
)
from production.utils.feedback import normalize_feedback_payload
from production.utils.serialization import html_script_json, stable_json, to_jsonable


REDACTORS = (
    redact_for_api,
    redact_for_log,
    redact_for_artifact,
    redact_for_webhook,
)


@pytest.mark.parametrize("redactor", REDACTORS)
def test_all_redaction_contexts_remove_nested_secrets_and_keep_safe_metadata(
    redactor,
) -> None:
    payload = {
        "Authorization": "Bearer auth-secret",
        "headers": {
            "Cookie": "session=cookie-secret",
            "X-API-Key": "api-key-secret",
        },
        "password": "plain-password",
        "client_secret": "client-secret",
        "login_password_hash": "sha256:credential-hash",
        "credential_hmac": "hmac:credential-hash",
        "refreshToken": "camel-token-secret",
        "loginPasswordHash": "sha256:camel-credential-hash",
        "file_hash": "sha256:file-integrity-value",
        "features_hash": "sha256:feature-integrity-value",
        "token_count": 17,
        "password_hash_present": True,
        "nested": [
            {
                "refresh-token": "refresh-secret",
                "callback_url": (
                    "https://alice:url-password@example.invalid/callback"
                    "?access_token=query-secret&state=public-state"
                    "#id_token=fragment-secret"
                ),
            }
        ],
        "embedded_json": json.dumps(
            {
                "passwd": "embedded-password",
                "safe": "retained",
            }
        ),
    }

    redacted = redactor(payload)
    encoded = json.dumps(redacted, sort_keys=True)

    for secret in (
        "auth-secret",
        "cookie-secret",
        "api-key-secret",
        "plain-password",
        "client-secret",
        "credential-hash",
        "camel-token-secret",
        "camel-credential-hash",
        "refresh-secret",
        "url-password",
        "query-secret",
        "fragment-secret",
        "embedded-password",
    ):
        assert secret not in encoded

    assert redacted["Authorization"] == REDACTION_MARKER
    assert redacted["headers"]["Cookie"] == REDACTION_MARKER
    assert redacted["headers"]["X-API-Key"] == REDACTION_MARKER
    assert redacted["login_password_hash"] == REDACTION_MARKER
    assert redacted["credential_hmac"] == REDACTION_MARKER
    assert redacted["refreshToken"] == REDACTION_MARKER
    assert redacted["loginPasswordHash"] == REDACTION_MARKER
    assert redacted["file_hash"] == "sha256:file-integrity-value"
    assert redacted["features_hash"] == "sha256:feature-integrity-value"
    assert redacted["token_count"] == 17
    assert redacted["password_hash_present"] is True
    assert redacted["nested"][0]["callback_url"] == (
        "https://<redacted>@example.invalid/callback"
        "?access_token=[REDACTED]&state=public-state"
        "#id_token=[REDACTED]"
    )
    assert json.loads(redacted["embedded_json"]) == {
        "passwd": REDACTION_MARKER,
        "safe": "retained",
    }


def test_sanitize_url_redacts_userinfo_and_only_sensitive_parameters() -> None:
    sanitized = sanitize_url(
        "mongodb://alice:correct-horse@[2001:db8::1]:27017/honeypot"
        "?authSource=admin&apiKey=unit-key&x-amz-signature=unit-signature&page=2"
        "#access_token=fragment-token&section=summary"
    )

    assert sanitized == "mongodb://<redacted>@[2001:db8::1]:27017/honeypot"
    assert sanitize_url("/callback?code=oauth-code&state=public") == (
        "/callback?code=[REDACTED]&state=public"
    )
    with pytest.raises(TypeError, match="expects a string"):
        sanitize_url(None)  # type: ignore[arg-type]


def test_log_redaction_scrubs_plaintext_headers_assignments_urls_and_exceptions() -> None:
    error = RuntimeError(
        "connect mongodb://db-user:db-password@example.invalid/honeypot"
        "?token=query-token\n"
        "Authorization: Bearer bearer-token\n"
        "Cookie: session=cookie-token\n"
        "password_hash=sha256:credential-digest"
    )

    redacted = redact_for_log(error)

    for secret in (
        "db-user",
        "db-password",
        "query-token",
        "bearer-token",
        "cookie-token",
        "credential-digest",
    ):
        assert secret not in redacted
    assert "mongodb://<redacted>@example.invalid/honeypot" in redacted
    assert "?token=" not in redacted
    assert "Authorization: [REDACTED]" in redacted
    assert "Cookie: [REDACTED]" in redacted
    assert "password_hash=[REDACTED]" in redacted


def test_embedded_json_is_bounded_and_plain_strings_are_truncated() -> None:
    oversized = '{"password":"' + ("x" * MAX_EMBEDDED_JSON_CHARS) + '"}'

    assert redact_for_api(oversized) == OVERSIZED_JSON_MARKER
    truncated = redact_for_log("a" * 1000, max_string_chars=64)
    assert len(truncated) == 64
    assert truncated.endswith("...[TRUNCATED]")
    with pytest.raises(ValueError, match="must be positive"):
        redact_for_log("value", max_string_chars=0)


def test_malformed_or_nonfinite_embedded_json_cannot_break_redaction() -> None:
    oversized_integer = '{"password":"unit-secret","value":' + ("9" * 5_000) + "}"
    nonfinite = '{"password":"unit-secret","value":NaN}'

    for value in (oversized_integer, nonfinite):
        redacted = redact_for_log({"detail": value}, max_string_chars=512)
        encoded = json.dumps(redacted, sort_keys=True)
        assert "unit-secret" not in encoded
        assert "[REDACTED]" in encoded

    assert redact_for_log("[Errno 111] Connection refused") == (
        "[Errno 111] Connection refused"
    )
    assert redact_for_api("[ -f /etc/passwd ] && echo yes") == (
        "[ -f /etc/passwd ] && echo yes"
    )


def test_feedback_normalization_redacts_sensitive_internal_callers() -> None:
    secret = "direct-feedback-secret"
    feedback = normalize_feedback_payload(
        {
            "session_id": "session-safe",
            "label": "useful",
            "password": secret,
            "authorization": f"Bearer {secret}",
        },
        now="2026-07-17T00:00:00+00:00",
    )

    encoded = json.dumps(feedback, sort_keys=True)
    assert secret not in encoded
    assert feedback["password"] == REDACTION_MARKER
    assert feedback["authorization"] == REDACTION_MARKER


def test_redaction_handles_dataclasses_collections_and_cycles() -> None:
    @dataclass
    class Record:
        observed_at: datetime
        password: str
        values: tuple[int, ...]

    cycle: list[object] = []
    cycle.append(cycle)
    value = {
        "record": Record(
            observed_at=datetime(2026, 7, 17, 9, 30),
            password="dataclass-secret",
            values=(2, 1),
        ),
        "set_values": {"b", "a"},
        "cycle": cycle,
    }

    redacted = redact_for_artifact(value)

    assert redacted["record"] == {
        "observed_at": "2026-07-17T09:30:00+00:00",
        "password": REDACTION_MARKER,
        "values": [2, 1],
    }
    assert redacted["set_values"] == ["a", "b"]
    assert redacted["cycle"] == [REDACTION_MARKER]


def test_to_jsonable_supports_backend_types_and_normalizes_datetimes_to_utc() -> None:
    ObjectId = type(
        "ObjectId",
        (),
        {
            "__module__": "bson.objectid",
            "__str__": lambda self: "507f1f77bcf86cd799439011",
        },
    )
    identifier = UUID("12345678-1234-5678-1234-567812345678")
    aware = datetime(
        2026,
        7,
        17,
        9,
        30,
        tzinfo=timezone(timedelta(hours=7)),
    )
    naive = datetime(2026, 7, 17, 2, 30)
    aware_key = datetime(
        2026,
        7,
        17,
        10,
        0,
        tzinfo=timezone(timedelta(hours=7)),
    )

    converted = to_jsonable(
        {
            "aware": aware,
            "naive": naive,
            "date": date(2026, 7, 17),
            "uuid": identifier,
            "decimal": Decimal("1.2300"),
            "path": Path("/var/lib/honeypot/report.json"),
            "bytes": b"\x00\xff",
            "object_id": ObjectId(),
            aware_key: "datetime-key",
        }
    )

    assert converted == {
        "aware": "2026-07-17T02:30:00+00:00",
        "naive": "2026-07-17T02:30:00+00:00",
        "date": "2026-07-17",
        "uuid": "12345678-1234-5678-1234-567812345678",
        "decimal": "1.2300",
        "path": "/var/lib/honeypot/report.json",
        "bytes": "base64:AP8=",
        "object_id": "507f1f77bcf86cd799439011",
        "2026-07-17T03:00:00+00:00": "datetime-key",
    }


def test_to_jsonable_is_deterministic_for_sets() -> None:
    assert stable_json({"values": {3, 1, 2}}) == '{"values":[1,2,3]}'


def test_html_script_json_prevents_script_element_breakout() -> None:
    attacker_text = "</script><script>window.PWNED=1</script>\u2028next"
    encoded = html_script_json({"detail": attacker_text})

    assert "</script>" not in encoded
    assert "<script>" not in encoded
    assert "\\u003c/script\\u003e" in encoded
    assert json.loads(encoded)["detail"] == attacker_text


def test_to_jsonable_rejects_unsupported_values_without_calling_str() -> None:
    class Unsupported:
        def __str__(self) -> str:
            raise AssertionError("unsupported __str__ must not be called")

    with pytest.raises(TypeError, match=r"unsupported JSON value at \$\.value"):
        to_jsonable({"value": Unsupported()})


def test_to_jsonable_rejects_cycles_key_collisions_and_non_finite_values() -> None:
    cyclic: list[object] = []
    cyclic.append(cyclic)

    with pytest.raises(ValueError, match="cyclic reference"):
        to_jsonable(cyclic)
    with pytest.raises(ValueError, match="mapping key collision"):
        to_jsonable({1: "integer", "1": "string"})
    with pytest.raises(ValueError, match="non-finite float"):
        to_jsonable({"score": float("nan")})
