from __future__ import annotations

import json
import time
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
    redact_error_for_log,
    redact_exception_for_log,
    redact_for_api,
    redact_for_artifact,
    redact_for_log,
    redact_for_session_state,
    redact_for_webhook,
    sanitize_url,
)
from production.utils.feedback import normalize_feedback_payload
from production.utils.serialization import html_script_json, stable_id, stable_json, to_jsonable


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


def test_exception_redaction_never_inspects_exception_arguments() -> None:
    error = RuntimeError(
        "connect mongodb://db-user:db-password@example.invalid/honeypot"
        "?token=query-token\n"
        "Authorization: Bearer bearer-token\n"
        "Cookie: session=cookie-token\n"
        "password_hash=sha256:credential-digest"
    )

    redacted = redact_for_log(error)

    assert redacted == "RuntimeError: operation_failed"
    assert redact_exception_for_log(error) == redacted
    assert redact_error_for_log(redacted) == redacted
    assert redact_error_for_log("opaque-unlabelled-secret") == "operation_failed"
    for redactor in (*REDACTORS, redact_for_session_state):
        assert redactor(RuntimeError("opaque-unlabelled-secret")) == redacted


def test_derived_raw_event_projection_drops_unknown_fields_and_login_credentials() -> None:
    secret = "opaque-event-field-secret"
    digest = "hmac-sha256-v1:active-key:" + ("a" * 64)
    payload = {
        "login_username": secret,
        "raw_events": [
            {
                "eventid": "cowrie.login.success",
                "timestamp": "2026-07-18T00:00:00Z",
                "username": secret,
                "password_hash": digest,
                "unexpected_sensor_field": secret,
            }
        ],
    }

    session_safe = redact_for_session_state(payload)
    artifact_safe = redact_for_artifact(payload)

    assert secret not in json.dumps(session_safe, sort_keys=True)
    assert session_safe["login_username"] == REDACTION_MARKER
    assert session_safe["raw_events"][0]["username"] == REDACTION_MARKER
    assert session_safe["raw_events"][0]["password_hash"] == digest
    assert "unexpected_sensor_field" not in session_safe["raw_events"][0]
    assert artifact_safe["raw_events"][0]["password_hash"] == REDACTION_MARKER


@pytest.mark.parametrize(
    "command",
    [
        "sshpass -p command-secret ssh root@example.invalid",
        "sshpass -p'command-secret' ssh root@example.invalid",
        "curl -u user:command-secret https://example.invalid/api",
        'curl --user="user:command-secret" https://example.invalid/api',
        "curl -U proxy:command-secret https://example.invalid/api",
        "curl --proxy-user proxy:command-secret https://example.invalid/api",
        "mysql -pcommand-secret -h db.example.invalid",
        "mysqldump --password='command-secret' exampledb",
        "redis-cli -a command-secret ping",
        "redis-cli --pass=command-secret ping",
        "AWS_SECRET_ACCESS_KEY=command-secret aws s3 ls",
        "PGPASSWORD=command-secret psql exampledb",
        "MYSQL_PWD=command-secret mysql exampledb",
        "REDISCLI_AUTH=command-secret redis-cli ping",
        "SSHPASS=command-secret sshpass ssh root@example.invalid",
        "PROVIDER_CLIENT_SECRET=command-secret run-client",
        'export API_TOKEN="command-secret"; run-client',
        "kubectl --token command-secret get pods",
        "docker login --password command-secret registry.example.invalid",
        "mongosh --password command-secret mongodb://example.invalid/db",
        "run-client --api-key command-secret",
        "run-client --client-secret=command-secret",
    ],
)
def test_artifact_redactor_scrubs_credential_bearing_command_forms(
    command: str,
) -> None:
    redacted = redact_for_artifact({"command": command})["command"]

    assert "command-secret" not in redacted
    assert REDACTION_MARKER in redacted


def test_artifact_redactor_scrubs_private_key_blocks() -> None:
    value = (
        "prefix\n-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "private-key-secret\n"
        "-----END OPENSSH PRIVATE KEY-----\nsuffix"
    )

    redacted = redact_for_artifact({"evidence": value})["evidence"]

    assert "private-key-secret" not in redacted
    assert "BEGIN OPENSSH PRIVATE KEY" not in redacted
    assert redacted == f"prefix\n{REDACTION_MARKER}\nsuffix"


@pytest.mark.parametrize(
    "label",
    ["ED25519 PRIVATE KEY", "SSH2 ENCRYPTED PRIVATE KEY"],
)
def test_artifact_redactor_scrubs_vendor_private_key_labels(label: str) -> None:
    value = f"-----BEGIN {label}-----\nprivate-key-secret\n-----END {label}-----"
    assert redact_for_artifact({"evidence": value})["evidence"] == REDACTION_MARKER


@pytest.mark.parametrize(
    "value",
    [
        "sshpass --help",
        "sshpass -P 'Password:' ssh root@example.invalid",
        "curl -I https://example.invalid/public",
        "mysql -p",
        "mysql -P3306 exampledb",
        "mysql --password exampledb",
        "redis-cli ping",
        "nmap -p 22 example.invalid",
        "ls -a /tmp",
        "sort -u names.txt",
        "ssh -i /run/operator-key root@example.invalid",
        "echo SECRETARY=public",
        "password_policy=strict",
        "token_count=3",
        "PRIVATE_KEY_PATH=/run/key",
        "-----BEGIN PUBLIC KEY-----\npublic-material\n-----END PUBLIC KEY-----",
    ],
)
def test_command_redactor_preserves_benign_command_evidence(value: str) -> None:
    assert redact_for_artifact({"command": value})["command"] == value


def test_inline_quoted_headers_preserve_command_structure() -> None:
    command = (
        "curl -H 'Authorization: Bearer header-secret' "
        "-H \"Cookie: session=cookie-secret\" https://example.invalid/path"
    )

    redacted = redact_for_artifact({"command": command})["command"]

    assert "header-secret" not in redacted
    assert "cookie-secret" not in redacted
    assert "-H 'Authorization: [REDACTED]'" in redacted
    assert '-H "Cookie: [REDACTED]"' in redacted
    assert redacted.endswith("https://example.invalid/path")


def test_curl_user_without_password_is_not_over_redacted() -> None:
    command = "curl -u alice https://example.invalid/public"
    assert redact_for_artifact({"command": command})["command"] == command


def test_plaintext_redaction_is_idempotent_across_repeated_report_boundaries() -> None:
    secret = "multi-boundary-secret"
    value = {
        "detail": (
            "headers={'Cookie': 'sid=" + secret + "', 'safe': 'retained'}"
        ),
        "command": f"sshpass -p '{secret}' ssh root@example.invalid",
    }

    once = redact_for_artifact(value)
    twice = redact_for_artifact(once)
    three_times = redact_for_artifact(twice)

    assert once == twice == three_times
    assert secret not in json.dumps(three_times, sort_keys=True)


def test_midline_cookie_redaction_consumes_the_complete_cookie_value() -> None:
    secret_one = "cookie-secret-one"
    secret_two = "cookie-secret-two"
    value = f"request failed Cookie: sid={secret_one}; csrf={secret_two}\nnext line"

    redacted = redact_for_log(value)

    assert secret_one not in redacted
    assert secret_two not in redacted
    assert "Cookie: [REDACTED]" in redacted
    assert redacted.endswith("\nnext line")


def test_large_plaintext_redaction_remains_bounded_and_scrubs_tail_secret() -> None:
    secret = "tail-command-secret"
    value = ("x" * 100_000) + f" sshpass -p {secret} ssh root@example.invalid"

    redacted = redact_for_artifact(value)

    assert secret not in redacted
    assert len(redacted) <= 100_100


@pytest.mark.parametrize(
    "command",
    [
        "sshpass " + ("arg " * 150) + "-p padded-command-secret ssh host",
        "curl " + ("-H x " * 60) + "-u user:padded-command-secret https://host",
        "mysql " + ("--connect-timeout=1 " * 20) + "-ppadded-command-secret db",
        "redis-cli " + ("--raw " * 60) + "-a padded-command-secret ping",
        "curl -H 'X-Test: a;b' -u user:padded-command-secret https://host",
        "sshpass -P 'P;rompt:' -p padded-command-secret ssh host",
        "mysql --init-command='SET a=1; SET b=2' -ppadded-command-secret db",
        "redis-cli --eval 'return a|b' -a padded-command-secret ping",
    ],
)
def test_command_redactor_handles_padding_and_quoted_separators(command: str) -> None:
    redacted = redact_for_artifact({"command": command})["command"]
    assert "padded-command-secret" not in redacted
    assert REDACTION_MARKER in redacted


@pytest.mark.parametrize(
    "value",
    [
        "password='malformed-command-secret",
        'export API_TOKEN="malformed-command-secret',
        "sshpass -p 'malformed-command-secret ssh host",
        'curl -u "user:malformed-command-secret https://host',
        "headers={'Cookie': 'malformed-command-secret}",
    ],
)
def test_redactor_fails_closed_on_unterminated_secret_quotes(value: str) -> None:
    redacted = redact_for_artifact({"detail": value})["detail"]
    assert "malformed-command-secret" not in redacted
    assert REDACTION_MARKER in redacted


@pytest.mark.parametrize(
    "key",
    [
        "passwords",
        "user_passwords",
        "tokens",
        "api_tokens",
        "secrets",
        "client_secrets",
        "private_keys",
        "access_keys",
        "authorization_headers",
        "password_list",
        "password_value",
        "token_values",
        "credential_values",
        "credential_value",
        "secret_key",
        "aws_secret_access_key",
        "aws_access_key_id",
        "auth",
        "bearer",
        "credentials_metadata",
        "password_metadata",
        "token_metadata",
        "client_secret_metadata",
        "authorization_metadata",
        "api_key_status",
        "client_secret_type",
        "password_source",
        "token_name",
        "private_key_path",
        "credential_access_token",
        "my_credential_access_password",
        "credential_targets",
        "credential_policy",
    ],
)
def test_structured_sensitive_key_variants_fail_closed(key: str) -> None:
    redacted = redact_for_artifact({key: "structured-key-secret"})
    assert redacted[key] == REDACTION_MARKER


def test_sensitive_metadata_suffixes_require_safe_value_types() -> None:
    redacted = redact_for_artifact(
        {
            "token_count": 3,
            "password_hash_present": True,
            "token_count_bad": "metadata-secret",
            "api_key_configured": "metadata-secret",
            "password_enabled": "metadata-secret",
        }
    )
    assert redacted["token_count"] == 3
    assert redacted["password_hash_present"] is True
    assert redacted["token_count_bad"] == REDACTION_MARKER
    assert redacted["api_key_configured"] == REDACTION_MARKER
    assert redacted["password_enabled"] == REDACTION_MARKER


@pytest.mark.parametrize(
    "redactor",
    [
        redact_for_api,
        redact_for_log,
        redact_for_artifact,
        redact_for_webhook,
    ],
)
def test_canonical_credential_path_entities_preserve_safe_shape(redactor) -> None:
    secret = "credential-path-secret"
    entity_id = stable_id("entity", {"type": "path", "value": "/etc/shadow"})
    entity = {
        "entity_id": entity_id,
        "entity_type": "path",
        "normalized_value": "/etc/shadow",
        "original_value": "/etc/shadow",
        "uncertain": False,
        "linkable": True,
        "password": secret,
        "unknown": secret,
    }

    redacted = redactor({"credential_paths": [entity]})

    assert redacted["credential_paths"] == [{
        "entity_id": entity["entity_id"],
        "entity_type": "path",
        "normalized_value": "/etc/shadow",
        "original_value": "/etc/shadow",
        "uncertain": False,
        "linkable": True,
    }]
    assert secret not in json.dumps(redacted, sort_keys=True)


def test_noncanonical_credential_path_entities_fail_closed() -> None:
    redacted = redact_for_artifact(
        {
            "credential_paths": [
                "credential-path-secret",
                {"entity_type": "path", "original_value": "/etc/shadow"},
                {
                    "entity_id": "entity_" + ("a" * 32),
                    "entity_type": "token",
                    "normalized_value": "credential-path-secret",
                    "original_value": "credential-path-secret",
                    "uncertain": False,
                    "linkable": True,
                },
            ]
        }
    )

    assert redacted["credential_paths"] == []


def test_smb_credential_path_strings_preserve_only_trusted_vocabulary() -> None:
    redacted = redact_for_artifact(
        {
            "credential_paths": [
                "/etc/shadow",
                "/root/.ssh/id_ed25519",
                "/home/alice/.aws/credentials",
                "/home/alice/.config/gcloud/application_default_credentials.json",
                "/root/.env",
                "/tmp/credential-path-secret",
                "/etc/shadow",
            ]
        }
    )

    assert redacted["credential_paths"] == [
        "/etc/shadow",
        "/root/.ssh/id_ed25519",
        "/home/alice/.aws/credentials",
        "/home/alice/.config/gcloud/application_default_credentials.json",
        "/root/.env",
    ]


def test_credential_evidence_collapses_dynamic_suffixes_and_rejects_oversize() -> None:
    secret = "dynamic-credential-evidence-secret"
    targets = redact_for_artifact(
        {
            "credential_targets": [
                f".config/gcloud/{secret}",
                f".azure/{secret})",
                f'.ssh/id_{secret}"',
                ".aws/credentials;",
                ".config/gcloud/" + ("x" * 10_000),
            ]
        }
    )["credential_targets"]
    paths = redact_for_artifact(
        {
            "credential_paths": [
                f"/home/alice/.config/gcloud/{secret}",
                f"/home/alice/.ssh/id_{secret}",
                "/home/alice/.config/gcloud/" + ("x" * 10_000),
            ]
        }
    )["credential_paths"]

    assert targets == [
        ".config/gcloud/<credential-file>",
        ".azure/<credential-file>",
        ".ssh/<private-key>",
        ".aws/credentials",
    ]
    assert paths == []
    assert secret not in json.dumps(targets)


def test_credential_path_shape_is_homogeneous_bounded_and_strict() -> None:
    valid_entity = {
        "entity_id": stable_id(
            "entity",
            {"type": "path", "value": "/etc/shadow"},
        ),
        "entity_type": "path",
        "normalized_value": "/etc/shadow",
        "original_value": "/etc/shadow",
        "uncertain": False,
        "linkable": True,
    }
    mixed = redact_for_artifact(
        {"credential_paths": [valid_entity, "/etc/shadow"]}
    )
    bad_reason = redact_for_artifact(
        {
            "credential_paths": [
                {**valid_entity, "uncertainty_reason": "password=secret"}
            ]
        }
    )
    malformed_reason = redact_for_artifact(
        {
            "credential_paths": [
                {**valid_entity, "uncertainty_reason": {"password": "secret"}}
            ]
        }
    )
    oversized = redact_for_artifact(
        {"credential_paths": ["/etc/shadow"] * 256}
    )

    assert mixed["credential_paths"] == []
    assert bad_reason["credential_paths"] == []
    assert malformed_reason["credential_paths"] == []
    assert oversized["credential_paths"] == ["/etc/shadow"]


def test_credential_path_entities_reject_forged_identity_or_normalization() -> None:
    canonical = {
        "entity_id": stable_id(
            "entity",
            {"type": "path", "value": "/etc/shadow"},
        ),
        "entity_type": "path",
        "normalized_value": "/etc/shadow",
        "original_value": "/etc/shadow",
        "uncertain": False,
        "linkable": True,
    }
    forged_id = {**canonical, "entity_id": "entity_" + ("f" * 32)}
    forged_path = {
        **canonical,
        "normalized_value": "/tmp/opaque-secret-value",
    }

    assert redact_for_artifact(
        {"credential_paths": [forged_id]}
    )["credential_paths"] == []
    assert redact_for_artifact(
        {"credential_paths": [forged_path]}
    )["credential_paths"] == []


def test_evaluation_only_account_credential_label_remains_sensitive() -> None:
    redacted = redact_for_artifact(
        {"account_and_credential_entities": "evaluation-label-secret"}
    )
    assert redacted["account_and_credential_entities"] == REDACTION_MARKER


def test_docker_and_credential_target_scans_remain_bounded() -> None:
    secret = "bounded-docker-secret"
    command = " ".join(
        ["docker", *(f"--flag-{index}" for index in range(6_000)), "login", "-p", secret]
    )
    targets = [f".config/gcloud/profile-{index}" for index in range(50_000)]

    started = time.perf_counter()
    safe_command = redact_for_artifact({"command": command})["command"]
    safe_targets = redact_for_artifact({"credential_targets": targets})[
        "credential_targets"
    ]
    elapsed = time.perf_counter() - started

    assert secret not in safe_command
    assert REDACTION_MARKER in safe_command
    assert safe_targets == [".config/gcloud/<credential-file>"]
    assert elapsed < 1.0


@pytest.mark.parametrize(
    "command",
    [
        "API_TOKEN_STATUS=env-command-secret run-client",
        "PASSWORD_SOURCE=env-command-secret run-client",
        "CLIENT_SECRET_TYPE=env-command-secret run-client",
        "kubectl '--token' env-command-secret get pods",
        "sshpass '-p' env-command-secret ssh host",
        "redis-cli '-a' env-command-secret ping",
        "curl '-u' user:env-command-secret https://host",
        "sshpass '-penv-command-secret' ssh host",
        "(sshpass -p env-command-secret ssh host)",
        "$(sshpass -p env-command-secret ssh host)",
        "docker login mysql --password env-command-secret",
        "echo mysql --password env-command-secret",
        "sshpass \\\n-p env-command-secret ssh host",
        "docker login -p env-command-secret registry.example.invalid",
        "mongosh -p env-command-secret mongodb://example.invalid/db",
        "`sshpass -p env-command-secret ssh host`",
        "smbclient //server/share -U user%env-command-secret",
        "openssl pkcs12 -passin pass:env-command-secret -in bundle.p12",
    ],
)
def test_shell_scanner_handles_quoted_options_wrappers_and_env_metadata(
    command: str,
) -> None:
    redacted = redact_for_artifact({"command": command})["command"]
    assert "env-command-secret" not in redacted
    assert REDACTION_MARKER in redacted


@pytest.mark.parametrize(
    "command",
    [
        "kubectl --token-count 3 get pods",
        "kubectl --token-endpoint https://example.invalid/token get pods",
    ],
)
def test_generic_long_option_scanner_preserves_benign_token_metadata(
    command: str,
) -> None:
    assert redact_for_artifact({"command": command})["command"] == command


def test_quoted_header_with_escaped_quote_cannot_leak_tail() -> None:
    command = (
        'curl -H "Cookie: sid=public\\"escaped-header-secret" '
        "https://example.invalid"
    )
    redacted = redact_for_artifact({"command": command})["command"]
    assert "escaped-header-secret" not in redacted
    assert "Cookie: [REDACTED]" in redacted


def test_shell_scanner_is_linear_for_repeated_executable_tokens() -> None:
    command = ("curl " * 5_000) + "-u user:repeated-command-secret https://host"
    redacted = redact_for_artifact({"command": command})["command"]
    assert "repeated-command-secret" not in redacted


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
