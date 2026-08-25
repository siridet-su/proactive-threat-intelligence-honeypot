from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest

from production.utils import credential_hmac as credential_hmac_module
from production.utils.config import ProductionConfig
from production.utils.credential_hmac import (
    CREDENTIAL_HMAC_SCHEME,
    CREDENTIAL_METADATA_SCHEMA,
    CredentialHMACError,
    CredentialHasher,
    credential_metadata_for_provenance,
    load_credential_hmac_keyring,
    resolve_credential_hmac_keyring_path,
    validate_production_credential_policy,
)
from production.utils.sensitive_data import REDACTION_MARKER, redact_for_artifact
from production.workers.session_monitor import SessionMonitor
from production.workers.session_worker import SessionWorker


def _keyring_document(
    active_key_id: str = "unit-2026-07",
    correlation_key_ids: list[str] | None = None,
) -> dict:
    aliases = list(correlation_key_ids or [])
    key_ids = [active_key_id, *aliases]
    return {
        "schema_version": "credential_hmac_keyring.v1",
        "active_key_id": active_key_id,
        "keys": {
            key_id: base64.b64encode(bytes([index + 1]) * 32).decode("ascii")
            for index, key_id in enumerate(key_ids)
        },
        "correlation_key_ids": aliases,
    }


def _write_keyring(path: Path, document: dict, mode: int = 0o600) -> Path:
    path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
    os.chmod(path, mode)
    return path


def test_credential_hmac_known_vector_and_safe_repr() -> None:
    encoded_key = base64.b64encode(bytes.fromhex("0b" * 32)).decode("ascii")
    hasher = CredentialHasher.from_document(
        {
            "schema_version": "credential_hmac_keyring.v1",
            "active_key_id": "unit-2026-01",
            "keys": {"unit-2026-01": encoded_key},
            "correlation_key_ids": [],
        }
    )

    assert hasher.digest("secret123") == (
        "hmac-sha256-v1:unit-2026-01:"
        "5a013b0ffb2689073ee0e62ccc415db99a583b16ae4728e877a785f20fc61df3"
    )
    assert encoded_key not in repr(hasher)
    assert "0b0b0b" not in repr(hasher)
    assert hasher.safe_summary() == {
        "hash_algorithm": CREDENTIAL_HMAC_SCHEME,
        "hashing_enabled": True,
        "active_key_id": "unit-2026-01",
        "correlation_key_ids": [],
    }


def test_key_rotation_emits_stable_prior_key_alias() -> None:
    old_document = _keyring_document(active_key_id="old-key")
    old_key = old_document["keys"]["old-key"]
    new_document = _keyring_document(
        active_key_id="new-key",
        correlation_key_ids=["old-key"],
    )
    new_document["keys"]["new-key"] = base64.b64encode(b"\x02" * 32).decode(
        "ascii"
    )
    new_document["keys"]["old-key"] = old_key
    old_hasher = CredentialHasher.from_document(old_document)
    new_hasher = CredentialHasher.from_document(new_document)

    active_digest, aliases = new_hasher.digests("rotation-secret")
    assert active_digest.startswith("hmac-sha256-v1:new-key:")
    assert aliases == (old_hasher.digest("rotation-secret"),)


def test_session_monitor_redacts_but_omits_hashes_without_injected_key() -> None:
    monitor = SessionMonitor()
    monitor.on_event(
        {
            "eventid": "cowrie.login.success",
            "session": "no-key",
            "src_ip": "203.0.113.10",
            "timestamp": "2026-07-17T00:00:00Z",
            "username": "root",
            "password": "attacker-secret",
            "password_hash": "hmac-sha256-v1:active-key:" + ("0" * 64),
            "password_hash_aliases": [
                "hmac-sha256-v1:prior-key:" + ("0" * 64)
            ],
        }
    )

    state = monitor.get_session("no-key")
    assert state is not None
    assert state.login_username == REDACTION_MARKER
    assert state.login_password == REDACTION_MARKER
    assert state.login_password_hash == ""
    assert state.login_password_hash_aliases == []
    assert state.credential_metadata["hashing_enabled"] is False
    assert state.raw_events[0]["password"] == REDACTION_MARKER
    assert "password_hash" not in state.raw_events[0]
    assert "attacker-secret" not in str(state)


def test_session_monitor_does_not_silently_enable_hashing_without_a_key() -> None:
    with pytest.raises(ValueError, match="without a CredentialHasher"):
        SessionMonitor(
            credential_policy={"hash_algorithm": CREDENTIAL_HMAC_SCHEME}
        )


@pytest.mark.parametrize(
    "event_fields",
    [
        {
            "password_hash": "sha256:untrusted-sensor-value",
            "password_hash_aliases": ["sha256:also-untrusted"],
        },
        {
            "password": "",
            "password_hash": "sha256:untrusted-sensor-value",
            "password_hash_aliases": ["sha256:also-untrusted"],
        },
        {
            "passwd": "",
            "passwd_hash": "sha256:untrusted-sensor-value",
            "passwd_hash_aliases": ["sha256:also-untrusted"],
        },
    ],
)
def test_session_monitor_drops_untrusted_hash_without_plaintext(
    event_fields: dict,
) -> None:
    monitor = SessionMonitor()
    monitor.on_event(
        {
            "eventid": "cowrie.login.failed",
            "session": "hash-only",
            "src_ip": "203.0.113.10",
            "timestamp": "2026-07-17T00:00:00Z",
            **event_fields,
        }
    )

    state = monitor.get_session("hash-only")
    assert state is not None
    assert "password_hash" not in state.raw_events[0]
    assert "password_hash_aliases" not in state.raw_events[0]
    assert "passwd_hash" not in state.raw_events[0]
    assert "passwd_hash_aliases" not in state.raw_events[0]


def test_session_monitor_emits_active_and_rotation_alias_hashes() -> None:
    hasher = CredentialHasher.from_document(
        _keyring_document(
            active_key_id="active-key",
            correlation_key_ids=["prior-key"],
        )
    )
    monitor = SessionMonitor(credential_hasher=hasher)
    monitor.on_event(
        {
            "eventid": "cowrie.login.success",
            "session": "with-key",
            "src_ip": "203.0.113.10",
            "timestamp": "2026-07-17T00:00:00Z",
            "username": "root",
            "password": "attacker-secret",
            "password_hash": "hmac-sha256-v1:active-key:" + ("0" * 64),
            "password_hash_aliases": [
                "hmac-sha256-v1:prior-key:" + ("0" * 64)
            ],
        }
    )

    state = monitor.get_session("with-key")
    assert state is not None
    assert state.login_password_hash.startswith("hmac-sha256-v1:active-key:")
    assert len(state.login_password_hash_aliases) == 1
    assert state.login_password_hash_aliases[0].startswith(
        "hmac-sha256-v1:prior-key:"
    )
    assert state.raw_events[0]["password_hash"] == state.login_password_hash
    assert state.raw_events[0]["password_hash_aliases"] == (
        state.login_password_hash_aliases
    )
    assert state.credential_metadata["active_key_id"] == "active-key"
    assert state.credential_metadata["password_hash_alias_count"] == 1
    assert "0" * 64 not in str(state.raw_events[0])

    public = redact_for_artifact(
        {
            "login_password_hash": state.login_password_hash,
            "login_password_hash_aliases": state.login_password_hash_aliases,
        }
    )
    assert public["login_password_hash"] == REDACTION_MARKER
    assert public["login_password_hash_aliases"] == REDACTION_MARKER


def test_credential_metadata_is_strict_safe_and_idempotent() -> None:
    raw = {
        "credential_observed": True,
        "raw_password_stored": False,
        "password_hash_present": True,
        "raw_events_sanitized": True,
        "hashing_enabled": True,
        "password_hash_alias_count": 1,
        "hash_algorithm": CREDENTIAL_HMAC_SCHEME,
        "active_key_id": "active-key",
        "correlation_key_ids": ["prior-key"],
        "password": "metadata-secret",
        "login_password_hash": "hmac-sha256-v1:active-key:" + ("a" * 64),
        "unknown": "must-not-survive",
    }
    expected = {
        "schema_version": CREDENTIAL_METADATA_SCHEMA,
        "metadata_status": "available",
        "credential_observed": True,
        "raw_password_stored": False,
        "password_hash_present": True,
        "raw_events_sanitized": True,
        "hashing_enabled": True,
        "password_hash_alias_count": 1,
        "hash_algorithm": CREDENTIAL_HMAC_SCHEME,
        "active_key_id": "active-key",
        "correlation_key_ids": ["prior-key"],
    }

    assert credential_metadata_for_provenance(raw) == expected
    redacted = redact_for_artifact(
        {"credential_metadata": raw, "credentials": raw}
    )
    assert redacted == {
        "credential_metadata": expected,
        "credentials": REDACTION_MARKER,
    }
    assert redact_for_artifact(redacted) == redacted

    malformed = {
        "credential_observed": 1,
        "raw_password_stored": "false",
        "password_hash_present": None,
        "raw_events_sanitized": [],
        "hashing_enabled": {},
        "password_hash_alias_count": True,
        "hash_algorithm": [],
        "active_key_id": [],
        "correlation_key_ids": ["valid-key", []],
    }
    unavailable = {
        "schema_version": CREDENTIAL_METADATA_SCHEMA,
        "metadata_status": "unavailable",
    }
    assert credential_metadata_for_provenance(malformed) == unavailable
    assert redact_for_artifact({"credential_metadata": malformed}) == {
        "credential_metadata": unavailable
    }

    partial_or_incoherent = (
        {"raw_password_stored": False},
        {**raw, "active_key_id": "prior-key"},
        {**raw, "password_hash_alias_count": 0},
        {**raw, "raw_password_stored": True},
        {**raw, "raw_events_sanitized": False},
        {**raw, "password_hash_present": False},
    )
    for candidate in partial_or_incoherent:
        assert credential_metadata_for_provenance(candidate) == unavailable


def test_secure_keyring_file_loads_and_resolver_prefers_explicit_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keyring_path = _write_keyring(tmp_path / "keyring.json", _keyring_document())
    hasher = load_credential_hmac_keyring(str(keyring_path))
    assert hasher.active_key_id == "unit-2026-07"

    credentials_dir = tmp_path / "credentials"
    credentials_dir.mkdir()
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(credentials_dir))
    assert resolve_credential_hmac_keyring_path(" /explicit/keyring.json ") == (
        "/explicit/keyring.json"
    )
    assert resolve_credential_hmac_keyring_path() == str(
        credentials_dir / "credential-hmac-keyring.json"
    )


def test_keyring_loader_rejects_symlinks_and_broad_permissions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    target = _write_keyring(tmp_path / "target.json", _keyring_document())
    symlink = tmp_path / "keyring-link.json"
    symlink.symlink_to(target)
    with pytest.raises(CredentialHMACError, match="cannot be opened"):
        load_credential_hmac_keyring(str(symlink))

    os.chmod(target, 0o640)
    with pytest.raises(CredentialHMACError, match="group or other"):
        load_credential_hmac_keyring(str(target))

    with pytest.raises(CredentialHMACError, match="must be absolute"):
        load_credential_hmac_keyring("relative-keyring.json")

    fifo = tmp_path / "keyring.fifo"
    os.mkfifo(fifo, mode=0o600)
    with pytest.raises(CredentialHMACError, match="regular file"):
        load_credential_hmac_keyring(str(fifo))


def test_keyring_loader_accepts_only_exact_protected_systemd_257_credential(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credentials_root = tmp_path / "run" / "credentials"
    credentials_directory = credentials_root / "session-worker.service"
    credentials_directory.mkdir(parents=True)
    keyring = _write_keyring(
        credentials_directory / "credential-hmac-keyring.json",
        _keyring_document(),
        mode=0o440,
    )
    os.chmod(credentials_directory, 0o550)
    monkeypatch.setattr(
        credential_hmac_module,
        "_SYSTEMD_CREDENTIALS_ROOT",
        credentials_root,
    )
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(credentials_directory))

    assert load_credential_hmac_keyring(str(keyring)).active_key_id == (
        "unit-2026-07"
    )


@pytest.mark.parametrize(
    "file_mode,directory_mode,filename",
    [
        (0o460, 0o550, "credential-hmac-keyring.json"),
        (0o444, 0o550, "credential-hmac-keyring.json"),
        (0o440, 0o750, "credential-hmac-keyring.json"),
        (0o440, 0o550, "different-name.json"),
    ],
)
def test_keyring_loader_rejects_unsafe_or_unbound_systemd_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    file_mode: int,
    directory_mode: int,
    filename: str,
) -> None:
    credentials_root = tmp_path / "run" / "credentials"
    credentials_directory = credentials_root / "session-worker.service"
    credentials_directory.mkdir(parents=True)
    keyring = _write_keyring(
        credentials_directory / filename,
        _keyring_document(),
        mode=file_mode,
    )
    os.chmod(credentials_directory, directory_mode)
    monkeypatch.setattr(
        credential_hmac_module,
        "_SYSTEMD_CREDENTIALS_ROOT",
        credentials_root,
    )
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(credentials_directory))

    with pytest.raises(CredentialHMACError, match="group or other"):
        load_credential_hmac_keyring(str(keyring))


def test_keyring_loader_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    keyring = tmp_path / "duplicate.json"
    keyring.write_text(
        '{"schema_version":"credential_hmac_keyring.v1",'
        '"active_key_id":"first","active_key_id":"second",'
        '"keys":{},"correlation_key_ids":[]}',
        encoding="utf-8",
    )
    os.chmod(keyring, 0o600)

    with pytest.raises(CredentialHMACError, match="valid UTF-8 JSON"):
        load_credential_hmac_keyring(str(keyring))


@pytest.mark.parametrize(
    "mutator,match",
    [
        (lambda doc: doc.update(schema_version="legacy.v0"), "unsupported.*schema"),
        (lambda doc: doc["keys"].update({"extra": doc["keys"]["unit-2026-07"]}), "exactly"),
        (lambda doc: doc["keys"].update({"unit-2026-07": "not-base64!"}), "base64"),
        (
            lambda doc: doc["keys"].update(
                {"unit-2026-07": base64.b64encode(b"short").decode("ascii")}
            ),
            "32-128 bytes",
        ),
        (lambda doc: doc.update(active_key_id="bad:key"), "1-64"),
        (lambda doc: doc.update(correlation_key_ids=["one", "two", "three"]), "at most"),
        (lambda doc: doc.update(inline_secret="forbidden"), "unknown fields"),
        (
            lambda doc: doc.update(
                keys={
                    "unit-2026-07": doc["keys"]["unit-2026-07"],
                    "prior-key": doc["keys"]["unit-2026-07"],
                },
                correlation_key_ids=["prior-key"],
            ),
            "distinct key material",
        ),
    ],
)
def test_keyring_document_validation_fails_closed(mutator, match: str) -> None:
    document = _keyring_document()
    mutator(document)
    with pytest.raises(CredentialHMACError, match=match):
        CredentialHasher.from_document(document)


@pytest.mark.parametrize(
    "override,match",
    [
        ({"store_raw_credentials": True}, "must not store plaintext"),
        ({"sanitize_raw_events": False}, "must sanitize"),
        ({"hash_algorithm": "sha256"}, "hmac-sha256-v1"),
        ({"hash_salt": "public-salt"}, "hash_salt"),
        ({"redact_fields": ["password"]}, "password and passwd"),
        (
            {"redact_fields": ["password", "passwd", "password_hash"]},
            "only password and passwd",
        ),
        ({"redaction": "<hidden>"}, "canonical"),
        ({"hmac_key": "inline"}, "unsupported fields"),
    ],
)
def test_production_credential_policy_rejects_unsafe_settings(
    override: dict,
    match: str,
) -> None:
    policy = {
        "store_raw_credentials": False,
        "redaction": "[REDACTED]",
        "hash_algorithm": CREDENTIAL_HMAC_SCHEME,
        "sanitize_raw_events": True,
        "redact_fields": ["password", "passwd"],
        **override,
    }
    with pytest.raises(CredentialHMACError, match=match):
        validate_production_credential_policy(policy)


def test_session_worker_rejects_missing_key_before_opening_storage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage_calls: list[str] = []
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    monkeypatch.setattr(
        "production.workers.session_worker.open_storage",
        lambda database_url: storage_calls.append(database_url),
    )

    with pytest.raises(CredentialHMACError, match="keyring file is required"):
        SessionWorker(ProductionConfig(database_url="sqlite:///:memory:"))
    assert storage_calls == []


def test_session_worker_rejects_unsafe_policy_before_opening_storage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage_calls: list[str] = []
    monkeypatch.setattr(
        "production.workers.session_worker.open_storage",
        lambda database_url: storage_calls.append(database_url),
    )
    config = ProductionConfig(database_url="sqlite:///:memory:")
    config.credential_policy = {
        **config.credential_policy,
        "store_raw_credentials": True,
    }

    with pytest.raises(CredentialHMACError, match="must not store plaintext"):
        SessionWorker(config)
    assert storage_calls == []
