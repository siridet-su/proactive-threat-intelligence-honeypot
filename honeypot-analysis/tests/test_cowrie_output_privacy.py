from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from production.cowrie_output.runtime import (
    CowrieOutputBoundaryError,
    verify_boundary,
    verify_bundle,
)
from production.tools.cowrie_output_integration import build_bundle, render_config
from production.utils.cowrie_privacy import (
    DEFAULT_POLICY,
    CredentialValueRegistry,
    load_policy,
    sanitize_cowrie_event_for_persistence,
    sanitize_twisted_event,
    serialize_cowrie_event_for_persistence,
)


ROOT = Path(__file__).resolve().parents[1]
REVISION = "1" * 40


def _login(secret: str = "synthetic-secret", *, success: bool = True) -> dict:
    outcome = "success" if success else "failed"
    return {
        "eventid": f"cowrie.login.{outcome}",
        "session": "session-privacy",
        "timestamp": "2026-07-30T00:00:00Z",
        "src_ip": "192.0.2.10",
        "src_port": 40000,
        "dst_port": 22,
        "protocol": "ssh",
        "sensor": "pi-test",
        "username": "operator",
        "password": secret,
        "message": f"login attempt [operator/{secret}] {outcome}",
    }


def _build(tmp_path: Path) -> Path:
    bundle = tmp_path / "bundle"
    build_bundle(ROOT, bundle, REVISION)
    return bundle


def _source_config() -> str:
    return """\
[honeypot]
log_path = /tmp/cowrie-log
logtype = rotating

[output_jsonlog]
enabled = true
logfile = ${honeypot:log_path}/cowrie.json

[output_textlog]
enabled = false
"""


def _configured_boundary(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    bundle = _build(tmp_path)
    source = tmp_path / "cowrie.before.cfg"
    source.write_text(_source_config(), encoding="utf-8")
    config = tmp_path / "cowrie.cfg"
    render_config(source, config, bundle)
    plugin = tmp_path / "sanitizedjson.py"
    plugin.symlink_to(bundle / "production/cowrie_output/sanitized_jsonlog.py")
    dropin = tmp_path / "20-sanitized-output.conf"
    dropin.write_bytes(
        (bundle / "deployment/cowrie_output/20-sanitized-output.conf").read_bytes()
    )
    return bundle, config, plugin, dropin


@pytest.mark.parametrize("success", [True, False])
def test_login_credentials_are_removed_before_serialization(success: bool) -> None:
    secret = "unicode-密碼-🔐" if success else "failed-password"
    event = _login(secret, success=success)
    serialized = serialize_cowrie_event_for_persistence(event)
    decoded = json.loads(serialized)
    assert secret.encode("utf-8") not in serialized
    assert b"operator" not in serialized
    assert decoded["eventid"] == event["eventid"]
    assert decoded["session"] == event["session"]
    assert decoded["src_ip"] == event["src_ip"]
    assert decoded["protocol"] == "ssh"
    assert decoded["username"] == "[REDACTED]"
    assert decoded["password"] == "[REDACTED]"
    assert decoded["message"] == "[REDACTED]"


def test_nested_alternate_empty_unicode_and_long_credentials_are_safe() -> None:
    huge = "z" * 100_000
    event = {
        "eventid": "cowrie.login.failed",
        "session": "nested",
        "password": "",
        "credentials": ["alternate-user", "alternate-password"],
        "nested": {
            "auth_secret": "密碼",
            "login_password": huge,
            "safe": {"status": "failed", "method": "password"},
        },
        "message": "",
    }
    serialized = serialize_cowrie_event_for_persistence(event)
    decoded = json.loads(serialized)
    assert b"alternate-password" not in serialized
    assert "密碼".encode() not in serialized
    assert huge.encode() not in serialized
    assert decoded["password"] == ""
    assert decoded["credentials"] == ["[REDACTED]", "[REDACTED]"]
    assert decoded["nested"]["safe"] == {"status": "failed", "method": "password"}


def test_repeated_events_are_idempotent_and_registry_scrubs_diagnostics() -> None:
    registry = CredentialValueRegistry(DEFAULT_POLICY)
    original = _login("registry-secret")
    first = sanitize_cowrie_event_for_persistence(original, registry=registry)
    second = sanitize_cowrie_event_for_persistence(first, registry=registry)
    assert first == second
    diagnostic = sanitize_twisted_event(
        {"log_format": "diagnostic registry-secret", "message": "registry-secret"},
        registry=registry,
    )
    assert "registry-secret" not in json.dumps(diagnostic)
    assert diagnostic["message"] == "[REDACTED]"


def test_failures_have_bounded_diagnostics_without_exception_values() -> None:
    registry = CredentialValueRegistry(DEFAULT_POLICY)
    registry.remember("exception-secret")
    event = sanitize_twisted_event(
        {
            "log_failure": RuntimeError("exception-secret"),
            "log_format": "failure: {log_failure}",
        },
        registry=registry,
    )
    assert event["log_format"] == "operation_failed"
    assert event["message"] == "operation_failed"
    assert "log_failure" not in event


def test_malformed_or_unserializable_events_are_rejected_without_partial_bytes() -> None:
    with pytest.raises(ValueError, match="must be an object"):
        serialize_cowrie_event_for_persistence(["not", "an", "object"])  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="not safely serializable"):
        serialize_cowrie_event_for_persistence(
            {"eventid": "cowrie.command.input", "input": object()}
        )


def test_rotation_and_restart_files_never_receive_plaintext(tmp_path: Path) -> None:
    active = tmp_path / "cowrie.json"
    rotated = tmp_path / "cowrie.json.2026-07-30"
    temporary = tmp_path / ".cowrie.json.tmp"
    secrets = ["first-rotation-secret", "second-restart-secret"]
    active.write_bytes(serialize_cowrie_event_for_persistence(_login(secrets[0])))
    active.rename(rotated)
    active.write_bytes(serialize_cowrie_event_for_persistence(_login(secrets[1])))
    temporary.write_bytes(b"sanitized diagnostic event rejected\n")
    for path in (active, rotated, temporary):
        content = path.read_bytes()
        assert all(secret.encode() not in content for secret in secrets)


def test_policy_is_strict_and_hash_bound(tmp_path: Path) -> None:
    policy = load_policy(ROOT / "configs/cowrie_output_privacy.v1.json")
    assert policy.policy_id == "cowrie_pre_persistence_credentials"
    document = json.loads(
        (ROOT / "configs/cowrie_output_privacy.v1.json").read_text(encoding="utf-8")
    )
    document["unknown_policy_key"] = True
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError, match="closed contract"):
        load_policy(bad)


def test_bundle_config_plugin_and_dropin_validate_together(tmp_path: Path) -> None:
    bundle, config, plugin, dropin = _configured_boundary(tmp_path)
    result = verify_boundary(
        config_path=config,
        bundle_root=bundle,
        plugin_link=plugin,
        drop_in=dropin,
    )
    assert result.git_revision == REVISION
    assert result.policy.sha256
    assert result.manifest_sha256


def test_both_safe_and_unsafe_writers_fail_closed(tmp_path: Path) -> None:
    bundle, config, plugin, dropin = _configured_boundary(tmp_path)
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            "[output_jsonlog]\nenabled = false",
            "[output_jsonlog]\nenabled = true",
        ),
        encoding="utf-8",
    )
    with pytest.raises(CowrieOutputBoundaryError, match="exactly"):
        verify_boundary(
            config_path=config,
            bundle_root=bundle,
            plugin_link=plugin,
            drop_in=dropin,
        )


def test_absent_component_hash_drift_and_open_permissions_fail_closed(
    tmp_path: Path,
) -> None:
    bundle = _build(tmp_path)
    target = bundle / "production/utils/cowrie_privacy.py"
    target.unlink()
    with pytest.raises(CowrieOutputBoundaryError, match="missing filesystem entries"):
        verify_bundle(bundle)

    bundle = _build(tmp_path / "second")
    target = bundle / "production/utils/cowrie_privacy.py"
    target.write_text(target.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(CowrieOutputBoundaryError, match="size mismatch"):
        verify_bundle(bundle)

    bundle = _build(tmp_path / "third")
    os.chmod(bundle, 0o755)
    with pytest.raises(CowrieOutputBoundaryError, match="owner-only"):
        verify_bundle(bundle)

    bundle = _build(tmp_path / "fourth")
    extra = bundle / "production/cowrie_output/__pycache__/runtime.pyc"
    extra.parent.mkdir(mode=0o700)
    extra.write_bytes(b"unmanifested bytecode")
    extra.chmod(0o600)
    with pytest.raises(CowrieOutputBoundaryError, match="unmanifested"):
        verify_bundle(bundle)


def test_config_render_preserves_unrelated_content_and_replaces_prior_safe_section(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.cfg"
    source.write_text(
        _source_config()
        + "\n[output_sanitizedjson]\nenabled = false\nlogfile = /wrong\n",
        encoding="utf-8",
    )
    destination = tmp_path / "rendered.cfg"
    render_config(source, destination, Path("/opt/honeypot-cowrie-output/current"))
    text = destination.read_text(encoding="utf-8")
    assert text.count("[output_sanitizedjson]") == 1
    assert "[output_textlog]\nenabled = false" in text
    assert "[output_jsonlog]\nenabled = false" in text
    assert "/wrong" not in text


def test_initialization_failure_has_no_output_side_effect(tmp_path: Path) -> None:
    bundle, config, plugin, dropin = _configured_boundary(tmp_path)
    output = tmp_path / "cowrie.json"
    (bundle / "configs/cowrie_output_privacy.v1.json").write_text(
        "{}", encoding="utf-8"
    )
    with pytest.raises(CowrieOutputBoundaryError):
        verify_boundary(
            config_path=config,
            bundle_root=bundle,
            plugin_link=plugin,
            drop_in=dropin,
        )
    assert not output.exists()


def test_installer_preserves_every_manifested_executable_mode() -> None:
    installer = (
        ROOT / "deployment/cowrie_output/install-sanitized-output.sh"
    ).read_text(encoding="utf-8")
    for script_name in (
        "install-sanitized-output.sh",
        "rollback-sanitized-output.sh",
        "run-sanitized-cowrie.sh",
    ):
        assert (
            f'chmod 0700 "${{release}}/deployment/cowrie_output/{script_name}"'
            in installer
        )
