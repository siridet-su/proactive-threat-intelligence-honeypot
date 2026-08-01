from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from production.cowrie_output import sanitized_jsonlog
from production.cowrie_output.observer_diagnostics import (
    set_isolated_diagnostic_sink,
)
from production.cowrie_output.twisted_logger import _isolated_text_observer
from production.cowrie_output.runtime import (
    DEPLOYMENT_CONTRACT,
    CowrieOutputBoundaryError,
    verify_boundary,
    verify_bundle,
)
from production.tools.cowrie_output_integration import (
    build_bundle,
    finish_live_rotation,
    prepare_live_rotation,
    render_config,
    validate_live_permissions,
    verify_starting_sanitizer,
)
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


def _live_boundary(tmp_path: Path):
    bundle = _build(tmp_path)
    logs = tmp_path / "logs"
    logs.mkdir(mode=0o750)
    source = tmp_path / "cowrie.before.cfg"
    source.write_text(
        _source_config().replace("/tmp/cowrie-log", str(logs)),
        encoding="utf-8",
    )
    config = tmp_path / "cowrie.cfg"
    render_config(source, config, bundle)
    return verify_boundary(config_path=config, bundle_root=bundle), logs


class _MemoryOutput:
    def __init__(self, *, fail_write: bool = False, fail_flush: bool = False) -> None:
        self.values: list[str] = []
        self.flushes = 0
        self.fail_write = fail_write
        self.fail_flush = fail_flush

    def write(self, value: str) -> None:
        if self.fail_write:
            raise OSError("untrusted write failure detail")
        self.values.append(value)

    def flush(self) -> None:
        if self.fail_flush:
            raise OSError("untrusted flush failure detail")
        self.flushes += 1


def _json_observer(output: _MemoryOutput):
    observer = object.__new__(sanitized_jsonlog.Output)
    observer.outfile = output
    observer._boundary = SimpleNamespace(policy=DEFAULT_POLICY)
    observer.epoch_timestamp = False
    observer._observer_sequence = 0
    return observer


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
    assert diagnostic["diagnostic_category"] == "diagnostic"
    assert diagnostic["diagnostic_outcome"] == "observed"


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
    assert event["diagnostic_category"] == "operation"
    assert event["diagnostic_outcome"] == "failed"
    assert "log_failure" not in event


@pytest.mark.parametrize(
    "secret",
    [
        "space containing credential",
        "quotes-'\"-and-\\escapes",
        "unicode-密碼-🔐",
        "control\ncharacters\tremain-private",
        "x" * 16_384,
    ],
)
def test_unstructured_diagnostics_are_projected_without_attacker_text(
    secret: str,
) -> None:
    event = {
        "log_format": f"unstructured authentication registry {secret}",
        "message": (f"unstructured authentication registry {secret}",),
        "log_namespace": f"attacker.{secret}",
        "log_system": secret,
        "session": "0123456789abcdef",
        "log_time": 42.0,
    }
    projected = sanitize_twisted_event(
        event,
        registry=CredentialValueRegistry(DEFAULT_POLICY),
    )
    encoded = json.dumps(projected, ensure_ascii=False, sort_keys=True)
    assert secret not in encoded
    assert set(projected) == {
        "log_format",
        "diagnostic_category",
        "diagnostic_outcome",
        "session_ref",
        "log_time",
    }
    assert projected["session_ref"].startswith("session_")


@pytest.mark.parametrize(
    ("eventid", "category", "outcome"),
    [
        ("cowrie.login.success", "authentication", "success"),
        ("cowrie.login.failed", "authentication", "failed"),
        ("cowrie.session.connect", "session", "started"),
        ("cowrie.session.closed", "session", "closed"),
        ("cowrie.command.input", "command", "observed"),
        ("cowrie.command.failed", "command", "failed"),
        ("cowrie.session.file_upload", "transfer", "observed"),
        ("cowrie.client.version", "client", "observed"),
        ("cowrie.direct-tcpip.request", "network", "observed"),
    ],
)
def test_diagnostic_projection_preserves_only_closed_operational_categories(
    eventid: str,
    category: str,
    outcome: str,
) -> None:
    projected = sanitize_twisted_event(
        {
            "eventid": eventid,
            "username": "arbitrary-user",
            "password": "arbitrary-password",
            "message": "arbitrary-user arbitrary-password",
            "session": "0123456789abcdef",
            "log_time": 1.0,
        },
        registry=CredentialValueRegistry(DEFAULT_POLICY),
    )
    assert projected["diagnostic_category"] == category
    assert projected["diagnostic_outcome"] == outcome
    assert "arbitrary-user" not in json.dumps(projected)
    assert "arbitrary-password" not in json.dumps(projected)


def test_diagnostic_projection_rejects_attacker_controlled_event_identity_and_time() -> None:
    secret = "event-identity-secret"
    projected = sanitize_twisted_event(
        {
            "eventid": secret,
            "session": {"credential": secret},
            "log_time": float("nan"),
            "message": secret,
        },
        registry=CredentialValueRegistry(DEFAULT_POLICY),
    )
    assert projected["diagnostic_category"] == "diagnostic"
    assert projected["diagnostic_outcome"] == "observed"
    assert projected["session_ref"] == "session_unavailable"
    assert projected["log_time"] == 0.0
    assert secret not in json.dumps(projected)


def test_malformed_or_unserializable_events_are_rejected_without_partial_bytes() -> None:
    with pytest.raises(ValueError, match="must be an object"):
        serialize_cowrie_event_for_persistence(["not", "an", "object"])  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="not safely serializable"):
        serialize_cowrie_event_for_persistence(
            {"eventid": "cowrie.command.input", "input": object()}
        )


def test_json_output_implements_cowrie_abstract_contract_and_writes_once() -> None:
    assert {"start", "stop", "write"} <= set(sanitized_jsonlog.Output.__dict__)
    secret = "generated-observer-secret"
    original = _login(secret)
    snapshot = json.loads(json.dumps(original))
    target = _MemoryOutput()
    observer = _json_observer(target)

    observer.write(original)

    assert original == snapshot
    assert len(target.values) == 1
    assert target.flushes == 1
    assert target.values[0].endswith("\n")
    assert target.values[0].count("\n") == 1
    decoded = json.loads(target.values[0])
    assert decoded["eventid"] == "cowrie.login.success"
    assert decoded["timestamp"] == original["timestamp"]
    assert decoded["username"] == "[REDACTED]"
    assert decoded["password"] == "[REDACTED]"
    assert secret not in target.values[0]
    assert list(decoded) == sorted(decoded)


@pytest.mark.parametrize("text_first", [True, False])
def test_observer_order_does_not_change_json_or_mutate_shared_event(
    text_first: bool,
) -> None:
    secret = "order-independent-secret"
    event = _login(secret)
    snapshot = json.loads(json.dumps(event))
    text_target = _MemoryOutput()
    text_events: list[dict] = []

    def text_writer(safe_event: dict) -> None:
        text_events.append(dict(safe_event))
        safe_event["diagnostic_category"] = "mutated-by-test-sink"

    text_observer = _isolated_text_observer(
        text_writer,
        text_target,
        SimpleNamespace(policy=DEFAULT_POLICY),
    )
    json_target = _MemoryOutput()
    json_observer = _json_observer(json_target)
    ordered = (
        (text_observer, json_observer.write)
        if text_first
        else (json_observer.write, text_observer)
    )
    for observer in ordered:
        observer(event)

    assert event == snapshot
    assert len(text_events) == 1
    assert len(json_target.values) == 1
    assert secret not in json_target.values[0]
    assert secret not in json.dumps(text_events)


def test_text_observer_failure_cannot_suppress_json_output() -> None:
    event = _login("text-failure-secret")

    def failed_text_writer(_safe_event: dict) -> None:
        raise RuntimeError("attacker-controlled exception detail")

    text_observer = _isolated_text_observer(
        failed_text_writer,
        _MemoryOutput(),
        SimpleNamespace(policy=DEFAULT_POLICY),
    )
    target = _MemoryOutput()
    json_observer = _json_observer(target)
    text_observer(event)
    json_observer.write(event)

    assert len(target.values) == 1
    assert "text-failure-secret" not in target.values[0]


@pytest.mark.parametrize(
    ("target", "category"),
    [
        (_MemoryOutput(fail_write=True), "write"),
        (_MemoryOutput(fail_flush=True), "flush"),
    ],
)
def test_json_persistence_failures_stop_with_bounded_diagnostics(
    target: _MemoryOutput,
    category: str,
) -> None:
    diagnostics: list[dict] = []
    previous = set_isolated_diagnostic_sink(diagnostics.append)
    try:
        with pytest.raises(SystemExit, match="failed closed"):
            _json_observer(target).write(_login("persistence-failure-secret"))
    finally:
        set_isolated_diagnostic_sink(previous)

    assert diagnostics[-1]["exception_category"] == category
    assert "persistence-failure-secret" not in json.dumps(diagnostics)
    assert "untrusted" not in json.dumps(diagnostics)


def test_json_serialization_failure_is_visible_and_writes_no_partial_record() -> None:
    target = _MemoryOutput()
    event = _login("serialization-secret")
    event["unsupported"] = object()
    with pytest.raises(SystemExit, match="event rejected"):
        _json_observer(target).write(event)
    assert target.values == []
    assert target.flushes == 0


def test_isolated_observer_diagnostics_are_closed_and_privacy_safe() -> None:
    diagnostics: list[dict] = []
    secret = "diagnostic-sink-secret"
    previous = set_isolated_diagnostic_sink(diagnostics.append)
    try:
        event = _login(secret)
        text_target = _MemoryOutput()
        _isolated_text_observer(
            lambda safe: text_target.write(json.dumps(safe, sort_keys=True)),
            text_target,
            SimpleNamespace(policy=DEFAULT_POLICY),
        )(event)
        _json_observer(_MemoryOutput()).write(event)
    finally:
        set_isolated_diagnostic_sink(previous)

    assert diagnostics
    assert secret not in json.dumps(diagnostics)
    for item in diagnostics:
        assert set(item) == {
            "schema_version",
            "observer",
            "phase",
            "sequence",
            "event_category",
            "event_id_sha256",
            "output_path_category",
            "write_attempted",
            "write_succeeded",
            "flush_succeeded",
            "exception_category",
        }


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


def test_rotation_boundary_closes_modes_before_copy_and_after_rotation(
    tmp_path: Path,
) -> None:
    boundary, logs = _live_boundary(tmp_path)
    active_json = logs / "cowrie.json"
    active_text = logs / "cowrie.log"
    historical = logs / "cowrie.json.2026-08-01"
    active_json.write_bytes(b"sanitized-json\n")
    active_text.write_bytes(b"categorical-diagnostic\n")
    historical.write_bytes(b"sanitized-history\n")
    active_json.chmod(0o640)
    active_text.chmod(0o600)
    historical.chmod(0o600)

    validate_live_permissions(boundary)
    prepare_live_rotation(boundary)
    assert stat.S_IMODE(active_json.stat().st_mode) == 0o600
    assert stat.S_IMODE(active_text.stat().st_mode) == 0o600

    compressed = logs / "cowrie.json.1.gz"
    compressed.write_bytes(active_json.read_bytes())
    compressed.chmod(stat.S_IMODE(active_json.stat().st_mode))
    active_json.write_bytes(b"")
    finish_live_rotation(boundary)
    assert stat.S_IMODE(active_json.stat().st_mode) == 0o640
    assert stat.S_IMODE(active_text.stat().st_mode) == 0o600
    assert stat.S_IMODE(historical.stat().st_mode) == 0o600
    assert stat.S_IMODE(compressed.stat().st_mode) == 0o600
    validate_live_permissions(boundary)


def test_live_permission_validation_rejects_open_rotations_and_symlinks(
    tmp_path: Path,
) -> None:
    boundary, logs = _live_boundary(tmp_path)
    active_json = logs / "cowrie.json"
    active_json.write_bytes(b"sanitized\n")
    active_json.chmod(0o640)
    unsafe = logs / "cowrie.json.1.gz"
    unsafe.write_bytes(b"sanitized\n")
    unsafe.chmod(0o640)
    with pytest.raises(CowrieOutputBoundaryError, match="historical Cowrie log mode"):
        validate_live_permissions(boundary)
    unsafe.chmod(0o600)
    link = logs / "unexpected.log"
    link.symlink_to(unsafe)
    with pytest.raises(CowrieOutputBoundaryError, match="historical Cowrie log type"):
        validate_live_permissions(boundary)


@pytest.mark.skipif(shutil.which("logrotate") is None, reason="logrotate unavailable")
def test_real_copytruncate_and_compression_never_create_group_readable_history(
    tmp_path: Path,
) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    active_json = logs / "cowrie.json"
    active_text = logs / "cowrie.log"
    active_json.write_bytes(b"sanitized-json\n")
    active_text.write_bytes(b"categorical-diagnostic\n")
    active_json.chmod(0o640)
    active_text.chmod(0o600)
    config = tmp_path / "logrotate.conf"
    state = tmp_path / "logrotate.state"
    original_json = active_json.read_bytes()
    config.write_text(
        f"""{active_text} {{
    size 1
    rotate 2
    compress
    copytruncate
    sharedscripts
    firstaction
        chmod 0600 {active_text}
    endscript
    lastaction
        chmod 0600 {active_text} {logs}/*.1.gz
    endscript
}}
""",
        encoding="utf-8",
    )
    result = subprocess.run(
        ["logrotate", "-f", "-s", str(state), str(config)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert stat.S_IMODE(active_json.stat().st_mode) == 0o640
    assert active_json.read_bytes() == original_json
    assert not (logs / "cowrie.json.1.gz").exists()
    assert stat.S_IMODE(active_text.stat().st_mode) == 0o600
    assert stat.S_IMODE((logs / "cowrie.log.1.gz").stat().st_mode) == 0o600


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
    logrotate = tmp_path / "cowrie.logrotate"
    logrotate.write_bytes(
        (bundle / "deployment/cowrie_output/cowrie.logrotate").read_bytes()
    )
    logrotate.chmod(0o644)
    result = verify_boundary(
        config_path=config,
        bundle_root=bundle,
        plugin_link=plugin,
        drop_in=dropin,
        logrotate=logrotate,
    )
    assert result.git_revision == REVISION
    assert result.policy.sha256
    assert result.manifest_sha256
    manifest = json.loads((bundle / "COWRIE_OUTPUT_MANIFEST.json").read_text())
    assert manifest["deployment"] == DEPLOYMENT_CONTRACT


def test_manifest_rejects_deployment_contract_drift(tmp_path: Path) -> None:
    bundle = _build(tmp_path)
    manifest_path = bundle / "COWRIE_OUTPUT_MANIFEST.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["deployment"]["compatibility"]["twisted"] = "unreviewed"
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
    )
    manifest_path.chmod(0o600)
    with pytest.raises(CowrieOutputBoundaryError, match="deployment contract"):
        verify_bundle(bundle)


def test_repeated_runtime_imports_leave_immutable_release_bytecode_free(
    tmp_path: Path,
) -> None:
    bundle = _build(tmp_path)
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": str(bundle),
        }
    )
    command = [
        sys.executable,
        "-c",
        (
            "from production.cowrie_output.runtime import verify_bundle; "
            "verify_bundle(__import__('pathlib').Path(__import__('sys').argv[1]))"
        ),
        str(bundle),
    ]
    for _ in range(2):
        subprocess.run(
            command,
            cwd=tmp_path,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
    assert not list(bundle.rglob("__pycache__"))
    assert not list(bundle.rglob("*.pyc"))
    verify_bundle(bundle)


def test_starting_sanitizer_link_and_manifest_are_exactly_bound(tmp_path: Path) -> None:
    revision = "2" * 40
    releases = tmp_path / "releases"
    release = releases / revision
    release.mkdir(parents=True)
    manifest = release / "COWRIE_OUTPUT_MANIFEST.json"
    manifest.write_text(json.dumps({"git_revision": revision}) + "\n")
    manifest.chmod(0o600)
    current = tmp_path / "current"
    current.symlink_to(release)
    assert (
        verify_starting_sanitizer(
            current,
            releases_root=releases,
            expected_revision=revision,
        )
        == revision
    )
    manifest.write_text(json.dumps({"git_revision": "3" * 40}) + "\n")
    manifest.chmod(0o600)
    with pytest.raises(CowrieOutputBoundaryError, match="identity"):
        verify_starting_sanitizer(
            current,
            releases_root=releases,
            expected_revision=revision,
        )


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
    assert 'chmod 0640 "${cowrie_root}/var/log/cowrie/cowrie.json"' in installer
    assert "historical-log-hashes.before.sha256" in installer
    historical_hash_command = installer.split(
        'historical-log-hashes.before.sha256'
    )[0].rsplit("find ", 1)[-1]
    for active_name in ("cowrie.json", "cowrie.log", "cowrie_custom.json"):
        assert f'! -path "${{cowrie_root}}/var/log/cowrie/{active_name}"' in (
            historical_hash_command
        )
    assert (
        'find "${cowrie_root}/var/log/cowrie" -xdev -type f' in installer
        and "-exec chmod 0600 {} +" in installer
    )
    assert "receipt_tool capture-stopped" in installer
    assert '--logrotate "${logrotate}"' in installer
    assert "cowrie_output_integration verify-start" in installer
    assert "cowrie_output_integration verify-bundle" in installer
    receipt_tool = (
        ROOT / "production/tools/cowrie_rollback_receipt.py"
    ).read_text(encoding="utf-8")
    assert 'protected_log = receipt_dir / "cowrie.log.protected.before"' in receipt_tool
    assert 'systemctl stop cowrie.service' in installer
    assert 'install -o root -g root -m 0644' in installer


def test_service_discards_untrusted_process_streams_and_binds_rotation_policy() -> None:
    dropin = (
        ROOT / "deployment/cowrie_output/20-sanitized-output.conf"
    ).read_text(encoding="utf-8")
    assert "StandardOutput=null" in dropin
    assert "StandardError=null" in dropin
    assert "--live-permissions" in dropin
    assert "--logrotate /etc/logrotate.d/cowrie" in dropin
    rotation = (
        ROOT / "deployment/cowrie_output/cowrie.logrotate"
    ).read_text(encoding="utf-8")
    assert "firstaction" in rotation
    assert "prepare-rotation" in rotation
    assert "lastaction" in rotation
    assert "finish-rotation" in rotation
    assert "copytruncate" in rotation
    first_line = rotation.splitlines()[0]
    assert "cowrie.log" in first_line
    assert "cowrie.json" not in first_line
    assert "compress" in rotation
