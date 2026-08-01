from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

import production.tools.cowrie_rollback_receipt as receipt_module
from production.tools.cowrie_rollback_receipt import (
    CAPTURE_STEPS,
    DIGEST_NAME,
    LEGACY_NAME,
    RECEIPT_NAME,
    SCHEMA_VERSION,
    RollbackReceiptError,
    apply_receipt,
    assert_stopped_log_unheld,
    capture_stopped_receipt,
    managed_roots,
    verify_receipt,
    verify_stopped_baseline,
)


INSTALL_TRANSACTION_STEPS = (
    "receipt_directory_created",
    "immutable_records_captured",
    "cowrie_stop_requested",
    "cowrie_stopped",
    "log_quarantined",
    "quarantine_hash_recorded",
    "receipt_sealed",
    "receipt_verified",
    "release_extracted",
    "release_manifest_verified",
    "active_link_changed",
    "configuration_installed",
    "systemd_dropin_installed",
    "rotation_policy_installed",
    "cowrie_restart_requested",
    "cowrie_healthy",
)


def _file(path: Path, content: str, mode: int = 0o640) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(mode)
    return path


def _fixture(tmp_path: Path) -> dict[str, Path | tuple[Path, ...]]:
    root = tmp_path / "installed"
    cowrie = root / "cowrie"
    config = _file(cowrie / "etc/cowrie.cfg", "original-config", 0o600)
    plugin = _file(
        cowrie / "src/cowrie/output/sanitizedjson.py", "original-plugin", 0o644
    )
    logs = cowrie / "var/log/cowrie"
    json_log = _file(logs / "cowrie.json", "original-json\n", 0o640)
    custom_log = _file(logs / "cowrie_custom.json", "original-custom\n", 0o600)
    text_log = _file(logs / "cowrie.log", "protected-original\n", 0o600)
    historical = _file(logs / "cowrie.json.2026-08-01", "history\n", 0o640)
    users = _file(root / "users.txt", "user-hash\n", 0o600)
    dropin = _file(root / "systemd/20-sanitized-output.conf", "old-dropin", 0o644)
    logrotate = _file(root / "logrotate/cowrie", "old-logrotate", 0o644)
    releases = root / "releases"
    prior = releases / "prior"
    candidate = releases / "candidate"
    prior.mkdir(parents=True)
    candidate.mkdir()
    current = root / "current"
    current.symlink_to(prior)
    receipt = tmp_path / "receipt"
    receipt.mkdir(mode=0o700)
    roots = managed_roots(
        cowrie_root=cowrie,
        users_file=users,
        current=current,
        drop_in=dropin,
        logrotate=logrotate,
    )
    return {
        "cowrie": cowrie,
        "config": config,
        "plugin": plugin,
        "logs": logs,
        "json": json_log,
        "custom": custom_log,
        "text": text_log,
        "historical": historical,
        "users": users,
        "dropin": dropin,
        "logrotate": logrotate,
        "prior": prior,
        "candidate": candidate,
        "current": current,
        "receipt": receipt,
        "roots": roots,
    }


def _capture(paths: dict[str, Path | tuple[Path, ...]]) -> tuple[str, int]:
    records, digest = capture_stopped_receipt(
        receipt_dir=paths["receipt"],  # type: ignore[arg-type]
        cowrie_root=paths["cowrie"],  # type: ignore[arg-type]
        users_file=paths["users"],  # type: ignore[arg-type]
        current=paths["current"],  # type: ignore[arg-type]
        config=paths["config"],  # type: ignore[arg-type]
        plugin=paths["plugin"],  # type: ignore[arg-type]
        drop_in=paths["dropin"],  # type: ignore[arg-type]
        logrotate=paths["logrotate"],  # type: ignore[arg-type]
    )
    return digest, len(records)


def test_v2_receipt_round_trip_restores_content_metadata_link_and_quarantine(
    tmp_path: Path,
) -> None:
    paths = _fixture(tmp_path)
    digest, record_count = _capture(paths)
    receipt = paths["receipt"]
    assert isinstance(receipt, Path)
    assert stat.S_IMODE((receipt / RECEIPT_NAME).stat().st_mode) == 0o600
    assert stat.S_IMODE((receipt / DIGEST_NAME).stat().st_mode) == 0o600
    assert hashlib.sha256((receipt / RECEIPT_NAME).read_bytes()).hexdigest() == digest

    config = paths["config"]
    plugin = paths["plugin"]
    dropin = paths["dropin"]
    logrotate = paths["logrotate"]
    current = paths["current"]
    candidate = paths["candidate"]
    historical = paths["historical"]
    text = paths["text"]
    assert all(
        isinstance(item, Path)
        for item in (config, plugin, dropin, logrotate, current, candidate, historical, text)
    )
    for path in (config, plugin, dropin, logrotate):
        path.write_text("candidate", encoding="utf-8")  # type: ignore[union-attr]
        path.chmod(0o600)  # type: ignore[union-attr]
    current.unlink()  # type: ignore[union-attr]
    current.symlink_to(candidate)  # type: ignore[union-attr]
    historical.chmod(0o600)  # type: ignore[union-attr]
    text.write_text("failed-candidate-log", encoding="utf-8")  # type: ignore[union-attr]
    text.chmod(0o600)  # type: ignore[union-attr]

    records, verified_digest, schema = verify_receipt(
        receipt,
        expected_uid=os.geteuid(),
        allowed_roots=paths["roots"],  # type: ignore[arg-type]
    )
    assert len(records) == record_count
    assert verified_digest == digest
    assert schema == SCHEMA_VERSION
    restored, applied_digest, applied_schema = apply_receipt(
        receipt,
        expected_uid=os.geteuid(),
        allowed_roots=paths["roots"],  # type: ignore[arg-type]
    )

    assert restored == record_count
    assert applied_digest == digest
    assert applied_schema == SCHEMA_VERSION
    assert config.read_text() == "original-config"  # type: ignore[union-attr]
    assert plugin.read_text() == "original-plugin"  # type: ignore[union-attr]
    assert dropin.read_text() == "old-dropin"  # type: ignore[union-attr]
    assert logrotate.read_text() == "old-logrotate"  # type: ignore[union-attr]
    assert current.is_symlink()  # type: ignore[union-attr]
    assert current.resolve() == paths["prior"]  # type: ignore[union-attr]
    assert stat.S_IMODE(historical.stat().st_mode) == 0o640  # type: ignore[union-attr]
    assert text.read_text() == "protected-original\n"  # type: ignore[union-attr]
    assert (receipt / "cowrie.log.failed-deployment").read_text() == (
        "failed-candidate-log"
    )
    verify_receipt(
        receipt,
        expected_uid=os.geteuid(),
        allowed_roots=paths["roots"],  # type: ignore[arg-type]
    )


def test_interrupted_receipt_application_is_retryable_after_every_record(
    tmp_path: Path,
) -> None:
    probe = _fixture(tmp_path / "probe")
    _capture(probe)
    receipt = probe["receipt"]
    assert isinstance(receipt, Path)
    records, _digest, _schema = verify_receipt(
        receipt,
        expected_uid=os.geteuid(),
        allowed_roots=probe["roots"],  # type: ignore[arg-type]
    )

    for failure_index in range(len(records)):
        paths = _fixture(tmp_path / f"failure-{failure_index}")
        _capture(paths)
        config = paths["config"]
        plugin = paths["plugin"]
        dropin = paths["dropin"]
        logrotate = paths["logrotate"]
        current = paths["current"]
        candidate = paths["candidate"]
        historical = paths["historical"]
        text = paths["text"]
        assert all(
            isinstance(path, Path)
            for path in (
                config,
                plugin,
                dropin,
                logrotate,
                current,
                candidate,
                historical,
                text,
            )
        )
        for path in (config, plugin, dropin, logrotate):
            path.write_text("candidate", encoding="utf-8")  # type: ignore[union-attr]
            path.chmod(0o600)  # type: ignore[union-attr]
        current.unlink()  # type: ignore[union-attr]
        current.symlink_to(candidate)  # type: ignore[union-attr]
        historical.chmod(0o600)  # type: ignore[union-attr]
        text.write_text("failed-candidate-log", encoding="utf-8")  # type: ignore[union-attr]
        text.chmod(0o600)  # type: ignore[union-attr]

        def interrupt(index: int, _record: receipt_module.RollbackRecord) -> None:
            if index == failure_index:
                raise RuntimeError("deterministic apply interruption")

        with pytest.raises(RuntimeError, match="deterministic apply interruption"):
            apply_receipt(
                paths["receipt"],  # type: ignore[arg-type]
                expected_uid=os.geteuid(),
                allowed_roots=paths["roots"],  # type: ignore[arg-type]
                fault=interrupt,
            )
        apply_receipt(
            paths["receipt"],  # type: ignore[arg-type]
            expected_uid=os.geteuid(),
            allowed_roots=paths["roots"],  # type: ignore[arg-type]
        )
        assert config.read_text() == "original-config"  # type: ignore[union-attr]
        assert plugin.read_text() == "original-plugin"  # type: ignore[union-attr]
        assert dropin.read_text() == "old-dropin"  # type: ignore[union-attr]
        assert logrotate.read_text() == "old-logrotate"  # type: ignore[union-attr]
        assert current.resolve() == paths["prior"]  # type: ignore[union-attr]
        assert stat.S_IMODE(historical.stat().st_mode) == 0o640  # type: ignore[union-attr]
        assert text.read_text() == "protected-original\n"  # type: ignore[union-attr]
        assert not list(paths["cowrie"].rglob("*.rollback-file"))  # type: ignore[union-attr]
        assert not list(paths["cowrie"].rglob("*.rollback-link"))  # type: ignore[union-attr]
        verify_receipt(
            paths["receipt"],  # type: ignore[arg-type]
            expected_uid=os.geteuid(),
            allowed_roots=paths["roots"],  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    ("drift", "message"),
    [
        ("unrecorded_log", "unrecorded path"),
        ("recreated_active_log", "unexpectedly exists"),
        ("immutable_content", "file content changed"),
        ("mutable_metadata", "metadata changed"),
    ],
)
def test_stopped_baseline_verification_rejects_post_seal_drift(
    tmp_path: Path,
    drift: str,
    message: str,
) -> None:
    paths = _fixture(tmp_path)
    _capture(paths)
    receipt = paths["receipt"]
    cowrie = paths["cowrie"]
    config = paths["config"]
    text = paths["text"]
    json_log = paths["json"]
    assert all(
        isinstance(path, Path)
        for path in (receipt, cowrie, config, text, json_log)
    )
    records, _digest, _schema = verify_receipt(
        receipt,  # type: ignore[arg-type]
        expected_uid=os.geteuid(),
        allowed_roots=paths["roots"],  # type: ignore[arg-type]
    )
    verify_stopped_baseline(
        records,
        receipt_dir=receipt,  # type: ignore[arg-type]
        cowrie_root=cowrie,  # type: ignore[arg-type]
    )
    if drift == "unrecorded_log":
        _file(cowrie / "var/log/cowrie/unrecorded.log", "new", 0o600)  # type: ignore[operator]
    elif drift == "recreated_active_log":
        _file(text, "unexpected", 0o600)  # type: ignore[arg-type]
    elif drift == "immutable_content":
        config.write_text("changed", encoding="utf-8")  # type: ignore[union-attr]
    else:
        json_log.chmod(0o600)  # type: ignore[union-attr]
    with pytest.raises(RollbackReceiptError, match=message):
        verify_stopped_baseline(
            records,
            receipt_dir=receipt,  # type: ignore[arg-type]
            cowrie_root=cowrie,  # type: ignore[arg-type]
        )


def test_concurrent_append_is_bound_only_after_writer_stops(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    text = paths["text"]
    receipt = paths["receipt"]
    assert isinstance(text, Path) and isinstance(receipt, Path)
    preliminary = hashlib.sha256(text.read_bytes()).hexdigest()
    with text.open("a", encoding="utf-8") as handle:
        handle.write("append-before-stop\n")
        handle.flush()
        os.fsync(handle.fileno())
    final_payload = text.read_bytes()

    records, _digest = capture_stopped_receipt(
        receipt_dir=receipt,
        cowrie_root=paths["cowrie"],  # type: ignore[arg-type]
        users_file=paths["users"],  # type: ignore[arg-type]
        current=paths["current"],  # type: ignore[arg-type]
        config=paths["config"],  # type: ignore[arg-type]
        plugin=paths["plugin"],  # type: ignore[arg-type]
        drop_in=paths["dropin"],  # type: ignore[arg-type]
        logrotate=paths["logrotate"],  # type: ignore[arg-type]
    )
    quarantine = next(record for record in records if record.kind == "quarantine")
    assert quarantine.saved_bytes == len(final_payload)
    assert quarantine.saved_sha256 == hashlib.sha256(final_payload).hexdigest()
    assert quarantine.saved_sha256 != preliminary
    assert not text.exists()

    text.write_text("failed-candidate", encoding="utf-8")
    text.chmod(0o600)
    apply_receipt(
        receipt,
        expected_uid=os.geteuid(),
        allowed_roots=paths["roots"],  # type: ignore[arg-type]
    )
    assert text.read_bytes() == final_payload


@pytest.mark.parametrize("append_after_copy", [1, 5])
def test_append_during_preliminary_immutable_scan_is_in_final_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    append_after_copy: int,
) -> None:
    paths = _fixture(tmp_path)
    text = paths["text"]
    receipt = paths["receipt"]
    assert isinstance(text, Path) and isinstance(receipt, Path)
    preliminary = hashlib.sha256(text.read_bytes()).hexdigest()
    real_copy_record = receipt_module._copy_record
    copied = 0

    def append_while_scanning(
        target: Path, saved: str, receipt_dir: Path
    ) -> receipt_module.RollbackRecord:
        nonlocal copied
        record = real_copy_record(target, saved, receipt_dir)
        copied += 1
        if copied == append_after_copy:
            with text.open("ab") as handle:
                handle.write(b"append-during-preliminary-scan\n")
                handle.flush()
                os.fsync(handle.fileno())
        return record

    monkeypatch.setattr(receipt_module, "_copy_record", append_while_scanning)
    records, _digest = capture_stopped_receipt(
        receipt_dir=receipt,
        cowrie_root=paths["cowrie"],  # type: ignore[arg-type]
        users_file=paths["users"],  # type: ignore[arg-type]
        current=paths["current"],  # type: ignore[arg-type]
        config=paths["config"],  # type: ignore[arg-type]
        plugin=paths["plugin"],  # type: ignore[arg-type]
        drop_in=paths["dropin"],  # type: ignore[arg-type]
        logrotate=paths["logrotate"],  # type: ignore[arg-type]
    )
    quarantine = next(record for record in records if record.kind == "quarantine")
    protected = receipt / "cowrie.log.protected.before"
    assert quarantine.saved_sha256 == hashlib.sha256(protected.read_bytes()).hexdigest()
    assert quarantine.saved_sha256 != preliminary


def test_active_log_inode_replacement_during_quarantine_fails_closed_and_restores(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _fixture(tmp_path)
    text = paths["text"]
    receipt = paths["receipt"]
    assert isinstance(text, Path) and isinstance(receipt, Path)
    real_replace = receipt_module.os.replace
    replacement = b"replacement-inode-at-quarantine\n"
    swapped = False

    def replace(source: object, destination: object) -> None:
        nonlocal swapped
        source_path = Path(source)  # type: ignore[arg-type]
        destination_path = Path(destination)  # type: ignore[arg-type]
        if source_path == text and destination_path.parent == receipt and not swapped:
            swapped = True
            text.unlink()
            text.write_bytes(replacement)
            text.chmod(0o640)
        real_replace(source, destination)

    monkeypatch.setattr(receipt_module.os, "replace", replace)
    with pytest.raises(RollbackReceiptError, match="identity changed"):
        _capture(paths)
    assert swapped is True
    assert text.read_bytes() == replacement
    assert stat.S_IMODE(text.stat().st_mode) == 0o640
    assert not (receipt / RECEIPT_NAME).exists()
    assert not (receipt / DIGEST_NAME).exists()


@pytest.mark.parametrize("failure_step", CAPTURE_STEPS)
def test_each_stopped_capture_failure_restores_log_and_invalidates_receipt(
    tmp_path: Path,
    failure_step: str,
) -> None:
    paths = _fixture(tmp_path)
    text = paths["text"]
    receipt = paths["receipt"]
    current = paths["current"]
    assert isinstance(text, Path) and isinstance(receipt, Path)
    assert isinstance(current, Path)
    original = text.read_bytes()
    original_mode = stat.S_IMODE(text.stat().st_mode)

    def inject(step: str) -> None:
        if step == failure_step:
            raise RuntimeError("deterministic capture fault")

    with pytest.raises(RuntimeError, match="deterministic capture fault"):
        capture_stopped_receipt(
            receipt_dir=receipt,
            cowrie_root=paths["cowrie"],  # type: ignore[arg-type]
            users_file=paths["users"],  # type: ignore[arg-type]
            current=current,
            config=paths["config"],  # type: ignore[arg-type]
            plugin=paths["plugin"],  # type: ignore[arg-type]
            drop_in=paths["dropin"],  # type: ignore[arg-type]
            logrotate=paths["logrotate"],  # type: ignore[arg-type]
            fault=inject,
        )

    assert text.read_bytes() == original
    assert stat.S_IMODE(text.stat().st_mode) == original_mode
    assert not (receipt / "cowrie.log.protected.before").exists()
    assert not (receipt / RECEIPT_NAME).exists()
    assert not (receipt / DIGEST_NAME).exists()
    assert current.resolve() == paths["prior"]
    with pytest.raises(RollbackReceiptError, match="no supported"):
        verify_receipt(
            receipt,
            expected_uid=os.geteuid(),
            allowed_roots=paths["roots"],  # type: ignore[arg-type]
        )
    assert all(
        stat.S_IMODE(path.stat().st_mode) == 0o600
        for path in receipt.iterdir()
        if path.is_file()
    )


def test_open_log_descriptor_blocks_stopped_capture(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    text = paths["text"]
    receipt = paths["receipt"]
    assert isinstance(text, Path) and isinstance(receipt, Path)
    with text.open("rb"):
        with pytest.raises(RollbackReceiptError, match="still held"):
            assert_stopped_log_unheld(text)
        with pytest.raises(RollbackReceiptError, match="still held"):
            _capture(paths)
    assert text.exists()
    assert not (receipt / "cowrie.log.protected.before").exists()


@pytest.mark.parametrize("condition", ["missing", "symlink", "collision"])
def test_ambiguous_quarantine_inputs_fail_closed(
    tmp_path: Path,
    condition: str,
) -> None:
    paths = _fixture(tmp_path)
    text = paths["text"]
    receipt = paths["receipt"]
    assert isinstance(text, Path) and isinstance(receipt, Path)
    if condition == "missing":
        text.unlink()
    elif condition == "symlink":
        text.unlink()
        text.symlink_to(paths["config"])
    else:
        (receipt / "cowrie.log.protected.before").write_text(
            "collision", encoding="utf-8"
        )
        (receipt / "cowrie.log.protected.before").chmod(0o600)
    with pytest.raises((OSError, RollbackReceiptError)):
        _capture(paths)
    if condition == "symlink":
        assert text.is_symlink()
    if condition == "collision":
        assert text.read_text(encoding="utf-8") == "protected-original\n"


def test_saved_hash_mismatch_restores_log_and_invalidates_seal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _fixture(tmp_path)
    text = paths["text"]
    receipt = paths["receipt"]
    assert isinstance(text, Path) and isinstance(receipt, Path)
    original = text.read_bytes()
    real_saved_receipt = receipt_module._saved_receipt

    def mismatched(path: Path) -> tuple[int, str]:
        size, digest = real_saved_receipt(path)
        if path.name == "cowrie.log.protected.before":
            return size, "0" * len(digest)
        return size, digest

    monkeypatch.setattr(receipt_module, "_saved_receipt", mismatched)
    with pytest.raises(RollbackReceiptError, match="saved-file receipt mismatch"):
        _capture(paths)
    assert text.read_bytes() == original
    assert not (receipt / RECEIPT_NAME).exists()


def test_fsync_failure_restores_original_log(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _fixture(tmp_path)
    text = paths["text"]
    logs = paths["logs"]
    assert isinstance(text, Path) and isinstance(logs, Path)
    original = text.read_bytes()
    real_fsync_directory = receipt_module._fsync_directory
    failed = False

    def fail_once(path: Path) -> None:
        nonlocal failed
        if path == logs and not failed:
            failed = True
            raise OSError("deterministic fsync failure")
        real_fsync_directory(path)

    monkeypatch.setattr(receipt_module, "_fsync_directory", fail_once)
    with pytest.raises(OSError, match="deterministic fsync failure"):
        _capture(paths)
    assert text.read_bytes() == original


def test_receipt_seal_failure_restores_original_log(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _fixture(tmp_path)
    text = paths["text"]
    assert isinstance(text, Path)
    original = text.read_bytes()

    def fail_seal(_receipt: Path, _records: object) -> tuple[Path, str]:
        raise OSError("deterministic receipt seal failure")

    monkeypatch.setattr(receipt_module, "write_receipt", fail_seal)
    with pytest.raises(OSError, match="deterministic receipt seal failure"):
        _capture(paths)
    assert text.read_bytes() == original


def test_transient_restore_interruption_is_retried(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _fixture(tmp_path)
    text = paths["text"]
    assert isinstance(text, Path)
    original = text.read_bytes()
    real_replace = receipt_module.os.replace
    interrupted = False

    def replace(source: object, destination: object) -> None:
        nonlocal interrupted
        source_path = Path(source)  # type: ignore[arg-type]
        destination_path = Path(destination)  # type: ignore[arg-type]
        if (
            source_path.name == "cowrie.log.protected.before"
            and destination_path.name == "cowrie.log"
            and not interrupted
        ):
            interrupted = True
            raise OSError("transient restore interruption")
        real_replace(source, destination)

    monkeypatch.setattr(receipt_module.os, "replace", replace)

    def inject(step: str) -> None:
        if step == "log_quarantined":
            raise RuntimeError("force recovery")

    with pytest.raises(RuntimeError, match="force recovery"):
        capture_stopped_receipt(
            receipt_dir=paths["receipt"],  # type: ignore[arg-type]
            cowrie_root=paths["cowrie"],  # type: ignore[arg-type]
            users_file=paths["users"],  # type: ignore[arg-type]
            current=paths["current"],  # type: ignore[arg-type]
            config=paths["config"],  # type: ignore[arg-type]
            plugin=paths["plugin"],  # type: ignore[arg-type]
            drop_in=paths["dropin"],  # type: ignore[arg-type]
            logrotate=paths["logrotate"],  # type: ignore[arg-type]
            fault=inject,
        )
    assert interrupted is True
    assert text.read_bytes() == original


def test_v2_receipt_tampering_fails_before_any_target_changes(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    _capture(paths)
    receipt = paths["receipt"]
    config = paths["config"]
    assert isinstance(receipt, Path) and isinstance(config, Path)
    config.write_text("candidate", encoding="utf-8")
    with (receipt / RECEIPT_NAME).open("ab") as handle:
        handle.write(b"{}\n")
    with pytest.raises(RollbackReceiptError, match="digest mismatch"):
        apply_receipt(
            receipt,
            expected_uid=os.geteuid(),
            allowed_roots=paths["roots"],  # type: ignore[arg-type]
        )
    assert config.read_text() == "candidate"


def test_v2_saved_file_mode_or_content_drift_fails_before_changes(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    _capture(paths)
    receipt = paths["receipt"]
    config = paths["config"]
    assert isinstance(receipt, Path) and isinstance(config, Path)
    config.write_text("candidate", encoding="utf-8")
    saved = receipt / "cowrie.cfg.before"
    saved.chmod(0o640)
    with pytest.raises(RollbackReceiptError, match="saved-file boundary"):
        apply_receipt(
            receipt,
            expected_uid=os.geteuid(),
            allowed_roots=paths["roots"],  # type: ignore[arg-type]
        )
    assert config.read_text() == "candidate"


def test_receipt_target_cannot_escape_through_managed_parent_symlink(
    tmp_path: Path,
) -> None:
    managed = tmp_path / "managed"
    outside = tmp_path / "outside"
    managed.mkdir()
    outside.mkdir()
    (managed / "escape").symlink_to(outside, target_is_directory=True)
    receipt = tmp_path / "receipt"
    receipt.mkdir(mode=0o700)
    target = managed / "escape/file"
    document = {
        "record_type": "entry",
        "kind": "metadata",
        "target": str(target),
        "present": False,
        "saved": None,
        "saved_bytes": None,
        "saved_sha256": None,
        "mode": None,
        "uid": None,
        "gid": None,
    }
    payload = (
        json.dumps(
            {
                "record_type": "header",
                "schema_version": SCHEMA_VERSION,
                "record_count": 1,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
        + json.dumps(document, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()
    (receipt / RECEIPT_NAME).write_bytes(payload)
    (receipt / RECEIPT_NAME).chmod(0o600)
    digest = hashlib.sha256(payload).hexdigest()
    (receipt / DIGEST_NAME).write_text(f"{digest}  {RECEIPT_NAME}\n")
    (receipt / DIGEST_NAME).chmod(0o600)
    with pytest.raises(RollbackReceiptError, match="parent escapes"):
        verify_receipt(
            receipt,
            expected_uid=os.geteuid(),
            allowed_roots=(managed,),
        )


@pytest.mark.parametrize("literal_tabs", [False, True])
def test_legacy_actual_and_literal_tab_receipts_restore_metadata(
    tmp_path: Path,
    literal_tabs: bool,
) -> None:
    root = tmp_path / "managed"
    root.mkdir()
    target = _file(root / "historical.log", "unchanged", 0o600)
    receipt = tmp_path / "receipt"
    receipt.mkdir(mode=0o700)
    separator = "\\t" if literal_tabs else "\t"
    (receipt / LEGACY_NAME).write_text(
        separator.join(
            [
                "metadata",
                str(target),
                "-",
                "640",
                str(os.geteuid()),
                str(os.getegid()),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (receipt / LEGACY_NAME).chmod(0o600)
    count, _digest, schema = apply_receipt(
        receipt,
        expected_uid=os.geteuid(),
        allowed_roots=(root,),
    )
    assert count == 1
    assert schema == "cowrie_output_rollback_receipt.legacy_tsv"
    assert stat.S_IMODE(target.stat().st_mode) == 0o640


@pytest.mark.parametrize(
    "line",
    [
        "metadata\\t/managed/path\\t-\\t600\\t1\n",
        "metadata\\t/managed/literal\\tpath\\t-\\t600\\t1\\t1\n",
        "unknown\\t/managed/path\n",
    ],
)
def test_legacy_malformed_or_ambiguous_receipts_fail_closed(
    tmp_path: Path,
    line: str,
) -> None:
    root = tmp_path / "managed"
    root.mkdir()
    receipt = tmp_path / "receipt"
    receipt.mkdir(mode=0o700)
    (receipt / LEGACY_NAME).write_text(line, encoding="utf-8")
    (receipt / LEGACY_NAME).chmod(0o600)
    with pytest.raises(RollbackReceiptError):
        verify_receipt(
            receipt,
            expected_uid=os.geteuid(),
            allowed_roots=(root,),
        )


@pytest.mark.parametrize("failure_step", INSTALL_TRANSACTION_STEPS)
def test_every_installer_failure_boundary_recovers_prior_managed_state(
    tmp_path: Path,
    failure_step: str,
) -> None:
    """Exercise the installer's receipt boundary without host systemd state.

    The shell contract is checked separately. This disposable state machine
    applies the same managed-file mutations and the real receipt verifier and
    restorer at each recorded failure boundary.
    """

    paths = _fixture(tmp_path)
    receipt = paths["receipt"]
    text = paths["text"]
    config = paths["config"]
    dropin = paths["dropin"]
    logrotate = paths["logrotate"]
    current = paths["current"]
    candidate = paths["candidate"]
    historical = paths["historical"]
    assert all(
        isinstance(path, Path)
        for path in (
            receipt,
            text,
            config,
            dropin,
            logrotate,
            current,
            candidate,
            historical,
        )
    )
    original = {
        "text": text.read_bytes(),  # type: ignore[union-attr]
        "config": config.read_bytes(),  # type: ignore[union-attr]
        "dropin": dropin.read_bytes(),  # type: ignore[union-attr]
        "logrotate": logrotate.read_bytes(),  # type: ignore[union-attr]
        "historical": historical.read_bytes(),  # type: ignore[union-attr]
    }
    original_modes = {
        path: stat.S_IMODE(path.stat().st_mode)  # type: ignore[union-attr]
        for path in (text, config, dropin, logrotate, historical)
    }
    forwarder_pid = 4242
    observed_forwarder_pid = forwarder_pid
    receipt_ready = False
    service_active = True
    reached: list[str] = []

    def boundary(step: str) -> bool:
        reached.append(step)
        return step == failure_step

    if not boundary("receipt_directory_created"):
        # These are diagnostic hashes only and never saved-file authority for
        # the live text log.
        preliminary_log_hash = hashlib.sha256(text.read_bytes()).hexdigest()  # type: ignore[union-attr]
        assert preliminary_log_hash
        if not boundary("immutable_records_captured"):
            service_active = False
            if not boundary("cowrie_stop_requested") and not boundary("cowrie_stopped"):
                if failure_step in CAPTURE_STEPS:
                    def fail_capture(step: str) -> None:
                        reached.append(step)
                        if step == failure_step:
                            raise RuntimeError("injected installer capture failure")

                    with pytest.raises(
                        RuntimeError, match="injected installer capture failure"
                    ):
                        capture_stopped_receipt(
                            receipt_dir=receipt,  # type: ignore[arg-type]
                            cowrie_root=paths["cowrie"],  # type: ignore[arg-type]
                            users_file=paths["users"],  # type: ignore[arg-type]
                            current=current,  # type: ignore[arg-type]
                            config=config,  # type: ignore[arg-type]
                            plugin=paths["plugin"],  # type: ignore[arg-type]
                            drop_in=dropin,  # type: ignore[arg-type]
                            logrotate=logrotate,  # type: ignore[arg-type]
                            fault=fail_capture,
                        )
                else:
                    _capture(paths)
                    receipt_ready = True
                    (candidate / "candidate-release").write_text(
                        "candidate", encoding="utf-8"
                    )  # type: ignore[operator]
                    if not boundary("release_extracted"):
                        if not boundary("release_manifest_verified"):
                            current.unlink()  # type: ignore[union-attr]
                            current.symlink_to(candidate)  # type: ignore[union-attr]
                            if not boundary("active_link_changed"):
                                config.write_text("candidate-config", encoding="utf-8")  # type: ignore[union-attr]
                                config.chmod(0o644)  # type: ignore[union-attr]
                                if not boundary("configuration_installed"):
                                    dropin.write_text("candidate-dropin", encoding="utf-8")  # type: ignore[union-attr]
                                    dropin.chmod(0o600)  # type: ignore[union-attr]
                                    if not boundary("systemd_dropin_installed"):
                                        logrotate.write_text("candidate-rotation", encoding="utf-8")  # type: ignore[union-attr]
                                        logrotate.chmod(0o600)  # type: ignore[union-attr]
                                        if not boundary("rotation_policy_installed"):
                                            text.write_text("candidate-log", encoding="utf-8")  # type: ignore[union-attr]
                                            text.chmod(0o600)  # type: ignore[union-attr]
                                            if not boundary("cowrie_restart_requested"):
                                                service_active = True
                                                boundary("cowrie_healthy")

    if receipt_ready:
        service_active = False
        apply_receipt(
            receipt,  # type: ignore[arg-type]
            expected_uid=os.geteuid(),
            allowed_roots=paths["roots"],  # type: ignore[arg-type]
        )
        candidate_file = candidate / "candidate-release"  # type: ignore[operator]
        if candidate_file.exists():
            candidate_file.unlink()
    service_active = True

    assert failure_step in reached
    assert service_active is True
    assert observed_forwarder_pid == forwarder_pid
    assert current.resolve() == paths["prior"]  # type: ignore[union-attr]
    assert not (current.parent / f"{current.name}.new").exists()  # type: ignore[union-attr]
    assert text.read_bytes() == original["text"]  # type: ignore[union-attr]
    assert config.read_bytes() == original["config"]  # type: ignore[union-attr]
    assert dropin.read_bytes() == original["dropin"]  # type: ignore[union-attr]
    assert logrotate.read_bytes() == original["logrotate"]  # type: ignore[union-attr]
    assert historical.read_bytes() == original["historical"]  # type: ignore[union-attr]
    for path, mode in original_modes.items():
        assert stat.S_IMODE(path.stat().st_mode) == mode
    assert all(
        stat.S_IMODE(path.stat().st_mode) == 0o600
        for path in receipt.iterdir()  # type: ignore[union-attr]
        if path.is_file()
    )


def test_installer_and_rollback_use_versioned_receipt_tool() -> None:
    root = Path(__file__).resolve().parents[1]
    installer = (root / "deployment/cowrie_output/install-sanitized-output.sh").read_text()
    rollback = (root / "deployment/cowrie_output/rollback-sanitized-output.sh").read_text()
    assert "cowrie_rollback_receipt" in installer
    assert "capture-stopped" in installer
    assert "receipt_tool verify-stopped" in installer
    assert "cowrie_rollback_receipt verify" in rollback
    assert "cowrie_rollback_receipt apply" in rollback
    assert "stat -c 'metadata\\t" not in installer
    assert 'IFS="$(printf \'\\t\')"' not in rollback
    assert rollback.index("cowrie_rollback_receipt verify") < rollback.index(
        "systemctl stop cowrie.service"
    )


def test_installer_records_complete_transaction_in_required_order() -> None:
    root = Path(__file__).resolve().parents[1]
    installer = (root / "deployment/cowrie_output/install-sanitized-output.sh").read_text()
    offsets = [installer.index(f"record_step {step}") for step in INSTALL_TRANSACTION_STEPS]
    assert offsets == sorted(offsets)
    assert installer.index("systemctl stop cowrie.service", offsets[1]) < installer.index(
        "receipt_tool capture-stopped"
    )
    assert installer.index("receipt_tool verify-stopped") < installer.index(
        'tar --no-same-owner -xf "${package}"'
    )
    capture_offset = installer.index("receipt_tool capture-stopped")
    assert installer.index("receipt_ready=1", capture_offset) < installer.index(
        'chmod 0600 "${receipt}/receipt-capture.json"'
    )
    assert 'timeout 30 systemctl stop cowrie.service' in installer
    assert 'process_file="/sys/fs/cgroup${control_group}/cgroup.procs"' in installer
    assert '[ -z "$(cat "${process_file}")" ]' in installer
    assert 'receipt_tool assert-stopped --active-log "${active_text_log}"' in installer
    assert 'receipt_tool apply' in installer
    assert 'start_cowrie_bounded' in installer
    assert 'rm -rf "${release}"' in installer
    assert 'for temporary_link in "${current}.new" "${plugin}.new"' in installer
    assert 'systemctl stop "${forwarder}"' not in installer
    assert 'systemctl restart "${forwarder}"' not in installer
    rollback = (
        root / "deployment/cowrie_output/rollback-sanitized-output.sh"
    ).read_text()
    assert 'process_file="/sys/fs/cgroup${control_group}/cgroup.procs"' in rollback
    assert '[ -z "$(cat "${process_file}")" ]' in rollback
    assert 'forwarder_pid=$(systemctl show "${forwarder}" -p MainPID --value)' in rollback
    assert rollback.count(
        'test "$(systemctl show "${forwarder}" -p MainPID --value)" = "${forwarder_pid}"'
    ) == 1


def test_v2_receipt_has_closed_header_and_entry_contract(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    _capture(paths)
    receipt = paths["receipt"]
    assert isinstance(receipt, Path)
    documents = [json.loads(line) for line in (receipt / RECEIPT_NAME).read_text().splitlines()]
    assert documents[0]["schema_version"] == SCHEMA_VERSION
    assert documents[0]["record_count"] == len(documents) - 1
    expected = {
        "record_type",
        "kind",
        "target",
        "present",
        "saved",
        "saved_bytes",
        "saved_sha256",
        "mode",
        "uid",
        "gid",
    }
    assert all(set(document) == expected for document in documents[1:])
