from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from production.tools.cowrie_rollback_receipt import (
    DIGEST_NAME,
    LEGACY_NAME,
    RECEIPT_NAME,
    SCHEMA_VERSION,
    RollbackReceiptError,
    apply_receipt,
    capture_receipt,
    managed_roots,
    verify_receipt,
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
    records, digest = capture_receipt(
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


def _move_quarantine(paths: dict[str, Path | tuple[Path, ...]]) -> None:
    text = paths["text"]
    receipt = paths["receipt"]
    assert isinstance(text, Path) and isinstance(receipt, Path)
    text.replace(receipt / "cowrie.log.protected.before")
    (receipt / "cowrie.log.protected.before").chmod(0o600)


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
    _move_quarantine(paths)

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


def test_v2_receipt_tampering_fails_before_any_target_changes(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    _capture(paths)
    _move_quarantine(paths)
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
    _move_quarantine(paths)
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


def test_installer_and_rollback_use_versioned_receipt_tool() -> None:
    root = Path(__file__).resolve().parents[1]
    installer = (root / "deployment/cowrie_output/install-sanitized-output.sh").read_text()
    rollback = (root / "deployment/cowrie_output/rollback-sanitized-output.sh").read_text()
    assert "cowrie_rollback_receipt capture" in installer
    assert "cowrie_rollback_receipt verify" in installer
    assert "cowrie_rollback_receipt verify" in rollback
    assert "cowrie_rollback_receipt apply" in rollback
    assert "stat -c 'metadata\\t" not in installer
    assert 'IFS="$(printf \'\\t\')"' not in rollback
    assert rollback.index("cowrie_rollback_receipt verify") < rollback.index(
        "systemctl stop cowrie.service"
    )


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
