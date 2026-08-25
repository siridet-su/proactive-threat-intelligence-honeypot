from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from live_invariant_receipt_writer import (
    REQUIRED_INVARIANTS,
    validate_complete_receipt,
    write_atomic_json,
)


def _complete_receipt() -> dict:
    return {
        "schema_version": "gcp_final_live_validation.v1",
        "status": "PASS",
        "errors": [],
        "checks": {name: True for name in REQUIRED_INVARIANTS},
    }


def test_pre_repair_keyword_call_reproduces_exact_failure() -> None:
    fd = os.open("/tmp", os.O_RDONLY)
    try:
        with pytest.raises(TypeError, match="gid"):
            # This is the exact invalid call from the failed ad-hoc validator.
            os.fchown(fd, 0, grp_id=os.getgid())  # type: ignore[call-arg]
    finally:
        os.close(fd)


def test_corrected_writer_uses_fd_uid_gid_and_mode(tmp_path: Path, monkeypatch) -> None:
    calls: list[tuple[int, int, int]] = []
    real_fchown = os.fchown

    def spy(fd: int, uid: int, gid: int) -> None:
        calls.append((fd, uid, gid))
        real_fchown(fd, uid, gid)

    monkeypatch.setattr(os, "fchown", spy)
    target = tmp_path / "receipt.json"
    write_atomic_json(
        target,
        {"ok": True},
        uid=os.getuid(),
        gid=os.getgid(),
        mode=0o640,
    )
    assert json.loads(target.read_text()) == {"ok": True}
    assert calls and calls[0][1:] == (os.getuid(), os.getgid())
    assert target.stat().st_mode & 0o777 == 0o640
    assert list(tmp_path.glob(".*.tmp")) == []


def test_atomic_writer_cleans_temporary_file_on_replace_failure(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "receipt.json"

    def fail_replace(_source, _destination):
        raise OSError("injected replace failure")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(OSError, match="injected replace failure"):
        write_atomic_json(
            target,
            {"ok": True},
            uid=os.getuid(),
            gid=os.getgid(),
        )
    assert not target.exists()
    assert list(tmp_path.glob(".*.tmp")) == []


def test_malformed_invariant_input_fails_closed() -> None:
    receipt = _complete_receipt()
    receipt["checks"].pop("rollback_readiness")
    with pytest.raises(ValueError, match="missing"):
        validate_complete_receipt(receipt)

    receipt = _complete_receipt()
    receipt["checks"]["shadow_canonical_write_disabled"] = False
    with pytest.raises(ValueError, match="failed"):
        validate_complete_receipt(receipt)
