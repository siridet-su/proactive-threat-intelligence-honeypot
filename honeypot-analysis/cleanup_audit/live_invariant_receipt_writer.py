"""Validation-only atomic writer for final live-invariant receipts.

This module is deliberately outside immutable release trees.  It does not
change candidate/runtime code; it only validates a completed result and writes
the compact receipt atomically with explicit ownership and mode.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Mapping


REQUIRED_INVARIANTS = (
    "durable_event_processing",
    "received_at_propagation",
    "terminal_evidence_cutoff",
    "v3_trusted_history_manifest",
    "semantic_uniqueness",
    "evidence_provenance_preserved",
    "v3_next_behavior_contract",
    "prediction_completion",
    "classifier_environment_binding",
    "shadow_non_authority",
    "shadow_canonical_write_disabled",
    "historical_replay_zero",
    "bounded_canonical_deltas",
    "alerts_lifecycle_invariants",
    "service_health",
    "selector_release_identity",
    "rollback_readiness",
)


def validate_complete_receipt(value: Any) -> dict[str, Any]:
    """Fail closed unless every required final invariant is explicitly true."""

    if not isinstance(value, Mapping):
        raise ValueError("final live-validation receipt must be an object")
    if value.get("schema_version") != "gcp_final_live_validation.v1":
        raise ValueError("final live-validation receipt schema is invalid")
    if value.get("status") != "PASS":
        raise ValueError("final live-validation receipt status is not PASS")
    errors = value.get("errors")
    if errors not in ([], None):
        raise ValueError("final live-validation receipt contains errors")
    checks = value.get("checks")
    if not isinstance(checks, Mapping):
        raise ValueError("final live-validation receipt checks are missing")
    missing = [name for name in REQUIRED_INVARIANTS if name not in checks]
    if missing:
        raise ValueError("required invariant checks are missing: " + ",".join(missing))
    failed = [name for name in REQUIRED_INVARIANTS if checks.get(name) is not True]
    if failed:
        raise ValueError("required invariant checks failed: " + ",".join(failed))
    return dict(value)


def write_atomic_json(
    path: str | os.PathLike[str],
    value: Mapping[str, Any],
    *,
    uid: int,
    gid: int,
    mode: int = 0o640,
) -> None:
    """Write JSON with explicit fd ownership/mode and failure cleanup.

    ``os.fchown`` intentionally receives positional ``uid`` and ``gid``.  A
    previous ad-hoc validator passed the unsupported keyword ``grp_id`` and
    failed before writing its receipt.
    """

    target = Path(path)
    if not target.parent.is_dir():
        raise FileNotFoundError(f"receipt parent directory is missing: {target.parent}")
    payload = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )
    fd, temporary = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent)
    )
    closed = False
    try:
        view = memoryview(payload)
        while view:
            view = view[os.write(fd, view) :]
        os.fchown(fd, int(uid), int(gid))
        os.fchmod(fd, int(mode))
        os.fsync(fd)
        os.close(fd)
        closed = True
        os.replace(temporary, target)
        directory_fd = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        if not closed:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def write_complete_receipt(
    path: str | os.PathLike[str],
    value: Mapping[str, Any],
    *,
    uid: int,
    gid: int,
    mode: int = 0o640,
) -> None:
    """Validate all invariants, then atomically write the complete receipt."""

    validated = validate_complete_receipt(value)
    write_atomic_json(path, validated, uid=uid, gid=gid, mode=mode)
