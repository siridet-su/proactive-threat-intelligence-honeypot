from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import subprocess
import sys

import pytest

from production.storage.backend import SQLiteStorage
from production.storage.canonical_event import CanonicalEventRecord
from production.storage.rollback_mirror_identity import (
    prepare_rollback_mirror,
    validate_rollback_mirror_identity,
    verify_rollback_mirror,
)
from production.utils.serialization import stable_json


EPOCH = "mongodb-retry-test"
RELEASE = "a" * 40
TREE = "b" * 40


def _prepare(tmp_path, name="mirror.db", epoch=EPOCH):
    return prepare_rollback_mirror(
        tmp_path / name,
        epoch_id=epoch,
        reviewed_release_sha=RELEASE,
        reviewed_release_tree=TREE,
        created_at="2026-08-13T00:00:00+00:00",
        mirror_id=f"rollback-mirror-{name}",
    )


def _rehash(identity):
    identity["identity_id"] = hashlib.sha256(
        stable_json({k: v for k, v in identity.items() if k != "identity_id"}).encode()
    ).hexdigest()


def test_prepared_identity_binds_checkpointed_zero_event_file(tmp_path):
    identity = _prepare(tmp_path)
    result = verify_rollback_mirror(identity, phase="prepared")
    assert result["phase"] == "prepared"
    assert result["event_count"] == 0
    assert result["initial_sha256_verified"] is True
    wal = tmp_path / "mirror.db-wal"
    assert not wal.exists() or wal.stat().st_size == 0


def test_active_restart_uses_lineage_not_mutable_initial_hash(tmp_path):
    identity = _prepare(tmp_path)
    storage = SQLiteStorage(f"sqlite:///{identity['path']}")
    record = CanonicalEventRecord.create(
        "sensor-1", {"eventid": "cowrie.command.input", "session": "s1", "input": "id"}
    )
    storage.store_canonical_event(record)
    assert hashlib.sha256((tmp_path / "mirror.db").read_bytes()).hexdigest() != identity["initial_sha256"]
    first = verify_rollback_mirror(identity, phase="auto")
    second = verify_rollback_mirror(identity, phase="auto")
    assert first == second
    assert first["phase"] == "active"
    assert first["event_count"] == 1
    assert first["initial_sha256_verified"] is False


def test_same_path_different_database_is_rejected(tmp_path):
    identity = _prepare(tmp_path)
    other = _prepare(tmp_path, "other.db", epoch="other-epoch")
    (tmp_path / "mirror.db").unlink()
    shutil.copy2(other["path"], identity["path"])
    with pytest.raises(ValueError, match="embedded lineage"):
        verify_rollback_mirror(identity, phase="auto")


def test_nonzero_mirror_cannot_validate_as_prepared(tmp_path):
    identity = _prepare(tmp_path)
    storage = SQLiteStorage(f"sqlite:///{identity['path']}")
    storage.store_canonical_event(CanonicalEventRecord.create(
        "sensor-1", {"eventid": "cowrie.command.input", "session": "s1", "input": "id"}
    ))
    with pytest.raises(ValueError, match="contains canonical events"):
        verify_rollback_mirror(identity, phase="prepared")


@pytest.mark.parametrize("field,value,error", [
    ("initial_sha256", "0" * 64, "initial SHA-256"),
    ("epoch_id", "wrong", "epoch binding"),
    ("sqlite_schema_version", 4, "schema version"),
    ("journal_mode", "delete", "durability settings"),
])
def test_tampered_identity_fails_closed(tmp_path, field, value, error):
    identity = _prepare(tmp_path)
    identity[field] = value
    if field != "epoch_id":
        _rehash(identity)
    with pytest.raises(ValueError, match=error):
        if field == "epoch_id":
            validate_rollback_mirror_identity(identity, epoch_id=EPOCH)
        else:
            verify_rollback_mirror(identity, phase="prepared")


def test_tampered_identity_receipt_hash_is_rejected(tmp_path):
    identity = _prepare(tmp_path)
    identity["mirror_id"] += "-tampered"
    with pytest.raises(ValueError, match="identity hash mismatch"):
        verify_rollback_mirror(identity)


def test_path_change_and_missing_lineage_are_rejected(tmp_path):
    identity = _prepare(tmp_path)
    identity["path"] = str(tmp_path / "missing.db")
    _rehash(identity)
    with pytest.raises(FileNotFoundError):
        verify_rollback_mirror(identity)

    plain = SQLiteStorage(f"sqlite:///{tmp_path / 'plain.db'}")
    plain.initialize()
    identity["path"] = str(tmp_path / "plain.db")
    identity["initial_sha256"] = hashlib.sha256((tmp_path / "plain.db").read_bytes()).hexdigest()
    _rehash(identity)
    with pytest.raises(ValueError, match="lineage schema"):
        verify_rollback_mirror(identity)


def test_embedded_lineage_is_immutable_and_wrong_epoch_copy_fails(tmp_path):
    identity = _prepare(tmp_path)
    connection = sqlite3.connect(identity["path"])
    try:
        with pytest.raises(sqlite3.IntegrityError, match="lineage is immutable"):
            connection.execute("UPDATE rollback_mirror_lineage SET epoch_id='wrong'")
    finally:
        connection.close()
    assert verify_rollback_mirror(identity)["phase"] == "prepared"


def test_identity_is_json_serializable_and_contains_no_secret(tmp_path):
    identity = _prepare(tmp_path)
    encoded = stable_json(identity)
    assert json.loads(encoded) == identity
    assert "mongodb+srv" not in encoded
    assert "password" not in encoded.lower()


def test_prepare_tool_writes_exclusive_nonsecret_identity_receipt(tmp_path):
    mirror = tmp_path / "tool-mirror.db"
    receipt = tmp_path / "tool-mirror-identity.json"
    command = [
        sys.executable, "-m", "production.tools.mongodb_epoch_receipt",
        "--prepare-mirror", str(mirror), "--output", str(receipt),
        "--epoch-id", EPOCH, "--release-sha", RELEASE, "--release-tree", TREE,
    ]
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    identity = json.loads(receipt.read_text())
    assert completed.stdout.strip() == identity["identity_id"]
    assert receipt.stat().st_mode & 0o777 == 0o600
    assert verify_rollback_mirror(identity, phase="prepared")["event_count"] == 0
    rejected = subprocess.run(command, capture_output=True, text=True)
    assert rejected.returncode != 0
    assert mirror.exists()
    assert receipt.exists()
