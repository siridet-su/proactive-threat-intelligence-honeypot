"""Content-addressed creation lineage for a mutable SQLite rollback mirror."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from production.storage.backend import SQLITE_SCHEMA_VERSION, SQLiteStorage, StorageError
from production.utils.serialization import stable_json, utc_now


IDENTITY_SCHEMA = "rollback_mirror_identity.v1"
DURABILITY_SCHEMA = "sqlite_rollback_mirror_durability.v1"
CREATOR_TOOL_VERSION = "mongodb_epoch_receipt.prepare_mirror.v1"
LINEAGE_TABLE = "rollback_mirror_lineage"
LINEAGE_COLUMNS = {
    "singleton",
    "mirror_id",
    "epoch_id",
    "created_at",
    "sqlite_schema_version",
    "initial_event_count",
    "journal_mode",
    "synchronous",
    "durability_policy_id",
    "creator_tool_version",
    "reviewed_release_sha",
    "reviewed_release_tree",
}
IDENTITY_FIELDS = {
    "schema_version",
    "identity_id",
    "mirror_id",
    "epoch_id",
    "path",
    "initial_sha256",
    "sqlite_schema_version",
    "initial_event_count",
    "created_at",
    "journal_mode",
    "synchronous",
    "durability_policy",
    "creator_tool_version",
    "reviewed_release_sha",
    "reviewed_release_tree",
}


def durability_policy() -> Dict[str, Any]:
    return {
        "schema_version": DURABILITY_SCHEMA,
        "journal_mode": "wal",
        "synchronous": "full",
        "checkpoint_before_initial_hash": "truncate",
        "initial_hash_artifacts": ["sqlite_main_database"],
        "post_activation_verification": "embedded_lineage_and_exact_event_reads",
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _identity_digest(identity: Dict[str, Any]) -> str:
    payload = {key: value for key, value in identity.items() if key != "identity_id"}
    return hashlib.sha256(stable_json(payload).encode("utf-8")).hexdigest()


def _require_sha256(value: Any, name: str) -> str:
    selected = str(value or "")
    if len(selected) != 64 or any(character not in "0123456789abcdef" for character in selected):
        raise ValueError(f"{name} must be a lowercase SHA-256")
    return selected


def _require_git_sha(value: Any, name: str) -> str:
    selected = str(value or "")
    if len(selected) != 40 or any(character not in "0123456789abcdef" for character in selected):
        raise ValueError(f"{name} must be a lowercase Git SHA-1")
    return selected


def _require_utc(value: Any, name: str) -> str:
    selected = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(selected.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{name} must be an ISO-8601 UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise ValueError(f"{name} must be UTC")
    return selected


def validate_rollback_mirror_identity(identity: Any, *, epoch_id: str) -> Dict[str, Any]:
    if not isinstance(identity, dict) or set(identity) != IDENTITY_FIELDS:
        raise ValueError("rollback mirror identity fields are not exact")
    if identity["schema_version"] != IDENTITY_SCHEMA:
        raise ValueError("rollback mirror identity version is invalid")
    if str(identity["epoch_id"] or "") != epoch_id:
        raise ValueError("rollback mirror identity epoch binding is invalid")
    path = Path(str(identity["path"] or ""))
    if not path.is_absolute() or path != path.resolve(strict=False):
        raise ValueError("rollback mirror identity path must be absolute")
    mirror_id = str(identity["mirror_id"] or "")
    if not mirror_id.startswith("rollback-mirror-") or len(mirror_id) > 255:
        raise ValueError("rollback mirror ID is invalid")
    _require_utc(identity["created_at"], "rollback mirror creation timestamp")
    _require_sha256(identity["initial_sha256"], "rollback mirror initial_sha256")
    if identity["sqlite_schema_version"] != SQLITE_SCHEMA_VERSION:
        raise ValueError("rollback mirror SQLite schema version is invalid")
    if identity["initial_event_count"] != 0:
        raise ValueError("rollback mirror initial event count must be zero")
    if identity["journal_mode"] != "wal" or identity["synchronous"] != "full":
        raise ValueError("rollback mirror durability settings are invalid")
    if identity["durability_policy"] != durability_policy():
        raise ValueError("rollback mirror durability policy is invalid")
    if identity["creator_tool_version"] != CREATOR_TOOL_VERSION:
        raise ValueError("rollback mirror creator tool version is invalid")
    _require_git_sha(identity["reviewed_release_sha"], "rollback mirror release SHA")
    _require_git_sha(identity["reviewed_release_tree"], "rollback mirror release tree")
    if identity["identity_id"] != _identity_digest(identity):
        raise ValueError("rollback mirror identity hash mismatch")
    return identity


def _lineage_payload(identity: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "mirror_id": identity["mirror_id"],
        "epoch_id": identity["epoch_id"],
        "created_at": identity["created_at"],
        "sqlite_schema_version": identity["sqlite_schema_version"],
        "initial_event_count": identity["initial_event_count"],
        "journal_mode": identity["journal_mode"],
        "synchronous": identity["synchronous"],
        "durability_policy_id": hashlib.sha256(
            stable_json(identity["durability_policy"]).encode("utf-8")
        ).hexdigest(),
        "creator_tool_version": identity["creator_tool_version"],
        "reviewed_release_sha": identity["reviewed_release_sha"],
        "reviewed_release_tree": identity["reviewed_release_tree"],
    }


def prepare_rollback_mirror(
    path: str | Path,
    *,
    epoch_id: str,
    reviewed_release_sha: str,
    reviewed_release_tree: str,
    created_at: str | None = None,
    mirror_id: str | None = None,
) -> Dict[str, Any]:
    """Create, checkpoint, close, and identify one fresh zero-event mirror."""

    selected = Path(path)
    if not selected.is_absolute():
        raise ValueError("rollback mirror path must be absolute")
    selected = selected.resolve(strict=False)
    if selected.exists() or selected.is_symlink():
        raise FileExistsError(selected)
    _require_git_sha(reviewed_release_sha, "reviewed release SHA")
    _require_git_sha(reviewed_release_tree, "reviewed release tree")
    timestamp = _require_utc(created_at or utc_now(), "rollback mirror creation timestamp")
    chosen_id = mirror_id or f"rollback-mirror-{uuid.uuid4()}"
    selected.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(selected, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    storage = SQLiteStorage(f"sqlite:///{selected}")
    try:
        storage.initialize()
        provisional = {
            "mirror_id": chosen_id,
            "epoch_id": str(epoch_id),
            "created_at": timestamp,
            "sqlite_schema_version": SQLITE_SCHEMA_VERSION,
            "initial_event_count": 0,
            "journal_mode": "wal",
            "synchronous": "full",
            "durability_policy_id": hashlib.sha256(
                stable_json(durability_policy()).encode("utf-8")
            ).hexdigest(),
            "creator_tool_version": CREATOR_TOOL_VERSION,
            "reviewed_release_sha": reviewed_release_sha,
            "reviewed_release_tree": reviewed_release_tree,
        }
        with storage.connection() as connection:
            count = int(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])
            if count != 0:
                raise StorageError("fresh rollback mirror contains canonical events")
            connection.execute(
                """
                CREATE TABLE rollback_mirror_lineage (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    mirror_id TEXT NOT NULL UNIQUE,
                    epoch_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    sqlite_schema_version INTEGER NOT NULL,
                    initial_event_count INTEGER NOT NULL CHECK (initial_event_count = 0),
                    journal_mode TEXT NOT NULL,
                    synchronous TEXT NOT NULL,
                    durability_policy_id TEXT NOT NULL,
                    creator_tool_version TEXT NOT NULL,
                    reviewed_release_sha TEXT NOT NULL,
                    reviewed_release_tree TEXT NOT NULL
                )
                """
            )
            columns = ", ".join(["singleton", *provisional.keys()])
            placeholders = ", ".join("?" for _ in range(len(provisional) + 1))
            connection.execute(
                f"INSERT INTO {LINEAGE_TABLE} ({columns}) VALUES ({placeholders})",
                (1, *provisional.values()),
            )
            connection.execute(
                f"CREATE TRIGGER rollback_mirror_lineage_no_update BEFORE UPDATE ON {LINEAGE_TABLE} BEGIN SELECT RAISE(ABORT, 'rollback mirror lineage is immutable'); END"
            )
            connection.execute(
                f"CREATE TRIGGER rollback_mirror_lineage_no_delete BEFORE DELETE ON {LINEAGE_TABLE} BEGIN SELECT RAISE(ABORT, 'rollback mirror lineage is immutable'); END"
            )
        checkpoint = sqlite3.connect(selected)
        try:
            checkpoint.execute("PRAGMA synchronous=FULL")
            result = checkpoint.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if result is None or any(int(value) != 0 for value in result):
                raise StorageError("rollback mirror WAL checkpoint did not fully drain")
        finally:
            checkpoint.close()
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(f"{selected}{suffix}")
            if sidecar.exists() and sidecar.stat().st_size:
                raise StorageError("rollback mirror has non-empty durable sidecar state")
        os.chmod(selected, 0o600)
        identity = {
            "schema_version": IDENTITY_SCHEMA,
            "identity_id": "",
            "mirror_id": chosen_id,
            "epoch_id": str(epoch_id),
            "path": str(selected),
            "initial_sha256": _sha256_file(selected),
            "sqlite_schema_version": SQLITE_SCHEMA_VERSION,
            "initial_event_count": 0,
            "created_at": timestamp,
            "journal_mode": "wal",
            "synchronous": "full",
            "durability_policy": durability_policy(),
            "creator_tool_version": CREATOR_TOOL_VERSION,
            "reviewed_release_sha": reviewed_release_sha,
            "reviewed_release_tree": reviewed_release_tree,
        }
        identity["identity_id"] = _identity_digest(identity)
        validate_rollback_mirror_identity(identity, epoch_id=epoch_id)
        verify_rollback_mirror(identity, phase="prepared")
        return identity
    except Exception:
        for candidate in (selected, Path(f"{selected}-wal"), Path(f"{selected}-shm"), Path(f"{selected}-journal")):
            candidate.unlink(missing_ok=True)
        raise


def verify_rollback_mirror(identity: Dict[str, Any], *, phase: str = "auto") -> Dict[str, Any]:
    """Verify exact initial bytes while prepared, or immutable lineage while active."""

    identity = validate_rollback_mirror_identity(identity, epoch_id=str(identity.get("epoch_id") or ""))
    path = Path(identity["path"])
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError("rollback mirror must be a regular non-symlink file")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("rollback mirror permissions are unsafe")
    uri = f"{path.resolve().as_uri()}?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=5.0)
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        quick = connection.execute("PRAGMA quick_check").fetchone()
        if not quick or str(quick[0]).lower() != "ok":
            raise ValueError("rollback mirror quick_check failed")
        schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower()
        synchronous_value = int(connection.execute("PRAGMA synchronous").fetchone()[0])
        event_count = int(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])
        columns = {
            str(row[1]) for row in connection.execute(f"PRAGMA table_info({LINEAGE_TABLE})")
        }
        if columns != LINEAGE_COLUMNS:
            raise ValueError("rollback mirror lineage schema is invalid")
        row = connection.execute(f"SELECT * FROM {LINEAGE_TABLE} WHERE singleton=1").fetchone()
        if row is None or connection.execute(f"SELECT COUNT(*) FROM {LINEAGE_TABLE}").fetchone()[0] != 1:
            raise ValueError("rollback mirror lineage record is missing")
        triggers = {
            str(item[0]) for item in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name=?",
                (LINEAGE_TABLE,),
            )
        }
        if triggers != {"rollback_mirror_lineage_no_update", "rollback_mirror_lineage_no_delete"}:
            raise ValueError("rollback mirror lineage immutability triggers are missing")
    finally:
        connection.close()
    if schema_version != identity["sqlite_schema_version"]:
        raise ValueError("rollback mirror schema version mismatch")
    if journal_mode != identity["journal_mode"] or synchronous_value != 2:
        raise ValueError("rollback mirror durability setting mismatch")
    expected = _lineage_payload(identity)
    actual = {key: row[key] for key in expected}
    if actual != expected:
        raise ValueError("rollback mirror embedded lineage mismatch")
    selected_phase = phase
    if selected_phase == "auto":
        selected_phase = "prepared" if event_count == 0 else "active"
    if selected_phase not in {"prepared", "active"}:
        raise ValueError("rollback mirror validation phase is invalid")
    if selected_phase == "prepared":
        if event_count != 0:
            raise ValueError("prepared rollback mirror contains canonical events")
        if _sha256_file(path) != identity["initial_sha256"]:
            raise ValueError("rollback mirror initial SHA-256 mismatch")
    return {
        "schema_version": "rollback_mirror_verification.v1",
        "phase": selected_phase,
        "mirror_id": identity["mirror_id"],
        "identity_id": identity["identity_id"],
        "event_count": event_count,
        "initial_sha256_verified": selected_phase == "prepared",
    }
