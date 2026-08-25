from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _database_facts(path: Path) -> dict[str, Any]:
    uri = f"{path.resolve().as_uri()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as conn:
        integrity = str(conn.execute("PRAGMA integrity_check").fetchone()[0])
        quick_check = str(conn.execute("PRAGMA quick_check").fetchone()[0])
        user_version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        tables = [
            str(row[0])
            for row in conn.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type='table' AND name NOT LIKE 'sqlite_%'
                ORDER BY name
                """
            ).fetchall()
        ]
        counts = {
            table: int(
                conn.execute(
                    f'SELECT COUNT(*) FROM "{table.replace(chr(34), chr(34) * 2)}"'
                ).fetchone()[0]
            )
            for table in tables
        }
    if integrity.lower() != "ok" or quick_check.lower() != "ok":
        raise RuntimeError("SQLite integrity verification failed")
    return {
        "integrity_check": integrity,
        "quick_check": quick_check,
        "user_version": user_version,
        "table_counts": counts,
    }


def _write_exclusive_json(path: Path, payload: dict[str, Any]) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def create_backup(source: Path, destination: Path) -> dict[str, Any]:
    source = source.resolve()
    destination = destination.resolve()
    manifest_path = Path(f"{destination}.manifest.json")
    if not source.is_file():
        raise ValueError("source SQLite database does not exist")
    if destination.exists() or manifest_path.exists():
        raise FileExistsError("backup destination or manifest already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    source_uri = f"{source.as_uri()}?mode=ro"
    try:
        with sqlite3.connect(source_uri, uri=True) as source_db:
            with sqlite3.connect(destination) as backup_db:
                source_db.backup(backup_db)
        os.chmod(destination, 0o600)
        facts = _database_facts(destination)
        manifest = {
            "schema_version": "sqlite_backup_manifest.v1",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "source_path": str(source),
            "backup_path": str(destination),
            "backup_sha256": _sha256(destination),
            "backup_bytes": destination.stat().st_size,
            **facts,
        }
        _write_exclusive_json(manifest_path, manifest)
        return {**manifest, "manifest_path": str(manifest_path)}
    except Exception:
        destination.unlink(missing_ok=True)
        manifest_path.unlink(missing_ok=True)
        raise


def verify_backup(backup: Path, manifest_path: Path) -> dict[str, Any]:
    backup = backup.resolve()
    manifest_path = manifest_path.resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "sqlite_backup_manifest.v1":
        raise ValueError("unsupported backup manifest schema")
    if Path(str(manifest.get("backup_path", ""))).resolve() != backup:
        raise ValueError("backup path does not match manifest")
    if int(manifest.get("backup_bytes", -1)) != backup.stat().st_size:
        raise ValueError("backup size does not match manifest")
    if str(manifest.get("backup_sha256", "")) != _sha256(backup):
        raise ValueError("backup SHA-256 does not match manifest")
    facts = _database_facts(backup)
    for key in ("user_version", "table_counts"):
        if manifest.get(key) != facts[key]:
            raise ValueError(f"backup {key} does not match manifest")
    return {
        "verified": True,
        "backup_path": str(backup),
        "manifest_path": str(manifest_path),
        "backup_sha256": manifest["backup_sha256"],
        **facts,
    }


def restore_backup(
    backup: Path, manifest_path: Path, destination: Path
) -> dict[str, Any]:
    verified = verify_backup(backup, manifest_path)
    destination = destination.resolve()
    if destination.exists():
        raise FileExistsError("restore destination already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    source_uri = f"{backup.resolve().as_uri()}?mode=ro"
    try:
        with sqlite3.connect(source_uri, uri=True) as backup_db:
            with sqlite3.connect(destination) as restored_db:
                backup_db.backup(restored_db)
        os.chmod(destination, 0o600)
        facts = _database_facts(destination)
        if facts["user_version"] != verified["user_version"]:
            raise RuntimeError("restored schema version differs from backup")
        if facts["table_counts"] != verified["table_counts"]:
            raise RuntimeError("restored table counts differ from backup")
        return {
            "restored": True,
            "restore_path": str(destination),
            "restore_sha256": _sha256(destination),
            **facts,
        }
    except Exception:
        destination.unlink(missing_ok=True)
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create, verify, or restore non-overwriting SQLite backups"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    backup_parser = subparsers.add_parser("backup")
    backup_parser.add_argument("--source", required=True, type=Path)
    backup_parser.add_argument("--destination", required=True, type=Path)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--backup", required=True, type=Path)
    verify_parser.add_argument("--manifest", required=True, type=Path)
    restore_parser = subparsers.add_parser("restore")
    restore_parser.add_argument("--backup", required=True, type=Path)
    restore_parser.add_argument("--manifest", required=True, type=Path)
    restore_parser.add_argument("--destination", required=True, type=Path)
    return parser


def main() -> int:
    args = _parser().parse_args()
    if args.command == "backup":
        result = create_backup(args.source, args.destination)
    elif args.command == "verify":
        result = verify_backup(args.backup, args.manifest)
    else:
        result = restore_backup(args.backup, args.manifest, args.destination)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
