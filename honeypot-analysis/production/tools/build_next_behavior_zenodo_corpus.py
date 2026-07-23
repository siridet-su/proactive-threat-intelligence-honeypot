#!/usr/bin/env python3
"""Build the corrected-target corpus from verified private Zenodo members.

Raw commands and original session identifiers are written only to the private
SQLite path supplied by the operator. Version-controlled outputs contain only
strict manifests, aggregate receipts, and privacy-safe HMAC identifiers.

Stages are resumable and fail closed:

``ingest``
    Verify source receipts, parse selected event logs, retain causal
    session/command/context ordering, and reject cross-member sessions.

Later classification and safe-corpus stages are added separately so a
completed source mapping remains independently auditable.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Sequence

from production.tools.fetch_next_behavior_zenodo_members import (
    file_sha256,
    load_source_manifest,
)


PRIVATE_SCHEMA_VERSION = 1
PRIVATE_STORE_ID = "next_behavior_zenodo_private_store.v1"
_CONTEXT_EVENT_TYPES = frozenset(
    {
        "cowrie.login.success",
        "cowrie.login.failed",
        "cowrie.session.file_download",
        "cowrie.session.file_upload",
    }
)
_SESSION_EVENT_TYPES = frozenset(
    {
        "cowrie.session.connect",
        "cowrie.command.input",
        "cowrie.session.closed",
    }
) | _CONTEXT_EVENT_TYPES


class NextBehaviorCorpusBuildError(ValueError):
    """Raised when private corpus generation cannot be trusted."""


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _sha256_file(path: Path) -> str:
    return file_sha256(path)


def _stable_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def open_private_database(path: Path) -> sqlite3.Connection:
    """Open the private SQLite store and enforce its exact schema version."""

    path.parent.mkdir(parents=True, exist_ok=True)
    database = sqlite3.connect(path)
    database.execute("PRAGMA journal_mode=WAL")
    database.execute("PRAGMA synchronous=NORMAL")
    database.execute("PRAGMA temp_store=MEMORY")
    database.execute("PRAGMA cache_size=-131072")
    database.execute("PRAGMA foreign_keys=ON")
    database.executescript(
        """
        CREATE TABLE IF NOT EXISTS build_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS processed_members (
            source_member TEXT PRIMARY KEY,
            source_sha256 TEXT NOT NULL,
            source_size_bytes INTEGER NOT NULL,
            chronological_order INTEGER NOT NULL,
            collection_start TEXT NOT NULL,
            collection_end TEXT NOT NULL,
            stats_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            raw_session_id TEXT PRIMARY KEY,
            source_member TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            protocol TEXT NOT NULL DEFAULT '',
            configuration TEXT NOT NULL DEFAULT '',
            closed INTEGER NOT NULL DEFAULT 0,
            cross_member INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_source_member
            ON sessions(source_member);
        CREATE TABLE IF NOT EXISTS command_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_member TEXT NOT NULL,
            source_line INTEGER NOT NULL,
            raw_session_id TEXT NOT NULL,
            event_time TEXT NOT NULL,
            command TEXT NOT NULL,
            UNIQUE(source_member, source_line)
        );
        CREATE INDEX IF NOT EXISTS idx_command_events_session_time
            ON command_events(raw_session_id, event_time, source_line);
        CREATE TABLE IF NOT EXISTS context_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_member TEXT NOT NULL,
            source_line INTEGER NOT NULL,
            raw_session_id TEXT NOT NULL,
            event_time TEXT NOT NULL,
            event_type TEXT NOT NULL,
            UNIQUE(source_member, source_line)
        );
        CREATE INDEX IF NOT EXISTS idx_context_events_session_time
            ON context_events(raw_session_id, event_time, source_line);
        """
    )
    existing = database.execute(
        "SELECT value FROM build_metadata WHERE key = 'private_store_id'"
    ).fetchone()
    if existing is not None and str(existing[0]) != PRIVATE_STORE_ID:
        database.close()
        raise NextBehaviorCorpusBuildError(
            "private database belongs to another schema"
        )
    database.execute(
        "INSERT OR IGNORE INTO build_metadata(key, value) VALUES (?, ?)",
        ("private_store_id", PRIVATE_STORE_ID),
    )
    database.execute(f"PRAGMA user_version={PRIVATE_SCHEMA_VERSION}")
    database.commit()
    return database


_SESSION_UPSERT = """
INSERT INTO sessions(
    raw_session_id, source_member, first_seen, last_seen,
    protocol, configuration, closed, cross_member
) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
ON CONFLICT(raw_session_id) DO UPDATE SET
    first_seen = CASE
        WHEN sessions.first_seen = '' OR excluded.first_seen < sessions.first_seen
        THEN excluded.first_seen ELSE sessions.first_seen END,
    last_seen = CASE
        WHEN excluded.last_seen > sessions.last_seen
        THEN excluded.last_seen ELSE sessions.last_seen END,
    protocol = CASE
        WHEN excluded.protocol != '' THEN excluded.protocol
        ELSE sessions.protocol END,
    configuration = CASE
        WHEN excluded.configuration != '' THEN excluded.configuration
        ELSE sessions.configuration END,
    closed = MAX(sessions.closed, excluded.closed),
    cross_member = MAX(
        sessions.cross_member,
        CASE WHEN sessions.source_member != excluded.source_member THEN 1 ELSE 0 END
    )
"""


def _flush_ingest(
    database: sqlite3.Connection,
    session_rows: list[tuple[Any, ...]],
    command_rows: list[tuple[Any, ...]],
    context_rows: list[tuple[Any, ...]],
) -> None:
    if session_rows:
        database.executemany(_SESSION_UPSERT, session_rows)
        session_rows.clear()
    if command_rows:
        database.executemany(
            """
            INSERT INTO command_events(
                source_member, source_line, raw_session_id, event_time, command
            ) VALUES (?, ?, ?, ?, ?)
            """,
            command_rows,
        )
        command_rows.clear()
    if context_rows:
        database.executemany(
            """
            INSERT INTO context_events(
                source_member, source_line, raw_session_id, event_time, event_type
            ) VALUES (?, ?, ?, ?, ?)
            """,
            context_rows,
        )
        context_rows.clear()
    database.commit()


def _verify_selected_member(
    source_member: Mapping[str, Any],
    raw_directory: Path,
) -> Path:
    path = raw_directory / source_member["filename"]
    if not path.is_file():
        raise NextBehaviorCorpusBuildError(
            f"missing source member: {source_member['filename']}"
        )
    if path.stat().st_size != source_member["size_bytes"]:
        raise NextBehaviorCorpusBuildError(
            f"source member size mismatch: {source_member['filename']}"
        )
    if _sha256_file(path) != source_member["sha256"]:
        raise NextBehaviorCorpusBuildError(
            f"source member SHA-256 mismatch: {source_member['filename']}"
        )
    return path


def _clear_partial_member(
    database: sqlite3.Connection,
    source_member: str,
) -> None:
    """Remove only an incomplete member before deterministic replay."""

    database.execute(
        "DELETE FROM command_events WHERE source_member = ?",
        (source_member,),
    )
    database.execute(
        "DELETE FROM context_events WHERE source_member = ?",
        (source_member,),
    )
    database.execute(
        """
        DELETE FROM sessions
        WHERE source_member = ?
          AND NOT EXISTS (
              SELECT 1 FROM processed_members
              WHERE processed_members.source_member = sessions.source_member
          )
        """,
        (source_member,),
    )
    database.commit()


def ingest_member(
    database: sqlite3.Connection,
    source_member: Mapping[str, Any],
    raw_directory: Path,
    *,
    flush_size: int = 20000,
) -> Dict[str, Any]:
    """Ingest one verified member without emitting private event content."""

    filename = _clean(source_member.get("filename"))
    path = _verify_selected_member(source_member, raw_directory)
    stored = database.execute(
        """
        SELECT source_sha256, source_size_bytes, chronological_order,
               collection_start, collection_end, stats_json
        FROM processed_members WHERE source_member = ?
        """,
        (filename,),
    ).fetchone()
    if stored is not None:
        if (
            str(stored[0]) != source_member["sha256"]
            or int(stored[1]) != source_member["size_bytes"]
            or int(stored[2]) != source_member["chronological_order"]
        ):
            raise NextBehaviorCorpusBuildError(
                f"stored source receipt mismatch: {filename}"
            )
        return {
            "status": "already_ingested",
            "source_member": filename,
            "collection_start": str(stored[3]),
            "collection_end": str(stored[4]),
            "stats": json.loads(str(stored[5])),
        }

    _clear_partial_member(database, filename)
    stats: Counter[str] = Counter()
    event_ids: Counter[str] = Counter()
    protocols: Counter[str] = Counter()
    configurations: Counter[str] = Counter()
    collection_start = ""
    collection_end = ""
    session_rows: list[tuple[Any, ...]] = []
    command_rows: list[tuple[Any, ...]] = []
    context_rows: list[tuple[Any, ...]] = []
    try:
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
            for source_line, line in enumerate(handle, start=1):
                stats["raw_event_records"] += 1
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    stats["malformed_records"] += 1
                    continue
                if not isinstance(event, dict):
                    stats["non_object_records"] += 1
                    continue
                event_id = _clean(event.get("eventid"))
                event_ids[event_id or "missing"] += 1
                timestamp = _clean(event.get("ts"))
                if timestamp:
                    if not collection_start or timestamp < collection_start:
                        collection_start = timestamp
                    if not collection_end or timestamp > collection_end:
                        collection_end = timestamp
                protocol = _clean(event.get("protocol")).lower()
                configuration = _clean(event.get("group"))
                if protocol:
                    protocols[protocol] += 1
                if configuration:
                    configurations[configuration] += 1
                if event_id not in _SESSION_EVENT_TYPES:
                    continue
                raw_session_id = _clean(event.get("session"))
                if not raw_session_id or not timestamp:
                    stats["relevant_events_missing_session_or_time"] += 1
                    continue
                stats["relevant_session_events"] += 1
                session_rows.append(
                    (
                        raw_session_id,
                        filename,
                        timestamp,
                        timestamp,
                        protocol,
                        configuration,
                        int(event_id == "cowrie.session.closed"),
                    )
                )
                if event_id == "cowrie.command.input":
                    stats["raw_command_input_events"] += 1
                    command = _clean(event.get("input"))
                    if command:
                        stats["nonempty_command_events"] += 1
                        command_rows.append(
                            (
                                filename,
                                source_line,
                                raw_session_id,
                                timestamp,
                                command,
                            )
                        )
                    else:
                        stats["empty_command_events"] += 1
                elif event_id in _CONTEXT_EVENT_TYPES:
                    stats["context_events"] += 1
                    context_rows.append(
                        (
                            filename,
                            source_line,
                            raw_session_id,
                            timestamp,
                            event_id,
                        )
                    )
                if len(session_rows) >= flush_size:
                    _flush_ingest(
                        database,
                        session_rows,
                        command_rows,
                        context_rows,
                    )
        _flush_ingest(database, session_rows, command_rows, context_rows)
    except (OSError, EOFError, sqlite3.Error) as exc:
        raise NextBehaviorCorpusBuildError(
            f"source member ingestion failed: {filename}: {type(exc).__name__}"
        ) from exc
    if not collection_start or not collection_end:
        raise NextBehaviorCorpusBuildError(
            f"source member has no usable event timestamps: {filename}"
        )

    summary = {
        **dict(sorted(stats.items())),
        "event_id_counts": dict(sorted(event_ids.items())),
        "protocol_event_counts": dict(sorted(protocols.items())),
        "configuration_event_counts": dict(sorted(configurations.items())),
    }
    database.execute(
        """
        INSERT INTO processed_members(
            source_member, source_sha256, source_size_bytes,
            chronological_order, collection_start, collection_end, stats_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            filename,
            source_member["sha256"],
            source_member["size_bytes"],
            source_member["chronological_order"],
            collection_start,
            collection_end,
            _stable_json(summary),
        ),
    )
    database.commit()
    return {
        "status": "ingested",
        "source_member": filename,
        "collection_start": collection_start,
        "collection_end": collection_end,
        "stats": summary,
    }


def _member_by_name(manifest: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {
        _clean(member["filename"]): dict(member)
        for member in manifest["members"]
    }


def ingest_members(
    *,
    source_manifest_path: Path,
    raw_directory: Path,
    private_database_path: Path,
    selected_members: Iterable[str] = (),
) -> Dict[str, Any]:
    manifest = load_source_manifest(source_manifest_path)
    manifest_hash = _sha256_file(source_manifest_path)
    members_by_name = _member_by_name(manifest)
    requested = [
        _clean(member) for member in selected_members if _clean(member)
    ] or [member["filename"] for member in manifest["members"]]
    unknown = sorted(set(requested) - set(members_by_name))
    if unknown:
        raise NextBehaviorCorpusBuildError(
            "selected members are outside the frozen manifest"
        )
    if len(requested) != len(set(requested)):
        raise NextBehaviorCorpusBuildError("selected member list is duplicated")

    database = open_private_database(private_database_path)
    try:
        stored_manifest = database.execute(
            "SELECT value FROM build_metadata WHERE key = 'source_manifest_sha256'"
        ).fetchone()
        if stored_manifest is not None and str(stored_manifest[0]) != manifest_hash:
            raise NextBehaviorCorpusBuildError(
                "private database source manifest hash mismatch"
            )
        database.execute(
            "INSERT OR IGNORE INTO build_metadata(key, value) VALUES (?, ?)",
            ("source_manifest_sha256", manifest_hash),
        )
        database.commit()
        receipts = [
            ingest_member(database, members_by_name[member], raw_directory)
            for member in requested
        ]
        cross_member_count = int(
            database.execute(
                "SELECT COUNT(*) FROM sessions WHERE cross_member = 1"
            ).fetchone()[0]
        )
        if cross_member_count:
            raise NextBehaviorCorpusBuildError(
                "raw session identifiers occur in more than one source member"
            )
        counts = {
            "processed_members": int(
                database.execute(
                    "SELECT COUNT(*) FROM processed_members"
                ).fetchone()[0]
            ),
            "sessions": int(
                database.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
            ),
            "command_events": int(
                database.execute(
                    "SELECT COUNT(*) FROM command_events"
                ).fetchone()[0]
            ),
            "context_events": int(
                database.execute(
                    "SELECT COUNT(*) FROM context_events"
                ).fetchone()[0]
            ),
            "cross_member_sessions": cross_member_count,
        }
    finally:
        database.close()
    return {
        "schema_version": PRIVATE_STORE_ID,
        "status": "ingest_complete",
        "source_manifest_sha256": manifest_hash,
        "selected_member_count": len(requested),
        "member_receipts": receipts,
        "counts": counts,
        "raw_content_emitted": False,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("ingest",))
    parser.add_argument(
        "--source-manifest",
        type=Path,
        default=Path("configs/next_behavior_zenodo_source.v1.json"),
    )
    parser.add_argument("--raw-directory", type=Path, required=True)
    parser.add_argument("--private-database", type=Path, required=True)
    parser.add_argument("--member", action="append", default=[])
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.stage != "ingest":
        raise NextBehaviorCorpusBuildError("unsupported build stage")
    result = ingest_members(
        source_manifest_path=args.source_manifest,
        raw_directory=args.raw_directory,
        private_database_path=args.private_database,
        selected_members=args.member,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
