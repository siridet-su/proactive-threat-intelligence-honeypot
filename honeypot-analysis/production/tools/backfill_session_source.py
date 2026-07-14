"""Backfill durable session provenance for legacy SQLite session rows."""

from __future__ import annotations

import argparse
import json
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List

from production.storage.session_provenance import infer_legacy_session_source, is_external_source_ip


def _sqlite_path(database_url: str) -> Path:
    if not database_url.startswith("sqlite:///"):
        raise ValueError("backfill_session_source currently supports sqlite:/// database URLs only")
    return Path(database_url.replace("sqlite:///", "", 1))


def _decode_payload(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return dict(raw)
    if not raw:
        return {}
    try:
        parsed = json.loads(str(raw))
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _session_column_exists(conn: sqlite3.Connection, column: str) -> bool:
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(sessions)").fetchall()}
    return column in columns


def _ensure_session_source_column(conn: sqlite3.Connection) -> None:
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(sessions)").fetchall()}
    if "session_source" not in columns:
        conn.execute("ALTER TABLE sessions ADD COLUMN session_source TEXT NOT NULL DEFAULT 'unknown_legacy'")
    if "is_external_source" not in columns:
        conn.execute("ALTER TABLE sessions ADD COLUMN is_external_source INTEGER NOT NULL DEFAULT 0")
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_sessions_source_updated
            ON sessions(session_source, updated_at)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_sessions_source_external_updated
            ON sessions(session_source, is_external_source, updated_at)
        """
    )


def _backup_database(source: Path, backup_path: Path) -> None:
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(source) as src, sqlite3.connect(backup_path) as dest:
        src.backup(dest)


def _load_rows(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    has_source = _session_column_exists(conn, "session_source")
    has_external = _session_column_exists(conn, "is_external_source")
    if has_source and has_external:
        rows = conn.execute(
            """
            SELECT session_id, src_ip, start_time, ended, session_source, is_external_source, payload_json, updated_at
            FROM sessions
            ORDER BY start_time, session_id
            """
        ).fetchall()
        return [dict(row) for row in rows]
    if has_source:
        rows = conn.execute(
            """
            SELECT session_id, src_ip, start_time, ended, session_source, payload_json, updated_at
            FROM sessions
            ORDER BY start_time, session_id
            """
        ).fetchall()
        output = []
        for row in rows:
            item = dict(row)
            item["is_external_source"] = 0
            output.append(item)
        return output
    rows = conn.execute(
        """
        SELECT session_id, src_ip, start_time, ended, payload_json, updated_at
        FROM sessions
        ORDER BY start_time, session_id
        """
    ).fetchall()
    output = []
    for row in rows:
        item = dict(row)
        item["session_source"] = "unknown_legacy"
        item["is_external_source"] = 0
        output.append(item)
    return output


def classify_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    classified: List[Dict[str, Any]] = []
    for row in rows:
        payload = _decode_payload(row.get("payload_json"))
        source = infer_legacy_session_source(row, payload)
        is_external = is_external_source_ip(row.get("src_ip") or payload.get("src_ip"))
        item = dict(row)
        item["payload"] = payload
        item["inferred_session_source"] = source
        item["inferred_is_external_source"] = is_external
        classified.append(item)
    return classified


def summarize(classified: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts = Counter(str(item["inferred_session_source"]) for item in classified)
    examples: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for item in classified:
        source = str(item["inferred_session_source"])
        if len(examples[source]) >= 8:
            continue
        examples[source].append(
            {
                "session_id": item.get("session_id"),
                "src_ip": item.get("src_ip"),
                "start_time": item.get("start_time"),
                "ended": bool(item.get("ended")),
                "is_external_source": bool(item.get("inferred_is_external_source")),
            }
        )
    return {
        "total_rows": len(classified),
        "counts": dict(sorted(counts.items())),
        "external_source_counts": dict(
            sorted(Counter(bool(item["inferred_is_external_source"]) for item in classified).items())
        ),
        "examples": dict(sorted(examples.items())),
    }


def apply_backfill(conn: sqlite3.Connection, classified: List[Dict[str, Any]]) -> None:
    for item in classified:
        payload = dict(item.get("payload") or {})
        payload["session_source"] = item["inferred_session_source"]
        payload["is_external_source"] = item["inferred_is_external_source"]
        conn.execute(
            """
            UPDATE sessions
            SET session_source = ?, is_external_source = ?, payload_json = ?
            WHERE session_id = ?
            """,
            (
                item["inferred_session_source"],
                1 if item["inferred_is_external_source"] else 0,
                json.dumps(payload, sort_keys=True, separators=(",", ":")),
                item["session_id"],
            ),
        )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Backfill session_source for legacy SQLite session rows.")
    parser.add_argument("--database-url", required=True, help="SQLite database URL, e.g. sqlite:///./runtime/production.db")
    parser.add_argument("--apply", action="store_true", help="Apply updates. Without this, only prints a dry-run summary.")
    parser.add_argument("--backup-path", help="SQLite backup path to create before --apply.")
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    db_path = _sqlite_path(args.database_url)
    if not db_path.exists():
        raise FileNotFoundError(db_path)
    if args.apply and not args.backup_path:
        raise ValueError("--backup-path is required with --apply")

    if args.apply:
        _backup_database(db_path, Path(args.backup_path))

    uri = f"file:{db_path}?mode={'rw' if args.apply else 'ro'}"
    with sqlite3.connect(uri, uri=True) as conn:
        conn.row_factory = sqlite3.Row
        if args.apply:
            _ensure_session_source_column(conn)
        classified = classify_rows(_load_rows(conn))
        summary = summarize(classified)
        if args.apply:
            apply_backfill(conn, classified)
            conn.commit()

    summary.update(
        {
            "database_url": args.database_url,
            "applied": bool(args.apply),
            "backup_path": args.backup_path or "",
        }
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
