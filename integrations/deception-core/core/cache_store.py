"""
cache_store.py — cache สิ่งที่ Qwen แต่งไปแล้ว ผูกกับ (session_id, door, cache_key)
ให้ขอซ้ำได้ของเดิมเป๊ะ (ด่านตัดสินของงาน 2.x) — SQLite ตัวเดียวกับ session_store.py
"""

import sqlite3
import threading
import time

from config import DB_PATH

_lock = threading.Lock()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS cache (
            session_id TEXT NOT NULL,
            door TEXT NOT NULL,
            cache_key TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at REAL NOT NULL,
            PRIMARY KEY (session_id, door, cache_key)
        )
        """
    )
    conn.commit()
    return conn


_conn = _connect()


def get(session_id: str, door: str, cache_key: str) -> str | None:
    with _lock:
        row = _conn.execute(
            "SELECT content FROM cache WHERE session_id = ? AND door = ? AND cache_key = ?",
            (session_id, door, cache_key),
        ).fetchone()
    return row[0] if row else None


def put(session_id: str, door: str, cache_key: str, content: str) -> None:
    with _lock:
        _conn.execute(
            "INSERT OR REPLACE INTO cache (session_id, door, cache_key, content, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (session_id, door, cache_key, content, time.time()),
        )
        _conn.commit()
