"""
phase_store.py — เก็บเนื้อหา Part-2 phase-adaptive ที่ pre-fetch ไว้ล่วงหน้า **ผูกกับ session_id**
(ต่างจาก template_store.py กลุ่ม A ที่ key เป็น (door,target,tier,content_type) แชร์ข้าม session).

ทำไมต้องแยกไฟล์ (2026-09-19, คำขอผู้ใช้ — ดู docs/reports/pi_phase_adaptive_per_session_files_2026-09-19.md):
  เดิมไฟล์ลวง phase-adaptive cache เนื้อหาต่อ **tier** แล้วใช้ซ้ำข้าม attacker ทุกคนที่ tier เดียวกัน →
  "ค่าในไฟล์" (creds/IP/wallet) เหมือนกันเป๊ะทุกคน = ดูเป็นไฟล์ static. เปลี่ยนเป็น key ต่อ session_id
  (ผูก IP ผ่าน session_store, TTL 7 วัน) → attacker ใหม่ = session ใหม่ = ไม่มี row = generate ใหม่ของ
  ตัวเอง; attacker คนเดิม re-read = เจอ row เดิม = **นิ่ง** (ไฟล์ไม่เปลี่ยนใต้เท้า = ไม่โป๊ะ) + ไม่ generate
  ทุกคำสั่ง (skip-if-exists ต่อ session ยังทำงาน).

**ไม่แตะ template_store.py** (Part 1 warm_tier/warm_session ของ psql/bash ใช้ร่วม — เปลี่ยน PK จะพัง) —
ไฟล์นี้ทำหน้าที่เดียวกันเป๊ะแต่ทุก key มี session_id นำหน้า. SQLite ตัวเดียวกับ template_store.py/
cache_store.py/session_store.py (DB_PATH เดียว ตามมติทีม: ไม่ลง Redis ประหยัด RAM).

logic reclaim/staleness ของ warm_status ยกมาจาก template_store.py ตรงๆ (single source of behaviour —
ถ้าตรรกะนั้นต้องเปลี่ยน ต้องแก้คู่กัน; แยกได้เพราะ key schema ต่างกันที่ session_id เท่านั้น).
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
        CREATE TABLE IF NOT EXISTS phase_content (
            session_id TEXT NOT NULL,
            door TEXT NOT NULL,
            target TEXT NOT NULL,
            tier INTEGER NOT NULL,
            content_type TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at REAL NOT NULL,
            PRIMARY KEY (session_id, door, target, tier, content_type)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS phase_warm_status (
            session_id TEXT NOT NULL,
            door TEXT NOT NULL,
            mode TEXT NOT NULL,
            tier INTEGER NOT NULL,
            status TEXT NOT NULL,
            updated_at REAL NOT NULL,
            PRIMARY KEY (session_id, door, mode, tier)
        )
        """
    )
    conn.commit()
    return conn


_conn = _connect()


def get(session_id: str, door: str, target: str, tier: int, content_type: str) -> str | None:
    with _lock:
        row = _conn.execute(
            "SELECT content FROM phase_content WHERE session_id=? AND door=? AND target=? "
            "AND tier=? AND content_type=?",
            (session_id, door, target, tier, content_type),
        ).fetchone()
    return row[0] if row else None


def put(session_id: str, door: str, target: str, tier: int, content_type: str, content: str) -> None:
    with _lock:
        _conn.execute(
            "INSERT OR REPLACE INTO phase_content "
            "(session_id, door, target, tier, content_type, content, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (session_id, door, target, tier, content_type, content, time.time()),
        )
        _conn.commit()


# staleness/reclaim semantics ยกจาก template_store.py (ดู docstring ฟังก์ชันนั้นสำหรับที่มาของบั๊ก
# 2026-09-01 pending-never-reclaimed): reclaim ได้ถ้าเป็น pending (worker จบแล้วแต่ไม่ครบ) หรือ
# in_progress ที่ค้างเกิน STALE_AFTER_S (worker เดิมน่าจะตาย)
STALE_AFTER_S = 600  # 10 นาที — generate 1 target ปกติ <30s


def try_claim(session_id: str, door: str, mode: str, tier: int) -> bool:
    """Atomic claim ต่อ (session_id, door, mode, tier) — คืน True ถ้า caller นี้ชนะ claim.
    ต่างจาก template_store.try_claim ที่ claim ต่อ (door,mode,tier): อันนี้ผูก session ด้วย เพราะแต่ละ
    session ต้อง warm เนื้อหาของตัวเองแยกกัน (คนละ content). กันแค่ 2 thread ของ session เดียวกัน
    (เช่น per-command warm + warm-on-lock ยิงพร้อมกัน) ไม่ให้ generate ซ้ำ."""
    with _lock:
        now = time.time()
        cur = _conn.execute(
            "INSERT OR IGNORE INTO phase_warm_status (session_id, door, mode, tier, status, updated_at) "
            "VALUES (?, ?, ?, ?, 'in_progress', ?)",
            (session_id, door, mode, tier, now),
        )
        if cur.rowcount > 0:
            _conn.commit()
            return True
        row = _conn.execute(
            "SELECT status, updated_at FROM phase_warm_status "
            "WHERE session_id=? AND door=? AND mode=? AND tier=?",
            (session_id, door, mode, tier),
        ).fetchone()
        can_reclaim = row and (
            row[0] == "pending"
            or (row[0] == "in_progress" and (now - row[1]) > STALE_AFTER_S)
        )
        if can_reclaim:
            _conn.execute(
                "UPDATE phase_warm_status SET status='in_progress', updated_at=? "
                "WHERE session_id=? AND door=? AND mode=? AND tier=?",
                (now, session_id, door, mode, tier),
            )
            _conn.commit()
            return True
        _conn.commit()
        return False


def touch(session_id: str, door: str, mode: str, tier: int) -> None:
    with _lock:
        _conn.execute(
            "UPDATE phase_warm_status SET updated_at=? "
            "WHERE session_id=? AND door=? AND mode=? AND tier=? AND status='in_progress'",
            (time.time(), session_id, door, mode, tier),
        )
        _conn.commit()


def set_status(session_id: str, door: str, mode: str, tier: int, status: str) -> None:
    with _lock:
        _conn.execute(
            "INSERT OR REPLACE INTO phase_warm_status "
            "(session_id, door, mode, tier, status, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (session_id, door, mode, tier, status, time.time()),
        )
        _conn.commit()


def get_status(session_id: str, door: str, mode: str, tier: int) -> str | None:
    with _lock:
        row = _conn.execute(
            "SELECT status FROM phase_warm_status "
            "WHERE session_id=? AND door=? AND mode=? AND tier=?",
            (session_id, door, mode, tier),
        ).fetchone()
    return row[0] if row else None
