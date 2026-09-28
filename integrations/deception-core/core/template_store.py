"""
template_store.py — เก็บเนื้อหาที่ pre-fetch ไว้ล่วงหน้าแบบ background (Prepared Response Layer
กลุ่ม A: shared/reusable ข้าม session — ดู docs/reports/pi_stageB_pregen_2026-08-23.md) คีย์เนื้อหา
(door, target, tier, content_type) **ไม่มี session_id** ต่างจาก cache_store.py (คีย์มี session_id
ด้วย ใช้กับกลุ่ม B: session-unique — ไฟล์นั้นไม่แตะ ยังทำหน้าที่เดิม) SQLite ตัวเดียวกับ
cache_store.py/session_store.py (DB_PATH เดียว ตามมติทีม: ไม่ลง Redis ประหยัด RAM)

warm_status กันสอง trigger (เช่น 2 session tier เดียวกันมาพร้อมกัน) เริ่ม warm ซ้ำซ้อน —
try_claim() ใช้ INSERT OR IGNORE บน PRIMARY KEY (door, mode, tier) เป็นตัว atomic claim

**บั๊กที่เจอ+แก้ 2026-08-23:** เดิม claim key เป็นแค่ (door, tier) ไม่มี mode — เพราะ door เป็น
"ssh" ตัวเดียวกันทั้ง bash/psql ตอนนี้ (ดู DOOR ใน prefetch_worker.py) ทำให้ claim (door,tier)
"ชนะ" ไปแล้วจาก bash วิ่งครั้งแรก แล้วรอบ psql tier เดียวกัน try_claim คืน False ทันที (คิดว่ามีคน
ทำแล้ว) ทั้งที่ไม่เคย generate psql เลยสักอัน — พบตอนรัน warm_all.py เต็มรูปแบบ (psql 3 tier ใช้
เวลารวม 0.0s ทั้งที่ควรใช้เวลาเป็นนาที) แก้ด้วยเพิ่ม mode เข้า key
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
        CREATE TABLE IF NOT EXISTS template_content (
            door TEXT NOT NULL,
            target TEXT NOT NULL,
            tier INTEGER NOT NULL,
            content_type TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at REAL NOT NULL,
            PRIMARY KEY (door, target, tier, content_type)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS warm_status (
            door TEXT NOT NULL,
            mode TEXT NOT NULL,
            tier INTEGER NOT NULL,
            status TEXT NOT NULL,
            updated_at REAL NOT NULL,
            PRIMARY KEY (door, mode, tier)
        )
        """
    )
    conn.commit()
    return conn


_conn = _connect()


def get(door: str, target: str, tier: int, content_type: str) -> str | None:
    with _lock:
        row = _conn.execute(
            "SELECT content FROM template_content WHERE door=? AND target=? AND tier=? "
            "AND content_type=?",
            (door, target, tier, content_type),
        ).fetchone()
    return row[0] if row else None


def put(door: str, target: str, tier: int, content_type: str, content: str) -> None:
    with _lock:
        _conn.execute(
            "INSERT OR REPLACE INTO template_content "
            "(door, target, tier, content_type, content, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (door, target, tier, content_type, content, time.time()),
        )
        _conn.commit()


# ถ้า worker ถูก kill กลางคัน (เช่น container ถูก recreate ระหว่าง generate) แถว in_progress
# จะค้างตลอดไป ไม่มีทาง retry ได้เลยถ้าไม่มี staleness check — เกิดจริงระหว่าง implement
# 2026-08-23 (สงสัยว่า process หายไปตอน rebuild image, ท้ายที่สุดพบว่ายังรันอยู่จริงแค่ ps ใน
# container ไม่มี แต่ใส่กันไว้เผื่อเคสจริงที่ process ตายจริงๆ)
STALE_AFTER_S = 600  # 10 นาที — generate 1 target ปกติ <30s, ครบ tier ปกติไม่เกินไม่กี่นาที


def try_claim(door: str, mode: str, tier: int) -> bool:
    """Atomic claim กันสอง trigger พร้อมกันไปเริ่ม warm ซ้ำ (เช่น session ใหม่ 2 อันมาพร้อมกัน
    ที่ tier เดียวกัน) — คืน True ถ้า caller นี้ "ชนะ" claim (ยังไม่มีแถว status ของ door/mode/tier
    นี้เลย, มีแต่ค้าง in_progress นานเกิน STALE_AFTER_S — ถือว่า worker เดิมตายไปแล้ว, หรือมีสถานะ
    pending — ดูด้านล่าง) คืน False ถ้ามีคน claim ไปแล้วจริง (in_progress สดๆ หรือ done)

    แก้บั๊กจริง 2026-09-01 (เจอระหว่างทดสอบ Part 2 DB — ดู
    docs/reports/pi_part2_db_findings_fix_2026-09-01.md): เดิม reclaim ได้แค่ `in_progress` ที่
    stale เท่านั้น **ไม่เคย reclaim `pending` เลย** — ถ้า target ไหนใน phase/tier นั้น generate
    ล้มเหลวแม้แค่ตัวเดียว (เช่น AI backend ล่มชั่วคราว) `warm_phase()`/`warm_tier()` จะ set สถานะเป็น
    `pending` แล้ว**ค้างแบบนั้นตลอดไป ไม่มีวันถูกลองใหม่เองเลย** ต้องลบ row มือเท่านั้น — ต่างจาก
    `in_progress` ที่บอกว่า worker "อาจจะยังทำงานอยู่จริง" (เลยต้องรอ STALE_AFTER_S กันแย่งงานกับ
    worker ที่ยังไม่ตาย) `pending` บอกชัดว่า worker **ทำงานจบไปแล้ว** (แค่ไม่สำเร็จครบ) จึง reclaim
    ได้ทันทีไม่ต้องรอเลย — ของที่เคย generate สำเร็จแล้วไม่ถูกทำซ้ำอยู่ดี (เช็คผ่าน
    `template_store.get()` ก่อนเสมอในทั้ง `warm_phase()`/`warm_tier()`) รีทำแค่ส่วนที่ยังขาด"""
    with _lock:
        now = time.time()
        cur = _conn.execute(
            "INSERT OR IGNORE INTO warm_status (door, mode, tier, status, updated_at) "
            "VALUES (?, ?, ?, 'in_progress', ?)",
            (door, mode, tier, now),
        )
        if cur.rowcount > 0:
            _conn.commit()
            return True
        row = _conn.execute(
            "SELECT status, updated_at FROM warm_status WHERE door=? AND mode=? AND tier=?",
            (door, mode, tier),
        ).fetchone()
        can_reclaim = row and (
            row[0] == "pending"
            or (row[0] == "in_progress" and (now - row[1]) > STALE_AFTER_S)
        )
        if can_reclaim:
            _conn.execute(
                "UPDATE warm_status SET status='in_progress', updated_at=? "
                "WHERE door=? AND mode=? AND tier=?",
                (now, door, mode, tier),
            )
            _conn.commit()
            return True
        _conn.commit()
        return False


def touch(door: str, mode: str, tier: int) -> None:
    """อัปเดต updated_at เฉยๆ ไม่เปลี่ยน status — เรียกระหว่าง warm_tier ทำงาน (ทีละ target)
    กัน false-positive staleness ตอนงานยังไม่เสร็จแต่กำลังทำอยู่จริง"""
    with _lock:
        _conn.execute(
            "UPDATE warm_status SET updated_at=? WHERE door=? AND mode=? AND tier=? "
            "AND status='in_progress'",
            (time.time(), door, mode, tier),
        )
        _conn.commit()


def set_status(door: str, mode: str, tier: int, status: str) -> None:
    with _lock:
        _conn.execute(
            "INSERT OR REPLACE INTO warm_status (door, mode, tier, status, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (door, mode, tier, status, time.time()),
        )
        _conn.commit()


def get_status(door: str, mode: str, tier: int) -> str | None:
    with _lock:
        row = _conn.execute(
            "SELECT status FROM warm_status WHERE door=? AND mode=? AND tier=?",
            (door, mode, tier),
        ).fetchone()
    return row[0] if row else None
