"""
cleanup.py — sweep session ที่ไม่มี activity นานเกิน SESSION_TTL_S แล้ว ลบทั้งแถว `sessions`
(session_store.py) + แถว `cache` (cache_store.py) ที่เกี่ยวข้อง

**decision_rationale (2026-08-23):** ระบบไม่มี "session end" event จริง (attacker ตัดการเชื่อมต่อ
เฉยๆ ไม่มี signal ส่งมา) เลยใช้ TTL แทน — เดิมเลือก 2 ชม. (session-end proxy)

**แก้ 2026-09-18 (Track B — identity persistence, ดู trackB_classifier_design_2026-09-18.md §1.1):**
เปลี่ยน TTL 2 ชม. → **7 วัน (identity-TTL, sliding จาก updated_at)** — เป้าหมายใหม่: IP เดิมกลับมา
ภายใน 7 วัน = ได้ attacker_type/phase/baseline-files/cache เดิม (ไม่ทายประเภทใหม่ ไม่สร้างไฟล์ซ้ำ).
`cache` ผูก session_id ที่ stable ต่อ IP (get_or_create_session คืน id เดิมของ IP เดิม) จึงยืด TTL
ตัวเดียวพอ — cache ตามไปเอง ไม่ต้องแยก TTL. + แก้ **cache orphan leak** ที่ P0 พบ (cache row ที่
session_id ไม่มีในตาราง sessions แล้ว เดิมไม่มี sweep ไหนลบ = ค้างถาวร; เจอจริง 103 แถวอายุ 10-33 วัน)

ไม่แตะตาราง `template_content`/`warm_status` (กลุ่ม A, template_store.py) — ถาวร ใช้ซ้ำทุก session
ไม่ต้อง sweep

**แก้ 2026-09-19 (per-session decoy files, ดู pi_phase_adaptive_per_session_files_2026-09-19.md):** ไฟล์ลวง
Part-2 เปลี่ยนจาก tier-shared → per-session (ตาราง `phase_content`/`phase_warm_status` ใน phase_store.py,
คีย์มี session_id) → **ต้อง sweep คู่กับ cache/session_action** (ต่างจากกลุ่ม A ที่ไม่มี session_id) ไม่งั้น
DB โตไม่หยุดเมื่อ attacker ใหม่เข้ามาเรื่อยๆ
"""

import sqlite3
import threading
import time

from config import DB_PATH

# 7 วัน — identity-TTL (sliding จาก updated_at). เปลี่ยนจาก 2 ชม. 2026-09-18 (Track B, ดู docstring)
# คงชื่อ SESSION_TTL_S ไว้ (login_decoy.py:286 อ้างในคอมเมนต์) — ความหมายตอนนี้ = อายุ identity ต่อ IP
SESSION_TTL_S = 7 * 24 * 3600
SWEEP_INTERVAL_S = 600  # sweep ทุก 10 นาที


def sweep_once() -> int:
    """ลบ session + cache rows ที่เก่ากว่า TTL — คืนจำนวน session ที่ลบ"""
    conn = sqlite3.connect(DB_PATH)
    try:
        cutoff = time.time() - SESSION_TTL_S
        stale = conn.execute(
            "SELECT ip, session_id FROM sessions WHERE updated_at < ?", (cutoff,)
        ).fetchall()
        for ip, session_id in stale:
            conn.execute("DELETE FROM cache WHERE session_id = ?", (session_id,))
            # เพิ่ม 2026-09-18 (P2): ตาราง session_action (action-flavor ผูก session_id) ต้องถูก
            # sweep คู่กับ cache — identity หมดอายุแล้ว flavor ที่จำไว้ก็ไม่ต้องเก็บ
            conn.execute("DELETE FROM session_action WHERE session_id = ?", (session_id,))
            # เพิ่ม 2026-09-19 (per-session decoy files, ดู pi_phase_adaptive_per_session_files_2026-09-19.md):
            # เนื้อหาไฟล์ลวง Part-2 ตอนนี้ผูก session_id (phase_store.py) — identity หมดอายุแล้วเนื้อหาที่
            # แต่งให้ attacker คนนั้นก็ไม่มีประโยชน์ (กลับมา = identity ใหม่อยู่ดี) กวาดคู่กับ cache/action
            conn.execute("DELETE FROM phase_content WHERE session_id = ?", (session_id,))
            conn.execute("DELETE FROM phase_warm_status WHERE session_id = ?", (session_id,))
            conn.execute("DELETE FROM sessions WHERE ip = ?", (ip,))
        # แก้ 2026-09-18 (P0 พบ cache orphan leak): cache row ที่ session_id ไม่มีในตาราง sessions
        # แล้ว (session ถูกลบไปก่อน / prefetch เขียนไว้โดยไม่มี session row live) — loop ข้างบนวนจาก
        # ตาราง sessions เท่านั้น จึงไม่เคยเจอ orphan พวกนี้ = ค้างถาวร โตไม่หยุด. ลบตรงๆ ที่นี่
        # (session_id เป็น NOT NULL ทั้ง 2 ตาราง จึงไม่มี footgun ของ NOT IN + NULL; ถ้า sessions
        # ว่าง orphan ทั้งหมดถูกลบ ซึ่งถูกต้อง — ไม่มี identity ไหนอ้าง cache พวกนั้นแล้ว)
        orphans = conn.execute(
            "DELETE FROM cache WHERE session_id NOT IN (SELECT session_id FROM sessions)"
        ).rowcount
        # เพิ่ม 2026-09-18 (P2): orphan safety net เดียวกันสำหรับ session_action (mirror cache) —
        # กัน leak แบบเดียวกับที่ P0 เจอใน cache (session_id ที่ sessions row หายไปแล้ว)
        action_orphans = conn.execute(
            "DELETE FROM session_action WHERE session_id NOT IN (SELECT session_id FROM sessions)"
        ).rowcount
        # เพิ่ม 2026-09-19 (per-session decoy files): orphan safety net เดียวกันสำหรับ 2 ตารางของ
        # phase_store.py — กัน leak แบบเดียวกับที่ P0 เจอใน cache (session_id ที่ sessions row หายไปแล้ว)
        phase_content_orphans = conn.execute(
            "DELETE FROM phase_content WHERE session_id NOT IN (SELECT session_id FROM sessions)"
        ).rowcount
        phase_status_orphans = conn.execute(
            "DELETE FROM phase_warm_status WHERE session_id NOT IN (SELECT session_id FROM sessions)"
        ).rowcount
        conn.commit()
        if orphans:
            print(f"cleanup: swept {orphans} orphan cache row(s)")
        if action_orphans:
            print(f"cleanup: swept {action_orphans} orphan session_action row(s)")
        if phase_content_orphans or phase_status_orphans:
            print(f"cleanup: swept {phase_content_orphans} phase_content + "
                  f"{phase_status_orphans} phase_warm_status orphan row(s)")
        return len(stale)
    finally:
        conn.close()


def _loop() -> None:
    while True:
        try:
            n = sweep_once()
            if n:
                print(f"cleanup: swept {n} stale session(s)")
        except Exception as e:
            print(f"cleanup: sweep failed: {e}")
        time.sleep(SWEEP_INTERVAL_S)


def start_background() -> None:
    threading.Thread(target=_loop, daemon=True).start()
