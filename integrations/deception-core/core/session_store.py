"""
session_store.py — session ผูกด้วย IP (ข้ามประตูได้ ตาม docs/10_system_concept_3day.md §5①)
เก็บด้วย SQLite (มติของแผน: ไม่ลง Redis ประหยัด RAM) · phase tracking reuse
SessionPhaseTracker จาก shared/predict_phase_rules.py ตรงๆ ไม่พิมพ์ logic ซ้ำ (CLAUDE.md §5)

แก้ 2026-08-30 (มติผู้ใช้ — ดู core/brain.py docstring): เพิ่มคอลัมน์ `attacker_type` — สุ่มครั้ง
เดียวตอนสร้าง session ใหม่ (`brain.simulate_attacker_type_at_login()`) ไม่คำนวณจาก command_count
ซ้ำทุกคำสั่งอีกต่อไป (ของเดิมทำให้ tier เปลี่ยนกลางทาง session บ่อยเกินไป กระทบ Part 2 background
warm ต้อง re-generate เนื้อหาซ้ำหลายรอบ)

แก้ 2026-09-08 (เชื่อม attacker-classifier จริง แทน placeholder สุ่ม — ดู core/brain.py +
core/attacker_classifier.py): attacker_type เริ่มเป็น default 'Bot' ตอน login แล้ว **จำแนกจริง
ครั้งเดียวเมื่อครบ CLASSIFY_AT_N คำสั่งแล้วล็อก** (ไม่ re-classify ทุกคำสั่ง — churn ต่ำ ตรง
ดีไซน์เดิม + ตรงมติ grilling 2026-09-07). ต้องเก็บ `client_version` (Cowrie ส่งมา — สัญญาณ bot
ที่สำคัญสุด) + `recent_commands` (สะสมคำสั่งจนกว่าจะจำแนก) + `attacker_type_locked` (กัน
re-classify). ก่อนครบ N ใช้ default 'Bot' (traffic จริงเป็นบอท 1-2 คำสั่งเกือบ 100% — บอทที่ทำ
<N คำสั่งจะคง Bot ถูกต้องโดยไม่ต้องจำแนกเลย)

แก้ 2026-08-31 (audit batch D, finding #1 — ดู docs/reports/pi_greybox_audit_2026-08-30.md): เพิ่ม
4 คอลัมน์ (`bash_history_baseline`/`bash_history_log`/`crontab_content`/`authorized_keys_content`)
เก็บ baseline ของ 3 ไฟล์ Part 1 ต่อ IP (ดูรายละเอียดใน git history)
"""

import sqlite3
import threading
import time
import uuid

import brain
import sigma_rules  # P8 — one-way upgrade SK/Bot->APT จาก sigma signature
from predict_phase_rules import SessionPhaseTracker

from config import DB_PATH

_lock = threading.Lock()

# จำแนก attacker_type จริงเมื่อครบกี่คำสั่ง (มติ grilling 2026-09-07: 3-5 คำสั่ง) แล้วล็อก
# ก่อนหน้านี้ = default 'Bot'. บอทจริงทำ 1-2 คำสั่งจะไม่ถึง N → คง Bot ถูกต้องโดยไม่ต้องจำแนก
CLASSIFY_AT_N = 3

# P4 (2026-09-18) confidence-gate lock — ดู docs/reports/pi_confidence_gate_lock_2026-09-18.md:
# เดิมล็อกทันทีที่ครบ CLASSIFY_AT_N. ตอนนี้เริ่ม "ลอง" จำแนกที่ N แล้วล็อกเมื่อ posterior ของคลาสที่ชนะ
# ≥ CONFIDENCE_THRESHOLD (มั่นใจพอ) หรือถึงเพดาน CLASSIFY_CAP_N คำสั่ง (บังคับล็อกแม้ยังไม่มั่นใจ)
CLASSIFY_CAP_N = 5           # เพดานคำสั่ง — ถึงจุดนี้บังคับล็อกเสมอ (ไม่ปล่อย unlocked ยาวเกินไป)
CONFIDENCE_THRESHOLD = 0.7   # posterior ของ winner ≥ ค่านี้ = ล็อกเลย (จูนจาก self-play P10 ได้)
APT_TIE_MARGIN = 0.10        # ตอนบังคับล็อก (conf<threshold) ถ้า APT ห่าง winner ≤ ค่านี้ → เลือก APT

# P8 (2026-09-19) one-way upgrade -> APT — ดู docs/reports/pi_sigma_upgrade_2026-09-19.md:
# APT tell มัก "มาช้า" (ล้าง log / probe VM / reverse shell หลัง recon) กว่า classifier จะล็อก (P4)
# ที่ N คำสั่งแรกไปแล้ว. ถ้าคำสั่ง "หลังล็อก" trip กฎ apt_signature (sigma_rules) → upgrade เป็น APT
# **ทางเดียว ไม่ downgrade** (กันสั่น flap). ทำเป็น monotonic tier↑: จาก Bot(1)/ScriptKiddie(2) → APT(3)
# **decision_rationale (§4 — ต่างจาก design doc ที่เขียน "SK→APT"):** รวม Bot ด้วยโดยตั้งใจ เพราะ
# default type = Bot (traffic ส่วนใหญ่เริ่มเป็น Bot) → APT ที่ถูกล็อกพลาดเป็น Bot ตอน confidence ต่ำ+
# ถึงเพดาน เป็นเคส mis-lock ที่ "น่าจะเกิดบ่อยสุด" การจำกัดแค่ SK จะพลาดเคสนี้. กฎ apt_signature เลือก
# เฉพาะ precision สูง (บอทจริงแทบไม่ทำ) → false-upgrade Bot->APT ต่ำมาก. หลัง upgrade type=APT ไม่อยู่
# ใน UPGRADE_FROM → ไม่ re-fire เอง (idempotent ไม่ต้องเพิ่มคอลัมน์ flag)
UPGRADE_FROM = frozenset({"Bot", "ScriptKiddie"})


def _apt_leaning_pick(posterior: dict, winner: str) -> str:
    """tie-break เอียง APT (เฉพาะตอนบังคับล็อกที่ยังไม่มั่นใจ): เคสก้ำกึ่ง เลือกเตรียม deception ระดับ
    สูงไว้ปลอดภัยกว่า (พลาดเป็น APT ทั้งที่จริงเป็น SK = เสียแค่ over-prepare; พลาดกลับกัน = under-prepare
    ให้ APT จริง). ถ้า posterior ว่าง (fallback สุ่ม) หรือ winner=APT อยู่แล้ว → คืน winner เดิม"""
    if not posterior or winner == "APT":
        return winner
    apt = posterior.get("APT", 0.0)
    top = posterior.get(winner, 0.0)
    return "APT" if (top - apt) <= APT_TIE_MARGIN else winner


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            ip TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            phase TEXT NOT NULL,
            command_count INTEGER NOT NULL DEFAULT 0,
            attacker_type TEXT NOT NULL DEFAULT 'Bot',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )
        """
    )
    cols = [r[1] for r in conn.execute("PRAGMA table_info(sessions)").fetchall()]
    if "attacker_type" not in cols:
        conn.execute("ALTER TABLE sessions ADD COLUMN attacker_type TEXT NOT NULL DEFAULT 'Bot'")
    for col in (
        "bash_history_baseline",
        "bash_history_log",
        "crontab_content",
        "authorized_keys_content",
        "client_version",
        "recent_commands",
    ):
        if col not in cols:
            conn.execute(f"ALTER TABLE sessions ADD COLUMN {col} TEXT NOT NULL DEFAULT ''")
    if "attacker_type_locked" not in cols:
        conn.execute(
            "ALTER TABLE sessions ADD COLUMN attacker_type_locked INTEGER NOT NULL DEFAULT 0"
        )
    # เพิ่ม 2026-09-18 (Track B P2 — gap A, ดู docs/reports/pi_action_flavor_persist_2026-09-18.md):
    # persist action-flavor (deceive/normal) ที่ phase_adaptive สุ่มผ่าน Nash — เดิมเก็บใน dict แรม
    # ตัวเดียว (`_session_phase_action`) หายตอน core restart → resample → flavor พลิกกลาง identity.
    # ผูก session_id ที่ stable ต่อ IP (get_or_create คืน id เดิม) → รอด restart ตลอดอายุ identity 7 วัน.
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS session_action (
            session_id TEXT NOT NULL,
            phase TEXT NOT NULL,
            attacker_type TEXT NOT NULL,
            action TEXT NOT NULL,
            created_at REAL NOT NULL,
            PRIMARY KEY (session_id, phase, attacker_type)
        )
        """
    )
    conn.commit()
    return conn


_conn = _connect()


class Session:
    def __init__(self, ip: str, session_id: str, phase: str, command_count: int,
                 attacker_type: str, client_version: str = "", recent_commands: str = "",
                 attacker_type_locked: int = 0, created_at: float = 0.0):
        self.ip = ip
        self.session_id = session_id
        self.phase_tracker = SessionPhaseTracker(initial_phase=phase)
        self.command_count = command_count
        self.attacker_type = attacker_type
        self.client_version = client_version
        self.recent_commands = recent_commands
        self.attacker_type_locked = attacker_type_locked
        # เพิ่ม 2026-09-12 (Work Item 4b) — created_at มีอยู่แล้วในตาราง (คอลัมน์เดิม) แค่ไม่เคย
        # โหลดเข้า Session object มาก่อน ใช้คำนวณ commands_per_minute ตอนจำแนก attacker_type
        self.created_at = created_at


def get_or_create_session(ip: str, client_version: str | None = None) -> Session:
    with _lock:
        row = _conn.execute(
            "SELECT session_id, phase, command_count, attacker_type, client_version, "
            "recent_commands, attacker_type_locked, created_at FROM sessions WHERE ip = ?",
            (ip,),
        ).fetchone()
        now = time.time()
        if row is None:
            session_id = uuid.uuid4().hex[:12]
            phase = "Reconnaissance"
            # แก้ 2026-09-08: เริ่มเป็น default 'Bot' (ไม่สุ่ม) — จำแนกจริงตอนครบ N คำสั่ง
            attacker_type = "Bot"
            cv = client_version or ""
            _conn.execute(
                "INSERT INTO sessions (ip, session_id, phase, command_count, attacker_type, "
                "client_version, recent_commands, attacker_type_locked, created_at, updated_at) "
                "VALUES (?, ?, ?, 0, ?, ?, '', 0, ?, ?)",
                (ip, session_id, phase, attacker_type, cv, now, now),
            )
            _conn.commit()
            return Session(ip, session_id, phase, 0, attacker_type, cv, "", 0, now)
        (session_id, phase, command_count, attacker_type, client_version_db, recent, locked,
         created_at) = row
        # อัปเดต client_version ถ้าเพิ่งรู้ (Cowrie ส่งมาทีหลัง) และยังไม่มีในแถว
        if client_version and not client_version_db:
            _conn.execute(
                "UPDATE sessions SET client_version = ?, updated_at = ? WHERE ip = ?",
                (client_version, now, ip),
            )
            _conn.commit()
            client_version_db = client_version
        return Session(ip, session_id, phase, command_count, attacker_type,
                       client_version_db or "", recent or "", locked, created_at)


def record_command(session: Session, command: str) -> str:
    """อัปเดต phase จากคำสั่งใหม่ (เดินหน้าเท่านั้น) + สะสมคำสั่ง + จำแนก attacker_type ด้วย
    **confidence-gate** (P4): เริ่มลองจำแนกเมื่อครบ CLASSIFY_AT_N คำสั่ง แล้วล็อกเมื่อ posterior ของ
    คลาสที่ชนะ ≥ CONFIDENCE_THRESHOLD หรือถึงเพดาน CLASSIFY_CAP_N (บังคับล็อก + tie-break เอียง APT).
    persist กลับ SQLite คืน phase ปัจจุบัน (ดู docstring const ด้านบน + pi_confidence_gate_lock_2026-09-18.md)"""
    new_phase = session.phase_tracker.update(command)
    session.command_count += 1
    # สะสมคำสั่ง (จนกว่าจะล็อก — หลังล็อกไม่ต้องเก็บเพิ่ม ประหยัดพื้นที่)
    if not session.attacker_type_locked:
        cmds = [c for c in session.recent_commands.split("\n") if c] if session.recent_commands else []
        cmds.append(command)
        session.recent_commands = "\n".join(cmds)
        # ครบ N -> "ลอง" จำแนก + ดู confidence ตัดสินล็อก (P4 — เดิมล็อกทันทีที่ครบ N ไม่ดู confidence)
        if session.command_count >= CLASSIFY_AT_N:
            # เพิ่ม 2026-09-12 (Work Item 4b): เวลาที่ผ่านมาตั้งแต่ session สร้าง — ใช้คำนวณ
            # commands_per_minute (session.created_at=0.0 ถ้าโหลดจาก row เก่าก่อนคอลัมน์นี้มีค่าจริง
            # เป็นไปไม่ได้เพราะคอลัมน์ created_at มีมาตั้งแต่ schema เดิม แต่กัน edge case ไว้เผื่อ)
            elapsed = (time.time() - session.created_at) if session.created_at else None
            atype, conf, posterior = brain.classify_attacker_type_with_confidence(
                cmds, ip=session.ip, client_version=session.client_version,
                elapsed_seconds=elapsed,
            )
            at_cap = session.command_count >= CLASSIFY_CAP_N
            if conf >= CONFIDENCE_THRESHOLD or at_cap:
                # บังคับล็อกเพราะถึงเพดานทั้งที่ยังไม่มั่นใจ → tie-break เอียง APT (conf สูงพอ = winner ชัด
                # อยู่แล้ว APT ไม่มีทางอยู่ใน margin, _apt_leaning_pick คืน winner เดิม)
                if conf < CONFIDENCE_THRESHOLD:
                    atype = _apt_leaning_pick(posterior, atype)
                session.attacker_type = atype
                session.attacker_type_locked = 1
            # ยังไม่ล็อก (conf ต่ำ + ยังไม่ถึงเพดาน) → คง default 'Bot' unlocked เก็บคำสั่งต่อรอบหน้า
    else:
        # P8: ล็อกไปแล้ว — เฝ้าคำสั่งใหม่หา apt_signature (sigma). เจอ → upgrade เป็น APT ทางเดียว
        # (เช็คแค่คำสั่งล่าสุด 1 ตัวก็พอ กฎ signature เดี่ยวชี้ชัด — ไม่ต้อง re-accumulate recent_commands)
        if session.attacker_type in UPGRADE_FROM and sigma_rules.apt_upgrade_signal([command]):
            session.attacker_type = "APT"  # locked ยังเป็น 1; type=APT ไม่อยู่ใน UPGRADE_FROM → ไม่ re-fire
    with _lock:
        _conn.execute(
            "UPDATE sessions SET phase = ?, command_count = ?, attacker_type = ?, "
            "recent_commands = ?, attacker_type_locked = ?, updated_at = ? WHERE ip = ?",
            (new_phase, session.command_count, session.attacker_type, session.recent_commands,
             session.attacker_type_locked, time.time(), session.ip),
        )
        _conn.commit()
    return new_phase


def get_login_decoy_baseline(ip: str) -> dict[str, str] | None:
    """คืน baseline ของ 3 ไฟล์ Part 1 ที่เคย generate ไว้แล้วสำหรับ IP นี้ (ถ้ามี) — None ถ้ายังไม่เคย"""
    with _lock:
        row = _conn.execute(
            "SELECT bash_history_baseline, bash_history_log, crontab_content, "
            "authorized_keys_content FROM sessions WHERE ip = ?",
            (ip,),
        ).fetchone()
    if row is None or not row[0]:
        return None
    return {
        "bash_history_baseline": row[0],
        "bash_history_log": row[1] or "",
        "crontab_content": row[2],
        "authorized_keys_content": row[3],
    }


def set_login_decoy_baseline(
    ip: str, bash_history_baseline: str, crontab_content: str, authorized_keys_content: str
) -> None:
    """บันทึก baseline ที่เพิ่ง generate ครั้งแรกสำหรับ IP นี้ (ต้อง ensure row มีอยู่ก่อนที่ caller)"""
    with _lock:
        _conn.execute(
            "UPDATE sessions SET bash_history_baseline = ?, crontab_content = ?, "
            "authorized_keys_content = ?, updated_at = ? WHERE ip = ?",
            (bash_history_baseline, crontab_content, authorized_keys_content, time.time(), ip),
        )
        _conn.commit()


def get_session_action(session_id: str, phase: str, attacker_type: str) -> str | None:
    """คืน action (deceive/normal-flavor) ที่ phase_adaptive เคยสุ่ม (Nash) ไว้แล้วสำหรับ
    (session,phase,type) นี้ — None ถ้ายังไม่เคย. ผูก session_id ที่ stable ต่อ IP → รอด core restart
    (แก้ gap A, ดู docs/reports/pi_action_flavor_persist_2026-09-18.md + phase_adaptive.py::
    _get_or_sample_action)"""
    with _lock:
        row = _conn.execute(
            "SELECT action FROM session_action WHERE session_id=? AND phase=? AND attacker_type=?",
            (session_id, phase, attacker_type),
        ).fetchone()
    return row[0] if row else None


def set_session_action(session_id: str, phase: str, attacker_type: str, action: str) -> str:
    """persist action ครั้งแรกที่สุ่ม แล้วคืน action ที่ถูกเก็บจริง (ของ winner). ใช้ INSERT OR IGNORE
    (PK = 3-tuple) → ถ้ามีอยู่แล้ว (เช่น 2 thread/worker สุ่มคนละตัวพร้อมกัน) ค่าแรกชนะ ตัวหลังถูก
    ignore แล้ว re-read คืนค่า winner → ทุก caller ลู่เข้า action เดียวกัน (consistency ที่ dict เดิม
    การันตีในโปรเซสเดียว แต่ตอนนี้การันตีข้ามโปรเซส/restart ด้วย)"""
    with _lock:
        _conn.execute(
            "INSERT OR IGNORE INTO session_action (session_id, phase, attacker_type, action, "
            "created_at) VALUES (?, ?, ?, ?, ?)",
            (session_id, phase, attacker_type, action, time.time()),
        )
        _conn.commit()
        row = _conn.execute(
            "SELECT action FROM session_action WHERE session_id=? AND phase=? AND attacker_type=?",
            (session_id, phase, attacker_type),
        ).fetchone()
    return row[0]


def append_bash_history_log(ip: str, commands: list[str]) -> None:
    """ต่อท้ายคำสั่งจริงที่ attacker พิมพ์ระหว่าง connection ที่เพิ่งปิด เข้า log สะสมของ IP นี้"""
    if not commands:
        return
    addition = "\n".join(commands)
    with _lock:
        row = _conn.execute(
            "SELECT bash_history_log FROM sessions WHERE ip = ?", (ip,)
        ).fetchone()
        if row is None:
            return
        existing = row[0] or ""
        new_log = f"{existing}\n{addition}" if existing else addition
        _conn.execute(
            "UPDATE sessions SET bash_history_log = ?, updated_at = ? WHERE ip = ?",
            (new_log, time.time(), ip),
        )
        _conn.commit()
