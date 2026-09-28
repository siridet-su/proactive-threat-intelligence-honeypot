"""
session_prompt_builder.py  (v2 — ตาม 07_behavior_spec)

ประกอบ system prompt ก่อนยิงเข้า Qwen ทุกเทิร์น
ฟิลด์ใหม่ 8 ตัว: Current path, Files here, Attacker, Kill Chain Phase, Mode, Action, Stage, Lure tier

การเปลี่ยนแปลงหลักจาก v1 (สำคัญ — อ่านก่อนแก้):
1. เพิ่ม 3 คันโยกตาม behavior spec:
   - action  = "รสชาติ" คำตอบ (engage=lure/delay, deceive) — ขยายให้คุม cat ไฟล์ล่อ / SELECT สมบัติ
     ไม่ใช่แค่ payload อีกต่อไป
   - stage   = อนุญาตให้มั่วของที่ไม่มีจริงไหม (A=ไม่, B=ได้ + ต้อง cache) ← ตัวกัน hallucination
     แทนบทบาทของ BASH_RULE เดิม
   - lure tier = สไตล์การล่อ (1 ล่อชัด = Bot/SK, 2 ล่อเนียน = APT) map จาก attacker type
2. Rule text เขียนใหม่ให้ตรงกับพฤติกรรม 3 คันโยกด้านบน (ของเดิมสั่ง "action มีผลแค่ payload +
   ห้ามมั่วไฟล์" ซึ่งขัดกับ spec ใหม่)

ยังคงเดิม: payoff matrix (Nash mix lure/deceive/delay), SessionPhaseTracker ของทีม
"""

import json
import os
import random

from predict_phase_rules import SessionPhaseTracker, predict_command_phase


# ---------------------------------------------------------------------------
# 0. Payoff matrix — โหลดครั้งเดียว, cache ไว้
#    หา payoff_matrices.json จากหลายที่ (config/ หรือ ข้างไฟล์นี้) ให้ทนต่อ layout
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_PAYOFF_CANDIDATES = [
    os.path.join("config", "payoff_matrices.json"),
    os.path.join(_HERE, "payoff_matrices.json"),
    os.path.join(_HERE, "config", "payoff_matrices.json"),
]

ATTACKER_PREFIX = {"Bot": "bot", "APT": "apt", "ScriptKiddie": "sk"}

# lure tier: attacker type -> สไตล์การล่อ (เขียน content แค่ 2 สไตล์ ไม่ใช่ 3 บุคลิก)
TIER_OF = {"Bot": 1, "ScriptKiddie": 2, "APT": 3}

# stage: phase ต้นๆ = ยังไม่ติดกับ (A), phase ที่ลงมือแล้ว = ติดกับ (B)
STAGE_A_PHASES = {"Reconnaissance", "Weaponization"}

_payoff_cache = None


def _load_payoff_matrix() -> dict:
    global _payoff_cache
    if _payoff_cache is None:
        for path in _PAYOFF_CANDIDATES:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    _payoff_cache = json.load(f)
                break
        else:
            raise FileNotFoundError(
                "หา payoff_matrices.json ไม่เจอใน: " + ", ".join(_PAYOFF_CANDIDATES)
            )
    return _payoff_cache


def get_lure_tier(attacker_type: str) -> int:
    return TIER_OF.get(attacker_type, 1)


def get_stage(kill_chain_phase: str) -> str:
    """A = ยังไม่ติดกับ (ตอบ static/ของจริง), B = ติดกับแล้ว (Qwen มั่วได้)"""
    return "A" if kill_chain_phase in STAGE_A_PHASES else "B"


# ---------------------------------------------------------------------------
# 1. Session state จาก Cowrie
# ---------------------------------------------------------------------------
class SessionState:
    def __init__(self, cwd, files_in_cwd, command_history, mode="bash", env_vars=None,
                 phase_tracker=None):
        self.cwd = cwd
        self.files_in_cwd = files_in_cwd
        self.command_history = command_history
        self.mode = mode                           # "bash" | "psql"
        self.env_vars = env_vars or {}
        self.phase_tracker = phase_tracker or SessionPhaseTracker()


# ---------------------------------------------------------------------------
# 2. Trajectory analysis — รับค่าจากทีมเพื่อน
# ---------------------------------------------------------------------------
def get_attacker_type(session_state: SessionState) -> str:
    """
    TODO: เชื่อมกับโมดูล trajectory analysis ของเพื่อน
    ต้องคืนหนึ่งใน ATTACKER_PREFIX.keys(): "Bot" / "APT" / "ScriptKiddie"
    """
    raise NotImplementedError("เชื่อมกับโมดูลจริงของทีม trajectory analysis")


# ---------------------------------------------------------------------------
# 3. Kill Chain Phase — ใช้ SessionPhaseTracker ของทีมตรงๆ
# ---------------------------------------------------------------------------
def estimate_kill_chain_phase(session_state: SessionState, latest_command: str) -> str:
    return session_state.phase_tracker.update(latest_command)


# ---------------------------------------------------------------------------
# 4. Payoff matrix (Nash mixed strategy)
# ---------------------------------------------------------------------------
def get_action_probabilities(attacker_type: str, kill_chain_phase: str) -> dict:
    matrix = _load_payoff_matrix()
    prefix = ATTACKER_PREFIX.get(attacker_type)
    phase_key = kill_chain_phase.lower()
    key = f"{prefix}_{phase_key}" if prefix else None
    entry = matrix.get(key)
    if entry is None:
        return {"lure": 0.7, "deceive": 0.1, "delay": 0.2}
    return entry["mix"]


def sample_action(probabilities: dict) -> str:
    actions = list(probabilities.keys())
    weights = list(probabilities.values())
    return random.choices(actions, weights=weights, k=1)[0]


def get_content_mode(action: str) -> str:
    """เปลี่ยน 2026-08-23 (มติผู้ใช้ — Prepared Response Layer redesign, ดู
    docs/07_behavior_spec.md + docs/reports/pi_stageB_pregen_2026-08-23.md):
    เดิม 'lure'/'delay' -> 'engage' (ไฟล์ล่อล็อกไว้ = 'Permission denied') ตอนนี้เปลี่ยนเป็น
    'lure'/'delay' -> 'normal' (เนื้อหาปกติทั่วไปตามประเภทไฟล์ อ่านได้จริง ไม่ล็อก) ·
    'deceive' -> 'deceive' (เนื้อหาหลอกล่อเต็มรูปแบบ, ไม่เปลี่ยน) — 'delay' ใช้เนื้อหาเดียวกับ
    'lure' เป๊ะ ต่างกันแค่เวลาหน่วงตอบ (ดู get_extra_delay_ms) ไม่ใช่เนื้อหา"""
    return "deceive" if action == "deceive" else "normal"


def get_extra_delay_ms(action: str) -> int:
    return random.randint(2000, 6000) if action == "delay" else 0


# ---------------------------------------------------------------------------
# 5a. Rule text — เขียนใหม่ให้ตรง 3 คันโยก (stage/action/tier)
#
# แก้ 2026-08-23 (Prepared Response Layer redesign): เดิม Action 'engage' (=lure/delay) สั่งให้
# ไฟล์ล่อ/payload "ล็อกไว้" (Permission denied / คำสั่งล้มเหลว) ผู้ใช้ตัดสินใจเปลี่ยนใหม่ —
# 'lure'/'delay' ให้เนื้อหาปกติทั่วไปของไฟล์ประเภทนั้น (อ่านได้จริง ไม่ใช่ปฏิเสธสิทธิ์) ส่วน
# 'deceive' ยังเป็นเนื้อหาหลอกล่อเต็มรูปแบบเหมือนเดิม — text ด้านล่างนี้ใช้กับ
# format_system_prompt_long() (base model / few-shot) และ build_batch_prompt() (โมเดลสำเร็จรูป
# Hailo stock — ดูด้านล่าง) เท่านั้น *ไม่กระทบ* format_system_prompt() แบบสั้นที่โมเดล
# fine-tuned (Colab 3B) เทรนไว้แล้ว เพราะ prompt สั้นไม่มี rule text ฝังอยู่ (มีแค่ action={action}
# เป็น token — ความหมายของ token นั้นเรียนรู้จาก training data ไม่ใช่จาก rule text) เปลี่ยน
# rule text ตรงนี้จึงไม่ทำให้ train/inference mismatch กับโมเดลเดิมที่ยังใช้เป็น psql fallback ได้
# ---------------------------------------------------------------------------
BASH_RULE = (
    "Rule: Act strictly as a Linux terminal; print only terminal output, no explanations. "
    "Files and directories listed in 'Files here' exist and must be shown truthfully from their "
    "real contents. For a path NOT in 'Files here': in Stage A it does not exist, so you MUST return "
    "'cat: <path>: No such file or directory' (never invent it); in Stage B you may fabricate "
    "believable, persona-consistent contents and must stay consistent if asked again, otherwise "
    "still return the not-found error. Action controls flavor: 'deceive' makes payload commands "
    "(wget/curl/sudo/chmod/nc) appear to succeed and sensitive bait files reveal rich, valuable-looking "
    "fabricated contents; 'lure' and 'delay' make the file show plain, ordinary, everyday contents "
    "typical of that file type/path — believable and readable, but unremarkable, nothing sensitive or "
    "juicy (payload commands under 'lure'/'delay' appear to succeed normally with routine output, "
    "no locked/denied response of any kind). Lure tier controls STYLE (from attacker type): tier 1 = "
    "terse/mechanical, keep an automated bot's script moving (plausible but generic, no elaborate loot); "
    "tier 2 = loud, obvious bait (plaintext secrets, flashy/round values) to keep a curious low-skill "
    "human digging; tier 3 = subtle, realistic, internally consistent bait that survives cross-checking."
)

PSQL_RULE = (
    "Rule: Act strictly as a psql session on database odoo_production; print only psql output. "
    "Only tables listed in 'Files here' exist — return real sample data for them. For a table NOT in "
    "'Files here': in Stage A return 'ERROR:  relation \"<table>\" does not exist'; in Stage B you may "
    "fabricate plausible rows and must stay consistent if asked again, otherwise return the same error. "
    "Action 'deceive' returns rich, valuable-looking rows (real secrets/PII-shaped data); 'lure' and "
    "'delay' return plain, ordinary rows typical of that table — believable row shapes and counts, but "
    "unremarkable, nothing sensitive. Lure tier STYLE: tier 1 = terse/plain rows (bot); tier 2 = flashy "
    "big/round values (script kiddie); tier 3 = realistic, consistent rows (VAT/format correct, APT)."
)


def get_mode_rule(mode: str) -> str:
    return PSQL_RULE if mode == "psql" else BASH_RULE


def format_system_prompt(cwd: str, files_str: str, attacker_type: str,
                          kill_chain_phase: str, mode: str, action: str,
                          stage: str = "A", tier: int = 1) -> str:
    """v3 (prompt สั้น): โมเดลรับเฉพาะคันโยกที่กำหนด output — mode/cwd/files/stage/action/tier.
    ตัด rule ยาว + Attacker/Kill Chain Phase ออกโดยตั้งใจ (ถูกย่อยเป็น action/stage/tier แล้ว
    = sufficient statistic). attacker_type/kill_chain_phase คงใน signature เพื่อ compat
    (สมองยังคำนวณ+ใช้ที่อื่น) แต่ไม่โผล่ใน prompt โมเดล. ต้องเทรน+infer ฟอร์แมตนี้ตัวเดียวกันเป๊ะ."""
    _atk = {1: "bot", 2: "script_kiddie", 3: "apt"}.get(tier, "bot")
    return (
        f"term mode={mode} stage={stage} action={action} attacker={_atk} "
        f"cwd={cwd} files=[{files_str}]"
    )


def format_system_prompt_long(cwd: str, files_str: str, attacker_type: str,
                              kill_chain_phase: str, mode: str, action: str,
                              stage: str = "A", tier: int = 1) -> str:
    """เวอร์ชันยาว (rule ครบ) — เก็บไว้สำหรับเส้น few-shot บน base model เท่านั้น
    ห้ามใช้ปนกับโมเดลที่เทรนด้วย prompt สั้น."""
    return (
        f"You are a Linux Ubuntu 22.04 terminal. "
        f"Current path: {cwd}. Files here: [{files_str}]. "
        f"Attacker: {attacker_type}. Kill Chain Phase: {kill_chain_phase}. "
        f"Mode: {mode}. Action: {action}. Stage: {stage}. Lure tier: {tier}. "
        f"{get_mode_rule(mode)}"
    )


# ---------------------------------------------------------------------------
# 4b. Batch prompt (Prepared Response Layer, เพิ่ม 2026-08-23) — สำหรับ prefetch_worker.py
# เรียกโมเดลสำเร็จรูปของ Hailo (qwen2.5:1.5b ผ่าน hailo-ollama, ไม่ fine-tune) generate เนื้อหา
# Stage B ล่วงหน้าเป็น batch/background ไม่ใช่ตอน request จริง — ต่างจาก format_system_prompt()
# แบบสั้น 2 จุด: (1) ไม่มี kill_chain_phase/session/cwd/files เกี่ยวข้องเลย (คีย์คือ
# target×tier×content_type เท่านั้น ตามที่ยืนยันแล้วว่า phase ไม่ได้อยู่ใน prompt จริง และ pre-gen
# ไม่ผูก session) (2) ใช้ instruction แบบสั้น-ตรง-เป็นรูปธรรม ไม่ใช่ BASH_RULE/PSQL_RULE แบบยาว —
# ทดสอบจริงกับ qwen2.5:1.5b บน hailo-ollama แล้วพบว่า rule แบบยาว/นามธรรมทำให้โมเดลหลุดไปโหมด
# อธิบาย/ขอโทษแทนที่จะ output ตรงๆ (เจอ 2026-08-23 ตอน implement — ดู
# docs/reports/pi_stageB_pregen_2026-08-23.md) คำสั่งสั้นตรงๆ + "Start immediately with the
# content:" ท้ายสุด ได้ผลดีกว่ามาก
#
# ⚠️ ห้ามใส่ literal newline (\\n) ในสตริงที่ส่งเป็น prompt ไปหา hailo-ollama โดยเด็ดขาด —
# HailoRT re-parse prompt เป็น JSON ภายในอีกชั้น แล้ว crash (HAILO_INTERNAL_FAILURE) ถ้าเจอ \\n
# ดิบๆ ในสตริง (ยืนยันจาก error log จริง 2026-08-23 — ใช้ " " หรือ "." คั่นประโยคแทนเสมอ)
# ---------------------------------------------------------------------------
_TIER_STYLE = {
    1: "terse, generic, and mechanical, nothing elaborate",
    # แก้ 2026-09-16: เดิมมีคำว่า "secrets" ฝังอยู่ในสไตล์ตรงๆ ทำให้ขัดกับ content_type="normal"
    # เอง (Style: ...secrets... ตามด้วย Make it look ordinary...nothing sensitive — ขัดกันในประโยค
    # ติดกัน) เจอจริงระหว่างพิมพ์ prompt ออกมาตรวจก่อนเทสเปรียบเทียบโมเดล — tier ควรบอกแค่สไตล์การ
    # นำเสนอ/format (โชว์ชัด ไม่ปิดบัง) ส่วนเนื้อหาไวหรือไม่ไวเป็นหน้าที่ของ content_type ล้วนๆ
    # (get_content_mode/_CONTENT_TYPE_HINT) ไม่ควรผูกซ้ำสองที่ ตัดคำว่า "secrets" ออก เหลือแค่ลักษณะ
    # การนำเสนอ (ตรงกับ tier 1/3 ที่ไม่มีปัญหานี้อยู่แล้ว)
    2: "loud and unsubtle, big round numbers and prominent plaintext values, nothing hidden or redacted",
    3: "subtle, realistic, professional-looking, and internally consistent",
}

_CONTENT_TYPE_HINT = {
    "deceive": "Make it look valuable and sensitive, worth stealing",
    "normal": "Make it look ordinary, routine, and unremarkable, nothing sensitive",
}


def build_batch_prompt(target: str, mode: str, content_type: str, tier: int,
                        schema_fact: str = "", target_type: str = "file") -> str:
    """content_type: 'deceive' หรือ 'normal' (จาก get_content_mode) · target_type: 'file'/'dir'
    (เฉพาะ mode='bash' — psql ไม่มีแนวคิด dir) พบจริง 2026-08-23 ว่าถ้าบอกโมเดลว่า "raw file
    content" กับ target ที่จริงเป็น directory (path ลงท้าย /) โมเดลสับสน ตอบสั้นผิดปกติ (แค่ echo
    path กลับมา) แก้ด้วยแยกคำสั่งชัดเจนตาม type

    แก้เพิ่ม 2026-08-26 (เจอจริงตอนผู้ใช้ทดสอบเดโมผ่าน SSH จริง ดู
    docs/reports/pi_prepared_response_qc_fix_2026-08-26.md): instruction เดิม (2026-08-23) ยังกัน
    ไม่พอ — เจอ 2 อาการใหม่ที่ QC เดิมไม่เคยจับ: (1) mode=psql ยัง echo SQL query กลับมาอยู่
    (res_users_backup, ir_attachment — deterministic ทดสอบซ้ำ 2 session ได้ผลเดิม ไม่ใช่สุ่ม)
    (2) โมเดลพ่นคำตอบมากกว่า 1 เวอร์ชันในคำตอบเดียว (เช่น postgresql.conf มี listen_addresses
    2 ค่าขัดกันเอง, crm_lead/stock_move_line มีตารางซ้อนกัน 2-3 บล็อกคอลัมน์ไม่ตรงกัน) —
    "Do not repeat the same line" (2026-08-23) กันแค่บรรทัดซ้ำเป๊ะ ไม่กันการพ่น "คำตอบทั้งชุด" ซ้ำ
    เป็นเวอร์ชันที่ 2 แบบเปลี่ยนคำ เพิ่ม instruction ห้าม SQL keyword ตรงๆ + ห้ามมีคำตอบเกิน 1 ชุด"""
    style = _TIER_STYLE.get(tier, _TIER_STYLE[1])
    flavor = _CONTENT_TYPE_HINT.get(content_type, _CONTENT_TYPE_HINT["normal"])
    if mode == "psql":
        # แก้ 2026-08-26: เน้นย้ำแรงขึ้นกว่าเดิม (2026-08-23) เพราะยังหลุดจริง — สั่งห้าม SQL
        # keyword ทุกคำแบบเจาะจง ไม่ใช่แค่ "ห้าม echo query" เฉยๆ
        kind = ("only the resulting data rows from a psql SELECT query, formatted as plain "
                "pipe-or-space-aligned table rows with real sample values. Your answer must NOT "
                "contain the words SELECT, FROM, WHERE, AS, or CASE anywhere -- if you catch "
                "yourself writing any of those words, delete it and write only the data table "
                "instead")
    elif target_type == "dir":
        kind = "the raw output of `ls -la` for this directory (list of files/subdirs with permissions, owner, size, date)"
    else:
        kind = "the raw file content"
    fact = f" Known facts, stay consistent with these: {schema_fact}." if schema_fact else ""
    return (
        f"Output only {kind}, no markdown, no explanation, no commentary. "
        f"This is {target} on a Linux server persona 'erp-db-01' (small Odoo ERP company). "
        # เพิ่ม 2026-08-23: แก้ปัญหาโมเดลใส่ปีเก่า (2015-2023) หลุดมาบ่อย (34/78 rows ตอน QC เต็ม
        # รูปแบบ) — บอกปีปัจจุบันตรงๆ ในพรอมต์ ไม่ใช่หวังให้โมเดลเดาเอง
        f"The current date is in 2026 — any timestamps, dates, or 'installed on' comments must "
        f"use 2026 dates, never older years. "
        # เพิ่ม 2026-08-23: แก้ self-repetition (18/91 rows ตอน QC เข้มขึ้น — โมเดลวนพ่นบรรทัด
        # เดิมซ้ำๆ โดยเฉพาะ tier=1) คู่กับ repeat_penalty ใน generation options
        f"Do not repeat the same line, sentence, or query more than once. "
        # เพิ่ม 2026-08-26: กันคนละปัญหากับข้างบน — ไม่ใช่บรรทัดซ้ำเป๊ะ แต่พ่น "คำตอบทั้งชุด" ซ้ำ
        # เป็นเวอร์ชันที่ 2 (เช่น config ตั้งค่าเดิมซ้ำ 2 ชุดคนละค่า, ตาราง SQL result 2-3 บล็อก)
        f"Write exactly ONE single, internally consistent answer -- never give two different "
        f"values for the same field or setting, and never write a second attempt, alternate "
        f"version, or another table after the first one. Stop as soon as the one answer is "
        f"complete. "
        f"Style: {style}. {flavor}.{fact} Start immediately with the content:"
    )


# ---------------------------------------------------------------------------
# 5. ประกอบ system prompt — เรียกทุกเทิร์น
# ---------------------------------------------------------------------------
def build_system_prompt(session_state: SessionState, latest_command: str):
    attacker_type = get_attacker_type(session_state)
    kill_chain_phase = estimate_kill_chain_phase(session_state, latest_command)
    action_probs = get_action_probabilities(attacker_type, kill_chain_phase)
    action = sample_action(action_probs)
    stage = get_stage(kill_chain_phase)
    tier = get_lure_tier(attacker_type)

    files_str = ", ".join(session_state.files_in_cwd)

    prompt = format_system_prompt(
        cwd=session_state.cwd, files_str=files_str, attacker_type=attacker_type,
        kill_chain_phase=kill_chain_phase, mode=session_state.mode, action=action,
        stage=stage, tier=tier,
    )

    metadata = {
        "cwd": session_state.cwd,
        "mode": session_state.mode,
        "attacker_type": attacker_type,
        "kill_chain_phase": kill_chain_phase,
        "action": action,
        "stage": stage,
        "tier": tier,
        "content_mode": get_content_mode(action),
        "extra_delay_ms": get_extra_delay_ms(action),
    }
    return prompt, metadata
