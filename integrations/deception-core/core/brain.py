"""
brain.py — 3 คันโยก (stage/action/tier) ต่อยอดจาก shared/session_prompt_builder.py โดยตรง
(reuse get_stage / get_action_probabilities / sample_action / get_lure_tier / get_content_mode
ทุกฟังก์ชัน ไม่พิมพ์ logic ซ้ำ — CLAUDE.md §5 single source of truth)

แก้ 2026-08-30 (มติผู้ใช้): attacker_type สุ่มครั้งเดียวตอน login แทนคำนวณจาก command_count ทุกคำสั่ง
(กัน tier เปลี่ยนกลางทาง session → Part 2 re-warm ซ้ำ)

แก้ 2026-09-08 (เชื่อม attacker-classifier จริง — งาน type-classi ของผู้ใช้): แทน
`simulate_attacker_type_at_login()` (สุ่ม placeholder) ด้วย `classify_attacker_type()` ที่เรียก
classifier จริง (Heuristic baseline / Bayesian proposed ผ่าน core/attacker_classifier.py) จาก
คำสั่งจริง + client version. เรียกจาก session_store.record_command() ครั้งเดียวตอนครบ N คำสั่งแล้ว
ล็อก (ไม่ re-classify ทุกคำสั่ง — churn ต่ำเหมือนเดิม). `simulate_attacker_type_at_login()` เก็บไว้
เป็น fallback ถ้า classifier import ไม่ได้ (เช่น type-classi ไม่ถูก deploy คู่มา)
"""

import random

from session_prompt_builder import (
    get_action_probabilities,
    get_content_mode,
    get_lure_tier,
    get_stage,
    sample_action,
)

# น้ำหนักการสุ่ม (fallback เท่านั้น) — Bot 70% / ScriptKiddie 25% / APT 5%
_ATTACKER_TYPE_WEIGHTS = {"Bot": 0.70, "ScriptKiddie": 0.25, "APT": 0.05}


def simulate_attacker_type_at_login() -> str:
    """FALLBACK เท่านั้น — สุ่มตามน้ำหนัก (ใช้เมื่อ classifier จริง import ไม่ได้)"""
    types = list(_ATTACKER_TYPE_WEIGHTS.keys())
    weights = list(_ATTACKER_TYPE_WEIGHTS.values())
    return random.choices(types, weights=weights, k=1)[0]


def classify_attacker_type(commands: list[str], ip: str | None = None,
                           client_version: str | None = None, username: str | None = None,
                           ip_seen_count: int = 0, elapsed_seconds: float | None = None) -> str:
    """จำแนก attacker_type จริงจากคำสั่ง + client version (default Bayesian proposed).
    ถ้า classifier import ไม่ได้ → fallback สุ่ม (กัน service ล่มเพราะ dependency ไม่ครบ)

    elapsed_seconds: เพิ่ม 2026-09-12 (Work Item 4b) — ส่งต่อจาก session_store.py (created_at ถึง
    ตอนจำแนก) เข้า attacker_classifier.build_signals() เพื่อคำนวณ commands_per_minute"""
    try:
        import attacker_classifier
    except Exception:
        return simulate_attacker_type_at_login()
    try:
        return attacker_classifier.classify(
            commands, ip=ip, client_version=client_version, username=username,
            ip_seen_count=ip_seen_count, method="bayesian", elapsed_seconds=elapsed_seconds,
        )
    except Exception:
        return simulate_attacker_type_at_login()


def classify_attacker_type_with_confidence(
    commands: list[str], ip: str | None = None, client_version: str | None = None,
    username: str | None = None, ip_seen_count: int = 0,
    elapsed_seconds: float | None = None,
) -> tuple[str, float, dict]:
    """คืน (type, confidence, posterior) — ให้ session_store ตัดสิน confidence-gate lock (P4, ดู
    docs/reports/pi_confidence_gate_lock_2026-09-18.md). confidence = posterior ของคลาสที่ชนะ.
    ถ้า classifier import/รันไม่ได้ → fallback (สุ่ม, 0.0, {}) — conf=0.0 ทำให้ gate รอจนถึงเพดาน
    แล้วบังคับล็อกด้วยค่าสุ่ม (ไม่ล่ม service เพราะ dependency ไม่ครบ, พฤติกรรมเดียวกับ classify_attacker_type)"""
    try:
        import attacker_classifier
    except Exception:
        return simulate_attacker_type_at_login(), 0.0, {}
    try:
        return attacker_classifier.classify_with_confidence(
            commands, ip=ip, client_version=client_version, username=username,
            ip_seen_count=ip_seen_count, elapsed_seconds=elapsed_seconds,
        )
    except Exception:
        return simulate_attacker_type_at_login(), 0.0, {}


def compute_levers(phase: str, attacker_type: str) -> dict:
    """รับ attacker_type ตรงๆ (มาจาก session.attacker_type) — ดู docstring หัวไฟล์"""
    stage = get_stage(phase)
    action_probs = get_action_probabilities(attacker_type, phase)
    action = sample_action(action_probs)
    tier = get_lure_tier(attacker_type)
    content_mode = get_content_mode(action)
    return {
        "attacker_type": attacker_type,
        "stage": stage,
        "action": action,
        "tier": tier,
        "content_mode": content_mode,
    }
