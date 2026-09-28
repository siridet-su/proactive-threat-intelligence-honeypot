"""
attacker_classifier.py — adapter เชื่อม classifier (type-classi/Honeypot_ML) เข้ากับ deception-core
จำแนกจาก **คำสั่งในหน่วยความจำ + ip + client version + username** (ข้อมูลที่ core มีจริง)
ไม่ใช่จากไฟล์ cowrie.json (นั่นคือ path สำหรับ eval offline)

แทน `brain.simulate_attacker_type_at_login()` (สุ่ม) — เรียกครั้งเดียวตอนครบ N คำสั่งแล้วล็อก
(ดู session_store.record_command). reuse ฟังก์ชันสัญญาณจาก signal_extractor + classifier ตัวจริง
(CLAUDE.md §5 — ไม่พิมพ์ logic ซ้ำ)

**ข้อจำกัดที่ core มี (ตรงไปตรงมา):**
  - มี: commands, ip, client_version (ถ้า Cowrie ส่งมา), username(login), phase
  - ไม่มี: password, command timestamps, failed-command count
  → timing_regularity/error_rate = ปิด (unknown). พิสูจน์แล้วว่าถ้ามี client_family ก็ยังแม่น
    (ดู scratchpad/test_core_signals) — client_version จาก Cowrie จึงเป็นตัวที่ "ต้องมี"

แก้ 2026-09-12 (grilling session, Work Item 4 — ดู ~/.claude/plans/attacker-polished-seahorse.md):
  (a) error_rate เปลี่ยนจาก hardcode 0.0 เป็น None — 0.0 คือ "วัดจริงแล้วไม่มีข้อผิดพลาดเลย" ซึ่ง
      ไม่ตรงกับความจริง (core ไม่เคยวัดเลย) ทำให้ทุก session ถูกตีเป็น bucket "none" ที่มี
      likelihood เอียงออกจาก ScriptKiddie อย่างเป็นระบบ (verify จริง — ดู work log 2026-09-12: สัญญาณ
      เดียวกันเป๊ะ เปลี่ยนจาก error_rate=0.0→None พลิกผลจาก Bot 47.7% เป็น ScriptKiddie 53.4%) ดู
      classifier.py::_error_bucket() สำหรับรายละเอียดเต็ม
  (b) เพิ่ม commands_per_minute (signal เสริมใหม่, provisional ไม่มี citation — ดู
      classifier.py::_pace_bucket() docstring) จาก elapsed_seconds ที่ session_store.py ส่งมา
      (created_at/updated_at มีอยู่แล้วฟรี ไม่ต้องแก้ Cowrie/schema เพิ่ม)
"""

from __future__ import annotations

import os
import sys

# reuse ตัวจริงจาก type-classi/Honeypot_ML (single source of truth)
_HERE = os.path.dirname(os.path.abspath(__file__))
_CLF_DIR = os.path.normpath(os.path.join(_HERE, "..", "type-classi", "Honeypot_ML"))
# เผื่อ deploy บน Pi ที่ layout ต่าง — ให้ override ได้ผ่าน env
_CLF_DIR = os.environ.get("ATTACKER_CLF_DIR", _CLF_DIR)
if _CLF_DIR not in sys.path:
    sys.path.insert(0, _CLF_DIR)

from signal_extractor import (  # noqa: E402
    _anti_honeypot,
    _chaining,
    _cleanup_antiforensics,  # P6
    _command_sophistication,
    _credential_source,
    _repetition,
    _targeted_enum,          # P6
)
from attack_mapping import attack_breadth  # noqa: E402 (P7 — ATT&CK advanced-tactic breadth)
from ip_reputation import reputation_bucket  # noqa: E402 (AbuseIPDB ตรง + fallback local-history)
from zeek_hassh import client_family as zeek_client_family  # noqa: E402 (HASSH เสริม + fallback)
from classifier import BayesianClassifier, HeuristicProfiler  # noqa: E402

# instance เดียว reuse (likelihood/prior คงที่ ไม่มี state ต่อ session)
_BAYES = BayesianClassifier()      # proposed (default — real-time, ไม่ใช้ depth)
_HEUR = HeuristicProfiler()        # baseline (เผื่อเทียบ)


def _commands_per_minute(n_commands: int, elapsed_seconds: float | None) -> float | None:
    """None ถ้าไม่มีข้อมูลเวลาจริง หรือ elapsed สั้นเกินจะเชื่อได้ (<1s — กัน divide เกือบ-0 ทำให้
    ค่าพุ่งเวอร์เกินจริง, n=3 คำสั่งที่ยิงพร้อมกันหมดในเสี้ยววินาทีก็ยังนับเป็น bursty ถูกอยู่ดี
    ผ่าน pace_bucket's "unknown" -> _EPS fallback เท่ากันทุก class ไม่ต้องกลัวข้อมูล noise ตรงนี้)"""
    if elapsed_seconds is None or elapsed_seconds < 1.0 or n_commands <= 0:
        return None
    return n_commands / (elapsed_seconds / 60.0)


def build_signals(commands: list[str], ip: str | None = None,
                  client_version: str | None = None, username: str | None = None,
                  ip_seen_count: int = 0, elapsed_seconds: float | None = None) -> dict:
    """แปลงข้อมูลที่ core มี -> signal dict (สัญญาณตอนเชื่อมต่อ timing/error = ปิด)

    elapsed_seconds: เพิ่ม 2026-09-12 (Work Item 4b) — วินาทีตั้งแต่ session สร้าง (session_store.py
    created_at) จนถึงตอนจำแนก (ไม่ใช่ per-command timestamp แบบ offline signal_extractor.py —
    หยาบกว่านั้น แต่ core มีให้ฟรีอยู่แล้วไม่ต้องแก้ Cowrie เพิ่ม)"""
    cmd_tuples = [(None, c) for c in commands]
    logins = [(username, None)] if username else []
    return {
        # client_family: Zeek HASSH เสริม (client string น่าเชื่อกว่า + จับ spoof) fallback Cowrie version
        "client_family": zeek_client_family(ip, client_version),
        "credential_source": _credential_source(logins),
        "timing_regularity": "unknown",     # core ไม่มี per-command timestamp
        # signal #7: AbuseIPDB (key ของเราเอง, cache) ถ้าใช้ได้ ไม่งั้น local-history (ip_seen_count)
        "ip_reputation": reputation_bucket(ip, ip_seen_count),
        "command_sophistication": _command_sophistication(cmd_tuples),
        "chaining": _chaining(cmd_tuples),
        "repetition": _repetition(cmd_tuples),
        "anti_honeypot_probe": _anti_honeypot(cmd_tuples),
        "cleanup_antiforensics": _cleanup_antiforensics(cmd_tuples),  # P6
        "targeted_enum": _targeted_enum(cmd_tuples),                  # P6
        "attack_breadth": attack_breadth(commands),                   # P7 (รับ list[str] ตรง)
        # แก้ 2026-09-12: None แทน 0.0 เดิม (ดู docstring หัวไฟล์ (a) — 0.0 คือ "วัดจริงว่าไม่ผิดเลย"
        # ไม่ตรงความจริงที่ core ไม่เคยวัด) classifier.py::_error_bucket(None) -> "unknown" ถูกต้อง
        "error_rate": None,
        "kill_chain_depth": 0,               # ไม่ใช้ real-time อยู่แล้ว
        # เพิ่ม 2026-09-12 (Work Item 4b, provisional — ดู classifier.py::_pace_bucket() docstring)
        "commands_per_minute": _commands_per_minute(len(commands), elapsed_seconds),
    }


def classify(commands: list[str], ip: str | None = None,
             client_version: str | None = None, username: str | None = None,
             ip_seen_count: int = 0, method: str = "bayesian",
             elapsed_seconds: float | None = None) -> str:
    """คืน attacker_type: "Bot" | "ScriptKiddie" | "APT" (ตรง ATTACKER_PREFIX.keys())"""
    sig = build_signals(commands, ip, client_version, username, ip_seen_count, elapsed_seconds)
    model = _HEUR if method == "heuristic" else _BAYES
    return model.classify(sig)


def classify_with_confidence(commands: list[str], ip: str | None = None,
                             client_version: str | None = None, username: str | None = None,
                             ip_seen_count: int = 0,
                             elapsed_seconds: float | None = None) -> tuple[str, float, dict]:
    """เวอร์ชัน Bayesian ที่คืน (type, confidence, posterior) — ให้ session_store ตัดสิน lock
    ตาม threshold ความมั่นใจได้ (one-shot-lock)"""
    sig = build_signals(commands, ip, client_version, username, ip_seen_count, elapsed_seconds)
    return _BAYES.classify_with_confidence(sig)
