"""
classifier.py — จำแนกประเภท attacker (Bot / ScriptKiddie / APT) 2 วิธี ใช้สัญญาณจาก signal_extractor:
  1) HeuristicProfiler  — baseline: 2-score (automation/skill) + threshold (อธิบายง่าย, เกณฑ์เทียบ)
  2) BayesianClassifier — proposed: naive-Bayes belief, likelihood ตั้งจาก prior งานวิจัย (ไม่เทรน),
     คืน posterior ทั้งก้อน → เอาไปถ่วง Nash payoff เป็น Bayesian game ได้ (ดู plan)

คลาสเอาต์พุตต้องตรง ATTACKER_PREFIX.keys() ของ honeypot: "Bot" / "ScriptKiddie" / "APT"

ที่มาน้ำหนัก/likelihood (ดู ~/.claude/plans/attacker-cheeky-gosling.md):
  HASSH (Salesforce) · IEEE 8757534 · patent US11689568 · arXiv 2006.01849 / 2101.02102
"""

from __future__ import annotations

import math

CLASSES = ["Bot", "ScriptKiddie", "APT"]


# ---------------------------------------------------------------------------
# discretize สัญญาณตัวเลขให้เป็น bucket (ใช้ร่วมทั้ง 2 วิธี)
# ---------------------------------------------------------------------------
def _depth_bucket(idx: int) -> str:
    if idx <= 1:
        return "shallow"      # Recon/Weaponization เท่านั้น
    if idx <= 3:
        return "mid"          # Delivery/Exploitation
    return "deep"             # Installation..Actions_on_Objectives


def _error_bucket(rate: float | None) -> str:
    """แก้บั๊กจริง 2026-09-12 (grilling session, Work Item 4a — ดู
    ~/.claude/plans/attacker-polished-seahorse.md): เดิมรับแค่ float ไม่มีทางแทน "ไม่มีข้อมูลวัดจริง"
    ได้เลย — core (attacker_classifier.py) เคย hardcode error_rate=0.0 เสมอ (ไม่มี failed-cmd count)
    ทำให้ทุก session ในโปรดักชันตกไป bucket "none" ซึ่งมี likelihood ที่ต่างกันจริงระหว่าง class
    (Bot 0.70 / ScriptKiddie 0.30 / APT 0.55 — ดู LIKELIHOODS ด้านล่าง) เหมือนเป็นข้อมูลที่วัดจริง
    ทั้งที่ไม่เคยวัดเลย เอียงออกจาก ScriptKiddie เข้าหา Bot/APT ทุกครั้งอย่างเป็นระบบ — เปลี่ยนให้
    core ส่ง None แทน (ดู attacker_classifier.py) แล้วคืน "unknown" ตรงนี้ (ไม่ต้องเพิ่ม row ใหม่ใน
    LIKELIHOODS["error_bucket"] — key ที่ไม่มีในตารางจะ fallback ไปที่ _EPS เท่ากันทุก class อยู่แล้ว
    ผ่าน _lik() ซึ่ง cancel กันหมดพอ normalize = เป็นกลางทางคณิตศาสตร์ 100% ไม่ใช่แค่ใกล้เคียง)
    self-play/offline (signal_extractor.py::compute_signals) ยังส่ง float จริงเสมอ ไม่กระทบ path นั้น"""
    if rate is None:
        return "unknown"
    if rate <= 0.0:
        return "none"
    if rate < 0.25:
        return "low"
    return "high"


def _pace_bucket(commands_per_minute: float | None) -> str:
    """เพิ่ม 2026-09-12 (grilling session, Work Item 4b — signal เสริมจาก session duration ที่มีอยู่
    แล้วฟรีใน session_store.py created_at/updated_at ไม่ต้องแก้ Cowrie/schema เพิ่ม)

    **assumption_flag (CLAUDE.md §4) — ต่างจากสัญญาณอื่นในไฟล์นี้ที่มีงานวิจัยอ้างอิงเฉพาะเจาะจง
    (HASSH/patent/IEEE/arXiv) สัญญาณนี้เป็น intuition ล้วนๆ ไม่มี citation รองรับ**: สคริปต์บอทยิง
    คำสั่งติดกันเร็วมาก (มักเป็นวินาทีเดียวกันหมด) ส่วนคนพิมพ์มือช้ากว่ามาก ไม่ว่า ScriptKiddie หรือ
    APT — ทิศทางที่คาดว่า APT อาจช้ากว่า ScriptKiddie อีกที (ระมัดระวัง/คิดก่อนพิมพ์ vs รีบก็อปวาง)
    เป็นการเดาที่ยังไม่ verify ด้วยข้อมูลจริง likelihood ด้านล่างจึงตั้งไว้แบบ "ไม่มั่นใจมาก" (spread
    แคบกว่าสัญญาณอื่น) โดยเฉพาะฝั่ง ScriptKiddie ที่ตั้งไว้กลางๆ ตรงๆ (ไม่รู้ทิศทางจริง) — **ต้อง
    verify ด้วย self-play re-eval จริงก่อนเชื่อว่าช่วยแยก SK/APT ได้จริงตามที่ตั้งใจ** (ดู
    docs/worklogs/work_log_2026-09-12.md งาน 4.3) ปรับ/ถอดสัญญาณนี้ได้ถ้าผลไม่ดีขึ้นจริง

    n=3 คำสั่ง (จุดจำแนกจริงของ core ตอน CLASSIFY_AT_N) เป็น sample เล็กมาก ค่านี้จึงมี noise สูง —
    threshold 10 คำสั่ง/นาทีเป็นเลขกว้างๆ ไม่ใช่เลขที่ผ่านการจูนจากข้อมูลจริง"""
    if commands_per_minute is None:
        return "unknown"
    return "bursty" if commands_per_minute >= 10.0 else "measured"


# ===========================================================================
# 1) HEURISTIC PROFILER (baseline)
# ===========================================================================
class HeuristicProfiler:
    """2-score: automation_score แยก Bot ออกจากคน, skill_score แยก APT ออกจาก ScriptKiddie

    use_depth=False (ค่าเริ่มต้น) = ตัดสัญญาณช้า kill_chain_depth ออก — ใช้กับตัวตัดสิน real-time
    ที่ต้องฟันธงเร็วเพื่อส่ง type ให้ชั้นเตรียมไฟล์ล่วงหน้าทัน (มติผู้ใช้ 2026-09-07: depth เป็น late
    signal ตอนตัดสินเร็ว attacker ยังไม่เดินลึก). ตั้ง True เฉพาะตอนวิเคราะห์ offline เต็ม session."""

    BOT_THRESHOLD = 2.5      # automation >= นี้ = Bot
    APT_THRESHOLD = 1.5      # (ถ้าเป็นคน) skill >= นี้ = APT

    def __init__(self, use_depth: bool = False):
        self.use_depth = use_depth

    def scores(self, sig: dict) -> tuple[float, float]:
        a = 0.0  # automation_score
        # client family (HASSH) — สัญญาณบอทที่แรงสุด
        a += {"automated": 2.0, "interactive": -2.0}.get(sig["client_family"], 0.0)
        # credential (patent US11689568)
        a += {"default": 1.0, "targeted": -1.0}.get(sig["credential_source"], 0.0)
        # timing (IEEE 8757534)
        a += {"regular": 1.0, "irregular": -1.0}.get(sig["timing_regularity"], 0.0)
        # ip reputation (#7)
        a += {"known-scanner": 1.0, "new-or-clean": -0.5}.get(sig["ip_reputation"], 0.0)
        # command style
        a += {"script": 2.0, "generic-payload": -0.5, "targeted": -1.0}.get(
            sig["command_sophistication"], 0.0)

        s = 0.0  # skill_score (ตีความเฉพาะเมื่อเป็นคน)
        # น้ำหนักหลัก = command_sophistication (มีที่มา honeypot-specific แข็งสุด)
        s += {"targeted": 2.0, "generic-payload": -1.0, "minimal": 0.0, "script": -0.5}.get(
            sig["command_sophistication"], 0.0)
        # anti-honeypot probe = สัญญาณ APT แข็ง (kiddie ไม่ทำ)
        s += {"yes": 2.0, "no": 0.0}.get(sig.get("anti_honeypot_probe", "no"), 0.0)
        # P6: cleanup/anti-forensics = APT tell (present-only, ไม่ลงโทษ absence ในฝั่ง heuristic)
        s += {"yes": 1.5, "no": 0.0}.get(sig.get("cleanup_antiforensics", "no"), 0.0)
        # P6: targeted-enum เจาะจง=APT / mass=SK. น้ำหนักเบากว่า command_sophistication (double-count)
        s += {"targeted": 1.0, "mass": -0.5, "none": 0.0}.get(sig.get("targeted_enum", "none"), 0.0)
        # P7: ATT&CK advanced-tactic breadth (double-count group → เบา). broad=หลาย advanced tactic=APT
        s += {"broad": 1.0, "moderate": 0.3, "narrow": 0.0}.get(sig.get("attack_breadth", "narrow"), 0.0)
        # chaining (คล่อง=APT) / repetition (ลังเล=kiddie)
        s += {"fluent": 1.0, "none": 0.0}.get(sig.get("chaining", "none"), 0.0)
        s += {"high": -1.0, "low": 0.0}.get(sig.get("repetition", "low"), 0.0)
        # error/typo = ตัวเสริมเท่านั้น (ที่มาอ้อม=general expertise ไม่ใช่ attacker-measured) → น้ำหนักครึ่ง
        # แก้ 2026-09-12: เปลี่ยนจาก subscript ตรงๆ ([...]) เป็น .get() — _error_bucket() คืน
        # "unknown" ได้แล้ว (ดู docstring ของมัน) ซึ่งไม่มี key นี้ใน dict นี้ subscript ตรงจะ KeyError
        s += {"none": 0.5, "low": 0.0, "high": -0.5}.get(_error_bucket(sig["error_rate"]), 0.0)
        # เพิ่ม 2026-09-12 (Work Item 4b, assumption_flag — ดู _pace_bucket() docstring): น้ำหนัก
        # เบามาก (ไม่มั่นใจ ไม่มี citation) ตั้งใจให้เล็กกว่าสัญญาณอื่นทุกตัวในฟังก์ชันนี้
        s += {"bursty": -0.3, "measured": 0.3}.get(
            _pace_bucket(sig.get("commands_per_minute")), 0.0)
        if self.use_depth:
            s += {"deep": 2.0, "mid": 1.0, "shallow": -1.0}[_depth_bucket(sig["kill_chain_depth"])]
        return a, s

    def classify(self, sig: dict) -> str:
        a, s = self.scores(sig)
        if a >= self.BOT_THRESHOLD:
            return "Bot"
        return "APT" if s >= self.APT_THRESHOLD else "ScriptKiddie"


# ===========================================================================
# 2) BAYESIAN CLASSIFIER (proposed)
# ===========================================================================
# P(signal_value | type) — ตั้งจาก prior งานวิจัย (ไม่ได้เทรนจากข้อมูล):
#   Bot        = อัตโนมัติ: automated client, จังหวะสม่ำเสมอ, script, ไม่เดินลึก, error 0
#   ScriptKiddie = คนมือใหม่: client โต้ตอบ, ก็อป payload, พิมพ์ผิดบ่อย, ลึกปานกลาง
#   APT        = คนมืออาชีพ: client โต้ตอบ, เจาะจง, พิมพ์ไม่พลาด, เดิน kill-chain ลึกเป็นระบบ
# ค่าที่ไม่อยู่ในตาราง (เช่น "unknown") ใช้ smoothing กลางๆ ผ่าน _lik()
LIKELIHOODS: dict[str, dict[str, dict[str, float]]] = {
    "client_family": {
        "Bot":          {"automated": 0.90, "interactive": 0.05, "unknown": 0.05},
        "ScriptKiddie": {"automated": 0.25, "interactive": 0.65, "unknown": 0.10},
        "APT":          {"automated": 0.20, "interactive": 0.70, "unknown": 0.10},
    },
    "credential_source": {
        "Bot":          {"default": 0.80, "targeted": 0.05, "unknown": 0.15},
        "ScriptKiddie": {"default": 0.55, "targeted": 0.30, "unknown": 0.15},
        "APT":          {"default": 0.15, "targeted": 0.70, "unknown": 0.15},
    },
    "timing_regularity": {
        "Bot":          {"regular": 0.75, "irregular": 0.10, "unknown": 0.15},
        "ScriptKiddie": {"regular": 0.25, "irregular": 0.55, "unknown": 0.20},
        "APT":          {"regular": 0.20, "irregular": 0.60, "unknown": 0.20},
    },
    "ip_reputation": {
        "Bot":          {"known-scanner": 0.65, "repeat": 0.25, "new-or-clean": 0.10},
        "ScriptKiddie": {"known-scanner": 0.35, "repeat": 0.30, "new-or-clean": 0.35},
        "APT":          {"known-scanner": 0.20, "repeat": 0.25, "new-or-clean": 0.55},
    },
    "command_sophistication": {
        "Bot":          {"script": 0.70, "generic-payload": 0.15, "targeted": 0.02, "minimal": 0.13},
        "ScriptKiddie": {"script": 0.15, "generic-payload": 0.55, "targeted": 0.10, "minimal": 0.20},
        "APT":          {"script": 0.05, "generic-payload": 0.20, "targeted": 0.65, "minimal": 0.10},
    },
    # error/typo — น้ำหนักอ่อนลง (ที่มาอ้อม): kiddie ผิดมากกว่าแต่ไม่เด็ดขาด (softened)
    "error_bucket": {
        "Bot":          {"none": 0.70, "low": 0.20, "high": 0.10},
        "ScriptKiddie": {"none": 0.30, "low": 0.35, "high": 0.35},
        "APT":          {"none": 0.55, "low": 0.30, "high": 0.15},
    },
    # chaining (ร้อยคำสั่ง = คล่อง): APT คล่องกว่า
    "chaining": {
        "Bot":          {"fluent": 0.40, "none": 0.60},
        "ScriptKiddie": {"fluent": 0.15, "none": 0.85},
        "APT":          {"fluent": 0.60, "none": 0.40},
    },
    # repetition (ทำซ้ำ/ลังเล): kiddie ซ้ำมากกว่า
    "repetition": {
        "Bot":          {"high": 0.10, "low": 0.90},
        "ScriptKiddie": {"high": 0.45, "low": 0.55},
        "APT":          {"high": 0.10, "low": 0.90},
    },
    # anti-honeypot probe: เกือบเฉพาะ APT (สัญญาณแข็ง)
    "anti_honeypot_probe": {
        "Bot":          {"yes": 0.03, "no": 0.97},
        "ScriptKiddie": {"yes": 0.05, "no": 0.95},
        "APT":          {"yes": 0.45, "no": 0.55},
    },
    # --- P6 (2026-09-19) สัญญาณแกน B ใหม่ (design §1.7②) ---
    # cleanup/anti-forensics (T1070/T1562): APT tell แข็งแต่ "มาช้า" → ตั้ง yes ให้ APT สูงพอเป็น
    # หลักฐานเมื่อเจอ แต่ไม่ให้ "no" ลงโทษ APT แรง (APT ส่วนใหญ่ยังไม่ล้างตอน N คำสั่งแรก) → yes
    # ต่ำทุกคลาสเพื่อให้ absence เกือบเป็นกลาง (0.75/0.92/0.95 ใกล้กัน) presence ต่างชัด (0.25:0.05=5:1)
    "cleanup_antiforensics": {
        "Bot":          {"yes": 0.05, "no": 0.95},
        "ScriptKiddie": {"yes": 0.08, "no": 0.92},
        "APT":          {"yes": 0.25, "no": 0.75},
    },
    # targeted-enum: targeted(เจาะจง=APT) / mass(กราด=SK) / none. ⚠️ ทับ command_sophistication
    # (design §1.8) → spread ตั้งใจ "เบากว่า" (targeted APT:SK = 0.55:0.15 ≈ 3.7:1 ต่ำกว่า
    # command_sophistication ที่ 0.65:0.10) — P9 rebalance รวมทีเดียว
    "targeted_enum": {
        "Bot":          {"targeted": 0.05, "mass": 0.30, "none": 0.65},
        "ScriptKiddie": {"targeted": 0.15, "mass": 0.55, "none": 0.30},
        "APT":          {"targeted": 0.55, "mass": 0.20, "none": 0.25},
    },
    # P7 (2026-09-19) attack_breadth = จำนวน advanced ATT&CK tactic (Cred Access/PrivEsc/Defense
    # Evasion/Persistence/Collection): narrow(0)/moderate(1)/broad(≥2). ⚠️ ทับ targeted_enum/cleanup/
    # anti_hp (design §1.8) → spread เบา (broad APT:SK = 0.45:0.15 = 3:1). structural early signal
    "attack_breadth": {
        "Bot":          {"narrow": 0.80, "moderate": 0.15, "broad": 0.05},
        "ScriptKiddie": {"narrow": 0.55, "moderate": 0.30, "broad": 0.15},
        "APT":          {"narrow": 0.25, "moderate": 0.30, "broad": 0.45},
    },
    "depth_bucket": {
        "Bot":          {"shallow": 0.80, "mid": 0.15, "deep": 0.05},
        "ScriptKiddie": {"shallow": 0.35, "mid": 0.45, "deep": 0.20},
        "APT":          {"shallow": 0.10, "mid": 0.35, "deep": 0.55},
    },
    # เพิ่ม 2026-09-12 (Work Item 4b) — provisional, ไม่มี citation รองรับ ดู _pace_bucket()
    # docstring: spread แคบกว่าสัญญาณอื่นทุกตัวโดยตั้งใจ (ไม่มั่นใจ) ScriptKiddie ตั้งกลางๆ ตรงๆ
    # (ไม่รู้ทิศทางจริง) ต้อง verify ด้วย self-play re-eval ก่อนเชื่อว่าช่วย SK/APT จริง
    "pace_bucket": {
        "Bot":          {"bursty": 0.75, "measured": 0.15, "unknown": 0.10},
        "ScriptKiddie": {"bursty": 0.40, "measured": 0.40, "unknown": 0.20},
        "APT":          {"bursty": 0.25, "measured": 0.55, "unknown": 0.20},
    },
}

# prior เริ่มต้น — base rate จริงเอียงไปทางบอท แต่ตั้งกลางๆ ได้ (ปรับได้, ไม่จูนจาก test set)
DEFAULT_PRIOR = {"Bot": 0.50, "ScriptKiddie": 0.25, "APT": 0.25}

_EPS = 0.01  # smoothing สำหรับค่า/คลาสที่ไม่อยู่ในตาราง

# ===========================================================================
# P9 (2026-09-19) SIGNAL_WEIGHTS — weighted (tempered) naive Bayes แก้ double-count
# ===========================================================================
# ปัญหา: naive Bayes สมมติ signal อิสระ แต่ axis-B หลายตัว "อ่าน command stream เดียวกัน" และ
# correlate หนัก (เช่น `sudo -l` จุด command_sophistication=targeted + targeted_enum=targeted +
# attack_breadth PrivEsc พร้อมกัน) → คูณ likelihood เหมือนเป็นหลักฐานอิสระ 3 ชิ้น = posterior เฟ้อ
# เข้า APT เกินจริง (design §1.8). แก้: ยกกำลัง likelihood ด้วย w_s ∈ (0,1] → `w_s · log(lik)` ในผลรวม
# log-space (= attribute-weighted / tempered NB, เทคนิคมาตรฐาน). แยก "ความ discriminative (likelihood
# เดิม ไม่แตะ)" ออกจาก "correlation discount (weight)".
# **ตั้งจาก design (correlation-aware) ไม่ fit จาก test set (§7 honesty) — จูนต่อได้ที่ P10 ด้วย self-play**
#
# หลักการตั้ง:
#  - axis A (client/HASSH, credential, ip_reputation, timing) = คนละ data channel (bytes HASSH,
#    login cred, IP DB, inter-cmd timing) → correlate ต่ำ → weight เต็ม 1.0
#  - axis B กลุ่ม "อ่านคำสั่งชุดเดียวกัน" → discount: command_sophistication เป็นหลัก (honeypot-specific,
#    จูนสุด) เก็บ weight สูงสุดในกลุ่ม, ตัวที่ทับมัน (targeted_enum/attack_breadth) ได้ต่ำ, ตัวที่
#    "พฤติกรรมต่างจริง" (cleanup=ล้าง log, anti_hp=probe VM) ได้กลางๆ
#  - pace/error = provisional/อ้อม → เบาอยู่แล้ว
SIGNAL_WEIGHTS: dict[str, float] = {
    # --- axis A: คนละ data channel, correlate ต่ำ → เต็ม ---
    "client_family": 1.0,
    "credential_source": 1.0,
    "ip_reputation": 1.0,
    "timing_regularity": 1.0,
    # --- axis B command-derived (correlate — อ่านคำสั่งชุดเดียวกัน) → discount ---
    "command_sophistication": 0.7,   # หลัก honeypot-specific จูนสุด → สูงสุดในกลุ่ม
    "targeted_enum": 0.3,            # ทับ command_sophistication มาก → ต่ำ
    "attack_breadth": 0.3,          # สรุปหลาย tactic (ทับ targeted/cleanup/anti_hp) → ต่ำ
    "cleanup_antiforensics": 0.5,   # พฤติกรรมต่างจริง (ล้าง log) → กลาง
    "anti_honeypot_probe": 0.6,     # พฤติกรรมต่างจริง (probe VM) สัญญาณเดิมแข็ง → กลางค่อนสูง
    # --- axis B behavioral (ทับน้อยกว่า) ---
    "chaining": 0.6,
    "repetition": 0.6,
    "error_bucket": 0.5,            # อ้อม (general-expertise ไม่ใช่ attacker-measured) → เบา
    "pace_bucket": 0.4,             # provisional ไม่มี citation → เบาสุด
    # --- offline only (use_depth) ---
    "depth_bucket": 0.6,
}


class BayesianClassifier:
    def __init__(self, prior: dict | None = None, use_depth: bool = False):
        self.prior = dict(prior or DEFAULT_PRIOR)
        self.use_depth = use_depth  # ดู HeuristicProfiler — depth เป็น late signal, ปิดตอน real-time

    @staticmethod
    def _lik(signal: str, value: str, cls: str) -> float:
        table = LIKELIHOODS.get(signal, {}).get(cls, {})
        return table.get(value, _EPS)

    def _evidence(self, sig: dict) -> dict[str, str]:
        """แปลง signal dict -> ค่าที่ใช้เป็น evidence (discretize ตัวเลข)"""
        ev = {
            "client_family": sig["client_family"],
            "credential_source": sig["credential_source"],
            "timing_regularity": sig["timing_regularity"],
            "ip_reputation": sig["ip_reputation"],
            "command_sophistication": sig["command_sophistication"],
            "chaining": sig.get("chaining", "none"),
            "repetition": sig.get("repetition", "low"),
            "anti_honeypot_probe": sig.get("anti_honeypot_probe", "no"),
            "cleanup_antiforensics": sig.get("cleanup_antiforensics", "no"),  # P6
            "targeted_enum": sig.get("targeted_enum", "none"),                # P6
            "attack_breadth": sig.get("attack_breadth", "narrow"),            # P7
            "error_bucket": _error_bucket(sig["error_rate"]),
            "pace_bucket": _pace_bucket(sig.get("commands_per_minute")),
        }
        if self.use_depth:
            ev["depth_bucket"] = _depth_bucket(sig["kill_chain_depth"])
        return ev

    def posterior(self, sig: dict) -> dict[str, float]:
        """คืน P(type | signals) แบบ normalize แล้ว (weighted/tempered naive Bayes, log-space).
        P9 (2026-09-19): คูณ log-likelihood ด้วย SIGNAL_WEIGHTS[signal] (default 1.0) เพื่อ discount
        signal ที่ correlate กัน (อ่านคำสั่งชุดเดียวกัน) กัน double-count — ดู SIGNAL_WEIGHTS docstring"""
        ev = self._evidence(sig)
        logp = {}
        for cls in CLASSES:
            lp = math.log(max(self.prior.get(cls, _EPS), _EPS))
            for signal, value in ev.items():
                lp += SIGNAL_WEIGHTS.get(signal, 1.0) * math.log(self._lik(signal, value, cls))
            logp[cls] = lp
        m = max(logp.values())
        exp = {c: math.exp(lp - m) for c, lp in logp.items()}
        z = sum(exp.values())
        return {c: exp[c] / z for c in CLASSES}

    def classify(self, sig: dict) -> str:
        post = self.posterior(sig)
        return max(post, key=post.get)

    def classify_with_confidence(self, sig: dict) -> tuple[str, float, dict]:
        post = self.posterior(sig)
        label = max(post, key=post.get)
        return label, post[label], post


# ===========================================================================
# self-test: archetype sessions (พิสูจน์ว่า logic map ถูก — ไม่ใช่การอ้าง accuracy)
# ===========================================================================
_ARCHETYPES = {
    "Bot": {
        "client_family": "automated", "credential_source": "default",
        "timing_regularity": "regular", "ip_reputation": "known-scanner",
        "command_sophistication": "script", "chaining": "none", "repetition": "low",
        "anti_honeypot_probe": "no", "error_rate": 0.0, "kill_chain_depth": 0,
        "commands_per_minute": 60.0,  # เพิ่ม 2026-09-12 (Work Item 4b) — สคริปต์ยิงติดกันเร็วมาก
        "cleanup_antiforensics": "no", "targeted_enum": "none",  # P6
        "attack_breadth": "narrow",  # P7 — bot แตะแต่ commodity tactic
    },
    "ScriptKiddie": {
        "client_family": "interactive", "credential_source": "default",
        "timing_regularity": "irregular", "ip_reputation": "repeat",
        "command_sophistication": "generic-payload", "chaining": "none", "repetition": "high",
        "anti_honeypot_probe": "no", "error_rate": 0.4, "kill_chain_depth": 2,
        "commands_per_minute": 8.0,
        "cleanup_antiforensics": "no", "targeted_enum": "mass",  # P6 — กราดเก็บกว้าง
        "attack_breadth": "narrow",  # P7 — download+discovery ล้วน commodity
    },
    "APT": {
        "client_family": "interactive", "credential_source": "targeted",
        "timing_regularity": "irregular", "ip_reputation": "new-or-clean",
        "command_sophistication": "targeted", "chaining": "fluent", "repetition": "low",
        "anti_honeypot_probe": "yes", "error_rate": 0.0, "kill_chain_depth": 5,
        "commands_per_minute": 2.0,
        "cleanup_antiforensics": "yes", "targeted_enum": "targeted",  # P6 — เจาะจง+ล้างร่องรอย
        "attack_breadth": "broad",  # P7 — หลาย advanced tactic (cred/privesc/evasion)
    },
}


def _self_test() -> None:
    h, b = HeuristicProfiler(), BayesianClassifier()
    print("archetype        heuristic     bayesian (confidence)   posterior")
    ok = 0
    for expected, sig in _ARCHETYPES.items():
        hl = h.classify(sig)
        bl, conf, post = b.classify_with_confidence(sig)
        ok += (hl == expected) + (bl == expected)
        ps = {k: round(v, 2) for k, v in post.items()}
        print(f"{expected:14s}   {hl:12s}  {bl:12s} ({conf:.2f})   {ps}")
    print(f"\ncorrect: {ok}/6 (heuristic+bayesian บน 3 archetype)")


if __name__ == "__main__":
    _self_test()
