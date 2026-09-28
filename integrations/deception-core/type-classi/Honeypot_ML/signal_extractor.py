"""
signal_extractor.py — สกัด "สัญญาณ" ระดับ session จาก Cowrie log สำหรับจำแนกประเภท attacker
(Bot / ScriptKiddie / APT). ใช้ร่วมกันทั้ง 2 วิธี: heuristic baseline และ Bayesian (proposed).

ที่มา/เหตุผลของแต่ละสัญญาณ (อ้างอิงงานวิจัย — ดู ~/.claude/plans/attacker-cheeky-gosling.md):
  แกน A (bot ↔ คน):
    - client_family      HASSH / SSH client string (Salesforce HASSH): lib อัตโนมัติ vs client โต้ตอบ
    - credential_source  patent US11689568: default-pass = bot, targeted/stolen = คน
    - timing_regularity  IEEE 8757534: bot จังหวะสม่ำเสมอ (~4s), คนไม่สม่ำเสมอ
    - ip_reputation      #7 (local-history fallback; AbuseIPDB ถ้ามีสิทธิ์) — mass-scanner = bot
  แกน B (kiddie ↔ APT, เฉพาะพวกที่เป็นคน):
    - error_rate            IEEE 8757534: คนพิมพ์ผิด/not-found; โปรพลาดน้อย
    - command_sophistication patent US11689568 / arXiv 2006.01849: script vs generic-payload vs targeted
    - kill_chain_depth       arXiv 2101.02102 / 2006.01849: APT เดิน kill-chain ลึกเป็นระบบ

**Single source of truth (CLAUDE.md §5):** reuse `SessionPhaseTracker`/`predict_command_phase`
จาก colab_upload/3_serve/predict_phase_rules.py — ไม่พิมพ์ logic phase ซ้ำ

รันเป็นสคริปต์: `python signal_extractor.py <cowrie.json> [--limit N]`
"""

from __future__ import annotations

import json
import os
import statistics
import sys
from collections import defaultdict
from datetime import datetime

# --- reuse phase tracker ตัวจริง (single source of truth) ---
_HERE = os.path.dirname(os.path.abspath(__file__))
_SERVE = os.path.normpath(os.path.join(_HERE, "..", "..", "colab_upload", "3_serve"))
if _SERVE not in sys.path:
    sys.path.insert(0, _SERVE)
from predict_phase_rules import SessionPhaseTracker, predict_command_phase  # noqa: E402


# ---------------------------------------------------------------------------
# pools / signatures (มีที่มาจากพฤติกรรมจริงที่สังเกตบน Pi + งานวิจัย)
# ---------------------------------------------------------------------------
# credential ที่เป็น default/brute ทั่วไป (patent US11689568: default-pass = bot)
DEFAULT_CREDS = {
    ("root", "root"), ("root", "admin"), ("root", "password"), ("root", "123456"),
    ("root", "1234"), ("root", ""), ("admin", "admin"), ("admin", "password"),
    ("admin", "1234"), ("admin", "123456"), ("user", "user"), ("test", "test"),
    ("ubuntu", "ubuntu"), ("pi", "raspberry"), ("oracle", "oracle"), ("postgres", "postgres"),
}
# username ที่เป็น default ล้วน (ไม่ต้องดู password) — bot brute list ทั่วไป
DEFAULT_USERS = {"root", "admin", "user", "test", "ubuntu", "guest", "oracle", "postgres", "pi"}

# SSH client string ของ automation framework (HASSH: lib อัตโนมัติ)
AUTOMATED_CLIENT_MARKERS = ("go", "paramiko", "libssh", "python", "golang", "renci", "putty_release_0.8")
# client โต้ตอบของคนจริง
INTERACTIVE_CLIENT_MARKERS = ("openssh", "putty")

# คำสั่ง fingerprint แบบสคริปต์บอท (สังเกตจริงบน Pi: uname -s -v -n -r -m, export PATH=...)
BOT_FINGERPRINT_CMDS = (
    "uname -s -v -n -r -m",
    "export path=",
    "echo xsec",
    "cat /proc/cpuinfo",
    "/gweerwe323",
)
# payload สำเร็จรูปแบบ script kiddie (ก็อปมาวาง)
GENERIC_PAYLOAD_MARKERS = (
    "wget ", "curl ", "chmod +x", "busybox", "; sh", "| sh", "tftp", "./x", "nc -",
)
# คำสั่งเจาะจงมีเทคนิค (targeted — APT-ish)
TARGETED_MARKERS = (
    "pg_dump", "select ", "\\dt", "psql", "sudo -l", "cat /etc/shadow", "find / -perm",
    "getcap", "crontab -l", ".pgpass", "odoo.conf", "pg_hba.conf",
)

# anti-honeypot / anti-VM probing — มืออาชีพเช็คว่าตัวเองอยู่ใน honeypot/VM ไหม
# ที่มา: งานวิจัย skill-level ("sophisticated attackers begin by probing the environment for
# signs of synthetic infrastructure") — kiddie ไม่ทำ APT ทำ (ตัวแยกแข็ง)
# หมายเหตุ: ไม่ใส่ /proc/cpuinfo (บอทขุดเหมืองก็อ่าน = กำกวม) ใช้เฉพาะคำสั่งเช็ค VM/sandbox ตรงๆ
ANTI_HP_MARKERS = (
    "systemd-detect-virt", "dmidecode", "virt-what", "/proc/1/cgroup", "/sys/class/dmi",
    "lscpu", "dmesg", "hypervisor", "vmware", "virtualbox", "qemu", "/proc/scsi/scsi",
    "lspci", "cat /sys/class/dmi/id/product_name",
)

# --- P6 (2026-09-19): สัญญาณแกน B ใหม่ 2 ตัว (design §1.7② / trackB_classifier_design) ---
# cleanup / anti-forensics — ลบร่องรอย = APT tell แข็ง (kiddie/bot แทบไม่ทำ). มักมา "ช้า" (หลัง
# recon) จึงตอน real-time N คำสั่งแรกอาจไม่ค่อยเจอ — เมื่อเจอถึงเป็นหลักฐานหนักฝั่ง APT
# ที่มา: MITRE ATT&CK T1070 (Indicator Removal) / T1562 (Impair Defenses) — พฤติกรรมล้างประวัติ/log
# เลือก marker ที่ "เจาะจงการลบร่องรอย" (กัน false positive จากคำสั่งทั่วไป): wtmp/lastlog/auth.log
# เป็น log ตรวจสอบ session โดยเฉพาะ, .bash_history / HISTFILE เป็นประวัติ shell ตรงๆ
CLEANUP_ANTIFORENSICS_MARKERS = (
    "history -c", "history -w", "set +o history", "unset histfile", "histfile=",
    "histsize=0", "histfilesize=0", ".bash_history", "shred ", "truncate -s0",
    "truncate -s 0", "/var/log/wtmp", "/var/log/lastlog", "/var/log/auth.log",
    "/var/log/secure", "/var/log/btmp", "rm -rf /var/log", "rm /var/log", "> /var/log/",
)

# targeted-enum — แยก "สำรวจแบบเจาะจง (privesc/secret เฉพาะจุด)" = APT ออกจาก "กราดเก็บกว้าง
# (mass-grab)" = ScriptKiddie. ต่างจาก command_sophistication ที่แค่บอก targeted/generic —
# ตัวนี้แยก "ความแม่นของการ enumerate" ระหว่างคนสองระดับ (มติ design §1.7②)
# ⚠️ double-count (design §1.8): marker บางตัวทับ TARGETED_MARKERS (sudo -l, find -perm, getcap,
# .pgpass) → likelihood ใน classifier.py ตั้ง spread "เบากว่า" command_sophistication โดยตั้งใจ
# (P9 จะ rebalance รวม) — ที่นี่แค่สกัดค่า
TARGETED_ENUM_MARKERS = (
    "sudo -l", "find / -perm", "find / -type f -perm", "-perm -4000", "-perm -u=s",
    "getcap", "cat /etc/sudoers", "/etc/sudoers.d", ".pgpass", "id_rsa", ".ssh/id",
    ".aws/credentials", ".env", "crontab -l", "cat /etc/shadow", "getent shadow",
    "linpeas", "linenum", "pspy",
)
# mass-grab — กราดเก็บกว้าง ไม่เจาะจง (kiddie): อ่านไฟล์ระบบทั่วไป/ดึงเครื่องมือมั่ว
MASS_GRAB_MARKERS = (
    "cat /etc/passwd", "cat /etc/group", "cat /etc/hosts", "cat /etc/os-release",
    "cat /etc/issue", "uname -a", "cat /proc/cpuinfo", "cat /proc/meminfo", "w\n", "who\n",
    "last\n", "ls -la /", "ls /home", "cat /etc/*release",
)


def _parse_ts(ts: str) -> float | None:
    """cowrie timestamp -> epoch seconds (ISO8601, มี/ไม่มี Z)"""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 1. โหลด cowrie.json แล้วจัดกลุ่มตาม session
# ---------------------------------------------------------------------------
def load_sessions(path: str) -> dict[str, dict]:
    """คืน {session_id: {commands:[(ts,input)], logins:[(user,pass)], client, kex, src_ip,
    connect_ts, close_duration}}"""
    sess: dict[str, dict] = defaultdict(lambda: {
        "commands": [], "logins": [], "client": None, "kex": None,
        "src_ip": None, "connect_ts": None, "close_duration": None, "n_failed_cmd": 0,
    })
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            sid = d.get("session")
            if not sid:
                continue
            e = d.get("eventid", "")
            s = sess[sid]
            if d.get("src_ip") and not s["src_ip"]:
                s["src_ip"] = d["src_ip"]
            if e == "cowrie.command.input":
                s["commands"].append((_parse_ts(d.get("timestamp")), d.get("input", "")))
            elif e == "cowrie.command.failed":
                s["n_failed_cmd"] += 1
            elif e == "cowrie.login.success":
                s["logins"].append((d.get("username"), d.get("password")))
            elif e == "cowrie.login.failed":
                s["logins"].append((d.get("username"), d.get("password")))
            elif e == "cowrie.client.version":
                s["client"] = d.get("version")
            elif e == "cowrie.client.kex":
                s["kex"] = d.get("hassh") or d.get("hasshAlgorithms") or "present"
            elif e == "cowrie.session.connect":
                s["connect_ts"] = _parse_ts(d.get("timestamp"))
            elif e == "cowrie.session.closed":
                s["close_duration"] = d.get("duration")
    return dict(sess)


# ---------------------------------------------------------------------------
# 2. per-session signal computation
# ---------------------------------------------------------------------------
def _client_family(client: str | None) -> str:
    if not client:
        return "unknown"
    c = client.lower()
    if any(m in c for m in AUTOMATED_CLIENT_MARKERS):
        return "automated"
    if any(m in c for m in INTERACTIVE_CLIENT_MARKERS):
        return "interactive"
    return "unknown"


def _credential_source(logins: list) -> str:
    """default / targeted / unknown.
    หมายเหตุ (เจอจริงบน Pi 2026-09-07): Cowrie เปิด privacy filter redact user/pass เป็น
    '[REDACTED]' → คำนวณ default-vs-targeted จาก log จริงไม่ได้ ต้องคืน 'unknown' (ห้ามตกไปเป็น
    'targeted' เพราะจะดันบอทให้ดูเหมือน APT). สำหรับ self-play data ที่เราสร้างเอง creds ไม่ถูก
    redact สัญญาณนี้ทำงานปกติ."""
    if not logins:
        return "unknown"
    saw_real = False
    for user, pw in logins:
        u = (user or "").strip().lower()
        p = (pw or "").strip()
        if "redact" in u or "redact" in p.lower():
            continue  # ค่าโดน redact — ข้าม
        saw_real = True
        if (u, p) in DEFAULT_CREDS or u in DEFAULT_USERS:
            return "default"
    return "targeted" if saw_real else "unknown"


def _timing(commands: list, duration) -> tuple[str, float]:
    """คืน (timing_regularity, req_rate_per_min). regularity: regular/irregular/unknown
    IEEE 8757534: bot delay สม่ำเสมอ ~4s; req_rate ≤10/min = human-ish"""
    ts = [t for t, _ in commands if t is not None]
    n = len(commands)
    # duration จาก session.closed อาจมาเป็น str -> coerce เป็น float ก่อนใช้
    try:
        duration = float(duration) if duration is not None else None
    except (TypeError, ValueError):
        duration = None
    # req_rate
    if duration and duration > 0:
        req_rate = n / (duration / 60.0)
    elif len(ts) >= 2 and (ts[-1] - ts[0]) > 0:
        req_rate = n / ((ts[-1] - ts[0]) / 60.0)
    else:
        req_rate = float(n)  # กระจุกในวินาทีเดียว = เร็วมาก
    # regularity จาก coefficient of variation ของ gap
    gaps = [b - a for a, b in zip(ts, ts[1:]) if b - a >= 0]
    if len(gaps) < 2:
        return "unknown", req_rate
    mean = statistics.mean(gaps)
    if mean <= 0:
        return "regular", req_rate  # ยิงพร้อมกันหมด = สคริปต์
    cv = statistics.pstdev(gaps) / mean
    return ("regular" if cv < 0.35 else "irregular"), req_rate


def _command_sophistication(commands: list) -> str:
    """script (fingerprint บอท) / generic-payload (ก็อป) / targeted (เจาะจง) / minimal"""
    if not commands:
        return "minimal"
    joined = " \n ".join((c or "").lower() for _, c in commands)
    if any(m in joined for m in TARGETED_MARKERS):
        return "targeted"
    if any(joined.strip().startswith(sig) or sig in joined for sig in BOT_FINGERPRINT_CMDS):
        return "script"
    if any(m in joined for m in GENERIC_PAYLOAD_MARKERS):
        return "generic-payload"
    return "minimal"


def _chaining(commands: list) -> str:
    """สัดส่วนคำสั่งที่ร้อยหลายอันในบรรทัดเดียว (';' หรือ '&&') = ความคล่อง (APT-ish)
    ที่มา: มือโปรทำงานคล่อง ร้อยคำสั่ง; มือใหม่พิมพ์ทีละอัน (general expertise)"""
    if not commands:
        return "none"
    chained = sum(1 for _, c in commands if c and (";" in c or "&&" in c))
    return "fluent" if chained / len(commands) >= 0.3 else "none"


def _repetition(commands: list) -> str:
    """สัดส่วนคำสั่งซ้ำ = ความลังเล/มั่ว (kiddie-ish). ที่มา: มือใหม่ทำซ้ำ วกวน"""
    texts = [(c or "").strip() for _, c in commands]
    if not texts:
        return "low"
    rep = 1 - len(set(texts)) / len(texts)
    return "high" if rep >= 0.3 else "low"


def _anti_honeypot(commands: list) -> str:
    """เช็คว่า attacker probe หา honeypot/VM ไหม = สัญญาณ APT แข็ง (kiddie ไม่ทำ)"""
    joined = " \n ".join((c or "").lower() for _, c in commands)
    return "yes" if any(m in joined for m in ANTI_HP_MARKERS) else "no"


def _cleanup_antiforensics(commands: list) -> str:
    """P6: ล้างประวัติ/log = APT tell แข็ง (MITRE T1070/T1562). yes/no.
    มักมาช้า (หลัง recon) → real-time N คำสั่งแรกอาจไม่เจอ; เมื่อเจอ = หลักฐานหนักฝั่ง APT"""
    joined = " \n ".join((c or "").lower() for _, c in commands)
    return "yes" if any(m in joined for m in CLEANUP_ANTIFORENSICS_MARKERS) else "no"


def _targeted_enum(commands: list) -> str:
    """P6: แยกความแม่นของการ enumerate — targeted (เจาะจง privesc/secret = APT) /
    mass (กราดเก็บกว้าง = ScriptKiddie) / none. targeted ชนะ mass ถ้าเจอทั้งคู่ (สัญญาณ
    เจาะจงเป็นตัวบ่งชี้ skill ที่หนักกว่า). ⚠️ ทับ command_sophistication บางส่วน → classifier
    ตั้ง likelihood เบากว่าโดยตั้งใจ (design §1.8, P9 rebalance)"""
    joined = " \n ".join((c or "").lower() for _, c in commands)
    if any(m in joined for m in TARGETED_ENUM_MARKERS):
        return "targeted"
    if any(m in joined for m in MASS_GRAB_MARKERS):
        return "mass"
    return "none"


def ip_reputation_bucket(seen_count: int) -> str:
    """แปลงจำนวนครั้งที่เคยเห็น src_ip (local-history) เป็น bucket — single source of truth
    ใช้ทั้งใน compute_signals และ core adapter (CLAUDE.md §5)"""
    if seen_count >= 5:
        return "known-scanner"
    if seen_count >= 2:
        return "repeat"
    return "new-or-clean"


def _kill_chain_depth(commands: list) -> tuple[int, int]:
    """reuse SessionPhaseTracker: คืน (furthest_phase_idx 0..6, n_distinct_attack_phases)"""
    tracker = SessionPhaseTracker()
    reached = set()
    for _, cmd in commands:
        if not cmd:
            continue
        tracker.update(cmd)
        ph, _ = predict_command_phase(cmd)
        if ph in SessionPhaseTracker.PHASE_ORDER:
            reached.add(ph)
    try:
        idx = SessionPhaseTracker.PHASE_ORDER.index(tracker.current_phase)
    except ValueError:
        idx = 0
    return idx, len(reached)


def compute_signals(sid: str, s: dict, ip_history: dict | None = None,
                     n_first: int | None = None) -> dict:
    """แปลง 1 session -> dict ของสัญญาณ (+ meta) — ค่าออกจริงทุกตัว ไม่มี hardcode

    n_first: ถ้าตั้ง = คิดสัญญาณจาก "N คำสั่งแรก" เท่านั้น (จำลองจุดตัดสิน real-time ที่ต้องฟันธง
    เร็วเพื่อส่ง type ให้ชั้นเตรียมไฟล์ล่วงหน้า — มติผู้ใช้ 2026-09-07). ค่า default = ทั้ง session
    (ใช้สำหรับวิเคราะห์ offline)"""
    commands = s["commands"][:n_first] if n_first else s["commands"]
    # lazy import: attack_mapping reuse marker pool จากไฟล์นี้ → import ตรงนี้เลี่ยง circular (P7)
    from attack_mapping import attack_breadth
    regularity, req_rate = _timing(commands, s.get("close_duration"))
    depth_idx, n_phases = _kill_chain_depth(commands)
    n_cmd = len(commands)
    error_rate = (s["n_failed_cmd"] / n_cmd) if n_cmd else 0.0
    # ip_reputation: local-history fallback (จำนวนครั้งที่เคยเห็น src_ip นี้)
    ip = s.get("src_ip")
    seen = (ip_history or {}).get(ip, 0)
    ip_rep = ip_reputation_bucket(seen)
    return {
        "session_id": sid,
        "src_ip": ip,
        "n_commands": n_cmd,
        # แกน A
        "client_family": _client_family(s.get("client")),
        "credential_source": _credential_source(s.get("logins", [])),
        "timing_regularity": regularity,
        "req_rate_per_min": round(req_rate, 3),
        "ip_reputation": ip_rep,
        "ip_seen_count": seen,
        # แกน B
        "error_rate": round(error_rate, 3),
        "command_sophistication": _command_sophistication(commands),
        "chaining": _chaining(commands),
        "repetition": _repetition(commands),
        "anti_honeypot_probe": _anti_honeypot(commands),
        "cleanup_antiforensics": _cleanup_antiforensics(commands),  # P6
        "targeted_enum": _targeted_enum(commands),                  # P6
        "attack_breadth": attack_breadth(commands),                 # P7 (ATT&CK advanced-tactic breadth)
        "kill_chain_depth": depth_idx,
        "n_attack_phases": n_phases,
    }


def extract_all(path: str) -> list[dict]:
    sessions = load_sessions(path)
    # ประวัติ IP: นับจำนวน session ต่อ src_ip ทั้งไฟล์ (local-history reputation)
    ip_history: dict[str, int] = defaultdict(int)
    for s in sessions.values():
        if s.get("src_ip"):
            ip_history[s["src_ip"]] += 1
    return [compute_signals(sid, s, ip_history) for sid, s in sessions.items()]


def main() -> None:
    if len(sys.argv) < 2:
        print("usage: python signal_extractor.py <cowrie.json> [--limit N]")
        sys.exit(1)
    path = sys.argv[1]
    limit = None
    if "--limit" in sys.argv:
        limit = int(sys.argv[sys.argv.index("--limit") + 1])
    rows = extract_all(path)
    # แสดงสรุป distribution ของแต่ละสัญญาณ (พิสูจน์ว่าออกค่าจริง ไม่ hardcode)
    from collections import Counter
    print(f"# sessions: {len(rows)}")
    for key in ("client_family", "credential_source", "timing_regularity",
                "command_sophistication", "ip_reputation", "kill_chain_depth"):
        c = Counter(r[key] for r in rows)
        print(f"{key:24s} {dict(c)}")
    print("\n# ตัวอย่าง session ที่มีคำสั่ง (n_commands>0):")
    shown = 0
    for r in rows:
        if r["n_commands"] > 0:
            print(json.dumps(r, ensure_ascii=False))
            shown += 1
            if limit and shown >= limit:
                break


if __name__ == "__main__":
    main()
