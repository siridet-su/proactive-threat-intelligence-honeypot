"""
login_decoy.py — Part 1 (2026-08-26): สร้าง decoy จริง (ไฟล์ + ตาราง DB) ทันทีหลัง attacker login
สำเร็จ ฝัง identity ของ attacker คนนั้น (IP/username/เวลา login) เรียกจาก
cowrie_patches/login_decoy.py (ฝั่ง Cowrie, thin client)

**สถาปัตยกรรม start+poll (เปลี่ยนจาก 1 คำขอค้างยาว 2026-08-26):** เดิมออกแบบเป็น POST เดียวค้าง
รอจนกว่า generate เสร็จ (~80-90 วินาที) แต่ verify จริงผ่าน SSH บน Pi แล้วเจอว่า connection ยาวขนาด
นั้นจากฝั่ง Cowrie (ผ่าน systemd hardened sandbox — `MemoryMax=256M`/`CPUQuota=50%`) โดน
`ConnectionLost` กลางทางซ้ำๆ ไม่ทราบสาเหตุแน่ชัด (ไม่เกิดกับ curl ธรรมดานอก sandbox) — แก้เป็น
`/v1/login_decoy/start` (คืนทันที, เริ่ม background thread) + `/v1/login_decoy/status` (poll ทุก
2-3 วิ) แทน ทุก HTTP call แต่ละครั้งสั้นมาก (<1 วิ) ไม่มีทางโดนปัญหา connection ยาวอีก — ผลลัพธ์
ปลายทางเหมือนเดิมทุกประการ (attacker เห็น prompt ทันที + คำสั่งแรกรอจนพร้อมถ้าจำเป็น — ดู
docs/reports/pi_part1_realfile_login_hook_2026-08-26.md)

target มาจาก schema ไฟล์เดิม (single source of truth — ไม่พิมพ์ path/ตารางซ้ำมือ ตาม CLAUDE.md §5):
- ไฟล์ bash: `vfs_schema_updated_2026-07-22.json` entries ที่ `real_editable == true`
- ตาราง psql: `psql_decoy_schema_part1_realdb.json` (ไฟล์เฉพาะ Part 1 — แทนที่
  `psql_decoy_schema.json`/schema `decoy` เดิม 6 ตารางที่ถูกลบไปแล้ว ดู
  docs/reports/pi_part1_realdb_cleanup_2026-08-26.md)

reuse ฟังก์ชัน generate ที่มีอยู่แล้วใน prefetch_worker.py (`_generate` สำหรับไฟล์, `_generate_decoy_rows`
+ `_ensure_decoy_table` + `_pg_connect` สำหรับตาราง DB) — ของกลุ่มนี้แก้บั๊กคุณภาพมาแล้วหลายรอบ
(กันโมเดลพ่นชื่อคอลัมน์ซ้ำ, กัน literal \\n crash hailo-ollama) ไม่เขียนใหม่ซ้ำ
"""

from __future__ import annotations

import base64
import datetime
import os
import random
import threading
import time

from prefetch_worker import (
    _VFS_SCHEMA_CANDIDATES,
    _ensure_decoy_table,
    _generate,
    _generate_decoy_rows,
    _load_json,
    _pg_connect,
)

import session_store
import config

_HERE = os.path.dirname(os.path.abspath(__file__))
_PSQL_PART1_CANDIDATES = [
    "/data/psql_decoy_schema_part1_realdb.json",
    os.path.join(_HERE, "psql_decoy_schema_part1_realdb.json"),
]
# เพิ่ม 2026-09-02 (roleplay_audit_remediation C1): ย้ายมาอ้างอิง config.py แทน hardcode "decoy" เอง
# (single source of truth ตาม CLAUDE.md §5 — เดิมพิมพ์ literal เดียวกันซ้ำใน phase_adaptive.py ด้วย)
_DECOY_SCHEMA_NAME = config.DECOY_SCHEMA_NAME

# tier/action ยังไม่รู้ตอน login (ยังไม่มีคำสั่งไหนเข้ามาเลย ทั้งคู่มาจากพฤติกรรมที่ยังไม่เกิดขึ้น) —
# ใช้ค่า default คงที่ตัวเดียว ไม่ variation แบบของเดิม (Part 2 ค่อยจัดการเรื่องปรับตาม action/phase)
_DECOY_TIER = 1
_DECOY_CONTENT_TYPE = "normal"

_bash_target_cache: list[dict] | None = None
_psql_target_cache: list[dict] | None = None


def _bash_real_editable_targets() -> list[dict]:
    global _bash_target_cache
    if _bash_target_cache is None:
        schema = _load_json(_VFS_SCHEMA_CANDIDATES)
        _bash_target_cache = [e for e in schema["filesystem"] if e.get("real_editable") is True]
    return _bash_target_cache


def _psql_part1_tables() -> list[dict]:
    global _psql_target_cache
    if _psql_target_cache is None:
        schema = _load_json(_PSQL_PART1_CANDIDATES)
        _psql_target_cache = schema["decoy_tables"]
    return _psql_target_cache


def _bash_fact(entry: dict, login_time: str) -> str:
    fact = f"department={entry.get('department')}, sensitivity={entry.get('sensitivity')}"
    if entry.get("style_hint"):
        fact += f". Style guide: {entry['style_hint']}"
    fact += f". The most recent activity/modification time should be consistent with {login_time}."
    return fact


def _psql_fact(table: dict) -> str:
    cols = ",".join(c for c in table.get("columns", []) if c != "id")
    fact = (f"department={table.get('maps_to_department')}, sensitivity={table.get('sensitivity')}, "
            f"columns={cols}")
    if table.get("style_hint"):
        fact += f". Style guide: {table['style_hint']}"
    return fact


# ============================================================================
# 2026-08-27 (content QC รอบ 2): field/ไฟล์ที่ format ตายตัวหรือลอง prompt ซ้ำแล้วโมเดล 1.5B ยังทำ
# ไม่ได้แม่นยำพอ (bank_account_masked ซ้ำชื่อคนทุกแถว, db_access_audit ประวัติเก่าเป็น 0 แถวบ้าง/
# SQL มั่วบ้าง, authorized_keys format พัง, crontab ค่า field ผิด syntax, .bash_history ปนภาษาอื่น)
# — ตัดสินใจ (มติผู้ใช้ 2026-08-27): เปลี่ยนเป็น generate แบบ deterministic/pool-based ในโค้ดแทน
# พึ่ง AI ล้วนๆ สำหรับจุดเหล่านี้ ไม่ใช่ปรับ prompt ต่อไปเรื่อยๆ — รับประกัน format ถูกต้อง 100%
# เร็วกว่า (ไม่ต้อง retry ผ่านโมเดล) เสีย "ความหลากหลายที่ AI คิดเองสด" ไปบางส่วนแลกกับความแน่นอน

_BANK_PREFIXES = ["KBANK", "SCB", "BBL", "KTB", "TMB", "GSB"]


def _gen_masked_bank_account() -> str:
    """เลขบัญชีธนาคารที่ mask บางส่วน — deterministic ไม่พึ่ง AI เลย กันปัญหาเดิม (โมเดลเอาชื่อ
    พนักงานมาใส่ซ้ำในคอลัมน์นี้ทุกแถว) แก้ไม่หายด้วย prompt มาแล้ว 2 รอบ"""
    style = random.choice([
        lambda: f"{random.choice(_BANK_PREFIXES)} XXX-X-{random.randint(1000, 9999)}-X",
        lambda: f"***-{random.randint(1000, 9999)}",
        lambda: f"XXX-XXX{random.randint(100, 999)}-{random.randint(0, 9)}",
    ])
    return style()


def _gen_authorized_keys_content(username: str) -> str:
    """SSH public key ปลอม — deterministic ไม่พึ่ง AI เลย (เดิม AI เคยพ่น placeholder 'AAAA...AAA'
    ค้าง/บรรทัดซ้ำ) สร้าง base64 blob สุ่มยาวสมจริง + comment user@host ปกติ

    แก้บั๊กจริง 2026-08-28 (blind audit): เดิม comment hardcode เป็น "sysadmin@..." ตายตัว ทั้งที่ไฟล์
    นี้จะไปอยู่ใน home ของ username ที่ attacker ใช้ login จริง (ไม่จำเป็นต้องเป็น sysadmin) — เปลี่ยน
    ไปใช้ username ที่ส่งเข้ามาแทน ให้ตรงกับเจ้าของไฟล์จริง"""
    blob = base64.b64encode(os.urandom(256)).decode("ascii")
    hosts = ["erp-db-01", "sysadmin-laptop", "backup-srv", "erp-db-01.internal"]
    return f"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ{blob} {username}@{random.choice(hosts)}\n"


_CRON_JOB_POOL = [
    "/usr/bin/pg_dump -U odoo -h localhost odoo_production | gzip > "
    "/var/backups/postgresql/odoo_production_$(date +%F).sql.gz",
    "find /var/log/odoo -name '*.log.*' -mtime +14 -delete",
    "/usr/bin/vacuumdb --all --analyze -q",
    "systemctl restart odoo >> /var/log/odoo/restart.log 2>&1",
    "rsync -a /var/backups/postgresql/ backup-srv:/mnt/backups/pi-erp/",
    "/home/sysadmin/scripts/backup_odoo.sh",
    "find /tmp -type f -mtime +3 -delete",
]


def _home_dir(username: str) -> str:
    """แปลง username -> home dir จริงตาม Linux convention — เพิ่ม 2026-09-02
    (roleplay_audit_remediation M1): เดิม _gen_crontab_content() ทำ f"/home/{username}/" ตรงๆ ไม่
    เช็คกรณี username == "root" (home จริงของ root คือ /root ไม่ใช่ /home/root — Linux ไม่มี
    /home/root เลย) ทำให้ crontab ของ attacker ที่ login เป็น root อ้าง path ที่ไม่มีอยู่จริง"""
    return "/root" if username == "root" else f"/home/{username}"


def _gen_crontab_content(username: str, login_time: str) -> str:
    """crontab -l ของ username นี้ — deterministic ไม่พึ่ง AI เลย (เดิม AI เคยใส่ค่านาที '60' ซึ่งผิด
    syntax cron จริง ต้อง 0-59) การันตี field ทุกตัวถูก syntax แน่นอน 100%

    แก้บั๊กจริง 2026-08-28 (blind audit): _CRON_JOB_POOL มี job หนึ่งอ้าง
    /home/sysadmin/scripts/backup_odoo.sh ตรงๆ — ถ้า attacker login ด้วย username อื่น path นี้จะไม่
    ตรงกับ home dir จริงของเขา (ไฟล์ scripts/backup_odoo.sh เป็นไฟล์เดิมของ persona ไม่ได้ generate
    ต่อ username แต่ crontab ควรอ้างอิงให้สอดคล้องกับ home dir ของคนที่ login) — แทนที่ "sysadmin"
    ด้วย username จริงในบรรทัด job ก่อนใช้

    แก้เพิ่ม 2026-09-02 (roleplay_audit_remediation M1): ใช้ `_home_dir()` แทน f"/home/{username}/"
    ตรงๆ กันกรณี root (ดู docstring `_home_dir`) — **เลือกทางแก้ (ก) จากรายงาน**: ตัดสินใจไม่ template
    path ของ backup_odoo.sh ตาม username เพราะไฟล์จริงอยู่ที่ /home/sysadmin/scripts/backup_odoo.sh
    ตำแหน่งเดียวตายตัว (ไม่ได้ generate ต่อ home ของผู้ login เหมือนไฟล์อื่น) — ถ้า template ตาม
    username จะยิ่งไม่ตรงกับไฟล์จริงสำหรับ user ที่ไม่ใช่ sysadmin (เดิมพังอยู่แล้ว การ "แก้ path" แบบ
    เดิมไม่ได้ช่วยอะไร) เปลี่ยนมาอ้าง path จริงตายตัวเสมอแทน ไม่ replace ตาม username สำหรับ job นี้

    แก้บั๊กจริง 2026-08-28 (ผู้ใช้เจอเอง — timezone): เดิมใช้ time.strftime() เรียกเวลาของตัวเอง ซึ่ง
    รันอยู่ใน container deception-core ที่เป็น UTC (Pi host จริงเป็น Asia/Bangkok +07) ทำให้
    "installed" comment ช้ากว่าเวลาจริง 7 ชม. เสมอ ทั้งที่ login_time ที่ถูกต้อง (Bangkok time, คำนวณ
    ฝั่ง cowrie บน host จริง) ถูกส่งเข้ามาเป็น parameter อยู่แล้วในทุกจุดอื่น — เปลี่ยนมาใช้ login_time
    แทน (single source of truth ตาม CLAUDE.md §5) ไม่พึ่ง clock ของ container เอง

    แก้เพิ่ม 2026-09-02 (roleplay_audit_remediation L5): เดิม "installed" = login_time เป๊ะ ทำให้ดูเหมือน
    crontab เพิ่งถูกติดตั้งตอนนี้เอง (production cron จริงติดตั้งไว้นานแล้วก่อนหน้า) — เปลี่ยนเป็นสุ่ม
    ย้อนหลังจาก login_time 30-400 วัน (คงที่ต่อ IP อยู่แล้วเพราะ caller เรียกฟังก์ชันนี้แค่ครั้งเดียวต่อ
    baseline ผ่าน `_resolve_static_bash_content()`)"""
    try:
        login_dt = datetime.datetime.strptime(login_time, "%Y-%m-%d %H:%M:%S")
        installed_dt = login_dt - datetime.timedelta(days=random.randint(30, 400))
        installed_str = installed_dt.strftime("%a %b %d %H:%M:%S %Y")
    except Exception:
        installed_str = time.strftime("%a %b %d %H:%M:%S %Y")  # fallback เฉพาะกรณี parse ไม่ได้
    lines = [
        "# DO NOT EDIT THIS FILE - edit the master and reinstall.",
        f"# (cron version -- installed {installed_str})",
    ]
    jobs = random.sample(_CRON_JOB_POOL, min(random.randint(2, 4), len(_CRON_JOB_POOL)))
    for job in jobs:
        if job == "/home/sysadmin/scripts/backup_odoo.sh":
            pass  # path จริงตายตัว (ดู docstring) -- ไม่ template ตาม username
        else:
            job = job.replace("/home/sysadmin/", f"{_home_dir(username)}/")
        minute = random.choice([0, 5, 10, 15, 30, 45])
        hour = random.choice(["*", str(random.randint(0, 23))])
        dow = random.choice(["*", "mon,thu", "sun", "mon,wed,fri,sun", "1-5"])
        lines.append(f"{minute} {hour} * * {dow} {job}")
    return "\n".join(lines) + "\n"


_BASH_HISTORY_EXTRA_POOL = [
    "whoami", "pwd", "ls -la", "cd ~", "history | tail -20", "sudo -i",
    "ping -c 3 8.8.8.8", "netstat -tlnp", "ps aux | grep odoo",
    "sudo journalctl -u odoo -n 50", "pg_dump -U odoo -h localhost odoo_production > /tmp/backup.sql",
    "sudo apt update", "sudo apt list --upgradable", "free -h", "uptime",
]


def _gen_bash_history_content(login_time: str, username: str) -> str:
    """.bash_history ของ sysadmin — pool-based (สุ่มเลือก+สลับลำดับจากคำสั่งจริงที่เตรียมไว้)
    แทน AI แต่งอิสระทั้งหมด (เดิม AI เคยปนคำสั่ง SQL/Python เข้ามาแทนคำสั่ง bash จริงหลายรอบ แก้ไม่
    หายด้วย prompt) ฐานข้อมูลคำสั่งอ้างอิงจาก static_contents.sysadmin_bash_history ของ schema เดิม
    (single source of truth ตาม CLAUDE.md ยังไม่พิมพ์ซ้ำมือ) + เสริมคำสั่งทั่วไปเพิ่มความหลากหลาย

    แก้บั๊กจริง 2026-08-28 (ผู้ใช้เจอเองตอนเทสมือด้วย username "eng"): pool มีบรรทัด
    "cd /home/sysadmin/scripts" ฝังอยู่ตรงๆ (จาก static_contents ของ schema) เดิมคืนดิบๆ ไม่แทนที่
    "sysadmin" ด้วย username จริง ทำให้ไม่ตรงกับ crontab/path อื่นที่ template ถูกต้องแล้ว (รอยรั่ว
    ให้ attacker สังเกตได้ว่าไฟล์นี้ไม่ได้เฉพาะเจาะจงกับ session ตัวเอง) — เพิ่ม username แล้ว replace
    เหมือนที่ _gen_crontab_content()/build_login_decoys() ทำอยู่แล้ว"""
    base_lines = []
    try:
        schema = _load_json(_VFS_SCHEMA_CANDIDATES)
        raw = schema.get("static_contents", {}).get("sysadmin_bash_history", "")
        base_lines = [ln for ln in raw.split("\n") if ln.strip()]
    except Exception:
        pass
    pool = list(dict.fromkeys(base_lines + _BASH_HISTORY_EXTRA_POOL))  # dedupe, keep order
    n = min(len(pool), random.randint(12, 18))
    chosen = random.sample(pool, n)
    random.shuffle(chosen)
    # แก้ 2026-09-02 (roleplay_audit_remediation M1 — จุดเดียวกับ _gen_crontab_content ที่รายงานเจอ):
    # ใช้ _home_dir() แทน f"/home/{username}/" ตรงๆ กันกรณี username=="root" ได้ "/home/root/scripts"
    # ที่ไม่มีจริงบน Linux (เหมือน bug เดิมของ crontab แต่จุดนี้รายงานไม่ได้เจอ เจอเองระหว่างไล่ path
    # ที่ใช้แพทเทิร์นเดียวกัน)
    chosen = [ln.replace("/home/sysadmin/", f"{_home_dir(username)}/") for ln in chosen]
    return "\n".join(chosen) + "\n"


_SQL_QUERY_POOL = [
    "SELECT * FROM res_partner WHERE id=42;",
    "SELECT login, active FROM res_users WHERE active=true;",
    "UPDATE ir_cron SET active=false WHERE id=7;",
    "SELECT COUNT(*) FROM account_move WHERE state='posted';",
    "SELECT * FROM sale_order WHERE state='sale' ORDER BY date_order DESC LIMIT 20;",
    "DELETE FROM ir_logging WHERE create_date < now() - interval '30 days';",
    "SELECT name, email FROM hr_employee WHERE active=true;",
    "UPDATE res_config_settings SET value='1' WHERE key='web.base.url';",
    "SELECT * FROM stock_move_line WHERE product_id=118;",
    "VACUUM ANALYZE account_move;",
]
_DB_AUDIT_USERNAME_POOL = ["admin", "odoo", "backup_svc", "reportuser"]


def _gen_db_access_audit_rows(cols: list[str], login_time: str, n: int = 6) -> list[list[str]]:
    """แถวประวัติเก่าของ db_access_audit — deterministic pool-based แทน AI ล้วนๆ (เดิม AI เคยตอบ
    query_text เป็นคำมั่วที่ไม่ใช่ SQL, หรือบางรอบไม่ตอบแถวมาเลยสักแถว, หรือใส่วันที่อนาคตผิด) —
    การันตีว่ามีแถวเสมอ, SQL ถูกต้องเสมอ, วันที่เป็นอดีตก่อน login_time เสมอ"""
    try:
        login_dt = datetime.datetime.strptime(login_time, "%Y-%m-%d %H:%M:%S")
    except Exception:
        login_dt = datetime.datetime.now()
    rows = []
    for _ in range(n):
        days_ago = random.randint(1, 45)
        ts = login_dt - datetime.timedelta(
            days=days_ago, hours=random.randint(0, 23), minutes=random.randint(0, 59)
        )
        mapping = {
            "accessed_by": random.choice(_DB_AUDIT_USERNAME_POOL),
            "source_ip": f"10.58.33.{random.randint(2, 250)}",
            "access_time": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "query_text": random.choice(_SQL_QUERY_POOL),
        }
        rows.append([mapping.get(c, "") for c in cols])
    return rows


def _resolve_static_bash_content(username: str, login_time: str, ip: str) -> dict[str, str]:
    """เพิ่ม 2026-08-31 (audit batch D, finding #1) — คืน content ของ 3 ไฟล์ที่ต้องคงที่ต่อ IP
    (`authorized_keys`/`crontab`/`.bash_history` baseline) แทนที่จะสุ่มใหม่ทุกครั้งที่ login เหมือน
    เดิม (root cause ของ audit finding #1 — reconnect จาก IP เดิมเจอ SSH key/cron job/bash history
    คนละชุดกันสิ้นเชิงทุกรอบ ทั้งที่ไม่มีใครแก้อะไรเลย)

    ถ้า IP นี้เคย login มาก่อนและยังไม่หมดอายุ (`session_store.get_login_decoy_baseline()` เจอ) ใช้
    ค่าเดิมซ้ำทั้งหมด — ถ้าเป็น IP ใหม่ (หรือหมดอายุไปแล้วตาม `cleanup.py::SESSION_TTL_S`) generate
    ครั้งเดียวด้วย generator แบบ pool-based เดิม (`_gen_*`) แล้วบันทึกไว้ให้ reconnect ครั้งถัดไปใช้ต่อ

    `.bash_history` เพิ่มคำสั่งจริงที่ attacker เคยพิมพ์ (`bash_history_log`, สะสมข้าม reconnect —
    เขียนที่ session close เท่านั้น ดู `session_store.append_bash_history_log()` /
    `/v1/login_decoy/record_history`) ต่อท้าย baseline เสมอ"""
    session_store.get_or_create_session(ip)  # ensure แถวมีอยู่ก่อน (single source of truth ของ
    # "สร้างแถว sessions ให้ ip นี้" — ไม่เขียน INSERT ซ้ำเองที่นี่ ตาม CLAUDE.md §5)
    existing = session_store.get_login_decoy_baseline(ip)
    if existing is not None:
        bash_history_baseline = existing["bash_history_baseline"]
        crontab_content = existing["crontab_content"]
        authorized_keys_content = existing["authorized_keys_content"]
        bash_history_log = existing["bash_history_log"]
    else:
        bash_history_baseline = _gen_bash_history_content(login_time, username)
        crontab_content = _gen_crontab_content(username, login_time)
        authorized_keys_content = _gen_authorized_keys_content(username)
        session_store.set_login_decoy_baseline(
            ip, bash_history_baseline, crontab_content, authorized_keys_content
        )
        bash_history_log = ""
    bash_history_content = (
        f"{bash_history_baseline}\n{bash_history_log}" if bash_history_log else bash_history_baseline
    )
    return {
        "authorized_keys": authorized_keys_content,
        "crontab": crontab_content,
        "bash_history": bash_history_content,
    }


def _build_bash_file_content(
    entry: dict, login_time: str, username: str, static_content: dict[str, str]
) -> str:
    """dispatch ไฟล์ bash แต่ละ target ไปยัง template generator เฉพาะทาง ถ้าเป็นเป้าหมายที่รู้จัก
    (authorized_keys/crontab/.bash_history) ไม่งั้น fallback ไป AI generate (`_generate()`) เหมือนเดิม
    เผื่อมี real_editable target อื่นเพิ่มในอนาคตที่ยังไม่มี template เฉพาะ

    แก้ 2026-08-31 (audit batch D): 3 ไฟล์ที่ต้องคงที่ต่อ IP รับ content ที่ resolve ไว้แล้วจาก
    `_resolve_static_bash_content()` (เรียกครั้งเดียวต่อ login ใน `_build_files_only()`) แทนที่จะ
    เรียก `_gen_*()` ตรงๆ ที่นี่เหมือนเดิม (ของเดิม generate ใหม่สุ่มทุกครั้งไม่มีเงื่อนไข)"""
    path = entry.get("path", "")
    if path.endswith(".ssh/authorized_keys"):
        return static_content["authorized_keys"]
    if "crontab" in path:
        return static_content["crontab"]
    if path.endswith(".bash_history"):
        return static_content["bash_history"]
    fact = _bash_fact(entry, login_time)
    return _generate(path, "bash", _DECOY_CONTENT_TYPE, _DECOY_TIER, fact, entry.get("type", "file"))


def _identity_row(cols: list[str], ip: str, username: str, login_time: str) -> list[str]:
    """แถวเดียวที่ตรงกับ session ปัจจุบันจริง — deterministic ไม่ผ่านโมเดล (identity ต้องแม่นยำ
    เป๊ะ ห้ามให้ AI เพี้ยน) ใช้เฉพาะตารางที่มี identity_fields ประกาศไว้ (db_access_audit)"""
    mapping = {
        "accessed_by": username,
        "source_ip": ip,
        "access_time": login_time,
        "query_text": "SELECT * FROM db_access_audit ORDER BY access_time DESC;",
    }
    return [mapping.get(c, "") for c in cols]


def _build_files_only(username: str, login_time: str, ip: str) -> dict[str, str]:
    """เพิ่ม 2026-08-28 — แยกออกมาจาก build_login_decoys() เดิม (ดู docstring ของฟังก์ชันนั้น) เพื่อ
    ให้ files พร้อมรายงานสถานะ "done" ได้ทันทีโดยไม่ต้องรอ DB (ซึ่งเรียก AI จริงและอาจ retry หลายรอบ
    ช้ากว่ามาก) — ผู้ใช้เจอเองว่า cat/crontab -l ยังช้าทั้งที่เนื้อหาไฟล์ deterministic ล้วนๆ ไม่ใช้ AI
    เลย รากปัญหาคือ readiness เดิมรวมไฟล์+DB เป็นสัญญาณเดียว (ดู docs/reports/
    pi_part1_audit_fixes_2026-08-28.md ส่วนที่ 8)

    แก้บั๊กจริง 2026-08-28 (blind audit): เดิม path ของแต่ละ target มาจาก schema ตรงๆ (literal
    "/home/sysadmin/...") ไม่ว่า attacker จะ login ด้วย username อะไรก็ตาม — login รับได้ทุก
    username (userdb.txt เป็น wildcard) แต่ไฟล์ไปโผล่แค่ home ของ "sysadmin" เท่านั้น ทำให้
    attacker ที่ login ด้วย username อื่น (เคสส่วนใหญ่ในโลกจริง) ไม่เห็นผลลัพธ์ของ Part 1 เลยสัก
    ไฟล์ — แทนที่ "sysadmin" ด้วย username จริงในทุก path ก่อนใช้ (mkfile() เดินสร้าง parent dir
    ให้เองอยู่แล้ว ไม่ต้องมี skeleton เดิมของ username นั้นมาก่อน)"""
    files: dict[str, str] = {}
    # เพิ่ม 2026-08-31 (audit batch D): resolve ครั้งเดียวต่อ login (ไม่ใช่ต่อไฟล์) — เช็ค/สร้าง
    # baseline คงที่ต่อ ip ของ 3 ไฟล์ authorized_keys/crontab/.bash_history ดู docstring ของ
    # _resolve_static_bash_content()
    static_content = _resolve_static_bash_content(username, login_time, ip)
    for entry in _bash_real_editable_targets():
        try:
            # แก้ 2026-09-02 (roleplay_audit_remediation M1 — root cause จริงของบั๊ก crontab/
            # bash_history ที่รายงานเจอ อยู่ตรงนี้): เดิม .replace("/sysadmin/", f"/{username}/")
            # ทำให้ username=="root" ได้ path "/home/root/..." ซึ่งไม่มีจริงบน Linux (home ของ root
            # คือ /root) — ใช้ _home_dir(username) แทนเพื่อ handle กรณี root ให้ถูก
            path = entry["path"].replace("/home/sysadmin/", f"{_home_dir(username)}/").replace(
                "crontabs/sysadmin", f"crontabs/{username}"
            )
            files[path] = _build_bash_file_content(entry, login_time, username, static_content)
        except Exception:
            continue  # ข้ามไฟล์นี้ไป — ไม่ทำให้ login ทั้ง session พัง
    return files


def _build_db_only(username: str, ip: str, login_time: str, session_id: str) -> list[str]:
    """เพิ่ม 2026-08-28 — แยกออกมาจาก build_login_decoys() เดิม (ดู _build_files_only() ด้านบน)
    ส่วนนี้ยังใช้ AI จริง (`_generate_decoy_rows()` สำหรับ payroll_export) และ retry ได้ถึง 4 รอบ —
    ช้ากว่า files มาก ตั้งใจแยกให้เป็น phase 2 ที่รอทีหลัง ไม่ปนกับ files phase อีกต่อไป"""
    db_tables: list[str] = []
    try:
        conn = _pg_connect()
        conn.autocommit = True
        cur = conn.cursor()
        # ล้างแถวของ session_id นี้ทิ้งก่อนเสมอ — เดิม session_id ผูกกับ IP (ผ่าน session_store.py)
        # ทำให้ IP เดิม login รอบใหม่ชนกับรอบเก่า (เจอบั๊กจริง 2026-08-28, ดู
        # docs/reports/pi_part1_audit_fixes_2026-08-28.md) ตอนนี้ session_id เป็น uuid สดใหม่ทุกครั้ง
        # ที่ /v1/login_decoy/start ถูกเรียก (ไม่ผูกกับ IP แล้ว — ดู core/app.py) เก็บ DELETE นี้ไว้
        # เป็นแค่ safety net เผื่อ id ชนกันโดยบังเอิญ (แทบเป็นไปไม่ได้กับ uuid) ไม่ใช่ workaround
        # หลักอีกต่อไป
        cleanup_session_decoys(session_id, conn=conn, pop_job=False)
        for t in _psql_part1_tables():
            table = t["table_name"]
            cols = [c for c in t.get("columns", []) if c != "id"]
            try:
                _ensure_decoy_table(cur, _DECOY_SCHEMA_NAME, table, cols, extra_cols=["session_id"])
                col_list = ", ".join(f'"{c}"' for c in cols)
                placeholders = ", ".join(["%s"] * (2 + len(cols)))
                if table == "db_access_audit":
                    # 2026-08-27: ประวัติเก่าเปลี่ยนเป็น deterministic pool แทน AI ล้วนๆ (ดู
                    # _gen_db_access_audit_rows -- แก้ปัญหา 0 แถว/SQL มั่ว/วันที่อนาคตที่ prompt
                    # แก้ไม่หายมาแล้ว 2 รอบ)
                    rows = _gen_db_access_audit_rows(cols, login_time)
                else:
                    rows = _generate_decoy_rows(
                        _psql_fact(t), cols, _DECOY_TIER, _DECOY_CONTENT_TYPE,
                        allow_sql=t.get("content_allows_sql", False),
                        dup_check_ignore_cols=(
                            {"bank_account_masked"} if table == "payroll_export" else None
                        ),
                        # เพิ่ม 2026-08-30 (ดู docs/reports/pi_gen_lock_payroll_rowcount_fix_2026-08-30.md):
                        # payroll_export เป็นตารางเดียวที่เหลือเรียก AI ตอน login (blocking) — ขอ 2
                        # แถวแทน 4 (default ของ _generate_decoy_rows) ลดเวลา generate ต่อครั้งเกือบ
                        # ครึ่ง (~18.7s -> ~9.6s, verify จริงบน Pi แล้ว) แก้คอขวดตอน login พร้อมกัน
                        # จาก IP เดียวกัน — ตารางอื่นในอนาคต (Part 2) ยังใช้ default 4 แถวตามเดิม
                        row_count=2 if table == "payroll_export" else 4,
                    )
                    if table == "payroll_export" and "bank_account_masked" in cols:
                        # 2026-08-27: bank_account_masked มักซ้ำกับ employee_name จากโมเดล --
                        # override หลัง generate เสมอ ไม่พึ่งความแม่นยำของ AI สำหรับคอลัมน์นี้
                        idx = cols.index("bank_account_masked")
                        rows = [list(r) for r in rows]
                        for r in rows:
                            r[idx] = _gen_masked_bank_account()
                next_id = 1
                for row in rows:
                    cur.execute(
                        f'INSERT INTO "{_DECOY_SCHEMA_NAME}"."{table}" '
                        f'(id, session_id, {col_list}) VALUES ({placeholders})',
                        [next_id, session_id, *row],
                    )
                    next_id += 1
                if "ip" in t.get("identity_fields", []):
                    id_row = _identity_row(cols, ip, username, login_time)
                    cur.execute(
                        f'INSERT INTO "{_DECOY_SCHEMA_NAME}"."{table}" '
                        f'(id, session_id, {col_list}) VALUES ({placeholders})',
                        [next_id, session_id, *id_row],
                    )
                db_tables.append(table)
            except Exception as e:
                # เพิ่ม 2026-08-28 — เดิมกลืน exception เงียบสนิท (ไม่มี log เลย) ทำให้ debug
                # บั๊กจริงยาก (เจอเองตอนแก้ keep_alive: ส่ง keep_alive ผิด type ไปหา hailo-ollama
                # ได้ 500 error, exception โดนกลืนตรงนี้เงียบๆ payroll_export ได้ 0 แถวทุกครั้งโดย
                # ไม่มีร่องรอยอะไรให้เห็นเลยจนต้องเช็ค DB ตรงๆ ถึงจะรู้) print() ธรรมดาพอ (stdout
                # ของ container ถูก docker logs จับอยู่แล้ว ไม่ต้องตั้ง logging module เพิ่ม)
                print(f"login_decoy: table {table} failed for session {session_id}: {e!r}")
                continue  # ข้ามตารางนี้ไป — ตารางอื่นยังทำต่อได้
        conn.close()
    except Exception as e:
        print(f"login_decoy: postgres connection failed for session {session_id}: {e!r}")
        # ต่อ Postgres ไม่ได้เลย — ไม่ทำให้ login พัง แค่ไม่มีตาราง DB ของ session นี้

    return db_tables


# --------------------------------------------------------------------------------------------
# background job tracker (เพิ่ม 2026-08-26 — ดู docstring หัวไฟล์เรื่อง start+poll) — in-memory
# dict เดียว ไม่ persist (deception-core restart แล้ว job หายได้ — ยอมรับได้ เพราะเป็นแค่ cache
# ผลลัพธ์ระหว่างรอ ไม่ใช่ข้อมูลถาวร Cowrie ฝั่ง client มี timeout ของตัวเองถ้า poll ไม่เจอ job)
# --------------------------------------------------------------------------------------------
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()


def start_login_decoy_job(username: str, ip: str, login_time: str, session_id: str) -> None:
    """เริ่ม background thread generate ให้ session นี้ — ไม่ทำซ้ำถ้ามี job pending อยู่แล้ว
    (กัน login ซ้ำเร็วๆ จาก IP เดิมยิงซ้อนกันหลาย thread โดยไม่ตั้งใจ)

    แก้บั๊กจริง 2026-08-28 (ผู้ใช้เจอเอง — cat/crontab ยังช้าทั้งที่ไม่ใช้ AI): เดิมรายงานสถานะ
    "status" เดียวรวมไฟล์+DB (ต้องรอทั้งคู่เสร็จ status ถึงเป็น "done") ทั้งที่ files เสร็จเร็วมาก
    (deterministic) ส่วน DB ใช้ AI จริงและ retry ได้หลายรอบ (ช้ากว่ามาก) — เปลี่ยนเป็นรายงานแยก
    `files_status`/`db_status` สองสัญญาณอิสระ ให้ฝั่ง cowrie (`cat`/`crontab -l`) resolve ได้ทันทีที่
    files เสร็จ โดยไม่ต้องรอ DB เลย (ดู docs/reports/pi_part1_audit_fixes_2026-08-28.md ส่วนที่ 8)"""
    with _jobs_lock:
        existing = _jobs.get(session_id)
        if existing is not None and existing.get("files_status") == "pending":
            return
        _jobs[session_id] = {
            "files_status": "pending", "files_result": None,
            "db_status": "pending", "db_result": None,
        }

    def _run() -> None:
        try:
            files = _build_files_only(username, login_time, ip)
        except Exception:
            files = {}
        with _jobs_lock:
            job = _jobs.setdefault(session_id, {})
            job["files_status"] = "done"
            job["files_result"] = {"files": files}

        try:
            db_tables = _build_db_only(username, ip, login_time, session_id)
        except Exception:
            db_tables = []
        with _jobs_lock:
            job = _jobs.setdefault(session_id, {})
            job["db_status"] = "done"
            job["db_result"] = {"db_tables": db_tables}

    threading.Thread(target=_run, daemon=True, name=f"login_decoy-{session_id}").start()


def get_login_decoy_job(session_id: str) -> dict:
    with _jobs_lock:
        job = _jobs.get(session_id)
    if job is None:
        return {"files_status": "unknown", "files_result": None,
                "db_status": "unknown", "db_result": None}
    return job


def cleanup_session_decoys(session_id: str, conn=None, pop_job: bool = True) -> None:
    """ลบแถวของ session นี้ทิ้ง (ตามมติ 'อยู่แค่ session เดียว') — ลบเฉพาะแถวที่ session_id ตรง ไม่
    DROP/TRUNCATE ทั้งตาราง (กันกระทบ session อื่นที่ยังใช้ตารางเดียวกันอยู่พร้อมกัน) เรียกได้ 2 ทาง:
    (1) ผ่าน connection ที่เปิดอยู่แล้ว (จาก build_login_decoys เอง ตอน login ซ้ำจาก IP เดิม — ต้อง
        ส่ง pop_job=False เพราะ ณ จุดนั้น job ของตัวเองยังไม่เสร็จ เพิ่ง claim "pending" ไปหมาดๆ ใน
        thread เดียวกัน — เจอบั๊กจริงตอน debug 2026-08-26: ถ้า pop `_jobs[session_id]` ตรงนี้ด้วย จะ
        ลบ entry "pending" ของตัวเองทิ้งทันที ทำให้ poll ฝั่ง Cowrie เจอ status="unknown" แล้ว
        give-up ก่อนเวลาอันควร (ภายในไม่กี่วิ แทนที่จะรอจน generate เสร็จจริง) หรือ
    (2) เปิด connection ใหม่เอง (จาก /v1/cleanup_session ตอนจบ session จริง — pop_job=True ค่า
        default เพราะตอนนั้น job เสร็จ/ไม่มีใครสนใจผลแล้วจริงๆ)"""
    own_conn = conn is None
    try:
        if own_conn:
            conn = _pg_connect()
            conn.autocommit = True
        cur = conn.cursor()
        for t in _psql_part1_tables():
            table = t["table_name"]
            try:
                cur.execute(
                    f'DELETE FROM "{_DECOY_SCHEMA_NAME}"."{table}" WHERE session_id = %s',
                    [session_id],
                )
            except Exception:
                continue  # ตารางอาจยังไม่ถูกสร้าง (login ครั้งแรกจริงๆ ของ IP นี้) — ข้ามไปเฉยๆ
        if own_conn:
            conn.close()
    except Exception:
        pass
    if pop_job:
        with _jobs_lock:
            _jobs.pop(session_id, None)  # กันสะสมไม่มีที่สิ้นสุดใน _jobs dict
