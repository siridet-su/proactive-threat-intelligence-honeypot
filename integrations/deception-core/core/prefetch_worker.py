"""
prefetch_worker.py — background speculative pre-fetch (Prepared Response Layer, ดู
docs/reports/pi_stageB_pregen_2026-08-23.md) เรียก hailo-ollama (โมเดลสำเร็จรูปของ Hailo,
ไม่ fine-tune) generate เนื้อหา bait/decoy ล่วงหน้า — trigger จาก router.py::track() ทุกคำสั่งใหม่
(ตามคำแนะนำอาจารย์: "เริ่มสร้างคำตอบจากข้อมูลช่วงแรกที่แฮกเกอร์พยายามพิมพ์")

**door ที่รองรับ (ขยายจากเดิม 2026-08-23):**
- `ssh` — cat/psql ผ่าน Cowrie (`cowrie_patches/cat.py`/`psql.py`)
- `ftp` — RETR ผ่าน `doors/ftp/main.py` (เพิ่มใหม่ — FTP ไม่เคยเรียก `/v1/track` เลยสักครั้ง
  ไม่มี session/phase progression ของตัวเอง เลย**ไม่มี background trigger เป็นของตัวเอง**
  ต้องพึ่ง `warm_all.py` bootstrap อย่างเดียว — ไฟล์ FTP lure เป็น shared ทั้งหมด (backup/export
  ทั่วไป ไม่ต้อง unique ต่อ session) ต้อง sync `_FTP_LURE_FILES` กับ
  `doors/ftp/main.py::LURE_FILES` ด้วยมือ (คนละ container/codebase แบบเดียวกับ
  KNOWN_TABLES/KNOWN_MODELS ที่ต้อง sync มืออยู่แล้วในโปรเจกต์นี้) ผลพลอยได้: เดิม FTP เรียก
  deception-core **synchronous** บล็อก event loop ของ pyftpdlib ~2-6 วิ/ครั้ง (docstring เดิมของ
  ftp/main.py ยอมรับเป็น known limitation) พอเปลี่ยนเป็น template lookup แล้วเหลือ ~30-40ms
  ไม่บล็อกจนสังเกตได้อีกต่อไป — แก้ปัญหานี้ไปในตัวโดยไม่ได้ตั้งใจ

สองกลุ่มตาม §Context ของแผน:
- **กลุ่ม A (shared)** — `warm_tier(door, mode, tier)`: เขียนเข้า `template_store.py` (ไม่ผูก
  session) ใช้ซ้ำได้ทุก session ที่ tier เดียวกัน ครบทั้ง 2 content_type (deceive/normal — key มี
  content_type แยกอยู่แล้ว)
- **กลุ่ม B (session-unique)** — `warm_session(session_id, door, mode, tier)`: เขียนตรงเข้า
  `cache_store.py` เดิม (คีย์ `(session_id, door, cache_key)` ไม่มี content_type แยก — generate แค่
  content_type='normal' ไว้ก่อน เพราะ payoff matrix ส่วนใหญ่ action มักตกที่ lure/delay (~90%)
  มากกว่า deceive (~10%) ถ้า action จริงออกเป็น deceive จะ cache-miss แล้ว fallback แทน — accepted
  trade-off, ไม่ generate 2 รอบเพราะ cache_store เก็บได้ค่าเดียวต่อคีย์อยู่แล้ว)

ทั้งสองฟังก์ชัน generate แบบ **serial** (lock เดียว) กัน hammer Hailo chip ด้วย concurrent request
"""

import json
import os
import re
import threading

import httpx

import cache_store
import session_prompt_builder as spb
import template_store
from config import (
    HAILO_OLLAMA_MODEL, HAILO_OLLAMA_TIMEOUT_S, HAILO_OLLAMA_URL,
    PG_DBNAME, PG_HOST, PG_PASSWORD, PG_PORT, PG_USER,
)

SSH_DOOR = "ssh"
FTP_DOOR = "ftp"

_HERE = os.path.dirname(os.path.abspath(__file__))
_VFS_SCHEMA_CANDIDATES = [
    "/data/vfs_schema_updated_2026-07-22.json",
    os.path.join(_HERE, "vfs_schema_updated_2026-07-22.json"),
]
# ต้อง sync กับ doors/ftp/main.py::LURE_FILES มือ (คนละ container/codebase ไม่มีทาง import
# ข้ามได้ตรงๆ) — ทุกไฟล์เป็น shared เท่านั้น (ไม่มี session-unique ฝั่ง FTP)
_FTP_LURE_FILES = [
    "backup_2026-07.sql.gz",
    "backup_2026-06.sql.gz",
    "customers_export.csv",
    "invoices_Q1_2026.csv",
]
_FTP_STYLE_HINT = (
    "This is a database backup archive or CSV export downloaded from an Odoo ERP system via "
    "FTP. For .sql.gz files, describe plausible binary/compressed-looking placeholder text is "
    "NOT wanted -- instead write a short plain-text summary a human might see if they ran "
    "`file` or `zcat | head` on it (e.g. mention it's a PostgreSQL dump, approximate table "
    "names). For .csv files, output actual CSV rows with a header line."
)

_vfs_cache = None


def _load_json(candidates: list[str]) -> dict:
    for path in candidates:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    raise FileNotFoundError("หาไฟล์ schema ไม่เจอใน: " + ", ".join(candidates))


def _bash_bait_targets(uniqueness: str) -> list[tuple[str, str, str]]:
    """คืน [(path, schema_fact_string, target_type), ...] จาก vfs_schema.json เฉพาะ
    content_policy=dynamic ที่ uniqueness ตรงกับที่ขอ — schema fact ดึงตรงจากไฟล์ (deterministic,
    ไม่ใช่ RAG/vector) target_type ('file'/'dir') ใช้บอกโมเดลให้ตอบถูกแบบ (ดู build_batch_prompt)

    แก้ 2026-09-16 รอบแรก (เจอระหว่างเทสเปรียบเทียบความเร็วโมเดล): ข้าม entry ที่
    `real_editable == true` (Part 1 เขียนลง VFS จริงตอน login แล้ว, deterministic/pool-based) —
    ยืนยันจาก `cowrie/commands/cat.py::_process_args()` ว่าเช็คไฟล์จริงใน VFS
    (`self.fs.file_contents()`) ก่อนเสมอ ก่อนจะถาม deception-core

    แก้ 2026-09-16 รอบสอง (คำถามผู้ใช้ "เราสร้างไฟล์อะไรใน /home/warehouse_staff /home/sysadmin"
    → เช็คจริงด้วย `ls.py`/SSH ทดสอบสด → เจอว่ากว้างกว่าที่คิดตอนรอบแรก): schema เองมี field
    `real_vfs_backing` ที่ตั้งใจไว้แล้วเพื่อบอกเรื่องนี้ตรงๆ (`postgresql.conf`/`odoo.log.1`/
    `session_a8f3.tmp` มี `real_vfs_backing: false` ชัดเจน พร้อม note ว่า "ให้ ls.py phantom entry
    แทน" — ส่วน `crontab sysadmin` มี note ตรงๆ ว่า "real_vfs_backing:false ถูกลบออก — ไม่ phantom
    อีกต่อไป" ตอนเปลี่ยนเป็น real_editable) — เปลี่ยนเงื่อนไขจาก deny-list (`real_editable`) เป็น
    allow-list ที่ตรงกับเจตนาเดิมของ schema โดยตรง: **มีแต่ entry ที่ `real_vfs_backing is False`
    เท่านั้นที่ Part 2 มีทางถูกใช้จริง** (`cat.py` ถึงจะ `FileNotFound` แล้ว fallback มาถาม
    deception-core) ยืนยันเพิ่มด้วย SSH สด: `ls -la /home/sysadmin/`/`/home/warehouse_staff/`
    คืนไฟล์/โฟลเดอร์จริงจาก VFS ที่ build ไว้ตั้งแต่ deploy (`2026-07-14`) ไม่เกี่ยวกับ Part 2 เลย —
    เดิม (รอบแรก) ตัดได้แค่ 3/11 (เฉพาะไฟล์ `real_editable`) รอบนี้ตัดเพิ่มอีก 5 entry ประเภท `dir`
    (`/opt/odoo/`, `/home/sysadmin/`, `/home/accountant/`, `/home/sales_team/`,
    `/home/warehouse_staff/` — ไม่มีสักอันที่ `real_vfs_backing is False`) เหลือ target ที่ยังมีชีวิต
    จริง 3 อัน (`postgresql.conf`, `odoo.log.1`, `session_a8f3.tmp`) จาก 11 เดิม — ดู docs/reports/
    pi_part2_skip_real_editable_targets_2026-09-16.md"""
    global _vfs_cache
    if _vfs_cache is None:
        _vfs_cache = _load_json(_VFS_SCHEMA_CANDIDATES)
    out = []
    for e in _vfs_cache["filesystem"]:
        if e.get("real_vfs_backing") is not False:
            continue
        if e.get("content_policy") == "dynamic" and e.get("uniqueness") == uniqueness:
            fact = f"department={e.get('department')}, sensitivity={e.get('sensitivity')}"
            # เพิ่ม 2026-08-23: style_hint มีอยู่ในสคีมาอยู่แล้วหลายรายการ (เขียนไว้ตั้งแต่ก่อนงาน
            # นี้) แต่ไม่เคยถูกอ่านมาใช้เลย — ต่อเข้า schema_fact ให้จริง เพิ่มคุณภาพเนื้อหาได้มาก
            # (เจอจริง: session_a8f3.tmp ไม่มี style_hint มาก่อน โมเดลตอบเป็น SQL แทน JSON ที่
            # ตั้งใจ — เพิ่ม style_hint ให้แล้วด้วย)
            if e.get("style_hint"):
                fact += f". Style guide: {e['style_hint']}"
            out.append((e["path"], fact, e.get("type", "file")))
    return out


def _ftp_lure_targets(uniqueness: str) -> list[tuple[str, str, str]]:
    """FTP lure ทั้งหมดเป็น shared เท่านั้น (ไม่มี session-unique ฝั่งนี้)"""
    if uniqueness != "shared":
        return []
    return [(name, f"department=Finance/IT, sensitivity=critical. Style guide: {_FTP_STYLE_HINT}", "file")
            for name in _FTP_LURE_FILES]


def _targets_for(door: str, mode: str, uniqueness: str) -> list[tuple[str, str, str]]:
    if door == FTP_DOOR:
        return _ftp_lure_targets(uniqueness) if mode == "bash" else []
    # mode == "psql": ลบ path เดิม (ตาราง decoy 6 ตัว, background/shared) ทิ้งแล้ว 2026-08-26
    # (ดู docs/reports/pi_part1_realdb_cleanup_2026-08-26.md) — ตาราง psql ของ Part 1 ใหม่ generate
    # ตอน login แบบ per-session/blocking ผ่าน login_decoy.py โดยตรง ไม่ผ่าน warm_tier/warm_session
    # เส้นทางนี้อีกต่อไป จึงคืน [] เสมอสำหรับ psql
    return [] if mode == "psql" else _bash_bait_targets(uniqueness)


_gen_lock = threading.Lock()

# เพิ่ม 2026-08-28 — ทดสอบตรงพบว่า hailo-ollama unload โมเดลออกจากชิปถ้าไม่มีคำขอเข้ามา 5 นาที
# (default ของ Ollama API) แล้วโหลดใหม่ตอนมีคำขอถัดไป ทำให้เสียเวลาเพิ่ม ~5-6 วิ (วัดจริง: cold
# 6.26s vs warm 0.93s สำหรับ prompt สั้นเท่ากัน) เหนือเวลา generate จริง ยิ่งซ้ำเติมคิวตอนมีหลาย
# session รอ (แต่ละคิวอาจโดน reload ซ้ำถ้าห่างกันเกิน 5 นาที) — ตั้ง keep_alive ยาวขึ้นให้โมเดลค้าง
# อยู่ในชิปตลอด (เครื่องนี้มี hailo-ollama ไว้ใช้เฉพาะโปรเจกต์นี้ ไม่ต้องแชร์กับโมเดลอื่นบ่อย)
#
# **แก้บั๊กจริง 2026-08-28**: ลองส่ง "-1" (string ตาม convention ของ Ollama จริง) ก่อน — พัง!
# hailo-ollama (reimplementation เฉพาะของ Hailo บน oatpp framework ไม่ใช่ Ollama ของจริง) ต้องการ
# keep_alive เป็น **int (วินาที)** เท่านั้น ส่ง string ไปได้ 500 Internal Server Error
# ("Value is NOT a Primitive type") ซึ่งโดน `except Exception` กว้างๆ ที่ build_login_decoys()
# กลืนไปเงียบๆ (payroll_export เลยได้ 0 แถวเสมอ ไม่มี error โผล่ให้เห็น) — ใช้เลข วินาที ตรงๆ แทน
# ทดสอบแล้วว่า int ใช้ได้จริง (200 OK, /api/ps โชว์ expires_at ยาวขึ้นตามที่ตั้ง)
_HAILO_KEEP_ALIVE = 1800  # วินาที (30 นาที) — พอสำหรับช่วงห่างปกติระหว่าง login ไม่ต้องค้างตลอดกาล

# qwen2.5:1.5b (stock, ไม่ fine-tune) ชอบห่อ output ด้วย ```lang ... ``` markdown fence ทั้งที่สั่ง
# ห้ามไว้ใน prompt แล้ว (เจอจริง 2026-08-23 ระหว่าง test warm_tier รอบแรก) — ตัด fence ออก เก็บแค่
# เนื้อหาข้างใน ถ้ามีหลาย block (บางทีโมเดลพ่น prose คั่นกลาง) รวมเฉพาะเนื้อหาใน fence เข้าด้วยกัน
# ทิ้ง prose นอก fence ไปเลย (แก้ปัญหา "อธิบายแทรก" ไปในตัว)
_FENCE_RE = re.compile(r"```[a-zA-Z]*\n?(.*?)```", re.DOTALL)


def _strip_markdown_fences(text: str) -> str:
    blocks = _FENCE_RE.findall(text)
    if blocks:
        return "\n\n".join(b.strip("\n") for b in blocks if b.strip())
    return text.replace("```", "").strip()


def _generate(target: str, mode: str, content_type: str, tier: int, schema_fact: str,
              target_type: str = "file") -> str:
    prompt = spb.build_batch_prompt(target=target, mode=mode, content_type=content_type,
                                     tier=tier, schema_fact=schema_fact, target_type=target_type)
    payload = {
        "model": HAILO_OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        # เพิ่ม 2026-08-23: เจอตอน QC เข้มขึ้น (self-repetition check) ว่า 18/91 rows โมเดล
        # วนพ่นบรรทัด/query เดิมซ้ำๆ ในคำตอบเดียวกัน (โดยเฉพาะ tier=1 "terse" style) —
        # repeat_penalty ช่วยลด แต่ยังไม่ทดสอบว่าหายสนิทหรือแค่ลดลง (ยังต้องรัน QC ยืนยันจริง)
        # ลด 2026-08-26: temperature 0.5 -> 0.35 (เจอจริงตอนผู้ใช้ทดสอบเดโม — โมเดลพ่นคำตอบ 2-3
        # เวอร์ชันขัดแย้งกันในคำตอบเดียว เช่น postgresql.conf/crm_lead/stock_move_line — ลด
        # temperature ให้นิ่งขึ้น ลดโอกาส "แตกกิ่ง" เป็นหลายเวอร์ชัน คู่กับ prompt instruction ใหม่
        # ใน session_prompt_builder.py — ดู docs/reports/pi_prepared_response_qc_fix_2026-08-26.md)
        "options": {"num_predict": 200, "temperature": 0.35, "repeat_penalty": 1.3},
        "keep_alive": _HAILO_KEEP_ALIVE,
    }
    with _gen_lock:  # serial — กันยิง hailo-ollama พร้อมกันหลาย thread เกินกำลังชิป
        resp = httpx.post(f"{HAILO_OLLAMA_URL}/api/generate", json=payload,
                           timeout=HAILO_OLLAMA_TIMEOUT_S)
        resp.raise_for_status()
        return _strip_markdown_fences(resp.json()["response"])


# --------------------------------------------------------------------------------------------
# psql decoy row generation helpers — เพิ่ม 2026-08-26 เช้า (ดู
# docs/reports/pi_prepared_response_qc_fix_2026-08-26.md) ตอนแรกผูกกับตาราง decoy 6 ตัวเดิม +
# background warm_tier() — 6 ตัวนั้นถูกลบทิ้งแล้วช่วงบ่ายวันเดียวกัน (มติผู้ใช้ "ไม่น่าจะไปใช้แล้ว"
# ดู docs/reports/pi_part1_realdb_cleanup_2026-08-26.md) แต่ฟังก์ชันด้านล่าง (generate ค่าข้อมูล
# ล้วนๆ ไม่มี SQL/header ปลอม, กัน literal \n crash hailo-ollama) เป็นของกลางที่ไม่ผูกกับตารางไหน
# เจาะจง — เก็บไว้ให้ Part 1 (login_decoy.py) เรียกใช้ต่อ (single source of truth เดียวกัน ไม่เขียน
# ซ้ำ) แค่ generate ครั้งเดียวตอน login แทนที่จะ background/shared แบบเดิม
# --------------------------------------------------------------------------------------------
_ROWS_PER_COMBO = 4


def _pg_connect():
    import psycopg2
    # เพิ่ม 2026-08-27: เจอจริงตอน verify Part 1 ว่า login_decoy job ค้าง "pending" ไม่รู้จบ
    # (เกิดซ้ำหลายรอบ แม้ restart container แล้วก็ยังเจอได้อีก) — connect() เดิมไม่มี
    # connect_timeout เลย ต่างจาก _query_real_db/_query_decoy_db ใน psql.py ที่มี connect_timeout=5
    # อยู่แล้ว — ยังไม่ยืนยัน 100% ว่าเป็นสาเหตุ (อาจเป็นที่ _gen_lock/hailo-ollama ก็ได้) แต่เป็นจุด
    # เสี่ยงที่เห็นชัดที่สุดที่ไม่มี timeout ป้องกันไว้เลย เพิ่มไว้กันไว้ก่อน
    return psycopg2.connect(host=PG_HOST, port=PG_PORT, dbname=PG_DBNAME,
                             user=PG_USER, password=PG_PASSWORD, connect_timeout=10)


def _decoy_row_prompt(fact: str, cols: list[str], tier: int, content_type: str, allow_sql: bool = False,
                       row_count: int = _ROWS_PER_COMBO) -> str:
    # เพิ่ม 2026-08-30 (แก้คอขวด login พร้อมกันช้า — ดู
    # docs/reports/pi_gen_lock_payroll_rowcount_fix_2026-08-30.md): เดิมใช้ _ROWS_PER_COMBO ตรงๆ
    # ทุกจุด ปรับต่อ caller ไม่ได้เลย — เปิดทาง override เฉพาะ call site ที่ต้องการ (เช่น
    # payroll_export ที่ขอ AI แต่งตอน login แบบ blocking ต้องการแถวน้อยลงเพื่อลดเวลารอ) โดย default
    # ยังคงเป็น _ROWS_PER_COMBO เท่าเดิมสำหรับตารางอื่นที่ยังไม่ได้ตัดสินใจเรื่องนี้
    style = _TIER_STYLE_LOCAL.get(tier, _TIER_STYLE_LOCAL[1])
    flavor = _CONTENT_TYPE_HINT_LOCAL.get(content_type, _CONTENT_TYPE_HINT_LOCAL["normal"])
    # เพิ่ม 2026-08-26 (รอบ 2 — เจอจริงตอน verify หลัง redesign): โมเดลชอบพ่นชื่อคอลัมน์ซ้ำเป็น
    # แถวข้อมูล (เช่น แถวแรก = "employee_name | bank_name | ...") หรือพ่นเส้นคั่น "----|----"
    # เป็นแถวข้อมูล — ทั้งที่สั่ง "no header row" ไปแล้ว ต้องเน้นย้ำแรงขึ้นเจาะจงขึ้น + บอกชัดว่า
    # ห้ามให้ค่าตรงกับชื่อคอลัมน์เป๊ะ
    # ⚠️ ห้ามใส่ literal \n ในพรอมต์ที่ส่งให้ hailo-ollama เด็ดขาด (HailoRT parse prompt เป็น
    # JSON อีกชั้น เจอ \n ดิบแล้ว crash HAILO_INTERNAL_FAILURE — บทเรียนเดิมจาก 2026-08-23 ที่
    # เผลอทำผิดซ้ำตอนเขียนพรอมต์นี้รอบแรก ใช้ ". " คั่นแทนเสมอ)
    numbered_cols = ". ".join(f"column {i+1} is {c}" for i, c in enumerate(cols))
    # 2026-08-27 (QC fix): เดิม "no SQL" เป็น boilerplate ตายตัวทุกตาราง ขัดกับ style_hint ของ
    # db_access_audit ที่สั่งว่า query_text ต้องเป็น SQL จริง (โมเดลเล็กทำตาม boilerplate มากกว่า
    # style_hint ที่แทรกท้ายพรอมต์ -- เจอจริงตอน QC 2026-08-27) เปิดทาง per-table override ผ่าน
    # allow_sql (มาจาก schema field content_allows_sql -- ดู login_decoy.py call site)
    sql_clause = (
        "One column may contain a real one-line SQL statement (e.g. a SELECT/UPDATE query) if "
        "that is what the column name calls for."
        if allow_sql else
        "No SQL of any kind in any column."
    )
    return (
        f"Generate exactly {row_count} example data rows for a database table with these "
        f"{len(cols)} columns in this exact order: {numbered_cols}. "
        f"Output ONLY the values, one row per line, columns separated by ' | ' (a single pipe "
        f"with spaces), {len(cols)} values per line matching the column order above exactly. "
        f"Never output the column names themselves as a row. Never output a separator line made "
        f"of dashes. Every line must be real example DATA only. "
        f"No id column, no header row, no explanation, no markdown, no table borders. "
        f"{sql_clause} "
        f"The current date is in 2026 -- any date value must use a 2026 date. "
        f"Each row must be different from the others. "
        f"Style: {style}. {flavor}. {fact}. Output the {row_count} data rows now, values only:"
    )


def _looks_like_header_or_separator(parts: list[str], cols: list[str]) -> bool:
    """กรองแถวขยะที่โมเดลพ่นชื่อคอลัมน์ซ้ำ หรือเส้นคั่น '----' มาเป็นแถวข้อมูล (เจอจริงตอน
    verify รอบ 2 — ir_attachment/crm_lead/hr_employee_bank_account/stock_move_line)"""
    norm_cols = {c.strip().lower() for c in cols}
    # แก้ 2026-09-01 (ดู docs/reports/pi_part2_legacy_erp_normal_flavor_fix_2026-09-01.md): เจอจริง
    # ว่าโมเดลบางครั้งพ่นชื่อคอลัมน์ซ้ำแบบมีเลขข้อนำหน้า (เช่น "1. customer_name") ทำให้เทียบตรงๆ
    # ไม่ตรงกับชื่อคอลัมน์ล้วนๆ หลุดผ่านเป็น data จริงไปได้ — ตัด prefix แบบ "1. "/"2) " ออกก่อนเทียบ
    # เสมอ (แก้เฉพาะจุดเทียบ ไม่กระทบค่าที่เก็บจริงถ้าแถวนี้ผ่าน เพราะฟังก์ชันนี้แค่คืน True/False)
    norm_parts = [re.sub(r"^\d+[.)]\s*", "", p.strip().lower()) for p in parts]
    if norm_cols and set(norm_parts) <= (norm_cols | {""}):
        return True  # ค่าในแถวตรงกับชื่อคอลัมน์ (หรือว่าง) ทั้งหมด = แถว header ปลอมตัวมา
    if all(re.fullmatch(r"-{2,}", p.strip()) for p in parts if p.strip()):
        return True  # แถวคั่นแบบ markdown/ascii-table
    return False

def _looks_like_duplicate_value_row(parts: list[str]) -> bool:
    """กรองแถวที่ 2 คอลัมน์ขึ้นไปมีค่าเหมือนกันเป๊ะ (case-insensitive, trim แล้ว) -- สัญญาณของ
    โมเดลก็อบค่าข้ามคอลัมน์ผิดที่ (เจอจริง 2026-08-27: bank_account_masked ซ้ำกับ employee_name
    ทุกแถว, accessed_by ซ้ำกับ access_time ใน db_access_audit) -- ไม่กรองค่าว่าง เพราะหลายตาราง
    มีคอลัมน์ว่างได้จริงตามปกติ"""
    seen_vals = set()
    for p in parts:
        v = p.strip().lower()
        if not v:
            continue
        if v in seen_vals:
            return True
        seen_vals.add(v)
    return False


_TIER_STYLE_LOCAL = {
    1: "terse, generic, and mechanical, nothing elaborate",
    2: "obvious and flashy, plaintext-looking secrets or big round numbers",
    3: "subtle, realistic, professional-looking, and internally consistent",
}
_CONTENT_TYPE_HINT_LOCAL = {
    "deceive": "Make it look valuable and sensitive, worth stealing",
    "normal": "Make it look ordinary, routine, and unremarkable, nothing sensitive",
}


def _generate_decoy_rows(fact: str, cols: list[str], tier: int, content_type: str,
                          allow_sql: bool = False,
                          dup_check_ignore_cols: set[str] | None = None,
                          row_count: int = _ROWS_PER_COMBO) -> list[list[str]]:
    # row_count เพิ่ม 2026-08-30 (ดู docs/reports/pi_gen_lock_payroll_rowcount_fix_2026-08-30.md) —
    # verify จริงบน Pi แล้วว่าขอแถวน้อยลง (4->2) ลดเวลา generate เกือบครึ่ง (~18.7s -> ~9.6s) และ
    # format ถูกต้องเสถียรกว่าเดิมด้วย (โมเดล 1.5B ทำ 2 แถวได้แม่นกว่า 4 แถว) ต้นตอที่แท้จริงของ
    # login พร้อมกันช้าคือชิป Hailo ประมวลผลได้ทีละ 1 คำขอ (ข้อจำกัดฮาร์ดแวร์ ไม่ใช่ _gen_lock ของ
    # เรา — ทดสอบแยกยืนยันแล้วว่ายิงตรงข้ามล็อกก็ไม่เร็วขึ้น) จุดเดียวที่ลดเวลารวมได้จริงคือลดเวลา
    # ต่อคำขอ ไม่ใช่ลดการล็อก
    threshold = min(2, row_count)  # เดิม hardcode 2 (เกณฑ์ "พอใช้ได้") ตรงกับ default row_count=4
    # พอดี -- ทำเป็น min(2, row_count) กันกรณี row_count น้อยกว่า 2 ในอนาคต ไม่เปลี่ยนพฤติกรรมเดิม
    # เมื่อ row_count=4 (ค่า default เดิม)
    prompt = _decoy_row_prompt(fact, cols, tier, content_type, allow_sql=allow_sql, row_count=row_count)
    # 2026-08-27 (รอบ 3): บางคอลัมน์ (เช่น payroll_export.bank_account_masked) ถูก override ทับ
    # เสมอหลัง generate อยู่แล้ว (ดู login_decoy.py) -- ไม่มีประโยชน์ที่จะ reject-แล้ว-retry เพราะ
    # ค่าคอลัมน์นั้นซ้ำกับคอลัมน์อื่น ทำให้เสียเวลา generate ซ้ำโดยเปล่าประโยชน์ (เจอจริง: ใช้เวลา
    # เต็ม ~220s แม้เหลือ AI table เดียว) -- dup_check_ignore_cols ให้ caller บอกได้ว่าคอลัมน์ไหน
    # ไม่ต้องเอามาเช็คซ้ำ
    ignore_idx = {cols.index(c) for c in (dup_check_ignore_cols or []) if c in cols}
    best: list[list[str]] = []
    for _attempt in range(4):
        with _gen_lock:
            resp = httpx.post(
                f"{HAILO_OLLAMA_URL}/api/generate",
                json={"model": HAILO_OLLAMA_MODEL, "prompt": prompt, "stream": False,
                      "options": {"num_predict": 220, "temperature": 0.35, "repeat_penalty": 1.3},
                      "keep_alive": _HAILO_KEEP_ALIVE},
                timeout=HAILO_OLLAMA_TIMEOUT_S,
            )
            resp.raise_for_status()
            text = _strip_markdown_fences(resp.json()["response"])
        rows, rows_lenient, seen, seen_lenient = [], [], set(), set()
        for line in text.splitlines():
            line = line.strip().strip("|").strip()
            _ban_prefixes = ("output", "here", "note") if allow_sql else ("select", "output", "here", "note")
            if not line or line.lower().startswith(_ban_prefixes):
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) != len(cols) or tuple(parts) in seen_lenient:
                continue
            if _looks_like_header_or_separator(parts, cols):
                continue
            seen_lenient.add(tuple(parts))
            check_parts = [v for i, v in enumerate(parts) if i not in ignore_idx]
            if _looks_like_duplicate_value_row(check_parts):
                # 2026-08-27 (QC fix, รอบ 2): เจอจริงว่าโมเดลบางตาราง (payroll_export) ทำค่าซ้ำ
                # ข้ามคอลัมน์ "ทุกแถวทุกครั้ง" อย่างเป็นระบบ -- reject-แล้ว-retry เฉยๆ จะได้ตาราง
                # ว่างเปล่าสนิท (แย่กว่าเดิม) เก็บไว้เป็น fallback แทนทิ้งขาด ถ้าสุดท้ายไม่มีแถว
                # strict เลยสัก 2 แถว ยังมีอะไรให้ใช้ดีกว่าไม่มีอะไรเลย
                rows_lenient.append(parts)
                continue
            seen.add(tuple(parts))
            rows.append(parts)
        if len(rows) >= threshold:
            return rows[:row_count]
        if len(rows) + len(rows_lenient) > len(best):
            best = (rows + rows_lenient)[:row_count]
        # เพิ่ม 2026-08-28 — log ไว้ถาวร (ไม่ใช่แค่ debug ชั่วคราว) ตอน attempt นี้ยังไม่ได้ >=2 rows
        # เพื่อดูว่าโมเดลตอบอะไรมาจริง — เจอเองตอนแก้ keep_alive ว่าจุดนี้ไม่มี log อะไรเลยมาก่อน
        # ทำให้ debug ยากเกินจำเป็น (ต้องเช็ค DB ตรงๆ ถึงจะรู้ว่า retry ล้มเหลว) ปกติไม่ควร fire
        # บ่อยเพราะ attempt แรกมักผ่านอยู่แล้ว fire เฉพาะตอน retry จริงๆ เท่านั้น ไม่ log ทุกครั้ง
        print(f"login_decoy: retry attempt={_attempt} strict_rows={len(rows)} lenient_rows={len(rows_lenient)} raw_response={text[:500]!r}")
    return best  # best effort หลังลอง 4 รอบ -- อาจมีค่าซ้ำคอลัมน์ปนอยู่ถ้า strict ไม่พอจริงๆ


def _ensure_decoy_table(cur, schema: str, table_name: str, cols: list[str],
                         extra_cols: list[str] | None = None) -> None:
    """สร้าง schema/table ถ้ายังไม่มี — `extra_cols` (เช่น session_id) ถูกเพิ่มเป็น TEXT เหมือนกัน
    แต่ caller เป็นคนดูแลไม่ให้ปนกับ `cols` ที่จะโชว์ให้ attacker เห็น (Part 1: login_decoy.py exclude
    ออกก่อนพิมพ์เสมอ)"""
    cur.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')
    all_cols = list(cols) + list(extra_cols or [])
    col_defs = ", ".join(f'"{c}" TEXT' for c in all_cols)
    cur.execute(
        f'CREATE TABLE IF NOT EXISTS "{schema}"."{table_name}" (id INTEGER NOT NULL, {col_defs})'
    )


def warm_tier(door: str, mode: str, tier: int) -> None:
    """กลุ่ม A (shared) — idempotent: ถ้า (door, mode, tier) claim ไปแล้ว (in_progress/done) ไม่ทำ
    ซ้ำ เขียนผล template_content ทีละอันทันทีที่เสร็จ (resume ได้ถ้า crash กลางคัน — เช็คก่อน
    generate ทุกอัน) — mode=="psql" ไม่ทำอะไรแล้ว (คืน [] จาก _targets_for เสมอ ดู comment ด้านบน)"""
    if not template_store.try_claim(door, mode, tier):
        return
    try:
        for target, fact, target_type in _targets_for(door, mode, "shared"):
            for content_type in ("deceive", "normal"):
                if template_store.get(door, target, tier, content_type) is not None:
                    continue
                content = _generate(target, mode, content_type, tier, fact, target_type)
                template_store.put(door, target, tier, content_type, content)
                template_store.touch(door, mode, tier)  # กัน staleness check เข้าใจผิดว่าตายกลางคัน
        template_store.set_status(door, mode, tier, "done")
    except Exception:
        template_store.set_status(door, mode, tier, "pending")  # trigger รอบหน้า retry ได้
        raise


def warm_session(session_id: str, door: str, mode: str, tier: int) -> None:
    """กลุ่ม B (session-unique) — เขียนตรงเข้า cache_store.py เดิม (ของเดิม ไม่สร้างตารางใหม่)
    cache_key รูปแบบเดียวกับที่ router.py ใช้จริง (f"{door}:{target}") กันไม่ให้ decide()
    cache-miss ตอน attacker เจอจริง (door="ftp" ไม่มีทางเข้ามาถึงจริง เพราะ FTP lure ทั้งหมดเป็น
    shared -- _targets_for คืน [] ให้เฉยๆ ไม่ error)"""
    for target, fact, target_type in _targets_for(door, mode, "session"):
        cache_key = f"{door}:{target}"
        if cache_store.get(session_id, door, cache_key) is not None:
            continue
        content = _generate(target, mode, "normal", tier, fact, target_type)
        cache_store.put(session_id, door, cache_key, content)
