"""
qc_check.py — QC เนื้อหาใน template_content ก่อนบอกว่า pre-fetch เสร็จ (ตาม CLAUDE.md ข้อ 6:
ต้องรันเช็คจริง ไม่ใช่ดูด้วยตา) รายงานตัวเลขจริง ไม่ใช่แค่ "เช็คแล้วโอเค"

เช็ค:
1. Duplicate/near-duplicate — เนื้อหาเหมือนกันเป๊ะข้าม (target, tier) ต่างกัน (โมเดลอาจ ignore
   context แล้วพ่นซ้ำ) — เช็ครวมทุก door (Part 1 + Part 2) เพราะจับ cross-door drift ได้ด้วย
2-3. ความยาวสั้นผิดปกติ/self-repeat/persona-leak/ปีเก่ากว่า persona — แยกรายงานเป็น Part 1
   (door=ssh/ftp) กับ Part 2 (door=phase2) คนละ section (ดูฟังก์ชัน _run_content_checks())
4. Tier distribution คร่าวๆ — ความยาวเฉลี่ยต่าง tier กันจริงไหม (ไม่ได้บังคับทิศทาง แค่รายงาน)
5. Coverage-gap ของ Part 2 — เทียบกับ target/tier/content_type ที่ควรมีจริงจาก schema (ผ่าน
   phase_adaptive._targets_by_phase() ตรงๆ ไม่ parse schema ซ้ำ) ว่าขาดอะไรไปบ้าง

แก้ 2026-09-12 (grilling session, Work Item 2 — ดู ~/.claude/plans/attacker-polished-seahorse.md):
Part 2 content (door="phase2") เข้า template_content table เดียวกันนี้อยู่แล้ว (ผ่าน
phase_adaptive.warm_phase()) เช็คเดิมทั้งหมดเห็นแถวเหล่านี้อยู่แล้วจริง — ช่องโหว่จริงที่พบคือ (ก)
target ประเภทตาราง (schema type="table") เก็บเนื้อหาเป็น JSON string {"rows": [[...]]} บรรทัดเดียว
ทำให้เช็คแบบ line-based (self-repeat) ไม่มีความหมาย (เห็นแค่ 1 "บรรทัด" เสมอ ไม่มีทางจับซ้ำได้เลย
ไม่ใช่ว่าเนื้อหาดีจริง แค่เช็คมองไม่เห็น) (ข) ไม่มีอะไรบอกว่า target/tier/content_type ไหนยังไม่เคย
warm เลย (ไม่รู้ว่า "0 findings" เพราะเนื้อหาดี หรือเพราะยังไม่ generate เลยด้วยซ้ำ) แก้ทั้งสองจุด
ด้านล่าง (flatten JSON เป็น per-row string ก่อนเช็ค + เพิ่ม coverage-gap report)

รัน: docker exec -w /app <deception-core container> python3 qc_check.py
"""

import json
import os
import re
import sqlite3
from collections import Counter, defaultdict

import phase_adaptive
from config import DB_PATH
from session_prompt_builder import TIER_OF

PERSONA_LEAK_TERMS = [
    "azure", "x86_64", "senior-project", "6.17.0-1020-azure", "ubuntu-pi-server",
]

MIN_LEN = 20

# เพิ่ม 2026-08-26 (เจอจริงตอนผู้ใช้ทดสอบเดโมผ่าน SSH จริง ดู
# docs/reports/pi_prepared_response_qc_fix_2026-08-26.md): 4 เช็คเดิม (dup/too-short/self-repeat
# บรรทัด/persona-leak) ไม่เคยจับ 2 failure class นี้เลย ทั้งที่หลุดจริงและกระทบการใช้งานตรงๆ:
# (a) mode=psql สะท้อน SQL query กลับมาแทนแถวข้อมูล (b) เนื้อหาขัดแย้งกันเอง (key เดิม ค่าไม่ตรงกัน
# ในไฟล์เดียว เช่น postgresql.conf) เช็คทั้งสองจากเนื้อหาตรงๆ ไม่ต้องพึ่ง live model

_HERE = os.path.dirname(os.path.abspath(__file__))
_PSQL_DECOY_CANDIDATES = [
    # แก้ 2026-09-16 (เจอระหว่างเทส Batch C): ไฟล์ถูกเปลี่ยนชื่อไปแล้วตั้งแต่ 2026-08-26 (ดู
    # docs/reports/pi_part1_realdb_cleanup_2026-08-26.md) แต่ candidate list นี้ไม่เคยอัปเดตตาม —
    # ทำให้ _load_psql_targets() คืน set ว่างเปล่ามาตลอด 3 สัปดาห์ (หาไฟล์เก่าไม่เจอเลยสักที) เช็ค
    # [3c] SQL-echo กับ [3e] multi-block เลยรายงาน "0 findings" เสมอ ไม่ใช่เพราะเนื้อหาดีจริง —
    # เพิ่มชื่อไฟล์ใหม่เข้าไป คงชื่อเก่าไว้เป็น fallback เผื่อรันกับ container เก่าที่ยังไม่ได้อัปเดต
    "/data/psql_decoy_schema_part1_realdb.json",
    os.path.join(_HERE, "psql_decoy_schema_part1_realdb.json"),
    "/data/psql_decoy_schema.json",
    os.path.join(_HERE, "psql_decoy_schema.json"),
]


def _load_psql_targets() -> set[str]:
    """target ที่เป็นชื่อตาราง psql decoy (ไม่มีคอลัมน์ mode เก็บใน template_content เอง — ต้อง
    เดาจาก schema แบบเดียวกับที่ prefetch_worker.py ใช้ single source of truth เดียวกัน)"""
    for path in _PSQL_DECOY_CANDIDATES:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                schema = json.load(f)
            return {t["table_name"] for t in schema.get("decoy_tables", [])}
    return set()


_SQL_ECHO_RE = re.compile(r"\bSELECT\b[\s\S]{0,300}\bFROM\b", re.IGNORECASE)

# key=value หรือ key = value แบบไฟล์ config ทั่วไป (postgresql.conf ฯลฯ) — ไม่รวมบรรทัด comment (#)
_KV_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.+?)\s*$")

# เจอจริง 2026-08-23: โมเดลชอบใส่ปี 2023 (เก่ากว่า persona timeline ของโปรเจกต์ที่เป็น 2026) —
# ไม่ block (ตัวเลข tolerate ได้ ไม่ใช่ persona-breaking รุนแรงเท่า PERSONA_LEAK_TERMS) แค่รายงาน
# ให้เห็นเป็น finding เผื่อพิจารณาแก้ prompt เพิ่มทีหลัง
import re as _re
_YEAR_RE = _re.compile(r"\b(19\d{2}|20[0-1]\d|202[0-5])\b")


def _phase2_table_targets() -> set[str]:
    """target key (table_name) ของ Part 2 entry ที่ type=="table" — reuse
    phase_adaptive._targets_by_phase()/_entry_key() ตรงๆ (single source of truth ตาม CLAUDE.md §5
    ไม่ parse pi/vfs_schema_part2_phase_adaptive.json ซ้ำเอง)"""
    tables: set[str] = set()
    for entries in phase_adaptive._targets_by_phase().values():
        for entry in entries:
            if entry.get("type") == "table":
                tables.add(phase_adaptive._entry_key(entry))
    return tables


def _flatten_table_rows(content: str) -> list[str] | None:
    """content ของ target ประเภทตาราง Part 2 เก็บเป็น JSON string {"rows": [[...], ...]}
    (ดู core/phase_adaptive.py::_build_legacy_erp_customers/_build_exfil_staging_log) — เช็คแบบ
    line-based เดิม (self-repeat) มองไม่เห็นอะไรเลยเพราะเป็น 1 บรรทัดตลอด แปลงเป็น 1 string ต่อแถว
    (pipe-join) ให้เทียบซ้ำกันได้เหมือนไฟล์ทั่วไป คืน None ถ้า parse ไม่ได้ (defensive — เนื้อหาพัง
    format จะโดนจับโดยเช็คอื่นอยู่แล้ว ไม่ใช่หน้าที่ฟังก์ชันนี้)"""
    try:
        rows = json.loads(content)["rows"]
    except Exception:
        return None
    return [" | ".join(str(v) for v in row) for row in rows]


def _run_content_checks(rows: list, table_targets: set[str], label: str) -> dict:
    """เช็คกลุ่ม too-short/self-repeat/persona-leak/anachronistic-year สำหรับ rows กลุ่มหนึ่ง
    (Part 1 หรือ Part 2 แยกกันเรียก — ดึงออกมาจาก main() เดิมที่เคย inline ซ้ำ 2 รอบตอนแยก door
    ตาม CLAUDE.md §5) คืน dict ของ finding list พร้อมพิมพ์รายงานย่อยไปด้วย"""
    print(f"\n--- {label}: {len(rows)} rows ---")

    too_short = [(d, t, tr, ct, len(c.strip())) for d, t, tr, ct, c in rows if len(c.strip()) < MIN_LEN]
    print(f"  [too-short] (<{MIN_LEN} chars): {len(too_short)}")
    for row in too_short[:10]:
        print(f"      {row}")

    self_repeats = []
    for door, target, tier, content_type, content in rows:
        if target in table_targets:
            # เพิ่ม 2026-09-12: table target เก็บเป็น JSON บรรทัดเดียว — flatten เป็น per-row
            # string ก่อนเช็ค ไม่งั้นเห็นแค่ 1 "บรรทัด" เสมอ ไม่มีทางจับ self-repeat ได้จริง
            flattened = _flatten_table_rows(content)
            lines = [ln for ln in (flattened or []) if len(ln) >= 15]
        else:
            lines = [ln.strip() for ln in content.splitlines() if len(ln.strip()) >= 15]
        counts = Counter(lines)
        repeated = [(ln, n) for ln, n in counts.items() if n >= 3]
        if repeated:
            self_repeats.append((door, target, tier, content_type, repeated[0]))
    print(f"  [self-repeat] within a single row: {len(self_repeats)}")
    for row in self_repeats[:10]:
        print(f"      {row}")

    leaks = []
    for door, target, tier, content_type, content in rows:
        low = content.lower()
        hits = [term for term in PERSONA_LEAK_TERMS if term in low]
        if hits:
            leaks.append((door, target, tier, content_type, hits))
    print(f"  [persona-leak] term hits: {len(leaks)}")
    for row in leaks[:10]:
        print(f"      {row}")

    old_years = []
    for door, target, tier, content_type, content in rows:
        hits = set(_YEAR_RE.findall(content))
        if hits:
            old_years.append((door, target, tier, content_type, sorted(hits)))
    print(f"  [anachronistic-years] (informational, not blocking): {len(old_years)}")
    for row in old_years[:10]:
        print(f"      {row}")

    return {
        "too_short": too_short, "self_repeats": self_repeats,
        "leaks": leaks, "old_years": old_years,
    }


def _phase2_coverage_gap(rows: list) -> list[tuple[str, int, str]]:
    """เพิ่ม 2026-09-12 (Work Item 2, coverage-gap report) — เทียบ (target, tier, content_type) ที่
    ควรมีจริงจาก schema (ทุก entry ที่ type != "dir" ใน _targets_by_phase(), tier ทุกค่าที่
    TIER_OF ใช้จริง [1,2,3], content_type ทั้ง 2 แบบ) กับที่มีจริงใน template_content door="phase2"
    — คืน list ของ combo ที่ขาด (ยังไม่เคย warm เลย) ไม่ตัดสินว่าเนื้อหาที่มีอยู่ดีหรือไม่ (หน้าที่
    ของเช็คอื่นด้านบน) แค่บอกว่า "ไม่มีอะไรให้เช็คเลย" ตรงไหนบ้าง — ซึ่งเป็น blind spot เดิมที่ไม่มี
    ใครเคยรายงานมาก่อน"""
    present = {(target, tier, content_type) for _, target, tier, content_type, _ in rows}
    expected: list[tuple[str, int, str]] = []
    tiers = sorted(set(TIER_OF.values()))
    for entries in phase_adaptive._targets_by_phase().values():
        for entry in entries:
            if entry.get("type") == "dir":
                continue
            key = phase_adaptive._entry_key(entry)
            for tier in tiers:
                for content_type in ("deceive", "normal"):
                    if (key, tier, content_type) not in present:
                        expected.append((key, tier, content_type))
    return sorted(set(expected))


def main() -> int:
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT door, target, tier, content_type, content FROM template_content ORDER BY tier, target, content_type"
    ).fetchall()
    conn.close()

    print(f"=== QC report: {len(rows)} template_content rows ===\n")

    # 1) duplicate/near-duplicate (exact match เนื้อหา ข้าม row ต่างกัน)
    content_to_keys = defaultdict(list)
    for door, target, tier, content_type, content in rows:
        content_to_keys[content.strip()].append((door, target, tier, content_type))
    dupes = {c: keys for c, keys in content_to_keys.items() if len(keys) > 1}
    print(f"[1] Exact-duplicate content groups: {len(dupes)}")
    for content, keys in list(dupes.items())[:10]:
        print(f"    dup x{len(keys)}: {keys}")

    # 2/2b/3/3b) แก้ 2026-09-12 (Work Item 2): แยกรายงาน Part 1 (door=ssh/ftp) กับ Part 2
    # (door=phase2) เป็นคนละ section ผ่าน _run_content_checks() เดียวกัน (ไม่พิมพ์ logic ซ้ำ 2 รอบ)
    # — table_targets ใช้ flatten JSON เป็น per-row string ก่อนเช็ค self-repeat (ดู docstring
    # _flatten_table_rows) ไม่งั้นเช็คแบบ line-based เดิมมองไม่เห็นอะไรเลยสำหรับ target ประเภทตาราง
    table_targets = _phase2_table_targets()
    part1_rows = [r for r in rows if r[0] in ("ssh", "ftp")]
    part2_rows = [r for r in rows if r[0] == "phase2"]
    other_rows = [r for r in rows if r[0] not in ("ssh", "ftp", "phase2")]
    print("\n[2-3b] Content checks (too-short / self-repeat / persona-leak / anachronistic-year):")
    part1_findings = _run_content_checks(part1_rows, table_targets, "Part 1 (door=ssh/ftp)")
    part2_findings = _run_content_checks(part2_rows, table_targets, "Part 2 (door=phase2)")
    other_findings = _run_content_checks(other_rows, table_targets, "อื่นๆ (door ที่ไม่รู้จัก)") \
        if other_rows else {"too_short": [], "self_repeats": [], "leaks": [], "old_years": []}
    too_short = part1_findings["too_short"] + part2_findings["too_short"] + other_findings["too_short"]
    self_repeats = (part1_findings["self_repeats"] + part2_findings["self_repeats"]
                     + other_findings["self_repeats"])
    leaks = part1_findings["leaks"] + part2_findings["leaks"] + other_findings["leaks"]
    old_years = part1_findings["old_years"] + part2_findings["old_years"] + other_findings["old_years"]

    # 3c) เพิ่ม 2026-08-26: SQL-echo — mode=psql (เดาจาก target ที่อยู่ใน psql_decoy_schema.json)
    # แต่เนื้อหากลับมีรูปแบบ "SELECT ... FROM ..." (สะท้อน query กลับมาแทนแถวข้อมูลจริง)
    psql_targets = _load_psql_targets()
    sql_echoes = []
    for door, target, tier, content_type, content in rows:
        if target in psql_targets and _SQL_ECHO_RE.search(content):
            sql_echoes.append((door, target, tier, content_type))
    print(f"\n[3c] SQL-echo in psql content (should be data rows, not a query): {len(sql_echoes)}")
    for row in sql_echoes[:10]:
        print(f"    {row}")

    # 3d) เพิ่ม 2026-08-26: self-contradiction — key เดิมปรากฏ >=2 ครั้งในไฟล์เดียวแต่ค่าต่างกัน
    # (เช่น postgresql.conf มี listen_addresses 2 ค่าคนละอัน) เช็คเฉพาะ content ที่มีรูปแบบ
    # key=value อย่างน้อย 2 บรรทัด (ข้าม psql/directory-listing ที่ไม่ใช่รูปแบบนี้)
    contradictions = []
    for door, target, tier, content_type, content in rows:
        if target in psql_targets:
            continue
        kv: dict[str, set[str]] = defaultdict(set)
        for line in content.splitlines():
            if line.strip().startswith("#"):
                continue
            m = _KV_RE.match(line)
            if m:
                kv[m.group(1)].add(m.group(2))
        bad = {k: v for k, v in kv.items() if len(v) > 1}
        if bad:
            contradictions.append((door, target, tier, content_type, bad))
    print(f"\n[3d] Self-contradicting key=value pairs within a single row: {len(contradictions)}")
    for row in contradictions[:10]:
        print(f"    {row}")

    # 3e: เพิ่ม 2026-08-26 — mode=psql พ่นตาราง SQL result หลายบล็อกซ้อนกัน (เช่น crm_lead,
    # stock_move_line เจอจริงตอนทดสอบ: 2-3 บล็อกคอลัมน์ไม่ตรงกัน) เช็คแบบหยาบ: นับ block ที่คั่น
    # ด้วยบรรทัดว่าง ถ้า psql content มีมากกว่า 1 block ที่ไม่ว่างเปล่า ถือว่าน่าสงสัย (ตาราง
    # ผลลัพธ์จริงควรเป็น block เดียว)
    multi_block = []
    for door, target, tier, content_type, content in rows:
        if target not in psql_targets:
            continue
        blocks = [b for b in re.split(r"\n\s*\n", content.strip()) if b.strip()]
        if len(blocks) > 1:
            multi_block.append((door, target, tier, content_type, len(blocks)))
    print(f"\n[3e] psql content split into multiple result blocks (should be one table): {len(multi_block)}")
    for row in multi_block[:10]:
        print(f"    {row}")

    # 4) tier length distribution (คร่าวๆ)
    by_tier = defaultdict(list)
    for door, target, tier, content_type, content in rows:
        by_tier[tier].append(len(content.strip()))
    print("\n[4] Content length by tier (mean, min, max, n):")
    for tier in sorted(by_tier):
        lens = by_tier[tier]
        print(f"    tier {tier}: mean={sum(lens)/len(lens):.0f} min={min(lens)} max={max(lens)} n={len(lens)}")

    # 5) เพิ่ม 2026-09-12 (Work Item 2) — coverage-gap ของ Part 2: (target, tier, content_type)
    # ที่ควรมีจริงจาก schema แต่ยังไม่เคย warm เลย — informational เท่านั้น (ไม่ block PASS เพราะ
    # deployment ใหม่/phase ที่ attacker ยังไม่ไปถึงย่อมมี gap เป็นปกติ ไม่ใช่ bug) แค่ทำให้ blind
    # spot เดิม (ไม่รู้ว่า "0 findings" เพราะดีจริงหรือเพราะยังไม่ generate) มองเห็นได้เป็นครั้งแรก
    missing = _phase2_coverage_gap(part2_rows)
    print(f"\n[5] Part 2 coverage gap (expected but never warmed): {len(missing)}")
    for combo in missing[:20]:
        print(f"    {combo}")
    if len(missing) > 20:
        print(f"    ... and {len(missing) - 20} more")

    print("\n=== summary ===")
    print(f"total rows: {len(rows)} (Part 1: {len(part1_rows)}, Part 2: {len(part2_rows)}"
          + (f", other: {len(other_rows)}" if other_rows else "") + ")")
    print(f"exact-duplicate groups: {len(dupes)}")
    print(f"too-short rows: {len(too_short)}")
    print(f"self-repeating rows: {len(self_repeats)}")
    print(f"persona-leak rows: {len(leaks)}")
    print(f"sql-echo rows: {len(sql_echoes)}")
    print(f"self-contradicting rows: {len(contradictions)}")
    print(f"multi-block psql rows: {len(multi_block)}")
    print(f"Part 2 coverage gap (informational, not blocking): {len(missing)}")

    ok = (not dupes and not too_short and not self_repeats and not leaks and not sql_echoes
          and not contradictions and not multi_block)
    print(f"PASS: {ok}")
    return 0 if ok else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
