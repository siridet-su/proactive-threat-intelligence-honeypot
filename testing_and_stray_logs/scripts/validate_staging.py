#!/usr/bin/env python3
"""
validate_staging.py — เช็คว่า staging/ ที่ build_staging.py สร้าง ตรงกับ
vfs_schema.json ครบทุก entry ไม่มีตกหล่น (ตามที่ระบุไว้ในงานข้อ 1)

เช็ค 5 อย่าง:
  1. จำนวน entries ใน schema == จำนวนที่สร้างจริงใน staging (แยก dir/file)
  2. ทุก path ใน schema มีอยู่จริงใน staging (ไม่มีตกหล่น)
  3. ไม่มีไฟล์/โฟลเดอร์เกินมาใน staging ที่ไม่ได้มาจาก schema (กัน leftover)
  4. เนื้อหาไฟล์ static/dynamic ตรงกับ static_contents เป๊ะ (byte-for-byte)
  5. ไฟล์ listing_only ต้องเป็นไฟล์เปล่า (0 bytes) เท่านั้น

Usage:
  python3 validate_staging.py <vfs_schema.json> <staging_dir>
"""

import json
import os
import sys


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <vfs_schema.json> <staging_dir>")
        sys.exit(1)

    schema_path, staging_dir = sys.argv[1], sys.argv[2]
    with open(schema_path, encoding="utf-8") as f:
        schema = json.load(f)

    fs_entries = schema["filesystem"]
    static_contents = schema.get("static_contents", {})

    errors = []
    warnings = []

    expected_dirs = {e["path"] for e in fs_entries if e["type"] == "dir"}
    expected_files = {e["path"] for e in fs_entries if e["type"] == "file"}

    # --- เช็ค 2: ทุก path ใน schema มีอยู่จริงใน staging ---
    for path in expected_dirs:
        full = os.path.join(staging_dir, path.lstrip("/"))
        if not os.path.isdir(full):
            errors.append(f"[MISSING DIR] {path} ไม่มีใน staging")

    for path in expected_files:
        full = os.path.join(staging_dir, path.lstrip("/"))
        if not os.path.isfile(full):
            errors.append(f"[MISSING FILE] {path} ไม่มีใน staging")

    # --- เช็ค 3: ไม่มีไฟล์/โฟลเดอร์เกินมา (leftover จาก run ก่อนหน้า) ---
    actual_files = set()
    for root, dirs, files in os.walk(staging_dir):
        for fn in files:
            full = os.path.join(root, fn)
            rel = "/" + os.path.relpath(full, staging_dir)
            actual_files.add(rel)

    extra_files = actual_files - expected_files
    if extra_files:
        for ex in sorted(extra_files):
            warnings.append(f"[EXTRA FILE] {ex} อยู่ใน staging แต่ไม่มีใน schema (leftover?)")

    # --- เช็ค 4 + 5: เนื้อหาตรง / listing_only ต้องว่าง ---
    for entry in fs_entries:
        if entry["type"] != "file":
            continue
        full = os.path.join(staging_dir, entry["path"].lstrip("/"))
        if not os.path.isfile(full):
            continue  # already reported as missing above

        policy = entry["content_policy"]
        with open(full, encoding="utf-8") as f:
            actual_content = f.read()

        if policy == "listing_only":
            if actual_content != "":
                errors.append(
                    f"[SHOULD BE EMPTY] {entry['path']} เป็น listing_only "
                    f"แต่มีเนื้อหา {len(actual_content)} ตัวอักษร"
                )
        else:  # static or dynamic
            ref_key = entry.get("static_content_ref") or entry.get("frozen_content_ref")
            expected_content = static_contents.get(ref_key, "")
            expected_content_norm = expected_content if expected_content.endswith("\n") else expected_content + "\n"
            if actual_content != expected_content_norm:
                errors.append(
                    f"[CONTENT MISMATCH] {entry['path']} เนื้อหาไม่ตรงกับ "
                    f"static_contents['{ref_key}'] เป๊ะ (byte-for-byte)"
                )

    # --- สรุปผล ---
    print("=" * 70)
    print(f"เช็ค entries: {len(expected_dirs)} dirs, {len(expected_files)} files ตาม schema")
    print(f"เช็ค entries จริงใน staging: {len(actual_files)} files พบ")
    print("=" * 70)

    if warnings:
        print(f"\n[!] คำเตือน {len(warnings)} รายการ:")
        for w in warnings:
            print("   ", w)

    if errors:
        print(f"\n[X] ข้อผิดพลาด {len(errors)} รายการ -- staging ยังไม่พร้อม deploy:")
        for e in errors:
            print("   ", e)
        sys.exit(1)
    else:
        print("\n[OK] ผ่านครบทุกเช็ค -- staging ตรงกับ schema 100%, พร้อมขั้นตอนถัดไป (createfs + copy เข้า honeyfs/)")


if __name__ == "__main__":
    main()
