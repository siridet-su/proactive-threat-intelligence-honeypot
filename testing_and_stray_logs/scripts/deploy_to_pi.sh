#!/bin/bash
# deploy_to_pi.sh — รันบนเครื่อง Pi จริงเท่านั้น (ขั้นตอน 4-5 ของ workflow)
#
# ทำ:
#   1. สำรอง fs.pickle เดิมไว้ก่อน (กันพลาดย้อนกลับไม่ได้)
#   2. รัน bin/createfs สร้าง fs.pickle ใหม่จาก staging/
#   3. copy เฉพาะไฟล์ static+dynamic (ตาม manifest) เข้า honeyfs/
#
# Usage (รันจาก /home/cowrie/cowrie เท่านั้น):
#   ./deploy_to_pi.sh <path/to/staging> <path/to/staging_manifest.json>

set -euo pipefail

STAGING_DIR="${1:?ต้องระบุ path ของ staging directory}"
MANIFEST_FILE="${2:?ต้องระบุ path ของ staging_manifest.json}"

COWRIE_ROOT="/home/cowrie/cowrie"
FS_PICKLE="$COWRIE_ROOT/src/cowrie/data/fs.pickle"
HONEYFS_DIR="$COWRIE_ROOT/honeyfs"
BACKUP_DIR="$COWRIE_ROOT/backups/fs_pickle_$(date +%Y%m%dT%H%M%SZ)"

if [ ! -d "$COWRIE_ROOT" ]; then
    echo "[X] ไม่พบ $COWRIE_ROOT -- สคริปต์นี้ต้องรันบนเครื่อง Pi จริงเท่านั้น"
    exit 1
fi

echo "[*] ขั้นตอน 1/3: สำรอง fs.pickle เดิม"
mkdir -p "$BACKUP_DIR"
if [ -f "$FS_PICKLE" ]; then
    cp "$FS_PICKLE" "$BACKUP_DIR/fs.pickle.bak"
    echo "    สำรองไว้ที่: $BACKUP_DIR/fs.pickle.bak"
else
    echo "    [!] ไม่พบ fs.pickle เดิม (อาจเป็นการ deploy ครั้งแรก) ข้ามการสำรอง"
fi

echo "[*] ขั้นตอน 2/3: รัน bin/createfs สร้าง fs.pickle ใหม่"
cd "$COWRIE_ROOT"
# -l = ที่มาของ filesystem จริง, -o = output pickle path
# depth ไม่ต้องระบุ createfs จะไล่ recursive เองตาม staging ที่มีให้
./bin/createfs -l "$STAGING_DIR" -o "$FS_PICKLE"
echo "    สร้างสำเร็จ: $FS_PICKLE"

echo "[*] ขั้นตอน 3/3: copy ไฟล์ static+dynamic เข้า honeyfs/"
python3 - "$STAGING_DIR" "$MANIFEST_FILE" "$HONEYFS_DIR" << 'PYEOF'
import json, os, shutil, sys

staging_dir, manifest_file, honeyfs_dir = sys.argv[1], sys.argv[2], sys.argv[3]

with open(manifest_file, encoding="utf-8") as f:
    manifest = json.load(f)

copied = 0
for rel_path in manifest:
    src = os.path.join(staging_dir, rel_path.lstrip("/"))
    dst = os.path.join(honeyfs_dir, rel_path.lstrip("/"))
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(src, dst)
    copied += 1

print(f"    copy สำเร็จ {copied} ไฟล์เข้า {honeyfs_dir}")
PYEOF

echo
echo "[OK] Deploy เสร็จสมบูรณ์"
echo "    ต่อไป: restart cowrie service แล้วทดสอบ SSH เข้าไป ls/cat ไฟล์จริง"
echo "    ถ้ามีปัญหา ย้อนกลับได้จาก: $BACKUP_DIR/fs.pickle.bak"
