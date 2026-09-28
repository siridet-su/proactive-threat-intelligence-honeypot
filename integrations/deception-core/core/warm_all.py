"""
warm_all.py — bootstrap: เรียก prefetch_worker.warm_tier() ครบทุก (door, mode, tier) กลุ่ม A รอบ
เดียวตอน deploy (กัน attacker คนแรกสุดเจอ cold-start ก่อน background trigger ทัน) ใช้โค้ดเดียวกับ
prefetch_worker.py เป๊ะ ไม่ implement ซ้ำ — รันครั้งเดียวตอน deploy/ตอนต้องการ warm ใหม่ทั้งหมด
(เช่น หลังแก้ schema/prompt แล้วอยาก regenerate)

**door="ftp" ต้องพึ่งสคริปต์นี้เท่านั้น** (ไม่มี background trigger เป็นของตัวเอง เพราะ FTP ไม่เคย
เรียก /v1/track — ดู prefetch_worker.py หัวไฟล์) — ถ้าลืมรันสคริปต์นี้หลัง deploy ใหม่ FTP lure
จะ fallback ตลอดไปจนกว่าจะรันสคริปต์นี้ครั้งหนึ่ง

รัน: docker exec -w /app <deception-core container> python3 warm_all.py

ถ้าอยาก force regenerate ใหม่ทั้งหมด (ไม่ resume จากของเดิม) ให้ clear ตาราง template_content +
warm_status ก่อนรัน (ดู docs/reports/pi_stageB_pregen_2026-08-23.md สำหรับตัวอย่างคำสั่ง SQL)
"""

import sys
import time

import prefetch_worker as pw

TIERS = (1, 2, 3)
DOOR_MODES = [
    (pw.SSH_DOOR, "bash"),
    (pw.SSH_DOOR, "psql"),
    (pw.FTP_DOOR, "bash"),
]


def main() -> int:
    t0 = time.time()
    ok = True
    for door, mode in DOOR_MODES:
        for tier in TIERS:
            print(f"warming door={door} mode={mode} tier={tier} ...", flush=True)
            try:
                pw.warm_tier(door, mode, tier)
                print(f"  done in {time.time()-t0:.1f}s (cumulative)", flush=True)
            except Exception as e:
                ok = False
                print(f"  FAILED: {e}", flush=True)
    print(f"warm_all finished in {time.time()-t0:.1f}s total, ok={ok}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
