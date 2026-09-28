"""
events.py — event log 1 บรรทัดต่อคำสั่ง (JSONL) ตาม docs/10_system_concept_3day.md §5
ใช้คำนวณ dwell time / จำนวนครั้งที่ gate ปลด / latency แยกตามผู้ตอบ ทีหลัง
"""

import json
import os
import threading
import time

from config import EVENTS_PATH

_lock = threading.Lock()


def log_event(**fields) -> None:
    fields.setdefault("ts", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    line = json.dumps(fields, ensure_ascii=False)
    with _lock:
        os.makedirs(os.path.dirname(EVENTS_PATH), exist_ok=True)
        with open(EVENTS_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
