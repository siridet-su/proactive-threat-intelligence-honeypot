import os

DB_PATH = os.environ.get("DECEPTION_DB_PATH", "/data/deception.db")
EVENTS_PATH = os.environ.get("DECEPTION_EVENTS_PATH", "/data/events.jsonl")
MODEL_ENDPOINT = os.environ.get("MODEL_ENDPOINT_URL", "")
MODEL_TIMEOUT_S = float(os.environ.get("MODEL_TIMEOUT_S", "8"))

# ทดลอง 2026-08-18: route mode="bash" ไป Hailo-10H บน Pi แทน Colab (psql ยังไป Colab
# เหมือนเดิม เพราะ Hailo psql พัง 0% ตาม docs/reports/lora_hef_quality_recheck_2026-08-16.md)
# ว่าง = ปิดฟีเจอร์นี้ ตกกลับไปใช้ MODEL_ENDPOINT (Colab) เหมือนเดิมทุกกรณี — ดู
# docs/reports/pi_hailo_bash_route_2026-08-18.md
MODEL_ENDPOINT_BASH_HAILO = os.environ.get("MODEL_ENDPOINT_URL_BASH_HAILO", "")
MODEL_TIMEOUT_S_HAILO = float(os.environ.get("MODEL_TIMEOUT_S_HAILO", "30"))

# เพิ่ม 2026-08-23: prefetch_worker.py เรียก hailo-ollama (โมเดลสำเร็จรูปของ Hailo, ไม่
# fine-tune — ดู docs/reports/pi_stageB_pregen_2026-08-23.md) รันอยู่บน Pi host พอร์ต 8000
# container นี้อยู่ custom bridge network (decoy-honeypot_internal, ไม่ใช่ docker0 default) —
# `host.docker.internal` resolve ผิดเป็น docker0 gateway (172.17.0.1) ต้องใช้ gateway ของ
# custom bridge ตรงๆ (172.18.0.1 — ยืนยันจาก `docker network inspect` จริง 2026-08-23) แพทเทิร์น
# เดียวกับบั๊กที่เจอมาก่อนแล้วตอนทำ hailo_serve.py bash route (pi_hailo_bash_route_2026-08-18.md
# หัวข้อ 7) + ต้องเปิด ufw ให้ subnet นี้เข้าพอร์ต 8000 ด้วย (เพิ่มแล้ว, scoped rule)
HAILO_OLLAMA_URL = os.environ.get("HAILO_OLLAMA_URL", "http://172.18.0.1:8000")
HAILO_OLLAMA_MODEL = os.environ.get("HAILO_OLLAMA_MODEL", "qwen2.5:1.5b")
HAILO_OLLAMA_TIMEOUT_S = float(os.environ.get("HAILO_OLLAMA_TIMEOUT_S", "90"))

# เพิ่ม 2026-08-26 (ดู docs/reports/pi_prepared_response_qc_fix_2026-08-26.md): psql decoy
# tables ย้ายจาก "AI แต่ง text เลียนแบบ psql output" -> "AI generate ค่า, insert เข้า Postgres
# จริง schema `decoy`, ให้ psql ตัวจริงจัดฟอร์แมต" — deception-core อยู่บน network เดียวกับ
# postgres container (decoy-honeypot_internal) resolve ชื่อ "postgres" ได้ตรงๆ (ไม่ต้องผ่าน
# gateway IP แบบ hailo-ollama)
PG_HOST = os.environ.get("PGHOST", "postgres")
PG_PORT = int(os.environ.get("PGPORT", "5432"))
PG_DBNAME = os.environ.get("PGDATABASE", "odoo_production")
PG_USER = os.environ.get("PGUSER", "odoo")
PG_PASSWORD = os.environ.get("PGPASSWORD", "")

# เพิ่ม 2026-09-02 (roleplay_audit_remediation finding C1): schema Postgres ที่เก็บตาราง decoy ของ
# Part 1/2 ทั้งหมด — เดิมชื่อ "decoy" ตรงๆ (`\dt` โชว์ schema ชื่อนี้ให้ attacker เห็นทันที = เปิดโปง
# ตัวเอง) ย้ายมาเป็น single source of truth ที่นี่ (CLAUDE.md §5) ให้ login_decoy.py/phase_adaptive.py
# import ค่าเดียวกัน แทนพิมพ์ literal "decoy" ซ้ำ 2 ที่เหมือนเดิม
# ⚠️ cowrie_patches/psql.py (ฝั่ง Cowrie) เป็นคนละ process/container กัน import ตรงๆ ไม่ได้ — ต้อง
# แก้ค่า hardcode ที่นั่นเองด้วยมือให้ตรงกับค่านี้เสมอเวลาเปลี่ยน (ดู comment ที่ psql.py)
DECOY_SCHEMA_NAME = os.environ.get("DECOY_SCHEMA_NAME", "reporting")
