FROM python:3.11-slim

WORKDIR /app

COPY core/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# core/ และ shared/ ถูก flatten ลง /app เดียวกันตอน build เพื่อให้ import ตรงๆ
# (import session_prompt_builder แบบเดียวกับที่ colab_upload/3_serve/server.py ทำ)
# ไม่ต้องพึ่ง sys.path hack หรือ package structure เพิ่ม
COPY core/*.py ./
COPY shared/*.py ./
COPY shared/payoff_matrices.json .

# add 2026-09-08: adapter import signal_extractor+classifier+ip_reputation+zeek_hassh
# source lives in type-classi/Honeypot_ML/ (single source of truth) -> bake into /app at build
# P7 (2026-09-19): +attack_mapping.py (ATT&CK tactic mapping — attacker_classifier import
# attack_breadth; signal_extractor lazy-import ด้วย). ต้อง bake ไม่งั้น import พังเงียบ→fallback สุ่ม
# P8 (2026-09-19): +sigma_rules.py (session_store import — one-way upgrade SK/Bot->APT). ต้อง bake ด้วย
COPY type-classi/Honeypot_ML/classifier.py type-classi/Honeypot_ML/signal_extractor.py type-classi/Honeypot_ML/ip_reputation.py type-classi/Honeypot_ML/zeek_hassh.py type-classi/Honeypot_ML/attack_mapping.py type-classi/Honeypot_ML/sigma_rules.py ./

# เพิ่ม 2026-08-23: prefetch_worker.py อ่าน schema สองไฟล์นี้ตรงๆ (single source of truth —
# deterministic schema-fact injection ไม่ใช่ RAG/vector search) — bake เข้า image ตอน build
# เหมือนไฟล์อื่น (เปลี่ยน schema ต้อง rebuild image เหมือนโค้ด ยอมรับ trade-off นี้แทนการเพิ่ม
# volume mount ซ้อนกับ deception-data:/data ที่มีอยู่แล้ว)
COPY vfs_schema_updated_2026-07-22.json .
# เปลี่ยน 2026-08-26 (Part 1): psql_decoy_schema.json (6 ตารางเก่า) ลบทิ้งแล้ว
# (docs/reports/pi_part1_realdb_cleanup_2026-08-26.md) แทนที่ด้วยไฟล์ Part 1
COPY psql_decoy_schema_part1_realdb.json .
# เพิ่ม 2026-08-30 (Part 2): phase_adaptive.py อ่าน schema นี้ตรงๆ (single source of truth)
COPY vfs_schema_part2_phase_adaptive.json .

EXPOSE 9000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "9000"]
