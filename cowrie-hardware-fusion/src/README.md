# Source Layout

สร้าง Python package รุ่นแรกแล้วสำหรับ schema-validated dataset construction โดยยังไม่
มี training หรือ production inference code

ของที่ implement แล้ว:

- อ่าน completed run manifest และ immutable telemetry JSONL ได้หนึ่งหรือหลาย segment
- ตรวจ identity, boot, sequence, monotonic clock และ coverage
- สร้าง aggregate feature row สำหรับ XGBoost
- สร้าง fixed-length channel arrays พร้อม missing masks สำหรับ TCN
- สร้าง deterministic content hashes
- experimental `pi_sensor` neutral-idle collector ที่เขียน bounded immutable spool

ขอบเขต implementation ถัดไป:

- Pi deployment review, batch ingestion และ Cowrie command correlation adapters
- train-only preprocessing และ run-level split generator
- XGBoost baseline
- MiniROCKET/TCN experiments
- ModernBERT shadow feature adapter
- late-fusion training/evaluation
- Cloud shadow inference runtime
