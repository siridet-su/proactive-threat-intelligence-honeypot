# Source Layout

สร้าง Python package สำหรับ schema-validated dataset construction และ audit-only XGBoost
smoke evaluation แล้ว โดยยังไม่มี production inference code

ของที่ implement แล้ว:

- อ่าน completed run manifest และ immutable telemetry JSONL ได้หนึ่งหรือหลาย segment
- ตรวจ identity, boot, sequence, monotonic clock และ coverage
- สร้าง aggregate feature row สำหรับ XGBoost
- สร้าง fixed-length channel arrays พร้อม missing masks สำหรับ TCN
- สร้าง deterministic content hashes
- experimental `pi_sensor` neutral-idle collector ที่เขียน bounded immutable spool
- สร้าง verified dataset source index จาก completed manifest/receipt/raw segments
- สร้าง deterministic grouped split ที่ exclude pilot และกัน connected groups ข้าม split
- ตรวจ bounded ordinary-workload contract สำหรับ disposable backend โดยไม่ execute
- รัน XGBoost PoC ด้วย repetition-held-out folds พร้อม hash-bound report/model artifacts

ขอบเขต implementation ถัดไป:

- authenticated batch upload และ Cowrie command correlation adapters
- disposable backend runtime/telemetry adapters หลัง review execution boundary
- train-only preprocessing
- production-eligible XGBoost baseline หลังเพิ่ม independent data
- MiniROCKET/TCN experiments
- ModernBERT shadow feature adapter
- late-fusion training/evaluation
- Cloud shadow inference runtime
