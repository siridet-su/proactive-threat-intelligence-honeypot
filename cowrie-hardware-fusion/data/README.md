# Local Data Area

โฟลเดอร์นี้สงวนไว้สำหรับ dataset ที่สร้างจาก controlled experiments ข้อมูลจริงไม่ถูก
commit เข้า Git ตามค่าใน `.gitignore`

โครงสร้างที่คาดไว้:

```text
data/
├── raw/        immutable run manifests, Cowrie events และ telemetry
├── interim/    validated/aligned session windows
└── processed/  frozen model matrices และ split manifests
```

Dataset receipt, schema, hashes และ split membership ที่ไม่มีข้อมูลอ่อนไหวควรเก็บเป็น
versioned artifacts ภายใต้ `schemas/` หรือพื้นที่ receipt ที่จะกำหนดภายหลัง

