# Local Data Area

โฟลเดอร์นี้สงวนไว้สำหรับ dataset ที่สร้างจาก controlled experiments ข้อมูลจริงไม่ถูก
commit เข้า Git ตามค่าใน `.gitignore`

canonical raw-run layout ที่ `index-dataset` ตรวจได้:

```text
data/
├── raw/
│   └── run=<run-id>/
│       ├── manifest.json
│       └── scope=<metric-scope>/
│           ├── collection-receipt.json
│           └── part-*.jsonl
├── interim/    validated/aligned session windows
└── processed/  frozen model matrices และ split manifests
```

`manifest.json` ต้องเป็น completed manifest ที่ cite receipt ทุก scope ส่วน segment files
ยัง immutable/content-addressed ตาม receipt ห้าม concatenate หรือ rename เพื่อทำ batch

Dataset receipt, schema, hashes และ split membership ที่ไม่มีข้อมูลอ่อนไหวควรเก็บเป็น
versioned artifacts ภายใต้ `schemas/` หรือพื้นที่ receipt ที่จะกำหนดภายหลัง
