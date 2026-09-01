# Cowrie Hardware Fusion

พื้นที่พัฒนาสำหรับทดลองว่า command evidence จาก Cowrie เมื่อรวมกับ
hardware/process/network telemetry แล้วช่วยจำแนก resource-abuse behavior และ
MITRE ATT&CK TTP candidates ได้ดีขึ้นกว่า command-only baseline หรือไม่

## สถานะ

สถานะปัจจุบันคือ `PILOT DATASET TOOLING` มี dataset builder รุ่นแรกแล้ว แต่ยังไม่มี
โมเดลใหม่ที่ถือว่าผ่านการเทรนหรือพร้อม deploy

ข้อตกลงปัจจุบัน:

- Raspberry Pi 5 เป็น Cowrie sensor และ telemetry collector
- training และ inference หลักรันบน Cloud
- raw telemetry 1 Hz ใช้ dedicated Atlas time-series แบบ short TTL + bounded spool +
  cloud object storage และไม่ใช้ ordinary `hardware_metrics` เดิม
- ModernBERT เดิมเป็น frozen text baseline/candidate source
- XGBoost เป็น hardware-feature baseline
- TCN เป็น time-series candidate ที่ต้องพิสูจน์เทียบกับ baseline
- Fusion รวม text evidence กับ observed hardware impact
- ผลจากโมเดลใหม่เริ่มต้นเป็น shadow/audit-only
- ไม่ execute attacker-controlled malware, miner หรือ outbound DoS บน Pi

## โครงสร้าง

```text
cowrie-hardware-fusion/
├── configs/   experiment/model/runtime configuration ที่ content-bound
├── data/      local datasets; ไม่ commit raw/processed data
├── docs/      live-state และ SecureBERT review evidence ที่นำเข้ามา
├── schemas/   experiment, telemetry, label และ prediction schemas
├── src/       collector adapters, feature pipeline, models และ fusion runtime
└── tests/     schema, leakage, reproducibility และ model-contract tests
```

## ลำดับการพัฒนา

1. Freeze experiment contract และ label semantics
2. สร้าง telemetry schema พร้อม session/run correlation
3. **กำลังทำ:** เก็บและ replay pilot dataset ผ่าน dataset builder v1
4. สร้าง trivial baseline และ XGBoost hardware-only baseline
5. ทดลอง MiniROCKET/TCN บน split เดียวกัน
6. เลือก hardware branch จาก frozen evaluation protocol
7. เทรน Fusion ด้วย leakage-safe predictions/features
8. รัน Cloud shadow inference ก่อนพิจารณาการเชื่อม production

## เอกสารเริ่มต้น

- [Experiment contract v1](docs/experiment_contract.v1.md)
- [Dataset builder v1](docs/dataset_builder.v1.md)
- [XGBoost, TCN and Fusion architecture](docs/model_architecture_xgboost_tcn_fusion.v1.md)
- [Dataset split policy v1](docs/dataset_split_policy.v1.md)
- [Dataset storage plan v1](docs/dataset_storage_plan.v1.md)
- [Pi environment audit](docs/pi_environment_audit_2026-09-01.md)
- [Scenario catalog v1](configs/scenario_catalog.v1.json)
- [Run manifest schema](schemas/experiment_run_manifest.v1.schema.json)
- [Telemetry sample schema](schemas/hardware_telemetry_sample.v1.schema.json)
- [ModernBERT live state](docs/securebert_deep_review/securebert_modernbert_live_state.md)
- [Cowrie + hardware model plan](docs/securebert_deep_review/cowrie_hardware_multimodal_model_plan_live_state.md)
- [Imported review index](docs/README.md)
