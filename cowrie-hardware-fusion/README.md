# Cowrie Hardware Fusion

พื้นที่พัฒนาสำหรับทดลองว่า command evidence จาก Cowrie เมื่อรวมกับ
hardware/process/network telemetry แล้วช่วยจำแนก resource-abuse behavior และ
MITRE ATT&CK TTP candidates ได้ดีขึ้นกว่า command-only baseline หรือไม่

## สถานะ

สถานะปัจจุบันคือ `PROTOCOL V2 FROZEN + COMMON-METRIC PARITY PASSED` มี collector,
dataset builder, receipt-driven source index, grouped split generator และ fixed
safe-container runtime แล้ว Pi matrix จริงของ `T1496.001`/`T1499.002` สำเร็จ 15 runs
XGBoost smoke แยก compute simulation ได้แต่ service-exhaustion ยังไม่ผ่าน Protocol v2 จึง
เปลี่ยน hardware target เป็น observed impact, เพิ่ม matched benign controls และ lock final
test ก่อนเก็บข้อมูลใหม่ Common Go/Python metrics ผ่าน parity บน Pi 225/225 comparisons
แต่ Go Agent ยังไม่ใช่ full dataset collector และยังไม่มีโมเดลใหม่ที่พร้อม deploy

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
3. **เสร็จ Stage A:** เก็บ/replay neutral-idle pilot 3 runs ผ่าน dataset builder v1
4. **เสร็จ tooling:** fixed ARM64 safe-container workload + Pi preflight/runtime receipts
5. **เสร็จ tooling:** สร้าง verified source index และ grouped split generator
6. **เสร็จ PoC:** เก็บ interleaved idle/benign/TTP Pi 15 runs, 1,350 valid samples
7. **เสร็จ smoke:** XGBoost repetition-held-out; T1496.001 ผ่าน 3/3, T1499.002 ไม่ผ่าน 0/3
8. **เสร็จ:** freeze protocol v2 สำหรับ 7 matched scenarios/140 planned runs และ lock
   final-test wave 35 runs
9. **เสร็จ:** audit common Go/Python metrics บน Pi ผ่าน 225/225 comparisons แบบ no-sink
10. **ลำดับถัดไป:** เพิ่ม service-pressure observability/local-spool adapter แล้วเก็บเฉพาะ
    development wave 70 runs ก่อนหยุด review signal
11. ทดลอง MiniROCKET/TCN เมื่อ XGBoost v2 และ independent-run gate ผ่าน
12. เลือก hardware branch จาก frozen evaluation protocol
13. เทรน Fusion ด้วย leakage-safe out-of-fold predictions/features
14. รัน Cloud shadow inference ก่อนพิจารณาการเชื่อม production

## เอกสารเริ่มต้น

- [Experiment contract v1](docs/experiment_contract.v1.md)
- [Dataset builder v1](docs/dataset_builder.v1.md)
- [Experimental 1 Hz collector v1](docs/experimental_collector.v1.md)
- [XGBoost, TCN and Fusion architecture](docs/model_architecture_xgboost_tcn_fusion.v1.md)
- [Dataset split policy v1](docs/dataset_split_policy.v1.md)
- [Bounded workload contract v1](docs/bounded_workload_contract.v1.md)
- [Pi safe-container PoC runbook v1](docs/pi_poc_runbook.v1.md)
- [Pi two-TTP PoC result — 2026-09-02](docs/pi_poc_results_2026-09-02.md)
- [Hardware-impact experiment protocol v2](docs/hardware_impact_experiment_protocol.v2.md)
- [Hardware Go Agent feature-parity audit](docs/hardware_agent_feature_parity_2026-09-02.md)
- [Dataset storage plan v1](docs/dataset_storage_plan.v1.md)
- [Pi environment audit](docs/pi_environment_audit_2026-09-01.md)
- [Stage A idle pilot report](docs/pilot_idle_collection_2026-09-01.md)
- [Scenario catalog v1](configs/scenario_catalog.v1.json)
- [Run manifest schema](schemas/experiment_run_manifest.v1.schema.json)
- [Telemetry sample schema](schemas/hardware_telemetry_sample.v1.schema.json)
- [ModernBERT live state](docs/securebert_deep_review/securebert_modernbert_live_state.md)
- [Cowrie + hardware model plan](docs/securebert_deep_review/cowrie_hardware_multimodal_model_plan_live_state.md)
- [Imported review index](docs/README.md)
