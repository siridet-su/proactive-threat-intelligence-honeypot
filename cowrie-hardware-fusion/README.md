# Cowrie Hardware Fusion

พื้นที่พัฒนาสำหรับทดลองว่า command evidence จาก Cowrie เมื่อรวมกับ
hardware/process/network telemetry แล้วช่วยจำแนก resource-abuse behavior และ
MITRE ATT&CK TTP candidates ได้ดีขึ้นกว่า command-only baseline หรือไม่

## สถานะ

สถานะปัจจุบันคือ `DEVELOPMENT RUNTIME READY / FRESH PI RECEIPT NEXT` มี collector,
dataset builder, receipt-driven source index, grouped split generator และ fixed
safe-container runtime แล้ว Pi matrix จริงของ `T1496.001`/`T1499.002` สำเร็จ 15 runs
XGBoost smoke แยก compute simulation ได้แต่ service-exhaustion ยังไม่ผ่าน Protocol v2 จึง
เปลี่ยน hardware target เป็น observed impact, เพิ่ม matched benign controls และ lock final
test ก่อนเก็บข้อมูลใหม่ Common Go/Python metrics ผ่าน parity บน Pi 225/225 comparisons
และ experimental collector เพิ่ม host/target PSI, TCP pressure และ cgroup v2 observability
แล้ว pilot v1 ได้ 7 runs/630 valid samples แต่ไม่ผ่าน treatment gate ตอนนี้ collector
`0.4.2` และ matrix/spec v2 แก้ phase scheduling, compute duty-cycle semantics และเพิ่ม
service rejection/latency evidence gate แล้ว excluded pilot v2 ผ่าน 7/7 runs และ 630/630
valid samples และ dataset builder v2 เพิ่ม 13 aggregate features/6 TCN channels พร้อม
order hashes แล้ว และ freeze XGBoost 3 profiles/TCN 2 profiles พร้อม leakage/missingness
gates แล้ว และ generator สร้าง local development controls 70 runs โดยไม่เปิด calibration/
final test พร้อม runtime validate/preflight/collect/finalize ที่ matrix-bound แล้ว Read-only
Pi audit ผ่าน headroom/image/service gates แต่ Pi เพิ่ง reboot จึงต้อง capture environment
receipt ใหม่และ regenerate controls ก่อน preflight จริง; ยังไม่มีโมเดลใหม่ที่พร้อม deploy

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
10. **เสร็จ:** เพิ่ม service-pressure observability ใน collector 0.4.0 และยืนยัน host/target
    no-sink canary บน Pi
11. **เสร็จ tooling:** สร้าง hash-bound matrix/spec/signal-report สำหรับ 7-scenario
    instrumentation pilot และขยาย fail-closed allowlist ใน collector 0.4.1
12. **เสร็จ pilot:** รัน 7 excluded scenarios ได้ 630/630 valid samples; hashes/cleanup
    ผ่าน แต่พบ compute inverse-throttling artifact และ service queue/drop/TCP pressure เป็นศูนย์
13. **เสร็จ tooling v2:** reset phase deadline หลัง lifecycle hook, compute ใช้ duty 25/75%
    ภายใต้เพดาน 1 CPU เดียวกัน และ service ใช้ bounded capacity/503/latency evidence gate
14. **เสร็จ pilot v2:** ARM64 image/runtime/evidence gates ผ่าน 7/7 scenarios และ
    630/630 valid samples; late/missing/error/reset เป็นศูนย์
15. **เสร็จ builder v2:** เพิ่ม pilot-proven host/cgroup/TCP aggregates และ TCN channels,
    feature/channel order hashes และ replay raw pilot ผ่าน 7/7
16. **เสร็จ:** freeze model feature contract v1: XGBoost 25/51/66 features, TCN 14/22
    channels, forbidden leakage inputs, mask policy และ audit-only claim
17. **เสร็จ tooling:** deterministic development matrix 70 runs, 2 planned day slots,
    schema/hash/claim gates; local control set generated และ final-test 35 runs ยังปิด
18. **เสร็จ tooling:** matrix-wide validator และ development-specific
    preflight/collect/finalize dispatch สำหรับ controlled/idle
19. **ลำดับถัดไป:** capture fresh Pi environment receipt, regenerate controls และทำ
    no-collection preflight
20. ทดลอง MiniROCKET/TCN เมื่อ XGBoost v2 และ independent-run gate ผ่าน
21. เลือก hardware branch จาก frozen evaluation protocol
22. เทรน Fusion ด้วย leakage-safe out-of-fold predictions/features
23. รัน Cloud shadow inference ก่อนพิจารณาการเชื่อม production

## เอกสารเริ่มต้น

- [Experiment contract v1](docs/experiment_contract.v1.md)
- [Dataset builder v1](docs/dataset_builder.v1.md)
- [Dataset builder v2](docs/dataset_builder.v2.md)
- [Model feature contract v1](docs/model_feature_contract.v1.md)
- [Hardware-impact development wave v1](docs/hardware_impact_development_wave.v1.md)
- [Experimental 1 Hz collector v1](docs/experimental_collector.v1.md)
- [XGBoost, TCN and Fusion architecture](docs/model_architecture_xgboost_tcn_fusion.v1.md)
- [Dataset split policy v1](docs/dataset_split_policy.v1.md)
- [Bounded workload contract v1](docs/bounded_workload_contract.v1.md)
- [Pi safe-container PoC runbook v1](docs/pi_poc_runbook.v1.md)
- [Pi two-TTP PoC result — 2026-09-02](docs/pi_poc_results_2026-09-02.md)
- [Hardware-impact experiment protocol v2](docs/hardware_impact_experiment_protocol.v2.md)
- [Hardware Go Agent feature-parity audit](docs/hardware_agent_feature_parity_2026-09-02.md)
- [Service-pressure observability v1](docs/service_pressure_observability.v1.md)
- [Service-pressure instrumentation pilot v1](docs/service_pressure_instrumentation_pilot.v1.md)
- [Service-pressure instrumentation result](docs/service_pressure_instrumentation_results_2026-09-02.md)
- [Service-pressure treatment revision v2](docs/service_pressure_treatment_revision.v2.md)
- [Service-pressure v2 pilot result](docs/service_pressure_v2_pilot_results_2026-09-03.md)
- [Dataset storage plan v1](docs/dataset_storage_plan.v1.md)
- [Pi environment audit](docs/pi_environment_audit_2026-09-01.md)
- [Stage A idle pilot report](docs/pilot_idle_collection_2026-09-01.md)
- [Scenario catalog v1](configs/scenario_catalog.v1.json)
- [Run manifest schema](schemas/experiment_run_manifest.v1.schema.json)
- [Telemetry sample schema](schemas/hardware_telemetry_sample.v1.schema.json)
- [ModernBERT live state](docs/securebert_deep_review/securebert_modernbert_live_state.md)
- [Cowrie + hardware model plan](docs/securebert_deep_review/cowrie_hardware_multimodal_model_plan_live_state.md)
- [Imported review index](docs/README.md)
