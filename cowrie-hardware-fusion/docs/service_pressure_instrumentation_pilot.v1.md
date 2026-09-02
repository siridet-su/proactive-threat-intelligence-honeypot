# Service-pressure instrumentation pilot v1

> สถานะ: `SUPERSEDED BY COMPLETED RESULT / SERVICE-TREATMENT GATE NOT PASSED`
> วันที่: `2026-09-02`
> ขอบเขต: 7 runs สำหรับตรวจ signal เท่านั้น, `pilot_only=true`, ห้ามใช้ train

## สิ่งที่ pilot นี้ตอบ

Pilot นี้ตรวจว่า metric service-pressure ที่ collector `0.4.x` เพิ่มเข้ามามี coverage และ
เปลี่ยนแปลงตาม workload จริงหรือไม่ ก่อนตัดสินใจแก้ frozen feature profile ของ XGBoost
มันไม่ใช่ development dataset และผล 7 runs นี้ห้ามนำไปคำนวณ model accuracy

Matrix ผูกกับ canonical protocol hash, scenario-catalog bytes, collector source, telemetry
schema, ARM64 image, workload binary, repository commit และ Pi environment signature ทุก
manifest เป็น `pilot_only=true`, `production_analytics_eligible=false`; matrix ระบุซ้ำว่า
`training_eligible=false` และ `changes_frozen_feature_set=false`

Tooling identity หลัง implementation:

- collector `0.4.1` source SHA-256:
  `f56cce1858f3d604e5e298258fc0d1af076fafaf03d9e3a6c17ae454e291d1a3`
- telemetry schema SHA-256:
  `b99697c8f92f8b45c70b9328e52156dab5fc7b30118ecba4b43809abef1a4d4e`
- scenario catalog byte SHA-256:
  `8793acf7a1ddddac22ce864cbbb9c45a1277891bf5e598d73d7a63ec85ad0ec9`
- frozen protocol canonical SHA-256:
  `8eb0786e8427f7fa685a8d137db62b1ecfff40a7897b65f742915477b9b2471d`

## Matrix 7 scenarios

| ลำดับ | Scenario | Treatment | Hardware target | TTP metadata |
|---:|---|---|---|---|
| 1 | `v2_neutral_idle` | ไม่มี workload | `NO_MATERIAL_IMPACT` | — |
| 2 | `v2_benign_compute_low` | 25% assigned CPU | `NO_MATERIAL_IMPACT` | — |
| 3 | `v2_benign_compute_high` | 75% assigned CPU | `COMPUTE_SATURATION` | — |
| 4 | `v2_t1496_001_compute_high` | 75% assigned CPU | `COMPUTE_SATURATION` | `T1496.001` |
| 5 | `v2_benign_service_low` | 10 requests/s | `NO_MATERIAL_IMPACT` | — |
| 6 | `v2_benign_service_high` | 150 requests/s | `SERVICE_PRESSURE` | — |
| 7 | `v2_t1499_002_service_high` | 150 requests/s | `SERVICE_PRESSURE` | `T1499.002` |

คู่ compute-high และ service-high ใช้ family, limits และ workload parameters เหมือนกันทุก
อย่างยกเว้น deterministic seed เพื่อไม่ให้ hardware model เรียน malicious intent จาก
treatment metadata ทั้ง TTP และ disposition เป็น evaluation metadata เท่านั้น

`protocol_intensity=150` ของ service มีหน่วย `requests_per_second` ไม่ใช่ CPU 150% ส่วน
`manifest.workload.intensity_percent` ของ service คือสัดส่วน assigned service capacity
25/75 ตามข้อจำกัด schema เดิม Raw CPU ที่เก็บยังเป็น continuous 0–100 และไม่แบ่ง rank

แต่ละ run เก็บ baseline/workload/recovery 30/30/30 วินาทีที่ 1 Hz รวม 90 samples; ทั้ง
matrix คือ 7 runs, 630 samples และเวลาวัดอย่างน้อย 630 วินาที ไม่รวม preflight/cooldown

## Safety boundary

- ใช้ static reviewed ARM64 image และ fixed entrypoint เดิม ไม่มี raw Cowrie command
- workload compute คือ bounded hashing/CPU work โดยไม่มี mining protocol
- workload service คือ HTTP server/client บน loopback ภายใน container เดียว
- Docker `network=none`, read-only rootfs, UID/GID 65532, drop all capabilities,
  no-new-privileges และ default seccomp
- จำกัด CPU 0.25/0.75 core, RAM 128 MiB, PID 16, output 4 KiB และ watchdog 40 วินาที
- ไม่ใช้ public VPS/WireGuard ingress, malware, miner, third-party target, Redis, MongoDB
  หรือ Atlas ใน instrumentation matrix นี้

## Artifact generation

หลัง freeze commit และตรวจ image/environment identity จริง ให้รันจาก project venv:

```bash
cowrie-hardware-dataset prepare-service-pressure-pilot \
  --experiment-id service-pressure-instrumentation-v1 \
  --generation v1 \
  --image-id sha256:<64-hex> \
  --implementation-sha256 <64-hex> \
  --repo-commit <40-hex> \
  --environment-signature-sha256 <64-hex> \
  --config configs/experimental_collector.pi_sensor.pilot.example.json \
  --protocol configs/hardware_impact_experiment_protocol.v2.json \
  --scenario-catalog configs/scenario_catalog.v1.json \
  --output-dir <new-control-directory>
```

คำสั่งใช้ exclusive create: ถ้า output directory มีอยู่แล้วจะ fail แทนการ overwrite
ผลลัพธ์มี `matrix.json`, planned manifest 7 ไฟล์ และ controlled workload spec 6 ไฟล์

## Pi execution flow

Neutral idle ใช้ `collector-preflight`, `collect-idle-run` และ
`finalize-idle-manifest` เดิม ส่วน controlled scenarios ใช้คำสั่งใหม่:

```bash
cowrie-hardware-dataset service-pressure-pilot-preflight \
  --manifest <planned-manifest.json> \
  --config <pi-collector-config.json> \
  --specification <workload-spec.json> \
  --protocol configs/hardware_impact_experiment_protocol.v2.json \
  --scenario-catalog configs/scenario_catalog.v1.json

cowrie-hardware-dataset collect-service-pressure-pilot-run \
  --manifest <planned-manifest.json> \
  --config <pi-collector-config.json> \
  --specification <workload-spec.json> \
  --protocol configs/hardware_impact_experiment_protocol.v2.json \
  --scenario-catalog configs/scenario_catalog.v1.json
```

หลัง collection/execution receipts ผ่าน ให้ใช้
`finalize-service-pressure-pilot-manifest` สร้าง completed manifest โดยไม่แก้ planned
ต้นฉบับ Runtime จะลบ container หลัง workload phase และ fail หาก cleanup ยืนยันไม่ได้

## Candidate signal report

หลัง transfer และ verify segment SHA-256 แล้ว สร้าง report ต่อ run:

```bash
cowrie-hardware-dataset summarize-service-pressure-signals \
  --manifest <completed-manifest.json> \
  --collection-receipt <collection-receipt.json> \
  --telemetry <part-*.jsonl> \
  --output <signal-report.json>
```

Report สรุป coverage/mean/p95/max แยก baseline, workload, recovery และคำนวณ
baseline→workload delta สำหรับ host metrics โดยครอบคลุม:

- host CPU/memory/I/O PSI
- host TCP states, socket allocation และ queue/drop/memory-pressure rates
- target network-namespace TCP states/socket/drop rates
- target cgroup CPU usage/throttling, memory/PID/I/O และ cgroup PSI

Target process/cgroup ไม่มีอยู่ใน baseline ตาม design จึงรายงาน workload availability แต่
ไม่สร้าง baseline delta ปลอม Signal ผ่านเข้าสู่ feature-freeze review เมื่อ workload coverage
อย่างน้อย 90%; host signal ต้องมี baseline coverage อย่างน้อย 90% ด้วย

Report ผูก manifest และ segment byte hashes แต่มี
`model_feature_eligible=false` เสมอ Scenario/TTP/label อยู่ใน `evaluation_context` และระบุ
ชัดว่า excluded from candidate values การเลือก feature จริงต้องพิจารณาครบทั้ง 7 reports,
document selection rule แล้ว freeze protocol/feature revision ใหม่ก่อนเริ่ม 70 development
runs

## Implemented artifacts

- `src/cowrie_hardware_fusion/instrumentation.py`
- `schemas/service_pressure_instrumentation_matrix.v1.schema.json`
- `schemas/service_pressure_workload_spec.v1.schema.json`
- `schemas/service_pressure_signal_report.v1.schema.json`
- CLI prepare/preflight/collect/finalize/summarize commands
- automated matrix, matched-pair และ signal-summary tests

Pilot รันครบแล้ว ผลจริงและ gate decision อยู่ที่
[service_pressure_instrumentation_results_2026-09-02.md](service_pressure_instrumentation_results_2026-09-02.md)
