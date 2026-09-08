# Service-pressure treatment revision v2

> สถานะ: `IMPLEMENTED / EXCLUDED PI RERUN PASS`
> วันที่: `2026-09-02`
> ขอบเขต: แก้ข้อบกพร่องของ excluded instrumentation pilot v1; ยังห้ามใช้ train

## เหตุผลที่ต้องมี v2

Pilot v1 เก็บ telemetry ได้ครบ 630/630 samples แต่ยังพิสูจน์ treatment ไม่ได้สองจุด:

- compute-low ใช้ full duty ใต้ quota 0.25 core จึงมี throttling/PSI สูงกว่า high ที่ quota
  0.75 core เป็นผลจากตัวจำลอง ไม่ใช่ความหมาย low/high ที่ต้องการ
- service-high เพิ่ม CPU work แต่ TCP connections คงที่และไม่เกิด queue drop/error ทำให้ยัง
  อ้าง `SERVICE_PRESSURE` จาก workload ที่เกิดขึ้นจริงไม่ได้

นอกจากนี้ Docker lifecycle hook ใช้เวลาหลังตั้ง sample deadline แล้ว ทำให้ workload sample
แรกของ service-low ถูกบันทึก late 1 จุด

## Treatment ที่แก้แล้ว

### Compute

Low/high ใช้ hard ceiling เท่ากันที่ `1.0 CPU`, worker 1 ตัว และ period 100 ms ต่างกันเฉพาะ
duty cycle:

| Scenario | Duty | CPU ceiling | เป้าหมาย |
|---|---:|---:|---|
| benign compute low | 25% | 1.0 core | `NO_MATERIAL_IMPACT` |
| benign compute high | 75% | 1.0 core | `COMPUTE_SATURATION` |
| T1496.001 matched simulation | 75% | 1.0 core | `COMPUTE_SATURATION` |

วิธีนี้ลด inverse-throttling artifact เพราะ low/high ไม่ได้เปลี่ยน quota boundary คู่
benign-high/T1496.001 ยังใช้ hardware treatment เหมือนกันทุก field ยกเว้น seed

### Service

Service runner ยังคงเป็น HTTP loopback ภายใน container ที่ `network=none` แต่ v2 เพิ่ม:

- `connection_mode=close` เพื่อให้แต่ละ request เป็น short-lived TCP connection
- client concurrency สูงสุด 8 และ server capacity 2
- accepted request หน่วงแบบ bounded 40 ms แล้วทำ hash work 500 iterations
- low = 10 requests/s; high/T1499.002 = 150 requests/s
- เมื่อ capacity เต็ม server ตอบ 503 ทันที ไม่มี outbound target และไม่มี packet flood

Low อยู่ต่ำกว่าความจุโดยประมาณ 50 requests/s ส่วน high สูงกว่าความจุประมาณ 3 เท่า จึงควร
สร้าง TCP churn และ degradation ที่ตรวจได้ โดยยังถูกจำกัด RAM 128 MiB, PID 16, 1 CPU,
watchdog 40 วินาที, non-root, read-only, drop-all capabilities และ no-new-privileges

## Observed-impact evidence gate

Workload summary เปลี่ยนเป็น `poc_workload_summary.v2` และเพิ่ม `attempts`, `rejected`,
`latency_p95_ms` ต่อจาก `operations/errors` Execution receipt เป็น label evidence เท่านั้น
และถูกห้ามใช้เป็น model feature

| Treatment | Gate ก่อน finalize |
|---|---|
| compute | attempts ≥1, errors=0, rejected=0 |
| service low | attempts ≥200, error fraction ≤5%, rejected=0, p95 latency ≥20 ms |
| service high/T1499.002 | attempts ≥3,000, error fraction ≥20%, rejected ≥1, p95 latency ≥20 ms |

ทุก summary ต้องมี `attempts = operations + errors` และ `rejected ≤ errors` ถ้า gate ไม่ผ่าน
คำสั่ง finalize จะ fail closed จึงไม่สามารถสร้าง completed manifest ที่อ้าง impact ตามแผนได้

ค่าจาก summary ไม่ใช่ input ของ XGBoost/TCN/Fusion มันใช้ยืนยัน treatment/label เท่านั้น
features ที่จะพิจารณายังต้องมาจาก production-observable hardware telemetry เช่น target
TCP states/socket pressure, cgroup CPU/PSI/memory และ host deltas

## Phase scheduling fix

Collector `0.4.2` reset deadline หลัง `lifecycle.before_phase()` ทุก phase ทำให้เวลา Docker
create/start/stop อยู่นอกช่วงวัด และ sample แรกได้รับ interval เต็ม Test จำลอง hook ช้า
2.25/1.5 วินาทียืนยันว่า 90 samples ไม่มี late flag จาก lifecycle delay

Collector source SHA-256 หลัง revision:
`d9f627edf0450a1dd03b427ada1e45f138aac523b570170e72afae52ffcde3fd`

Telemetry schema ไม่เปลี่ยนและยังมี SHA-256:
`b99697c8f92f8b45c70b9328e52156dab5fc7b30118ecba4b43809abef1a4d4e`

## Contract/versioning

- เพิ่ม `service_pressure_workload_spec.v2` โดยไม่แก้ไฟล์ schema v1
- เพิ่ม `service_pressure_instrumentation_matrix.v2` และบังคับ generation `v2`
- execution receipt v1 รองรับทั้ง historical summary v1 และ summary v2
- fixed entrypoint identity ใหม่คือ `poc_workload_v2`
- pilot v2 ยังคง `pilot_only=true`, `training_eligible=false`,
  `changes_frozen_feature_set=false`

## Verification

- Python test suite: 58 passed
- Go tests: compute/config passed; loopback integration ผ่านบน Pi environment
- matched benign/malicious treatment invariant ผ่าน
- schema validation, evidence gate pass/fail และ slow-lifecycle scheduling test ผ่าน
- excluded Pi rerun ผ่าน 7/7 runs, 630/630 samples และทุก evidence gate

## ลำดับถัดไป

1. freeze XGBoost aggregate-feature และ TCN channel revision จาก signal ที่ pilot พิสูจน์
2. แยก host-only profile จาก target/cgroup-required profile เพื่อวัด deployment trade-off
3. generate development-wave control artifacts หลัง feature revision ผ่าน test เท่านั้น
4. เก็บ 70 development runs หลายวันตาม protocol โดยยังไม่เปิด final-test wave

ผลจาก pilot v1 ที่ถูก supersede เฉพาะ treatment design ยังคงเก็บเป็นหลักฐานที่
[service_pressure_instrumentation_results_2026-09-02.md](service_pressure_instrumentation_results_2026-09-02.md)

ผลจริงของ v2, hashes, quality audit และ candidate decision อยู่ที่
[service_pressure_v2_pilot_results_2026-09-03.md](service_pressure_v2_pilot_results_2026-09-03.md)
