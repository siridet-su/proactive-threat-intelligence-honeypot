# Dataset Builder v2

> สถานะ: `IMPLEMENTED / 7-RUN RAW REPLAY PASS / PROFILE CONTRACT NEXT`
> Builder: `0.2.0`
> Output: `derived_training_window.v2`

## เหตุผลของ revision

Builder v1 เก็บ host metrics และ target process CPU/RSS/socket FD พื้นฐาน แต่ยังไม่แปลง
service-pressure/cgroup signals ที่ collector `0.4.x` เพิ่มเข้ามา Pilot v2 พิสูจน์แล้วว่า
target TCP TIME_WAIT, cgroup CPU usage/PSI และ memory ตอบสนองต่อ bounded treatment จึงเพิ่ม
เฉพาะ signal ที่มี coverage และ separation จริง โดยไม่อ่าน simulator execution receipt

Schema v1 ยังเก็บไว้เพื่อ validate historical artifacts; CLI รุ่นปัจจุบันสร้าง v2 เป็นค่า
เริ่มต้นและ smoke reader รองรับทั้ง v1/v2 แต่ไม่อนุญาตให้ปน feature schema ในการ train run
เดียวกัน

## XGBoost aggregate revision

Feature vector เต็มมี 67 continuous numeric features และมี order identity:

- `feature_schema_version=xgboost_hardware_features.v2`
- `feature_order` เป็นชื่อทั้งหมดเรียง lexical
- `feature_order_sha256=2cb0663c008e58d2b0dc5efc7509e515ebc16c006dff9d5cad51084d578f881b`

เพิ่มจาก v1 จำนวน 13 ค่า:

```text
host_cpu_psi_some_delta_from_baseline_mean
host_cpu_psi_some_mean
host_cpu_psi_some_p95
target_cgroup_cpu_usage_usec_per_second_mean
target_cgroup_cpu_usage_usec_per_second_p95
target_cgroup_cpu_psi_some_usec_per_second_mean
target_cgroup_cpu_psi_some_usec_per_second_p95
target_cgroup_memory_current_bytes_mean
target_cgroup_memory_current_bytes_p95
target_tcp_time_wait_mean
target_tcp_time_wait_p95
target_sockets_used_mean
target_sockets_used_p95
```

ไม่มี TCP-total feature เพราะ pilot พบว่าเกือบซ้ำกับ TIME_WAIT และไม่มี queue/drop feature
เพราะค่าทดลองเป็นศูนย์ทั้งหมด `target_process_present_fraction` ยังคง output เพื่อความเข้ากัน
ได้/diagnostic แต่ต้อง exclude จาก model profile v3 เพราะเป็น execution-boundary availability
ซึ่งอาจสร้าง simulator artifact

## TCN channel revision

TCN มี 22 channels และมี order identity:

- `channel_schema_version=tcn_hardware_channels.v2`
- `channel_order_sha256=0c9b4aa70bc5f6b78ad63933b4a894fd8121454f34e76916bc8c933e92722256`

เพิ่ม 6 channels:

```text
host_cpu_psi_some_usec_per_second
target_tcp_time_wait
target_sockets_used
target_cgroup_cpu_usage_usec_per_second
target_cgroup_cpu_psi_some_usec_per_second
target_cgroup_memory_current_bytes
```

ค่าที่ไม่มีใน sample จะ serialize เป็น `0.0` แต่ mask ใน `channel_present` เป็น 0 จึงต้องใช้
value และ mask คู่กันเสมอ ห้ามตีความ zero-imputation ว่า metric วัดได้และเป็นศูนย์

## Identity validation

`validate_derived_window_identity()` ตรวจ:

- feature order ตรงกับ feature keys และ order hash
- channel order ตรงกับ channel/mask keys และ order hash
- channel/mask length ตรงกับ sample mask
- record content hash ตรงทั้ง object

Smoke XGBoost v2 ตรวจ feature order/hash ซ้ำก่อนสร้าง matrix row เพื่อป้องกัน schema name
เหมือนกันแต่ column order สลับ

## Pilot replay verification

Raw excluded pilot v2 ทั้ง 7 runs ถูก replay เป็น workload window 30 วินาทีสำเร็จ:

- coverage 1.0 ทุก record
- feature order hash ตรงทั้ง 7 records
- channel order hash ตรงทั้ง 7 records
- aggregate CPU usage, TIME_WAIT, sockets และ host PSI delta ตรงกับ independent signal
  reports
- derived records ยังเป็น pilot evidence และห้ามใช้วัด model accuracy/train

ตัวอย่าง service-high benign จาก builder:

```text
target_cgroup_cpu_usage_usec_per_second_mean = 118817.7521
target_tcp_time_wait_mean                    = 2453.4
target_sockets_used_mean                     = 6.8
host_cpu_psi_some_delta_from_baseline_mean   = 3833.3235
```

## Model-profile boundary ที่ freeze แล้ว

Full vector ไม่ใช่คำสั่งให้ใช้ทุก feature จึง freeze profiles แยกไว้ดังนี้:

1. `host_extended_v3`: host-only รวม CPU PSI ใช้เป็น deployment-oriented baseline
2. `target_augmented_v3`: host profile + target/cgroup/TCP metrics ใช้วัด upper-bound gain
3. diagnostic Go-agent overlap เพื่อเทียบกับ telemetry ที่ production มีอยู่เดิม

Target profile ยัง deploy ไม่ได้จนกว่าจะ map collector ไปยัง Cowrie container/cgroup,
วัด availability ใน shadow mode และพิสูจน์ว่า semantics ไม่ต่างจาก controlled container
อย่างมีสาระสำคัญ

Machine-readable authority, exact membership/counts, TCN mask policy และ validation command:
[model_feature_contract.v1.md](model_feature_contract.v1.md)

## Leakage boundary

ห้ามนำค่าต่อไปนี้เข้า feature/channel:

- scenario/TTP/disposition/impact labels และ treatment intensity
- run/experiment/record IDs, timestamps และ split groups
- workload attempts/operations/errors/rejections/latency จาก execution receipt
- container/image/implementation identity

Receipt มีไว้ verify treatment และ label authority เท่านั้น ส่วน features มาจาก raw
production-observable telemetry schema

ผล pilot ที่ใช้ตัดสิน revision:
[service_pressure_v2_pilot_results_2026-09-03.md](service_pressure_v2_pilot_results_2026-09-03.md)
