# Hardware-impact experiment protocol v2

> สถานะ: `FROZEN BEFORE NEW COLLECTION`
> วันที่ freeze: `2026-09-02`
> Protocol ID: `pi-hardware-impact-v2-20260902`
> Canonical SHA-256: `8eb0786e8427f7fa685a8d137db62b1ecfff40a7897b65f742915477b9b2471d`

ไฟล์ authority คือ
[hardware_impact_experiment_protocol.v2.json](../configs/hardware_impact_experiment_protocol.v2.json)
เอกสารนี้อธิบายเหตุผลและขั้นตอนปฏิบัติ แต่หากค่าต่างกันให้ยึด JSON ที่ผ่าน schema และ
semantic validator

## สิ่งที่โมเดล hardware ทำนาย

Hardware branch ไม่ควรทำนายว่า workload เป็น TTP ใดจาก CPU/RAM เพียงอย่างเดียว
เพราะ benign compile และ compute hijacking อาจสร้างผลกระทบทาง hardware เหมือนกัน
เป้าหมายของ XGBoost v2 จึงเป็น `primary_impact` สาม class:

- `NO_MATERIAL_IMPACT`
- `COMPUTE_SATURATION`
- `SERVICE_PRESSURE`

`T1496.001` และ `T1499.002` เป็น ground-truth metadata สำหรับวัดผลและใช้ใน Fusion
กับ text intent จาก ModernBERT เท่านั้น ไม่ใช่ target ของ hardware model

```text
ModernBERT: command intent / TTP candidates
Hardware branch: observed impact
Fusion: intent + impact, เริ่มจาก audit-only
```

## Matched scenario design

| Scenario | Disposition | Family/intensity | Hardware target | TTP metadata |
|---|---|---:|---|---|
| `v2_neutral_idle` | neutral | none / 0 | no impact | none |
| `v2_benign_compute_low` | benign | compute / 25 | no impact | none |
| `v2_benign_compute_high` | benign | compute / 75 | compute saturation | none |
| `v2_t1496_001_compute_high` | malicious simulation | compute / 75 | compute saturation | T1496.001 |
| `v2_benign_service_low` | benign | service / 10 | no impact | none |
| `v2_benign_service_high` | benign | service / 150 | service pressure | none |
| `v2_t1499_002_service_high` | malicious simulation | service / 150 | service pressure | T1499.002 |

คู่ benign/malicious ใช้ family และ intensity เท่ากันโดยตั้งใจ เพื่อบังคับไม่ให้ hardware
branch จำชื่อ scenario หรือแยก intent ที่ telemetry พิสูจน์ไม่ได้ ค่า intensity เป็น treatment
metadata และห้ามนำเข้า model feature; CPU และ metric อื่นเก็บแบบ continuous ไม่แบ่ง rank
1–4

## Acquisition waves

แต่ละ run เก็บ baseline/workload/recovery `30/30/30` วินาทีที่ 1 Hz รวม 90 samples
แผนเต็มคือ 20 repetitions × 7 scenarios = 140 independent runs หรือ 12,600 samples
กระจายอย่างน้อย 5 วัน:

| Partition | Repetitions/scenario | Runs | Policy |
|---|---:|---:|---|
| development train | 10 | 70 | เก็บก่อนแล้วหยุดตรวจ signal |
| calibration | 5 | 35 | ใช้หลังเลือก model/profile |
| final test | 5 | 35 | lock จน model และ threshold freeze |

ห้ามรันรวดเดียวครบ 140 แล้วเปิด final test ระหว่างแก้ feature งานถัดไปคือเก็บเฉพาะ
development wave หลัง service-pressure observability และ collection path ผ่าน review

## Feature profiles

- `go_agent_overlap_v1` — 25 features ที่ Go agent ปัจจุบันพอเทียบได้ ใช้เป็น diagnostic
  baseline ไม่ใช่ full collector replacement
- `host_extended_v2` — 48 host features รวม disk I/O, per-core imbalance,
  socket/process/thread และ health signals
- `target_augmented_v2` — 54 features; เพิ่ม target process/cgroup metrics 6 ค่า

Forbidden features ได้แก่ IDs, timestamps, scenario/label, treatment intensity และ
execution-receipt operations ตัว builder ต้อง fit preprocessing จาก development train
เท่านั้น และ Fusion ต้องรับ out-of-fold prediction/features

## Frozen XGBoost plan

ใช้ multiclass soft probabilities, balanced class weights และ fixed parametersใน protocol
โดยไม่ทำ hyperparameter tuning กับ dataset รอบนี้ Selection metric คือ macro-F1 และต้อง
รายงาน per-class metrics, no-impact false-positive rate, Brier score และ ECE

Promotion gate ขั้นต่ำคือ macro-F1 `0.75`, recall ทุก class `0.70`, no-impact false-positive
rate ไม่เกิน `0.15` และ macro-F1 ดีกว่า majority baseline อย่างน้อย `0.10` อย่างไรก็ตาม
`deployment_allowed=false`; ผ่าน gate แล้วจึงอนุญาตให้ทดลอง calibration/Fusion แบบ
shadow ไม่ได้อนุญาต production action

## Safety and validation

- ใช้เฉพาะ bounded simulation; ไม่มี malware, attacker code หรือ external target
- workload container ใช้ `network=none`; ไม่มี production sink write
- Pi ทำหน้าที่ sensor/data generator; training รัน Arch หรือ Cloud
- raw evidence อยู่ local spool แบบ receipt/hash-bound ก่อนย้ายออก

ตรวจ protocol ได้ด้วย:

```bash
cowrie-hardware-dataset validate-hardware-impact-protocol \
  --protocol configs/hardware_impact_experiment_protocol.v2.json
```

Validator ตรวจทั้ง JSON Schema, content hash, label authority, matched controls, wave totals,
final-test lock, feature leakage/nesting และ fixed model policy
