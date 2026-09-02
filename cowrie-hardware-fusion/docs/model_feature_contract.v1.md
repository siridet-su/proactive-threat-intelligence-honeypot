# Model Feature Contract v1

วันที่ freeze: 2026-09-03
สถานะ: `FROZEN / AUDIT-ONLY / FINAL TEST CLOSED`

เอกสารนี้กำหนดว่า output จาก dataset builder v2 ส่วนใดเข้า XGBoost และ TCN ได้จริง
เพื่อไม่ให้ full vector 67 features ถูกนำไปใช้ทั้งหมดโดยไม่มี deployment/leakage boundary
authority ที่เครื่องอ่านได้คือ
[`configs/model_feature_contract.v1.json`](../configs/model_feature_contract.v1.json)

## Binding

- builder `0.2.0`, window `derived_training_window.v2`
- XGBoost schema v2: 67 generated features,
  order hash `2cb0663c...f881b`
- TCN schema v2: 22 generated channels,
  order hash `0c9b4aa7...22256`
- contract hash `257121d6...af18`
- ผูกกับ matrix, audit summary และ Pi export hashes ของ service-pressure pilot v2
- pilot records เป็น evidence สำหรับเลือก signal เท่านั้น ไม่ใช่ training/evaluation data

## XGBoost profiles

| Profile | จำนวน | หน้าที่ | Availability |
|---|---:|---|---|
| `go_agent_overlap_v1` | 25 | diagnostic baseline จากค่าที่ใกล้กับ Go hardware agent เดิม | มีแหล่งข้อมูล production ใกล้เคียงแล้ว |
| `host_extended_v3` | 51 | candidate หลักจาก host telemetry รวม PSI | ต้องใช้ extended collector |
| `target_augmented_v3` | 66 | upper-bound candidate เพิ่ม target/cgroup/TCP signals | ต้อง map Cowrie process/container/cgroup และพิสูจน์ availability |

สาม profile เป็น strict nested comparison ทำให้วัด gain ของข้อมูลเพิ่มแต่ละชั้นได้ตรงไปตรงมา
`target_augmented_v3` ไม่ใช้ `target_process_present_fraction` แม้ builder จะสร้างไว้ เพราะ
ใน pilot ค่านี้บอกขอบเขตการเริ่ม/หยุด simulator ได้ง่ายกว่าพฤติกรรมโจมตีจริง

## TCN profiles

| Profile | จำนวน channels | หน้าที่ |
|---|---:|---|
| `host_extended_v3` | 14 | host time series รวม host CPU PSI |
| `target_augmented_v3` | 22 | host + target process/cgroup/TCP time series |

TCN ต้องรับ `sample_present` และ `channel_present` masks คู่กับ values เสมอ ค่า `0.0`
ที่ใช้เติมช่องว่างห้ามตีความว่า sensor วัดได้จริงและมีค่าเป็นศูนย์

## Leakage และ claim controls

ห้ามใช้ model input ต่อไปนี้:

- run/record/experiment/scenario IDs, timestamps และ split-group identities
- disposition, impact, TTP labels และ workload intensity
- attempts, operations, errors, rejected และ latency จาก execution receipt
- `target_process_present_fraction`

receipt มีไว้พิสูจน์ว่า treatment สำเร็จและกำหนด label เท่านั้น ไม่ใช่ observation ที่
production model จะเห็น Contract ยังบังคับ `deployment_authority=audit_only`,
`final_test_opened=false` และ target profile ต้องผ่าน shadow availability test ก่อน

## Validation

```bash
python -m cowrie_hardware_fusion.cli validate-model-feature-contract \
  --contract configs/model_feature_contract.v1.json \
  --window path/to/derived-window.json
```

validator ตรวจ JSON Schema, contract hash, derived-record hash, builder/schema/order binding,
profile nesting, input availability, forbidden inputs, TCN mask policy และ fail-closed claims
แล้ว Excluded Pi pilot windows ทั้ง 7 records ผ่าน contract นี้ครบ 7/7

## ขั้นถัดไป

สร้าง development matrix 70 runs ตาม Protocol v2 โดยยังไม่เปิด final-test wave จากนั้น build
windows ด้วย v2 และเริ่ม XGBoost development evaluation เปรียบเทียบสาม profile ข้างต้น
Target profile เป็นการวัด upper bound จนกว่าจะผ่าน Cowrie target mapping/shadow gate
