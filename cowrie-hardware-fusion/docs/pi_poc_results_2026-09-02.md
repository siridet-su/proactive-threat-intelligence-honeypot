# Raspberry Pi Two-TTP PoC Result — 2026-09-02

> สถานะ: `PI MATRIX COMPLETE / XGBOOST SMOKE COMPLETE / NOT DEPLOYABLE`
>
> ขอบเขตผล: ยืนยันว่าเส้นทาง Pi telemetry → immutable dataset → derived window →
> repetition-held-out prediction ทำงานจริงใน controlled PoC เท่านั้น ไม่ใช่ค่าความแม่นยำ
> บน attacker หรือ production traffic

## ผลสรุป

รัน matrix v2 บน Raspberry Pi 5 สำเร็จครบ 15/15 runs ได้ raw telemetry 1,350 records
ที่ valid ทั้งหมด และสร้าง workload window 30 วินาทีได้ครบ 15 records ที่ coverage 100%
XGBoost รอบแรกแยก `T1496.001` simulation ได้ 3/3 แต่ยังแยก `T1499.002` ไม่ได้ 0/3
ดังนั้น pipeline ใช้งานได้จริง ส่วน service-exhaustion branch ยังต้องเพิ่ม independent data
และ telemetry ที่สะท้อน service pressure โดยตรง

โมเดลและการเทรนอยู่บน development machine/Cloud side ตาม architecture เดิม Pi ทำหน้าที่
เป็น sensor และ controlled data generator เท่านั้น Go hardware agent production ไม่ถูกเปิด และ
ไม่มีการเขียน Redis, MongoDB หรือ Atlas ระหว่างการทดลอง

## สิ่งที่รันจริงบน Pi

- 5 scenarios × 3 repetitions; interleave ตาม `r01`, `r02`, `r03`
- run ละ baseline/workload/recovery 30/30/30 วินาที ที่ 1 Hz
- neutral idle 3 runs
- benign compute 25% CPU limit 3 runs เทียบกับ `T1496.001` 75% 3 runs
- benign service 10 req/s 3 runs เทียบกับ `T1499.002` 150 req/s 3 runs
- workload เป็น fixed ARM64 Go binary ใน scratch image ไม่ใช่ miner, malware หรือ DDoS
- container ใช้ network none, read-only rootfs, non-root, drop all capabilities,
  no-new-privileges, default seccomp, ไม่มี host mount, RAM 128 MiB และ PID limit 16

controlled workload ทั้ง 12 runs ได้ execution receipt, exit success, error เท่ากับศูนย์ และ
`cleanup_verified=true` ทั้งหมด หลังทุก run ไม่เหลือ container ที่มี PoC label และ production
containers เดิมยังอยู่ในสถานะ running

### Workload receipt summary

| Scenario | Runs | Operations ต่อ run | Mean operations | Errors | Cleanup |
|---|---:|---:|---:|---:|---|
| benign compute | 3 | 12,538–12,940 | 12,677.7 | 0 | 3/3 |
| T1496.001 simulation | 3 | 43,867–44,191 | 44,024.3 | 0 | 3/3 |
| benign service | 3 | 296 | 296.0 | 0 | 3/3 |
| T1499.002 simulation | 3 | 4,309–4,457 | 4,400.3 | 0 | 3/3 |

### Hardware signal ใน workload window

ค่าต่อไปนี้เป็นค่าเฉลี่ยข้าม 3 runs ยกเว้น temperature ซึ่งรายงานค่าสูงสุด:

| Scenario | Host CPU mean | Host CPU p95 | Target CPU p95 | Target RSS p95 | Temp max |
|---|---:|---:|---:|---:|---:|
| idle | 1.93% | 4.95% | 0.00% | 0 B | 58.40°C |
| benign compute | 7.94% | 8.77% | 25.67% | 5.94 MB | 57.85°C |
| T1496.001 | 20.12% | 20.65% | 76.00% | 5.94 MB | 60.60°C |
| benign service | 1.78% | 2.46% | 1.67% | 9.03 MB | 57.85°C |
| T1499.002 | 6.37% | 10.89% | 18.00% | 12.94 MB | 60.05°C |

ตัวเลข CPU ยังคงเป็น continuous raw/derived values ไม่ได้หารเป็น rank 1–4 ค่า 25/75
เป็น treatment limit ของ container ไม่ใช่ค่าที่ป้อนแทน telemetry จริง

## Data integrity

| Artifact/verification | SHA-256 หรือผลตรวจ |
|---|---|
| ARM64 workload binary | `2600d844e453bfaa1126f1ad8ade3fde072a1f65d343053d35c1e0087a1f9155` |
| OCI image ID | `411497a421a7a33f81c707c8b460ba32e1a4496f4d898936463a4f0155a8e95c` |
| Matrix v2 canonical content | `cb481d48d9dd6fb5e67a9f11a75044ec3f9d67cf8e05931475df511df7459bef` |
| Export archive, Pi และ local | `9d774b95cd60e98a9ee8cc66f6d9164693c4ff831eb7113d8379b5234cf4eda1` |
| Dataset source index canonical content | `72fcb6b7b3a6c5bea70226100cbabf4a73a7349871c96f421957f62fc862bf42` |
| Dataset source index file | `3dc97332e180270ba698b14a8f8078a2fdc11ae4a8f5e34a357e038d76a32dff` |

หลัง transfer ได้ re-index raw runs ทั้ง 15 ชุดจาก local อีกครั้งโดยใช้ dataset ID เดิม
ผลคือ index file เหมือนฝั่ง Pi ทุก byte และ canonical content hash ตรงกัน ข้อมูลรวมมี:

- 15 completed pilot runs, 15 collection receipts
- 1,350/1,350 valid records, collector error 0
- serialized telemetry 4,955,469 bytes
- late samples 3 รายการจากทั้ง 90-second runs; ใน 30-second training windows มี 1 รายการ
- target process ต้องปรากฏ 360 samples และปรากฏครบ 360 samples
- 15 derived windows, sample/baseline coverage 100% ทุก window

### v1 aborted attempt

matrix generation v1 จบ idle `r01` หนึ่ง run แต่ benign-compute `r01` ถูกหยุดแบบ fail closed
ก่อนเริ่ม workload เพราะ Docker local log driver ไม่รับ `max-file=1` ขณะที่ compression เปิดอยู่
มีเพียง partial baseline 30 records และไม่มี completed receipt/manifest จึงไม่นำมาใช้และไม่ reuse
run ID หลังแก้เป็น `compress=false` และยืนยัน `no-new-privileges=true` แล้วสร้าง generation v2 ใหม่
ทั้งหมด เหตุการณ์นี้ถูกเก็บใน environment receipt v2 ไม่ถูกลบหรือปะปนใน dataset v2

## XGBoost smoke protocol

- input 15 workload windows × 54 aggregate hardware features
- labels: `NO_TTP=9`, `T1496.001=3`, `T1499.002=3`
- split axis คือ `collection_batch`; fold `r01`, `r02`, `r03` ถูก hold out ทั้งรอบ
- แต่ละ fold train 10 runs และ test 5 runs ไม่มี window จาก repetition เดียวกันข้าม partition
- XGBoost `multi:softprob`, 40 boosting rounds, depth 2, eta 0.1, seed `20260902`,
  `nthread=1`, ไม่มี class weighting และไม่มี hyperparameter tuning
- Python 3.12.13, NumPy 2.5.2, XGBoost 3.4.1 ใน isolated venv
- report authority คือ `pilot_smoke_only_not_for_deployment`

คำสั่ง reproduce หลังมี verified raw data:

```bash
.venv-poc-ml/bin/python -m cowrie_hardware_fusion.cli train-xgboost-smoke \
  --source-index data/poc-pi-two-ttp-v2/local-verified-source-index-matching-id.json \
  --window data/poc-pi-two-ttp-v2/windows/workload-30s/*.json \
  --output-dir artifacts/pi-poc-two-ttp-v2/xgboost-smoke-v1-final \
  --seed 20260902 \
  --num-boost-round 40 \
  --minimum-coverage 0.99 \
  --schema-dir schemas
```

final local report:

- canonical report content SHA-256:
  `2ff94bb19787392a38b970cba03f13da2b527f582563e43aedd44432a8661a47`
- serialized report file SHA-256:
  `543d9ab80f1e4d432c11231cb9c6cceeb438ec8c45fe46f3d60ef979450e95b4`
- local path: `artifacts/pi-poc-two-ttp-v2/xgboost-smoke-v1-final/report.json`

## Out-of-fold result

| Actual | Predicted NO_TTP | Predicted T1496.001 | Predicted T1499.002 | Recall |
|---|---:|---:|---:|---:|
| NO_TTP | 9 | 0 | 0 | 1.00 |
| T1496.001 | 0 | 3 | 0 | 1.00 |
| T1499.002 | 3 | 0 | 0 | 0.00 |

- Accuracy: `0.8000`
- Macro-F1: `0.6190`
- NO_TTP precision/recall/F1: `0.75 / 1.00 / 0.8571`
- T1496.001 precision/recall/F1: `1.00 / 1.00 / 1.00`
- T1499.002 precision/recall/F1: `0.00 / 0.00 / 0.00`

ทั้งสาม folds ให้ confusion pattern เดียวกัน ผลนี้จึงไม่ได้เกิดจาก repetition เดียวที่ผิดปกติ
แต่ห้ามตีความ 3/3 ของ T1496.001 เป็น 100% production accuracy เพราะทุก run มาจาก Pi,
binary, environment และวันเดียวกัน

## ทำไม T1499.002 ยังไม่ผ่าน

1. แต่ละ training fold มี positive ของแต่ละ TTP เพียง 2 runs ขณะที่ใช้ 54 features และ
   `NO_TTP` 6 runs ทำให้ tree มีข้อมูลน้อยมากสำหรับสร้าง leaf ของ minority class
2. service control และ T1499.002 ใช้ socket count สูงสุดเท่ากันคือ 3 เพราะ server/client อยู่ใน
   process/network namespace เดียว ต่างกันหลัก ๆ ที่ request rate, target CPU และ RSS
3. `--network=none` ทำให้ loopback traffic ภายใน container ไม่ปรากฏเป็น host-interface
   throughput จึงไม่ควรคาดหวังให้ host network bytes เป็นตัวบอก request flood
4. operations/request count อยู่ใน execution receipt เพื่อยืนยัน treatment แต่ไม่ป้อนเข้าโมเดล
   เพราะเป็น simulator-side knowledge ที่ production ไม่มีและจะทำให้ label leakage

หลังเห็นผลนี้จะไม่ปรับ feature/min-child/class weight แล้วนำ fold เดิมมารายงานเป็น unbiased
คะแนนใหม่ การลอง config บน fold ที่เปิดผลแล้วใช้ได้เพียง diagnostic และต้อง freeze protocol ใหม่
ก่อนเก็บ independent runs ชุดถัดไป

## ข้อสรุปและ next gate

PoC ตอบว่า **ระบบเก็บและใช้ hardware evidence เพื่อทำนายได้จริง** และ signal ของ compute
hijacking simulation ชัด แต่ยังตอบไม่ได้ว่า hardware model แยก service-exhaustion ได้อย่าง
น่าเชื่อถือ หรือช่วย ModernBERT บน production traffic ได้เท่าไร

ขั้นต่อไปที่ควรทำก่อน TCN/Fusion:

1. freeze XGBoost protocol v2 ก่อนเก็บข้อมูลใหม่ โดยแยก `host-only` กับ
   `target-augmented` feature profiles ที่กำหนดจาก deployment availability
2. เพิ่มอย่างน้อย 10–20 independent runs ต่อ scenario กระจายหลายวันและหลาย background load
3. เพิ่ม benign service intensity หลายระดับและ load ที่ใกล้ 150 req/s เพื่อกัน shortcut
4. เก็บ service-side observability ที่ production หาได้จริง เช่น Cowrie event rate, accepted
   connections, latency/error/queue pressure และ cgroup throttling โดยไม่ใช้ simulator receipt
   เป็น model feature
5. ให้ hardware branch ทำนาย observed impact ก่อน เช่น `COMPUTE_SATURATION` หรือ
   `SERVICE_PRESSURE`; ให้ frozen ModernBERT จัด intent/TTP candidate แล้ว Fusion ค่อยวัดว่า
   text intent กับ observed impact สนับสนุนหรือขัดกัน
6. เปิด independent test ชุดใหม่เพียงครั้งเดียวหลัง freeze; ยังไม่เริ่ม TCN เพราะ 15 runs
   เล็กเกินไปสำหรับเทียบ neural time-series model อย่างมีความหมาย

## Verification

- Python tests: `35 passed`
- Go workload tests/vet: ผ่านก่อน build ARM64 image
- Pi compute/service canaries: ผ่าน
- matrix v2: `15/15 completed`
- XGBoost report/model artifacts: hash-bound และถูก gitignore เนื่องจากเป็น pilot artifacts
