# XGBoost, TCN and Fusion Model Architecture v1

> สถานะ: `DESIGN / NOT IMPLEMENTED`  
> ปรับปรุงล่าสุด: 2026-09-01  
> Deployment target: Cloud shadow inference  
> Authority: model outputs เป็น audit-only

## สรุป

XGBoost และ TCN เป็นตัวเลือกสองแบบสำหรับอ่าน hardware telemetry ไม่จำเป็นต้องใช้
พร้อมกันตอน deploy ส่วน Fusion model นำ hardware evidence จากตัวที่ชนะไปประกอบกับ
ModernBERT command evidence

```text
Command fragment
    -> frozen ModernBERT
    -> text/TTP features
                              \
                               -> Fusion -> TTP + impact candidate
                              /
1 Hz hardware telemetry
    -> XGBoost OR TCN
    -> intent-neutral impact features
```

ลำดับพัฒนา:

```text
XGBoost baseline
    vs
TCN candidate
    -> เลือก hardware branch จาก frozen evaluation
    -> train Fusion กับ ModernBERT
```

## 1. XGBoost ทำงานอย่างไร

### 1.1 Input

XGBoost ไม่อ่าน raw time series โดยตรงใน design v1 แต่รับหนึ่งแถวต่อ
`run × observation window`

Raw telemetry 30 วินาที:

```text
CPU:  8, 9, 12, 47, 82, 94, 93, 91, ...
RAM: 31,31, 32, 33, 35, 36, 37, 38, ...
NET:  1, 1,  2, 15, 48, 80, 76, 72, ...
```

Feature builder สรุปเป็น:

```text
cpu_mean
cpu_max
cpu_p95
cpu_std
cpu_slope
cpu_delta_from_baseline
cpu_seconds_above_70
cpu_seconds_above_90
per_core_imbalance
memory_delta
network_tx_max
network_packet_rate_p95
process_count_delta
temperature_delta
sample_coverage
```

CPU ดิบเก็บเป็น continuous `0–100` แล้วค่อย derive features ห้ามแทนค่าดิบด้วย rank
1–4 การแบ่ง 25/50/75/90 ใช้เป็น scenario intensity หรือ optional display feature เท่านั้น

### 1.2 Learning mechanism

XGBoost สร้าง decision trees ต่อเนื่องกัน แต่ละ tree พยายามแก้ residual/error ของ trees
ที่สร้างก่อนหน้า

ตัวอย่างเชิงแนวคิด:

```text
Tree 1:
  cpu_delta_from_baseline > 45?
    -> compute-impact score เพิ่ม

Tree 2:
  network_packet_rate สูง แต่ CPU ไม่สูง?
    -> network-impact score เพิ่ม

Tree 3:
  CPU สูงสั้นมากและกลับ baseline เร็ว?
    -> ลด sustained-compute score
```

ผลของหลาย trees ถูกบวกเป็น logits/scores แล้วแปลงเป็น per-label outputs

```text
NO_MATERIAL_IMPACT       0.04
COMPUTE_SATURATION       0.88
NETWORK_FLOOD_PATTERN    0.03
MEMORY_PRESSURE          0.03
PROCESS_EXHAUSTION       0.02
```

ตัวเลขข้างต้นเป็นตัวอย่าง ไม่ใช่ calibrated probability จนกว่าจะผ่าน calibration
protocol

### 1.3 Task

Hardware labels เป็น intent-neutral เช่น `COMPUTE_SATURATION` ไม่ใช่ `MINING`
เพราะ compile/benchmark กับ simulated compute hijacking สามารถสร้าง CPU pattern ใกล้กัน

หากเป็น multi-label ให้ train one-vs-rest binary booster ต่อ impact label หรือใช้
reviewed multi-output wrapper ที่ freeze label order ชัดเจน

### 1.4 จุดแข็ง

- เหมาะกับ controlled dataset ขนาดเล็กถึงกลาง
- เรียน nonlinear thresholds และ feature interactions ได้
- เทรน/inference เร็ว
- วิเคราะห์ feature importance และ failure cases ได้ง่ายกว่า neural model
- เป็น baseline สำหรับพิสูจน์ว่า temporal deep learning เพิ่มคุณค่าจริงหรือไม่

### 1.5 จุดอ่อน

- คุณภาพขึ้นกับ window/feature engineering
- ลำดับละเอียดอาจหายหลังสรุป mean/max/p95
- แยก pattern ที่มี summary ใกล้กันแต่ลำดับต่างกันได้ไม่ดีเท่า sequence model

## 2. TCN ทำงานอย่างไร

TCN คือ Temporal Convolutional Network ซึ่งอ่านลำดับ telemetry โดยตรง

### 2.1 Input

ถ้ามี 20 hardware features เก็บ 60 วินาทีที่ 1 Hz:

```text
input shape = [batch, 20 features, 60 time steps]
```

ตัวอย่าง channels:

```text
CPU       [8, 9, 12, 47, 82, 94, ...]
RAM       [31,31,32, 33, 35, 36, ...]
Disk I/O  [0, 0,  1, 15, 40, 38, ...]
Net TX    [1, 1,  2, 48, 80, 76, ...]
Process   [90,90,91,94,110,143, ...]
Temp      [48,48,48,50, 54, 58, ...]
```

Normalization parameters fit จาก development train เท่านั้น Missing/counter-reset flags
ต้องส่งเป็น mask/quality channels หรือทำให้ model abstain ตาม policy

### 2.2 Temporal convolution

TCN ใช้ causal/dilated convolution มอง pattern หลายระยะ:

```text
dilation 1  -> spike ระยะสั้น
dilation 2  -> ramp-up หลายวินาที
dilation 4  -> sustained pattern ระยะกลาง
dilation 8+ -> context ระยะยาว
```

Causal หมายถึง output ณ decision timestamp ไม่อ่าน telemetry ในอนาคต ส่วน dilation
ช่วยขยาย receptive field โดยไม่ต้องเพิ่ม layer จำนวนมาก

Residual blocks ช่วยให้ gradient ไหลผ่าน network และแต่ละ block เรียน feature เพิ่มจาก
representation ก่อนหน้า

```text
telemetry sequence
  -> causal convolution
  -> activation/dropout
  -> dilated residual blocks
  -> temporal pooling
  -> telemetry embedding
  -> impact head
```

### 2.3 Patterns ที่คาดว่าจะเรียน

```text
Compute saturation:
  CPU สูงต่อเนื่อง + temperature ค่อยเพิ่ม + process คงอยู่

Short benign burst:
  CPU พุ่งสั้นแล้วกลับ baseline

Process exhaustion:
  process/thread count พุ่ง + memory pressure + service degradation

Network flood pattern:
  packet/connection rate เพิ่มเร็ว + incomplete/short flows + local sink pressure
```

TCN สร้าง telemetry embedding เช่น 64–128 dimensions ก่อน classification head

### 2.4 จุดแข็ง

- เรียน spike, ramp, duration และ recovery shape ได้โดยตรง
- ใช้หลาย telemetry channels พร้อมกัน
- เหมาะกับ early/detection windows หลายขนาด
- เบากว่า time-series Transformer ที่มี context ใกล้กัน

### 2.5 จุดอ่อน

- ต้องการ independent runs มากกว่า XGBoost
- overfit scenario/tool/background conditions ได้ง่าย
- tuning และอธิบาย failure ยากกว่า
- ถ้า telemetry มี clock/missing-data problems จะเรียน artifact แทน behavior

## 3. Fusion ทำงานอย่างไร

Fusion ไม่ใช่การนำ confidence สองตัวมาบวกหรือเฉลี่ยกัน เพราะ ModernBERT raw softmax
score และ hardware score ยังมี calibration semantics ต่างกัน

### 3.1 Text features

จาก frozen ModernBERT:

- relevant/full logits หรือ frozen embedding
- top candidate ID
- top score
- top-1/top-2 margin
- entropy
- model availability/truncation flags

Canonical wrapper เดิมคืน top candidate เป็นหลัก หาก experiment ต้องใช้ full logits ต้อง
สร้าง shadow adapter แยกและห้ามเปลี่ยน canonical output semantics

### 3.2 Hardware features

กรณี XGBoost:

- out-of-fold impact logits/scores
- missing/coverage flags
- optional selected aggregate features

กรณี TCN:

- out-of-fold impact logits/scores
- telemetry embedding
- sequence mask/coverage flags

### 3.3 Late fusion

รุ่นแรกใช้ Logistic Regression หรือ small MLP:

```text
[ModernBERT features | hardware features | quality flags]
                         -> Fusion head
                         -> TTP/impact candidates
```

ตัวอย่างการตีความ:

| Text branch | Hardware branch | Fusion evidence state |
|---|---|---|
| T1496.001 candidate | Compute saturation | intent + impact corroborate |
| T1496.001 candidate | No material impact | intent observed; impact not observed |
| no T1496 evidence | Compute saturation | impact observed; malicious intent unproven |
| T1498.001 candidate | Network flood pattern | intent + network impact corroborate |
| unavailable text | Compute saturation | impact-only; TTP identification incomplete |

### 3.4 Leakage control

Fusion development rows ต้องใช้ hardware predictions จาก out-of-fold base models ไม่ใช่
prediction จาก XGBoost/TCN ที่ train ด้วย row/run เดียวกัน

หาก ModernBERT ถูก freeze และไม่ได้ train ด้วย dataset ใหม่ สามารถ extract features ได้
โดยไม่เกิด stacking leakage จาก dataset นี้ หาก fine-tune เมื่อใดต้องสร้าง out-of-fold
text predictions และ model identity ใหม่

## 4. Training order

```text
1. Freeze run-level split
2. Build raw 1 Hz sequences และ aggregate windows
3. Train trivial threshold baseline
4. Train XGBoost hardware-only
5. Train MiniROCKET/TCN hardware-only บน split เดียวกัน
6. เลือก hardware branch ด้วย development/calibration protocol
7. Freeze winning hardware model
8. Generate out-of-fold fusion features
9. Train Logistic/MLP Fusion
10. Open final test ตาม frozen protocol
11. Deploy Cloud shadow inference
```

## 5. Deployment candidates

### Candidate A — recommended first

```text
Frozen ModernBERT
       +
XGBoost hardware model
       -> Logistic Regression Fusion
```

เหมาะเมื่อ dataset ยังเล็กและต้องการ debug/interpretability

### Candidate B — promote only if it wins

```text
Frozen ModernBERT
       +
Small TCN hardware encoder
       -> Small MLP Fusion
```

เลือกเมื่อ TCN ชนะ XGBoost บน Macro-F1/PR-AUC/false-positive/detection-latency gates
อย่างมีนัยสำคัญเชิงปฏิบัติและทำซ้ำได้

## 6. Output and authority

ตัวอย่าง shadow output:

```json
{
  "ttp_candidates": {"T1496.001": 0.86},
  "impact_candidates": {"COMPUTE_SATURATION": 0.92},
  "evidence_state": {
    "intent_observed": true,
    "impact_observed": true,
    "telemetry_complete": true
  },
  "hardware_model": "xgboost-or-tcn-frozen-id",
  "fusion_model": "fusion-frozen-id",
  "authority": "audit_only",
  "canonical_write_allowed": false
}
```

Rule/trust authority เดิมยังแยกต่างหาก Fusion v1 ไม่มีสิทธิ์สร้าง trusted TTP, finding,
guidance, alert หรือ action

## 7. การตัดสินว่าตัวไหนชนะ

เปรียบเทียบด้วย frozen run-level test set:

- Macro-F1 และ per-label precision/recall/F1
- PR-AUC ต่อ impact/TTP
- false positives ต่อ benign run/hour
- false negatives ของ high-impact labels
- detection latency ที่ 5/10/30/60 seconds
- missing-data robustness
- ECE/Brier หลัง calibration
- Cloud inference latency/cost

Accuracy อย่างเดียวไม่พอ และห้ามเลือก TCN เพียงเพราะเป็น neural model

## References

- XGBoost: https://arxiv.org/abs/1603.02754
- TCN: https://arxiv.org/abs/1803.01271
- MiniROCKET: https://arxiv.org/abs/2012.08791
- [Experiment contract](experiment_contract.v1.md)
- [Dataset split policy](dataset_split_policy.v1.md)
- [Dataset storage plan](dataset_storage_plan.v1.md)

