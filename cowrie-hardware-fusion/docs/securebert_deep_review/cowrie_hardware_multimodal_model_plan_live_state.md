# Cowrie Command + Hardware Telemetry Model Plan — LIVE STATE

> สถานะเอกสาร: `LIVE STATE / PROPOSAL` — ปรับปรุงต่อเนื่องตามผลทดลอง  
> ปรับปรุงล่าสุด: 2026-09-01 (Asia/Bangkok)  
> หลักฐาน integration ล่าสุด: repo `proactive-threat-intelligence-honeypot` local `main` วันที่ 2026-09-01  
> เป้าหมาย: สร้างโมเดลใหม่จาก controlled Cowrie honeypot experiments และ hardware/network telemetry เพื่อทดสอบว่าการเพิ่มข้อมูลพฤติกรรมของเครื่องช่วยจำแนก TTP ได้ดีขึ้นหรือไม่

## สรุปข้อเสนอ

แนวทางหลักคือไม่สร้าง SecureBERT ตัวที่สอง แต่ใช้โมเดลสองสาขาแล้วทำ late fusion:

1. ใช้ ModernBERT command classifier เดิมเป็น text branch โดยเริ่มจากการ freeze weights
2. ใช้ small Temporal Convolutional Network (TCN) เป็น telemetry branch
3. รวม raw logits/representation จาก text branch กับ telemetry embedding ผ่าน fusion head
4. ให้ deterministic rules และ trust policy อยู่แยกจากโมเดลเหมือนระบบเดิม
5. รันโมเดลใหม่ใน shadow/audit-only จนกว่าจะผ่าน evaluation และ calibration gates

จากสถาปัตยกรรมจริง โมเดลใหม่ไม่ควรถูกเพิ่มตรงเข้า `SessionWorker` hot path ในระยะแรก
แต่ควรทำเป็น isolated shadow sidecar ตาม pattern ของ
`production/prediction_next_distinct_poc`: อ่านข้อมูลแบบจำกัดสิทธิ์, ไม่มี canonical
write path และเขียนผลลง isolated shadow store เท่านั้น

ก่อน TCN ต้องสร้าง baseline อย่างน้อยหนึ่งตัวจาก MiniROCKET หรือ window statistics +
XGBoost/Logistic Regression เพื่อพิสูจน์ว่าความซับซ้อนของ deep learning ให้ประโยชน์จริง

## 1. Research questions

คำถามหลัก:

> เมื่อใช้ command evidence ร่วมกับ hardware/process/network telemetry แล้ว ระบบสามารถ
> จำแนก TTP และผลกระทบจากการใช้ทรัพยากรได้ดีกว่า rules + command classifier เดิมหรือไม่
> บน held-out attack sessions ที่ไม่รั่วจากชุดเทรน

คำถามย่อย:

- Telemetry เพียงอย่างเดียวจำแนกพฤติกรรมได้ดีเพียงใด
- Command text เพียงอย่างเดียวทำได้ดีเพียงใดบน dataset ใหม่
- Fusion ลด false positives จาก benign high-load workloads ได้หรือไม่
- Fusion ช่วยแยก compute hijacking, bandwidth abuse, endpoint DoS และ outbound attack
  behavior ได้หรือไม่
- สามารถตรวจพบได้เร็วเพียงใดหลังเริ่มพฤติกรรม
- โมเดลสามารถรันบน Raspberry Pi 5 ภายใต้ memory/latency budget ได้หรือไม่

## 2. ขอบเขตของ prediction

ต้องแยกสองงานออกจากกันอย่างชัดเจน:

### 2.1 Current-behavior detection/classification

ใช้ command และ telemetry ที่เกิดภายใน observation window เพื่อจำแนกพฤติกรรมที่กำลัง
เกิดหรือเพิ่งเกิด งานนี้อนุญาตให้ใช้ telemetry หลัง command ภายใน window ที่กำหนด

### 2.2 Early prediction

ทำนายพฤติกรรมก่อนเกิดผลกระทบเต็มรูปแบบ โดยใช้เฉพาะข้อมูลที่มีอยู่ ณ decision timestamp
ห้ามนำ telemetry ในอนาคตหลัง decision timestamp มาเป็น input มิฉะนั้นจะเกิด temporal
leakage และไม่สามารถเรียกว่า prediction ได้

ผลของสองงานต้องรายงานแยกกัน ห้ามรวม metric หรือใช้คำว่า prediction กับ experiment ที่
เห็นผลกระทบหลังเหตุการณ์แล้ว

## 3. Cowrie execution boundary

Cowrie default shell backend เป็น emulation คำสั่ง miner, stress tool หรือ network tool
อาจไม่ได้ execute จริงบน Raspberry Pi ดังนั้น host CPU/RAM ที่วัดได้อาจเป็นภาระของ
Cowrie/logger ไม่ใช่ผลจาก attacker payload

สำหรับ experiment ที่ต้องวัดผลของ payload จริง ให้ใช้:

```text
Authorized attacker simulator
       ↓
Cowrie proxy
       ↓
Isolated disposable VM/backend
       ↓
Guest/cgroup/process/network telemetry
```

ข้อกำหนดด้านความปลอดภัย:

- ห้าม execute payload บน Pi host ที่ให้บริการจริง
- backend ต้องแยกจาก LAN และ management plane
- deny outbound internet โดย default
- ใช้ local sinkhole, fake mining pool และ local test target เท่านั้น
- ห้ามยิง traffic ไปยัง third-party systems
- ใช้ VM snapshot/reset หรือสร้าง disposable instance ต่อ experiment
- จำกัด CPU, memory, process count, disk และ network rate
- เก็บ telemetry ของ Pi host กับ backend guest แยก namespace กัน
- บันทึก backend image/hash และ isolation policy ไว้กับ dataset receipt

### 3.1 สถานะ hardware pipeline ที่มีอยู่จริง

Hardware path ปัจจุบันเป็น Go pipeline แยกจาก canonical Python analysis path:

```text
hardware-agent
  -> Redis stream raw:hardware
  -> processor-agent
  -> MongoDB hardware_metrics
```

ค่าที่ implementation ปัจจุบันส่งจริงมีเพียง total CPU percent, memory used/percent,
root disk used/percent, CPU temperature และ network byte totals/rates แยกตาม interface
โดยใช้ `NETWORK_SAMPLE_SECONDS` ซึ่งตัวอย่าง config กำหนด 30 วินาที

ข้อจำกัดปัจจุบัน:

- ไม่มี `sensor_id`, `session_id`, `experiment_id` หรือ deterministic telemetry sample ID
  สำหรับ join กับ canonical Cowrie session
- ไม่มี per-process/cgroup metrics, per-core CPU, load/iowait, swap/page faults,
  disk I/O, socket/connection rate หรือ process tree
- README กล่าวถึง packet/error/drop fields แต่ implementation ปัจจุบันยังไม่ emit
- processor ใช้ insert สำหรับ hardware sample จึงต้องออกแบบ idempotency/dedup ใหม่ก่อน
  ใช้เป็น dataset authority
- Hardware collection กับ canonical `honeypot-analysis` อยู่คนละ pipeline/authority
  boundary การใช้ timestamp อย่างเดียวจึงยังไม่เพียงพอสำหรับ causal join

ดังนั้น telemetry เดิมใช้ทำ operational dashboard ได้ แต่ยังไม่พร้อมเป็น training dataset
สำหรับ command-to-resource-impact model โดยไม่เพิ่ม schema, correlation และ provenance

อ้างอิง Cowrie proxy/backend pool:

- https://docs.cowrie.org/en/stable/PROXY.html
- https://docs.cowrie.org/en/latest/BACKEND_POOL.html

## 4. หน่วยข้อมูลและการจัดเวลา

หน่วยข้อมูลหลักที่แนะนำคือ `attack run/session` ไม่ใช่ metric row แต่ละบรรทัด

ข้อมูลขั้นต่ำต่อ run:

```text
experiment_id
scenario_id
attack_run_id
sensor_id
host_id_pseudonymous
session_id
backend_id
backend_image_hash
command_event_id
telemetry_sample_id
telemetry_schema_version
collector_version_or_hash
command_fragment
command_timestamp
metric_timestamp
monotonic_timestamp
clock_sync_error_ms
telemetry_quality_flags
telemetry matrix [time, feature]
process/network evidence
ground_truth_ttp_set
impact_class
attack_start_timestamp
attack_end_timestamp
decision_timestamp
benign_or_malicious
split_group
```

ค่าเริ่มต้นสำหรับทดลอง ซึ่งเปลี่ยนได้หลัง profiling:

- sampling interval: 1 second
- pre-context: 30 seconds ก่อน command/attack start
- detection window: 60–120 seconds หลัง command
- early window: 5, 10, 30 seconds หลัง command โดยตัดข้อมูลที่เกิน decision timestamp
- สร้าง multi-scale features จากช่วง 5, 30 และ 120 seconds

ถ้ามีหลาย command ซ้อนกันใน session ต้องบันทึก causal ambiguity และไม่ผูก resource
spike เข้ากับ command เดียวโดยอัตโนมัติ

## 5. Telemetry ที่ควรเก็บ

### CPU และ platform health

- utilization รวมและราย core
- user/system/iowait/irq/steal
- load average 1/5/15 นาที
- CPU frequency
- temperature
- thermal throttling/undervoltage flags
- context switches และ run queue

### Memory

- used/available/cache
- swap usage และ swap-in/swap-out
- page faults
- reclaim pressure
- OOM kill events
- per-process RSS/PSS เมื่อทำได้

### Disk/filesystem

- read/write bytes และ IOPS
- I/O latency/queue depth
- disk utilization
- free space/inode changes
- executable/file creation ที่สัมพันธ์กับ session

### Network

- RX/TX bytes และ packets ต่อวินาที
- connection attempts/success/failure
- concurrent connections
- unique destination IP/port count
- packet/drop/error rate
- protocol และ destination diversity
- DNS request rate
- per-process socket attribution เมื่อทำได้

### Process/service

- process/thread count
- process start/exit
- executable path/hash
- parent-child process relation
- per-process CPU/memory/network
- service restart/crash
- container/cgroup identifiers

Hardware metrics เพียงอย่างเดียวมักบอกได้ว่ามี resource anomaly แต่ยังบอก intent/TTP
ได้ไม่ดี จึงควรมี command, process และ network evidence ร่วมด้วย

## 6. Label space

ชุดเริ่มต้นที่สอดคล้องกับโจทย์:

| Label | ความหมายใน experiment |
|---|---|
| `T1496` | Resource Hijacking |
| `T1498` | Network Denial of Service |
| `T1499` | Endpoint Denial of Service |
| `T1090` | Proxy |
| `T1046` | Network Service Discovery |
| `NORMAL` | Benign workload |
| `UNKNOWN` | หลักฐานไม่พอหรืออยู่นอก label scope |

ระยะแรกควรใช้ top-level Techniques เพื่อให้เข้ากับ label space ของ ModernBERT เดิม
เมื่อ dataset และ ground truth ละเอียดพอจึงแยก sub-techniques เช่น `T1496.001`
Compute Hijacking หรือ `T1496.002` Bandwidth Hijacking

หนึ่ง session สามารถมีหลาย TTP จึงควรใช้ multi-label head (`sigmoid` + binary loss)
สำหรับ session-level model แต่ experiment แบบ per-command ที่เปรียบเทียบกับโมเดลเดิมต้อง
รักษา single-label top-level target แยกต่างหากเพื่อให้เปรียบเทียบแบบ apples-to-apples

ห้ามใช้ rule outputs หรือ SecureBERT predictions เป็น ground truth labels เพราะจะทำให้
โมเดลเรียนเลียนแบบระบบเดิมและทำให้ evaluation เป็นวงกลม Ground truth ต้องมาจาก
controlled scenario manifest ประกอบกับ execution/process/network evidence

## 7. Scenario design

แต่ละ malicious scenario ต้องมี benign counterexample ที่ใกล้เคียง:

| Malicious behavior | Benign counterexample ที่ควรมี |
|---|---|
| CPU-intensive miner simulation | authorized compile/render/benchmark |
| Memory exhaustion | authorized memory benchmark ภายใต้ limit |
| Disk exhaustion/high writes | backup/copy/log rotation |
| High outbound traffic | authorized backup/upload ไป local target |
| Port/service scanning | authorized inventory/health probe |
| Proxy/tunnel behavior | approved local forwarding test |
| Service crash/restart | planned deployment/service restart |

ต้องเปลี่ยนเครื่องมือ, command spelling, argument, payload location, duration, intensity,
background load และ temperature condition เพื่อป้องกันไม่ให้โมเดลจำเพียงชื่อคำสั่งหรือ
threshold เดียว

Dataset ที่สร้างเองให้ provenance และ ground truth ที่ควบคุมได้ดี แต่ข้อสรุปต้องจำกัดอยู่
ที่ lab distribution จนกว่าจะมี external/real-world validation ที่แยกต่างหาก

## 8. โมเดลที่เสนอ

### 8.1 Baseline A: Aggregated features + XGBoost/Logistic Regression

สร้าง mean, max, min, standard deviation, slope, delta, count และ rate ของแต่ละ metric
ในแต่ละ window แล้วใช้ XGBoost หรือ Logistic Regression

เหตุผล:

- เหมาะกับ dataset เล็ก
- เทรนและ inference เร็ว
- ตรวจ feature importance และ failure mode ได้ง่าย
- เป็น baseline สำหรับตัดสินว่า deep model คุ้มค่าหรือไม่

### 8.2 Baseline B: MiniROCKET

ใช้ MiniROCKET แปลง fixed-length telemetry window เป็น features แล้วต่อด้วย linear
classifier เป็น baseline time-series ที่เร็วและเกือบ deterministic

อ้างอิง: https://arxiv.org/abs/2012.08791

### 8.3 Recommended neural model: Small TCN

Input shape:

```text
[batch, telemetry_features, time_steps]
```

ค่าเริ่มต้นสำหรับ model search:

```text
3–5 residual TCN blocks
channels: 32 → 64 → 128
kernel size: 3 หรือ 5
dilation: 1, 2, 4, 8, ...
telemetry embedding: 64–128 dimensions
dropout: tune เฉพาะ train split
```

เหตุผลที่เหมาะ:

- dilated convolution จับ spike และ sustained pattern หลาย timescales
- เบากว่า time-series Transformer
- inference ขนานและเหมาะกับ CPU
- รวมกับ text branch ผ่าน embedding ได้ง่าย
- สามารถควบคุมขนาดให้เหมาะกับ Raspberry Pi 5

อ้างอิง: https://arxiv.org/abs/1803.01271

### 8.4 Later candidate: PatchTST

พิจารณาเมื่อมี independent sessions จำนวนมากและมี GPU สำหรับเทรน PatchTST แบ่ง
time series เป็น patches เพื่อลด attention cost และเก็บ temporal context ที่ยาวขึ้น

ยังไม่ใช่ตัวเลือกแรกสำหรับ controlled dataset ขนาดเล็กหรือ Pi deployment

- Paper: https://openreview.net/pdf?id=Jbdc0vTOcol
- Classification implementation:
  https://huggingface.co/docs/transformers/model_doc/patchtst

### 8.5 เหตุผลที่ไม่ใช้ SecureBERT ตัวที่สองเป็น telemetry model

- BERT family ถูกออกแบบมาสำหรับ token sequence ไม่ใช่ continuous sensor values
- การ serialize metrics เป็นข้อความทำให้ numerical/temporal structure อ่อนลง
- modality ซ้ำกับ ModernBERT command branch เดิม
- เพิ่ม RAM และ latency บน Pi โดยไม่เพิ่ม inductive bias ที่ตรงกับ telemetry

หากต้องสร้าง multimodal model เดียว ให้ใช้ two-tower architecture: frozen ModernBERT
text tower + TCN telemetry tower ไม่ใช่ BERT สองตัว

## 9. Fusion design

ห้ามนำ raw confidence จากสองโมเดลมาบวกหรือเฉลี่ยโดยตรง เพราะ score ของ ModernBERT
เดิมยังไม่ calibrated probability

แบบที่แนะนำ:

```text
command fragments
    ↓
frozen ModernBERT
    ↓
raw logits / compressed text representation ─────┐
                                                 │
telemetry window                                 ├─ concatenate
    ↓                                            │
MiniROCKET or TCN                                │
    ↓                                            │
telemetry representation ────────────────────────┘
                                                 ↓
                                      Logistic/MLP fusion head
                                                 ↓
                              multi-label TTP + impact predictions
                                                 ↓
                                      existing authority/trust gate
```

เริ่มจาก freeze ModernBERT และ train เฉพาะ telemetry model/fusion head เพื่อลดข้อมูลที่
ต้องใช้และรักษา baseline เดิม หลังจากมีข้อมูลมากพอจึงทดลอง unfreeze เฉพาะ classifier
หรือ layer ท้าย โดยต้องสร้าง experiment identity ใหม่

ถ้า meta-classifier ใช้ predictions จากโมเดลที่ฝึกบน dataset เดียวกัน ต้องสร้าง
out-of-fold base predictions สำหรับ fusion training เพื่อป้องกัน stacking leakage

## 10. Dataset split และ leakage controls

ห้าม random split metric rows หรือ overlapping windows

ให้ group split ด้วยอย่างน้อย:

- `attack_run_id`
- `session_id`
- scenario/tool family
- payload/command template
- experiment day หรือ collection batch

ชุด test ควรมี:

- command variants ที่ไม่ปรากฏใน train
- tool variants ที่ไม่ปรากฏใน train เมื่อข้อมูลพอ
- benign high-load conditions
- background-load/temperature conditions ต่างจาก train
- session duration และ attack intensity หลายระดับ

Scaler, feature selector, tokenizer adaptation, threshold tuning และ calibration ต้อง fit
จาก train/validation เท่านั้น ห้ามอ่าน test distribution ก่อน freeze experiment

## 11. Training objectives

สำหรับ session-level multi-label TTP:

```text
loss_ttp = binary cross entropy หรือ focal loss เมื่อ imbalance สูง
```

แนะนำ multi-task head เพิ่ม:

```text
head 1: multi-label TTP
head 2: NORMAL / RESOURCE_ABUSE / DOS / OUTBOUND_ABUSE / OTHER
head 3: severity หรือ early-impact risk (ถ้ามี ground truth ที่นิยามชัด)
```

ห้ามสร้าง severity label จาก CPU threshold เพียงอย่างเดียวแล้วนำ CPU ค่าเดิมเข้าโมเดล
เพราะจะเป็น label leakage

Class weighting/resampling ต้องกำหนดจาก train split และบันทึกไว้ใน training receipt

## 12. Evaluation matrix

ใช้ frozen test set เดียวกันเปรียบเทียบ:

1. Rules only
2. Rules + ModernBERT เดิม
3. Telemetry aggregated features + XGBoost/Logistic Regression
4. Telemetry MiniROCKET
5. Telemetry TCN
6. ModernBERT + TCN fusion
7. Rules + fused model ภายใต้ authority policy เดิม

ทำ ablation เพิ่ม:

- command only
- hardware only
- process/network only
- hardware + process/network
- command + hardware
- command + hardware + process/network

Metrics ที่ต้องรายงาน:

- Macro-F1 และ Micro-F1
- Precision/Recall/F1 ราย label
- PR-AUC ราย label
- confusion matrix สำหรับ single-label/impact head
- false positives per hour และ per benign session
- false negatives ราย high-impact TTP
- detection latency/early-warning lead time
- peak RSS, CPU utilization และ inference latency บน Pi 5
- ECE/Brier score เมื่อจะอ้างว่า output เป็น calibrated probability
- confidence intervals จาก session-level bootstrap เมื่อ sample size เพียงพอ

Accuracy เพียงตัวเดียวไม่เหมาะเมื่อ classes ไม่สมดุล

Thresholds ต้องเลือกจาก validation set แล้ว lock ก่อนเปิด test set ถ้าต้องใช้ score เป็น
probability ให้ calibrate ด้วย calibration split แยกจาก train และ final test

## 13. Deployment และ authority

ลำดับนำขึ้นใช้งาน:

```text
offline evaluation
    ↓
shadow inference / audit-only
    ↓
latency and memory profiling on Pi 5
    ↓
drift/false-positive observation
    ↓
reviewed implementation decision
```

ข้อกำหนด production:

- model, config, scaler, feature order และ label mapping ต้องมี content hashes
- บันทึก observation window และ truncation/missing-feature flags ใน evidence
- ตรวจ finite values, tensor shape, label order และ clock alignment ก่อน inference
- missing telemetry ต้อง fail ไปเป็น audit-only/unknown ตาม policy
- มี inference timeout และ resource limit
- export/quantize เป็น ONNX/INT8 ได้หลังทำ equivalence test เท่านั้น
- model-only และ fusion-only outputs เริ่มต้นเป็น audit-only
- ห้ามเปลี่ยน rule authority จากผล accuracy experiment โดยอัตโนมัติ
- shadow feeder ต้องรับเฉพาะ projection ที่จำเป็นต่อ inference; ห้ามส่ง credentials,
  raw session object หรือข้อมูลที่ไม่จำเป็น
- prediction record ต้องเก็บ model/config/feature-schema hashes, evidence cutoff,
  source session revision และ missing/alignment flags
- ใช้ service account และ filesystem boundary แยกจาก canonical writer ตาม pattern ของ
  next-distinct shadow predictor ที่มีอยู่

## 14. Implementation phases และ exit gates

### Phase 0 — Experiment contract

- [ ] นิยาม detection กับ prediction แยกกัน
- [ ] freeze label definitions และ ATT&CK version
- [ ] ออกแบบ scenario/benign counterexamples
- [ ] กำหนด isolation และ outbound-deny policy
- [ ] กำหนด dataset schema และ clock source

Exit gate: experiment manifest ผ่าน review และไม่มี external target

### Phase 1 — Data collection pipeline

- [ ] Cowrie/backend event IDs เชื่อมกับ telemetry ได้
- [ ] เพิ่ม `sensor_id`, pseudonymous `host_id`, deterministic `telemetry_sample_id`
      และ schema/collector identity
- [ ] ทำ hardware writes ให้ idempotent หรือมี dedup contract ที่ตรวจได้
- [ ] เก็บ guest, cgroup, process และ network telemetry
- [ ] บันทึก command timestamps และ decision timestamps
- [ ] reset backend ได้ reproducibly
- [ ] สร้าง immutable run receipts และ hashes

Exit gate: replay หนึ่ง run แล้วได้ command/telemetry/label ตรงกัน

### Phase 2 — Dataset production

- [ ] เก็บ malicious scenarios หลาย variants
- [ ] เก็บ benign counterexamples
- [ ] ตรวจ missing data และ timestamp drift
- [ ] group train/validation/calibration/test split
- [ ] ตรวจ duplicate/near-duplicate leakage

Exit gate: frozen dataset manifest และ split membership

### Phase 3 — Baselines

- [ ] Rules only
- [ ] ModernBERT เดิม
- [ ] Aggregated features + XGBoost/Logistic Regression
- [ ] MiniROCKET

Exit gate: reproducible baseline report

### Phase 4 — TCN และ fusion

- [ ] train telemetry-only TCN
- [ ] freeze ModernBERT และ extract text features
- [ ] train fusion head
- [ ] run ablation และ threshold selection
- [ ] evaluate locked test set หนึ่งครั้งตาม protocol

Exit gate: fusion ชนะ baseline ตาม predeclared metrics โดยไม่เพิ่ม false positives หรือ
resource cost เกิน budget

### Phase 5 — Pi 5 shadow deployment

- [ ] verify model assets ก่อน load
- [ ] วัด RSS/CPU/latency/temperature
- [ ] เก็บ audit-only predictions
- [ ] ตรวจ drift, missing telemetry และ operational failures

Exit gate: ผ่านระยะ shadow ที่กำหนดและมี implementation review ใหม่ก่อนพิจารณา authority

## 15. สิ่งที่ต้องบันทึกเพื่อ reproducibility

- dataset source/ownership/license statement
- exact run and split membership
- scenario scripts และ hashes
- backend image/config/network-policy hashes
- telemetry collector/version/feature order
- clock synchronization method
- preprocessing/scaler parameters
- base checkpoint and tokenizer hashes
- model architecture/hyperparameters
- optimizer, learning-rate schedule, epochs, batch size
- random seeds และ deterministic settings
- class weights/sampling policy
- training, validation, calibration และ test metrics
- selected thresholds และเหตุผล
- model/runtime dependency lock

## 16. Open decisions

- [ ] งานหลักเป็น per-command classification หรือ session-level multi-label detection
- [ ] ต้องการ early prediction ก่อนผลกระทบกี่วินาที
- [ ] backend รันบน Pi, VM เครื่องอื่น หรือ remote backend pool
- [ ] telemetry collector และ sampling interval ที่ Pi รับไหว
- [ ] label set ใช้ top-level อย่างเดียวหรือมี sub-techniques
- [ ] จำนวน independent runs ต่อ scenario ที่ทำได้จริง
- [ ] memory/latency/temperature budget สำหรับ production inference
- [ ] fusion ใช้ full logits, top-k features หรือ frozen encoder embedding

## 17. Implementation live update — 2026-09-01

สถานะปัจจุบันขยับจาก design-only เป็น `STAGE A IDLE PILOT VERIFIED` แล้ว:

- สร้าง `cowrie-hardware-fusion` project boundary แยกจาก production path
- มี run manifest, raw telemetry และ derived-window JSON Schemas
- implement dataset builder `0.1.0` สำหรับ completed controlled run
- builder สร้าง XGBoost aggregate features รวม `cpu_p95`, baseline deltas, duration,
  memory/disk/network/process/thermal features
- builder สร้าง fixed-length TCN channels พร้อม `sample_present` และ
  `channel_present` masks โดยยังไม่ fit scaler/imputer
- identifiers, timestamps, scenario ID และ split groups แยกอยู่นอก model feature block
- default gate ต้องได้ target และ baseline coverage อย่างน้อย 99%, sequence ไม่ซ้ำ,
  monotonic clock เพิ่ม, NTP synchronized และไม่ข้าม boot
- output มี deterministic content hashes และ validate กับ derived schema
- experimental collector `0.2.0` สำหรับ `pi_sensor` neutral-idle Stage A เขียนเฉพาะ
  bounded immutable local spool ไม่มี Redis/Mongo/cloud/workload execution path
- network schema ระบุ `include_in_aggregate` เพื่อห้ามนับ `wlan0` กับ overlay traffic ซ้ำ
- มี manifest finalizer ที่ตรวจ receipt/segment hashes, counts และ contiguous sequences
  ก่อนสร้าง completed manifest copy
- automated tests ปัจจุบันผ่าน 17 tests ครอบคลุม percentile semantics, missing/leading
  sample alignment, duplicates, correlation, determinism, spool interruption/no-overwrite,
  raw/receipt schemas, multi-segment input และ synthetic 90-sample replay จาก collector
  เข้า builder
- deploy แบบ manual เฉพาะงานทดลองผ่าน detached worktree/isolated venv บน Pi โดยไม่แก้
  production worktree หรือ service configuration
- neutral-idle pilot สำเร็จ 3 runs รวม 270/270 valid samples ไม่มี late/missing/reset/error
- finalizer บนเครื่อง dev ยืนยัน hashes/counts/sequence หลัง transfer และ completed
  manifests ตรงกับที่ Pi สร้างแบบ byte-for-byte
- replay immutable segments เป็น XGBoost/TCN windows 5/10/30 วินาทีได้ coverage 100%
- raw เฉลี่ย 3,584.13 bytes/sample หรือประมาณ 295.32 MiB/วัน/scope ที่ 1 Hz;
  gzip estimate จาก idle pilot ประมาณ 27.94 MiB/วัน

ไฟล์ implementation หลัก:

- `src/cowrie_hardware_fusion/dataset.py`
- `src/cowrie_hardware_fusion/collector.py`
- `src/cowrie_hardware_fusion/spool.py`
- `src/cowrie_hardware_fusion/cli.py`
- `schemas/derived_training_window.v1.schema.json`
- [Dataset builder v1](../dataset_builder.v1.md)
- [Experimental 1 Hz collector v1](../experimental_collector.v1.md)

สิ่งที่ยังไม่ถือว่าเสร็จ:

- feature/channel schema ยังไม่ freeze จนกว่าจะมี ordinary-load counterexamples
- collector ยังไม่เป็น service; isolated venv มี `psutil` แต่ system Python ไม่ถูกแก้
- ยังไม่มี uploader, Atlas experimental time-series หรือ rollup
- ยังไม่ได้สร้าง command-event correlation, batch split หรือ model training
- ยังไม่มี XGBoost/TCN/Fusion checkpoint

ลำดับถัดไปคือ implement safe ordinary-load orchestration ที่ไม่มี attacker-controlled
execution, เพิ่ม receipt-driven batch discovery/grouped split และเก็บ benign
counterexamples หลายเวลา ก่อน freeze feature/channel schema และเทรน trivial/XGBoost
baseline; neutral-idle pilot นี้เป็น `pilot_only=true` และห้ามใช้รายงาน model accuracy

## References

- Detailed XGBoost/TCN/Fusion architecture:
[model_architecture_xgboost_tcn_fusion.v1.md](../model_architecture_xgboost_tcn_fusion.v1.md)
- Existing model live state: [securebert_modernbert_live_state.md](securebert_modernbert_live_state.md)
- Existing model review: [securebert_review_final_report.v1.md](securebert_review_final_report.v1.md)
- Main production architecture: `honeypot-analysis/CURRENT_SYSTEM_FULL_TECHNICAL_DOCUMENTATION.md`
- Existing isolated sidecar pattern: `honeypot-analysis/production/prediction_next_distinct_poc/`
- Current hardware implementation: `agents/hardware-agent/main.go`
- Hardware persistence path: `agents/processor-agent/main.go`
- TCN: https://arxiv.org/abs/1803.01271
- MiniROCKET: https://arxiv.org/abs/2012.08791
- XGBoost: https://arxiv.org/abs/1603.02754
- PatchTST: https://openreview.net/pdf?id=Jbdc0vTOcol
- MITRE Resource Hijacking: https://attack.mitre.org/techniques/T1496/
- MITRE Network DoS: https://attack.mitre.org/techniques/T1498/
- MITRE Endpoint DoS: https://attack.mitre.org/techniques/T1499/
- MITRE Proxy: https://attack.mitre.org/techniques/T1090/
- Cowrie proxy: https://docs.cowrie.org/en/stable/PROXY.html
- Cowrie backend pool: https://docs.cowrie.org/en/latest/BACKEND_POOL.html
