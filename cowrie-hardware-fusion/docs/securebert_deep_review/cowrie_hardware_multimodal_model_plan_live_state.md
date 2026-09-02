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

## 17. Implementation live update — 2026-09-01 ถึง 2026-09-02

สถานะปัจจุบันขยับจาก design-only เป็น
`STAGE A VERIFIED / STAGE B PRE-EXECUTION TOOLING` แล้ว:

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
- automated tests ปัจจุบันผ่าน 26 tests ครอบคลุม percentile semantics, missing/leading
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
- receipt-driven indexer ตรวจ completed manifest, receipt, raw segment hashes/bytes/schema/
  sequence แล้ว freeze exact dataset membership
- grouped splitter exclude pilot runs และป้องกัน shared leakage axes ข้าม partition ด้วย
  connected components; Stage A index hash `63a10edf...e3599b9` มี eligible runs เท่ากับ 0
  จึง fail split ตามที่ออกแบบ
- bounded-workload preflight ตรวจ benign compute contract สำหรับ OCI container ภายใน
  disposable VM พร้อม no-network/read-only/drop-capabilities/no-new-privileges/seccomp
  และ resource/watchdog limits โดยยังไม่มี execution adapter

ไฟล์ implementation หลัก:

- `src/cowrie_hardware_fusion/dataset.py`
- `src/cowrie_hardware_fusion/collector.py`
- `src/cowrie_hardware_fusion/spool.py`
- `src/cowrie_hardware_fusion/batch.py`
- `src/cowrie_hardware_fusion/workload.py`
- `src/cowrie_hardware_fusion/cli.py`
- `schemas/derived_training_window.v1.schema.json`
- [Dataset builder v1](../dataset_builder.v1.md)
- [Experimental 1 Hz collector v1](../experimental_collector.v1.md)
- [Bounded workload contract v1](../bounded_workload_contract.v1.md)

สิ่งที่ยังไม่ถือว่าเสร็จ:

- feature/channel schema ยังไม่ freeze จนกว่าจะมี ordinary-load counterexamples
- collector ยังไม่เป็น service; isolated venv มี `psutil` แต่ system Python ไม่ถูกแก้
- ยังไม่มี uploader, Atlas experimental time-series หรือ rollup
- ยังไม่ได้สร้าง command-event correlation, eligible split หรือ model training
- ยังไม่มี disposable backend/runtime adapter และ workload preflight ไม่ execute งาน
- ยังไม่มี XGBoost/TCN/Fusion checkpoint

ลำดับถัดไปคือ provision/review disposable backend, implement backend telemetry/runtime
adapter ตาม bounded-workload contract แล้วเก็บ benign counterexamples หลายเวลา ก่อน
freeze feature/channel schema และเทรน trivial/XGBoost baseline; neutral-idle pilot นี้
เป็น `pilot_only=true` และห้ามใช้รายงาน model accuracy

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

## 18. Pi two-TTP PoC live update — 2026-09-02

ส่วนนี้ supersede สถานะ `STAGE B PRE-EXECUTION TOOLING` ในข้อ 17 สำหรับ PoC ขนาดเล็ก
เท่านั้น สถาปัตยกรรม production ยังคงให้ training/inference หลักอยู่ Cloud และ Pi เป็น
sensor/controlled data generator

สถานะ: `SUPERSEDED BY SECTION 19 / PI EXECUTION COMPLETE`

- เลือก 2 behavior candidates แรกคือ `T1496.001 Compute Hijacking` และ
  `T1499.002 Service Exhaustion Flood`
- เพิ่ม paired benign compute/service controls และ neutral idle เพื่อไม่ให้โมเดลจำเพียง
  ว่า CPU สูงเท่ากับ malicious
- matrix v1 มี 5 scenarios × 3 repetitions, interleave ตาม repetition; run ละ
  baseline/workload/recovery 30/30/30 วินาที ที่ 1 Hz รวม 15 runs/1,350 samples
- ค่า 25/75 เป็น treatment intensity metadata; model features ยังคงใช้ continuous raw
  measurements และ aggregate mean/max/p95/slope/delta ไม่ใช้การหารเป็น rank 1–4
- collector ขยับเป็น `0.3.0`; idle contract เดิมยัง fail closed และ controlled path รับ
  เฉพาะ `poc_pi_*` manifest ที่ใช้ `safe_container`
- workload เป็น static ARM64 Go binary ใน scratch image: bounded SHA-256 compute หรือ
  HTTP server/client ที่ loopback ภายใน container เดียว ไม่มี mining protocol, raw
  Cowrie command, host mount, DNS หรือ external target
- runtime บังคับ network none, read-only rootfs, non-root UID/GID, drop all capabilities,
  no-new-privileges, default seccomp, CPU 0.25/0.75 core, RAM 128 MiB และ PID 16
- preflight ผูก catalog/manifest/spec/collector/binary/image hashes และตรวจ cgroup v2,
  Docker seccomp, RAM/disk/load/temperature gates ก่อนทุก run
- workload phase เก็บ target process CPU/RSS/threads/socket/cgroup identity เพิ่มจาก host
  metrics เดิม; baseline/recovery target เป็น null
- data เขียนเฉพาะ bounded local spool และ execution/collection receipts ไม่เปิด Go
  hardware agent production และไม่เขียน Atlas
- automated tests ปัจจุบันผ่าน 30 Python tests; Go compute/service bounds tests ผ่าน โดย
  local sandbox skip socket integration และกำหนดให้ service integration ต้องผ่านบน Pi
- PoC จะ train XGBoost smoke baseline ด้วย repetition-held-out folds หลัง transfer และ
  verify immutable data; TCN/Fusion รับ sequence ได้แต่ห้ามอ้าง accuracy จากเพียง 15 runs

เอกสารและ implementation หลัก:

- [Pi safe-container PoC runbook](../pi_poc_runbook.v1.md)
- `src/cowrie_hardware_fusion/poc.py`
- `workloads/poc-workload/`
- `schemas/pi_poc_workload_spec.v1.schema.json`
- `schemas/pi_poc_execution_receipt.v1.schema.json`
- `schemas/pi_poc_matrix.v1.schema.json`

## 19. Pi two-TTP PoC result — 2026-09-02

สถานะ: `MATRIX COMPLETE / XGBOOST SMOKE COMPLETE / T1499 BRANCH NOT PASSED`

- Pi matrix v2 รันครบ 15/15 runs ได้ 1,350/1,350 valid samples และ workload windows
  15/15 ชุดที่ sample/baseline coverage 100%
- controlled workload 12/12 runs ไม่มี workload error, cleanup ผ่านทั้งหมด และไม่กระทบ
  production containers; ไม่มี Redis/MongoDB/Atlas write
- transfer archive SHA-256 ตรงกันระหว่าง Pi/local และ local re-index ให้ source index file
  ตรงกับ Pi ทุก byte; canonical index hash คือ
  `72fcb6b7b3a6c5bea70226100cbabf4a73a7349871c96f421957f62fc862bf42`
- XGBoost ใช้ 54 continuous aggregate features และ repetition-held-out 3 folds โดยแต่ละ fold
  train 10/test 5 runs; ไม่มี repetition เดียวกันข้าม train/test
- out-of-fold Accuracy `0.80`, Macro-F1 `0.619`; NO_TTP ถูก 9/9, T1496.001 ถูก 3/3,
  แต่ T1499.002 ถูก 0/3 และถูกทำนายเป็น NO_TTP ทั้งหมด
- ผลนี้ยืนยัน end-to-end pipeline และ compute signal เท่านั้น ยังไม่ใช่ production accuracy
  และยังไม่สนับสนุนให้ deploy hardware checkpoint หรือเริ่ม Fusion
- next gate คือ freeze feature/training protocol v2 ก่อนเก็บ independent runs ใหม่อย่างน้อย
  10–20 runs ต่อ scenario หลายวัน เพิ่ม production-observable service pressure และคง final
  test ไว้ unopened; TCN ยังไม่เหมาะกับ dataset 15 runs

รายละเอียด evidence, hashes, telemetry และ confusion matrix:
[pi_poc_results_2026-09-02.md](../pi_poc_results_2026-09-02.md)

## 20. Hardware-impact protocol v2 และ Go Agent parity — 2026-09-02

สถานะ: `PROTOCOL FROZEN / COMMON-METRIC PARITY PASSED / DEVELOPMENT DATA NOT STARTED`

ส่วนนี้ supersede “next gate” ในข้อ 19:

- freeze protocol `pi-hardware-impact-v2-20260902` ก่อนเก็บ independent data ใหม่;
  canonical SHA-256 คือ
  `8eb0786e8427f7fa685a8d137db62b1ecfff40a7897b65f742915477b9b2471d`
- hardware XGBoost เปลี่ยน target จาก TTP เป็น observed `primary_impact` สาม class:
  no material impact, compute saturation และ service pressure
- `T1496.001`/`T1499.002` เหลือบทบาท ground-truth metadata และ Fusion evaluation;
  ModernBERT ยังเป็น command-intent/TTP candidate branch
- scenario v2 มี 7 matched neutral/benign/malicious simulations โดย compute และ service
  แต่ละ impact มี benign/malicious pair ที่ family/intensity เท่ากัน เพื่อไม่ให้ hardware
  model อ้าง intent ที่ telemetry แยกไม่ได้
- แผนเต็ม 20 repetitions/scenario = 140 runs/12,600 samples อย่างน้อย 5 วัน แบ่ง
  development 70, calibration 35 และ locked final test 35 runs; หยุด review หลัง
  development wave ไม่เปิด final test ระหว่างแก้ feature
- feature profiles ถูก freeze เป็น Go-overlap diagnostic 25 features, host-extended 48 และ
  target-augmented 54 features; intensity, scenario, label, IDs และ timestamp ถูกห้ามเข้า
  model
- XGBoost v2 ใช้ balanced class weights/fixed parameters/no tuning; TCN ถูก gate ไว้จนกว่า
  XGBoost และจำนวน independent runs จะผ่าน
- เพิ่ม semantic protocol validator และ automated tests รวมปัจจุบัน 44 Python tests

Feature-parity audit บน `pi-z` ใช้ proposed static ARM64 Go binary และ experimental
Python collector แบบ read-only/no-sink โดยไม่แก้/restart production service และไม่เขียน
Redis/MongoDB/Atlas พบว่า legacy gopsutil memory กับ psutil นิยาม `used` ไม่เหมือนกัน จึง
เพิ่ม explicit Go `mem_pressure_* = total - available` แทนการขยาย tolerance หลังแก้แล้ว
probe 5 คู่ผ่าน 225/225 common-field comparisons

คำว่า parity ผ่านในที่นี้ไม่ใช่ full collector parity: Go Agent ยังขาด run/sample identity,
clock/quality metadata, per-core/disk-I/O/socket/process/thermal health, target cgroup และ
immutable receipt-bound spool ดังนั้น experimental collector ยังคงเป็น dataset authority
และห้ามเปิด Go Agent ที่ 1 Hz เข้า ordinary Redis/Atlas

ลำดับถัดไป:

1. เพิ่ม production-observable service-pressure features และ receipt-bound local collection
2. review safe workload/collector manifests กับ protocol hash
3. เก็บเฉพาะ development wave 70 runs บน Pi หลายวัน
4. transfer/hash-verify แล้ว train fixed XGBoost บน Arch/Cloud
5. หยุดตรวจ signal/per-class recall/false positives ก่อนเก็บ calibration wave

เอกสาร authority/evidence:

- [Hardware-impact experiment protocol v2](../hardware_impact_experiment_protocol.v2.md)
- [Hardware Go Agent feature-parity audit](../hardware_agent_feature_parity_2026-09-02.md)

## 21. Service-pressure observability implementation — 2026-09-02

สถานะ: `COLLECTOR 0.4.0 IMPLEMENTED / PI CANARY PASS / SIGNAL PILOT NOT STARTED`

ส่วนนี้ supersede ลำดับถัดไปข้อ 1 ใน Section 20:

- experimental collector `0.4.0` เพิ่ม host CPU/memory/I/O PSI, TCP states, socket
  allocation และ kernel listen/backlog/queue/memory-pressure totals/rates
- target observation เพิ่ม context switches, network-namespace TCP states/socket/pressure
  และ cgroup v2 CPU usage/throttling, memory events, PID usage, aggregate I/O และ
  CPU/memory/I/O PSI
- parser ไม่ persist address, port, raw IP, raw PID, command, credential หรือ simulator
  operation count; collector source hash รวม module service-pressure แล้ว
- Pi host no-sink snapshot valid โดย missing/error 0 และ target safe-container canary
  revision 4 valid/schema-valid โดย missing/error 0
- target canary เห็น TCP listen 1, established 2 และ cgroup blocks CPU/memory/PID/I/O/PSI
  ครบ; readable empty `io.stat` ถูกนิยามเป็น zero I/O ไม่ใช่ missing
- ทดลองอ่าน per-process FD/I/O แล้วพบ cross-UID permission boundary จึงตัด field นี้ออกและ
  ไม่เพิ่ม root/ptrace capability; ใช้ cgroup I/O ที่อ่านได้โดยไม่ยกระดับสิทธิ์แทน
- safe canary ใช้ `network=none`, read-only, non-root และ hard limits; cleanup ผ่าน,
  production containers 9 ตัว, ไม่มี `chf-*` ค้าง และไม่มี Redis/MongoDB/Atlas write
- automated tests ปัจจุบันผ่าน 52 tests

Metric ใหม่ยังเป็น raw candidate observability และยังไม่ถูกเพิ่มเข้า frozen model feature
profile เพราะ canary เดียวพิสูจน์ availability แต่ไม่พิสูจน์ class-separation signal ขั้นถัดไป
คือสร้าง 7-scenario instrumentation matrix แบบ `pilot_only=true` scenario ละหนึ่ง run แล้ว
วัด coverage/baseline deltas ก่อน freeze feature/profile revision และก่อน development wave
70 runs

รายละเอียด fields, privacy decision และ evidence hashes:
[service_pressure_observability.v1.md](../service_pressure_observability.v1.md)

## 22. Service-pressure instrumentation tooling — 2026-09-02

สถานะ: `TOOLING READY / 7 PI RUNS NOT STARTED`

ส่วนนี้ supersede “ขั้นถัดไป” ใน Section 21 เฉพาะงานเตรียม tooling:

- เพิ่ม generator สำหรับ protocol-v2 scenarios ครบ 7 ตัว; scenario ละหนึ่ง run,
  baseline/workload/recovery 30/30/30 วินาทีที่ 1 Hz รวม 630 planned samples
- matrix ผูก canonical protocol hash, scenario catalog byte hash, collector source,
  telemetry schema, ARM64 image/workload implementation, repository commit และ Pi
  environment signature
- matrix, manifests และ specs บังคับ `pilot_only=true`, `training_eligible=false` และ
  `changes_frozen_feature_set=false`; 7 runs นี้ใช้ตัดสิน instrumentation เท่านั้น
- compute high benign/T1496.001 และ service high benign/T1499.002 ใช้ hardware treatment
  เดียวกันเป็น matched pairs; TTP/disposition ไม่ถูกใช้เป็น candidate value
- แยก service `protocol_intensity=10/150 requests_per_second` จาก manifest assigned
  service capacity 25/75% เพื่อไม่ตีความ 150 เป็น CPU percent
- collector patch `0.4.1` เพิ่ม exact allowlist สำหรับ protocol-v2 idle/controlled
  scenarios โดยไม่เปลี่ยน telemetry semantics; runtime ยังคง fixed image,
  `network=none`, non-root, read-only และ hard limits
- collector `0.4.1` source hash คือ
  `f56cce1858f3d604e5e298258fc0d1af076fafaf03d9e3a6c17ae454e291d1a3`;
  telemetry schema hash ยังคง `b99697c8...a4d4e` และ protocol canonical hash ยังคง
  `8eb0786e...2471d`
- เพิ่ม report builder สำหรับ host/target PSI, TCP state/socket/drop และ target cgroup
  CPU/memory/PID/I/O metrics สรุป coverage/mean/p95/max/delta แยก phase
- target ไม่มี baseline ตาม design จึงไม่สร้าง delta ปลอม; signal เข้า feature-freeze
  review เมื่อ workload coverage ≥90% และ host signal ต้องมี baseline coverage ≥90%
- report ผูก completed manifest/segment hashes และมี `model_feature_eligible=false` เสมอ;
  simulator operation count ไม่ถูกใช้เป็น model feature
- automated tests ปัจจุบันผ่าน 55 tests รวม matrix exclusion, schema bindings,
  matched-pair invariants และ synthetic signal summary

ขั้นถัดไปคือ query image/environment identity จริงจาก Pi หลัง freeze commit, generate
control artifacts, รัน preflight แล้วจึงรัน 7 excluded instrumentation runs พร้อม verify
cleanup/receipts ก่อน transfer กลับ Arch เพื่อสร้าง signal reports

รายละเอียด matrix, intensity semantics, commands และ selection gate:
[service_pressure_instrumentation_pilot.v1.md](../service_pressure_instrumentation_pilot.v1.md)

## 23. Service-pressure instrumentation result — 2026-09-02

สถานะ: `7/7 COMPLETE / TELEMETRY PASS / SERVICE-TREATMENT GATE NOT PASSED`

ส่วนนี้ supersede “7 PI RUNS NOT STARTED” ใน Section 22:

- deploy source/control archives ไป isolated Pi directory โดย source/control SHA-256 ตรง
  Arch/Pi และไม่แก้ production worktree หรือ services
- preflight ผ่าน NTP, interfaces/disk, cgroup v2, Docker seccomp, ARM64 image identity,
  RAM/disk/load/temperature gates ก่อน execution
- รัน 7/7 scenarios ได้ 630/630 valid samples; baseline/workload/recovery 210/210/210,
  missing/error/reset 0, completed manifests 7, segments 21 และ controlled cleanup 6/6
- มี late sample 1 จุดที่ service-low workload sequence แรก 1,148.257 ms เพราะ Docker
  lifecycle hook ใช้เวลาหลัง deadline ถูกกำหนด ต้อง reset deadline หลัง hook ก่อนเก็บ
  development sequence
- service high เทียบ low: cgroup CPU usage ~27.5×, CPU PSI ~11.3×, memory ~2.3×;
  benign/T1499 high pair ต่างกันเพียง ~0.32%, 1.69%, 3.77% ตามลำดับ จึงยืนยันว่า
  collector เห็น target resource response และ matched treatment ทำงาน
- target TCP total/established/socket คงที่ 3/2/5, queue/drop rates เป็นศูนย์,
  memory/I/O PSI เป็นศูนย์ และ execution errors 0 ทั้ง service-high pair จึงยังไม่มี
  evidence แข็งแรงพอรองรับ `SERVICE_PRESSURE` label
- compute-low ที่ full duty ภายใต้ quota 0.25 core มี throttled time/CPU PSI สูงกว่า
  compute-high 0.75 core เป็น inverse-throttling simulator artifact; ห้ามใช้ cgroup pressure
  ชุดนี้ฝึก class โดยไม่แก้ treatment
- Pi→Arch result archive SHA-256 ตรงกันคือ
  `4feddbda88b3207d3e9f8a0ca264f38d3843edda164205b0749d6a11e0e7a360`;
  Arch regenerate reports หลัง verify receipt/raw schema แล้วได้ไฟล์ตรง Pi ทุก byte
- candidate ที่นำไปทดสอบซ้ำคือ cgroup CPU usage, CPU PSI, memory current และ host CPU PSI
  delta; ยังไม่เพิ่มเข้า frozen feature profiles และ 7 runs ยังคง excluded
- ไม่มี malware/miner/external target/Redis/MongoDB/Atlas write, ไม่มี experiment container
  ค้าง; production 9 containers, hardware service inactive และ processor active

ขั้นถัดไปคือแก้ phase scheduler, เปลี่ยน compute treatment จาก quota artifact เป็น bounded
duty/worker allocation, เพิ่ม bounded short-lived loopback connection/concurrency พร้อม
latency/error evidence gate แล้ว freeze workload image/spec revision ใหม่เพื่อ rerun excluded
pilot ก่อนเริ่ม development 70 runs Training v2 และ final test ยังไม่เริ่ม

รายละเอียด evidence hashes, operation counts, signal table และ gate decision:
[service_pressure_instrumentation_results_2026-09-02.md](../service_pressure_instrumentation_results_2026-09-02.md)

## 24. Service-pressure treatment revision v2 — 2026-09-02

สถานะ: `IMPLEMENTED / LOCAL TEST PASS / EXCLUDED PI RERUN PENDING`

ส่วนนี้ supersede ขั้นแก้ treatment ใน Section 23 แต่ยังไม่ supersede ผล pilot v1:

- collector `0.4.2` reset sample deadline หลัง lifecycle hook เพื่อกัน Docker startup/stop
  time สร้าง late sample ปลอม; slow-hook test ได้ 90/90 samples โดย late 0
- compute low/high เปลี่ยนเป็น duty cycle 25/75% ภายใต้ hard ceiling 1 CPU เดียวกัน
  แทน full-duty ที่ quota 0.25/0.75 ซึ่งสร้าง inverse-throttling artifact
- service ใช้ short-lived loopback connections, client concurrency 8, server capacity 2,
  bounded delay 40 ms และ low/high 10/150 requests/s; ยังคง `network=none`
- workload summary v2 เพิ่ม attempts/rejected/p95 latency และ finalize gate บังคับให้
  service-high มี error fraction ≥20%, rejection ≥1 และ p95 ≥20 ms; service-low ต้อง
  rejection=0/error≤5%; summary เป็น label evidence และห้ามใช้เป็น model feature
- เพิ่ม matrix/spec schema v2 โดยเก็บ v1 ไว้เป็น historical contract; entrypoint identity
  เปลี่ยนเป็น `poc_workload_v2`
- Python suite ผ่าน 58 tests; Go config/compute ผ่าน ส่วน loopback integration จะยืนยันบน Pi
- revision นี้ยังเป็น `pilot_only=true`, `training_eligible=false`; ห้ามเริ่ม 70-run
  development wave จนกว่า ARM64 image และ excluded 7-run rerun จะผ่าน treatment/telemetry gate

ขั้นถัดไปคือ freeze commit, build/hash ARM64 image, ทำ service integration canary บน Pi,
generate v2 artifacts แล้ว rerun 7 scenarios/630 samples ก่อนตัดสิน feature revision

รายละเอียด treatment, evidence thresholds และ run order:
[service_pressure_treatment_revision.v2.md](../service_pressure_treatment_revision.v2.md)

## 25. Service-pressure v2 excluded pilot result — 2026-09-03

สถานะ: `7/7 COMPLETE / QUALITY PASS / TREATMENT GATES PASS`

ส่วนนี้ supersede `EXCLUDED PI RERUN PENDING` ใน Section 24:

- freeze commit `95d7970`; ARM64 binary `c5ef621d...eb86`; final labeled image
  `sha256:bcb5296b...e24c3`; matrix canonical hash `0c1bab3b...4e07`
- image canary ตัวแรกไม่มี OCI revision label จึงถูก preflight ปฏิเสธก่อน collection;
  rebuild จาก reviewed Dockerfile พร้อม binary-hash label แล้ว final preflight ผ่าน
- รันครบ 7/7, 630/630 valid samples, phase 210/210/210, 21 segments,
  late/missing/error/reset 0 และ controlled cleanup 6/6
- service-low มี 301 attempts, rejection 0, error 0.33%, p95 ~41 ms; high benign/T1499
  มี ~4,524 attempts, rejection ~3,200, error ~70.7%, p95 ~41.4 ms ทุก gate ผ่าน
- compute cgroup CPU high/low ~2.97× และ throttling เป็นศูนย์ทั้งคู่ จึงแก้ quota artifact
- service high/low: TIME_WAIT ~15.6×, CPU PSI ~9.4×, CPU usage ~8.4×,
  memory ~1.6×; matched benign/T1499 signals หลักต่างประมาณ 0.1–2%
- export Pi→Arch SHA-256 ตรงกัน `5570a87c...edf1`; audit summary byte-identical และ
  Arch regenerate signal reports ตรง Pi 7/7
- candidate review คือ cgroup CPU usage, TCP TIME_WAIT, target socket summary,
  cgroup memory และ CPU PSI ablation; queue/drop เป็นศูนย์และ simulator receipt ยังคง
  forbidden model input
- ต้องแยก host-only กับ target/cgroup-required profiles; ห้ามอ้าง target profile deployable
  กับ Cowrie production ก่อนทำ target mapping และ shadow availability test

ขั้นถัดไปคือ freeze XGBoost aggregate features/TCN channels revision ใหม่จาก candidate ที่
ผ่าน แล้วทดสอบ builder กับ raw pilot ก่อน generate development wave 70 runs โดย final test
ยังคงปิด

รายละเอียด hashes, execution evidence, signal table และ feature decision:
[service_pressure_v2_pilot_results_2026-09-03.md](../service_pressure_v2_pilot_results_2026-09-03.md)
