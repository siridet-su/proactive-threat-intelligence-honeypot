# Cowrie Hardware Fusion Experiment Contract v1

> สถานะ: `DRAFT / PRE-COLLECTION`  
> วันที่ freeze ร่างแรก: 2026-09-01 (Asia/Bangkok)  
> Authority: research-only; output ทั้งหมดเป็น shadow/audit-only

## 1. วัตถุประสงค์

ทดสอบว่า hardware/process/network telemetry ที่มี provenance และ time alignment ชัดเจน
ช่วยเพิ่มคุณภาพการจำแนก resource-impact TTP candidates เมื่อรวมกับ ModernBERT
command evidence ได้หรือไม่ โดยเปรียบเทียบกับ command-only และ hardware-only baselines
บน independent held-out runs

ระบบต้องตอบคำถามแยกกันสามงาน:

1. **Hardware impact detection:** มีผลกระทบชนิดใดเกิดขึ้นจริงใน observation window
2. **Command intent classification:** ModernBERT เสนอ ATT&CK candidate ใดจาก command
3. **Fusion classification:** command intent และ observed impact สนับสนุนหรือขัดกันอย่างไร

Hardware branch ไม่มีหน้าที่อนุมาน malicious intent จาก CPU/RAM/network เพียงอย่างเดียว

## 2. ขอบเขตที่ยืนยันจากระบบจริง

Read-only audit ของ `pi-z` วันที่ 2026-09-01 ยืนยันว่า:

- Raspberry Pi เป็น ARM64, 4-core Cortex-A76, RAM ประมาณ 8 GB และไม่มี swap
- เวลาเครื่องเป็น Asia/Bangkok และ NTP synchronized
- Cowrie ทำงานด้วย `[honeypot] backend = shell` ซึ่งเป็น emulation
- `honeypot-hardware.service` ติดตั้งอยู่แต่ disabled/inactive ตอนตรวจ
- hardware agent เดิมเคยส่งข้อมูลทุก 30 วินาทีและถูก operator หยุดโดยตั้งใจเมื่อ
  2026-08-31 เนื่องจาก MongoDB Atlas เต็ม ไม่ใช่ agent failure; วันที่ 2026-09-01
  operator เพิ่ม capacity และอนุญาตให้ enable ได้
- interface ที่ตั้งไว้คือ `wlan0`, `tailscale0`, `lo`; primary คือ `wlan0`
- hardware retention เดิมคือ 48 ชั่วโมง
- Cowrie, collector, processor, sensor forwarder และ Zeek ทำงานอยู่
- มี decoy containers และ Ollama ร่วมใช้ host เดียวกัน
- repo บน Pi สะอาดที่ commit `d44f01bec6a542f4c8f1a84f07e6b2b7a0058d4f`

ผลตาม contract:

- `pi_sensor` telemetry อธิบายภาระของ Pi/Cowrie/decoy stack เท่านั้น
- command ที่ Cowrie emulation รับไว้ไม่ใช่หลักฐานว่า payload execute บน Pi
- scenario ที่อ้างผลจาก compute hijacking หรือ outbound network abuse ต้องมี
  `backend_guest`/`backend_cgroup` execution evidence จาก bounded benign workload
- total host CPU ต้องไม่ถูกใช้แทน per-process/cgroup evidence
- experimental telemetry ต้องใช้ schema/stream แยกจาก operational `raw:hardware`
- experimental telemetry 1 Hz ห้าม persist เข้า ordinary Atlas `hardware_metrics` เดิม;
  ใช้ dedicated time-series collection + short TTL ได้หลัง preflight

รายละเอียด audit อยู่ใน [Pi environment audit](pi_environment_audit_2026-09-01.md)

## 3. Research hypotheses

### H1 — hardware signal

Hardware model แยก observed impact patterns เช่น compute saturation, memory pressure,
network flood pattern และ process exhaustion จาก no-material-impact ได้ดีกว่า trivial
single-threshold baseline บน held-out runs

### H2 — benign counterexamples

เมื่อมี benign high-load counterexamples โมเดล hardware-only จะไม่ถูกกล่าวอ้างว่าแยก
malicious intent ได้; intent ต้องมาจาก independent scenario evidence หรือ text branch

### H3 — fusion value

Fusion ระหว่าง frozen ModernBERT evidence กับ hardware impact evidence เพิ่ม Macro-F1
หรือ recall ของ T1496/T1498/T1499 โดยไม่เพิ่ม false positives บน benign high-load เกิน
predeclared tolerance เมื่อเทียบกับ ModernBERT-only baseline

### H4 — temporal value

TCN/MiniROCKET ต้องชนะ XGBoost window-feature baseline บน frozen protocol ก่อนถูกเลือก
เป็น production shadow hardware branch

## 4. Model responsibilities

```text
Cowrie command fragment
        -> frozen ModernBERT
        -> text candidate/logits
                              \
                               -> Fusion -> research TTP/impact candidate
                              /
1 Hz telemetry window
        -> XGBoost or TCN
        -> intent-neutral impact evidence
```

### 4.1 Hardware branch targets

Hardware model ใช้ multi-label observed impacts:

- `NO_MATERIAL_IMPACT`
- `COMPUTE_SATURATION`
- `MEMORY_PRESSURE`
- `DISK_IO_PRESSURE`
- `NETWORK_HIGH_THROUGHPUT`
- `NETWORK_FLOOD_PATTERN`
- `PROCESS_EXHAUSTION`
- `SERVICE_PRESSURE`
- `SERVICE_DEGRADATION`
- `UNKNOWN`

คำว่า `COMPUTE_SATURATION` ตั้งใจเป็น intent-neutral: compile และ simulated compute
hijacking อาจมี hardware label เดียวกัน แต่มี scenario disposition/TTP ต่างกัน

### 4.2 Text branch

ModernBERT เดิมถูก freeze และยังคงเป็น candidate source ไม่มี authority สร้าง trusted
TTP โดยลำพัง การนำ full logits/embedding เข้า shadow experiment ต้องใช้ adapter แยกและ
ห้ามเปลี่ยน canonical classifier output

### 4.3 Fusion branch

Fusion รับ leakage-safe text/hardware features แล้วทำนาย:

- TTP candidate set
- impact candidate set
- `intent_observed` / `impact_observed` / `evidence_incomplete`

Fusion output เป็น `audit_only` เสมอใน v1 และไม่มี canonical write/action path

## 5. Unit of observation

หน่วยอิสระหลักคือ **experiment run** ไม่ใช่ telemetry row หรือ sliding window

หนึ่ง run ต้องมี:

```text
baseline phase   >= 30 seconds
workload phase   = 10, 30, 60 or 120 seconds
recovery phase   >= 30 seconds
sampling         = 1 second
```

Derived windows เริ่มต้น:

- early/detection windows: 5, 10, 30, 60 seconds
- multi-scale summary windows: 5, 30, 60 seconds
- window ทุกอัน inherit split จาก parent `run_id`

หาก decision timestamp เห็น telemetry หลังเหตุการณ์ ให้เรียกงานนั้นว่า detection ไม่ใช่
prediction

## 6. Data records

### 6.1 Run manifest

ทุก run ต้อง validate กับ:

`schemas/experiment_run_manifest.v1.schema.json`

Manifest ระบุ scenario, workload identity/hash, sensor/backend identity, safety controls,
timing, ground truth source และ split groups

### 6.2 Raw telemetry

ทุก sample ต้อง validate กับ:

`schemas/hardware_telemetry_sample.v1.schema.json`

CPU เก็บเป็น continuous percentage `0–100` พร้อมนิยาม metric scope ไม่แบ่ง rank 1–4
แทนค่าดิบ Rank/intensity bucket ใช้เป็น experiment metadata หรือ dashboard เท่านั้น

### 6.3 Command correlation

ใช้ authenticated canonical session ID จาก production ingest เมื่อมีอยู่ ห้ามสร้าง
session authority ใหม่จาก timestamp เพียงอย่างเดียว

หนึ่ง telemetry sample อาจทับหลาย session จึงใช้ array ของ canonical session IDs และ
ระบุ `correlation_state` แทนการบังคับ one-to-one

`experiment_id`, `run_id`, scenario/workload names และ raw timestamps ห้ามเข้า model
feature matrix

### 6.4 Dataset storage boundary

Telemetry 1 Hz สร้าง 86,400 samples/วัน/metric scope ซึ่งมากกว่า sampling 30 วินาที
เดิม 30 เท่า Raw experimental samples จึงต้องใช้:

```text
experimental collector
  -> bounded durable local spool
  -> authenticated batch upload
  -> dedicated Atlas time-series hot tier (7-day TTL)
  -> content-addressed cloud object/dataset storage
  -> validated Parquet/feature datasets
```

Ordinary MongoDB Atlas `hardware_metrics` เดิมไม่ใช่ raw 1 Hz sink แต่ dedicated
time-series collection ใช้เป็น hot tier ได้ Long-term training authority ยังคงเป็น
immutable object segments + validated Parquet รายละเอียดอยู่ใน
`dataset_storage_plan.v1.md`

## 7. Ground truth

Ground truth ต้องมาจาก:

1. predeclared scenario catalog
2. bounded workload receipt และ implementation hash
3. observed process/cgroup/network evidence
4. completed/aborted state และ quality flags

ห้ามใช้สิ่งต่อไปนี้เป็น ground truth:

- rule output
- SecureBERT/ModernBERT prediction
- Fusion prediction
- CPU threshold เพียงค่าเดียว
- filename หรือ command token ที่เป็นส่วนหนึ่งของ model input

Run ที่ workload ไม่เริ่ม, telemetry ไม่ครบ หรือ safety stop ทำงานต้อง mark `aborted` หรือ
`invalidated`; ห้ามเปลี่ยน label เพื่อให้ตรงกับสิ่งที่โมเดลทาย

## 8. Safety boundary

- actual malware/miner execution: prohibited
- public/third-party traffic targets: prohibited
- Internet mining pool/proxy: prohibited
- workload: bounded benign implementation เท่านั้น
- scenario ที่มี execution/outbound network: default deny ที่ execution boundary และ
  local sink allowlist เท่านั้น
- neutral-idle ที่ไม่มี execution ต้องบันทึก host egress truth และใช้
  `egress_enforcement_scope=not_applicable_no_execution`; ห้ามอ้าง host default-deny
  หากไม่ได้ enforce จริง
- untrusted binary: ห้ามรันบน Pi หรือ container-only boundary
- disposable VM/backend ต้อง reset จาก content-addressed image
- CPU, memory, process, disk, network และ duration ต้องมี hard limits/watchdog
- Pi production services ห้าม restart/enable/disable เพื่อเก็บข้อมูลโดยไม่มี deployment
  change review แยกต่างหาก

## 9. Collection stages

### Stage A — collector validation

- สร้าง experimental collector/stream ที่ 1 Hz
- ยังไม่รัน attack-like workload
- ยืนยัน sample ID, clock, missing values, restart/counter reset behavior
- เก็บ idle และ ordinary decoy background load

### Stage B — pilot controlled runs

- ใช้ scenario catalog pilot matrix
- อย่างน้อย 3 repetitions ต่อ cell
- เก็บ benign/malicious-simulation pairs ที่มี hardware load ใกล้กัน
- scenario ที่ต้อง execute ใช้ isolated backend/local sink เท่านั้น

### Stage C — full collection

- อย่างน้อย 5 implementation/command variants ต่อ target family เมื่อทำได้
- เป้าหมายอย่างน้อย 50 independent runs ต่อ class และควรได้ 100+ ต่อ class
- เก็บหลายวัน หลาย background-load states และหลาย environment signatures

## 10. Dataset acceptance gates

ก่อนใช้ train:

- schema validation ผ่านทุก retained record
- ไม่มี duplicate `sample_id`
- samples ที่คาดหวังครบอย่างน้อย 99% ต่อ valid run หรือมี predeclared exception
- wall clock synchronized และ monotonic sequence ไม่ย้อน
- counter reset/reboot ถูก flag
- phase boundaries และ workload receipt ตรงกัน
- credentials/raw secrets ไม่อยู่ใน telemetry/manifests
- controlled runs ไม่ปะปนกับ production analytics
- raw 1 Hz telemetry ไม่ถูกเขียนเข้า ordinary Atlas `hardware_metrics` เดิม
- spool/storage budget ผ่าน preflight ก่อนเริ่ม run; พื้นที่ไม่พอต้อง abort run
- split leakage tests ผ่านตาม `dataset_split_policy.v1.md`
- dataset manifest, file hashes และ exact run membership ถูก freeze

## 11. Evaluation order

1. Trivial thresholds/statistical heuristic
2. XGBoost aggregated-window hardware-only
3. MiniROCKET hardware-only
4. Small TCN hardware-only
5. Frozen ModernBERT command-only
6. ModernBERT + winning hardware branch fusion
7. Rules + existing ModernBERT policy baseline เพื่อรายงานระบบเดิม

Metric หลักคือ Macro-F1, per-label precision/recall/F1, PR-AUC, false positives per benign
run/hour, detection latency, missing-data behavior และ calibration metrics เมื่อจะตีความ
score เป็น probability

## 12. Exit gate ก่อนเริ่มเขียน model

- [ ] schema และ catalog ผ่าน review
- [x] experimental collector manual pilot ไม่เปลี่ยน production authority path
- [x] neutral-idle pilot 3 runs replay แล้วได้ record/hash ตรงกัน
- [ ] benign counterexamples มีครบ
- [ ] split policy สามารถสร้าง disjoint groups ได้จริง
- [ ] ไม่มี actual malware หรือ external target
