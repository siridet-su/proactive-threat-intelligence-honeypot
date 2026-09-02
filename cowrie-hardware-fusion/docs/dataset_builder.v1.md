# Dataset Builder v1

> สถานะ: `IMPLEMENTED / PI POC REPLAY + XGBOOST SMOKE VERIFIED`
> เวอร์ชัน: `0.1.0`
> ขอบเขต: controlled experiment data เท่านั้น

## หน้าที่

Dataset builder รับหนึ่ง completed run:

```text
experiment_run_manifest.v1 JSON
                 +
hardware_telemetry_sample.v1 JSONL segment(s)
                 |
                 v
schema + correlation + coverage validation
                 |
       +---------+---------+
       |                   |
XGBoost aggregate     fixed-length TCN
feature row           raw channels + masks
```

ผลลัพธ์ validate กับ `derived_training_window.v1.schema.json` และมี content hash เพื่อ
ตรวจ reproducibility

## XGBoost output

ค่าสำคัญที่สร้าง เช่น:

- `cpu_mean`, `cpu_max`, `cpu_p95`, `cpu_std`
- `cpu_slope_per_second`, `cpu_delta_from_baseline_mean`
- `cpu_seconds_above_70`, `cpu_seconds_above_90`
- memory, disk I/O, network rate, process และ thermal summaries
- target-process availability/features เมื่อ execution boundary มีข้อมูลจริง
- sample/baseline coverage

`cpu_p95` ใช้ linear interpolation เหมือน default percentile ของ NumPy ค่า input CPU
ยังเป็น continuous `0–100`

## TCN output

TCN block เป็น fixed-length channels ตาม horizon โดยยังไม่ normalize:

```text
cpu_total_percent
memory_used_percent
disk_read/write_bytes_per_second
network_rx/tx_bytes_per_second
network_rx/tx_packets_per_second
connection/socket count
temperature
process/thread count
target process CPU/RSS/socket count
```

ข้อมูลที่ขาดเติม `0.0` เพื่อ serialize เท่านั้น และต้องอ่านร่วมกับ `sample_present` และ
`channel_present` เสมอ ค่า imputation/scaler จริงต้อง fit จาก development train ภายหลัง

## Validation gates

- manifest ต้องมี state `completed`
- ทุก sample ต้องผ่าน JSON Schema ก่อน build ผ่าน CLI
- `run_id`, `experiment_id` และ `metric_scope` ต้องตรงกัน
- ห้ามมี `sample_id` หรือ sequence ซ้ำ
- window ห้ามข้าม boot และ `monotonic_ns` ต้องเพิ่ม
- baseline และ target coverage default ต้องไม่น้อยกว่า 99%
- identifiers, timestamps, scenario ID และ split group ไม่อยู่ใน model feature block

## ใช้งาน

จากโฟลเดอร์ `cowrie-hardware-fusion`:

```bash
PYTHONPATH=src python -m cowrie_hardware_fusion.cli build-window \
  --manifest data/raw/run-0001/manifest.json \
  --telemetry data/raw/run-0001/part-000000.jsonl \
              data/raw/run-0001/part-000030.jsonl \
              data/raw/run-0001/part-000060.jsonl \
  --metric-scope pi_sensor \
  --phase workload \
  --horizon-seconds 30 \
  --output data/interim/run-0001.pi_sensor.workload.30s.json
```

หรือ install editable แล้วใช้ `cowrie-hardware-dataset build-window ...`

ไฟล์หลัง `--telemetry` รับได้หนึ่งหรือหลาย immutable segments และต้องเรียงตาม receipt;
builder ยังตรวจ sequence/correlation ซ้ำและไม่ต้อง concatenate raw evidence

## Verified batch index

แต่ละ completed run ใช้ canonical layout ใน [data README](../data/README.md) แล้ว freeze
exact raw membership ด้วย:

```bash
cowrie-hardware-dataset index-dataset \
  --dataset-id controlled-dataset-v1 \
  --run-root data/raw/run=run-0001 data/raw/run=run-0002 \
  --output data/processed/controlled-dataset-v1.source-index.json
```

คำสั่งตรวจ manifest/receipt/sample schemas, receipt content hash, segment bytes/hash,
contiguous sequence, scope/correlation และ receipt citation ก่อนออก
`dataset_source_index.v1` ที่มี index hash

จากนั้นสร้าง run-level assignment:

```bash
cowrie-hardware-dataset split-dataset \
  --index data/processed/controlled-dataset-v1.source-index.json \
  --split-id controlled-split-v1 \
  --output data/processed/controlled-split-v1.json
```

splitter exclude `pilot_only=true`, รวม runs ที่แชร์ leakage axes เป็น connected component
เดียว และ fail หากมี independent components น้อยกว่าสามแทนการลด guard อัตโนมัติ

## Pilot XGBoost smoke command

PoC-only trainer รับ verified source index กับ derived workload windows แล้วตรวจ record hash,
manifest binding, label binding, coverage และ feature schema ก่อนแบ่ง fold ด้วย
`collection_batch` ทั้งกลุ่ม:

```bash
python -m pip install -e '.[poc-ml]'

cowrie-hardware-dataset train-xgboost-smoke \
  --source-index data/processed/poc.source-index.json \
  --window data/interim/*.workload.30s.json \
  --output-dir artifacts/poc-xgboost-smoke-v1
```

output มี fold models, full-data inspection-only model, predictions, confusion matrix,
per-class precision/recall/F1, Macro-F1, feature ordering, library/config/model hashes และ
ข้อจำกัด `pilot_smoke_only_not_for_deployment` โฟลเดอร์ output ต้องยังไม่มีเพื่อไม่เขียนทับ
หลักฐานเดิม ผลรัน Pi จริงอยู่ใน
[pi_poc_results_2026-09-02.md](pi_poc_results_2026-09-02.md)

## สิ่งที่ยังไม่ทำใน v1

- Cowrie command-event correlation adapter
- train-only normalization/imputation
- Parquet/NumPy export
- production-eligible XGBoost หรือ TCN training

neutral-idle pilot จริง 3 runs replay/index ผ่านแล้ว แต่ถูก exclude จาก split ทั้งหมด
ลำดับถัดไปคือเพิ่ม ordinary-load/benign counterexamples จาก isolated backend ก่อน freeze
feature/channel schema สร้าง eligible split และเทรน baseline
