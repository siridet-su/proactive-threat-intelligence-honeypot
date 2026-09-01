# Dataset Storage Plan v1

> สถานะ: `DRAFT / LOCAL SPOOL IMPLEMENTED / NOT DEPLOYED`
> ปรับปรุง: 2026-09-01 หลัง operator เพิ่ม Atlas capacity และอนุญาตให้ enable agent

## Decision

แยก storage เป็นสาม tier:

1. **Atlas hot time-series:** raw 1 Hz ระยะสั้นสำหรับ dashboard/debug
2. **Atlas rollups:** 10-second/60-second aggregates สำหรับ operational trends
3. **Cloud object storage:** immutable raw segments และ Parquet dataset สำหรับ training

สามารถ enable hardware agent เดิมที่ 30 วินาทีได้หลังตรวจ capacity/TTL แต่ห้ามเปลี่ยน
เป็น 1 วินาทีโดยเขียนเข้า ordinary `hardware_metrics` เดิม เพราะ schema, idempotency,
Redis backlog และ retention ยังไม่รองรับ

Record rate ต่อ metric scope:

| Sampling | Records/hour | Records/day |
|---:|---:|---:|
| 30 seconds | 120 | 2,880 |
| 1 second | 3,600 | 86,400 |

หากเก็บหลาย scopes เช่น `pi_sensor`, `backend_guest`, `backend_cgroup`,
`target_process`, `local_sink` จำนวน records จะเพิ่มตาม scope ที่เปิดจริง จึงต้องวัด
bytes/sample จาก pilot ก่อนกำหนด storage budget

## Proposed path

```text
Pi/backend experimental collector
        -> rotated durable spool segments
        -> authenticated bounded batch uploader
        -> dedicated Atlas time-series hot collection (short TTL)
        -> cloud raw object storage (immutable)
        -> schema validation + partitioned Parquet dataset
        -> XGBoost / TCN / Fusion training
```

Cloud object-storage provider/bucket ยังเป็น deployment decision ที่ต้องระบุใน config
ภายหลัง หากใช้ GCP ให้พิจารณา GCS แต่ contract นี้ไม่ผูกกับ provider

## Recommended retention defaults

| Tier | Resolution | Default retention | Use |
|---|---:|---:|---|
| Atlas hot raw | 1 second | 7 days | dashboard, debugging, recent-run validation |
| Atlas short rollup | 10 seconds | 30 days | operational comparisons |
| Atlas long rollup | 60 seconds | 180 days | trends/capacity history |
| Object raw + validated Parquet | 1 second | 365 days minimum | reproducibility and training |
| Invalid/quarantine segments | original | 7 days | bounded debugging only |

เริ่ม hot raw ที่ 7 วันก่อน แม้ cluster ใหญ่ขึ้น แล้ววัด `storageSize + totalIndexSize`
จริงครบหนึ่งสัปดาห์ หากยังมี headroom อย่างน้อย 30% ค่อยพิจารณาขยายเป็น 14 วัน

Training pipeline ห้ามพึ่ง Atlas raw TTL: ทุก completed run ต้อง export และ verify object
storage receipt ก่อน raw hot data หมดอายุ

## Pi/backend spool

Local implementation `0.2.0` มี bounded spool, per-record fsync, byte/record rotation,
read-only published segments, content hashes, no-overwrite และ completed collection
receipt แล้ว แต่ยังไม่มี uploader/quarantine service และยังไม่ deploy บน Pi ดู
[Experimental 1 Hz collector v1](experimental_collector.v1.md)

- reuse durability pattern ของ existing Cowrie sensor forwarder: write, fsync, checkpoint
- rotate ตาม byte size และเวลา ไม่สร้างไฟล์เดียวโตไม่จำกัด
- segment มี schema version, first/last sequence, record count และ SHA-256
- upload สำเร็จและ remote receipt ตรง hash ก่อนลบ local segment
- มี hard maximum spool bytes และ minimum free-disk preflight
- controlled experiment ต้อง abort เมื่อพื้นที่ไม่พอ ห้าม overwrite/drop แบบเงียบ
- spool ห้ามมี credentials, raw commands หรือ raw IPs

## Cloud raw layout

Logical partition layout:

```text
raw/
  schema=hardware_telemetry_sample.v1/
  date=YYYY-MM-DD/
  sensor=<pseudonymous-id>/
  run=<run-id>/
  scope=<metric-scope>/
  part-<first-sequence>-<sha256>.jsonl

validated/
  dataset=<dataset-id>/
  run=<run-id>/
  scope=<metric-scope>/
  part-*.parquet

manifests/
  run=<run-id>/manifest.json
  dataset=<dataset-id>/dataset-manifest.json
```

Raw uploaded bytes เป็น immutable evidence ส่วน Parquet เป็น reproducible derived form
และต้องอ้าง raw segment hashes

## Atlas hot collection

สร้าง database/collection แยก ไม่เปลี่ยน ordinary collection เดิม:

```text
database:   honeypot_telemetry_v1
collection: hardware_telemetry_1s_v1
timeField:  ts              # BSON Date/ISODate, not Unix float
metaField:  meta
granularity: seconds
expireAfterSeconds: 604800  # 7 days
```

ตัวอย่าง stable metadata:

```json
{
  "sensor_id": "pseudonymous-sensor",
  "metric_scope": "pi_sensor",
  "subject_id": "stable-subject",
  "schema_version": "hardware_telemetry_sample.v1",
  "collector_version": "0.1.0"
}
```

`metaField` ต้องเปลี่ยนน้อยเพื่อให้ bucket แน่นและ compression ดี ห้ามใส่ session arrays,
command IDs, timestamp, phase หรือ quality flags ใน `meta` ส่วน `run_id` เก็บเป็น
measurement field เว้นแต่ profiling พิสูจน์ว่าการ query/bucketing แบบอื่นดีกว่า

Atlas hot projection ต้องรักษาลำดับ/shape ของ fields ให้คงที่และใช้ numeric BSON types
ไม่ใช่ numeric strings ส่วน raw evidence schema เดิมยังเก็บใน object storage

MongoDB time-series ไม่มี unique index จึงห้ามถือว่า `sample_id` ป้องกัน duplicate ที่
database layer ได้ ต้องมี idempotent segment/upload ledger แยก หรือ deduplicate จาก
`sample_id` ระหว่าง validation ก่อน freeze dataset

## Rollups

สร้างจาก raw hot/object data โดย job ที่มี config/hash ชัดเจน:

- 10-second: mean, min, max, p95, std, last counter และ quality count
- 60-second: ค่าเดียวกันพร้อม sample coverage/missing count
- counter fields เช่น total bytes ใช้ `last`; rates ใช้ mean/max/p95
- run/session correlation ไม่ถูกสรุปรวมข้าม run โดยเงียบ

Dashboard ระยะยาวอ่าน rollup ไม่อ่าน raw 1 Hz

## Lifecycle

ก่อนเปิด collector ต้อง freeze:

- storage provider/bucket identity
- encryption/access policy
- retention ของ raw, validated และ processed datasets
- spool maximum/minimum-free thresholds
- segment rotation limits
- upload retry/backoff และ quarantine limits
- deletion receipt policy
- cost/capacity alert thresholds
- Atlas collection type/timeField/metaField/granularity/TTL receipt
- rollup code/config hashes และ source cutoff

## Existing agent preflight

ก่อนตั้ง `NETWORK_SAMPLE_SECONDS=1` ต้องแก้/ตรวจอย่างน้อย:

- hardware agent ปัจจุบัน hardcode Redis `MAXLEN ~5000`; ที่ 1 Hz เหลือ backlog เพียง
  ประมาณ 83 นาที เทียบกับประมาณ 41 ชั่วโมง 40 นาทีที่ 30 วินาที
- processor ปัจจุบันใช้ `InsertOne` เข้า ordinary collection และไม่มี deterministic
  sample ID/unique constraint
- timestamp ปัจจุบันเป็น Unix number แต่ time-series `timeField` ต้องเป็น BSON Date
- success log ทุก sample จะเพิ่ม journal volume อย่างมาก ต้อง rate-limit/aggregate
- TTL/index และ oldest/newest record ต้องตรวจว่าทำงานจริง
- dashboard/query เดิมต้องไม่ถูกเปลี่ยน schema โดยไม่ migrate

## Pilot exit gate

- [ ] วัด serialized bytes/sample จริง
- [ ] คำนวณ bytes/run และ bytes/day สำหรับ scopes ที่เปิด
- [ ] ทดสอบ network outage และ resume โดยไม่ duplicate/loss
- [ ] ตรวจ SHA-256/record count หลัง upload
- [ ] schema-invalid segment เข้า quarantine แบบ bounded
- [ ] ordinary Atlas `hardware_metrics` ไม่มี record 1 Hz จาก experimental collector
- [ ] dedicated time-series TTL และ rollups ทำงานตาม receipt
- [ ] raw/validated manifests reproduce exact run membership ได้
