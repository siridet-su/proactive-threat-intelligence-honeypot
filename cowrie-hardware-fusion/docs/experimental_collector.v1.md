# Experimental 1 Hz Collector v1

> สถานะ: `IMPLEMENTED LOCALLY / NOT DEPLOYED`
> Runtime version: `0.2.0`
> ขอบเขต: `pi_sensor` + `neutral_idle` Stage A pilot เท่านั้น

## Safety boundary

Collector รุ่นนี้ตั้งใจแคบกว่าระบบสุดท้ายและ fail closed:

- รับเฉพาะ manifest state `planned` หรือ `running`
- รับเฉพาะ `scenario_id=neutral_idle`, workload family `none`, intensity `0`
- รับเฉพาะ `execution_boundary.kind=none` และ `metric_scope=pi_sensor`
- ปฏิเสธ manifest ที่ประกาศ malware, third-party target, command event หรือ TTP
- ไม่มีโค้ด execute workload/command
- ไม่มี Redis, MongoDB, Atlas, uploader หรือ canonical write path
- ไม่แก้/เปิด/หยุด production service

ดังนั้นรุ่นนี้ใช้ตรวจความถูกต้องและต้นทุนของ telemetry/spool ก่อนเท่านั้น ยังใช้เก็บ
compute-hijacking/network-flood simulation ไม่ได้

## Data path

```text
Linux read-only metrics
  -> hardware_telemetry_sample.v1
  -> canonical JSONL bytes
  -> fsync every record
  -> size/record rotation
  -> immutable content-addressed segments
  -> collection-receipt.json
```

Spool ไม่มีการ overwrite หรือ resume แบบเดาเอง หาก run directory มีไฟล์อยู่แล้วจะหยุด
ทันที การ interrupt/error จะเหลือ `.partial` และไม่มี completed receipt เพื่อไม่ทำให้
ข้อมูลไม่ครบดูเหมือน run สำเร็จ

## Metrics

- total/per-core CPU, CPU time components, load, frequency, context switches
- memory/swap และ `/proc/vmstat` counters เมื่ออ่านได้
- root usage และ configured block-device I/O/rates
- configured network interfaces, counters และ rates
- TCP/socket counts โดยไม่ persist IP address
- temperature เมื่อ sysfs รองรับ
- process/thread counts; target process ยังเป็น `null`

`wlan0` เป็น aggregate interface ส่วน `tailscale0` และ `lo` เป็น observability-only
เพื่อป้องกันการนับ traffic ซ้ำ Dataset builder บังคับอ่านเฉพาะ interface ที่มี
`include_in_aggregate=true`

## Pi facts ที่ยืนยันแบบ read-only วันที่ 2026-09-01

- Python `3.12.3`
- system Python ยังไม่มี `psutil`; deployment ต้องใช้ isolated venv/package install
- root filesystem คือ `mmcblk0p2`
- `wlan0`, `tailscale0` และ `lo` มีอยู่จริง
- NTP synchronized เป็น `yes`

ตัวอย่าง config จึงใช้ `mmcblk0p2` และยังต้อง copy ไปเป็น deployment-specific config
ห้ามแก้ example ให้กลายเป็น secret-bearing production config

## Review/run workflow

ติดตั้งใน isolated development environment:

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[collector,test]'
```

สร้าง source/schema hashes:

```bash
.venv/bin/cowrie-hardware-dataset collector-source-hash
```

นำ `collector_source_sha256` ไปใส่ใน
`manifest.collection.collector_sha256` แล้วตรวจ preflight:

```bash
.venv/bin/cowrie-hardware-dataset collector-preflight \
  --manifest /path/to/planned-manifest.json \
  --config /path/to/collector-config.json
```

preflight ตรวจ manifest/safety/source identity, NTP, interface, disk device, spool quota
และ free disk โดยสร้างเฉพาะ empty run spool directory

เมื่อ review ผ่านจึง collect idle run:

```bash
.venv/bin/cowrie-hardware-dataset collect-idle-run \
  --manifest /path/to/planned-manifest.json \
  --config /path/to/collector-config.json
```

หลังได้ receipt ต้อง validate segment count/hash แล้วจึงสร้าง finalized manifest copy ที่
state `completed` พร้อม actual started/ended timestamps ด้วยคำสั่ง:

```bash
.venv/bin/cowrie-hardware-dataset finalize-idle-manifest \
  --manifest /path/to/planned-manifest.json \
  --receipt /spool/run=<run-id>/scope=pi_sensor/collection-receipt.json \
  --output /path/to/completed-manifest.json
```

คำสั่งนี้ตรวจ receipt content hash, segment SHA-256, byte/record count และ contiguous
sequence ก่อนสร้างไฟล์ output แบบ exclusive ห้ามแก้ raw planned manifest แบบไม่มี receipt

## สิ่งที่ยังไม่ทำ

- Pi deployment/service unit และ dedicated OS user
- signed/authenticated batch uploader
- Atlas hot time-series/TTL/rollup
- Cowrie session/command correlation
- cgroup/backend/target-process collectors
- safe workload orchestration
- resume/quarantine operational workflow; interrupted run ต้องใช้ run ID ใหม่หลัง review
