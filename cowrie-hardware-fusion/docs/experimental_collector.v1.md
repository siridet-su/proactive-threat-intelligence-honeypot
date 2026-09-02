# Experimental 1 Hz Collector v1

> สถานะ: `ISOLATED IDLE VERIFIED / CONTROLLED PI POC IMPLEMENTED / NOT A SERVICE`
> Runtime version: `0.3.0`
> ขอบเขต: `pi_sensor` สำหรับ neutral idle และ fixed `poc_pi_*` safe-container runs

## Safety boundary

Collector รุ่นนี้ตั้งใจแคบกว่าระบบสุดท้ายและ fail closed:

- รับเฉพาะ manifest state `planned` หรือ `running`
- idle path รับเฉพาะ `scenario_id=neutral_idle`, family `none`, intensity `0` และ
  `execution_boundary.kind=none`
- controlled path รับเฉพาะ allowlisted `poc_pi_*`, boundary `safe_container` และ scope
  `pi_sensor`; specification validator ต้องตรวจ label/profile/image/security/limits ก่อน
- ปฏิเสธ manifest ที่ประกาศ actual malware, third-party target หรือ command event
- neutral-idle ใช้ `egress_enforcement_scope=not_applicable_no_execution`; field
  `default_deny_egress` บันทึกสภาพ host จริงและไม่ได้อ้างว่า Pi เป็น default-deny
- ไม่มี path execute raw command; controlled lifecycle เรียกเฉพาะ Docker argument list ที่
  สร้างจาก fixed reviewed specification
- ไม่มี Redis, MongoDB, Atlas, uploader หรือ canonical write path
- ไม่แก้/เปิด/หยุด production service

รุ่นนี้ใช้เก็บ fixed behavioral simulation สำหรับ Pi PoC ได้ แต่ยังไม่ใช่ production
service และไม่รับ attacker-controlled input

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
- process/thread counts; controlled workload phase เพิ่ม target process CPU แบบ
  single-core basis, RSS, threads, socket count และ pseudonymous process/cgroup identity

`wlan0` เป็น aggregate interface ส่วน `tailscale0` และ `lo` เป็น observability-only
เพื่อป้องกันการนับ traffic ซ้ำ Dataset builder บังคับอ่านเฉพาะ interface ที่มี
`include_in_aggregate=true`

## Pi facts ที่ยืนยันแบบ read-only วันที่ 2026-09-01

- Python `3.12.3`
- system Python ยังไม่มี `psutil`; deployment ต้องใช้ isolated venv/package install
- root filesystem คือ `mmcblk0p2`
- `wlan0`, `tailscale0` และ `lo` มีอยู่จริง
- NTP synchronized เป็น `yes`

ทดลองผ่าน detached source worktree และ isolated venv ใต้ experiment directory บน Pi
โดยไม่แก้ production worktree หรือ service configuration ตัวอย่าง config จึงใช้
`mmcblk0p2` และยังต้อง copy ไปเป็น deployment-specific config ห้ามแก้ example ให้
กลายเป็น secret-bearing production config

Stage A neutral-idle pilot สำเร็จ 3 runs รวม 270 samples: ทุก sample ผ่าน schema,
ไม่มี late sample, missing field, counter reset หรือ collector error และ replay เป็น
derived windows 5/10/30 วินาทีได้ coverage 100% ดู
[pilot report](pilot_idle_collection_2026-09-01.md)

## Hardware Go Agent parity snapshot

วันที่ 2026-09-02 ตรวจ common metrics ระหว่าง experimental collector กับ proposed Go
Agent source บน Pi แบบ read-only/no-sink ซ้ำ 5 คู่ ผ่าน 225/225 comparisons ดู
[feature-parity audit](hardware_agent_feature_parity_2026-09-02.md)

Memory ต้องใช้ semantics เดียวกัน: experimental collector ใช้ `total - available` จึง
เทียบกับ Go fields `mem_pressure_used_bytes` และ `mem_pressure_percent` เท่านั้น Legacy Go
fields `mem_used_bytes`/`mem_percent` ใช้อีกนิยามและไม่ใช่ training authority

สร้าง snapshot ของ experimental collector โดยไม่เปิด spool หรือ cloud sink:

```bash
cowrie-hardware-dataset snapshot-experimental-hardware \
  --config configs/experimental_collector.pi_sensor.pilot.example.json \
  --interval-seconds 2 \
  --output experimental-snapshot.json
```

Snapshot นี้ใช้ audit semantics/plumbing เท่านั้น ห้ามใช้เป็น training sample Full dataset
ยังต้องมาจาก manifest/schema/receipt-bound collection workflow ด้านล่าง และ experimental
collector ยังคงเป็น v2 dataset authority เพราะ Go Agent มีเฉพาะ feature subset

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

สำหรับ controlled Pi PoC ต้องรัน `pi-poc-preflight` ก่อนทุก run แล้วใช้:

```bash
.venv/bin/cowrie-hardware-dataset collect-pi-poc-run \
  --manifest /path/to/planned-manifest.json \
  --config /path/to/collector-config.json \
  --specification /path/to/workload-spec.json \
  --scenario-catalog configs/scenario_catalog.v1.json
```

คำสั่งนี้สร้าง container เฉพาะ workload phase และต้องได้ execution receipt ที่ยืนยัน
fixed image/limits/output/cleanup คู่กับ collection receipt ดู safety gates ทั้งหมดใน
[Pi PoC runbook](pi_poc_runbook.v1.md)

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

controlled run ใช้ `finalize-pi-poc-manifest` แทน เพื่อบังคับตรวจและอ้างอิงทั้ง
collection receipt กับ execution receipt

## สิ่งที่ยังไม่ทำ

- Pi deployment/service unit และ dedicated OS user
- signed/authenticated batch uploader
- Atlas hot time-series/TTL/rollup
- Cowrie session/command correlation
- backend guest/cgroup multi-scope collectors (Pi PoC มี target process ภายใน
  `pi_sensor` แล้ว แต่ยังไม่ใช่ backend multi-scope)
- production-grade workload orchestration; runtime ปัจจุบันเป็น fixed manual PoC เท่านั้น
- resume/quarantine operational workflow; interrupted run ต้องใช้ run ID ใหม่หลัง review
