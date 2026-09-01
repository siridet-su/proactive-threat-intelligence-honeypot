# Raspberry Pi Honeypot Environment Audit — 2026-09-01

> วิธีตรวจ: SSH read-only ไปยัง `pi-z`  
> ไม่มีการแก้ไฟล์, restart/enable/disable service, เขียน Redis/Mongo หรืออ่านค่า secrets

## Host

| รายการ | ค่าที่สังเกต |
|---|---|
| Architecture | ARM64 / Cortex-A76 |
| Logical CPUs | 4 |
| Maximum reported CPU frequency | 2.4 GHz |
| RAM | 8,322,752,512 bytes |
| Swap | 0 bytes |
| Root filesystem | 125,302,771,712 bytes; ใช้ประมาณ 45% ตอนตรวจ |
| Timezone | Asia/Bangkok |
| NTP | synchronized |
| Kernel | Ubuntu Raspberry Pi 6.8.0-1063-raspi |

Read-only collector preflight follow-up ในวันเดียวกันยืนยันเพิ่มว่า:

- Python system runtime คือ `3.12.3`
- system Python ยังไม่มี package `psutil`
- root filesystem block device คือ `mmcblk0p2`
- `wlan0`, `tailscale0` และ `lo` ยังมีอยู่จริง
- `timedatectl` รายงาน `NTPSynchronized=yes`

## Honeypot services

Active ตอนตรวจ:

- `cowrie.service`
- `honeypot-collector.service`
- `honeypot-processor.service`
- `honeypot-sensor-forwarder.service`
- `honeypot-local-firewall.service`
- `zeek.service` (`active/exited` หลัง deploy)

Installed แต่ inactive/disabled:

- `honeypot-hardware.service`
- `honeypot-ti-worker.service`

Hardware service log แสดง successful 30-second pushes จนถูก stop อย่างปกติเมื่อ
2026-08-31 16:57:20 +07 ไม่มี crash/error ใน log ช่วงท้ายที่ตรวจ

Operator clarification วันที่ 2026-09-01: service ถูกหยุดโดยตั้งใจเพราะ MongoDB Atlas
เต็ม ไม่ใช่เพราะ hardware agent, Redis หรือ sensor ล้มเหลว ข้อความนี้มาจาก operator
โดยตรงและไม่ได้อนุมานจาก journal

Operator update ภายหลังในวันเดียวกัน: เพิ่มขนาด cloud/Atlas แล้วและอนุญาตให้ enable
hardware agent ได้ การอนุญาตนี้ไม่ได้เปลี่ยนข้อเท็จจริงว่า audit รอบนี้เป็น read-only
และไม่ได้ enable service

## Cowrie mode

Effective config ที่ตรวจได้:

```text
[honeypot]
backend = shell
```

Proxy/backend-pool settings มีอยู่ใน config แต่ไม่ใช่ active backend ดังนั้น commands
ใน Cowrie session ปัจจุบันเป็น emulation และไม่ใช่หลักฐานว่า payload execute บน Pi

## Existing hardware configuration

```text
NETWORK_SAMPLE_SECONDS=30
NETWORK_INTERFACES=wlan0,tailscale0,lo
NETWORK_PRIMARY_INTERFACE=wlan0
RAW_STREAM_MAXLEN=50000
HARDWARE_METRICS_RETENTION=48h
```

Implementation ปัจจุบันส่ง:

- total CPU percent
- memory used bytes/percent
- root disk used bytes/percent
- CPU temperature
- per-interface up flag, RX/TX byte totals, byte rates และ Mbps

Implementation ยังไม่มี sensor/run/session/sample identity, per-core/process/cgroup CPU,
load/iowait, memory pressure/page faults, disk I/O, packet/error/drop rates หรือ process tree

Mongo processor ใช้ `InsertOne` กับ `hardware_metrics` และยังไม่มี deterministic sample
ID/unique index จึงยังไม่เหมาะเป็น dataset authority โดยตรง

## Concurrent host workloads

พบ Docker workloads หลายตัว ได้แก่ deception core, FTP/web/middleware/SMTP decoys,
Odoo/PostgreSQL, BuildKit และ Ollama แต่ snapshot ตอนตรวจใช้ CPU ต่ำเป็นส่วนใหญ่

ผลต่อ dataset:

- total CPU/RAM มี background workloads ปนอยู่
- ต้องบันทึก environment signature และ per-process/cgroup/container metrics
- ห้ามใช้ snapshot ครั้งเดียวเป็นตัวแทน baseline ทุกวัน
- ควรเก็บ baseline ต่อ run และ benign background-load variants

## Code identity

Repo บน Pi:

```text
branch: main
commit: d44f01bec6a542f4c8f1a84f07e6b2b7a0058d4f
working tree: clean
```

Local repo มี commits เพิ่มจาก Pi แต่ไม่มี diff ใน hardware-agent, processor-agent,
sensor-forwarder หรือ ingest API สำหรับช่วง commit ที่ตรวจ จึงใช้ source ปัจจุบันอธิบาย
runtime fields ข้างต้นได้ภายใต้ขอบเขตนี้

## Design decision

ไม่ได้ enable หรือปรับ `honeypot-hardware.service` ระหว่าง audit แม้ operator อนุญาตให้
enable ภายหลัง การเก็บ dataset 1 Hz ยังต้องใช้ deployment change แยกและควรส่งเข้า
experimental stream/schema เพื่อไม่กระทบ operational dashboard, retention และ
canonical authority เดิม

Ordinary MongoDB Atlas `hardware_metrics` เดิมไม่ควรเป็น sink ของ telemetry 1 Hz: หนึ่ง metric
scope จะเพิ่มจากประมาณ 2,880 records/วันที่ sampling 30 วินาที เป็น 86,400 records/วัน
ที่ sampling 1 วินาที ควรใช้ dedicated time-series hot tier, bounded local spool และ
cloud object/dataset storage แยก
ตาม [Dataset storage plan](dataset_storage_plan.v1.md)
