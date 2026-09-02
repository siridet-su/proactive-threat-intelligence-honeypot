# Hardware Go Agent feature-parity audit — 2026-09-02

> สถานะ: `COMMON METRICS PASS / FULL FEATURE PARITY NOT IMPLEMENTED`
> Host: `pi-z` (Raspberry Pi 5, ARM64)
> ขอบเขต: read-only, no sink, not training data

## สภาพ production ก่อนและหลัง probe

- production repo: `/home/cpe27/proactive-threat-intelligence-honeypot`
- deployed commit: `d44f01bec6a542f4c8f1a84f07e6b2b7a0058d4f`
- deployed agent source SHA-256:
  `7dbf6c1e735fbc134a7575ed0e91a73ea319e95f36fa0397bb8e6f04ae3e7bf8`
- deployed agent binary SHA-256:
  `8236350d37da732574de69323183423e3e69375e1af31ec43851fd3599bb53f9`
- `honeypot-hardware.service` เป็น inactive/disabled อยู่แล้ว
- `honeypot-processor.service` ยังคง active
- production source, binary และ service ไม่ถูกแก้/restart
- ไม่เขียน Redis, MongoDB หรือ Atlas; ไม่สร้าง training row
- production containers ยังคง 9 ตัว และไม่มี PoC container ค้าง

สร้าง ARM64 audit binary จาก proposed source แล้ว copy เฉพาะเข้า
`/home/cpe27/honeypot-experiment/parity-v2-20260902-r2` binary ที่ probe ใช้มี SHA-256:
`9558c6bb51a4c2c6d62a4af9182a6791b57a21371b7d637e1a70daad2435f31c`

## Documentation drift ที่ตรวจพบ

Go agent README เคยระบุ packet/error/drop counters และ packet rates แต่ source production
ยังปล่อยเพียง byte counters/rates บางส่วน Proposed source จึงเพิ่ม field ที่ขาดและเพิ่ม
unit tests โดยยังรักษา legacy primary-interface fields

ปัญหาเชิง semantics ที่สำคัญกว่าคือ memory:

- gopsutil legacy `Used` = `Total - Free - Buffers - Cached`
- Python psutil `used` = `Total - Available`

คู่แรกจึงต่างกันจริงประมาณ 236,662,784 bytes และ 2.87 percentage points ไม่ใช่ timing
noise และไม่ควรแก้โดยขยาย tolerance Proposed Go source รักษา `mem_used_*` เดิมสำหรับ
dashboard แล้วเพิ่ม `mem_pressure_used_bytes`/`mem_pressure_percent` แบบ
`Total - Available` สำหรับ training/parity

## Probe result

Probe แต่ละคู่เริ่ม Go snapshot และ Python experimental snapshot แยก process ใกล้กัน
warm counter 2 วินาที แล้วเทียบ 45 fields:

- scalar 6 fields: CPU, pressure-memory bytes/percent, root disk bytes/percent, temperature
- network 13 fieldsต่อ interfaceสำหรับ `wlan0`, `tailscale0`, `lo`: up, byte/packet totals,
  errors, drops และ byte/packet rates

Single-pair r2:

- 45/45 within tolerance; 0 observed differences; 0 unavailable
- canonical report SHA-256:
  `4e88edc913b93e86e62676851a3950b37b54e6e4ce4eb75e1e3245838bf4f85d`
- serialized report SHA-256:
  `9cf2351347a4612f0e1845c0d009a0cf2eadcd4a39b5188494ffa0368fb17540`
- Go snapshot serialized SHA-256:
  `ac1e859f0de131bde5e94d3b32da777709146ef84173b1d32e0b0760643975ce`
- Python snapshot serialized SHA-256:
  `b0bc4ce26f1ec092f760f2a3b7ca61c2155525c8f6fb9308094741136629c43e`

Repeated series 5 independent pairs:

- 5/5 reports passed
- 225/225 comparisons within tolerance; 0 differences; 0 unavailable
- series summary serialized SHA-256:
  `653f2fb76959a12259e15f4c9f7d5eea6f9793389941e52698c01e591546d63f`
- evidence archive SHA-256:
  `bdaf525fc82bcd068615c58ff30c37026dc5a182f5eaf0e83ee5345fe7877118`

Local raw evidence อยู่ใต้ ignored path
`data/hardware-parity-v2-20260902-r2/` และไม่ commit snapshots ที่มี runtime measurements

## ความหมายของคำว่า pass

ผลนี้ยืนยันว่า common fields ที่ทั้งสอง collector มีและนิยามตรงกันอ่านค่า Pi ใกล้เคียงกัน
ภายใต้ tolerances ที่ประกาศล่วงหน้า ไม่ได้ยืนยันว่า Go Agent มี feature ครบเท่า
experimental collector

Go Agent ยังขาดสิ่งที่ dataset v2 ต้องพึ่งพา เช่น:

- run/sample identity, monotonic/boot/NTP และ per-record quality metadata
- per-core CPU, CPU time, load/frequency, vmstat และ swap detail
- block-device I/O counters/rates
- socket/process/thread counts และ thermal throttle/undervoltage state
- target process/cgroup CPU, RSS, socket และ pseudonymous identity
- immutable local spool, schema validation, manifest/execution/collection receipts

ดังนั้นรอบ v2 ยังใช้ experimental collector เป็น dataset authority ส่วน
`go_agent_overlap_v1` ใช้ diagnostic comparison เท่านั้น ห้ามเปิด Go Agent ที่ 1 Hz เข้า
ordinary Redis/Atlas เพื่อแทน collector

## Reproduce แบบ sink-free

Go snapshot:

```bash
./hardware-agent-parity \
  --snapshot-json \
  --snapshot-interval 2s \
  --snapshot-interfaces wlan0,tailscale0,lo \
  --snapshot-primary-interface wlan0 > go-snapshot.json
```

Experimental collector snapshot:

```bash
cowrie-hardware-dataset snapshot-experimental-hardware \
  --config configs/experimental_collector.pi_sensor.pilot.example.json \
  --interval-seconds 2 \
  --output experimental-snapshot.json
```

Compare:

```bash
cowrie-hardware-dataset compare-hardware-snapshots \
  --go-snapshot go-snapshot.json \
  --experimental-snapshot experimental-snapshot.json \
  --output parity-report.json
```

Snapshot mode ประกาศ `read_only_no_sink` และ comparator ปฏิเสธเอกสารที่ระบุว่าพยายาม
เขียน Redis/Mongo, ใช้ production service, ไม่ได้อยู่ในโหมดนี้ หรือไม่ผ่าน collector
quality gate Snapshot เป็น audit evidence เท่านั้น
