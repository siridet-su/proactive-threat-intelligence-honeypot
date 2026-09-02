# Service-pressure observability v1

> สถานะ: `COLLECTOR 0.4.0 IMPLEMENTED / PI HOST+TARGET CANARY PASS`
> วันที่ตรวจบน Pi: `2026-09-02`
> ขอบเขต: raw observability candidate, no-sink, not training data

## วัตถุประสงค์

PoC แรกแยก `T1499.002` ไม่ได้ เพราะ host interface ไม่เห็น loopback traffic ภายใน
container และ target socket count คงที่ที่ 3 ไม่ว่ารัน 10 หรือ 150 req/s Collector `0.4.0`
จึงเพิ่มสัญญาณที่บอกว่า Linux/service เริ่มรอคิว, drop, throttle หรือใช้ resource สูง โดย
ต้องเป็นข้อมูลที่ production runtime สามารถสังเกตได้ ไม่ใช้ request/operation count จาก
simulator receipt เป็น model feature

Operator ยืนยันแยกต่างหากว่า public VPS/WireGuard ingress ทำให้ Cowrie เห็น source IP จริง
แต่ canary ในเอกสารนี้ยังใช้ fixed local safe-container และไม่ได้ส่ง public load

## Raw metrics ที่เพิ่ม

Host-level:

- CPU, memory และ I/O Pressure Stall Information (PSI): avg10/60/300, cumulative stall
  microseconds และ stall microseconds/second
- TCP state counts จาก `/proc/net/tcp*` โดยนับ state เท่านั้น ไม่เก็บ address/port
- socket allocation summary จาก `/proc/net/sockstat*`
- kernel TCP pressure totals/rates เช่น listen overflow/drop, request-queue full,
  backlog drop, TCP memory pressure, abort-on-memory และ receive-queue drop

Target process/network namespace:

- CPU single-core basis, RSS, threads และ socket count เดิม
- voluntary/involuntary context-switch totals
- TCP state, socket summary และ TCP pressure ใน target network namespace
- pseudonymous process/parent/cgroup identity; raw PID ไม่ถูก persist

Target cgroup v2:

- CPU usage/user/system, period/throttled-period/throttled-time totals และ rates
- memory current/peak และ low/high/max/OOM/OOM-kill event totals/rates
- current PID count และ PID-limit events
- aggregate cgroup read/write/discard bytes/operations totals และ rates
- CPU/memory/I/O PSI totals, rolling averages และ rates

Readable-but-empty `io.stat` แปลเป็น zero counters ไม่ใช่ missing เพราะ service workload ที่
ไม่มี disk I/O เป็น observation ที่ถูกต้อง

## สิทธิ์และ privacy decision

Canary แรกพิสูจน์ว่า `psutil.num_fds()` และ per-process I/O อ่านไม่ได้เมื่อ collector กับ
container ใช้คนละ UID จึงไม่นำสอง field นี้เข้า collector และไม่เพิ่ม ptrace/root capability
เพื่อแลกกับ feature ส่วน I/O ใช้ cgroup `io.stat` ที่อ่านได้โดยไม่ยกระดับสิทธิ์แทน

ไม่มี parser ตัวใด persist socket address, port, raw IP, payload, command, credential หรือ
simulator operation count Collector source identity รวม `service_pressure.py` แล้วเพื่อให้
manifest/receipt hash ผูก parser ชุดนี้ด้วย

## Pi evidence

Pi kernel `6.8.0-1063-raspi` เปิด host และ cgroup PSI, sockstat, TcpExt และ cgroup v2 files
ที่ต้องใช้

Host no-sink snapshot:

- valid, missing/error 0
- PSI ครบ CPU/memory/I/O; socket summary 10 fields; TCP pressure 16 total/rate fields
- canonical snapshot SHA-256:
  `0743dac8cdb919fe9eab5d21ef3f41f2d23beedbd02771ccbbd80ef4747d1b75`
- serialized snapshot SHA-256:
  `5d1e9f8b1049b4765388d87a209bcd15d0a74812c69d8b99010a5d6fae48a26e`

Final target canary revision 4:

- source archive SHA-256:
  `2f0a56c5605940155537cf6bcffab0898cbb491d77cc670e42e91be29f03edd3`
- collector source SHA-256 ตรงกันบน Pi/Arch:
  `75a2b09031c82fedbafbbcc4dc1d49f00807663722d9bae3ef2a591d9f246c8f`
- telemetry schema SHA-256 ตรงกันบน Pi/Arch:
  `b99697c8f92f8b45c70b9328e52156dab5fc7b30118ecba4b43809abef1a4d4e`
- canonical snapshot SHA-256:
  `eb931f56204695362bc6a6aded3b83b4b58cbbfad144411737abd75ed2a9fd91`
- serialized snapshot SHA-256:
  `057bccbda917beb5e0f399791b80c09d0787f8633e8b0c44dbeefd0dee5f2bba`
- valid/schema-valid, missing/error 0
- target TCP states: listen 1, established 2, total 3
- cgroup blocks ครบ CPU, memory, pids, I/O และ PSI สำหรับ CPU/memory/I/O
- safe service workload 8 วินาที, `network=none`, non-root, read-only rootfs,
  capabilities dropped, no-new-privileges, CPU/RAM/PID limits
- cleanup verified; production containers กลับมา 9 ตัวและไม่มี `chf-*` ค้าง
- `honeypot-hardware.service` ยัง inactive; `honeypot-processor.service` ยัง active
- ไม่มี Redis, MongoDB หรือ Atlas write

Raw snapshot copy อยู่ใน ignored path
`data/service-pressure-v040-20260902-r4/` และไม่ commit runtime measurements

## ขอบเขต claim และ next gate

ผลนี้พิสูจน์ collection semantics/availability เพียงหนึ่งช่วงสั้น ไม่ได้พิสูจน์ว่า metric
แยก service-pressure class ได้ Metric ใหม่จึงยังไม่ถูกเพิ่มเข้า frozen XGBoost/TCN feature
profiles เพื่อไม่เลือก feature จาก canary แล้วอ้างเป็น unbiased result

ขั้นถัดไปคือสร้าง 7-scenario instrumentation matrix แบบ `pilot_only=true`, scenario ละหนึ่ง
run แล้ววัด coverage และ baseline→workload deltas ของ candidate metrics หาก signal เหมาะสม
จึง freeze protocol/feature profile revision ใหม่ก่อนเริ่ม development wave 70 runs

## Verification

- Python tests: `52 passed`
- local schema/content checks: pass
- Pi host snapshot: pass
- Pi target cgroup snapshot: pass
- Pi canary cleanup: pass
