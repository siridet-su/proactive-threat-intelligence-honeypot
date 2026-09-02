# Service-pressure instrumentation pilot result — 2026-09-02

> สถานะ: `7/7 RUNS COMPLETE / TELEMETRY PASS / SERVICE-TREATMENT GATE NOT PASSED`
> ขอบเขต: excluded instrumentation data, not training/evaluation data

## Executive result

รัน matrix ครบ 7/7 บน `pi-z` และได้ 630/630 schema-valid samples โดยไม่มี missing
field, collector error หรือ counter reset Collector/source/telemetry/receipt hashes ตรงกัน
ระหว่าง Pi และ Arch และ controlled container cleanup ผ่าน 6/6

Instrumentation ใหม่เห็น target cgroup CPU usage, CPU PSI และ memory response ชัด และ
matched benign/malicious high-treatment pairs ให้ค่าใกล้กันตาม design แต่ service-high
workload ยังไม่สร้าง service pressure ที่ยืนยันได้: target TCP state/socket counts คงที่,
queue/drop counters เป็นศูนย์ และ execution errors เป็นศูนย์ทั้งคู่ ดังนั้นยังห้าม freeze
feature revision หรือเริ่ม development 70 runs ด้วย label `SERVICE_PRESSURE` ชุดนี้

## Frozen identities และ transfer

- source repository commit ที่ matrix ผูกไว้:
  `0a2a18f4654ad1af0b655dc8c7bc994264db1bba`
- matrix canonical SHA-256:
  `36625b2506eac6f67196deffb0f8504102a1f394619020e05514e0bb6e3a921f`
- serialized matrix SHA-256:
  `f9e4bedca5e0d6f7cab23cb84518368e43a7758c2dfd2806882359377961bbdd`
- collector `0.4.1` source SHA-256:
  `f56cce1858f3d604e5e298258fc0d1af076fafaf03d9e3a6c17ae454e291d1a3`
- telemetry schema SHA-256:
  `b99697c8f92f8b45c70b9328e52156dab5fc7b30118ecba4b43809abef1a4d4e`
- frozen protocol canonical SHA-256:
  `8eb0786e8427f7fa685a8d137db62b1ecfff40a7897b65f742915477b9b2471d`
- scenario catalog byte SHA-256:
  `8793acf7a1ddddac22ce864cbbb9c45a1277891bf5e598d73d7a63ec85ad0ec9`
- ARM64 image ID:
  `sha256:411497a421a7a33f81c707c8b460ba32e1a4496f4d898936463a4f0155a8e95c`
- workload implementation SHA-256:
  `2600d844e453bfaa1126f1ad8ade3fde072a1f65d343053d35c1e0087a1f9155`
- deployed source archive SHA-256:
  `ad4216ae385a3ecc8f901a6d36d10bec81b6ba79f4d22c921e37c745fd8a9991`
- deployed control archive SHA-256:
  `269c984fe7285c5a15db85c9048d05b09dc601c888d6869dda3129ff129f9b6c`
- Pi→Arch result archive SHA-256:
  `4feddbda88b3207d3e9f8a0ca264f38d3843edda164205b0749d6a11e0e7a360`

Archive มี completed manifests 7, immutable raw segments 21, collection receipts 7,
execution receipts 6 และ signal reports 7 Local Arch report generation ตรวจ exact
receipt membership/segment bytes/raw schema ใหม่อีกครั้ง และ report files ตรงกับ Pi ทุก byte

## Collection quality

| รายการ | ผล |
|---|---:|
| Runs | 7/7 |
| Samples | 630/630 |
| Baseline/workload/recovery | 210/210/210 |
| Valid samples | 630 |
| Samples with missing fields | 0 |
| Samples with collector errors | 0 |
| Samples with counter resets | 0 |
| Late samples | 1 |
| Controlled cleanup | 6/6 |

Late sample อยู่ที่ `v2_benign_service_low`, workload sequence 30, late 1,148.257 ms
เพราะ Docker create/start hook ใช้เวลาหลัง deadline ของ sample แรกใน phase ถูกกำหนดแล้ว
ค่า metric ยัง valid แต่ต้อง reset sampling deadline หลัง lifecycle hook ก่อนเก็บ development
sequence เพื่อไม่ให้ startup time ทำให้ first workload/recovery sample late

## Execution evidence

Operation count เป็น receipt evidence เท่านั้นและไม่ใช่ model feature

| Scenario | Mode | Operations | Errors | Cleanup |
|---|---|---:|---:|---|
| `v2_neutral_idle` | none | — | — | n/a |
| `v2_benign_compute_low` | compute | 12,819 | 0 | pass |
| `v2_benign_compute_high` | compute | 43,971 | 0 | pass |
| `v2_t1496_001_compute_high` | compute | 44,342 | 0 | pass |
| `v2_benign_service_low` | service | 280 | 0 | pass |
| `v2_benign_service_high` | service | 4,446 | 0 | pass |
| `v2_t1499_002_service_high` | service | 4,438 | 0 | pass |

High matched pairs มี throughput ใกล้กัน แปลว่า benign/malicious metadata ไม่ได้เปลี่ยน
hardware treatment อย่างมีนัยสำคัญใน pilot นี้

## Service signal findings

ค่าเป็น workload mean; target metrics ไม่มี baseline เพราะ container ถูกสร้างเฉพาะ workload
phase

| Candidate | Service low | Benign service high | T1499.002 high | Interpretation |
|---|---:|---:|---:|---|
| cgroup CPU usage µs/s | 6,190.6 | 170,363.3 | 170,916.2 | high ≈27.5× low; high pair diff ≈0.32% |
| cgroup CPU PSI some µs/s | 151.1 | 1,704.5 | 1,733.4 | high ≈11.3× low; high pair diff ≈1.69% |
| cgroup memory current bytes | 3,176,857.6 | 7,289,651.2 | 7,564,219.7 | high ≈2.3× low; high pair diff ≈3.77% |
| target TCP total | 3.0 | 3.0 | 3.0 | static, no separation |
| target TCP established | 2.0 | 2.0 | 2.0 | persistent loopback pair |
| target sockets used | 5.0 | 5.0 | 5.0 | static, no separation |
| target/host listen or backlog drop rate | 0 | 0 | 0 | no queue/drop pressure observed |
| cgroup memory/I/O PSI | 0 | 0 | 0 | no memory or I/O pressure observed |

Host CPU PSI workload-minus-baseline mean เพิ่มประมาณ 560 µs/s ใน service-low และ
2,928/2,618 µs/s ใน high pair จึงเก็บไว้เป็น supplemental candidate แต่ host I/O PSI มี
background variation สูงและทิศทางไม่สัมพันธ์กับ service intensity จึงยังไม่ควร freeze

## Compute-treatment finding

Compute high matched pair ให้ cgroup CPU usage 738,772/738,607 µs/s ใกล้กันมาก แต่
compute-low ให้ 246,256 µs/s ตาม quota พร้อม cgroup throttled time 752,761 µs/s และ CPU
PSI 713,632 µs/s ซึ่งสูงกว่า high treatment ที่ throttled ~248k และ PSI 177k–207k

สาเหตุคือ workload ขอ CPU 100% ตลอดเวลาแล้วใช้ cgroup quota 0.25/0.75 core เป็นตัวกำหนด
intensity ทำให้ low profile ถูก throttle/รอนานกว่า high profile นี่เป็น simulator artifact
ที่อาจทำให้โมเดลตีความ cgroup pressure กลับด้าน จึงต้องเปลี่ยน compute intensity ให้ใช้
bounded duty cycle/worker allocation ภายใต้ hard safety ceiling ก่อน development collection

## Candidate decision

นำไปทดสอบซ้ำหลังแก้ workload:

- target cgroup CPU usage rate
- target cgroup CPU PSI some
- target cgroup memory current
- host CPU PSI baseline delta เป็น supplemental candidate

ยังไม่เลือกเข้า frozen feature profile:

- TCP state/socket counts ของ workload รุ่นนี้ เพราะคงที่
- listen/backlog/request-queue/drop counters เพราะเป็นศูนย์ทั้งหมด
- memory/I/O PSI และ cgroup I/O เพราะเป็นศูนย์
- host I/O PSI เพราะ background noise สูงใน single-run pilot
- cgroup CPU throttling/PSI เดิมจนกว่าจะแก้ quota artifact

คำว่า “ยังไม่เลือก” ไม่ได้แปลว่าลบ raw observability ออกจาก collector; เก็บไว้เพื่อทดสอบ
workload revision ที่สร้าง connection churn/queue pressure อย่างปลอดภัย

## Gate และงานถัดไป

1. แก้ phase scheduling ให้ sample แรกเริ่มหนึ่ง interval หลัง Docker lifecycle hook
2. เปลี่ยน compute low/high จาก full-duty + 0.25/0.75 quota เป็น bounded duty/worker
   treatment ภายใต้ hard CPU ceiling เพื่อไม่สร้าง inverse-throttling artifact
3. สร้าง service workload revision ที่ใช้ bounded short-lived loopback connections และ
   concurrency/backlog pressure พร้อม latency/error receipt evidence โดยยังคง
   `network=none`, non-root, read-only และไม่มี external target
4. เพิ่ม observed-impact evidence gate: ห้าม finalize `SERVICE_PRESSURE` label หากไม่มี
   threshold evidence ที่กำหนดล่วงหน้า; operation/error/latency ใช้ยืนยัน label ได้แต่ห้าม
   เป็น model feature
5. build/freeze ARM64 workload image/spec revision ใหม่ แล้วรัน excluded instrumentation
   matrix ซ้ำ
6. freeze feature/profile revision เฉพาะเมื่อ signal direction, matched-pair consistency และ
   label evidence ผ่าน จากนั้นจึงเริ่ม development wave 70 runs

ณ จุดนี้ training dataset v2 ยังไม่ได้เริ่ม, final test ยังไม่เปิด และ XGBoost/TCN/Fusion
ไม่มี checkpoint ใหม่

## Safety/post-run state

- ไม่มี malware, miner, public/third-party target หรือ outbound DoS
- service traffic อยู่ใน container loopback ภายใต้ Docker `network=none`
- ไม่มี Redis, MongoDB หรือ Atlas write
- ไม่มี `chf-poc-*` container ค้าง
- production containers กลับมา 9 ตัว
- `honeypot-hardware.service` inactive ตาม operator intent
- `honeypot-processor.service` active
