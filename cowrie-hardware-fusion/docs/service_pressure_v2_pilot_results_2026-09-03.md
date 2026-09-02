# Service-pressure v2 excluded pilot result — 2026-09-03

> สถานะ: `7/7 COMPLETE / QUALITY PASS / TREATMENT GATES PASS`
> เวลารันจริง: `2026-09-03 00:02–00:13 Asia/Bangkok`
> ขอบเขต: instrumentation only, `pilot_only=true`, `training_eligible=false`

## ข้อสรุป

Treatment v2 แก้สองปัญหาจาก pilot v1 ได้สำเร็จ:

- compute 25/75% duty ภายใต้เพดาน 1 CPU เดียวกันให้ cgroup CPU usage ต่างกัน 2.97×
  และไม่มี quota throttling ทั้งสองระดับ จึงไม่เกิด inverse-throttling artifact เดิม
- service 10/150 requests/s ให้ target TCP TIME_WAIT ต่างกัน 15.6× และ high ทั้งคู่มี
  bounded 503/rejection ประมาณ 70.7% พร้อม p95 latency ประมาณ 41.4 ms

Matched benign/TTP pairs ยังตอบสนองใกล้กันมากใน signal หลัก จึงไม่มีหลักฐานว่า hardware
treatment แอบ encode malicious/benign disposition การติด TTP ยังเป็น evaluation metadata
ไม่ใช่สิ่งที่ hardware branch พิสูจน์เอง

## Frozen identities

- repository commit: `95d7970d4d2c11611627b73aa918582a0b6642a2`
- collector `0.4.2` source SHA-256:
  `d9f627edf0450a1dd03b427ada1e45f138aac523b570170e72afae52ffcde3fd`
- telemetry schema SHA-256:
  `b99697c8f92f8b45c70b9328e52156dab5fc7b30118ecba4b43809abef1a4d4e`
- ARM64 binary SHA-256:
  `c5ef621d8b5aa3bd1b542c971ee91af3ebbc694704e50856b126dd6c97e6eb86`
- reviewed Dockerfile SHA-256:
  `3bd2df874fd7231ac92f2a04ab5c59c44f908f4e4ffbd330796a880f27b13bee`
- immutable image ID:
  `sha256:bcb5296bd79343e4f21ad11efb2ab8d1b4dde785d34cff4b5072a459863e24c3`
- source archive SHA-256:
  `41ff52f44a3395a60a496e4f635f48af8e3c06f3d78d237f2932b1e2d02373e3`
- final control archive SHA-256:
  `1130b96414f3d49af10d64db1b8a4efe4dbf80273355661313822e1c3015850f`
- matrix canonical SHA-256:
  `0c1bab3b0fc8951cfb0302dcb8164507c430b51bef807ad5f5a60fb7ded74e07`
- matrix serialized-file SHA-256:
  `6f819301edd96472b2b761e1663dac04c39c64f61073f104be8d2293c77feb53`
- Pi→Arch export SHA-256:
  `5570a87cbe8c22689f36426c8ae01848436e52d09678300208e289a8bbb9edf1`
- Pi/Arch audit-summary SHA-256:
  `698998819a6e452abc34c81319af88a2e7862c3eac2572f5d6533f60c031ab42`

Image แรก `sha256:cb2999e...966e5` ผ่าน canary แต่ไม่มี OCI revision label จึงถูก runtime
preflight ปฏิเสธก่อน collection ไม่มี sample ใดผูกกับ image นั้น Control ชุดนั้นถูกแยก
ไว้ใน `rejected-control-image-no-label` เป็น audit trail แล้ว generate matrix ใหม่ด้วย
labeled image ข้างต้น

## Data-quality audit

| Check | ผล |
|---|---:|
| runs/completed manifests | 7/7 |
| raw segments | 21 |
| schema-valid samples | 630/630 |
| baseline/workload/recovery | 210/210/210 |
| late samples | 0 |
| missing-field occurrences | 0 |
| collector-error occurrences | 0 |
| counter-reset occurrences | 0 |
| controlled cleanup | 6/6 |
| Arch regenerated reports exact match | 7/7 |

หลังจบไม่มี `chf-poc-*` container ค้าง Production containers ยังรัน 9 ตัว และทั้ง
`hardware-metrics.service`/`hardware-metrics-processor.service` ยัง inactive ตามสถานะก่อน
ทดลอง ไม่มี Redis, MongoDB หรือ Atlas write จาก pilot

## Execution evidence

| Scenario | Attempts | Success | Errors | Rejected | Error % | p95 latency ms |
|---|---:|---:|---:|---:|---:|---:|
| compute low | 12,942 | 12,942 | 0 | 0 | 0.00 | 0 |
| compute high benign | 44,694 | 44,694 | 0 | 0 | 0.00 | 0 |
| T1496.001 compute high | 44,669 | 44,669 | 0 | 0 | 0.00 | 0 |
| service low | 301 | 300 | 1 | 0 | 0.33 | 40.99 |
| service high benign | 4,524 | 1,324 | 3,200 | 3,198 | 70.73 | 41.38 |
| T1499.002 service high | 4,523 | 1,320 | 3,203 | 3,200 | 70.82 | 41.38 |

ทุก controlled run ผ่าน gate ที่ระบุใน spec v2 Service-low error หนึ่งครั้งเป็น request ที่
ถูก cancel ตอน bounded duration จบ ไม่ใช่ capacity rejection และยังต่ำกว่า 5% gate

## Candidate telemetry results

ค่าด้านล่างเป็น workload-phase mean ยกเว้นคอลัมน์ที่ระบุ:

| Scenario | cgroup CPU us/s | CPU PSI us/s | Memory MiB | TCP TIME_WAIT mean | TIME_WAIT p95 | TCP total mean | sockets used mean |
|---|---:|---:|---:|---:|---:|---:|---:|
| compute low | 249,941 | 270 | 1.53 | 0 | 0 | 0 | 1.00 |
| compute high benign | 742,128 | 473 | 1.64 | 0 | 0 | 0 | 1.00 |
| T1496.001 compute high | 743,348 | 325 | 1.61 | 0 | 0 | 0 | 1.00 |
| service low | 14,187 | 266 | 4.97 | 157 | 293 | 158 | 3.00 |
| service high benign | 118,818 | 2,512 | 7.83 | 2,453 | 4,506 | 2,458 | 6.80 |
| T1499.002 service high | 118,931 | 2,546 | 7.95 | 2,447 | 4,382 | 2,452 | 6.67 |

การแยก treatment:

- compute-high/low: CPU usage 2.97×, CPU PSI 1.75×, throttled time 0 ทั้งคู่
- service-high/low: CPU usage 8.38×, CPU PSI 9.44×, memory 1.57×,
  TIME_WAIT 15.58×, TCP total 15.51× และ sockets used 2.27×
- matched compute-high CPU usage ต่าง 0.16%; matched service-high CPU usage 0.10%,
  CPU PSI 1.35%, memory 1.46%, TIME_WAIT 0.27% และ TCP total 0.27%

Kernel listen/backlog drop rates ยังเป็นศูนย์ จึงไม่ควรใช้เป็น feature ใน revision นี้
Service degradation ถูกยืนยันด้วย application-capacity rejection ใน receipt แต่ receipt
ดังกล่าวเป็น label evidence เท่านั้นและห้ามเข้า model feature

## Feature-revision decision

เข้าสู่ aggregate/channel implementation review:

- target cgroup CPU usage rate
- target TCP TIME_WAIT
- target network-namespace sockets used
- target cgroup memory current
- target cgroup CPU PSI `some` ในฐานะ ablation candidate เพราะ matched compute PSI ยัง
  แปรผันมากกว่า CPU usage

ยังไม่เลือก:

- target TCP total เพราะเกือบซ้ำกับ TIME_WAIT ใน workload นี้
- listen/backlog/queue drops เพราะทุกค่าศูนย์
- execution attempts/errors/rejections/latency เพราะเป็น simulator/label evidence
- TTP/disposition/scenario/treatment identifiers เพราะเป็น leakage

ต้องสร้างอย่างน้อยสอง profile แยกกัน: host-only สำหรับ deployment baseline และ
target/cgroup-required สำหรับวัด upper-bound gain ห้ามสรุปว่า target profile deploy ได้กับ
Cowrie production จนกว่าจะมี collector mapping ไปยัง Cowrie container/cgroup และผ่าน
shadow availability test บน Pi จริง

## Data location

- Pi: `/home/cpe27/honeypot-experiment/service-pressure-instrumentation-v2`
- Arch ignored data: `cowrie-hardware-fusion/data/service-pressure-instrumentation-v2/`
- export: `data/service-pressure-instrumentation-v2/pi-export.tar.gz`
- extracted evidence: `data/service-pressure-instrumentation-v2/pi-export/`
- Arch-regenerated reports: `data/service-pressure-instrumentation-v2/local-verified-reports/`

ขั้นถัดไปคือ implement/freeze feature schema และ TCN channel schema revision, test
deterministic builder บน raw v2 pilot และ generate development-wave control artifacts โดย
ยังไม่เปิด final-test wave
