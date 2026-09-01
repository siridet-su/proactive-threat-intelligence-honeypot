# Raspberry Pi Safe-Container Hardware PoC v1

> สถานะ: `IMPLEMENTED / TESTED LOCALLY / PI EXECUTION PENDING`
> เป้าหมาย: smoke test ว่า hardware telemetry แยก behavior candidate ของ
> `T1496.001` และ `T1499.002` จาก idle/benign controls ได้หรือไม่

## Claim boundary

PoC นี้ใช้ fixed benign programs จำลอง resource behavior เท่านั้น ไม่ใช้ malware,
miner, botnet code, raw Cowrie command หรือ external target ผลลัพธ์เป็น
`behavioral TTP candidate` จาก controlled ground truth ไม่ได้พิสูจน์เจตนาของ attacker
และข้อมูล 3 repetitions ต่อ scenario ยังเล็กเกินไปสำหรับอ้าง production accuracy

## Scenario matrix

| Scenario | Label | Fixed load | Container CPU limit |
|---|---|---:|---:|
| neutral idle | no TTP | none | none |
| benign compute control | no TTP | SHA-256 benchmark | 0.25 core |
| compute hijacking simulation | T1496.001 | SHA-256 benchmark | 0.75 core |
| benign service control | no TTP | 10 loopback req/s | 0.25 core |
| service exhaustion simulation | T1499.002 | 150 loopback req/s | 0.75 core |

เก็บ scenario ละ 3 runs แบบ interleave ตาม repetition เพื่อลด time-order confound
แต่ละ run มี baseline 30 วินาที + workload 30 วินาที + recovery 30 วินาที ที่ 1 Hz
รวม 15 runs, 1,350 raw samples และเวลาอย่างน้อย 22.5 นาที

ค่า `25/75` ใน manifest เป็นระดับ treatment ของ scenario ไม่ใช่ CPU utilization ที่
วัดได้จริง Feature ของโมเดลเก็บค่า continuous เช่น mean/max/p95/slope และเก็บ
intensity rank ไว้เป็น metadata/stratification เท่านั้น ไม่ป้อน rank เป็น model feature

## Execution boundary

ทุก controlled run ใช้ scratch OCI image ที่มี binary ARM64 เพียงไฟล์เดียว และ Docker
บังคับ:

- `--network=none`; service/client สื่อสารผ่าน `127.0.0.1` ภายใน network namespace เดียว
- read-only root filesystem, user `65532:65532`, drop capabilities ทั้งหมด
- `no-new-privileges`, Docker default seccomp, ไม่มี mount จาก host
- CPU 0.25 หรือ 0.75 core, memory 128 MiB, PID limit 16
- internal timeout 32 วินาที, phase stop grace 2 วินาที และ watchdog contract 40 วินาที
- output จำกัด 4 KiB และ container ต้องถูกลบ/ตรวจว่าไม่เหลือก่อนออก receipt

Preflight ปฏิเสธการรันถ้า image/binary hash ไม่ตรง, architecture ไม่ใช่ ARM64, cgroup v2
หรือ seccomp ไม่มี, container name ซ้ำ, RAM ว่างต่ำกว่า 2 GiB, disk ว่างต่ำกว่า 5 GiB,
load 1 นาทีสูงกว่า 3 หรืออุณหภูมิสูงกว่า 75°C

## Telemetry path

ใช้ experimental Python collector `0.3.0` ใน isolated venv เดิมบน Pi ไม่เปิด Go
hardware agent production และไม่เขียน Redis/MongoDB Atlas ข้อมูลทั้งหมดอยู่ใน bounded
local spool แยกต่างหาก

นอกจาก host CPU/per-core/load/memory/disk/network/thermal/process metrics แล้ว ช่วง
workload จะอ่าน process ของ container โดยตรงและเก็บ pseudonymous PID/parent hashes,
CPU แบบ single-core basis, RSS, thread count, socket count และ cgroup hash หลังจบ phase
target จะถูก clear เพื่อไม่ปะปนกับ recovery

## Reproducible workflow

1. รัน Go unit tests/vet แล้ว cross-compile static ARM64 binary
2. คำนวณ SHA-256 ของ binary และ build scratch image พร้อม revision label เดียวกัน
3. inspect image ID/architecture/entrypoint/user แล้วรัน compute และ service canary 10 วินาที
4. freeze matrix/manifests/specifications ด้วย `prepare-pi-poc-matrix`
5. ก่อนทุก run รัน `pi-poc-preflight`
6. idle ใช้ `collect-idle-run`; controlled scenario ใช้ `collect-pi-poc-run`
7. controlled run ต้องได้ทั้ง collection receipt และ execution receipt ก่อน
   `finalize-pi-poc-manifest`
8. transfer immutable spool มายัง training workspace, verify hashes แล้วสร้าง 30-second
   workload windows สำหรับ XGBoost และ TCN
9. XGBoost smoke evaluation ใช้ repetition-held-out folds; TCN/Fusion ยังไม่ใช้รายงาน
   accuracy จนมี independent runs มากกว่านี้

## Stop conditions

หยุด matrix ทันทีถ้า preflight fail, container cleanup ไม่สำเร็จ, production container
เปลี่ยนสถานะ, sample invalid/late มากผิดปกติ, workload exit ไม่เป็นศูนย์, Pi throttled,
อุณหภูมิเกิน gate หรือ headroom ต่ำกว่าเกณฑ์ หลังแก้เหตุแล้วต้องใช้ run ID ใหม่ ห้ามเขียน
ทับ partial evidence
