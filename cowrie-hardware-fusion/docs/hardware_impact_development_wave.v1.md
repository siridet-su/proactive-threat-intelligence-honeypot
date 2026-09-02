# Hardware-impact development wave v1

วันที่เตรียม control set: 2026-09-03

สถานะ: RUNTIME TOOLING READY / FRESH PI RECEIPT PENDING / FINAL TEST CLOSED

## Scope

ขั้นนี้สร้างเฉพาะ development_train ตาม Protocol v2:

- 7 scenarios × 10 repetitions = 70 independent planned runs
- run ละ baseline/workload/recovery 30/30/30 วินาที ที่ 1 Hz
- 6,300 planned samples หรือ sampling time 105 นาที
- แบ่ง planned day slot ละ 35 runs เพื่อให้เก็บอย่างน้อย 2 วันจริง
- calibration 35 runs และ final-test 35 runs ไม่ได้ถูก generate
- หลัง development wave ต้องหยุดตรวจ data quality/signal/model ก่อนขั้นถัดไป

ค่า training_eligible=true หมายถึง run จะเข้า development dataset ได้หลัง collection,
receipt, treatment evidence, schema และ quality gates ผ่านครบ ไม่ได้หมายความว่า planned
manifest ที่ยังไม่รันเป็น training data แล้ว

## Deterministic schedule

Generator ใช้ seed 20260903 และจัดลำดับ scenario ด้วย canonical SHA-256 ภายในแต่ละ
repetition เพื่อลด systematic order effect:

- day slot 1: repetitions 1, 3, 5, 7, 9
- day slot 2: repetitions 2, 4, 6, 8, 10
- 7 scenarios ปรากฏอย่างละ 10 ครั้ง
- matched benign/malicious pair ใช้ treatment/limits/parameters เดียวกัน ยกเว้น
  deterministic seed

Planned slot เป็นข้อกำหนดการจัดคิว ไม่ใช่หลักฐาน collection day ขั้น audit หลังรันต้องตรวจ
timestamp ว่าแต่ละ slot อยู่คนละ UTC date จริง มิฉะนั้นทั้ง wave ต้องไม่ผ่าน

## Bound identities

Local generated matrix:

    experiment_id       hardware-impact-development-v2-20260903
    matrix_sha256       f22c5a17cc3826c502b7653a13a4ca2eb1b5b5c642fb7fbd13c8eb21f995d959
    protocol_sha256     8eb0786e8427f7fa685a8d137db62b1ecfff40a7897b65f742915477b9b2471d
    feature_contract    def95353e69628454541a27b64559e8c537c9772a82ebb303b67e93cc27f5666
    runner_image        sha256:bcb5296bd79343e4f21ad11efb2ab8d1b4dde785d34cff4b5072a459863e24c3
    runner_binary       c5ef621d8b5aa3bd1b542c971ee91af3ebbc694704e50856b126dd6c97e6eb86
    repo_commit         ab3c88fccc84e7a05ca46e48f4d377b2a8b9b07f
    environment         dbbc7e9536578f120b416509636fe35598434c7fe44363c79e9985fdfcff3a45

Matrix และ 70 control directories อยู่ที่
data/hardware-impact-development-v2-controls/ ซึ่งถูก .gitignore เพราะเป็น generated
experiment control data ก่อน deploy ต้อง query Pi ใหม่และ regenerate หาก image, collector,
repo commit หรือ environment signature ไม่ตรง

## Safety and leakage

- fixed reviewed ARM64 image และ fixed entrypoint เท่านั้น
- Docker network=none, read-only root, UID/GID 65532, drop all capabilities,
  no-new-privileges, CPU/memory/PID/output limits และ watchdog
- ไม่มี attacker code, malware, miner หรือ external target
- receipt operations/errors/rejections/latency ใช้ treatment evidence เท่านั้น
- matrix/spec ผูก Protocol v2 และ Model Feature Contract v1 คนละ hash
- manifests เป็น non-pilot development candidates แต่ยัง
  production_analytics_eligible=false

## Generate

    python -m cowrie_hardware_fusion.cli prepare-hardware-impact-development \
      --experiment-id hardware-impact-development-v2-20260903 \
      --image-id sha256:<reviewed-arm64-image> \
      --implementation-sha256 <reviewed-binary-sha256> \
      --repo-commit <40-or-64-hex-source-identity> \
      --environment-signature-sha256 <fresh-pi-signature> \
      --config configs/experimental_collector.pi_sensor.pilot.example.json \
      --protocol configs/hardware_impact_experiment_protocol.v2.json \
      --feature-contract configs/model_feature_contract.v1.json \
      --scenario-catalog configs/scenario_catalog.v1.json \
      --output-dir data/hardware-impact-development-v2-controls

Generator ตรวจ schema ของ matrix, 70 manifests และ 60 workload specs รวมถึง exact
scenario coverage, deterministic order, day slots, matched treatments, artifact hashes,
development-only claims และ final-test lock

## ก่อนเริ่ม collection

1. commit/push generator และ review diff
2. audit Pi ปัจจุบัน: image identity, environment signature, disk/RAM/load/temperature,
   NTP, production-container count และ hardware-metrics services
3. หาก identity ใดเปลี่ยน ให้ regenerate control set และบันทึก matrix hash ใหม่
4. ใช้ runtime commands ที่ validate development spec/matrix โดยตรง แล้วทำ no-collection
   preflight กับ run แรกของแต่ละ family
5. เก็บ day slot 1 เท่านั้น ตรวจ receipts/cleanup/quality ก่อนนัดเก็บ day slot 2

ยังไม่อนุญาต calibration/final-test generation หรือ model training จน development
collection และ audit ผ่าน

## Runtime commands

ทุกคำสั่งอ่าน matrix และ control directories ครบ 70 ชุดและตรวจ hashes/schema/semantic
ก่อนเลือก run เดียว จึงไม่สามารถส่ง manifest ที่อยู่นอก matrix เข้า collector ได้:

- validate-hardware-impact-development-controls — ตรวจ 70 controls โดยไม่แตะ Pi runtime
- hardware-impact-development-preflight — ตรวจ collector/Docker/headroom โดยไม่เก็บข้อมูล
- collect-hardware-impact-development-run — เก็บหนึ่ง matrix-bound run
- finalize-hardware-impact-development-manifest — ตรวจ collection/execution receipts,
  observed-impact gate แล้วสร้าง completed manifest

Idle runs ไม่มี workload spec/execution receipt และ dispatch ไป idle collector ส่วนอีก 60
runs ใช้ reviewed safe-container lifecycle เดิม Service parameters ของ development schema
ถูกส่งต่อเป็น connection-mode, capacity และ handler-delay เหมือน pilot v2

## Read-only Pi audit 2026-09-03 04:09 +07

- aarch64, kernel 6.8.0-1063-raspi, uptime ประมาณ 1 ชั่วโมง 18 นาที
- NTP synchronized, load 1m 0.10
- available RAM 6,411,137,024 bytes, root free 65,331,101,696 bytes
- production containers 9 ตัวทำงาน; experiment container ค้าง 0
- Cowrie active
- honeypot-hardware, hardware-metrics และ hardware-metrics-processor inactive
- reviewed image ID/architecture/user/entrypoint/revision label ตรงทั้งหมด

Pi เพิ่ง reboot ดังนั้น signature จาก pilot ไม่ใช้เป็น fresh development identity แม้
software/image หลักยังตรง ต้อง capture receipt ใหม่หลัง runtime tooling ถูก deploy แล้ว
regenerate matrix ก่อน preflight จริง
