# Experiment environment receipt v2

สถานะ: IMPLEMENTED / LOCAL TEST PASS / PI CAPTURE NEXT

Receipt นี้ทำให้ environment signature มีนิยามที่ reproduce ได้ แทนการ hash output จาก
คำสั่ง shell แบบไม่กำหนด schema

## Environment signature

environment_signature_sha256 ผูกกับ:

- sensor/subject pseudonymous IDs
- hash ของ boot ID โดยไม่เก็บ raw boot ID
- architecture, kernel, CPU model/count, total RAM/swap และ root device
- interface names และ NTP synchronization state โดยไม่เก็บ IP
- Python/psutil, collector repo/source และ telemetry-schema identities
- production repo commit/clean flag, service states และ running container image IDs
- reviewed workload image ID, architecture, user, entrypoint และ binary hash

เวลา capture และ headroom ชั่วขณะไม่อยู่ใน environment signature เพื่อให้ capture ซ้ำใน
boot/runtime state เดียวกันได้ signature เดิม แต่ fields เหล่านี้ยังอยู่ใน receipt และถูก
ครอบด้วย receipt_sha256

## Safety gates

Validator ปฏิเสธ receipt เมื่อ:

- NTP ไม่ synchronized หรือ Cowrie ไม่ active
- honeypot-hardware, hardware-metrics หรือ hardware-metrics-processor ไม่ inactive
- มี running container ที่ชื่อขึ้นต้นด้วย chf-poc-
- available memory ต่ำกว่า 2 GiB, root free ต่ำกว่า 5 GiB, load 1m มากกว่า 3
  หรืออุณหภูมิสูงกว่า 75°C
- reviewed runner ไม่ใช่ arm64, UID/GID 65532, entrypoint /poc-workload
- environment signature หรือ receipt hash ไม่ตรง

## Privacy

Collector ไม่อ่าน/เก็บ credentials, raw IP, hostname, Cowrie commands หรือ container IDs
Container name, image reference และ immutable image ID ถูกเก็บเพื่ออธิบาย background
workload เท่านั้น

## Capture on Pi

    python -m cowrie_hardware_fusion.cli capture-pi-environment-receipt \
      --config pi-collector-config.json \
      --collector-repo-commit <deployed-source-commit> \
      --production-repo /home/cpe27/proactive-threat-intelligence-honeypot \
      --runner-image-id sha256:<reviewed-image-id> \
      --output environment-receipt.v2.json

ไฟล์ output เขียนแบบ exclusive ห้าม overwrite receipt เดิม ตรวจภายหลังได้ด้วย:

    python -m cowrie_hardware_fusion.cli validate-pi-environment-receipt \
      --receipt environment-receipt.v2.json

ขั้นถัดไปคือ commit/deploy source แบบ isolated ไป Pi, capture receipt และใช้ค่า
environment_signature_sha256 ใน development matrix ที่ regenerate ใหม่
