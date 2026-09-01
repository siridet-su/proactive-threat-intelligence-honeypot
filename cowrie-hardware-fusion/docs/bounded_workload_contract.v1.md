# Bounded Ordinary Workload Contract v1

> สถานะ: `PREFLIGHT IMPLEMENTED / EXECUTION ADAPTER NOT IMPLEMENTED`
> ขอบเขต: `benign_compute_control` บน disposable backend เท่านั้น

## เหตุผลที่ไม่รันบน Pi

scenario catalog กำหนด benign compute workload ให้ใช้ metric scopes
`backend_guest`, `backend_cgroup`, `target_process` และ execution boundary
`disposable_vm` ขณะที่ collector บน Pi รองรับเฉพาะ `pi_sensor + kind=none` การเอา
workload runner ไปต่อกับ Pi โดยตรงจึงผิด contract แม้งานนั้นจะเป็น benchmark ที่เรา
เขียนเอง

Pi ยังคงทำหน้าที่ Cowrie sensor/neutral telemetry collector ส่วน workload ที่มี execution
ต้องอยู่ใน backend ที่ทิ้งได้และมี enforcement evidence จริง

## สิ่งที่ implement แล้ว

`workload-preflight` ตรวจความสอดคล้องของ planned run manifest, scenario catalog และ
`bounded_workload_spec.v1` แล้วออก content-bound receipt โดยไม่เริ่ม process/container

gate ปัจจุบันอนุญาตเพียง:

- scenario `benign_compute_control` และ label `benign_control`
- fixed entrypoint `cpu_duty_cycle_v1`; ไม่มี raw Cowrie command/attacker input
- OCI container ภายใน `disposable_vm`
- image digest และ implementation hash ต้องตรงกับ manifest
- `network_mode=none` และ network-policy hash ต้องตรงกับ manifest
- read-only root filesystem, drop all capabilities, no-new-privileges และ seccomp hash
- hard CPU, memory, PID, tmpfs และ output limits
- CPU quota ต้องคำนวณตรงกับ continuous intensity 25/50/75/90%
- workload duration, termination grace และ watchdog ต้องสอดคล้องกัน
- TTP set ต้องว่าง เพราะเป็น benign counterexample ไม่ใช่ malicious simulation

## ใช้งาน preflight

ตัวอย่าง config มี placeholder hashes และใช้ได้เพื่อ review/schema test เท่านั้น:

```bash
cowrie-hardware-dataset workload-preflight \
  --manifest schemas/examples/experiment_run_manifest.benign_compute.v1.example.json \
  --specification configs/bounded_workload.benign_compute.example.json \
  --scenario-catalog configs/scenario_catalog.v1.json \
  --output /path/to/workload-preflight-receipt.json
```

ผลลัพธ์มี manifest/spec/catalog/policy hashes และแสดง `contract_valid=true`,
`execution_authorized=false`, `execution_started=false` เสมอ หมายถึงเอกสารสอดคล้อง
แต่ receipt นี้ไม่ให้อำนาจ runtime เริ่มงาน

## สิ่งที่ต้องมีเพิ่มเติมก่อน execute ครั้งแรก

- disposable VM identity/image receipt ที่สร้างใหม่ได้และทำลายทิ้งได้
- reviewed workload image digest และ source/entrypoint implementation hash จริง
- default-deny/no-network enforcement receipt จาก runtime ไม่ใช่ค่าประกาศลอย ๆ
- seccomp profile bytes/hash, read-only mount และ capability receipt
- backend guest/cgroup/target-process collector พร้อม clock/boot correlation
- runtime adapter ที่ใช้ argv แบบตายตัว ไม่มี shell และตรวจ exit/watchdog/cleanup receipt
- independent review ว่า CPU/memory/PID limits enforce จริงใน environment นั้น
- aborted/quarantine path เมื่อ collector, clock, policy หรือ cleanup check ล้มเหลว

จนกว่ารายการนี้ครบ ห้ามเพิ่มคำสั่ง execute เข้า CLI และห้ามใช้ production Cowrie/Pi
เป็น execution backend

## Content identity ปัจจุบัน

- scenario catalog SHA-256:
  `7bda736a17d12ea2a7aff19a1d86e2acf4c44bb5047bbd7b97294b4d78d61865`
- specification schema: `bounded_workload_spec.v1`
- preflight receipt schema: `bounded_workload_preflight_receipt.v1`

เมื่อ scenario catalog เปลี่ยน example/spec hash เดิมต้อง fail จนกว่าจะ review และ bind
hash ใหม่โดยตั้งใจ
