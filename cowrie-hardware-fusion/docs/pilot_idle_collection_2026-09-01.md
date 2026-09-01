# Stage A Neutral-Idle Pilot Report — 2026-09-01

> ผล: `PASS` สำหรับ collector/spool/schema/replay path
> ขอบเขต: `pi_sensor`, `neutral_idle`, 1 Hz, manual isolated pilot
> ข้อห้าม: ข้อมูลชุดนี้เป็น `pilot_only=true` และไม่ใช่ training/evaluation dataset

## สิ่งที่พิสูจน์แล้ว

เก็บ telemetry บน Raspberry Pi 5 ผ่าน detached source worktree และ isolated venv โดย
ไม่แก้ production repo checkout, ไม่เปิด/หยุด production service, ไม่ execute command,
miner, malware หรือ traffic generator และไม่เขียน Redis/MongoDB/Atlas ระหว่างเก็บ

ทุก run ใช้ 30 วินาที baseline + 30 วินาที neutral workload phase + 30 วินาที recovery
collector เขียน canonical JSONL ลง bounded local spool, fsync ทุก record, rotate ทุก
30 records และออก content-addressed receipt จากนั้น finalizer ตรวจ schema, hashes,
byte/record counts และ contiguous sequence ทั้งบน Pi และเครื่อง dev หลัง transfer

## Content-bound environment

- experiment: `pilot-v1-20260901`
- repository commit: `3175160531cc182c79271052f81989c014e84940`
- collector source SHA-256: `7a89851fafa52d2eda333fabe8a083e6d37abe6ca8391cbc24c6d5fe9699270c`
- telemetry schema SHA-256: `e00a904c6082e36029885e7e3c706aed3ea5166a47481927c2b9bc493233a2e9`
- environment signature SHA-256: `89a3de3b018a963e15bc46e3c8b0319d6795b91c58f69083c0ff2dff78234248`
- execution boundary: `kind=none`, `egress_enforcement_scope=not_applicable_no_execution`

Pi host firewall มี OUTPUT policy `ACCEPT`; manifest จึงบันทึก
`default_deny_egress=false` ตามข้อเท็จจริง ไม่มี workload execution ใน Stage A จึงไม่
อ้างว่า policy นี้ป้องกัน payload การทดลอง

## Collection results

| Run suffix | Records | Segments | Raw bytes | Receipt SHA-256 | Result |
|---|---:|---:|---:|---|---|
| `001` | 90 | 3 | 322,655 | `04be9fb6e27752e7d4c73745080288aadc0c635b27d3411affbfd0f6a383319b` | pass |
| `002` | 90 | 3 | 322,416 | `b06f7cd47d3b619fc0f25104a3ca506c6414e0a1e473e3749a4e25f9ce1415fa` | pass |
| `003` | 90 | 3 | 322,645 | `3f85577012b41e8ce0901618fcfeb14b0b65d05b6f32f65dda68eb03470c53e4` | pass |
| **รวม** | **270** | **9** | **967,716** | — | **pass** |

ทุก run มี baseline/workload/recovery อย่างละ 30 records และผลรวมเป็น:

- valid samples: 270/270
- late samples: 0; ค่าสูงสุด `late_by_ms=2.368416`
- missing fields: 0
- counter resets: 0
- collector errors: 0
- CPU range: 9.8–36.9%; per-run mean 12.64–14.38%
- memory range: 33.7–35.2%; per-run mean 34.02–34.72%
- temperature range: 54.55–60.60°C; per-run mean 55.89–57.80°C

ค่าข้างต้นเป็นสภาพเครื่องจริงช่วงเก็บ จึงใช้เป็น sanity check ไม่ใช่เกณฑ์ label แบบ
แบ่ง CPU 1–4 rank และไม่ใช่หลักฐานความแม่นยำของโมเดล

## Replay results

ทั้ง 3 runs ถูก replay จาก immutable segments ตามลำดับ receipt เป็น derived windows
5, 10 และ 30 วินาที รวม 9 records ทุก record ผ่าน derived schema และมี target/baseline
coverage 100% ผลลัพธ์แต่ละ record มี:

- aggregate continuous features สำหรับ XGBoost เช่น `cpu_mean`, `cpu_p95`, slope,
  baseline delta, memory/disk/network/process/thermal summaries
- fixed-length TCN arrays 16 channels พร้อม `sample_present` และ `channel_present`
- provenance, split groups และ deterministic record SHA-256

CLI รองรับหลาย immutable JSONL segments หลัง `--telemetry` โดยไม่ต้อง concatenate raw
evidence; correlation และ sequence validation ยังทำงานกับ sample รวมทุก segment

## Storage observation

raw JSONL เฉลี่ย 3,584.13 bytes/sample สำหรับ idle `pi_sensor` pilot:

- 1 Hz ต่อ scope: ประมาณ 295.32 MiB/วัน หรือ 8.65 GiB/30 วัน
- gzip ของ 9 segments: 91,565 bytes หรือ 9.5% ของ raw
- หาก compression ratio นี้คงเดิม: ประมาณ 27.94 MiB/วัน หรือ 0.82 GiB/30 วัน
- spool limit 1 GiB รองรับ raw rate นี้เชิงทฤษฎีประมาณ 83.22 ชั่วโมง ก่อนชน
  `min_free_bytes` และก่อนรวม receipt/metadata

compression และ capacity ต้องวัดใหม่เมื่อมี ordinary load, scopes เพิ่ม, schema เปลี่ยน
หรือใช้ Atlas/object-store จริง

## ข้อสรุปและลำดับถัดไป

Stage A ยืนยันว่า collector → immutable spool → receipt → transfer → local finalizer →
XGBoost/TCN derived window ทำงานได้จริง แต่ 3 runs อยู่ติดกันและเป็น class เดียว จึงห้าม
ใช้ train/test หรือสรุป accuracy

งานถัดไป:

1. เพิ่ม receipt-driven batch discovery และ grouped split tooling
2. implement safe ordinary-load orchestration ที่ไม่ execute attacker-controlled input
3. เก็บ benign counterexamples ต่างเวลา/ต่าง background load ก่อน freeze feature schema
4. เพิ่ม resource-limited local-sink/network และ CPU/memory scenario หลัง safety review
5. เมื่อมี independent runs เพียงพอ จึงสร้าง trivial และ XGBoost baseline ก่อนพิจารณา TCN
