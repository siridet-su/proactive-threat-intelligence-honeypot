---
title: CWD filesystem telemetry code review
date: 2026-09-09
environment: loopback
commit: 738861c
status: partial
---

# CWD filesystem telemetry code review

## Objective

ตรวจสอบ feature real-time filesystem activity ที่ merge ผ่าน pull request #17
ตั้งแต่การรับ Cowrie JSON, การสร้าง CWD projection ใน MongoDB, REST/SSE API
จนถึงการแสดง topology และ session history บน dashboard โดยเน้นความถูกต้องของ
ข้อมูล, retry/idempotency, pagination, resource lifecycle, security boundary และ
test coverage

ช่วง commit ที่ตรวจคือ `03a41a7..738861c` บน branch `main` รวมการเปลี่ยนแปลง
13 ไฟล์ เพิ่ม 1,020 บรรทัด และลบ 3 บรรทัด

## Procedure

1. Pull `origin/main` แบบ fast-forward-only จาก `03a41a7` เป็น `738861c`
2. อ่าน repository instructions และ design note ที่เกี่ยวข้อง
3. ตรวจ diff และไล่ data flow ต่อไปนี้

   ```text
   Cowrie JSON log
     -> collector-agent
     -> Redis raw:cowrie
     -> processor-agent
     -> MongoDB cwd_session_state / cwd_events
     -> Next.js REST API / MongoDB Change Stream / SSE
     -> FilesystemActivity UI
   ```

4. ตรวจ execution flow ของ Redis live consumer และ pending-message recovery
5. ตรวจ keyset pagination, MongoDB/BSON type conversion และ SSE reconnect
6. รัน Go tests, ESLint, Next.js production build และ whitespace check

## Expected result

- Deployment จาก source ใน repository สามารถสร้าง CWD telemetry ได้ครบเส้นทาง
- Current CWD ต้องไม่ย้อนกลับเมื่อเกิด at-least-once delivery หรือ retry
- History pagination ต้องไม่ข้ามหรือทำซ้ำ event แม้ timestamp เท่ากัน
- UI ต้องไม่แสดง history ของ session อื่นหลังผู้ใช้เปลี่ยน selection
- SSE ต้องกลับมารับ update ได้หลัง MongoDB หลุดชั่วคราว
- ค่าที่ประกาศใน API contract ต้อง serialize ได้โดยไม่สูญเสียข้อมูล
- Tests และ production build ต้องผ่าน

## Observed result

Static checks และ build ผ่าน แต่ยังมี correctness และ integration findings ที่
ควรแก้ก่อน production rollout

### P1 — ไม่มี CWD telemetry producer ใน deployment source ชุดนี้

Collector เพียงคัดลอก `cwd_before`, `cwd`, `cwd_after`, `cwd_action` และ
`cwd_status` ที่มีอยู่แล้วใน Cowrie JSON ไปเป็น Redis stream fields; collector
ไม่ได้สร้างค่า CWD ขึ้นมาเอง

Processor รับ `cowrie.command.input` เฉพาะเมื่อ payload มี `cwd_before` และรับ
transition ผ่าน event ใหม่ชื่อ `cowrie.session.cwd` แต่การเปลี่ยนแปลงที่ตรวจไม่มี
Cowrie patch, output plugin หรือ config ที่สร้าง schema ดังกล่าว

นอกจากนี้ design note เดิมระบุว่า Cowrie log ปัจจุบันไม่มี CWD และตัวอย่าง plugin
ในเอกสารเพิ่ม field ชื่อ `cwd` ให้ `cowrie.command.input` ซึ่งยังไม่ตรงกับ processor
ที่ต้องการ `cwd_before`

หลักฐาน:

- [`agents/collector-agent/main.go`](../../agents/collector-agent/main.go#L196-L208)
- [`agents/processor-agent/cwd.go`](../../agents/processor-agent/cwd.go#L53-L81)
- [`dashboard-v2/docs/REALTIME_CWD_TRACKING.md`](../../dashboard-v2/docs/REALTIME_CWD_TRACKING.md#L31-L44)
- [`dashboard-v2/docs/REALTIME_CWD_TRACKING.md`](../../dashboard-v2/docs/REALTIME_CWD_TRACKING.md#L321-L358)

ผลกระทบ: หาก production ไม่มี Cowrie instrumentation ที่จัดการอยู่นอก repository
ทั้ง `cwd_session_state` และ `cwd_events` จะไม่ถูกสร้าง และหน้า Filesystem
Activity จะอยู่ใน empty state ตลอด

ข้อเสนอแนะ: เพิ่มและ pin Cowrie patch/plugin พร้อม config และ fixture ใน repository
หรือกำหนด producer contract ภายนอกให้ชัดเจน จากนั้นเพิ่ม end-to-end fixture ที่พิสูจน์
ว่า Cowrie log หนึ่งชุดสร้าง state, history และ dashboard response ได้จริง

### P1 — Pending retry สามารถเขียน current CWD เก่าทับค่าที่ใหม่กว่า

Processor รัน live consumer และ `XAUTOCLAIM` recovery พร้อมกัน ขณะที่
`recordCwdObservation` อ่าน state เดิมแล้วใช้ `UpdateOne` เขียน state ใหม่โดยไม่มี
เงื่อนไขว่า `observation.At` ต้องใหม่กว่าหรือเท่ากับ `updatedAt` ปัจจุบัน

ตัวอย่าง failure path:

1. Event A บันทึก CWD projection สำเร็จ แต่ขั้นตอนถัดไปของ message processing ล้มเหลว
   จึงยังไม่ ACK
2. Event B ที่ใหม่กว่าถูกประมวลผลและเขียน current CWD
3. Recovery claim event A หลังครบ idle timeout แล้วเขียน state เก่าทับ event B

TTL ของ state จะถูกคำนวณจาก timestamp เก่าด้วย จึงอาจทำให้ state หมดอายุเร็วกว่าที่ควร

หลักฐาน:

- [`agents/processor-agent/main.go`](../../agents/processor-agent/main.go#L112-L113)
- [`agents/processor-agent/main.go`](../../agents/processor-agent/main.go#L190-L209)
- [`agents/processor-agent/cwd.go`](../../agents/processor-agent/cwd.go#L147-L194)

ผลกระทบ: Dashboard อาจแสดง current path ผิด แม้ history event จะยัง idempotent ด้วย
`$setOnInsert`

ข้อเสนอแนะ: ทำ state transition แบบ atomic และยอมรับ update เฉพาะ observation ที่ไม่
เก่ากว่า state ปัจจุบัน พร้อมทดสอบ out-of-order delivery, duplicate delivery และ
live/recovery concurrency กับ MongoDB-compatible test fixture

### P2 — History pagination ข้าม event ที่ timestamp เท่ากัน

Cursor encode ทั้ง `at` และ `id` และ query sort ด้วย `{ at: -1, _id: -1 }` แต่
pagination filter ใช้เพียง `{ at: { $lt: cursorAt } }` โดยไม่ใช้ cursor ID

MongoDB BSON Date เก็บเวลาใน precision ระดับ millisecond ดังนั้น event มากกว่าหนึ่ง
รายการสามารถมี `at` เท่ากันได้ เมื่อรายการกลุ่มนั้นคร่อมขอบหน้า event ที่เหลือซึ่งมี
timestamp เท่ากับรายการสุดท้ายของหน้าก่อนจะถูกตัดออกทั้งหมด

หลักฐาน:

- [`dashboard-v2/src/lib/filesystem-server.ts`](../../dashboard-v2/src/lib/filesystem-server.ts#L144-L157)
- [`dashboard-v2/src/lib/filesystem-server.ts`](../../dashboard-v2/src/lib/filesystem-server.ts#L179-L201)

ผลกระทบ: Session path audit อาจไม่ครบถ้วนโดยไม่มี error แจ้งผู้ใช้

ข้อเสนอแนะ: ใช้ compound keyset cursor ตาม sort order คือ `at < cursorAt` หรือ
`at == cursorAt && _id < cursorId` และเพิ่ม test ที่มี event timestamp เดียวกันเกิน
หนึ่งหน้า

### P2 — Response เก่าสามารถเขียน history ทับ session ที่เลือกใหม่

`loadHistory` ไม่มี `AbortController`, request generation token หรือการตรวจว่า
response ยังตรงกับ `selectedSessionId` ปัจจุบัน หากผู้ใช้เลือก session A แล้วเลือก
session B ก่อน request แรกจบ response ของ A อาจกลับมาทีหลังและแทนที่ history ของ B

หลักฐาน:

- [`dashboard-v2/src/components/filesystem/FilesystemActivity.tsx`](../../dashboard-v2/src/components/filesystem/FilesystemActivity.tsx#L128-L150)

ผลกระทบ: UI แสดง audit events ภายใต้หัวข้อและ context ของคนละ session ชั่วคราวหรือ
จนกว่าจะ refresh/select ใหม่

ข้อเสนอแนะ: ยกเลิก request เดิมเมื่อ session เปลี่ยนและตรวจ request/session identity
ก่อน commit state รวมถึง reset history/cursor ทันทีเมื่อเริ่มโหลด session ใหม่

### P2 — Change-stream reconnect หยุดหลัง retry ที่ล้มเหลวหนึ่งครั้ง

เมื่อ change stream ปิด ระบบตั้ง timer เพื่อเรียก `ensureFilesystemChangeStream()`
อีกครั้ง แต่ callback ไม่ catch rejected promise และไม่ schedule retry รอบถัดไป

Subscriber และ HTTP SSE connection ยังคงเปิดอยู่ อีกทั้ง heartbeat ยังทำงาน ทำให้
browser แสดงสถานะ live ได้แม้ server ไม่มี MongoDB change stream แล้ว

หลักฐาน:

- [`dashboard-v2/src/lib/filesystem-server.ts`](../../dashboard-v2/src/lib/filesystem-server.ts#L208-L245)
- [`dashboard-v2/src/app/api/filesystem-topology/stream/route.ts`](../../dashboard-v2/src/app/api/filesystem-topology/stream/route.ts#L34-L59)

ผลกระทบ: Topology ค้างแบบเงียบ ๆ หลัง transient MongoDB/network failure

ข้อเสนอแนะ: catch reconnect failure, schedule retry แบบ bounded backoff ต่อเนื่อง
และส่งสถานะ unavailable หรือปิด SSE เพื่อให้ EventSource ฝั่ง browser reconnect

### P3 — `sequence` ถูกแปลงเป็น `null` ที่ API boundary

Processor บันทึก `time.Time.UnixNano()` เป็น BSON Int64 ซึ่งมีค่ามากกว่า
`Number.MAX_SAFE_INTEGER` แล้ว MongoDB Node driver deserialize เป็น `Long` แต่
`normalizeHistoryEvent` รับเฉพาะ JavaScript `number`

การทดลอง serialize/deserialize ด้วย MongoDB package เวอร์ชันใน project ยืนยันว่า
ค่า `1788912000000000000` ถูกอ่านกลับเป็น object ชนิด `Long`

หลักฐาน:

- [`agents/processor-agent/cwd.go`](../../agents/processor-agent/cwd.go#L200-L215)
- [`dashboard-v2/src/lib/filesystem-server.ts`](../../dashboard-v2/src/lib/filesystem-server.ts#L159-L176)

ผลกระทบ: `sequence` ใน REST response และข้อความ `event <sequence>` ใน UI จะหายไป
เสมอสำหรับข้อมูลที่ writer ใหม่นี้สร้าง

ข้อเสนอแนะ: กำหนด sequence ใน API contract เป็น decimal string หรือแปลง BSON
`Long` เป็น string โดยไม่ผ่าน JavaScript number

## Metrics

| Check | Result |
| --- | --- |
| `go test ./...` ใน `agents/processor-agent` | Passed |
| `go test ./...` ใน `agents/collector-agent` | Passed; package ไม่มี test files |
| `npm run lint` ใน `dashboard-v2` | Passed |
| `npm run build` ใน `dashboard-v2` | Passed; TypeScript และ route generation สำเร็จ |
| `git diff --check 03a41a7..738861c` | Passed |
| Source files changed during review | None |
| Findings | 2 P1, 3 P2, 1 P3 |

## Limitations

- ไม่ได้เชื่อมต่อ production Cowrie, Redis หรือ MongoDB
- ไม่ได้ยืนยันว่ามี Cowrie patch/config ที่จัดการอยู่นอก repository หรือไม่ ดังนั้น
  finding เรื่อง telemetry producer จะไม่เป็น blocker เฉพาะกรณีที่มี external
  instrumentation ซึ่ง emit schema เดียวกันและมี deployment evidence ชัดเจน
- Tests ปัจจุบันครอบคลุมเฉพาะการ parse/validate CWD observation บางกรณี ยังไม่มี
  integration test สำหรับ MongoDB state transition, pagination, SSE reconnect หรือ
  browser request race
- ผลนี้เป็น static review และ local build validation ไม่ใช่ production approval

## Follow-up

ลำดับที่แนะนำก่อน deploy:

1. ทำ producer contract และ Cowrie instrumentation ให้ deploy/reproduce ได้
2. ป้องกัน out-of-order state update แบบ atomic และเพิ่ม concurrency/retry tests
3. แก้ compound cursor pagination และเพิ่ม timestamp-tie tests
4. ยกเลิกหรือ guard stale history requests เมื่อเปลี่ยน session
5. ทำ change-stream reconnect loop ที่สื่อสถานะ failure ไปถึง client
6. เปลี่ยน `sequence` contract เป็นชนิดที่รักษา Int64 ได้
7. รัน staging end-to-end validation ด้วย synthetic Cowrie fixtures แล้วบันทึก
   evidence แยกต่างหาก
