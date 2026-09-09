# Real-time Attacker Directory Tracking (CWD)

## สถานะปัจจุบัน

Dashboard ใช้ CWD ที่ Cowrie อ่านจาก virtual shell โดยตรง ไม่ parse หรือจำลอง
ผลจาก command text เพราะวิธีจำลองให้ผลผิดเมื่อเจอ alias, script, command ที่ล้มเหลว
หรือ shell semantics ที่ซับซ้อน

เส้นทางข้อมูลคือ:

```text
Cowrie authoritative CWD event
  -> sanitized JSON output
  -> collector / Redis Stream
  -> processor
  -> MongoDB cwd_session_state + cwd_events
  -> REST snapshot/history + MongoDB Change Stream/SSE
  -> Filesystem Activity UI
```

รายละเอียด patch และขั้นตอน staging อยู่ที่
[`../../integrations/cowrie/README.md`](../../integrations/cowrie/README.md)

## Source event contract

ก่อน execute ทุก command, Cowrie ส่ง directory ปัจจุบัน:

```json
{"eventid":"cowrie.command.input","session":"...","input":"pwd","cwd":"/home/operator","cwd_status":"confirmed"}
```

เมื่อใช้ `cd`, Cowrie ส่งผล transition หลังตรวจ virtual filesystem แล้ว:

```json
{"eventid":"cowrie.session.cwd","session":"...","cwd_before":"/home/operator","cwd_after":"/var/tmp","cwd_action":"changed","cwd_status":"confirmed"}
```

เมื่อ interactive shell พร้อมใช้งาน Cowrie จะส่ง `cwd_action: "entered"` หนึ่งครั้ง
เพื่อประกาศ CWD เริ่มต้นของ session ทันที จึงไม่ต้องรอให้ผู้โจมตีสั่ง `cd` ก่อน
dashboard จะระบุตำแหน่งได้

ถ้า `cd` ล้มเหลว ใช้ `cwd_action: "failed_change"` และ `cwd_after` เท่ากับ
directory เดิม Processor จะไม่เก็บ attacker-supplied target เป็น current state
หรือ `toPath`

## MongoDB model

`cwd_session_state` เก็บ current state หนึ่ง document ต่อ session:

- `_id` และ `sessionId`: Cowrie session ID
- `cwdState.path`, `status`, `observedAt`, `sourceEventId`: ค่าล่าสุดที่ยืนยันได้
- `stateSequence`, `stateSourceEventId`: compare-and-set ordering keys
- `lifecycle.status`, `startedAt`, `closedAt`: สถานะ live ของ Cowrie session
- `updatedAt`, `expires_at`: topology ordering และ TTL

Processor update state แบบ ordered compare-and-set ด้วย timestamp nanoseconds และ
source event ID เป็น tie-breaker ดังนั้น retry หรือ event เก่าที่มาถึงช้าจะไม่เขียนทับ
state ใหม่กว่า

เมื่อ Processor รับ `cowrie.session.closed` จะ mark state เป็น `closed` โดยไม่ลบ
history หรือ state ทิ้งทันที เพื่อให้ audit ย้อนหลังได้จนกว่า TTL จะหมดอายุ แต่ live
topology จะ query เฉพาะ state ที่ยัง active ดังนั้น callout ของ connection ที่ปิดแล้วจะ
หายจาก dashboard ผ่าน Change Stream/SSE โดยอัตโนมัติ และ late/retried CWD event จะไม่
revive session ที่ปิดไปแล้ว

state เก่าที่ไม่มี `lifecycle.status` จะไม่ถูกนับเป็น live โดยปริยาย เพื่อไม่แสดง
connection ที่ไม่อาจยืนยันสถานะได้เป็นศัตรูที่ยังเชื่อมต่ออยู่; authoritative CWD event
ถัดไปจะ enrich state เก่านั้นกลับเป็น `active` อย่างปลอดภัย

`cwd_events` เก็บเฉพาะ Cowrie-emitted transitions (`changed`, `entered`,
`failed_change`) เพื่อ audit history ไม่สร้าง transition จากการเดา command:

- `eventId` เป็น idempotency และ pagination tie-breaker
- `at` เป็น primary sort key
- `sequence` เก็บเป็น decimal string เพื่อไม่เสียความละเอียดของ BSON Int64 ใน JavaScript
- `fromPath`, `toPath`, `action`, `status` อธิบาย transition

## Dashboard behavior

- `GET /api/filesystem-topology` อ่าน snapshot ล่าสุดจาก `cwd_session_state` โดยจำกัด
  live payload ที่ 500 sessions และส่ง `truncated: true` แทนการตัดข้อมูลแบบเงียบ ๆ
- `GET /api/sessions/[sessionId]/cwd-history` ใช้ keyset pagination ที่ sort ด้วย
  `(at DESC, eventId DESC)` จึงไม่ข้าม event ที่ timestamp เท่ากัน
- `GET /api/filesystem-topology/stream` ส่ง snapshot และ update ผ่าน SSE; เมื่อมี
  CWD mutation หลายรายการในช่วงสั้น ๆ server จะ coalesce เป็น snapshot เดียวก่อน
  broadcast ให้ subscribers ใน Node process เดียวกัน
- UI แสดง topology graph ขนาดใหญ่และ source-IP callout ของ session ที่ยัง active;
  กราฟ prioritise เส้นทางล่าสุดเพื่อให้อ่านง่าย ขณะที่ Path inspector ค้นหาและแบ่งหน้า
  session ที่จุดนั้นได้
- snapshot เดียวกันมี `recentClosedSessions` ไม่เกิน 12 รายการ เรียงตาม `closedAt`
  เพื่อให้ short-lived SSH probe เปิด audit trail ได้หลังหายจาก live graph โดยไม่
  ทำให้ live callout ถูกปะปนกับ connection ที่สิ้นสุดแล้ว
- Session route navigator เรียง `cwd_events` จากเริ่มต้นไปเหตุการณ์ล่าสุด และให้
  operator ย้อน/เดินหน้าได้ทีละ verified transition หรือข้ามไป checkpoint ล่าสุด;
  ปุ่มจะไม่สร้าง route จาก command ที่ไม่มี CWD event
- เมื่อ MongoDB Change Stream ปิดหรือ error ฝั่ง server จะปิด SSE เพื่อให้ browser
  reconnect และรับ snapshot ใหม่ แทนการส่ง heartbeat จาก stream ที่ตายแล้ว
- เมื่อผู้ใช้เปลี่ยน session UI จะ abort history request เดิมและปฏิเสธ response ที่
  stale เพื่อไม่ให้ history ของ session ก่อนหน้าปะปน

## Compatibility and rollout

Processor ยังอ่าน draft `cwd_before` ของ `cowrie.command.input` และ legacy session
field ใน MongoDB ได้ แต่ production contract ใหม่ควรส่ง `cwd` พร้อม
`cwd_status: "confirmed"`

ก่อน rollout:

1. Apply Cowrie patch ใน clean staging checkout ที่ pinned revision
2. ตรวจ sanitized JSON ด้วย fixture ทั้ง command, successful `cd`, failed `cd`
3. Replay fixture ผ่าน collector และ processor
4. ตรวจ current state, transition history, same-timestamp pagination และ SSE reconnect
5. Deploy ผ่าน staged service procedure พร้อม rollback ที่มีอยู่ ห้าม apply patch ตรง
   ลง dirty live checkout

## Validation commands

```sh
(cd agents/collector-agent && go test ./...)
(cd agents/processor-agent && go test ./...)
(cd dashboard-v2 && npm test)
(cd dashboard-v2 && npm run lint)
(cd dashboard-v2 && npm run build)
pytest -q honeypot-analysis/tests/test_cowrie_output_privacy.py
git -C /path/to/clean/cowrie apply --check integrations/cowrie/patches/0001-authoritative-cwd-telemetry.patch
```
