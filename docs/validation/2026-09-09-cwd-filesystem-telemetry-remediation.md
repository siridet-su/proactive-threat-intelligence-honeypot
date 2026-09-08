---
title: CWD filesystem telemetry remediation
date: 2026-09-09
base_commit: 242478c
status: staging-ready
---

# CWD filesystem telemetry remediation

## Objective

แก้ finding ทั้ง 6 รายการจาก code review ของ real-time filesystem activity ให้
source contract, processor state, REST/SSE API และ UI ทำงานสอดคล้องกัน โดยไม่เดา
CWD จาก attacker command text

## Resolution summary

| Finding | Resolution | Evidence |
| --- | --- | --- |
| ไม่มี deployable CWD producer | เพิ่ม patch ที่ pin กับ Cowrie commit `575146bc6b24d70082527d66cd805d9bae0e0db4`, JSONL fixtures, collector mapping และ sanitizer contract test | `integrations/cowrie/`, collector/processor tests |
| Pending retry เขียน state เก่าทับ state ใหม่ | เปลี่ยน state write เป็น ordered compare-and-set ด้วย `stateSequence` และ `stateSourceEventId`; stale/duplicate observation ไม่ update state หรือ TTL | `cwdStateOrderFilter`, `updateLatestCwdState` |
| Pagination ข้าม timestamp tie | ใช้ compound keyset `(at DESC, eventId DESC)` ทั้ง query, sort, cursor และ index | `filesystem-data.ts`, Vitest cursor tests |
| History response ข้าม session | abort request เก่า, reset history/cursor และตรวจ generation/session ก่อน commit React state | `FilesystemActivity.tsx` |
| SSE ค้างหลัง change stream ตาย | server ปิด dependent SSE responses เมื่อ MongoDB stream error/close เพื่อให้ browser reconnect และโหลด fresh snapshot | `filesystem-server.ts`, SSE route |
| BSON Int64 sequence กลายเป็น `null` | schema v2 เก็บ Unix nanoseconds เป็น decimal string และ API ยังอ่าน legacy MongoDB `Long` แบบ lossless | processor writer, `asSequence` tests |

## Producer contract

Cowrie patch ส่ง `cwd` ที่อ่านจาก `protocol.cwd` ใน `cowrie.command.input` ก่อน
execution และส่ง `cowrie.session.cwd` หลัง successful/failed `cd` โดยระบุ
`cwd_before`, `cwd_after`, `cwd_action`, `cwd_status`

Patch ผ่าน `git apply --check` กับ clean pinned checkout และไฟล์ Python ที่ patch
แล้วผ่าน `py_compile` การ apply/deploy จริงต้องทำใน isolated staging checkout ตาม
[`integrations/cowrie/README.md`](../../integrations/cowrie/README.md); ไม่ได้แก้
dirty live Cowrie checkout บนเครื่องนี้

## Validation

| Check | Result |
| --- | --- |
| Collector `go test -race ./...` | Passed |
| Processor `go test -race ./...` | Passed |
| Dashboard `npm ci --dry-run` | Passed |
| Dashboard `npm test` | Passed, 5 tests |
| Dashboard `npm run lint` | Passed |
| Dashboard `npm run build` | Passed, Next.js 16.2.10 production build |
| CWD sanitizer regression | Passed, 2 cases |
| Cowrie patched-file `py_compile` | Passed |
| Cowrie clean-checkout `git apply --check` | Passed |
| `git diff --check` | Passed |

Full `test_cowrie_output_privacy.py` execution produced 82 passes and 2 failures.
Both failures are existing host-bound permission checks against
`/home/cowrie/users.txt`; the test temp directory owner differs from that live file
owner. The two newly added CWD sanitizer cases pass independently.

## Remaining rollout validation

Local validation does not replace a staging end-to-end run with Cowrie, Redis,
MongoDB replica-set change streams and a browser. Before production rollout:

1. Apply the pinned patch to the project's clean Cowrie staging build
2. Replay the included fixtures through collector and processor
3. Exercise concurrent/retried delivery against staging MongoDB
4. Verify same-millisecond history across page boundaries and force a change-stream disconnect
5. Capture service deployment and rollback receipts
