# Filesystem Activity — Semantic Visualization Implementation Plan

Status: **Ready for sequential implementation**

Prepared: 2026-09-22

Scope: `dashboard-v2` → `/filesystem-activity`

Related documents:

- [`FILESYSTEM_ACTIVITY_REDESIGN_PLAN.md`](FILESYSTEM_ACTIVITY_REDESIGN_PLAN.md) — UX/UI direction and component architecture
- [`FILESYSTEM_ACTIVITY_PHASE0_BASELINE.md`](FILESYSTEM_ACTIVITY_PHASE0_BASELINE.md) — behavior contracts that must not regress
- [`REALTIME_CWD_TRACKING.md`](REALTIME_CWD_TRACKING.md) — authoritative CWD data flow and evidence semantics
- [`../../docs/FILESYSTEM-ACTIVITY-AUDIT-FIXES.md`](../../docs/FILESYSTEM-ACTIVITY-AUDIT-FIXES.md) — completed historical audit/remediation record

## 1. Objective

ปรับ File System Activity ให้ visualization สื่อความหมายของหลักฐานอย่างถูกต้องก่อนปรับรูปลักษณ์ โดยทำงานเป็นชุดเล็กที่ review, test และ rollback ได้แยกจากกัน

ผลลัพธ์ที่ต้องได้:

1. Live และ retained audit state ไม่ถูกเรียกหรือแสดงปะปนกัน
2. UI ไม่อ้างว่า history/topology ครบ หาก client ยังโหลดข้อมูลไม่ครบ
3. เส้น filesystem hierarchy แยกออกจาก attacker transition อย่างชัดเจน
4. failed directory change ไม่สร้างหรือชี้ target ที่ telemetry ไม่ยืนยัน
5. search, time filter และ count ใช้ scope เดียวกันตั้งแต่ URL ถึง UI
6. heuristic path label ไม่ถูกนำเสนอเป็น file-drop evidence
7. workspace ใช้งานได้ด้วย keyboard, touch, mobile และ 200% zoom

เอกสารนี้เป็น execution plan ไม่ใช่หลักฐานว่า implementation เสร็จแล้ว แต่ละรายการจะเปลี่ยนสถานะเป็น `DONE` ได้ต่อเมื่อ acceptance criteria และ test gate ของรายการนั้นผ่าน

Current focus: **`FSV-003` — Propagate time scope through search pagination**

| Checkpoint | Scope | Status |
| --- | --- | --- |
| 0 | Baseline and characterization | `DONE` |
| 1 | Evidence semantics | `IN_PROGRESS` |
| 2 | Verified transition model/rendering | `BLOCKED_BY_1` |
| 3 | Workspace structure | `BLOCKED_BY_2` |
| 4 | Accessibility/responsive interaction | `BLOCKED_BY_3` |
| 5 | Final verification/documentation | `BLOCKED_BY_4` |

## 2. Non-negotiable data contracts

ข้อกำหนดต่อไปนี้ต้องคงอยู่ตลอดทุก phase:

- Cowrie-emitted CWD คือ authority; ห้าม parse command text เพื่อเดา directory
- path ที่นำมา render ต้องเป็น canonical absolute path ที่ผ่าน validation แล้ว
- `failed_change` ยืนยันได้เพียงว่า change ล้มเหลวขณะอยู่ที่ `fromPath`; destination ที่ไม่ถูกเก็บต้องไม่ถูกสร้างกลับจาก UI
- Live topology และ retained audit directory เป็นคนละ authority lane
- client-generated timestamp ไม่ใช่ evidence timestamp
- partial history ต้องไม่ถูกเรียกว่า complete history
- connection state และ telemetry freshness เป็นคนละมิติ
- URL contract เดิมของ `view`, `sessionId`, `hop`, `hideHome` และ `targetPath` ต้องไม่ regression
- stream, history, replay timer และ response polling ต้องมี owner อย่างละหนึ่งชุด
- response action authorization และ confirmation contract ไม่อยู่ใน scope ของการ redesign
- ไม่มีการเพิ่ม file-write, malware หรือ file-drop claim หากไม่มี authoritative telemetry รองรับ

## 3. Confirmed findings and target behavior

| ID | Priority | Current risk | Required behavior |
| --- | --- | --- | --- |
| `FSV-001` | P0 | Audit canvas ใช้ generic footer และอาจเรียก retained session ว่า active | Canvas รับ explicit `live`/`audit` context; audit แสดง retained lifecycle และ evidence time |
| `FSV-002` | P0 | Audit graph สร้างจาก history ที่โหลดอยู่ แต่อาจอ้างว่าเก็บทุก directory | แสดง loaded/total coverage และ `Partial topology` จนกว่าจะพิสูจน์ว่า complete |
| `FSV-003` | P0 | Session search/load-more ไม่ส่ง `from/to` แม้ UI มี time scope | ทุก search page ใช้ time scope เดียวกับ directory/summary และมี regression test ที่ระดับ URL |
| `FSV-004` | P0 | Active session ไม่มี `closedAt` แต่ผ่าน retained time filter และ count อาจอิงเฉพาะหน้าที่โหลด | Retained time filter อิง `closedAt`; active session แยกกลุ่ม; exact server count เป็น authoritative denominator |
| `FSV-005` | P0 | failed event ถูก label ว่าเป็น target ทั้งที่ค่าที่ render คือ origin | แสดง failure annotation ที่ origin และบอกว่า destination unavailable/unverified |
| `FSV-006` | P0 | `/tmp`, `/etc` และ path heuristic ถูกเรียกว่า Sensitive target / Drop directory | ใช้ `Rule-based path of interest`; file-drop wording ต้องมี file evidence เท่านั้น |
| `FSV-007` | P0 | hierarchy edge ถูก highlight จากชุด visited path จนอาจดูเหมือน transition จริง | Hierarchy และ verified transition เป็นคนละ model/renderer/legend |
| `FSV-008` | P1 | Search placeholder สื่อว่าค้นหา path ใดก็ได้ แต่ backend ค้น current/last CWD | แก้ label ให้ตรง scope หรือเพิ่ม visited-path query แบบ authoritative ก่อนใช้ wording เดิม |
| `FSV-009` | P1 | Minimap แสดงตลอดแม้ topology เล็ก | แสดงตาม density/zoom/user preference |
| `FSV-010` | P1 | Fullscreen เปลี่ยน component branch และอาจ reset local workspace state | ใช้ stateful workspace instance เดียวหรือ hoist state ที่ต้องคงอยู่ |
| `FSV-011` | P1 | Timeline splitter รองรับ mouse แต่ไม่รองรับ touch | ใช้ Pointer Events พร้อม capture และคง keyboard support |
| `FSV-012` | P1 | Tab semantics ยังไม่ครบ; controls/text บางส่วนเล็กเกินไป | WAI-ARIA tabs, roving focus, 40–44 px touch targets และ meaningful text อย่างน้อย 12 px |
| `FSV-013` | P1 | เวลาใน session list ไม่บอกว่า Started หรือ Closed และ timezone ไม่ชัด | ระบุ field/zone ชัดเจนและเปิดทาง copy ISO timestamp |

## 4. Execution rules

### 4.1 Sequential-only production changes

- ทำ production change ทีละ work item ตามลำดับในเอกสารนี้
- ห้ามเริ่ม item ถัดไปหาก targeted tests ของ item ปัจจุบันยังไม่ผ่าน และห้ามปิด checkpoint หาก full gate ยังไม่ผ่าน
- ห้ามรวม semantic correction, structural refactor และ visual polish ใน commit เดียว
- เพิ่ม characterization test ก่อนแก้ behavior ที่อาจทำให้ผู้ใช้ตีความหลักฐานผิด
- เมื่อแก้ test ให้ทดสอบ observable behavior ไม่ผูกกับ implementation detail โดยไม่จำเป็น
- อ่าน diff ทั้งหมดก่อน commit และ stage เฉพาะไฟล์ของ work item นั้น
- ไม่แก้หรือ overwrite unrelated user changes ใน working tree

### 4.2 Stop conditions

หยุด phase และ audit ก่อนดำเนินการต่อเมื่อพบกรณีใดกรณีหนึ่ง:

- ต้องเปลี่ยน backend evidence contract หรือ retention policy
- ไม่สามารถแยก confirmed telemetry ออกจาก client-derived presentation ได้
- count ระหว่าง directory, search, summary และ selected session ให้ผลขัดกัน
- history completeness ไม่มี metadata ที่พิสูจน์ได้
- เกิด duplicate SSE connection, fetch owner, replay timer หรือ response polling
- URL/back-forward/deep-hop behavior เปลี่ยน
- targeted regression test ต้องถูกลบหรือทำให้อ่อนลงเพื่อให้ implementation ผ่าน
- visual test environment ใช้งานไม่ได้ แต่ change นั้นพึ่งการยืนยันด้วย browser; ให้บันทึก `NOT RUN` แทนการถือว่าผ่าน

### 4.3 Commit convention

หนึ่ง work item ที่ผ่าน gate เท่ากับหนึ่ง focused commit ตัวอย่าง:

```text
test(filesystem): lock audit evidence semantics
fix(filesystem): distinguish retained audit context
fix(filesystem): expose partial topology coverage
fix(filesystem): align audit search time scope
fix(filesystem): correct failed-change presentation
feat(filesystem): render verified transition overlay
refactor(filesystem): preserve workspace across fullscreen
fix(filesystem): support pointer timeline resizing
```

## 5. Implementation sequence

### Checkpoint 0 — Protect the baseline

Goal: สร้าง safety net โดยยังไม่แก้ production behavior

#### `FSV-000A` Record preflight state

Status: **DONE — 2026-09-22**

Actions:

- บันทึก `HEAD`, `git status --short` และรายชื่อ user-modified files
- ตรวจว่า diff ปัจจุบันไม่มี whitespace error ด้วย `git diff --check`
- ห้าม clean/reset/checkout user changes
- ตรวจ availability ของ Playwright browser ก่อนรับงานที่ต้องมี screenshot evidence

Acceptance:

- มีรายการไฟล์ที่ห้าม overwrite ชัดเจน
- ระบุได้ว่า browser suite เป็น `PASS`, `FAIL` หรือ `NOT RUN` พร้อมเหตุผล

#### `FSV-000B` Add semantic characterization tests

Status: **DONE — 2026-09-22**

Preferred test scopes:

- `tests/filesystem-phase0-baseline.test.ts`
- `tests/filesystem-coverage-expansion.test.ts`
- `tests/filesystem-audit-filter.test.ts`
- `tests/filesystem-audit-directory.test.ts`
- `tests/filesystem-ownership-boundaries.test.tsx`
- component test ใหม่เฉพาะ footer/failed state หาก test เดิมไม่เหมาะ

Required cases:

1. closed retained session ไม่ถูกเรียกว่า active
2. audit view-materialization time ไม่ถูกแสดงเป็น evidence freshness
3. partial history มี partial coverage presentation
4. search และ load-more ส่ง `from/to`
5. retained time filtering ไม่รวม active session ผ่าน `closedAt = missing`
6. exact matching count ไม่ถูกแทนด้วยจำนวน records ที่ client โหลดแล้ว
7. failed change ไม่มี target node/target label
8. heuristic path ไม่ถูกเรียกว่า file drop

Gate:

```bash
cd dashboard-v2
npx vitest run tests/filesystem-phase0-baseline.test.ts \
  tests/filesystem-audit-filter.test.ts \
  tests/filesystem-audit-directory.test.ts
npx eslint tests
```

Expected checkpoint state: characterization tests ของ contracts ที่ถูกต้องต้องผ่านทั้งหมด ส่วน defect regression test ให้เพิ่มแบบ test-first ภายใน work item ที่เกี่ยวข้อง โดยยืนยันว่า test fail ด้วยเหตุผลที่คาดไว้ แล้วแก้ production code และทำให้ test ผ่านก่อน commit ห้าม commit intentionally failing test ไว้เป็น baseline

##### Phase 0 Baseline Evidence Record

- **Contract-to-test mapping**:
  - `a. failed_change contributes only verified fromPath and never unverified destination`:
    - `tests/filesystem-phase0-baseline.test.ts` (`materializes every verified historical branch and excludes failed destination typo nodes`)
    - `tests/filesystem-coverage-expansion.test.ts` (`derives active hop route accurately for transitions and failures`)
  - `b. closed/retained session lifecycle remains distinct from live topology state`:
    - `tests/filesystem-phase0-baseline.test.ts` (`preserves the retained lifecycle on the source model while characterizing the canvas adapter lane`)
    - `tests/filesystem-audit-directory.test.ts` (`strictly bounds effective closed sessions to the snapshot buffer (12 items) in live mode`, `verifies buildAuditSessionsQuery enforces closed lifecycle`)
  - `c. connection state and telemetry freshness remain independent dimensions`:
    - `tests/filesystem-phase0-baseline.test.ts` (`keeps transport connection and telemetry age as independent input dimensions`)
    - `tests/filesystem-freshness.test.ts`
  - `d. client-generated audit snapshot time is not authoritative evidence time`:
    - `tests/filesystem-phase0-baseline.test.ts` (`preserves authoritative evidence timestamps on session models and materialized nodes`)
    - `tests/filesystem-freshness.test.ts` (`derives snapshot receipt age from snapshotReceivedAtMs, never generatedAt`)
    - *Note*: The Phase 0 baseline deliberately does not freeze the audit snapshot `generatedAt` implementation or encode client view-materialization time as accepted presentation semantics; `FSV-001` remains unconstrained to rename, remove, or stop exposing that field. Telemetry freshness independence is proven via `tests/filesystem-freshness.test.ts`.
  - `e. partial history/completeness metadata remains explicit and is not silently converted to complete`:
    - `tests/filesystem-phase0-baseline.test.ts` (`keeps partial history completeness metadata explicit and prevents silent conversion to complete`)
    - `tests/filesystem-audit-filter.test.ts` (`rejects history payloads that omit completeness metadata`, `keeps an event's absolute hop number stable as older pages are loaded`)
    - `tests/filesystem-history-pagination.test.ts`
  - `f. URL/deep-link state ownership and replay/history owners remain single-owner`:
    - `tests/filesystem-ownership-boundaries.test.tsx` (`renders the production timeline composition with one required replay presentation model`, `keeps response capability request, abort, and reopen lifecycles on the controlled production tab`, `advances exactly one autoplay hop after presentational width and rerender changes`, `renders TopologyCanvas with authoritative freshness and creates no fallback freshness interval`)
    - `tests/filesystem-coverage-expansion.test.ts` (`round-trips URL search params without loss or corruption`, `safely falls back to live defaults on malformed or malicious query parameters`)
    - `tests/filesystem-audit-filter.test.ts` (`audit URL state synchronization and session expiration`)
  - `g. current authoritative path and ancestors are preserved without parsing command text`:
    - `tests/filesystem-phase0-baseline.test.ts` (`preserves authoritative current path and ancestors without parsing command text`, `materializes every verified historical branch and excludes failed destination typo nodes`)
- **Exact validation commands and results**:
  - `npx vitest run tests/filesystem-phase0-baseline.test.ts tests/filesystem-coverage-expansion.test.ts tests/filesystem-audit-filter.test.ts tests/filesystem-audit-directory.test.ts tests/filesystem-ownership-boundaries.test.tsx`:
    **PASSED** (5 test files, 79 tests passed, 0 failures)
  - `npm test`:
    **PASSED** (29 test files passed, 1 skipped; 500 tests passed, 2 expected fail, 14 skipped)
  - `npm run lint`:
    **PASSED** (ESLint exited 0 with zero warnings/errors)
  - `npm run build -- --webpack`:
    **PASSED** (Next.js production build compiled and generated static/dynamic routes successfully with webpack fallback)
- **Browser gate status**:
  - **`NOT RUN`**: Phase 0 is test/documentation-only and managed Chromium executable is unavailable in this environment; visual gate will be verified during later checkpoints when browser runtime is configured.
- **Known environment limitations**:
  - Default Turbopack build is blocked by environment local port bind refusal (`EPERM`/`EACCES`); Webpack fallback (`npm run build -- --webpack`) is the verified build path.
- **Production source confirmation**:
  - Zero files modified under `dashboard-v2/src/`. No production source code changed during Phase 0.

---

### Checkpoint 1 — Correct evidence semantics

ทำ `FSV-001` ถึง `FSV-006` ทีละรายการ ห้ามรวมกันเป็น bulk patch

#### `FSV-001` Explicit live/audit presentation context

Status: **DONE — 2026-09-22**

Primary files:

- `src/components/filesystem/TopologyCanvas.tsx`
- `src/components/filesystem/TopologySummaryBar.tsx`
- `src/components/filesystem/AuditFilesystemWorkspace.tsx`
- `src/components/filesystem/FilesystemActivity.tsx`
- `tests/fa013-component-evidence.test.tsx`
- `tests/filesystem-ownership-boundaries.test.tsx`

Implementation:

- Replaced optional `isAuditMode?: boolean` with required discriminated `presentationContext: TopologyPresentationContext` across `TopologyCanvas` and `TopologySummaryBar`.
- Exported pure helper `deriveTopologyPresentationContext(mode, selectedSession)` in `TopologyCanvas.tsx` strictly accepting only authoritative session types (`FilesystemTopologySession | FilesystemClosedSession | null | undefined`), eliminating duck-typed objects, lifecycle string inputs, and top-level timestamp fallbacks.
- Authoritative derivation uses narrow type guard `isFilesystemClosedSession` to identify retained sessions by their authoritative lifecycle object; sessions without retained lifecycle are classified as active.
- Made compact audit evidence summary visible at all supported breakpoints with stable accessible label `aria-label="Audit evidence timestamps"`, removing 2xl-only/hidden utilities (`hidden`, `2xl:inline`) on audit text and separator. Removed `truncate` to ensure audit evidence is not hidden, truncated, or clipped; enabled natural multi-line text wrapping at constrained widths via `whitespace-normal break-words min-w-0 max-w-full` without horizontal page overflow or ellipsis clipping.
- Truthful unavailable states: null, blank, or invalid authoritative timestamps display explicit `Observed unavailable` and `Closed unavailable` labels instead of "No timestamp"; active audit investigations show `Observed <timestamp|unavailable> · Active investigation` without closed fields; unselected audit views remain neutral.
- Restricted live-only properties (`snapshotGeneratedAt`, `freshnessState`, `staleThresholdMs`) to the `{ mode: "live" }` discriminant branch in `TopologySummaryBarProps`, strictly disallowing them in audit mode via TypeScript (`snapshotGeneratedAt?: never`).
- Live presentation context preserves existing active session count, live telemetry freshness, and snapshot wording.

Acceptance:

- ไม่มีคำว่า active สำหรับ selected closed session (PASS)
- ไม่มี freshness claim หรือ snapshot.generatedAt ใน audit mode (PASS)
- TypeScript บังคับให้ caller ระบุ context ผ่าน discriminated union (PASS)
- Audit evidence summary มองเห็นได้ในทุก breakpoint ไม่ถูกซ่อน (hidden) หรือถูกตัด (truncate/ellipsis/line-clamp) และ wrap ข้อความได้อย่างเป็นธรรมชาติที่ความกว้างจำกัด (PASS)
- Automated component tests ยืนยัน class contract และ semantic contracts ว่าไม่มี hidden, truncate, nowrap, overflow-hidden หรือ line-clamp utilities และรองรับ wrapping (PASS)
- Null และ invalid timestamp แสดง label unavailable อย่างชัดเจน (PASS)
- Derivation helper รับเฉพาะ authoritative session types (PASS)

Verification:

- `npx vitest run tests/fa013-component-evidence.test.tsx tests/filesystem-ownership-boundaries.test.tsx tests/filesystem-phase0-baseline.test.ts`: **PASSED** (14/14 tests)
- `npx vitest run tests/filesystem-*.test.ts*`: **PASSED** (15 passed, 1 skipped; 340 passed, 14 skipped)
- `npm test`: **PASSED** (29 passed, 1 skipped; 501 passed, 2 expected fail, 14 skipped)
- `npm run lint`: **PASSED** (0 errors, 0 warnings)
- `npm run build -- --webpack`: **PASSED** (production webpack build succeeded)
- Browser gate status: **`NOT RUN`** (Playwright managed Chromium runtime is not configured in this CLI environment; responsive visual verification remains explicitly documented as `NOT RUN` pending a configured browser gate)

Targeted gate:

```bash
npx vitest run tests/filesystem-phase0-baseline.test.ts \
  tests/filesystem-ownership-boundaries.test.tsx \
  tests/fa013-component-evidence.test.tsx
```

#### `FSV-002` Truthful history/topology coverage

Status: **DONE — 2026-09-22**

Primary files:

- `src/components/filesystem/filesystemUtils.ts`
- `src/components/filesystem/FilesystemActivity.tsx`
- `tests/filesystem-audit-coverage.test.ts`

Implementation:

- Authoritative summary-path union: Updated `buildAuditSnapshot` to register every canonical path in `session.auditSummary.visitedPaths` before loaded history with `observedAt: null`. It then registers current `cwdState.path` with its authoritative `observedAt` and loaded history `fromPath` and `toPath` (for non-failed moves) with `event.at`. Canonical ancestors for every path are materialized without parsing command text, and summary-only paths never invent timestamps or transitions.
- Truthful event coverage model: Created pure typed helper `deriveAuditCoverage` and formatter `formatAuditCoverageWording` in `filesystemUtils.ts` exposing `loadedEvents`, `totalEvents`, `unloadedEvents`, `eventCoverage` (`loading | partial | complete | error`), `pathCoverage` (`{ source: "auditSummary", status: "authoritative" }`), `historyStatus`, `isRefreshing`, and `wording`.
- Fail-closed rules: `totalEvents` uses the maximum trustworthy total from `historyTotalItems`, `session.auditSummary.eventCount`, and loaded history length (`getHistoryWindowMetrics`). `complete` is permitted only when `historyComplete === true` and `loadedEvents >= totalEvents`. When `historyComplete === true` but `loadedEvents < totalEvents`, it strictly fails closed to `partial`. Initial/reset states with un-loaded events do not claim complete.
- Refreshing and error boundary semantics:
  - Refreshing with partial data preserves exact N/M facts (`Loaded 15 of 40 retained events`) and states that retained event history is refreshing along with unloaded count (`25 earlier events remain unloaded`) without claiming complete.
  - Refreshing with complete data preserves `complete` status, states that all events remain loaded (`All 40 retained events remain loaded`), and notes that history is refreshing without claiming that earlier events are loading or remain unloaded.
  - Refreshing with zero loaded data and non-zero total truthfully states `Loaded 0 of 25 retained events across authoritative directory coverage. Retained event history is refreshing...`.
  - Error after complete data preserves already-loaded evidence (`All 30 retained events remain loaded across authoritative directory coverage. Latest history refresh failed.`) without falsely claiming remaining history is unavailable.
  - Error with partial data retains exact loaded facts and notes remaining history is unavailable.
  - Zero-event and singular boundaries: 0-event cases truthfully state `0 retained events recorded`, and singular 1-event complete cases use grammatical phrasing (`The retained event is loaded...`).
- Truthful user-facing wording: Removed unconditional "All historical directories touched by this session are preserved on the canvas." claim in `FilesystemActivity.tsx`. Subtitle now derives truthful wording distinguishing authoritative directory coverage from event history coverage. When a session is pinned outside active filters, filter messaging is retained and appended with coverage wording.
- Preserved existing behavior: Excluded `failed_change.toPath` from graph materialization, kept hop/session selection intact across pagination, added zero polling or timers, and left `FSV-001` presentation context and `FSV-003` scope untouched.

Acceptance:

- first page ของ multi-page history ไม่ถูกนำเสนอว่า complete (PASS)
- load-more แล้ว count/coverage อัปเดตโดยไม่ reset selected hop (PASS)
- ไม่มี path จาก failed destination ปะปนใน nodes (PASS)
- ข้อความ unconditional "All historical directories..." ถูกแทนที่ด้วย truthful coverage wording (PASS)
- แยก authoritative directory coverage ออกจาก partial/complete event history ชัดเจน (PASS)
- summary-only paths ปรากฏบน canvas โดยไม่มี timestamp หรือ transition ปลอม (PASS)
- refreshing complete data ไม่พูดว่า loading earlier events หรือ remain unloaded (PASS)
- error หลังโหลดครบแล้ว preserve evidence เดิมไว้ ไม่บอกว่า remaining history unavailable (PASS)
- zero-event และ singular count (1 event) ใช้ไวยากรณ์ที่ถูกต้องและสะท้อนความจริง (PASS)

Verification:

- `npx vitest run tests/filesystem-audit-coverage.test.ts`: **PASSED** (18/18 tests)
- `npx vitest run tests/filesystem-phase0-baseline.test.ts tests/filesystem-coverage-expansion.test.ts tests/filesystem-hooks.test.ts tests/filesystem-hop-resolution.test.ts tests/filesystem-audit-coverage.test.ts`: **PASSED** (105/105 tests)
- `npm test`: **PASSED** (30 passed, 1 skipped; 519 passed, 2 expected fail, 14 skipped)
- `npm run lint`: **PASSED** (0 errors, 0 warnings)
- `npm run build -- --webpack`: **PASSED** (production webpack build succeeded, 19/19 static pages generated)
- Browser gate status: **`NOT RUN`** (Playwright managed Chromium runtime is not configured in this CLI environment; responsive visual verification remains explicitly documented as `NOT RUN` pending a configured browser gate)
- FSV-003 and later work confirmation: FSV-003 through FSV-013 remain completely untouched.

#### `FSV-003` Propagate time scope through search pagination

Primary files:

- `src/components/filesystem/useAuditDirectory.ts`
- API/request helper ที่สร้าง audit-directory URL
- `tests/filesystem-audit-directory.test.ts`

Implementation:

- initial search, debounced search, retry และ load-more ส่ง canonical `from/to` ชุดเดียวกัน
- generation/abort guards เดิมต้องยังป้องกัน stale response
- cache/in-flight identity ต้องรวม time scope เพื่อไม่ reuse ผลต่างช่วงเวลา

Acceptance:

- URL ของทุก search page มี `from` และ `to` เมื่อ filter active
- เปลี่ยน time range ระหว่าง request แล้ว response เก่าไม่เขียนทับผลใหม่
- load-more ต่อ cursor ภายใต้ scope เดิมเท่านั้น

#### `FSV-004` Define retained time and count semantics

Primary files:

- `src/components/filesystem/filesystemUtils.ts`
- `src/components/filesystem/AuditFilterControls.tsx`
- `src/components/filesystem/AuditSessionSelect.tsx`

Implementation:

- Retained time filter ใช้ `lifecycle.closedAt` และระบุ label ว่า `Closed at`
- Active sessions ไม่เข้า retained-time denominator โดยอัตโนมัติ
- ถ้าจำเป็นต้องแสดง active selection ให้แยก badge/group และใช้ `Last observed at` อย่าง explicit
- ใช้ server `matchingCount` เป็น exact result count; แยก `loadedCount` ออกจาก `matchingCount`
- เวลาใน session option ต้องเขียนว่า `Started` หรือ `Closed`

Acceptance:

- “Yesterday” ไม่รวม active session เพียงเพราะไม่มี `closedAt`
- UI แยก `N matching` และ `M loaded` เมื่อ pagination ยังไม่ครบ
- filter summary, result list และ empty state ใช้นิยามเดียวกัน

#### `FSV-005` Correct failed-change visualization

Primary files:

- `src/components/filesystem/useAuditReplay.ts`
- `src/components/filesystem/TopologyCanvas.tsx`
- `src/components/filesystem/RouteEventList.tsx`
- `src/components/filesystem/CwdRouteHistory.tsx`

Implementation:

- failed event มี verified origin แต่ไม่มี verified target
- Canvas วาง warning annotation ที่ `fromPath`
- Copy ระบุว่า `Directory change failed while at …; attempted destination unavailable or unverified`
- ไม่สร้าง target node, target connector หรือ target-oriented label
- Timeline ยังคงนับ event และเลือก hop ได้ตาม contract เดิม

Acceptance:

- event ที่มี attacker-controlled legacy `toPath` ไม่ทำให้ target ปรากฏ
- graph position ไม่กระโดดเมื่อเลือก failed hop
- icon/text สื่อ failure โดยไม่พึ่งสีอย่างเดียว

#### `FSV-006` Separate heuristic from evidence

Primary files:

- `src/components/filesystem/filesystemUtils.ts`
- `src/components/filesystem/TopologyCanvas.tsx`
- `src/components/filesystem/FilesystemInspector.tsx`

Implementation:

- เปลี่ยน wording เป็น `Rule-based path of interest`
- เปิดเผย rule/category ใน tooltip หรือ inspector
- ใช้ warning outline/icon แทน evidence badge
- ห้ามใช้คำว่า `drop`, `malware`, `compromised` หรือ `sensitive target` จาก path rule เพียงอย่างเดียว

Acceptance:

- `/tmp` แสดงได้เพียง heuristic interest
- UI มี accessible explanation ว่า label มาจาก rule ไม่ใช่ observed file action

Checkpoint 1 full gate:

```bash
npm test
npm run lint
npm run build
git diff --check
```

Phase audit: ตรวจ wording และ state matrix ของ active, closed, partial, complete, failed และ selected-outside-filter ก่อนเริ่ม transition renderer

---

### Checkpoint 2 — Model and render verified transitions

Goal: แยก filesystem structure ออกจาก event sequence ใน domain model ก่อนเปลี่ยนสีหรือ animation

#### `FSV-007A` Introduce a pure transition presentation model

Suggested model:

```ts
type VerifiedCwdTransition = {
  eventId: string;
  absoluteHop: number;
  action: "entered" | "changed" | "failed_change";
  fromPath: string | null;
  toPath: string | null;
  observedAt: string;
  status: string;
};
```

Rules:

- `changed`: render directed transition only when both endpoints are verified
- `entered`: render entry marker; do not invent a parent transition
- `failed_change`: origin annotation only; `toPath` is null at presentation boundary
- repeated A → B and B → A events remain separate transitions
- event ID/hop number is identity; path is not identity
- hierarchy nodes remain unique by canonical path

Implementation order:

1. pure mapper and unit tests
2. replay hook exposes typed transitions/current transition
3. no Canvas visual change until mapper tests pass

#### `FSV-007B` Add a separate transition overlay

Primary files:

- `src/components/filesystem/TopologyCanvas.tsx`
- extracted graph/transition module if needed
- `src/components/filesystem/filesystemUtils.ts`

Visual grammar:

| Meaning | Encoding |
| --- | --- |
| Filesystem hierarchy | Thin neutral solid line, no arrow |
| Verified transition | Directed primary/amber line with arrow and hop number |
| Previous transition | Medium/dim line |
| Current transition | Strong line/ring plus text/icon |
| Future transition | Neutral/dim or hidden according to replay contract |
| Revisit/loop | Separate event identity or count; never deduplicated by path |
| Failed change | Warning at origin, no target edge |
| Unloaded gap | Dashed bracket/text; never inferred |

Acceptance:

- hierarchy edge is never recolored solely because both endpoint paths were visited
- non-parent transition such as `/home/a → /tmp` is drawn as the actual transition
- revisits remain visible/inspectable in chronological order
- legend matches renderer in every state
- reduced-motion removes travel/pulse without removing state information

#### `FSV-007C` Density and minimap behavior

- sparse graph uses fit-to-content
- minimap appears only above density threshold, when zoom differs from fit, or by user preference
- density aggregation never hides the current transition endpoints without an explicit aggregate indicator
- zoom/fit/locate remain direct controls; layout/density/grid/reset move under `View`

Checkpoint 2 gate:

```bash
npx vitest run tests/filesystem-hooks.test.ts \
  tests/filesystem-layout.test.ts \
  tests/filesystem-replay-scrubber.test.ts
npm test
npm run lint
npm run build
```

Browser gate: replay entered/changed/failed/revisit fixtures at desktop and mobile. If Chromium is unavailable, record `NOT RUN` and do not close Checkpoint 2 visual acceptance.

---

### Checkpoint 3 — Stabilize the workspace structure

Goal: ลด duplicated state/markup หลัง semantic และ transition behavior คงที่แล้ว

#### `FSV-010A` Single workspace across page/fullscreen

- render `AuditFilesystemWorkspace` เป็น stateful instance เดียว
- ใช้ shell/portal/layout variant สำหรับ fullscreen
- preserve canvas viewport, selected directory, selected hop, minimap state, rail width และ mobile tab
- focus trap, Escape และ focus restoration ต้องคงอยู่
- network/replay/response owners ต้องไม่เพิ่มเมื่อ toggle fullscreen

#### `FSV-008` Align search wording

เลือกหนึ่งแนวทางโดยไม่ผสม semantics:

1. เปลี่ยน copy เป็น `Search IP, session ID, or current/last CWD`; หรือ
2. เพิ่ม authoritative visited-path search ที่ audit projection และทดสอบ overflow/completeness ก่อนใช้คำว่า `path`

ค่าเริ่มต้นที่ปลอดภัยสำหรับ phase นี้คือแนวทางที่ 1 เพราะไม่ขยาย backend contract

#### `FSV-009` Simplify workspace controls

- primary: Zoom, Fit, Locate
- secondary menu: Arrange, Density, Grid, Reset
- status/coverage ไม่อยู่ใน toolbar customization group
- toolbar ต้องไม่เกิด orphan controls ที่ 1280 px, 768 px และ 200% zoom

Checkpoint 3 gate:

- fullscreen toggle 10 รอบไม่ reset local state และไม่เพิ่ม timer/request owner
- back/forward/deep link ยังรักษา session/hop/filter
- page และ fullscreen ใช้ wording/legend/state เดียวกัน

---

### Checkpoint 4 — Accessibility and responsive interaction

#### `FSV-011` Pointer-capable splitter

- เปลี่ยนจาก mouse events เป็น Pointer Events
- ใช้ pointer capture ระหว่าง drag
- รองรับ mouse, touch และ pen
- คง Arrow keys, Home/End และ accessible value text
- drag cancellation/unmount ต้อง cleanup listeners เสมอ

#### `FSV-012A` Complete tab semantics

- `role="tablist"`, `role="tab"`, `role="tabpanel"`
- `aria-selected`, `aria-controls`, matching IDs
- roving `tabIndex`
- Arrow Left/Right หรือ Up/Down ตาม orientation, Home, End
- Map/Timeline/Details บน mobile ใช้ pattern เดียวกัน
- inactive panel policy ต้องชัดเจนว่า hidden หรือ unmounted และต้องไม่สร้าง duplicate owner

#### `FSV-012B` Readability and touch targets

- meaningful labels อย่างน้อย 12 px
- interactive target 40–44 px บนอุปกรณ์ touch
- icon-only control มี accessible name และ keyboard tooltip
- ตรวจ contrast ใน light/dark
- 200% zoom ไม่มี horizontal page scroll หรือ control overlap

#### `FSV-013` Forensic time presentation

- label เวลาเป็น `Observed`, `Started` หรือ `Closed`
- แสดง timezone (`UTC` หรือ local zone) อย่าง explicit
- detail view มี copy ISO timestamp
- relative time เป็น secondary และไม่แทน absolute evidence time

Checkpoint 4 gate:

- keyboard-only walkthrough ครบทุก workflow หลัก
- touch drag splitter ทำงาน
- screen-reader relationships ของ tabs/panels ถูกต้อง
- reduced-motion ไม่มี continuous animation แต่ current state ยังชัดเจน

---

### Checkpoint 5 — Final verification and documentation

#### Functional matrix

- Live → Audit → Back → Live → Forward → Audit
- direct retained-session URL และ deep hop ที่อยู่นอก history page แรก
- search + time filter + load more + reset
- selected session outside current filter
- replay first/previous/play/next/last และ failed hop
- partial history → load more → complete history
- fullscreen enter/exit ระหว่าง replay
- fresh, stale, disconnected และ retained snapshot states

#### Visual matrix

| Dimension | Values |
| --- | --- |
| Viewport | 1920×1080, 1440×900, 1280×800, 768×1024, 390×844 |
| Theme | Light, dark |
| Zoom | 100%, 200% |
| Graph | Sparse, medium, aggregated/dense |
| History | Empty, one event, partial, complete, failed, revisit |
| Transport | Connected/fresh, connected/stale, disconnected/retained |
| Session | Active live, closed retained, expired/not found, pinned outside filter |

#### Automated gates

Run from `dashboard-v2`:

```bash
npm test
npm run test:browser
npm run lint
npm run build
```

Run integration suites when the isolated test targets are available:

```bash
npm run test:filesystem-history-integration
npm run test:filesystem-audit-integration
```

Repository gate:

```bash
git diff --check
git status --short
```

Final report must record:

- commit chain by work item
- files changed per checkpoint
- exact test commands and results
- browser/manual states verified
- every `NOT RUN` item and reason
- remaining known limitations
- confirmation that unrelated user changes were preserved

## 6. File ownership map for implementation

| Concern | Primary source files | Primary regression suites |
| --- | --- | --- |
| Page/mode/workspace orchestration | `FilesystemActivity.tsx`, `AuditFilesystemWorkspace.tsx` | navigation, ownership and browser specs |
| Audit directory/search/time scope | `useAuditDirectory.ts`, audit APIs/helpers | `filesystem-audit-directory.test.ts`, `filesystem-audit-filter.test.ts` |
| Audit snapshot/coverage/counts | `filesystemUtils.ts` | phase-0, coverage and filter tests |
| Replay/transition model | `useAuditReplay.ts`, `useSessionCwdHistory.ts` | hooks, replay scrubber, hop-resolution tests |
| Graph/viewport/overlay/minimap | `TopologyCanvas.tsx` and extracted pure graph modules | layout, component evidence and browser specs |
| Footer/status semantics | `TopologySummaryBar.tsx`, page header/status components | phase-0 and ownership tests |
| Timeline/events/tabs | `CwdRouteHistory.tsx`, `RouteEventList.tsx`, `ReplayTransport.tsx` | replay scrubber/component tests |
| Path heuristic presentation | `filesystemUtils.ts`, `FilesystemInspector.tsx`, `TopologyCanvas.tsx` | semantic component tests |
| Splitter/accessibility | `TimelineSplitter.tsx`, `useTimelineDrag.ts`, tab components | focused interaction tests and browser spec |

Large files such as `FilesystemActivity.tsx`, `TopologyCanvas.tsx` และ `filesystemUtils.ts` ควรถูกแยกเฉพาะเมื่อ behavior ของ phase นั้นมี test ครอบคลุมแล้ว ห้ามทำ utility split พร้อม semantic change ใน commit เดียว

## 7. Current readiness and known constraints

พร้อมเริ่มที่ `Checkpoint 0` โดยมีข้อควรระวังดังนี้:

- baseline quiet-state work ถูก validate และ commit บน `main` ที่ `15806b2` (`feat(filesystem): clarify quiet live topology state`)
- implementation branch คือ `feat/filesystem-visualization-semantics` ซึ่งสร้างจาก clean `main` หลัง commit ดังกล่าว
- work agent ต้องเริ่มจาก clean working tree และห้ามย้อนแก้ baseline commit โดยไม่มี audit finding ที่เจาะจง
- full Vitest suite ณ วันที่จัดทำเอกสารผ่าน 29 test files โดยมี 497 tests passed, 2 expected failures และ 14 skipped
- `git diff --check` ผ่าน
- targeted component/ownership tests ผ่าน 2 files / 7 tests และ ESLint ของ quiet-state files ผ่าน
- production build ผ่านด้วย webpack fallback (`npm run build -- --webpack`); default Turbopack build ถูก environment ปฏิเสธการ bind local port และต้องบันทึกเป็น environment-blocked ไม่ใช่ pass
- Playwright visual run ยังไม่พร้อมรับรอง เพราะ managed Chromium executable ไม่ได้ติดตั้งใน environment ปัจจุบัน; ห้ามถือ browser gate ว่าผ่านจนกว่าจะติดตั้งหรือกำหนด executable ที่ใช้งานได้และรัน suite สำเร็จ
- ก่อนแก้ Next.js code ต้องอ่าน relevant documentation ใต้ `node_modules/next/dist/docs/` ตาม repository `AGENTS.md`

## 8. Definition of done

งานทั้งหมดถือว่าเสร็จเมื่อ:

- P0 findings `FSV-001` ถึง `FSV-007` มี automated regression coverage และผ่านทุก gate
- closed retained session ไม่ถูกเรียกว่า active ในทุก viewport/shell
- partial audit graph มี coverage disclosure ที่เห็นและอ่านได้ด้วย assistive technology
- hierarchy และ transition แยกกันทั้ง data model, rendering และ legend
- failed change ไม่มี destination claim ที่ไม่ได้รับการยืนยัน
- time-filtered search/pagination/count ใช้ scope เดียวกัน
- heuristic paths ไม่ถูกนำเสนอเป็น observed file drop
- fullscreen ไม่ reset state หรือเพิ่ม lifecycle owner
- keyboard, pointer/touch, reduced-motion, light/dark และ 200% zoom ผ่าน verification matrix
- unit/component, lint, build และ browser suite ผ่าน หรือมีรายการ `NOT RUN` ที่ยังทำให้ checkpoint นั้นไม่ถูกปิด
- final implementation report เชื่อมทุก requirement กับ commit และ test evidence ได้
