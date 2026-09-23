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

Current focus: **FSV-008 — Align search wording**

| Checkpoint | Scope | Status |
| --- | --- | --- |
| 0 | Baseline and characterization | `DONE` |
| 1 | Evidence semantics | `DONE` |
| 2 | Verified transition model/rendering | `DONE` |
| 3 | Workspace structure | `IN_PROGRESS` |
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

Status: **DONE — 2026-09-22**

Primary files:

- `src/components/filesystem/useAuditDirectory.ts`
- `tests/filesystem-audit-directory.test.ts`

Implementation:

- Canonical search URL propagation: Forwarded `from` and `to` into `buildAuditSessionsUrl` within `searchSessions` in `useAuditDirectory.ts` whenever `filterOptions` provides them (mirroring `fetchInitial`), ensuring initial queries, debounced searches, and pagination calls include canonical `from`/`to` parameters when active.
- Two explicit pagination modes:
  - No options argument (`loadMoreSearch()`): Continues using the exact stored canonical page-1 scope (`hideHome`, `targetPath`, `from`, `to`) parsed from `state.searchScopeKey`.
  - Options object supplied (`loadMoreSearch(options)`): Represents the complete current UI scope. Constructs a full canonical scope key via `createAuditScopeKey({ q: state.searchQuery, hideHome: Boolean(options.hideHome), targetPath: options.targetPath ?? null, from: options.from, to: options.to })` and compares it directly against `state.searchScopeKey`. If any property differs (including bounded ↔ unbounded transitions where `from`/`to` are `undefined`), it rejects the stale cursor, calls `clearSearch()`, and sends no cursor request.
- Out-of-order response safety: Existing AbortController signals and `searchGeneration` counter guards protect against out-of-order responses across different time ranges for the same query text. Stale responses from prior scopes or ranges are safely discarded before touching store state.
- Scope change cleanup: Any initial scope change via `fetchInitial` (including time range changes) aborts any in-flight search and resets search state.

Acceptance:

- URL ของทุก search page มี `from` และ `to` เมื่อ filter active (PASS)
- เปลี่ยน time range ระหว่าง request แล้ว response เก่าไม่เขียนทับผลใหม่ (PASS)
- load-more ต่อ cursor ภายใต้ scope เดิมเท่านั้น (PASS)
- load-more reject mismatched time scopes และ clear search state โดยไม่ส่ง old cursor (PASS)
- load-more with options object ถือเป็น complete current scope; bounded ↔ unbounded transition ถูก reject และ reset (PASS)
- load-more without arguments ใช้ exact stored canonical scope อย่างถูกต้อง (PASS)
- generation guard ป้องกัน out-of-order responses จากต่างช่วงเวลา (PASS)

Verification:

- `npx vitest run tests/filesystem-audit-directory.test.ts`: **PASSED** (37/37 tests)
- `npx vitest run tests/filesystem-phase0-baseline.test.ts tests/filesystem-coverage-expansion.test.ts tests/filesystem-audit-filter.test.ts tests/filesystem-audit-directory.test.ts tests/filesystem-ownership-boundaries.test.tsx tests/filesystem-audit-coverage.test.ts tests/fa013-component-evidence.test.tsx`: **PASSED** (106/106 tests)
- `npm test`: **PASSED**
- `npm run lint`: **PASSED**
- `npm run build -- --webpack`: **PASSED**
- Browser gate status: **`NOT RUN`** (Playwright managed Chromium runtime is not configured in this CLI environment; responsive visual verification remains explicitly documented as `NOT RUN` pending a configured browser gate)
- FSV-004 and later work confirmation: FSV-004 through FSV-013 remain completely untouched. Checkpoint 1 remains `IN_PROGRESS`.

#### `FSV-004` Define retained time and count semantics

Status: **DONE — 2026-09-23**

Primary files:

- `src/components/filesystem/useAuditDirectory.ts`
- `src/components/filesystem/AuditFilterControls.tsx`
- `src/components/filesystem/AuditSessionSelect.tsx`
- `src/components/filesystem/AuditNoticeRegion.tsx`
- `src/components/filesystem/FilesystemActivity.tsx`
- `src/components/filesystem/AuditFilesystemWorkspace.tsx`
- `tests/filesystem-retained-semantics.test.tsx`

Implementation:

- Retained time filter: strictly filters closed sessions using `lifecycle.closedAt` (inclusive bounds matching server `$gte`/`$lte`). Sessions with missing, null, empty, or invalid `closedAt` never pass an active time filter. No fallback to `startedAt` or `observedAt`.
- Active session separation: active ephemeral sessions do not have `closedAt` and never pass a retained Closed-at time filter. They contribute 0 to `retainedTotalCount`, `retainedMatchingCount`, and `retainedLoadedCount`. In `AuditSessionSelect`, active sessions remain in a separately labelled active group with `Not filtered by Closed at` / `Outside Closed-at filter` indicator.
- Lifecycle classification: uses authoritative lifecycle shape (`"lifecycle" in session && Boolean(session.lifecycle)`). Sessions with null/empty/invalid `closedAt` remain classified as retained and display `Closed time unavailable`, never misclassified as active.
  - Authoritative count model & evidence states: defined typed model `retainedLoadedCount`, `retainedMatchingCount`, `retainedTotalCount`, `activeVisibleCount`, and `retainedCountStatus` (`authoritative | loaded-only | loading | error | stale`).
  - Only `retainedMatchingCount !== null` is presented as exact matching evidence. Zero loaded is never inferred as zero matching.
  - When summary matches scope: `retainedTotalCount = summary.totalSessions`; `retainedMatchingCount` derives from `summary.matchingCount` (or derived from `totalSessions - homeOnlyCount` for home-only, or `totalSessions` for time-only/unbounded scopes).
  - Cross-field count validation & fail-closed invariants (FSV-004 Audit Correction):
    - `isValidSessionCount(n)` strictly validates that discrete session counts are non-negative safe integers (`typeof n === "number" && Number.isSafeInteger(n) && n >= 0`). Fractional numbers, non-finite values (NaN, ±Infinity), unsafe integers, and negative values immediately fail closed.
    - `isSummaryCountEvidenceValid(summary)` validates structural cross-field invariants: `totalSessions` and `homeOnlyCount` must be valid session counts; `0 <= summary.homeOnlyCount <= summary.totalSessions`; and if present, `summary.matchingCount` must be a valid session count and `0 <= summary.matchingCount <= summary.totalSessions`.
    - Pure scope-aware validation/derivation helper `evaluateScopeAwareSummaryCounts`:
      - Enforces cross-field and scope-specific invariants across `totalSessions`, `homeOnlyCount`, `matchingCount`, and the active filter scope (`hideHomeOnly` / `targetPathFilter`).
      - Scope 1 (Unfiltered / time-only): `effective matching = totalSessions`; if `matchingCount` is present, it must equal `totalSessions`.
      - Scope 2 (Hide-home only): `effective matching = totalSessions - homeOnlyCount`; if `matchingCount` is present, it must equal that derived value (`totalSessions - homeOnlyCount`).
      - Scope 3 (Target path only): `matchingCount` is required; `matchingCount <= totalSessions`; `effective matching = matchingCount`.
      - Scope 4 (Target path plus hide-home): `matchingCount` is required; `matchingCount <= totalSessions - homeOnlyCount`; `effective matching = matchingCount`.
      - For every scope: `effective matching >= retainedLoadedCount` and `totalSessions >= retainedLoadedCount`.
      - Contradiction handling: any scope contradiction invalidates the entire exact summary, failing closed to `retainedMatchingCount = null`, `retainedTotalCount = null`, `retainedCountStatus = "loaded-only"`.
      - Unified trust: `countEvaluation.isValid` controls both retained exact counts and public `homeOnlyCount` trust (falling back to locally loaded evidence if invalid).
      - Scope attribution is mandatory: exact summary counts are trusted only when a non-null `summaryScopeKey` is explicitly present and equals the canonical current scope key. Missing, stale, or mismatched attribution fails closed; there is no compatibility flag that disables coherence validation.
    - Fails closed on target-path contradictions (`matchingCount > totalSessions`), negative totals (`totalSessions=-1, matchingCount=5`), and invalid home summaries (`homeOnlyCount < 0` or `homeOnlyCount > totalSessions`), eliminating silent `Math.max(0, ...)` clamping that previously masked server contradictions.
    - Public `homeOnlyCount` fallback: `summary.homeOnlyCount` is used only if `countEvaluation.isValid` passes; if summary count evidence is malformed or scope-incoherent, it falls back to counting locally loaded sessions across `allSessions`, preventing corrupt server counts from contaminating filter badges.
  - Contradiction check: if server matching count or total count is smaller than loaded matching count (`matchingCount < retainedLoadedCount` or `totalSessions < retainedLoadedCount`), fails closed (`retainedMatchingCount = null`, `retainedTotalCount = null`, `retainedCountStatus = "loaded-only"`).
  - Complete directory fallback: when no summary payload exists and `isDirectoryComplete` proves the entire result set, `retainedMatchingCount = retainedLoadedCount`. Total is proven equal to loaded count only when unfiltered (`retainedTotalCount = retainedLoadedCount`); when path or home filters are active without summary, total-before-filter is unproven (`retainedTotalCount = null`). A present but missing-scope, stale, or mismatched summary never falls through to this promotion path.
  - Search count scope separation: search results maintain separate count scope. While search is active, global directory `retainedMatchingCount` is never used as search denominator; group is truthfully labelled `Retained search results (M loaded)`.
- UI presentation contracts:
  - `AuditFilterControls`: displays `aria-label="Retained audit result coverage"`, renders `N retained matching · M loaded` (or `N retained matching` when complete, or `M retained loaded · exact count loading/unavailable` when non-authoritative).
  - `AuditSessionSelect`: renamed group to "Retained sessions" (`role="group"` with label `Retained sessions (${filteredClosedSessions.length} loaded of ${retainedMatchingCount} matching)` when incomplete). `formatSessionMetadata` renders `Closed <time>` for closed sessions and `Last observed <time>` for active sessions, never `Invalid Date`, with explicit unavailable fallbacks.
  - `AuditNoticeRegion`: renders `0 retained sessions match filter` only when matching count is authoritatively 0; under loading/error states renders loaded evidence and `exact match count loading/unavailable`. "Switch to match" is enabled only when loaded closed matches exist, selecting only `filteredClosedSessions[0]`, never selecting active sessions.
  - `auditCanvasSubtitle`: uses `formatRetainedSubtitleCoverage` to truthfully distinguish loaded count from exact matching count under non-authoritative states.

Acceptance:

- “Yesterday” includes closed session closed yesterday and excludes closed session started yesterday with closedAt today (PASS)
- Active session observed yesterday does not pass retained time filter and contributes 0 to retained counts (PASS)
- UI separates `N matching` and `M loaded` when pagination is incomplete (PASS)
- Non-authoritative states (loading/error/stale/loaded-only) disclose loaded count and never claim exact match counts (PASS)
- Retained session with `closedAt: null` is classified as retained, never active (PASS)
- Search result counts do not display global retained matching count as denominator (PASS)
- "Switch to match" selects only loaded closed sessions and never active sessions (PASS)
- Complete directory fallback preserves null total when filters are active without summary (PASS)
- Contradictory server totals fail closed to loaded-only (PASS)
- Server summaries with `matchingCount > totalSessions`, `homeOnlyCount > totalSessions`, negative, fractional, or non-finite counts fail closed to loaded-only (PASS)
- Scope-specific contradiction rejection (PASS):
  - Hide-home-only contradiction fails closed (`total=10, homeOnly=2, matching=3` -> loaded-only) (PASS)
  - Valid hide-home-only agreement reports authoritative (`total=10, homeOnly=2, matching=8` -> matching=8, total=10) (PASS)
  - Combined hide-home and target-path contradiction fails closed (`total=10, homeOnly=8, matching=5` -> loaded-only) (PASS)
  - Valid combined hide-home and target-path reports authoritative (`total=10, homeOnly=8, matching=2` -> matching=2, total=10) (PASS)
  - Unfiltered/time-only contradiction fails closed (`total=10, matchingCount=3` -> loaded-only) (PASS)
  - Valid unfiltered redundancy reports authoritative (`total=10, matchingCount=10` -> matching=10, total=10) (PASS)
- Corrupted or scope-contradictory summary `homeOnlyCount` safely falls back to local loaded evidence without contaminating public badge (PASS)
- Exact summary evidence without an explicit matching `summaryScopeKey` fails closed and cannot use directory completion as an implicit promotion path (PASS)
- Legacy multi-page fixtures use separate target-path, unfiltered, and hide-home summaries with their own canonical scope keys instead of reusing one summary across scopes (PASS)
- Group renamed to "Retained sessions" and active group labelled as separate from Closed-at filter (PASS)
- Timestamp formatting distinguishes `Closed <time>` from `Last observed <time>` and handles missing/invalid values with explicit unavailable text (PASS)
- Filter summary, selector, notice region, and canvas subtitle use unified truthful semantics (PASS)

Verification:

- `npx vitest run tests/filesystem-retained-semantics.test.tsx`: **PASSED** (47/47 tests)
- `npx vitest run tests/filesystem-retained-semantics.test.tsx tests/filesystem-audit-directory.test.ts tests/filesystem-audit-filter.test.ts tests/combobox-popover.test.ts tests/filesystem-ownership-boundaries.test.tsx tests/fa013-component-evidence.test.tsx`: **PASSED** (173/173 tests)
- `npx vitest run tests/filesystem-*.test.ts*`: **PASSED** (410 tests passed, 14 skipped)
- `npm test`: **PASSED** (571 passed, 2 expected fail, 14 skipped)
- `npm run lint`: **PASSED** (0 errors, 0 warnings)
- `npm run build -- --webpack`: **PASSED** (production webpack build succeeded, 19/19 static pages generated)
- `git diff --check`: **PASSED** (clean diff formatting)
- Browser gate status: **`NOT RUN`** (Playwright managed Chromium runtime is not configured in this CLI environment; responsive visual verification remains explicitly documented as `NOT RUN` pending a configured browser gate)
- FSV-005 work confirmation: FSV-005 is complete. FSV-006 through FSV-013 remain completely untouched. Checkpoint 1 remains `IN_PROGRESS`.

#### `FSV-005` Correct failed-change visualization

Status: **DONE — 2026-09-23**

Primary files:

- `src/components/filesystem/useAuditReplay.ts`
- `src/components/filesystem/filesystemUtils.ts`
- `src/components/filesystem/TopologyCanvas.tsx`
- `src/components/filesystem/RouteEventList.tsx`
- `src/components/filesystem/ReplayTransport.tsx`
- `src/components/filesystem/CwdRouteHistory.tsx`

Implementation:

- failed event มี verified origin แต่ไม่มี verified target ใน loaded และ anchored replay
- ใช้ pure derivation path เดียวกันเพื่อ preserve event identity, hop number, timing และ verified visited paths โดยตัด legacy failed destination ออกจาก presentation state
- Canvas แยก replay context, verified target, layout focus, camera focus และ failure annotation ออกจากกัน
- Canvas วาง warning annotation ที่ `fromPath` หรือแสดง truthful canvas status เมื่อ origin ไม่อยู่ใน partial graph
- Copy ระบุว่า `Directory change failed while at …; attempted destination unavailable or unverified`
- ไม่สร้าง target node, target connector, target badge หรือ target-oriented label จาก failed destination
- Timeline, transport และ Evidence tab ใช้ verified origin และยังคงนับ/เลือก event ตาม contract เดิม

Acceptance:

- event ที่มี attacker-controlled legacy `toPath` ไม่ทำให้ target ปรากฏ (PASS)
- graph position ไม่กระโดดเมื่อเลือก failed hop (PASS)
- icon/text สื่อ failure โดยไม่พึ่งสีอย่างเดียว (PASS)

Correction audit follow-up:

- Canvas regression coverage uses the production selectors `[data-testid="active-hop-target-badge"]` and `[data-active-hop-connector="true"]`. Failed hops prove both selectors, `.pti-hop-energy`, and target-oriented accessible text/attributes are absent; a successful adjacent parent/child hop proves the badge and connector selectors are live.
- The camera deduplication ref stores the last processed/presented hop event ID. It is updated before failed-path, missing-target, drag-safeguard, and cleared-active-hop exits, so the transition contract is:

  | Last processed | Current hop | Auto-center result | Next stored event |
  | --- | --- | --- | --- |
  | `null` | successful `A` | eligible for verified destination `A` | `A` |
  | `A` | failed `B` | no centering | `B` |
  | `B` | successful `A` | eligible for verified destination `A` | `A` |
  | `A` | successful `A` | deduplicated | `A` |

- A successful event whose verified target node is absent is still recorded before the node guard, and failed events never request target auto-centering.

Verification:

- focused regression suite: **PASSED** (19/19 tests)
- semantic/replay gate: **PASSED** (110/110 tests)
- all filesystem tests: **PASSED** (429 tests passed, 14 skipped)
- `npm test`: **PASSED** (590 tests passed, 2 expected fail, 14 skipped)
- `npm run lint`: **PASSED** (0 errors, 0 warnings)
- `npm run build -- --webpack`: **PASSED** (production webpack build succeeded, 19/19 static pages generated)
- Browser gate status: **`NOT RUN`** (system Chromium is present at `/usr/bin/chromium`, but Playwright's configured webServer probe fails with `EPERM` when connecting to `127.0.0.1:3100`; no browser was installed and no responsive visual verification is claimed)

#### `FSV-006` Separate heuristic from evidence

Status: **DONE — 2026-09-23**

Primary files:

- `src/components/filesystem/filesystemUtils.ts`
- `src/components/filesystem/TopologyCanvas.tsx`
- `src/components/filesystem/FilesystemInspector.tsx`

Implementation:

- Replaced the boolean `isSensitiveDirectory(path)` presentation API with `classifyRuleBasedPathInterest(path)`.
- The classifier returns `RuleBasedPathInterest | null` with explicit `source: "path-rule"`, structured category, category label, matched root, rule description, and a path-only explanation that states the result is not evidence of observed file activity.
- Matching is case-sensitive and segment-boundary-safe; the classifier matches only exact roots or real descendants and never parses command text or creates topology nodes.
- Canvas and Inspector consume the same structured classifier. Canvas uses a warning-colored outline/icon with stable selector `[data-testid="rule-based-path-interest"]` and accessible rule text. Inspector renders an informational explanatory panel with the category, matched rule, matched root, and neutral path-only explanation.
- Removed the heuristic phrases `Sensitive target / Drop directory` and `(sensitive target)` from generated Canvas and Inspector text, titles, and accessibility output.

Rule/category matrix:

| Matched root | Category | Category label | Rule description |
| --- | --- | --- | --- |
| `/root` | `privileged-home` | Privileged account home | Privileged account home path rule |
| `/tmp` | `temporary-directory` | Temporary directory | Temporary directory path rule |
| `/var/tmp` | `temporary-directory` | Temporary directory | Temporary directory path rule |
| `/dev/shm` | `shared-memory` | Shared memory | Shared-memory path rule |
| `/etc` | `system-configuration` | System configuration | System configuration path rule |

Acceptance:

- `/tmp` and descendants expose only `Rule-based path of interest` with the temporary-directory rule context.
- `/tmpfile`, `/etcetera`, `/rooted`, `/dev/shmemory`, `/TMP`, and `/ETC` return no classification.
- Canvas exposes the category, matched rule, matched root, path-only wording, and not-evidence meaning through accessible text; ordinary paths expose no indicator.
- Inspector exposes the same structured facts after selecting the Directory tab; ordinary paths expose no annotation.
- Failed-change presentation remains separate: the verified origin may receive both its existing failed-origin annotation and a path-rule indicator, while the unverified destination remains absent and cannot receive a path-interest label.

Forbidden-claim regression coverage:

- Pure classifier, Canvas, and Inspector tests inspect text, `innerHTML`, `title`, `aria-label`, `aria-description`, and every other DOM attribute for the forbidden heuristic claims.
- The focused Canvas test proves the warning icon and rule text are present, while a normal node has no rule indicator and failed destinations remain unmaterialized.

Checkpoint 1 semantic state audit:

| State | FSV-006 result | Existing contract preserved |
| --- | --- | --- |
| Active live session | Path-rule annotation may appear on a materialized path | Active lifecycle and live freshness wording remain unchanged |
| Retained/closed audit session | Path-rule annotation may appear on a materialized path | Retained lifecycle and evidence timestamps remain unchanged |
| Partial topology/history | Classifier runs only on materialized authoritative paths | Partial coverage remains explicit; no completeness claim is added |
| Complete topology/history | Same path-rule semantics apply | Coverage wording remains owned by the coverage model |
| Failed change | Origin may show separate failure and path-rule annotations | Unverified destination remains absent and receives no label |
| Selected session outside filter | No classifier state changes session selection | Active/retained notice and exact/loaded counts remain unchanged |

Verification:

- `npx vitest run tests/filesystem-path-interest-semantics.test.tsx`: **PASSED** (12/12 tests)
- `npx vitest run tests/filesystem-path-interest-semantics.test.tsx tests/filesystem-failed-change-visualization.test.tsx tests/filesystem-layout.test.ts tests/fa013-component-evidence.test.tsx tests/filesystem-ownership-boundaries.test.tsx tests/filesystem-retained-semantics.test.tsx`: **PASSED** (142/142 tests)
- `npx vitest run tests/filesystem-*.test.ts*`: **PASSED** (441 tests passed, 14 skipped)
- `npm test`: **PASSED** (602 tests passed, 2 expected fail, 14 skipped)
- `npm run lint`: **PASSED** (0 errors, 0 warnings)
- `npm run build -- --webpack`: **PASSED** (production webpack build succeeded, 19/19 static pages generated)
- Browser gate status: **`NOT RUN`** (system Chromium is present at `/usr/bin/chromium`, but Playwright's configured webServer probe fails with `EPERM` when connecting to `127.0.0.1:3100`; no browser was installed and no responsive visual verification is claimed)

Checkpoint 1 status: **DONE**

Checkpoint 2 status: **IN_PROGRESS**; current focus is `FSV-007B`.

```bash
npm test
npm run lint
npm run build
git diff --check
```

---

### Checkpoint 2 — Model and render verified transitions

Goal: แยก filesystem structure ออกจาก event sequence ใน domain model ก่อนเปลี่ยนสีหรือ animation

#### `FSV-007A` Introduce a pure transition presentation model — **DONE (2026-09-23)**

Final model and pure mappers:

```ts
type CwdTransitionPresentationKind =
  | "directed"
  | "entry"
  | "failed-origin"
  | "unavailable";

interface VerifiedCwdTransition {
  eventId: string;
  absoluteHop: number | null;
  action: "entered" | "changed" | "failed_change";
  presentationKind: CwdTransitionPresentationKind;
  fromPath: string | null;
  toPath: string | null;
  markerPath: string | null;
  observedAt: string;
  status: SessionCwdHistoryEvent["status"];
}

deriveVerifiedCwdTransition(
  event: SessionCwdHistoryEvent,
  absoluteHop: number | null | undefined,
): VerifiedCwdTransition;

deriveVerifiedCwdTransitions(
  events: readonly SessionCwdHistoryEvent[],
  historyTotalItems: number | null | undefined,
): VerifiedCwdTransition[];
```

The anchored helper `deriveAnchoredVerifiedCwdTransition(event, historyTotalItems)` validates the
positive safe `event.hopNumber` against a valid retained total and delegates to the same single-event
mapper. Invalid, missing, or contradictory hop metadata produces `absoluteHop: null` without dropping
the event.

| Source event | Presentation result |
| --- | --- |
| `changed` with two verified absolute endpoints | `directed`; preserves exact `fromPath → toPath` direction, including non-parent transitions |
| `entered` with a verified target | `entry`; marks `toPath` only and never creates a parent or `fromPath → toPath` transition |
| `failed_change` with a verified origin | `failed-origin`; preserves `fromPath` as origin/marker and always exposes `toPath: null` |
| `failed_change` without a verified origin | `failed-origin`; preserves identity and metadata with no marker or endpoint |
| Missing or invalid endpoint for `changed`/`entered` | `unavailable`; preserves identity and metadata with no drawable endpoint |

Only non-empty paths beginning with `/` cross the verified path boundary. The mapper does not parse
commands, infer parents, normalize paths, rewrite case, or mutate source events. Failed legacy
destinations are omitted from the presentation object and therefore from serialized output.

Repeated A → B events remain separate entries by event ID. Reverse B → A events preserve their direction,
self transitions A → A retain their event identity, and non-parent `/home/a → /tmp` remains directed.
No transition is deduplicated by path, direction, or endpoint pair; hierarchy nodes remain owned by the
existing topology model.

Absolute-hop behavior uses the complete retained event sequence. For a chronological loaded window, the
mapper assigns `indexOffset + chronologicalIndex + 1`, where `indexOffset` comes from
`historyTotalItems`; failed events therefore retain their positions when hidden by `showFailedAttempts`.
Anchored events outside the loaded page use their valid authoritative `hopNumber`, remain separate from
`displayedTransitions`, and expose `absoluteHop: null` when that number is missing, unsafe, non-positive,
or contradictory with the retained total. `successfulHopNumber` is not used for this model.

Anchored hop validation matrix:

| `event.hopNumber` / retained total | `absoluteHop` |
| --- | ---: |
| undefined or absent | `null` |
| `0` | `null` |
| negative integer | `null` |
| fractional number | `null` |
| `NaN` | `null` |
| positive `Infinity` | `null` |
| unsafe integer (`Number.MAX_SAFE_INTEGER + 1`) | `null` |
| valid positive safe integer within retained total | preserved |
| valid hop equal to retained total | preserved |
| valid hop greater than retained total | `null` |
| valid hop with invalid or unavailable retained total | preserved; no contradictory upper bound is available |

`AuditReplayPresentation` and `UseAuditReplayReturn` now expose typed `displayedTransitions` and
`currentTransition`. The displayed array remains one-to-one with `displayedHistory`; the current loaded
transition is selected by the same displayed index, while an anchored current transition is derived by
the shared single-event mapper. Existing selection, filtering, navigation, timers, pacing, URL ownership,
unloaded gaps, and `ActiveHopRoute` behavior remain unchanged.

Canvas props and all visual renderer behavior are intentionally unchanged in FSV-007A. No transition
overlay, edge recoloring, arrow, animation, layout, camera, minimap, or legend work entered this phase;
FSV-007B will consume the model after its separate audit.

Verification:

- `npx vitest run tests/filesystem-transition-model.test.tsx`: **PASSED** (24/24 tests)
- `npx vitest run tests/filesystem-transition-model.test.tsx tests/filesystem-hooks.test.ts tests/filesystem-failed-change-visualization.test.tsx tests/filesystem-hop-resolution.test.ts tests/filesystem-replay-scrubber.test.ts tests/filesystem-ownership-boundaries.test.tsx`: **PASSED** (123/123 tests)
- `npx vitest run tests/filesystem-*.test.ts*`: **PASSED** (465 tests passed, 14 skipped)
- `npm test`: **PASSED** (626 tests passed, 2 expected failures, 14 skipped)
- `npm run lint`: **PASSED** (0 errors, 0 warnings)
- `npm run build -- --webpack`: **PASSED** (production webpack build succeeded, 19/19 static pages generated)
- Browser gate: **NOT RUN**; this phase exposes data only and makes no visual change.

#### `FSV-007B` Add a separate transition overlay — **DONE (2026-09-23)**

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

Implemented behavior:

- `TopologyCanvas` now renders filesystem parent/child structure only as thin neutral solid lines.
  Hierarchy paths have no arrowheads, replay state, visited-path recoloring, or transition identity.
- `TransitionOverlay` consumes only the `VerifiedCwdTransition` models exposed by `useAuditReplay`.
  The audit workspace passes `displayedTransitions` and `currentTransition` through the existing
  context boundary; live topology remains unchanged and has no synthesized transition sequence.
- Directed transitions render on a separate SVG layer with arrowheads and absolute hop labels.
  Non-parent transitions are drawn directly between their verified endpoints. Repeated routes,
  reverse routes, and self-transitions retain separate elements keyed by event identity; repeated
  routes use separate lanes rather than being collapsed into one hierarchy edge.
- Previous, current, and future events use distinct renderer states. The current event retains a
  static strong line/ring and label in reduced-motion mode; travel and pulse elements are omitted
  when reduced motion is requested.
- `entered` events render an entry marker at the verified destination. `failed_change` events render
  a warning marker at the verified origin and never render a destination edge. Unavailable endpoints
  remain in the accessible chronological sequence without a fabricated drawable endpoint.
- A current anchored event outside the loaded window is rendered separately without appending it to
  `displayedTransitions`. A dashed `Unloaded history gap` disclosure explicitly states that no
  intermediate transitions were inferred.
- The visible legend uses the same six encodings as the renderer: filesystem hierarchy, previous,
  current, future, entry, and failed-at-origin. A screen-reader-only ordered sequence exposes every
  displayed event in chronological order, including revisits and unavailable endpoints.

Verification:

- Test-first failure: the focused suite initially failed to resolve the not-yet-created
  `TransitionOverlay` module.
- `npx vitest run tests/filesystem-transition-overlay.test.tsx`: **PASSED** (8/8 tests)
- `npx vitest run tests/filesystem-transition-overlay.test.tsx tests/filesystem-transition-model.test.tsx tests/filesystem-failed-change-visualization.test.tsx tests/filesystem-hooks.test.ts tests/filesystem-replay-scrubber.test.ts tests/filesystem-layout.test.ts tests/filesystem-ownership-boundaries.test.tsx`: **PASSED** (159/159 tests)
- `npx vitest run tests/filesystem-*.test.ts*`: **PASSED** (473 tests passed, 14 skipped)
- `npm test`: **PASSED** (634 tests passed, 2 expected failures, 14 skipped)
- `npm run lint`: **PASSED** (0 errors, 0 warnings)
- `npm run build -- --webpack`: **PASSED** (production webpack build succeeded, 19/19 static pages generated)
- Browser gate: **NOT RUN**. `npm run test:browser` started the configured web server, but all six
  Playwright cases stopped before browser execution because the managed Chromium executable
  `chromium_headless_shell-1243` is not installed. No browser was downloaded and no responsive visual
  pass is claimed.

Checkpoint 2 remains **IN_PROGRESS**; current focus is `FSV-007C`.

#### `FSV-007C` Density and minimap behavior — **DONE (2026-09-23)**

- sparse graph uses fit-to-content
- minimap appears only above density threshold, when zoom differs from fit, or by user preference
- density aggregation never hides the current transition endpoints without an explicit aggregate indicator
- zoom/fit/locate remain direct controls; layout/density/grid/reset move under `View`

Implemented behavior:

- The existing responsive viewport owner now records the current fitted zoom even after manual
  interaction. Sparse topology continues to auto-fit while the user has not adjusted the camera,
  and `Fit topology in view` resets the camera to that authoritative content fit.
- Minimap visibility is derived by a pure policy with three preferences: `auto`, `show`, and `hide`.
  `auto` renders only when node/source totals exceed the detailed-density threshold or current zoom
  differs from fitted zoom by more than the numerical tolerance. `show` explicitly renders and
  reserves fit clearance; `hide` overrides density and zoom. An unavailable fit does not fabricate a
  zoom difference.
- Minimap visibility preference lives under `View → Appearance`. The minimap is no longer always
  mounted and no longer carries a blanket mobile `hidden` class when its policy says it is visible.
- `pointForGraph` accepts verified required paths. `TopologyCanvas` supplies both verified endpoints
  of the current directed transition, the entry destination, or the failed origin. Those paths and
  their ancestors remain rendered through clustered/aggregated density. The presentation-safe failed
  destination remains `null` and can never enter the required-path list.
- Endpoint coverage is evaluated against the loaded topology and rendered graph. If a verified path
  cannot be drawn, the canvas names either its nearest visible aggregate or the truthful unavailable
  loaded-topology state; it never silently redirects a transition.
- Aggregated nodes retain an explicit `+N` badge with aggregate path semantics. Density and layout
  actions, grid visibility, minimap policy, and reset remain under `View`; Zoom, Fit, and Locate remain
  direct controls. The summary bar is informational and no longer exposes separate density or
  auto-arrange actions. Its base legend now labels hierarchy, source connections, and active sources
  without duplicating or contradicting the verified-transition legend.

Minimap policy:

| Preference | Sparse at fitted zoom | Above density threshold | Zoom differs from fit |
| --- | --- | --- | --- |
| `auto` | hidden | visible | visible |
| `show` | visible | visible | visible |
| `hide` | hidden | hidden | hidden |

Verification:

- Test-first failure: the focused suite initially failed to resolve the new `topologyDensity` policy
  module; the mobile visibility assertion then reproduced the legacy `hidden sm:block` behavior.
- `npx vitest run tests/filesystem-density-minimap.test.tsx`: **PASSED** (6/6 tests)
- `npx vitest run tests/filesystem-density-minimap.test.tsx tests/filesystem-hooks.test.ts tests/filesystem-layout.test.ts tests/filesystem-replay-scrubber.test.ts tests/filesystem-transition-model.test.tsx tests/filesystem-transition-overlay.test.tsx tests/filesystem-failed-change-visualization.test.tsx tests/filesystem-ownership-boundaries.test.tsx`: **PASSED** (165/165 tests)
- `npx vitest run tests/filesystem-*.test.ts*`: **PASSED** (479 tests passed, 14 skipped)
- `npm test`: **PASSED** (640 tests passed, 2 expected failures, 14 skipped)
- `npm run lint`: **PASSED** (0 errors, 0 warnings)
- `npm run build -- --webpack`: **PASSED** (production webpack build succeeded, 19/19 static pages generated)
- Browser gate: **PASSED (2026-09-23)** with the installed system Chromium via
  `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium npm run test:browser` (7/7 cases).
  A dedicated real-browser fixture exercises `entered → changed → failed_change → revisit` at
  375×900 and 1440×900. It verifies chronological accessibility, exact directed routes, entry and
  failed-origin markers, absence of the unverified failed destination from the rendered DOM,
  revisit selection, no horizontal page overflow, and explicit minimap visibility on both widths.
  The existing Live → Audit → Back regression was corrected to assert the active source supplied by
  its fixture instead of the stale contradictory `No active honeypot sessions` copy.

FSV-007C implementation and the required desktop/mobile browser replay gate are complete.
Checkpoint 2 is **DONE**; Checkpoint 3 is **IN_PROGRESS** with `FSV-010A` as the current focus.

Checkpoint 2 gate:

```bash
npx vitest run tests/filesystem-hooks.test.ts \
  tests/filesystem-layout.test.ts \
  tests/filesystem-replay-scrubber.test.ts
npm test
npm run lint
npm run build
```

Browser gate: **PASSED** — replay entered/changed/failed/revisit fixtures at desktop and mobile run
against `/usr/bin/chromium` without installing a managed browser.

---

### Checkpoint 3 — Stabilize the workspace structure

Goal: ลด duplicated state/markup หลัง semantic และ transition behavior คงที่แล้ว

#### `FSV-010A` Single workspace across page/fullscreen — **DONE (2026-09-23)**

- render `AuditFilesystemWorkspace` เป็น stateful instance เดียว
- ใช้ shell/portal/layout variant สำหรับ fullscreen
- preserve canvas viewport, selected directory, selected hop, minimap state, rail width และ mobile tab
- focus trap, Escape และ focus restoration ต้องคงอยู่
- network/replay/response owners ต้องไม่เพิ่มเมื่อ toggle fullscreen

Implemented behavior:

- `FilesystemActivity` now contains exactly one `AuditFilesystemWorkspace` invocation. The stable
  workspace receives `isFullscreen` as a layout prop while the surrounding page/fullscreen header
  shell changes in place, so `TopologyCanvas`, timeline, and their local state are never replaced by
  a second branch instance.
- The fullscreen shell retains `role="dialog"`, modal semantics, initial focus, Tab trapping, Escape
  exit, body-scroll locking, and focus restoration to the page trigger. Page mode retains its audit
  toolbar and existing URL/session/filter ownership.
- A real-browser continuity case toggles fullscreen ten times and proves there is still one verified
  transition overlay, with zoom, explicit minimap preference, selected directory, selected hop,
  timeline rail width, and request count unchanged. The same mounted workspace also preserves the
  mobile Timeline panel while entering and exiting fullscreen.
- History/replay/response/stream hooks remain owned by `FilesystemActivity`; the refactor only
  consolidates presentation branches and adds no request, timer, SSE, or polling owner.

Verification:

- Test-first ownership assertion: **FAILED as expected** before production refactor because source
  contained two `<AuditFilesystemWorkspace>` invocations (expected 1, received 2).
- `npx vitest run tests/filesystem-ownership-boundaries.test.tsx tests/filesystem-layout.test.ts tests/filesystem-replay-scrubber.test.ts tests/filesystem-navigation-history.test.ts tests/fa013-component-evidence.test.tsx`:
  **PASSED** (119/119 tests).
- `npx vitest run tests/filesystem-*.test.ts*`: **PASSED** (480 passed, 14 skipped).
- `npm test`: **PASSED** (737 passed, 2 expected failures, 14 skipped).
- `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium npm run test:browser`:
  **PASSED** (8/8 real-browser tests).
- `npm run lint`: **PASSED** with 0 errors; 4 pre-existing warnings from merged `origin/main` remain
  outside filesystem scope.
- `npm run build -- --webpack`: **PASSED** (18/18 static pages generated).

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
