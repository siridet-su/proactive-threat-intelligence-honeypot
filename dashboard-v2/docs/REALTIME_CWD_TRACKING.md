# Real-time Attacker Directory Tracking (CWD)

> **Current-state addendum — 2026-09-25:** The Filesystem Activity Response tab
> and Dashboard session-termination control path described in older sections
> are retired. The current forensic sidebar has Route Replay and Evidence only.
> Pi agent and deployment status are documented in
> [`docs/RESPONSE-CONTROL-PLANE.md`](../../docs/RESPONSE-CONTROL-PLANE.md).
> Historical polling and action-record details below are retained as past
> implementation evidence, not as current behavior.

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
  live payload ที่ 500 sessions และส่ง `truncated: true` แทนการตัดข้อมูลแบบเงียบ ๆ;
  แต่ละ live/retained session มี `auditSummary.visitedPaths`, `homeOnly` และ
  `eventCount` ที่ server aggregate จาก `cwd_events` ตลอดช่วง retention แล้วรวมกับ
  CWD ล่าสุด เพื่อให้ Audit filter ไม่ขึ้นกับ topology ที่กำลัง render หรือ history
  page ที่ browser โหลดไว้
- `GET /api/filesystem-topology/audit-sessions` ให้บริการ searchable & keyset-paginated
  directory สำหรับ session ที่ปิดแล้วทั้งหมด รองรับ `q` / `search`, `targetPath`,
  `hideHome`, `cursor` และ `limit` โดยอิง compound index `{ "lifecycle.status": 1, "lifecycle.closedAt": -1, "sessionId": -1 }`
  ทำให้ค้นหาและ paginate ผ่าน archive ได้อย่างรวดเร็วโดยไม่กระทบ live change stream
- `GET /api/sessions/[sessionId]/cwd-history` ใช้ keyset pagination ที่ sort ด้วย
  `(at DESC, eventId DESC)` จึงไม่ข้าม event ที่ timestamp เท่ากัน และส่ง
  `totalItems`, `totalSuccessfulItems`, `complete` เพื่อให้ Replay ระบุชัดว่าโหลด
  retained history ครบหรือยัง พร้อมรักษาหมายเลข hop เดิมเมื่อโหลด page เก่าขึ้นมา
- `GET /api/filesystem-topology/stream` ส่ง snapshot และ update ผ่าน SSE; เมื่อมี
  CWD mutation หลายรายการในช่วงสั้น ๆ server จะ coalesce เป็น snapshot เดียวก่อน
  broadcast ให้ subscribers ใน Node process เดียวกัน
- UI แสดง topology graph ขนาดใหญ่และ source-IP callout ของ session ที่ยัง active;
  กราฟ prioritise เส้นทางล่าสุดเพื่อให้อ่านง่าย ขณะที่ Path inspector ค้นหาและแบ่งหน้า
  session ที่จุดนั้นได้
- snapshot เดียวกันแยก live topology ออกจาก closed directory อย่างสมบูรณ์ โดยเก็บเพียง
  immediate transition buffer ไม่เกิน 12 รายการ (`RECENT_CLOSED_BUFFER_LIMIT = 12`)
  เรียงตาม `closedAt` และใช้ in-memory cache สำหรับ closed session audit paths เพื่อลด
  query & aggregation overhead ลง ~95%; หาก operator เลือกหรือเปิด link ของ session
  เก่าที่อยู่นอก 12 รายการนี้ UI จะ query จาก `/api/filesystem-topology/audit-sessions`
  มาผสานเข้ากับ selection และ replay canvas โดยอัตโนมัติ โดยไม่เกิด false-positive expiration
- Session route navigator เรียง `cwd_events` จากเริ่มต้นไปเหตุการณ์ล่าสุด และให้
  operator ย้อน/เดินหน้าได้ทีละ verified transition หรือข้ามไป checkpoint ล่าสุด;
  ปุ่มจะไม่สร้าง route จาก command ที่ไม่มี CWD event
- เมื่อ MongoDB Change Stream ปิดหรือ error ฝั่ง server จะปิด SSE เพื่อให้ browser
  reconnect และรับ snapshot ใหม่ แทนการส่ง heartbeat จาก stream ที่ตายแล้ว
- เมื่อผู้ใช้เปลี่ยน session UI จะ abort history request เดิมและปฏิเสธ response ที่
  stale เพื่อไม่ให้ history ของ session ก่อนหน้าปะปน
- Route Replay แสดงสถานะ loading/empty/error เฉพาะในแท็บของตนเอง; แท็บ Command
  data และ Response อิง selected session/lifecycle โดยตรง จึงยังตรวจ capability และ
  disconnect live session ได้แม้ไม่มี CWD transition หรือ history endpoint ล้มเหลว
- Multi-session IP cluster interaction: แหล่งที่มา (IP) เดียวกันที่มีหลาย active session พร้อมกัน
  จะถูกรวมเป็น Cluster เดียวกันใน Canvas และ Sidebar (`SessionSourceList`) โดย:
  - Callout และ Inspector เปิดเผยทุก session ที่กำลังเชื่อมต่อและ path ทั้งหมดที่ IP นั้นกำลังแตะต้อง (`targetPaths`)
    โดยไม่ชี้นำหรือบิดเบือนว่า path ล่าสุดคือทางเดียวที่มีการเชื่อมต่ออยู่
  - Leader lines บน Canvas วาดเส้นเชื่อมไปยังทุก active directory ใน cluster โดยเส้นของ selected session เป็น solid primary
    และเส้นของ sibling sessions ใน IP เดียวกันเป็น dashed primary stroke
  - Callout card และ Sidebar รองรับการ expand/collapse แบบ accessible พร้อม keyboard navigation (Arrow Up/Down, Enter, Space, Escape)
    และ Inspector Session tab แสดงรายการ sibling active sessions เพื่อให้สลับดูหรือเปิด Forensics & Replay ของแต่ละ session ได้โดยตรง deterministic
- Two-dimensional world bounds fit: การคำนวณ Fit camera บน Canvas ครอบคลุมทั้งแกน X และ Y (`calculateWorldBounds` และ `calculateTwoDimensionalFit`)
  โดยรองรับพิกัด manual drag ที่อยู่นอกกรอบ `0..100` (%) โดยไม่ clamp, คำนวณขนาดจริงของ element ที่ render (node card และ callout card ที่ expand),
  จัดการ minimap clearance ในมุมขวาล่างเมื่อเปิด Overview minimap บนหน้าจอ >= sm, และปรับ scale/pan อย่างสมดุลทั้งใน compact view (~380px) และ fullscreen view
- Truthful count semantics: แยกนิยามและสัญญาการนับจำนวนอย่างเป็นเอกภาพทั่วทั้งระบบระหว่าง unique sources, active sessions, exact-path sessions, และ descendant-branch sessions
  โดยไม่เกิดความขัดแย้งระหว่าง Badge กับรายการที่ render:
  - `exactCount`: เซสชันที่มี CWD ตรงกับ node path โดยตรง (`session.cwdState.path === node.path`)
  - `descendantCount`: เซสชันที่มี CWD อยู่ใน subdirectories ใต้ node path นั้น (`session.cwdState.path !== node.path && node.sessionIds.includes(session.sessionId)`)
  - `branchCount`: ผลรวมเซสชันทั้งหมดใน subtree กิ่งนี้ (`exactCount + descendantCount`)
  - `uniqueSourcesCount`: จำนวน IP ต้นทางที่ไม่ซ้ำกันใน subtree กิ่งนี้
  - Badge บน Canvas Node: หากมีทั้งสองส่วนจะแสดง `${exactCount} (${branchCount})`, หากมีเฉพาะ exact จะแสดง `${exactCount}`, หากมีเฉพาะ descendant จะแสดง `↳${branchCount}`
    พร้อม tooltip อธิบายสัดส่วนชัดเจน
  - Canvas Footer: แสดง `${effectiveSessions.length} active sessions` และ `${totalLiveSources} unique sources` อย่างตรงไปตรงมา
  - Directory Inspector: Badge บนแท็บ Directory แสดงยอด branchรวมตรงกับรายการเริ่มต้น ("All in branch"), พร้อม Summary Metrics Cards 3 กล่อง (`Exact path`, `In subdirs`, `Unique sources`),
    และ 3 โหมดรายการย่อย (`All in branch`, `Exact path`, `By source`) พร้อมป้ายระบุ `Exact` / `Subdir` บนแถวของแต่ละเซสชัน
- Bounded response-action polling and event-stream propagation:
  - กำจัด network overhead ต่อ Raspberry Pi: เมื่อไคลเอนต์ query ตรวจสถานะ pending action (`?actionId=...`) เซิร์ฟเวอร์จะไม่ ping HTTP health check ไปยัง Pi ซ้ำซ้อน แต่จะใช้ in-memory TTL cache (10 วินาที) ของ `responseControlHealthy`
  - ลดการอ่าน MongoDB เหลือ 1 รอบ (`getTerminateActionWithState`): ผสานการอ่าน `session_response_actions` เข้ากับการอ่าน `cwd_session_state` ครั้งเดียวเพื่อตรวจ closure verification และคำนวณ `active` status พร้อมกัน หาก action ถูก verified ไปแล้วจะไม่แตะต้อง collection session เลย (0 duplicate reads)
  - Bounded backoff polling: ไคลเอนต์ (`CwdRouteHistory`) เปลี่ยนจาก fixed 1s interval เป็น exponential bounded backoff (เริ่ม 1,000ms -> 1,500ms -> 2,250ms -> สูงสุด 3,500ms, bounded duration 24s)
  - Event-stream acceleration: ไคลเอนต์จับสัญญาณจาก SSE topology stream โดยตรงผ่าน `sessionIsLive` — เมื่อ SSE snapshot ส่งสัญญาณว่าเซสชันปิดตัวลง (`sessionIsLive` เปลี่ยนเป็น false) ระบบจะ trigger status check ทันที (delay 100ms) โดยไม่ต้องรอรอบ timer
- Freshness and degraded-state semantics (FS-012):
  - แยก transport stream status ออกจาก data freshness status อย่างชัดเจน:
    - Transport stream: ตรวจสอบสถานะการเชื่อมต่อของ SSE socket (`Live stream` / `Connecting` / `Reconnecting`)
    - Data freshness: จำแนกความสดใหม่ของข้อมูล snapshot เป็น 4 ระดับ (`fresh`, `stale`, `degraded`, `offline`) โดยคำนวณจาก `lastUpdateAgeMs` เทียบกับ `DEFAULT_STALE_THRESHOLD_MS` (30 วินาที)
  - Retained snapshot guarantee: เมื่อเกิดปัญหาเครือข่ายหรือ SSE reconnecting ระบบจะไม่ลบหรือซ่อน canvas snapshot ล่าสุดที่ถูกต้องออกไป (`regionStatus === "error" && !snapshot`) ช่วยให้ operator ยังคงมองเห็น topology และตำแหน่งเซสชันก่อนหน้าได้อย่างต่อเนื่อง
  - Degraded connection banner: เมื่อการเชื่อมต่อขาดหายแต่ยังมี snapshot ในหน่วยความจำ ระบบจะแสดงแถบเตือนแบบลอยด้านบน canvas ("Degraded connection: Showing retained snapshot from Xs ago") พร้อมปุ่ม "Refresh snapshot" และ "Reconnect now" เพื่อกู้คืนสถานะการเชื่อมต่อทันที
  - Header indicators & live tickers: เพิ่มป้ายกำกับ freshness badge แสดง update age ("Live & Fresh · 4s ago" / "Stale · 35s ago") และปุ่ม Reconnect ทันทีที่เข้าสู่สถานะ degraded หรือ stale
- Accessible combobox and popover primitive (FS-013):
  - รวมศูนย์พฤติกรรมของ Path Selector (`AuditFilterControls`) และ Session Selector (`AuditSessionSelect`) ไว้ใน primitive เดียวกัน (`ComboboxPopover.tsx`):
    - WAI-ARIA Semantics: Popover ทำหน้าที่เป็น `role="listbox"` พร้อม `aria-label`, `aria-activedescendant`, `id` กำกับแต่ละ option, และ `aria-live="polite"` status announcer ที่แจ้งผลการค้นหา/จำนวนตัวเลือกต่อ Screen Reader
    - Pure navigation helpers: `calculateNextComboboxIndex` และ `findTypeaheadIndex` รองรับ Arrow Down/Up (wrap-around), Home/End, และการกดปุ่มจากช่องค้นหาลงมายังตัวเลือกแรกได้อย่างราบรื่น
    - Keyboard Typeahead: `useComboboxNavigation` รองรับ multi-character circular typeahead พร้อม buffer reset timer (500ms) ทำให้พิมพ์ค้นหาตัวเลือกได้โดยไม่ต้องแตะเมาส์
    - Focus return & outside click: คืน focus ไปยังปุ่ม trigger เสมอเมื่อปิดเมนู (Escape หรือเลือกรายการ) และดักจับ click/touch นอก container เพื่อปิดอัตโนมัติ
    - Motion & Accessibility: รองรับ `useReducedMotion()` โดยสลับระหว่าง Framer Motion slide-fade กับ instant cut อย่างไร้รอยต่อ
    - React 19 immutability compliance: ใช้ `registerOptionRef(index)` closure helper เพื่อความถูกต้องตาม React compiler purity rules
    - Automated unit tests: 15 unit tests ครอบคลุม pure navigation, boundaries, empty list, และ circular typeahead ใน `tests/combobox-popover.test.ts`
- Structured toolbar hierarchy and responsive grouping (FS-014):
  - แยก 4 functional toolbar domains อย่างเด็ดขาด พร้อม WAI-ARIA roles (`toolbar`, `group`, `tablist`, `region`) และ semantic labels เพื่อป้องกันการ wrap มั่วเป็นเศษปุ่ม (orphan button wrap) ในทุก responsive breakpoints:
    1. Global View Controls (`FilesystemActivity`): แยก Mode Switcher (`role="tablist"` `aria-label="Filesystem view modes"`) และ Telemetry Status Bar (`role="region"` `aria-label="Stream telemetry status"`) ออกเป็น 2 atomic groups ที่ wrap อย่างเป็นระเบียบเมื่อหน้าจอแคบ ไม่แตกกระจาย
    2. Canvas Navigation (`TopologyCanvas`): รวม Zoom Stepper (`ZoomOut`, tabular `%`, `ZoomIn`) และ Camera Navigation (`ScanLine` Fit view, `LocateFixed` Center selected IP) ใน container เดียวกัน (`role="group"` `aria-label="Canvas navigation"`, `flex-nowrap`), ล็อกไม่ให้ปุ่มซูมหรือกล้องแตกแถว
    3. Layout Editing (`TopologyCanvas`): รวม Mode Toggle (`Explore` vs `Arrange`), `Undo` layout change, และ Layout Options Dropdown (`Settings2` Auto arrange / Restore default) ใน container เดียวกัน (`role="group"` `aria-label="Layout editing"`, `flex-nowrap`), ทำให้ชุดเครื่องมือจัดผังคงความเป็นเอกภาพเสมอ
    4. Replay Actions & Workspace (`FilesystemActivity`): จัดโครงสร้าง In-Page Audit Toolbar และ Fullscreen Studio Header แยกเป็น 2 ส่วนชัดเจน: Session/Filter Scope Selector และ Replay Workspace Toolbar (Playback Scrubber + Timeline Panel Toggle + Fullscreen Toggle) รองรับ responsive layout ตั้งแต่ mobile (<640px), tablet (sm..lg), จนถึง widescreen (xl/2xl)
  - Formalized hierarchy contracts: เพิ่ม `ToolbarDomain`, `TOOLBAR_HIERARCHY_CONTRACT`, และ `getToolbarGroupContract` ใน `filesystemUtils.ts` พร้อม unit tests 5 รายการใน `tests/filesystem-layout.test.ts` (รวม 101 tests ทั้งหมด)
- Density-aware topology modes (FS-015):
  - โหมดการแสดงผลตามความหนาแน่น 3 ระดับ (`detailed`, `clustered`, `aggregated`) พร้อม `auto` preference:
    - `detailed` (ชุดเล็ก: totalNodes <= 15 และ totalSources <= 4): แสดงโหนดและ callout ทั้งหมดเต็มความละเอียด ไม่มีการย่อหรือตัดทอน
    - `clustered` (ชุดกลาง: totalNodes <= 42 และ totalSources <= 10): จัดกลุ่มตาม source/branch และรักษาสมดุลความหนาแน่นผ่าน `GRAPH_NODE_LIMIT` (42 โหนด) และ `GRAPH_CALLOUT_LIMIT` (8 แหล่งที่มา)
    - `aggregated` (ชุดใหญ่: totalNodes > 42 หรือ totalSources > 10): ย่อกิ่งที่ไม่ได้เลือกให้เหลือเฉพาะ top-level hubs (depth <= 1) พร้อม badge แจ้งเตือนจำนวนไดเรกทอรีย่อยที่ถูก aggregate (`+N`) บน node card
  - Expand-on-focus mechanics:
    - เมื่อคลิกเลือกโหนดใดโหนดหนึ่ง หรือมี active hop พาดผ่าน (`focusedPath`), ระบบจะขยายกิ่งนั้นและไดเรกทอรีย่อยทั้งหมดใน subtree ของกิ่งนั้นทันที (`includePath` ทั้งหมดที่มี prefix เดียวกัน) ในขณะที่กิ่งอื่นๆ ที่ไม่ได้เลือกยังคงถูกย่อไว้อย่างกะทัดรัด
  - Truthful density metrics & visible hidden-item counts:
    - ทุกโหนดคำนวณ `hiddenChildCount` (`totalDescendants - renderedDescendants`) และ `isAggregated` อย่างถูกต้อง
    - ป้ายบน node card แสดง `+{node.hiddenChildCount}` พร้อม tooltip อธิบายชัดเจน และ `aria-label` แจ้ง Screen Reader
    - Toolbar เพิ่มกลุ่ม Density mode (`role="group"` `aria-label="Density mode"`) เพื่อให้ผู้ใช้สามารถสลับระหว่าง `Auto`, `Detailed`, `Clustered`, `Aggregated` ได้อย่างอิสระ
    - Footer รายงานสถานะความหนาแน่นตามจริง เช่น `12 of 85 paths (73 aggregated in branches)` พร้อมปุ่ม `Expand all` และ `Reset to auto`
  - Unit tests: 8 unit tests เพิ่มเติมใน `tests/filesystem-layout.test.ts` (รวม 109 tests ผ่าน 100%)

- **Modular Architecture and Hook Separation (`FS-016`):**
  - แยก logic การคำนวณ data flow และ state machine ขนาดใหญ่ออกจาก 3 feature components หลัก (`FilesystemActivity`, `TopologyCanvas`, `CwdRouteHistory`) ให้เป็น Custom Hooks และ Pure Helper Functions ที่ทดสอบได้แบบ Unit Test:
    1. `useFilesystemStreaming`: จัดการ SSE stream subscription, initial HTTP fallback polling, automatic freshness decay ticker, stale/degraded state flags, และ recovery actions (`refresh`, `reconnect`)
    2. `useSessionCwdHistory`: จัดการ remote keyset pagination สำหรับ CWD transition events, AbortController cancellation ตาม session switching, monotonic generation checking, และ history accumulation
    3. `useFilesystemUrlState`: ซิงโครไนซ์ state ของระบบกับ Browser URL (`view`, `sessionId`, `hideHome`, `targetPath`, `hop`) รองรับ Back/Forward ผ่าน `popstate` event และ deep-linking พร้อม fallback ที่ปลอดภัย
    4. `useAuditReplay`: จัดการ Replay Timeline scrubber, playback loop timer พร้อม speed toggling (1400ms / 700ms), sequential hop navigation, และ pure helper `deriveActiveHopRoute`
    5. `useResponseAction`: ควบคุม Pi Cowrie session termination lifecycle, capability check, single-pass status caching, bounded exponential polling backoff, และ unified `OperationToast` notifications
    6. `useTopologyViewport`: ควบคุม interactive map viewport, pan/zoom clamping (`clampZoom`), focal point calculation (`calculateFocalPan`), keyboard arrow navigation (`calculateKeyPanStep`), touch pinch zoom, และ 2D responsive auto-fit
    7. `useTopologyArrange`: ควบคุม drag & drop สำหรับ IP callouts และ directory nodes, click suppression บน drag gestures (`consumeNodeClickSuppression`, `consumeCalloutClickSuppression`), layout undo stack, auto-arrange, และ localStorage persistence ที่ทนทานต่อ corrupt storage
  - ทดสอบความถูกต้องด้วยชุดทดสอบ `tests/filesystem-hooks.test.ts` (12 unit tests) รวมเป็น 122 tests ผ่านทั้งหมด 100% พร้อม zero ESLint warnings และ Next.js production build สำเร็จ

- **Hardened Layout Persistence (`FS-017`):**
  - ออกแบบโมดูล `layoutPersistence.ts` เพื่อป้องกันและกู้คืนความผิดพลาดของ browser storage ในทุกสภาวะ:
    1. Resilient Storage Access (`getLocalStorageSafe`): ดักจับ `SecurityError` และข้อจำกัดของ Sandboxed iframe/Private browsing โดยคืนค่า `null` อย่างปลอดภัย ไม่ทำให้การเรนเดอร์ React พัง
    2. Versioned Envelope & Zero-Loss Migration (`parseAndValidateLayout`, `loadLayoutFromStorage`): บันทึกข้อมูลผัง topology ในรูปแบบ Schema Envelope Version 1 (`{ version: 1, updatedAt: timestamp, positions: { ... } }`) พร้อม backward compatibility กับข้อมูล layout เดิมที่เป็น format version 0 unversioned โดยจะ auto-upgrade เป็น version 1 ให้โดยอัตโนมัติ
    3. Strict Coordinate Validation: กรองค่าที่เป็น `null`, array, non-numeric, `NaN`, หรือ `Infinity` ทิ้ง และจำกัดขอบเขตพิกัดไม่ให้หลุดเกิน `[-NODE_WORKSPACE_LIMIT, NODE_WORKSPACE_LIMIT]` (±400)
    4. Isolated Storage Scoping (`getLayoutStorageKeys`): แยกคีย์จัดเก็บของ Live mode (`pti-label-layout-live`, `pti-node-layout-live`) ออกจากคีย์ของ Audit session (`pti-label-layout-audit-${safeSessionId}`, `pti-node-layout-audit-${safeSessionId}`) อย่างเด็ดขาด พร้อม URI-encode session ID เพื่อป้องกัน key injection
    5. Automatic Pruning & Quota Exhaustion Recovery (`pruneStaleAuditLayouts`): ลบ audit session layout เก่าที่เกิน 14 วัน (`AUDIT_LAYOUT_MAX_AGE_MS`) หรือมีจำนวนเกิน 30 รายการ (`MAX_STORED_AUDIT_LAYOUTS`) ตามลำดับเวลาที่อัปเดตเก่าที่สุด (ไม่ลบ Live keys) และหากเกิด `QuotaExceededError` ขณะเซฟ ระบบจะเรียก prune และลองบันทึกซ้ำอัตโนมัติ
  - ตรวจสอบความถูกต้องด้วยชุดทดสอบ `tests/layout-persistence.test.ts` (17 unit tests) รวมทั้งสิ้น 139 tests ผ่านทั้งหมด 100% พร้อม Next.js build ผ่านแบบสมบูรณ์

- **Comprehensive Automated Coverage Expansion (`FS-018`):**
  - เพิ่มชุดทดสอบครอบคลุมทุกมิติหลักของระบบ Filesystem Activity ใน `tests/filesystem-coverage-expansion.test.ts` (19 tests):
    1. Filter Truth: ทดสอบความถูกต้องของ `isHomeOnlySession` และ `sessionTouchesPath` ทั้ง exact, descendant, และ non-matching sibling paths, รวมถึงการสกัด `getDistinctSessionPaths` ที่เรียงลำดับตามจำนวน session และ path อย่างแม่นยำ
    2. Session Selection & Anti-Hijacking: ทดสอบ `resolveSessionSelection` ใน Live mode และ Audit mode ที่ไม่ silent hijack session แต่จะแจ้ง `expiredSessionId` ชัดเจน
    3. Replay Navigation & Completeness: ทดสอบ boundary clamping ของ `calculateNextHistoryEventId` (next/prev/loop) และ active hop route derivation สำหรับทั้ง successful transitions และ denied/failed attempts
    4. Empty-History Response: ตรวจสอบ capability resolution (`terminateCapabilityFrom`) ทั้งสถานะ available, forbidden, unconfigured, และ error
    5. URL Restoration & Roundtrip: ทดสอบ roundtrip fidelity ของ `buildAuditUrlSearch` และ `parseAuditUrlParams` พร้อมการ sanitize malformed query params
    6. 2D World Bounds & Viewport Fit: ทดสอบการคำนวณ world bounds สำหรับ node coordinates นอกช่วง 0..100 และ viewport fit ที่รองรับ minimap clearance
    7. Responsive Sidebar Constraints: ทดสอบ `clampTimelineSidebarWidth` ที่จำกัด min 360px, max 760px, และ 65% ของหน้าจอบน narrow viewports
    8. Keyboard & Touch Navigation: ทดสอบ `calculateKeyPanStep` สำหรับปุ่มลูกศร 4 ทิศทาง และ `calculateTouchPinchZoom` ที่รองรับ gesture pinch-in/out และป้องกัน negative/zero distance
    9. Reduced Motion: ทดสอบ `getMotionDuration` ที่ตัดระยะเวลา animation เป็น 0 ทันทีเมื่อผู้ใช้เปิด reduced motion
  - ผลการทดสอบ: 158 Vitest tests ใน 9 test suites ผ่าน 100%, zero ESLint warnings, และ Next.js production build ผ่านฉลุย

- **Time-based Replay Scrubber and Dwell Interval Tracking (`FS-019`):**
  - พัฒนาระบบ Replay Scrubber ให้สะท้อนระยะเวลาและจังหวะเวลาจริงของการกระทำของผู้บุกรุก (Non-uniform attacker timing) แทนการเล่นด้วยคาบเวลาคงที่:
    1. Forensic Time Delta & Elapsed Formatting (`formatTimeDelta`, `formatElapsedTime`):
       - แปลงช่วงเวลาเป็นข้อความฟอร์เรนสิกที่กระชับและแม่นยำ เช่น `<1s`, `14s`, `2m 05s`, `1h 02m`, `1d 01h`
       - แสดงเวลาที่ผ่านไปจากจุดเริ่มต้นเซสชัน (`+00:00`, `+01:15`, `+01:02:05`) บนการ์ดประวัติแต่ละ hop
    2. Real-Time Dwell Metrics Calculation (`calculateHistoryTimeMetrics`):
       - คำนวณช่วงเวลาพัก (dwell time / interval) ระหว่างแต่ละ hop และคำนวณสัดส่วนเวลาสะสมเทียบกับความยาวเซสชันจริง (`timeProgressPercent`) เพื่อไม่ชี้นำให้นักวิเคราะห์เข้าใจผิดว่าผู้บุกรุกเคลื่อนที่ด้วยความเร็วสม่ำเสมอ
    3. Dynamic Realistic Playback Pacing (`calculateReplayPacingDelay`):
       - เพิ่มโหมดการเล่น 2 แบบ สลับได้ผ่านปุ่ม `Pacing` (`Real` vs `Step`):
         - `Step` (Uniform): ใช้คาบเวลาคงที่ตามเดิม (1400ms ที่ 1x, 700ms ที่ 2x) เหมาะสำหรับการเลื่อนดูทีละขั้นอย่างรวดเร็ว
         - `Real` (Realistic): หน่วงเวลาการเล่นอัตโนมัติตามระยะเวลาหยุดคิด/เว้นช่วงจริงของผู้บุกรุก โดยสเกลอย่างมีขอบเขตระหว่าง 300ms (สำหรับคำสั่งรัวๆ <1s) จนถึง 3200ms (สำหรับการทิ้งช่วงนานเป็นสิบๆ นาที) ทำให้นักวิเคราะห์รับรู้ถึงความลังเลหรือการทิ้งช่วงของผู้บุกรุกได้อย่างเป็นธรรมชาติโดยไม่ทำให้หน้าเว็บค้าง
    4. Interactive Range Scrubber & Dual Progress Bar:
       - เพิ่มแถบเลื่อน interactive range scrubber (`<input type="range">`) ที่รองรับการลากเมาส์ ทัชสกรีน หรือแป้นพิมพ์ เพื่อกระโดดข้ามไปยัง hop ใดๆ ได้ทันที
       - แถบความคืบหน้าแบบ Dual Progress แสดงทั้งลำดับขั้นตอน (Hop step) และเปอร์เซ็นต์เวลาจริงของเซสชันที่ล่วงเลยไป (Session elapsed time progress)
    5. Timeline Dwell Badges & Idle Pause Detection:
       - แสดงป้ายกำกับระยะเวลาทิ้งช่วง (เช่น `+14s dwell`) ในรายการเส้นทางไดเรกทอรี
       - หากผู้บุกรุกหยุดนิ่งเกิน 1 นาที (`>= 60s`), ระบบจะแสดงป้ายเตือน `Attacker pause: +Xm Ys` สีส้มสะดุดตา เพื่อระบุจุดผิดสังเกตทางพฤติกรรมทันที
  - ผลการทดสอบ: 164 Vitest tests ใน 9 test suites ผ่าน 100%, zero ESLint warnings, และ Next.js production build ผ่านฉลุย

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
