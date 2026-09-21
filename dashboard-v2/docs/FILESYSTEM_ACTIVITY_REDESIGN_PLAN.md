# Filesystem Activity — Production UX/UI Redesign Plan

Status: **Proposed for review — no implementation yet**

Date: 2026-09-20

Scope: `dashboard-v2` → `/filesystem-activity`
Primary reference: current Audit & Replay screen supplied by the product owner

## 1. Executive summary

หน้า Filesystem Activity มี capability ที่ค่อนข้างครบแล้ว ทั้ง live topology, retained-session search, URL deep link, filter, route replay, pagination, fullscreen, layout persistence และ response action แต่ UI ปัจจุบันให้น้ำหนักกับ controls เกือบทุกชิ้นเท่ากัน จึงทำให้ workflow หลักของ analyst ไม่ชัด และทำให้ข้อมูลสำคัญอย่าง session scope, lifecycle, selected hop และ freshness ถูกกลืนไปกับ toolbar จำนวนมาก

ข้อเสนอคือ redesign หน้าเดิมให้เป็น **investigation workspace** ที่มีลำดับชัดเจน:

1. เลือก operating mode: Live Monitor หรือ Session Investigation
2. ระบุ session/evidence scope ที่กำลังดู
3. อ่าน trajectory และ event sequence พร้อมกัน
4. เจาะ detail หรือทำ response action เมื่อจำเป็น

ทิศทางนี้ยังคง data source, URL contract, filter semantics, replay behavior และ response authorization เดิมทั้งหมด ไม่สร้าง KPI หรือข้อสรุปที่ backend ไม่ได้ให้มา

## 2. สิ่งที่ตรวจแล้ว

### 2.1 Source และ architecture

- `src/components/filesystem/FilesystemActivity.tsx` — page orchestration, mode switch, filtering, audit directory, replay, fullscreen และ layout composition (ประมาณ 1,630 บรรทัด)
- `src/components/filesystem/TopologyCanvas.tsx` — graph layout, viewport, density, arrange mode, minimap, nodes, source callouts และ footer (ประมาณ 1,935 บรรทัด)
- `src/components/filesystem/CwdRouteHistory.tsx` — replay transport, scrubber, timeline, command state และ response tab (ประมาณ 862 บรรทัด)
- `src/components/filesystem/AuditSessionSelect.tsx` — local/remote session search และ pagination
- `src/components/filesystem/AuditFilterControls.tsx` — home-only/path filters และ filtered count
- `src/components/filesystem/FilesystemContextPanel.tsx` / `FilesystemInspector.tsx` / `SessionSourceList.tsx` — live-mode context
- `src/components/filesystem/useFilesystemStreaming.ts` — snapshot/SSE/freshness ownership
- `src/components/filesystem/useAuditDirectory.ts` — authoritative retained-session directory
- `src/components/filesystem/useSessionCwdHistory.ts` — CWD history pagination/deep-hop lookup
- `src/components/filesystem/useAuditReplay.ts` — selected hop, playback, duration และ route presentation
- `src/components/filesystem/filesystemUtils.ts` — graph/audit snapshot/layout/semantics utilities
- existing filesystem unit, integration และ Playwright browser tests

### 2.2 Existing contracts ที่ต้องรักษา

- Live snapshot และ retained audit directory เป็นคนละ authority lane
- ห้ามเดา path ที่ telemetry ไม่ได้ยืนยัน
- failed `cd` ต้องไม่สร้าง directory node ปลอม
- audit canvas ต้องเก็บ historical directories ที่ session เคยแตะ แม้ attacker จะออกจาก path แล้ว
- session, hop และ filters ต้อง deep-link/back/forward ผ่าน URL ได้เหมือนเดิม
- remote session search และ keyset pagination ต้องทำงานเหมือนเดิม
- ต้องมี replay owner, timer owner, history owner และ response polling owner เพียงชุดเดียว
- response action ต้องเปิดตาม role/capability เดิม และต้องยืนยันก่อน disconnect
- refresh ต้องเก็บ last valid snapshot เมื่อทำได้ และต้องไม่ทำให้ selection หาย
- fullscreen ต้อง trap/restore focus และ `Escape` ต้องออกได้
- layout preference ที่มีอยู่ต้อง migrate หรือรักษาได้อย่างปลอดภัย

## 3. Current-state audit

ระดับความสำคัญ:

- **P0** — อาจทำให้ analyst ตีความสถานะหรือหลักฐานผิด
- **P1** — กระทบ task completion, scanability หรือ usability อย่างมาก
- **P2** — polish, consistency หรือ maintainability

### 3.1 Data meaning และ status clarity

| Priority | Finding | Evidence / impact | Direction |
| --- | --- | --- | --- |
| P0 | `Live stream` กับ `Stale · 3h ago` แสดงติดกันโดยไม่มีชื่อ scope | connection state ของ SSE และ age ของ telemetry เป็นคนละเรื่อง ผู้ใช้จึงอาจเข้าใจว่าระบบขัดแย้งกัน | แยกเป็น `Connection: Connected` และ `Latest telemetry: 3h ago`; ใน Audit mode ลด stream state เป็น secondary system status |
| P0 | Audit ของ closed session ถูกเรียกว่า `active session` ใน canvas footer | `buildAuditSnapshot()` ใส่ selected session ลง `snapshot.sessions` เพื่อวาดกราฟ แล้ว generic footer ใช้คำว่า active | ส่ง explicit context (`live` หรือ `audit`) หรือ audit-specific summary; closed session ต้องแสดง `Retained session`/`Closed` ไม่ใช่ active |
| P0 | `generatedAt` ของ audit snapshot ถูกสร้างด้วยเวลาปัจจุบัน | เวลาที่ materialize view อาจถูกอ่านผิดว่าเป็นเวลาหลักฐาน | แยก `View generated` ออกจาก `Evidence observed/closed`; ไม่ใช้เวลาสร้าง client snapshot เป็น evidence freshness |
| P1 | filter count, selection และ pinned-outside-filter state กระจายหลายตำแหน่ง | session ยังคงถูกเปิดได้แม้อยู่นอก filter ซึ่งเป็น behavior ที่ดี แต่ banner และ toolbar ทำให้เข้าใจยาก | แสดง filter chips + `Selected outside results` badge ติดกับ session scope และมี action เดียวที่ชัดเจน |
| P1 | `Refresh` ไม่บอกว่ากำลัง refresh อะไร | ใน Audit mode ปุ่ม page-level refresh เรียก topology snapshot แต่ retained session/history มี lifecycle แยก | เปลี่ยน label/action ตาม scope เช่น `Refresh live topology`; audit data ใช้ retry/load controls ของ region นั้นเอง |
| P1 | Command data เป็น tab เทียบเท่ากับ Route Replay ทั้งที่ยังไม่มี authoritative feed | ผู้ใช้คาดว่าจะมีข้อมูล แต่พบ empty state หลังคลิก | คง capability ไว้แต่แสดง availability ก่อนเข้า เช่น `Evidence · Unavailable` หรือ disabled-with-explanation โดยไม่ซ่อน semantic warning |

### 3.2 Information hierarchy และ layout

| Priority | Finding | Impact | Direction |
| --- | --- | --- | --- |
| P1 | page header, mode switch, stream state, filters, replay tools และ canvas tools มี visual weight ใกล้กัน | ไม่มี obvious starting point | ใช้ 3 ชั้น: page/mode → investigation scope → workspace controls |
| P1 | audit toolbar มี controls จำนวนมากในแถวเดียวและ wrap แบบไม่เป็นกลุ่มที่คาดเดาได้ | อ่านยาก โดยเฉพาะ 1280–1440 px และ 200% zoom | session selector เป็น primary; filters เข้า popover พร้อม active chips; workspace actions แยกขวา |
| P1 | page-mode audit workspace fix ที่ `600/660px` | จอสูงมีพื้นที่ว่างมาก แต่จอเตี้ยอาจบังคับ nested scroll | ใช้ viewport-aware height เช่น `min-height` + `calc(100dvh - shell offsets)` และมี max ตาม content ไม่ fix สอง breakpoint |
| P1 | canvas ใช้พื้นที่มากแม้ graph มีเพียง 4 paths | sparse graph ดูหลวมและ event sequence ไม่เด่น | fit-to-content ตาม density, จำกัด whitespace และใช้ route overlay เป็น visual focus |
| P1 | timeline ถูกบีบใน rail แคบ ขณะที่แต่ละ event มีข้อมูลหลายบรรทัด | timestamp/path/badge truncate และ scan เทียบ hop ยาก | rail เริ่มประมาณ 400–440 px บน wide desktop, resize ได้; sticky replay header; event row hierarchy ใหม่ |
| P1 | mobile/tablet stack canvas ก่อน timeline ยาว ๆ | ผู้ใช้ต้อง scroll ไปมาระหว่าง hop กับ graph | ใช้ workspace tabs `Map / Timeline / Details` ใต้ desktop breakpoint และรักษา selected hop ร่วมกัน |
| P2 | nested cards/borders เยอะเกินไป | ลด visual grouping เพราะทุกอย่างดูเป็น card | ใช้ surface ใหญ่ 1 ชั้นต่อ region แล้วใช้ divider/spacing ภายใน |
| P2 | footer ของ canvas ยาวและรวม status, counts, freshness, legend | ข้อความ wrap และแย่งพื้นที่กราฟ | แยก `view summary` ซ้าย, legend ขวา; detail freshness ไป status popover |

### 3.3 Visualization

| Priority | Finding | Impact | Direction |
| --- | --- | --- | --- |
| P0 | graph ผสม filesystem hierarchy edge กับ attacker transition โดยความต่างยังไม่ชัดพอ | เส้น `parent → child` อาจถูกอ่านเป็น attacker route | neutral thin hierarchy edge; amber directional transition edge; arrowhead, hop number และ legend ที่ตรงกัน |
| P1 | attacker/source card ดูเหมือน node หนึ่งใน filesystem | mental model ของ actor กับ directory ปนกัน | ทำ source เป็น actor anchor ที่รูปแบบต่างจาก folder อย่างชัดเจน พร้อม `Entry` connector |
| P1 | current hop, visited path และ future path แยกกันไม่ชัดใน glance แรก | replay มี motion แต่ state comparison ยาก | visited = solid amber, current = stronger outline/pulse แบบ reduced-motion safe, future/unvisited = neutral/dim |
| P1 | minimap แสดงแม้ topology เล็ก | ใช้พื้นที่แต่ให้ประโยชน์ต่ำ | แสดง minimap เมื่อ graph เกิน density threshold, zoom ≠ fit หรือผู้ใช้เปิดเอง |
| P1 | layout/arrange/density tools เด่นพอ ๆ กับ investigation tools | secondary customization แย่ง attention | เหลือ Zoom, Fit, Locate เป็น direct controls; รวม Arrange/Density/Reset ใน `View settings` |
| P2 | labels และ badges บางจุดใช้ 9–11 px | ขัดกับ production theme contract และอ่านยากบน 90% zoom/HiDPI | meaningful text ขั้นต่ำ 12 px; 10–11 px ใช้ได้เฉพาะ nonessential decoration ที่มี accessible equivalent |

### 3.4 Interaction และ accessibility

| Priority | Finding | Impact | Direction |
| --- | --- | --- | --- |
| P1 | forensic tabs ใช้ button + `aria-pressed` แทน tab semantics | assistive technology ไม่ได้รับ tab/panel relationship ที่ครบ | ใช้ `role="tablist"`, `role="tab"`, `aria-selected`, `aria-controls` และ roving focus |
| P1 | splitter รองรับ mouse + keyboard แต่ไม่รองรับ pointer/touch | tablet resize ไม่ทำงานแม้ element ใช้ `touch-none` | ย้ายเป็น Pointer Events พร้อม pointer capture; keyboard contract เดิมยังอยู่ |
| P1 | icon-only tools พึ่ง native `title` | discoverability ช้าและไม่สม่ำเสมอ | shared tooltip ที่ keyboard/focus เปิดได้ และ accessible name ชัดเจน |
| P1 | canvas selection กับ replay hop selection เป็นคนละ state แต่ UI ไม่อธิบาย | ผู้ใช้อาจคลิก folder แล้วคิดว่าเปลี่ยน active hop | แยกคำว่า `Inspecting directory` กับ `Replay position`; มี `Return to current hop` เมื่อ diverge |
| P2 | fullscreen และ in-page มี markup ซ้ำจำนวนมาก | state/label/a11y behavior มีโอกาส drift | render workspace tree เดียว แล้วเปลี่ยน shell/layout variant |
| P2 | warning/error styles บางส่วนใช้ hard-coded amber classes | light theme/semantic token consistency เสี่ยง | ใช้ `warning-*`, `danger-*`, `surface-*` tokens ทั้งหมด |

### 3.5 Code organization

ปัญหาหลักไม่ใช่เพียงจำนวนบรรทัด แต่คือ presentation, orchestration และ mode-specific wording อยู่ใน component เดียวกัน:

- `FilesystemActivity.tsx` มี duplicated audit workspace สำหรับ page/fullscreen รวมถึง duplicated expired/filter banners
- `TopologyCanvas.tsx` เป็นทั้ง state owner, toolbar, graph renderer, minimap, density manager, status banner, footer และ arrange inspector
- `CwdRouteHistory.tsx` เป็นทั้ง tab shell, transport controls, scrubber, timeline list, unavailable command state และ response host
- `filesystemUtils.ts` รวม domain formatting, graph algorithms, freshness, URL helpers และ UI constantsไว้ด้วยกัน

ผลคือการ redesign โดยแก้ class names ตรง ๆ จะเสี่ยง regression และทำให้ page/fullscreen ไม่ตรงกัน ควรแยก presentation boundaries ก่อน แล้วรักษา hooks/authoritative state owners เดิม

## 4. Proposed information architecture

### 4.1 Shared page level

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│ Filesystem Activity                       Connection ● Connected   Status ▾  │
│ Observe live directory movement or investigate a retained attacker session  │
│ [ Live Monitor ] [ Session Investigation ]                                  │
└──────────────────────────────────────────────────────────────────────────────┘
```

- Page title มีเพียงครั้งเดียว; app-shell breadcrumb/title ด้านบนคงรูปแบบเดิมได้
- Mode switch เป็น navigation ระดับหน้า ไม่ปะปนกับ telemetry badges
- System connection status แสดงชื่อ dimension ชัดเจน และเปิดรายละเอียด freshness ได้
- ไม่แสดง raw count ใน mode tab ถ้า count นั้นเปลี่ยนความหมายระหว่าง live/audit

### 4.2 Live Monitor

```text
┌──────────────────────────────── Live scope bar ──────────────────────────────┐
│ Latest telemetry 02:41:07 · 3h ago   1 active session   [Refresh topology]  │
└──────────────────────────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────┬───────────────────────────────┐
│ Live filesystem topology                     │ Context                       │
│ [Zoom] [Fit] [Locate]             [View ▾]   │ [Session] [Directory]         │
│                                              │ selected source/path/status   │
│                topology                     │                               │
│                                              │ Browse sources                │
│ summary                            legend    │                               │
└──────────────────────────────────────────────┴───────────────────────────────┘
```

- topology เป็น primary region
- context rail กว้างคงที่ประมาณ 320–360 px และ sticky ภายใน viewport เมื่อ content ยาว
- source browser อยู่ใน context rail แต่ default collapse เมื่อมี source เดียวและไม่มี retained item ที่เกี่ยวข้อง
- active session count ใช้ได้เฉพาะ Live mode

### 4.3 Session Investigation / Audit

```text
┌──────────────────────────── Investigation scope bar ─────────────────────────┐
│ [Search IP / session / path........................] [Closed] [Filters (2)]  │
│ 10.58.33.2  ·  session 8cc7927a…  ·  observed 17 Sep 2026 11:39:55          │
└──────────────────────────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────┬───────────────────────────────┐
│ Attack trajectory                            │ Investigation panel           │
│ Current: /home/root → /etc · Hop 2 of 2      │ [Route] [Evidence] [Response] │
│ [Zoom] [Fit] [Current hop]       [View ▾]    │ ┌ sticky replay transport ┐   │
│                                              │ │ ◀  Play  ▶  1×  Real     │   │
│ hierarchy + directional trajectory           │ │ elapsed / duration        │   │
│                                              │ └──────────────────────────┘   │
│ selected directory inspector (contextual)    │ chronological event list      │
│ summary / legend                             │                               │
└──────────────────────────────────────────────┴───────────────────────────────┘
```

Recommended desktop ratio: flexible canvas + **400–440 px** investigation rail. User resize remains available between configured min/max values.

Key behavior:

- Scope bar แสดง session identity, lifecycle และ active filters ก่อน workspace
- canvas title เน้น current transition แทน repeat source IP อย่างเดียว
- replay transport sticky อยู่บน investigation panel ไม่หายเมื่อ scroll events
- route timeline เป็น chronological evidence lane; graph เป็น spatial/hierarchical lane
- `Evidence` ใช้แทน `Command data` เพื่อรองรับ current unavailable state โดยไม่ claim ว่ามี command feed
- `Response` แยกด้วย shield icon และ danger semantics; ไม่ใช้ amber primary highlight สำหรับ destructive control
- fullscreen ใช้ component tree เดียวกัน โดยเปลี่ยน container เป็น dialog shell และเพิ่มพื้นที่—not a second implementation

### 4.4 Tablet/mobile

```text
[ Live | Investigation ]
[ Session selector........................ ]
[ Status ] [Filters] [More]

[ Map ] [Timeline ] [Details ]
┌────────────────────────────┐
│ one active workspace panel │
│                            │
└────────────────────────────┘

sticky bottom replay controls (Timeline/Map when a hop is selected)
```

- ไม่ stack map + 800px timeline ต่อกัน
- selection state ร่วมกันทุก workspace tab
- filters เปิดเป็น popover บน tablet และ bottom sheet/dialog บน mobile
- canvas ยัง pan/zoom ได้ แต่ direct controls ลดเหลือสิ่งจำเป็น
- minimum target 40×40 px; ไม่มี body horizontal scroll

## 5. Visual design rules for this page

### 5.1 Hierarchy

- ใช้ `canvas` เป็น page background, `surface` สำหรับ workspace และ `surface-subtle` เฉพาะ inset/secondary controls
- แต่ละ region มี border ชั้นเดียว; ใช้ divider ภายในแทน nested cards
- Amber ใช้กับ selected route/current investigation เท่านั้น
- Green = connected/confirmed, amber = stale/warning/selected brand context, red = destructive/failure, blue/cyan = informational
- machine values เช่น IP, path, session ID, timestamp ใช้ mono; label และ prose ใช้ sans

### 5.2 Typography and density

- page title 20–24 px
- workspace title 16 px
- body/control 13–14 px
- metadata ไม่ต่ำกว่า 12 px
- control height 36 px เฉพาะ compact canvas toolbar; primary selector/action 40 px
- path และ session ID ใช้ middle truncation/accessible full value ไม่ใช้ตัดท้ายอย่างเดียวในทุกกรณี

### 5.3 Motion

- route transition animation 160–240 ms สำหรับ step interaction
- autoplay edge energy อาจต่อเนื่องได้เฉพาะเมื่อ playing และต้องหยุดเมื่อ paused
- `prefers-reduced-motion` ใช้ static current-state styling
- หลีกเลี่ยง scale/glow สำหรับ ordinary hover; current hop ใช้ outline/contrast ก่อน animation

## 6. Proposed component architecture

ชื่อ final ปรับได้ระหว่าง implementation แต่ boundary ควรเป็นดังนี้:

```text
FilesystemActivity                 state/orchestration owner
├─ FilesystemPageHeader            title, mode switch, scoped system status
├─ LiveFilesystemWorkspace
│  ├─ LiveScopeBar
│  ├─ TopologyWorkspace
│  └─ FilesystemContextPanel
└─ AuditFilesystemWorkspace        one tree for page/fullscreen variants
   ├─ AuditScopeBar                session selector, lifecycle, filters
   ├─ AuditNoticeRegion            expired/pinned/error notices
   ├─ TopologyWorkspace
   │  ├─ TopologyHeader
   │  ├─ TopologyToolbar
   │  ├─ TopologyScene
   │  ├─ ConditionalMinimap
   │  └─ TopologySummaryBar
   ├─ WorkspaceSplitter
   └─ InvestigationPanel
      ├─ InvestigationTabs
      ├─ ReplayTransport
      ├─ RouteEventList
      ├─ EvidenceAvailabilityPanel
      └─ ResponseActionPanel
```

### Ownership rules

- `FilesystemActivity` หรือ controller hook เป็นเจ้าของ selected session/path/mode/URL coordination
- `useFilesystemStreaming` เป็นเจ้าของ SSE/snapshot/freshness เพียงตัวเดียว
- `useAuditDirectory` เป็นเจ้าของ retained directory/search เพียงตัวเดียว
- `useSessionCwdHistory` เป็นเจ้าของ history request/pagination เพียงตัวเดียว
- `useAuditReplay` เป็นเจ้าของ timer/playback เพียงตัวเดียว
- `useResponseActionController` mount/poll เมื่อ Response tab active ตาม contract เดิม
- presentational shells ห้ามเริ่ม fetch, timer หรือ duplicate state owner

### Utility split

หลัง UI stable ควรแยก `filesystemUtils.ts` แบบ mechanical โดยไม่เปลี่ยน behavior:

- `filesystem-domain.ts` — path/session semantic helpers
- `filesystem-graph.ts` — node/callout/layout calculations
- `filesystem-replay.ts` — timeline calculations/formatting
- `filesystem-freshness.ts` — freshness presentation mapping
- `filesystem-url.ts` — URL serialization helpers
- `filesystem-layout.ts` — bounds, density และ persistence constants

ไม่ควรทำ utility split พร้อม visual redesign ใน commit เดียว เพราะ review/regression tracing จะยาก

## 7. Implementation plan

### 7.0 Execution and audit protocol

Implementation ต้องทำเป็นงานย่อยที่ audit และ rollback ได้ ไม่รวมหลาย phase หรือหลาย concern ไว้ใน commit เดียว

#### Responsibility model

- Primary agent เป็น orchestrator, code reviewer และผู้ commit ทุก checkpoint
- Sub-agent รับ prompt ที่มี scope แคบ, file boundary, behavior contract, acceptance criteria และ test command ชัดเจน
- Sub-agent ห้ามขยาย scope, เปลี่ยน data semantics, commit หรือแก้ unrelated files
- Sub-agent ต้องรายงาน files changed, assumptions, tests run, unresolved risks และ diff summary เมื่อจบงาน
- Primary agent ต้องอ่าน diff และไฟล์ที่ได้รับผลจริงทุกครั้ง ไม่รับผลจาก summary ของ sub-agent อย่างเดียว
- ถ้า audit พบ defect ให้ส่ง focused correction prompt กลับไปยัง sub-agent แล้วตรวจซ้ำก่อน commit
- ใช้ sub-agent พร้อมกันได้เฉพาะงาน read-only หรือ file scopes ที่พิสูจน์แล้วว่าไม่ชนกัน; งาน implementation บน shared worktree ให้ทำตามลำดับเป็นค่าเริ่มต้น

#### Required loop for every subtask

```text
1. Confirm clean checkpoint / record current HEAD
2. Send bounded implementation prompt to sub-agent
3. Inspect changed files and full diff
4. Audit behavior, ownership, semantics, accessibility and scope
5. Request corrections when required
6. Run targeted tests for the changed behavior
7. Run full check gate
8. Perform manual/self-test against the acceptance criteria
9. Record evidence and residual risks
10. Commit only the reviewed files with one focused commit
11. Confirm clean worktree before the next subtask
```

#### Minimum quality gate per commit

รันจาก `dashboard-v2`:

```bash
npm test
npm run lint
npm run build
```

เพิ่มตามชนิดงาน:

- component/interaction change: targeted Vitest test และ relevant Playwright spec
- URL/navigation/fullscreen/replay change: `npm run test:browser`
- history pipeline change: `npm run test:filesystem-history-integration` เมื่อ test target พร้อม
- audit directory/scale change: `npm run test:filesystem-audit-integration` เมื่อ test target พร้อม
- responsive/visual change: screenshot self-test ตาม viewport matrix ในหัวข้อ 8
- accessibility change: keyboard-only walkthrough, focus order, accessible-name และ reduced-motion self-test

หาก gate ใดรันไม่ได้เพราะ environment dependency ต้องไม่รายงานว่า pass ให้บันทึก `NOT RUN` พร้อมเหตุผลและใช้ test ที่ใกล้เคียงที่สุด ก่อนขออนุมัติว่าจะ commit แบบมี known limitation หรือหยุดแก้ environment ก่อน

#### Review checklist before commit

- diff อยู่ใน scope ของ prompt และไม่มี unrelated user changes
- authoritative data lane และ wording ถูกต้อง โดยเฉพาะ live/retained/closed/freshness
- ไม่มี duplicate fetch, SSE subscription, polling loop, autoplay timer หรือ state owner
- loading/error/empty/stale/partial states ยังทำงานและไม่ทำ selection หาย
- URL, back/forward และ deep-link behavior ไม่ regression
- keyboard, focus, touch/pointer และ reduced-motion behavior เหมาะกับส่วนที่แก้
- light/dark tokens ถูกใช้แทน hard-coded palette ใหม่
- meaningful text ไม่ต่ำกว่า 12 px
- tests ไม่ได้ถูกทำให้อ่อนลงเพื่อให้ implementation ผ่าน
- commit มีเฉพาะ reviewed files และ message อธิบายหนึ่ง logical change

#### Commit policy

- หนึ่งงานย่อยที่ผ่าน audit = หนึ่ง commit
- ใช้ focused conventional message เช่น `refactor(filesystem): unify audit workspace shell`
- ห้ามรวม formatting, cleanup หรือ utility split ที่ไม่เกี่ยวข้องเข้ากับ feature commit
- ไม่ amend/rewrite checkpoint ที่ส่งให้ review แล้ว; correction หลัง review ใช้ commit ใหม่
- หลังแต่ละ commit ต้องรายงาน hash, files, checks, self-test result และ known limitations
- เมื่อจบแต่ละ phase ให้ทำ phase audit เพิ่มอีกหนึ่งรอบ; ถ้าต้องแก้ใช้ dedicated fix commit ก่อนเริ่ม phase ถัดไป

#### Standard sub-agent prompt contract

ทุก prompt ต้องมีอย่างน้อย:

```text
Objective:
Allowed files:
Forbidden changes:
Behavior/data contracts to preserve:
Implementation requirements:
Acceptance criteria:
Tests/self-checks to run:
Required completion report:
Do not commit; the primary agent will audit and commit.
```

Primary agent จะปรับ prompt ให้เจาะจงตามงาน ไม่ส่งทั้ง phase ขนาดใหญ่ให้ sub-agent ครั้งเดียว

### Phase 0 — Lock behavior and visual baselines

- capture desktop screenshots ที่ 1440×900 และ 1920×1080 สำหรับ Live/Audit, sparse/dense, fresh/stale
- capture tablet 768×1024 และ mobile 390×844
- เพิ่ม fixture สำหรับ closed session, active session, failed hop, empty history, partial history และ selected-outside-filter
- บันทึก network/timer ownership baseline จาก tests เดิม
- เพิ่ม semantic test ยืนยันว่า closed audit ไม่ถูก label เป็น active

Deliverable: baseline artifacts และ failing tests สำหรับ semantic issues ที่ตั้งใจแก้

### Phase 1 — Structural refactor without redesign

- extract shared page header/status components
- extract `AuditFilesystemWorkspace` จาก JSX page/fullscreen ที่ซ้ำกัน
- extract expired/pinned filter notice เป็น component เดียว
- extract topology header/toolbar/summary shell โดย `TopologyCanvas` ยังเป็น state owner เดิม
- extract replay transport/event list จาก `CwdRouteHistory`
- ยืนยันว่า DOM มี topology, replay timer, history panel และ response owner อย่างละหนึ่ง

Deliverable: UI หน้าตาใกล้เดิม แต่ component boundary พร้อม redesign

### Phase 2 — Correct status semantics

- เพิ่ม explicit workspace context ให้ canvas (`live`/`audit`)
- เปลี่ยน live connection/freshness เป็นสอง labeled dimensions
- audit footer ใช้ retained/closed vocabulary ตาม selected session lifecycle
- ห้ามใช้ client-generated audit snapshot time เป็น evidence timestamp
- rename refresh actions ให้ตรง resource ที่ refresh จริง
- รวม pinned-outside-filter messaging ไว้ที่ audit scope

Deliverable: ไม่มีสถานะที่ขัดกันหรือทำให้ตีความหลักฐานผิด

### Phase 3 — Page hierarchy and responsive workspace

- สร้าง page header + mode navigation + scoped status
- สร้าง Live scope bar และ Audit scope bar
- เปลี่ยน fixed `600/660px` เป็น viewport-aware workspace
- desktop ใช้ resizable canvas/rail; tablet/mobile ใช้ Map/Timeline/Details tabs
- migrate stored timeline width ผ่าน existing clamp; invalid legacy value fallback อย่างปลอดภัย
- fullscreen reuse workspace tree เดียวและคง focus trap/restore

Deliverable: stable layout ที่ 390 px ถึง wide desktop และ 200% zoom

### Phase 4 — Topology visualization redesign

- แยก visual encoding ของ hierarchy edge กับ attacker transition
- เพิ่ม arrow direction, hop number และ current/visited/future states จาก replay model เดิม
- fit sparse graph ให้ใช้พื้นที่อย่างมีประสิทธิภาพ
- conditional minimap ตาม density/zoom
- ลด direct toolbar controls และย้าย arrange/density/reset ไป View settings
- เพิ่ม explicit `Inspecting directory` state และ `Return to current hop`
- ปรับ legend ให้ตรงกับ encoding จริงทุก state

Deliverable: analyst มองครั้งแรกแยก filesystem structure กับ attack trajectory ได้

### Phase 5 — Investigation panel redesign

- tabs ใช้ WAI-ARIA tab pattern
- replay transport sticky และจัดกลุ่ม first/prev/play/next/last, speed, pacing
- scrubber แสดง elapsed/total และ hop position โดยไม่ซ้ำข้อมูลหลายจุด
- timeline row เน้น destination/action ก่อน timestamp/status metadata
- แสดง pause/failure/anchored gap โดย text + icon ไม่พึ่งสี
- Evidence tab แสดง availability state ก่อน; ห้ามสื่อว่ามี command/payload data เมื่อไม่มี feed
- Response tab คง controller/capability/confirmation contract เดิม

Deliverable: replay และ timeline ใช้งานต่อเนื่องโดยไม่ต้องสลับสายตาหลาย region

### Phase 6 — Accessibility and production polish

- minimum readable text, contrast และ 40×40 touch target audit
- keyboard order: mode → scope → canvas → investigation tabs → replay → event list
- shared tooltip สำหรับ icon-only controls
- pointer/touch splitter พร้อม keyboard fallback
- live regions เฉพาะ status ที่ควรถูก announce; ไม่ announce ทุก autoplay animation
- reduced-motion audit
- loading/error/empty/refreshing/stale state ต่อ region โดยไม่ layout jump
- light/dark theme visual pass ด้วย semantic tokens เท่านั้น

Deliverable: WCAG 2.2 AA-oriented interaction และ production visual consistency

### Phase 7 — Verification and cleanup

- run unit/component/browser suites
- add visual regression screenshots สำหรับ key matrices
- verify no extra request/poll/timer during resize, tab switch, fullscreen หรือ rerender
- verify back/forward/deep-link for `view`, `sessionId`, `hop`, `hideHome`, `targetPath`
- verify audit pagination/search race handling เดิม
- remove obsolete duplicated markup/styles หลัง parity ยืนยันแล้ว
- document final component/state ownership

Deliverable: tested implementation และ short implementation report

## 8. Verification matrix

### Functional

- Live → Audit → Back → Live → Forward → Audit รักษา selection/hop/filter
- direct URL เปิด retained session และ deep hop ได้
- search, load more, filter reset และ pinned session ทำงานเหมือนเดิม
- replay first/prev/play/next/last, 1×/2×, Real/Step และ failed attempts ทำงานเดิม
- current hop sync ระหว่าง graph, scrubber และ timeline
- fullscreen enter/exit ไม่ reset replay หรือเพิ่ม timer
- response capability fetch เกิดเฉพาะเมื่อเปิด Response tab และ abort เมื่อออก

### Visual/responsive

- 1920×1080, 1440×900, 1280×800, 768×1024, 390×844
- browser zoom 100%, 200% และ text zoom where supported
- sparse graph 1–4 nodes, medium graph, graph เกิน render limits
- timeline 0, 1, 2, many events และ partial retained history
- long IPv6-compatible source string, long path และ long session ID
- light/dark, fresh/stale/disconnected, active/closed, loading/error/empty
- ไม่มี body horizontal scroll หรือ toolbar overlap

### Accessibility

- complete keyboard route โดยไม่ต้องใช้ pointer
- visible focus ไม่ถูก clip ใน canvas/panel
- tablist/tabpanel relationships ถูกต้อง
- splitter/value announcements ถูกต้อง
- status ไม่พึ่งสีเพียงอย่างเดียว
- current hop/selected directory/selected session มี programmatic state
- reduced motion ไม่มี continuous travel/pulse

### Regression commands

```bash
npm test
npm run test:browser
npm run lint
npm run build
```

Integration scripts ที่ต้องใช้ database/test target ให้รันเมื่อ environment พร้อม:

```bash
npm run test:filesystem-history-integration
npm run test:filesystem-audit-integration
```

## 9. Definition of done

- ผู้ใช้ระบุได้ทันทีว่ากำลังอยู่ Live Monitor หรือ Session Investigation
- session scope, lifecycle และ active hop เห็นได้โดยไม่ต้องตีความ badge หลายชุด
- ไม่มีคำว่า active สำหรับ closed retained session
- graph แยก hierarchy และ attacker movement ได้โดยไม่ต้องอ่าน documentation
- sparse graph ไม่เหลือ dead space เกินจำเป็น; dense graph ยัง navigate ได้
- replay controls และ active event ใช้งานได้ใน viewport เดียวบน desktop
- mobile ไม่ต้อง scroll สลับระหว่าง graph กับ timeline เพื่อ replay หนึ่ง hop
- page/fullscreen ใช้ stateful workspace instance เดียว
- no duplicate network owner, polling owner หรือ autoplay timer
- URL/deep-link/pagination/filter/response contracts เดิมผ่านทั้งหมด
- text สำคัญไม่ต่ำกว่า 12 px และ interaction หลักผ่าน keyboard/touch
- light/dark, loading/error/empty/stale/degraded states ผ่าน visual review

## 10. Recommended review decisions

ก่อนเริ่ม implementation ขออนุมัติ direction ต่อไปนี้:

1. ใช้คำ **Live Monitor** และ **Session Investigation** แทนชื่อ mode ปัจจุบัน เพื่อแยก monitoring กับ forensic work ให้ชัด
2. Audit desktop ใช้ resizable evidence rail เริ่มต้น 400–440 px และ fullscreen reuse DOM tree เดียว
3. Tablet/mobile ใช้ `Map / Timeline / Details` workspace tabs แทน vertical stack
4. รวม Arrange, Density และ Reset เข้า `View settings`; คง Zoom, Fit และ Locate เป็น direct controls
5. แสดง minimap แบบ conditional ไม่เปิดตลอดสำหรับ sparse graph
6. เปลี่ยน `Command data` เป็น `Evidence` พร้อม availability state โดยยังไม่เพิ่ม backend data ใหม่
7. implementation ทำตาม phase เพื่อให้ semantic correction และ structural refactor review แยกจาก visual changes ได้

## 11. Out of scope for this redesign

- การสร้าง command/file telemetry source ใหม่
- การเพิ่ม threat score, risk score หรือ model inference ใหม่
- การเปลี่ยน retention policy หรือ backend pagination contract
- การเปลี่ยน authorization/role ของ response action
- การเปลี่ยนความหมายของ confirmed/conditional/failed evidence
- การเพิ่ม auto-response หรือ action ที่ผู้ใช้ไม่ได้ยืนยัน
