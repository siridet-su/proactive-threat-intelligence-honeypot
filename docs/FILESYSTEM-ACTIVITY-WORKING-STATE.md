---
title: Filesystem Activity live working state
status: active
last_updated: 2026-09-24
owner: Dashboard Filesystem workstream
---

# Filesystem Activity live working state

This document is the tactical source of truth for improving the Dashboard
Filesystem Activity experience. Update it in the same change that completes,
blocks, defers, or materially changes any tracked item.

The architectural contract remains in
[`dashboard-v2/docs/REALTIME_CWD_TRACKING.md`](../dashboard-v2/docs/REALTIME_CWD_TRACKING.md).
The canonical corrective-remediation status and detailed acceptance evidence
remain in [`FILESYSTEM-ACTIVITY-AUDIT-FIXES.md`](FILESYSTEM-ACTIVITY-AUDIT-FIXES.md).
Reproducible test results belong in [`validation/`](validation/).

## Working rules

- Keep exactly one item in **In progress** unless tasks are intentionally being
  executed in parallel.
- Do not mark an item **Done** until its acceptance criteria and relevant tests
  pass.
- Record the commit or validation note in the item's Evidence column.
- Add newly discovered work to the backlog before implementing it.
- If scope or data semantics change, update the canonical design/API document
  in the same change.
- Do not place secrets, private management addresses, raw attacker data, or
  credentials in this document.

## Status legend

| Status | Meaning |
| --- | --- |
| `TODO` | Accepted work that has not started. |
| `IN PROGRESS` | Current implementation or validation focus. |
| `PARTIAL` | Some acceptance scope is complete, but a named corrective item or gate remains outstanding. |
| `BLOCKED` | Cannot progress until the recorded dependency is resolved. |
| `DONE` | Acceptance criteria passed and evidence is recorded. |
| `DEFERRED` | Intentionally outside the current workstream. |

## Current focus

There is no active FA remediation item. `FA-001` through `FA-016` are all
accepted `DONE`.

`FS-024` is the current product UX addition: a standardized square radar plane
that fills the available Live topology panel, with a circular sweep rotating
around its center. It does not reopen or change any FA evidence contract.

`FS-007` is `DONE`: FA-001, FA-002, FA-011, and accepted FA-016 jointly
complete the live-topology/Audit-directory separation and its bounded,
truthful retained-session behavior. The outstanding manual/live response-agent
validation remains recorded as an unrelated gate and was not performed.

## Historical baseline

The following is historical baseline evidence, not current repository
validation. It was recorded on 2026-09-15 against the then-unmodified working
tree after commit `78ce21c`.

| Check | Historical result |
| --- | --- |
| Filesystem Vitest suites | Passed: 2 files, 9 tests |
| Filesystem-scoped ESLint | Passed |
| Next.js production build | Passed |
| Working tree after review | Clean |

The baseline passing did not close the findings. Its test count and clean-tree
state must not be read as evidence about the current repository.

## Current remediation state

The original FS rows below retain their historical implementation evidence.
Their corrective acceptance and current validation are cross-referenced to the
canonical audit tracker; the final FA-013 audit evidence is recorded there to
avoid duplicating a large evidence block.

### Now — correctness and truthful UI

| ID | Status | Work | Acceptance criteria | Evidence |
| --- | --- | --- | --- | --- |
| `FS-001` | `DONE` | Replace client-inferred Audit filters with complete per-session audit summaries. | `homeOnly` and path-touch results include active and closed history, do not depend on the selected session's loaded page, and have unit/integration coverage. | Historical implementation evidence: server `auditSummary` contract and 15 focused tests. Corrected and accepted by `FA-001` (`d4b96d5`), with final acceptance recorded in the canonical audit tracker. |
| `FS-002` | `DONE` | Make history completeness explicit. | API returns total/completeness metadata; Replay never claims to show all history while earlier pages remain unloaded; hop numbering stays stable as pages load. | Historical implementation evidence: API completeness contract and 18 focused tests. Corrected and accepted by `FA-010` commit chain; final guarded MongoDB validation is recorded in the canonical audit tracker. |
| `FS-003` | `DONE` | Decouple Response and Command tabs from CWD-history state. | An authorized operator can inspect response capability and disconnect any eligible live session even when route history is empty, loading, or unavailable. | Historical implementation evidence: independent sidebar gating and 29-test suite; no FA corrective item mapped to FS-003. |
| `FS-004` | `DONE` | Expose topology render limits. | UI shows rendered versus available sources/paths and offers a clear way to focus or expand omitted data; no limit is silent. | Historical implementation evidence: render-limit indicators and 37 tests; no FA corrective item mapped to FS-004. |
| `FS-005` | `DONE` | Resolve filtered-selection semantics. | A `0/N` result cannot look like a matching topology; either clear the selection into a filter empty state or label the retained item prominently as pinned outside the result set. | Historical implementation evidence: pinned-outside-filter and `0/N` states. Corrected and accepted by `FA-001` (`d4b96d5`); final acceptance is in the canonical audit tracker. |
| `FS-006` | `DONE` | Synchronize Audit navigation state with the URL. | View, session, filters, and selected hop survive reload/share; Back and Forward restore coherent state; expired session links show a specific state instead of silently choosing another session. | Historical implementation evidence: initial URL/popstate implementation. Corrected and accepted by `FA-005` (`ac74c8b`) and `FA-008` accepted chain; final acceptance is in the canonical audit tracker. |

### Next — data flow, scale, and topology behavior

| ID | Status | Work | Acceptance criteria | Evidence |
| --- | --- | --- | --- | --- |
| `FS-007` | `DONE` | Split live topology transport from the closed-session Audit directory. | Live SSE no longer queries and rebroadcasts the full retained closed-session list on every CWD update; Audit sessions are searchable and paginated. | FA-001, FA-002, FA-011, and accepted FA-016 jointly complete this item. FA-016 acceptance covers exact projection semantics, bounded item plans, truthful count/summary bounds, source-owned retention, stable repair/cleanup cursors, event-outbox ownership, and isolated MongoDB evidence. |
| `FS-008` | `DONE` | Define multi-session IP cluster interaction. | A cluster exposes every active session and path without implying that the latest path is the only route; selection behavior is deterministic and keyboard accessible. | Historical implementation evidence: cluster disclosure, multi-route rendering, and 57 tests; no FA corrective item mapped to FS-008. |
| `FS-009` | `DONE` | Replace the fit algorithm with two-dimensional world bounds. | Fit considers X/Y, rendered element sizes, manual positions outside `0..100`, minimap clearance, and compact/fullscreen canvas sizes. | Historical implementation evidence: 2D bounds and 63 tests; no FA corrective item mapped to FS-009. |
| `FS-010` | `DONE` | Correct count semantics. | Labels distinguish unique sources, sessions, exact-path sessions, and descendant-branch sessions; badges and their resulting lists always agree. | Historical implementation evidence: unified count semantics and 68 tests; no FA corrective item mapped to FS-010. |
| `FS-011` | `DONE` | Reduce response-action polling cost. | Pending actions do not perform a Pi health check plus multiple MongoDB reads every second; status propagation has bounded backoff or an event stream and preserves terminal-state feedback. | Historical implementation evidence: cache, single-pass state read, and bounded polling. Corrected and accepted by `FA-003`/`FA-004`; manual live response-agent smoke validation remains an outstanding gate, as recorded canonically. |
| `FS-012` | `DONE` | Add freshness and degraded-state semantics. | Connected transport and fresh data are distinguishable; UI shows last update age, stale threshold, retry actions, and recovery without discarding the last valid snapshot. | Historical implementation evidence: freshness/degraded implementation and 81 tests. Corrected and accepted by `FA-006` (`2098af3`); final acceptance is in the canonical audit tracker. |

### Later — UX, accessibility, and maintainability

| ID | Status | Work | Acceptance criteria | Evidence |
| --- | --- | --- | --- | --- |
| `FS-013` | `DONE` | Consolidate Session and Path selectors on an accessible combobox/popover primitive. | Arrow navigation, typeahead, Escape, focus return, listbox semantics, screen readers, and reduced motion work consistently in both selectors. | Historical implementation evidence: shared combobox primitive and 96 tests. Corrected and accepted by `FA-007`; final component/browser acceptance is recorded under `FA-013` in the canonical audit tracker. |
| `FS-014` | `DONE` | Simplify toolbar hierarchy and responsive behavior. | Global view controls, canvas navigation, layout editing, and replay actions remain visually distinct without wrapping into ambiguous rows at supported breakpoints. | Historical implementation evidence: four toolbar domains and 101 tests. FA-013 adds accepted Chromium responsive/reduced-motion coverage; details are in the canonical audit tracker. |
| `FS-015` | `DONE` | Add density-aware topology modes. | Small sets render fully; medium sets cluster by source/branch; large sets aggregate and expand on focus while preserving visible hidden-item counts. | Historical implementation evidence: density-aware modes and 109 tests; no FA corrective item mapped to FS-015. |
| `FS-016` | `DONE` | Refactor the three oversized feature components. | Streaming, Audit/replay state, URL state, response actions, and layout math are isolated into testable hooks/modules; presentational components do not own unrelated data flow. | Historical implementation evidence: seven modular hooks and 122 tests. Corrected and accepted by `FA-012` commit chain; final ownership evidence is in the canonical audit tracker. |
| `FS-017` | `DONE` | Harden layout persistence. | Blocked/corrupt storage cannot crash rendering; stale entries are pruned or version-migrated; live and per-session Audit layouts remain isolated. | Historical implementation evidence: persistence hardening and 139 tests; no FA corrective item mapped to FS-017. |
| `FS-018` | `DONE` | Expand automated coverage. | Tests cover filter truth, pagination completeness, empty-history Response, URL restoration, topology limits, cluster selection, 2D fit, fullscreen/sidebar behavior, keyboard use, touch gestures, and reduced motion. | Historical implementation evidence: initial 158-test expansion. Corrected and accepted by `FA-007`, `FA-008`, and `FA-013`; final component/browser evidence is in the canonical audit tracker. |

## Product additions after the foundation is correct

These remain product backlog items and are not the active remediation focus.

| ID | Status | Addition | Acceptance criteria | Evidence |
| --- | --- | --- | --- | --- |
| `FS-019` | `DONE` | Time-based replay scrubber. | Shows real event time and gaps, supports jump/step/play, and does not imply uniform attacker timing. | Historical implementation evidence: initial time-aware scrubber and 164 tests. Corrected and accepted by `FA-009`; final component/browser evidence is recorded under `FA-013` in the canonical audit tracker. |
| `FS-020` | `TODO` | Focus controls. | Operator can focus a session or directory branch and return to live/global context in one predictable action. | Backlog; not part of FA-014. |
| `FS-021` | `TODO` | Exact historical transition overlay. | Repeated visits and lateral jumps are represented as actual event transitions rather than only first-visit node badges. | Backlog; not part of FA-014. |
| `FS-022` | `TODO` | Correlated command and file telemetry. | Command/file events are shown only when joined by authoritative identifiers, with provenance and explicit unavailable states. | Backlog; not part of FA-014. |
| `FS-023` | `TODO` | Forensic export and shareable evidence links. | Exported JSON/CSV preserves session, event IDs, timestamps, status, and filter scope; shared links open the same session/hop without embedding sensitive data. | Backlog; not part of FA-014. |
| `FS-024` | `IN PROGRESS` | Add a full-surface square radar treatment to Live topology. | Establish a 1000×1000 logical radar plane that fills the available Live panel; omit persistent inner and outer range-frame boxes and use canvas-edge ticks instead; add four short diagonal corner rays anchored at the actual responsive canvas corners with angles recalculated from each canvas width/height ratio so each ray stays collinear with the sweep from center to corner; connect opposing edge ticks with visible, continuous, perpendicular full-canvas crosshairs through the exact center and beneath the sweep; use a shared 2px stroke, primary color, opacity, and glow for both crosshairs and edge ticks; compute the sweep beam's first rectangle-boundary intersection as its angle turns; keep the multi-stop gradient wave in a 48-degree sector behind the crisp moving beam and restore its peak opacity to 0.48; omit the extra blurred bloom and static center haze, and retain a restrained glow attached to the beam; retain the solid 32×32 rounded-square primary-color emitter at the exact center, without an icon; animate two rounded-square waves from the center on a 5.6-second cycle, with both expanding more slowly and fading linearly over a longer interval at their extents; keep the outer wave faster than the delayed inner wave, fading at the 924-unit reach and 664-unit reach respectively; calculate wave corner radii from the responsive plane so their outlines match the canvas's rounded corners; disable the waves for reduced-motion users; render the full themed radar plane and overlay only when the live snapshot has no sessions; once a session exists, use the normal neutral map surface; omit the themed radar grid, axes, edge/corner ticks, sweep, and pulse outlines; render a neutral background grid only while View > Show background grid is enabled; omit the status title in the steady listening state while retaining operator-facing copy during loading/reconnect; derive grid, emitter, wave, edge-tick, and sweep colors from the system primary token (brick orange in light theme and bright brass in dark theme); keep the radar plane a solid untinted surface (white in light theme and the dark surface token in dark theme); keep corner marks decorative without adding telemetry, omit corner readouts; place retained-session count beside the Session Audit control, keep topology controls interactive, and leave Audit presentation unchanged. | Implemented in the local dashboard; the authenticated `/filesystem-activity` page returned HTTP 200. Screenshot review remains needed to confirm the themed standby treatment disappears on populated topology while the neutral grid still follows View > Show background grid. |

## Deferred outside this workstream

- Returning-attacker virtual filesystem continuity remains governed by
  [`design/returning-attacker-continuity.md`](design/returning-attacker-continuity.md).
- Customer appliance packaging and the outbound WSS gateway remain governed by
  [`HONEYPOT-PORTAL-INSTALLER-GUIDE.md`](HONEYPOT-PORTAL-INSTALLER-GUIDE.md).
- Do not expand the scoped Response surface beyond approved, allow-listed
  operations as part of a Filesystem UI change.

## Current validation and evidence policy

FA-015 was accepted `DONE` on `725102189587477bd9eafe13c8ac2d6e2e97e20c`.
FA-016 was accepted `DONE` at terminal implementation commit
`24586f20665564e8d4c58997d8c475791819db59` (`24586f2`). There is no active FA
remediation item, and FS-007 is `DONE` through FA-001, FA-002, FA-011, and
accepted FA-016. The manual/live response-agent validation remains unrelated,
outstanding, and not performed.

FA-016 implementation and follow-up re-audit evidence is recorded in
[`validation/FA-016-audit-scale.md`](validation/FA-016-audit-scale.md). The
isolated MongoDB command passed its 1,900-session dashboard and processor
coverage, including v1-to-v2 migration, monotonic interleavings, event-outbox
close races, rejected-observation ownership, old canonical/legacy writers, and
scoped overflow coverage, with separate item/count/summary and retention-repair
execution bounds recorded there. Retention coverage now also includes source
expiry normalization, raw stable repair keysets, resumable orphan cleanup, and
TTL-ordering/source-recreation races. The independent final re-audit accepted
FA-016 as DONE with no remaining blocking findings.

The current repository validation is the independent final FA-013 audit dated
2026-09-19 and is recorded in the canonical audit tracker. It ran these
reproducible commands: `cd dashboard-v2 && npm test`,
`cd dashboard-v2 && npm run test:browser`, `cd dashboard-v2 && npm run lint`,
`cd dashboard-v2 && npm run build`, and `go test -count=1 ./...` in each of the
five `agents/*` Go modules. It recorded 22 Vitest files with 460 passing and 2
skipped tests, 6/6 Chromium tests, zero ESLint errors/warnings, a passing
production build, all five Go modules passing, and `git diff --check` passing.
No manual/live validation was performed. The repository had no test-results or
playwright-report artifacts. These are current audit results, not replacement
claims about the 2026-09-15 historical baseline.

## Decision log

| Date | Decision | Reason |
| --- | --- | --- |
| 2026-09-24 | Live topology uses a `1000×1000` logical square radar plane centered within the responsive canvas; Audit retains its existing map treatment. | The range frames must stay square at any viewport ratio, while the radar grid can fill the complete Live workspace without implying geography or changing evidence. |
| 2026-09-24 | In the empty Live state, the radar plane expands to the remaining panel height and a sweep rotates from the center; reduced-motion preferences disable the sweep. | This uses the available workspace while preserving square geometry and avoiding animation for users who request reduced motion. |
| 2026-09-24 | Place the four accent ticks at the actual canvas edges; keep the square range frames centered. | Edge ticks should anchor the full responsive canvas even when the square radar plane is letterboxed by a wide viewport. |
| 2026-09-24 | Size the circular sweep using the measured canvas dimensions and render a fading trail behind its beam; keep the beam itself unglowed. | The scan should traverse the full responsive plane while its energy glow follows behind the leading line. |
| 2026-09-24 | Intersect every sweep ray with the rectangle boundary; shape the trailing wake from those per-angle endpoints and fade it by angular lag. | Beam length then reaches the first edge at every heading, and the wake stays strongest next to the beam even when it is short near a horizontal edge. |
| 2026-09-24 | Use an eased multi-stop opacity ramp for the Live radar wake and keep the dashed center axes low contrast beneath it. | The center axes remain intentional radar guides; reducing their contrast prevents them from reading as a dashed seam through the transparent end of the glow. |
| 2026-09-24 | Simplify the Live radar chrome to two square range frames, one outlined storage beacon, and no corner diagnostics; move retained-session access into the page's Session Audit controls. | This preserves the radar's orientation and retained-session action while giving the sweep and listening state more visual space. |
| 2026-09-25 | Pin the Live Radar beacon to the canvas's exact center, separate the listening copy beneath it, and animate one faint pulse ring with reduced-motion support. | The sweep visibly originates from the beacon; separating it from the status stack prevents the content block from shifting the source away from the geometric origin. |
| 2026-09-25 | Give only the `Listening for sessions` title a low-amplitude opacity breath on the emitter's 2.8-second rhythm; keep it static for reduced-motion users. | A restrained rhythm reinforces the waiting state while staying visually coordinated with the central emitter. |
| 2026-09-25 | Derive Live radar colors from the system primary and warning tokens, with a light surface treatment and a dark brass accent; update the Canvas sweep when the active theme changes. | The radar should read as part of the dashboard in both themes, and its grid, beacon, ticks, and animated wake should stay in one palette. |
| 2026-09-25 | Extend low-contrast perpendicular crosshairs from the Live canvas edges through the exact origin, enlarge the Radar emitter, and omit transport-layer status from the listening state. | The crosshairs connect the cardinal edge ticks to the sweep origin, while a more visible emitter anchors the otherwise open center; listening copy should describe the operator-facing state rather than its transport protocol. |
| 2026-09-25 | Match both full-canvas crosshair strokes to the 1.5px cardinal edge ticks and lower the sweep wake opacity and blur. | Equal stroke widths make the edge marks flow into the crosshair; a softer trail keeps the scan visible without reading as a broad fog. |
| 2026-09-25 | Keep the crosshairs at 1.5px and raise their primary-color contrast after visual review showed the previous lines were too faint. | The edge-to-edge perpendicular axes should be readily visible while their thin strokes preserve the radar's open center. |
| 2026-09-25 | Use one shared 2px accent stroke, opacity, and glow for edge ticks and full-canvas crosshairs after screenshot review showed they still looked unequal. | Matching the complete rendered treatment makes each crosshair appear to continue the short marker at its edge. |
| 2026-09-25 | Place four short diagonal registration marks at the actual corners of the responsive canvas, independently of the centered square range frame. | The corner cues should frame the full radar plane even when its square range frame is letterboxed inside a wider canvas. |
| 2026-09-25 | Extend diagonal corner marks to the straight canvas edges beyond the rounded corner cutouts. | The inset marks should visually meet the same canvas boundary as the cardinal center ticks without being clipped by the rounded corners. |
| 2026-09-25 | Aim short diagonal corner marks inward from each actual canvas corner at 45°. | Corner marks should read as rays emerging from the canvas corners rather than slashes crossing the border. |
| 2026-09-25 | Compute each corner ray's inward angle from the live canvas width and height so it is collinear with the center-to-corner radar sweep. | The rectangular canvas's diagonal angle changes with its aspect ratio; fixed 45° marks would diverge from the sweep except on a square canvas. |
| 2026-09-25 | Keep the existing gentle listening-title breath and reduce the trailing radar wake's peak opacity and blur again. | The status keeps its quiet breathing cue while a lighter wake leaves the rotating beam and center easier to read. |
| 2026-09-25 | Replace the central Radar icon and circular pulse with a solid rounded-square emitter and two rounded-square waves that land on the matching rounded range frames. | The emitter and double-beat pulse should follow the canvas geometry, keep exact alignment with both range frames, and stop animating for reduced-motion users. |
| 2026-09-15 | Start with `FS-001`; defer visual additions until Audit filtering is authoritative. | Incorrect result sets would invalidate later selection, count, and topology UX. |
| 2026-09-15 | Keep this tracker separate from design and validation evidence. | Work status changes frequently; architecture and evidence must remain durable and independently reviewable. |
| 2026-09-25 | Supersede the solid center emitter decision: keep the exact center open and let the paired rounded-square waves provide the only expanding center treatment. | The continuously repeating waves already define the radar origin and pulse; a persistent filled block obscures that open center. |
| 2026-09-25 | Correct the preceding refinement: retain the solid center emitter and remove the two persistent range-frame boxes; let the rounded-square waves define those extents only while each pulse is visible. | The requested removal referred to the static outer and inner boxes that the waves overlap, not the center emitter. |
| 2026-09-25 | Slow both rounded-square waves, extend their fades at full reach, and lengthen their repeating cycle to 5.6 seconds. | A slower expansion and longer linear fade make both pulses easier to follow, with the inner beat still delayed and slower than the outer beat. |
| 2026-09-25 | Remove the steady-state “Listening for sessions” title and sector-shaped sweep haze; keep only a soft glow on the moving radar line. | The open center stays clear, and the moving line remains the only source of beam glow. |
| 2026-09-25 | Clarify the sweep refinement: retain the gradient wave that follows behind the rotating line; remove only the extra bloom and static center haze. | The animated wake is part of the radar motion; the glow should stay localized to the beam without a broad blurred fog. |
| 2026-09-25 | Stop the radar beam and paired pulse outlines when the live snapshot contains a session; leave the grid and crosshairs as map context. | The animated scan is a standby treatment and should not compete with observed filesystem activity. |
| 2026-09-25 | Clarify the active-session state: hide the entire themed standby radar treatment, including grid, axes, edge ticks, and corner marks; use the normal map surface behind observed topology. | All decorative radar-plane elements belong to the empty/standby state, not the populated activity map. |
| 2026-09-25 | Keep the neutral background grid available on populated topology through View > Show background grid while hiding the themed standby radar grid and decoration. | The grid remains a user-controlled map aid; radar colors, axes, corner marks, sweep, and pulse waves remain limited to the empty standby state. |
| 2026-09-25 | Restore the stronger trailing sweep gradient with a 0.48 peak and remove the radar plane's color tint, using a solid white light-theme canvas. | The moving wake supplies its own localized brightness; dark theme keeps its solid dark surface. |
| 2026-09-19 | Accept FA-015 and move the sole remediation focus to FA-016; preserve FS-007 as PARTIAL. | Large-collection optimization is now the only remaining FA item; FS-007 cannot be accepted until FA-016 passes final audit. |

## Update log

| Date | Change | Evidence |
| --- | --- | --- |
| 2026-09-24 | Refined `FS-024`: expand the Live standby canvas to the available panel height and rotate a circular radar sweep about its center. | Next.js HMR compiled the edited modules; no host or telemetry behavior changed. |
| 2026-09-24 | Refined `FS-024`: move the four accent ticks from the centered square frame to the actual canvas edges. | HMR compilation and whitespace validation are recorded with the implementation entry; no host or telemetry behavior changed. |
| 2026-09-24 | Refined `FS-024`: extend the circular sweep to the full canvas and add a fading energy trail behind the beam. | HMR compilation is recorded with the implementation entry; no host or telemetry behavior changed. |
| 2026-09-24 | Refined `FS-024`: calculate beam and trail extents from the first boundary hit for every sweep angle. | HMR compilation is recorded with the implementation entry; no host or telemetry behavior changed. |
| 2026-09-24 | Refined `FS-024`: smooth the trailing glow with additional opacity stops, remove the extra fill pass, and soften the dashed axes behind the wake. | Next.js HMR compiled the edited modules; no host or telemetry behavior changed. |
| 2026-09-24 | Refined `FS-024`: reduce the range frames to two, simplify the origin to one outlined HardDrive icon, remove corner diagnostics, and move the retained-session shortcut beside Session Audit & Replay. | Next.js HMR compiled the edited modules; no host or telemetry behavior changed. |
| 2026-09-25 | Refined `FS-024`: replace the storage glyph with a centered Radar emitter, move status copy below the origin, and add one reduced-motion-aware pulse ring. | Next.js HMR compilation and whitespace validation are recorded with the implementation entry; no host or telemetry behavior changed. |
| 2026-09-25 | Refined `FS-024`: add a subtle 2.8-second opacity breath to the listening title and disable it for reduced motion. | Next.js HMR compiled the edited page; no host or telemetry behavior changed. |
| 2026-09-25 | Refined `FS-024`: replace the fixed green radar palette with the theme's brick-orange or bright-brass primary color across CSS and Canvas, and use theme-aware radar surfaces. | Next.js HMR and `git diff --check` results are recorded in the implementation log; no host or telemetry behavior changed. |
| 2026-09-25 | Refined `FS-024`: connect opposing edge ticks with subtle perpendicular crosshairs, enlarge the central Radar emitter, and remove transport details from the listening status. | HMR compilation and whitespace validation are recorded with the implementation entry; no host or telemetry behavior changed. |
| 2026-09-25 | Refined `FS-024`: set full-canvas crosshair thickness to match the edge ticks and reduce the sweep wake's opacity and bloom. | HMR compilation and whitespace validation are recorded with the implementation entry; no host or telemetry behavior changed. |
| 2026-09-25 | Refined `FS-024`: keep crosshairs at the edge ticks' 1.5px thickness and raise their color contrast for visibility. | HMR compilation and whitespace validation are recorded with the implementation entry; no host or telemetry behavior changed. |
| 2026-09-25 | Refined `FS-024`: share the same 2px accent stroke, opacity, and glow between edge ticks and the full-canvas crosshairs. | HMR compilation and whitespace validation are recorded with the implementation entry; no host or telemetry behavior changed. |
| 2026-09-25 | Refined `FS-024`: move the four diagonal corner marks to the actual canvas corners rather than the centered square frame. | HMR compilation and whitespace validation are recorded with the implementation entry; no host or telemetry behavior changed. |
| 2026-09-25 | Refined `FS-024`: extend each corner slash to touch the adjacent straight canvas edges beyond the rounded border radius. | HMR compilation and whitespace validation are recorded with the implementation entry; no host or telemetry behavior changed. |
| 2026-09-25 | Refined `FS-024`: rotate the four corner marks to radiate inward from the actual canvas corners at 45°. | HMR compilation and whitespace validation are recorded with the implementation entry; no host or telemetry behavior changed. |
| 2026-09-25 | Refined `FS-024`: calculate corner-ray angles from the responsive canvas dimensions so each matches the sweep's corner bearing. | HMR compilation and whitespace validation are recorded with the implementation entry; no host or telemetry behavior changed. |
| 2026-09-25 | Refined `FS-024`: preserve the breathing listening label and soften the wake with lower gradient opacity and blur. | HMR compilation and whitespace validation are recorded with the implementation entry; no host or telemetry behavior changed. |
| 2026-09-25 | Refined `FS-024`: replace the center icon and circular pulse with a solid rounded-square emitter and a fast outer / slower inner double-beat wave. | HMR compilation and whitespace validation are recorded with the implementation entry; no host or telemetry behavior changed. |
| 2026-09-25 | Refined `FS-024`: remove the persistent solid center emitter while retaining the paired rounded-square waves. | HMR compilation and whitespace validation are recorded with the implementation entry; no host or telemetry behavior changed. |
| 2026-09-25 | Refined `FS-024`: restore the solid center emitter and remove both persistent range-frame boxes while preserving the two animated waves. | HMR compilation and whitespace validation are recorded with the implementation entry; no host or telemetry behavior changed. |
| 2026-09-25 | Refined `FS-024`: lengthen the paired wave cycle to 5.6 seconds, slow both expansions, and extend their linear fade at full reach. | HMR compilation and whitespace validation are recorded with the implementation entry; no host or telemetry behavior changed. |
| 2026-09-25 | Refined `FS-024`: omit the steady listening label and broad sweep haze, leaving a glow around the moving radar line. | HMR compilation and whitespace validation are recorded with the implementation entry; no host or telemetry behavior changed. |
| 2026-09-25 | Refined `FS-024`: restore the low-opacity wave behind the sweep line while keeping the extra bloom and static center haze disabled. | HMR compilation and whitespace validation are recorded with the implementation entry; no host or telemetry behavior changed. |
| 2026-09-25 | Refined `FS-024`: hide the sweep and both pulse outlines whenever the live snapshot contains a session. | HMR compilation and whitespace validation are recorded with the implementation entry; no host or telemetry behavior changed. |
| 2026-09-25 | Refined `FS-024`: hide the entire radar plane and overlay when a session exists, returning to the neutral map surface. | HMR compilation and whitespace validation are recorded with the implementation entry; no host or telemetry behavior changed. |
| 2026-09-25 | Refined `FS-024`: restore the neutral background grid on populated topology and keep it controlled by View > Show background grid, with standby radar effects still hidden. | Next.js HMR compilation and `git diff --check` are recorded with the implementation entry; no host or telemetry behavior changed. |
| 2026-09-25 | Refined `FS-024`: restore a stronger 0.48-peak sweep wake and remove the tinted radar background, keeping a solid white light-theme plane. | Next.js HMR compilation and `git diff --check` are recorded with the implementation entry; no host or telemetry behavior changed. |
| 2026-09-24 | Started `FS-024`: define the standard square radar plane and add a live-only radar overlay to the topology canvas. | User requested the Live workspace use a full-screen square radar treatment; no telemetry or API contract changes are in scope. |
| 2026-09-19 | Continued only FA-016: made history projection an event-level durable outbox, separated current-state/history ownership, blocked rejected observed payloads from seeding or clearing readiness, and covered old canonical/legacy writers after the v2 marker. | Clean preflight at audited `60a73c4`; `git fetch origin --prune` succeeded; `origin/main` was already an ancestor; isolated integration passed 12 dashboard tests and executed 9 production FA-016 Mongo tests plus 2 target-safety tests; dashboard execution plans remained bounded and steady-state reconciliation performed zero `cwd_events` reads. Full dashboard tests, lint, build, diff check, and all five Go modules passed. FA-016 remains IN PROGRESS and FS-007 remains PARTIAL pending re-audit. |
| 2026-09-19 | Continued only FA-016: exact cursor-aware overflow composition, generation-owned readiness/CAS with bounded execution evidence, stale/late history crash recovery, padded canonical convergence, and deterministic race barriers. | Clean start at `5aeb4c0`; initial sandbox fetch failure and approved successful retry are recorded in validation evidence; `origin/main` was already an ancestor; dashboard baseline passed; isolated FA-016 integration passed 12 dashboard tests and six processor tests; full dashboard and five-module Go validation passed. FA-016 remains IN PROGRESS and FS-007 remains PARTIAL pending final re-audit. |
| 2026-09-19 | Accepted FA-015 on `725102189587477bd9eafe13c8ac2d6e2e97e20c` and continued FA-016 as the sole current focus; remediation commit `54c872b` was created without rewriting prior history; retained FS-007 as PARTIAL. | FA-015 validation is recorded in [`docs/validation/FA-015-change-hygiene.md`](validation/FA-015-change-hygiene.md); FA-016 remediation evidence is recorded in [`docs/validation/FA-016-audit-scale.md`](validation/FA-016-audit-scale.md) and remains pending final re-audit. |
| 2026-09-19 | Accepted FA-013 and reconciled this tracker to FA-014; qualified FS-007 as partial because FA-016 remains TODO and retained FS-020+ as backlog. | Accepted FA-013 chain and independent final audit evidence are recorded in `FILESYSTEM-ACTIVITY-AUDIT-FIXES.md`; FA-014 remains the sole current focus pending re-audit. |
| 2026-09-16 | Completed `FS-019`; started `FS-020`. | Historical implementation note: 164-test time-based scrubber result; superseded for corrective acceptance by FA-009 and FA-013. |
| 2026-09-16 | Completed `FS-018`; started `FS-019`. | Historical implementation note: 158-test foundation result; the “100% complete” wording and FA-014/FA-015/FA-016 focus state describe that earlier checkpoint and are superseded by the current backlog above. |
| 2026-09-15 | Created the live working state from the Filesystem Activity code/UX/logic review. | Historical baseline recorded above; its clean-tree statement applies only to that review point. |
| 2026-09-19 | Continued only FA-016: replaced the non-atomic source event counter with the indexed event outbox marker, closed failed-upsert/crash/concurrent-reconciler ownership gaps, and added exact dashboard pending-marker plan coverage. | Clean preflight at `7ef06f1`; fetch succeeded; `origin/main` `4390d88` was already an ancestor; implementation commits `53c9cc6` and `bd351b1`; isolated integration passed 12 dashboard tests and executed 11 production FA-016 Mongo tests plus 2 loopback-target safety tests with none skipped; full dashboard validation and all five Go modules passed. FA-016 remains IN PROGRESS and FS-007 remains PARTIAL pending re-audit. |
| 2026-09-19 | Continued only FA-016: made source-state TTL authoritative for projection retention, added bounded resumable repair and source-checked orphan cleanup, and covered projection-first deletion with concurrent reconciliation and exact projection facts. | Clean preflight at `5036d03`; fetch succeeded; `origin/main` `4390d88` was already the merge base; dashboard baseline passed before edits; isolated retention integration passed with no skipped FA-016 cases. FA-016 remains IN PROGRESS and FS-007 remains PARTIAL pending re-audit. |
| 2026-09-20 | Continued only FA-016: normalized eligible source expiry, replaced trimmed repair cursors with raw `(session field, _id)` keysets, made orphan cleanup resumable with source-recreation rechecks, made cursor CAS independent of BSON field order, and added bounded malformed-expiry migration. | Preflight started clean at `a479cc0`; fetch succeeded; `origin/main` `4390d88` was already the merge base; dashboard baseline passed; the isolated production Mongo run passed 15 FA-016 cases plus cursor/safety checks, with adversarial repair and cleanup plans bounded at 256 documents/keys. The first 20-repeat attempt lost its temporary MongoDB container mid-run; the replacement repeat result is recorded in the FA-016 validation evidence. FA-016 remains IN PROGRESS and FS-007 remains PARTIAL pending re-audit. |
| 2026-09-20 | Continued only FA-016: corrected repair readiness ownership by projecting all readiness fields and requiring exact generation equality with no pending/dirty markers; added canonical/legacy ownership and paused-writer race coverage. | Preflight started clean at `3015b8b`; fetch succeeded; `origin/main` `4390d88` was already the merge base; dashboard baseline passed; ownership, event-outbox, repair, cleanup, and dotted-CAS tests passed `-count=20` (`ok honeypot/processor-agent 86.808s`), and raw repair plans remained bounded at 256 documents/keys. FA-016 remains IN PROGRESS and FS-007 remains PARTIAL pending re-audit. |
| 2026-09-20 | Accepted FA-016 `DONE` at terminal implementation commit `24586f2`; no FA remediation item remains active, and accepted FA-016 completes FS-007 with FA-001, FA-002, and FA-011. | Independent re-audit reported no remaining blocking findings: isolated FA-016 MongoDB coverage passed 12/12 dashboard tests and the processor FA-016 suite; dashboard Vitest passed 463 with 14 skipped; ESLint, Next.js production build, all five Go modules, and `git diff --check` passed; targeted ownership/cursor coverage passed `-count=20`; no temporary Mongo containers or browser-test artifacts remained. Manual/live response-agent validation remains unrelated and outstanding. |
