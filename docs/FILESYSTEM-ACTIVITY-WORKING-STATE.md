---
title: Filesystem Activity live working state
status: active
last_updated: 2026-09-19
owner: Dashboard Filesystem workstream
---

# Filesystem Activity live working state

This document is the tactical source of truth for improving the Dashboard
Filesystem Activity experience. Update it in the same change that completes,
blocks, defers, or materially changes any tracked item.

The architectural contract remains in
[`dashboard-v2/docs/REALTIME_CWD_TRACKING.md`](../dashboard-v2/docs/REALTIME_CWD_TRACKING.md).
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
| `BLOCKED` | Cannot progress until the recorded dependency is resolved. |
| `DONE` | Acceptance criteria passed and evidence is recorded. |
| `DEFERRED` | Intentionally outside the current workstream. |

## Current focus

**In progress:** `FA-012` — establish explicit filesystem feature ownership boundaries.

**Why now:** The original `FS-016` hook extraction remains complete. This follow-up
remediation is not accepted yet: it is isolating the response-action controller,
replay timer, topology presentation, and shared page composition without changing
the original filesystem behavior contracts.

## Baseline

Reviewed on 2026-09-15 against the unmodified working tree after commit
`78ce21c`.

| Check | Result |
| --- | --- |
| Filesystem Vitest suites | Passed: 2 files, 9 tests |
| Filesystem-scoped ESLint | Passed |
| Next.js production build | Passed |
| Working tree after review | Clean |

The baseline passing does not close the findings below; current tests do not
cover their product semantics or browser interactions.

## Now — correctness and truthful UI

| ID | Status | Work | Acceptance criteria | Evidence |
| --- | --- | --- | --- | --- |
| `FS-001` | `DONE` | Replace client-inferred Audit filters with complete per-session audit summaries. | `homeOnly` and path-touch results include active and closed history, do not depend on the selected session's loaded page, and have unit/integration coverage. | Server `auditSummary` contract; 15 focused Vitest tests; scoped ESLint; Next production build (uncommitted). |
| `FS-002` | `DONE` | Make history completeness explicit. | API returns total/completeness metadata; Replay never claims to show all history while earlier pages remain unloaded; hop numbering stays stable as pages load. | API completeness contract; absolute-window regression tests; 18 focused Vitest tests; scoped ESLint; Next production build (uncommitted). |
| `FS-003` | `DONE` | Decouple Response and Command tabs from CWD-history state. | An authorized operator can inspect response capability and disconnect any eligible live session even when route history is empty, loading, or unavailable. | Independent sidebar content gating; full 29-test Vitest suite; full ESLint; Next production build (uncommitted). |
| `FS-004` | `DONE` | Expose topology render limits. | UI shows rendered versus available sources/paths and offers a clear way to focus or expand omitted data; no limit is silent. | Rendered vs available indicators in footer & sidebar with Show all / Compact controls; selectedSessionId prioritization; rail gap relaxation; 37 Vitest tests, ESLint, and Next production build passed. |
| `FS-005` | `DONE` | Resolve filtered-selection semantics. | A `0/N` result cannot look like a matching topology; either clear the selection into a filter empty state or label the retained item prominently as pinned outside the result set. | Filtered-selection and 0/N empty state resolved; prominent 'Pinned outside filter' banner on canvas; contextual empty states in TopologyCanvas and AuditSessionSelect; 40 Vitest tests, ESLint, and Next production build passed. |
| `FS-006` | `DONE` | Synchronize Audit navigation state with the URL. | View, session, filters, and selected hop survive reload/share; Back and Forward restore coherent state; expired session links show a specific state instead of silently choosing another session. | Full URL state synchronization (`view`, `sessionId`, `hideHome`, `targetPath`, `hop`) with `popstate` support, danger banner for expired sessions without silent hijacking; 49 Vitest tests, ESLint, and Next production build passed. |

## Next — data flow, scale, and topology behavior

| ID | Status | Work | Acceptance criteria | Evidence |
| --- | --- | --- | --- | --- |
| `FS-007` | `DONE` | Split live topology transport from the closed-session Audit directory. | Live SSE no longer queries and rebroadcasts the full retained closed-session list on every CWD update; Audit sessions are searchable and paginated. | Live SSE closed buffer decoupled to 12 items with in-memory immutable audit path cache; dedicated keyset-paginated & regex searchable `/api/filesystem-topology/audit-sessions` endpoint; remote audit session lookup & pagination in AuditSessionSelect and FilesystemActivity; 54 Vitest tests, ESLint, and Next production build passed. |
| `FS-008` | `DONE` | Define multi-session IP cluster interaction. | A cluster exposes every active session and path without implying that the latest path is the only route; selection behavior is deterministic and keyboard accessible. | Cluster sessions and targetPaths exposed in callouts; multi-route leader lines rendered on canvas & minimap; accessible keyboard navigation (Arrow/Escape/Enter) in callout cards; cluster accordion in SessionSourceList; sibling sessions switcher in FilesystemInspector; 57 Vitest tests, ESLint, and Next production build passed. |
| `FS-009` | `DONE` | Replace the fit algorithm with two-dimensional world bounds. | Fit considers X/Y, rendered element sizes, manual positions outside `0..100`, minimap clearance, and compact/fullscreen canvas sizes. | Two-dimensional world bounds & viewport fit implemented; considers X and Y, rendered element sizes, manual coordinates outside 0..100 without clamping, minimap clearance, and compact/fullscreen canvas sizes; 63 Vitest tests, ESLint, and Next production build passed. |
| `FS-010` | `DONE` | Correct count semantics. | Labels distinguish unique sources, sessions, exact-path sessions, and descendant-branch sessions; badges and their resulting lists always agree. | Unified count semantics implemented via `getDirectorySessionCounts`; node badge shows exact (branch) or ↳branch with detailed tooltip; footer distinguishes unique sources from active sessions; Directory inspector features summary metric cards (Exact, In subdirs, Unique sources), matching tab badges, and exact/subdir row tags; 68 Vitest tests, ESLint, and Next production build passed. |
| `FS-011` | `DONE` | Reduce response-action polling cost. | Pending actions do not perform a Pi health check plus multiple MongoDB reads every second; status propagation has bounded backoff or an event stream and preserves terminal-state feedback. | In-memory TTL caching (10s) on `responseControlHealthy` bypasses outbound Pi health pings on capability probes; single-pass `getTerminateActionWithState` eliminates redundant MongoDB reads across collections; `ResponseActionLifecycleManager` enforces an identity-preserving lifecycle with monotonic backoff (1.5x up to 3.5s, 24s ceiling) that preserves current delay across live-to-closed `sessionIsLive` transitions without resetting backoff; persistent terminal toasts (verified, failed, timeout) preserved; Vitest test suite, ESLint, and Next production build passed. |
| `FS-012` | `DONE` | Add freshness and degraded-state semantics. | Connected transport and fresh data are distinguishable; UI shows last update age, stale threshold, retry actions, and recovery without discarding the last valid snapshot. | Separated transport stream status from data freshness classification (fresh/stale/degraded/offline); guaranteed non-discarding retained snapshot on error/reconnect; floating degraded banner with update age, stale threshold, and immediate HTTP refresh / SSE reconnect controls; header transport badge and freshness badge with live age ticker; 81 Vitest tests, zero-warning ESLint, and Next.js production build passed. |

## Later — UX, accessibility, and maintainability

| ID | Status | Work | Acceptance criteria | Evidence |
| --- | --- | --- | --- | --- |
| `FS-013` | `DONE` | Consolidate Session and Path selectors on an accessible combobox/popover primitive. | Arrow navigation, typeahead, Escape, focus return, listbox semantics, screen readers, and reduced motion work consistently in both selectors. | Unified accessible ComboboxPopover primitive and useComboboxNavigation hook with WAI-ARIA listbox semantics, circular ArrowDown/ArrowUp and Home/End navigation, multi-character typeahead buffer, focus return, outside-click detection, and useReducedMotion support; adopted across AuditFilterControls (Path selector) and AuditSessionSelect (Session selector); 96 Vitest tests, zero-warning ESLint, and Next production build passed. |
| `FS-014` | `DONE` | Simplify toolbar hierarchy and responsive behavior. | Global view controls, canvas navigation, layout editing, and replay actions remain visually distinct without wrapping into ambiguous rows at supported breakpoints. | Four distinct toolbar domains (Global view controls, Canvas navigation, Layout editing, Replay actions) separated into semantic containers with WAI-ARIA roles (toolbar, group, tablist, region) and accessible labels; Canvas navigation (Zoom In/Out/%, Fit view, Center IP) and Layout editing (Explore/Arrange, Undo, Options menu) encapsulated in atomic non-wrapping pill groups; Replay controls structured with dedicated scrubber, panel toggle, and fullscreen actions across mobile, tablet, and widescreen breakpoints; 101 Vitest tests, zero-warning ESLint, and Next.js production build passed. |
| `FS-015` | `DONE` | Add density-aware topology modes. | Small sets render fully; medium sets cluster by source/branch; large sets aggregate and expand on focus while preserving visible hidden-item counts. | Density-aware topology modes (`detailed` <= 15 nodes / 4 sources, `clustered` <= 42 nodes / 10 sources, `aggregated` > 42 nodes / 10 sources) with `auto` preference; expand-on-focus subtree expansion; truthful node `hiddenChildCount` badges (`+N`) and footer breakdown (`N of Total paths (M aggregated in branches)`) with `Expand all` and `Reset to auto` actions; accessible Density mode toolbar group; 109 Vitest tests (8 new density tests), zero-warning ESLint, and Next.js production build passed. |
| `FS-016` | `DONE` | Refactor the three oversized feature components. | Streaming, Audit/replay state, URL state, response actions, and layout math are isolated into testable hooks/modules; presentational components do not own unrelated data flow. | Isolated 7 custom hooks (`useFilesystemStreaming`, `useSessionCwdHistory`, `useFilesystemUrlState`, `useAuditReplay`, `useResponseAction`, `useTopologyViewport`, `useTopologyArrange`); decoupled oversized feature components; 122 Vitest tests (12 new hook helper tests) passed 100%, zero ESLint warnings/errors, Next.js production build passed. |
| `FS-017` | `DONE` | Harden layout persistence. | Blocked/corrupt storage cannot crash rendering; stale entries are pruned or version-migrated; live and per-session Audit layouts remain isolated. | Resilient `layoutPersistence` module with `getLocalStorageSafe` SecurityError protection, schema envelope v1 and zero-loss legacy v0 migration, finite coordinate bounds validation (±400), isolated Live and per-session Audit storage keys, and 14-day / 30-entry auto-pruning with QuotaExceeded retry; 139 Vitest tests (17 new persistence tests) passed 100%, zero-warning ESLint, clean Next.js production build passed. |
| `FS-018` | `DONE` | Expand automated coverage. | Tests cover filter truth, pagination completeness, empty-history Response, URL restoration, topology limits, cluster selection, 2D fit, fullscreen/sidebar behavior, keyboard use, touch gestures, and reduced motion. | Expanded automated test suite in `tests/filesystem-coverage-expansion.test.ts` (19 tests) covering filter truth (`isHomeOnlySession`, `sessionTouchesPath`, `getDistinctSessionPaths`), session selection anti-hijacking, replay boundary clamping & failure route anchoring, empty-history terminate capability resolution, URL roundtrip fidelity, 2D world bounds & minimap clearance fit, responsive sidebar clamping (360–760px / 65%), arrow key pan steps, touch pinch scaling, and reduced motion duration; 158 Vitest tests passed 100%, zero-warning ESLint, clean Next.js production build. |

## Product additions after the foundation is correct

| ID | Status | Addition | Acceptance criteria | Evidence |
| --- | --- | --- | --- | --- |
| `FS-019` | `DONE` | Time-based replay scrubber. | Shows real event time and gaps, supports jump/step/play, and does not imply uniform attacker timing. | Time-aware forensic scrubber with interactive range slider, dual progress indication (step + time elapsed), dwell interval badges and pause detection (>60s) in timeline list, dynamic realistic playback pacing (delays scale with real dwell time clamped 300ms–3200ms) with realistic vs uniform mode toggle; 164 Vitest tests (6 new time helper & pacing tests) passed 100%, zero ESLint warnings, clean Next.js production build. |
| `FS-020` | `TODO` | Focus controls. | Operator can focus a session or directory branch and return to live/global context in one predictable action. | — |
| `FS-021` | `TODO` | Exact historical transition overlay. | Repeated visits and lateral jumps are represented as actual event transitions rather than only first-visit node badges. | — |
| `FS-022` | `TODO` | Correlated command and file telemetry. | Command/file events are shown only when joined by authoritative identifiers, with provenance and explicit unavailable states. | — |
| `FS-023` | `TODO` | Forensic export and shareable evidence links. | Exported JSON/CSV preserves session, event IDs, timestamps, status, and filter scope; shared links open the same session/hop without embedding sensitive data. | — |

## Deferred outside this workstream

- Returning-attacker virtual filesystem continuity remains governed by
  [`design/returning-attacker-continuity.md`](design/returning-attacker-continuity.md).
- Customer appliance packaging and the outbound WSS gateway remain governed by
  [`HONEYPOT-PORTAL-INSTALLER-GUIDE.md`](HONEYPOT-PORTAL-INSTALLER-GUIDE.md).
- Do not expand the scoped Response surface beyond approved, allow-listed
  operations as part of a Filesystem UI change.

## Decision log

| Date | Decision | Reason |
| --- | --- | --- |
| 2026-09-15 | Start with `FS-001`; defer visual additions until Audit filtering is authoritative. | Incorrect result sets would invalidate later selection, count, and topology UX. |
| 2026-09-15 | Keep this tracker separate from design and validation evidence. | Work status changes frequently; architecture and evidence must remain durable and independently reviewable. |

## Update log

| Date | Change | Evidence |
| --- | --- | --- |
| 2026-09-15 | Created the live working state from the Filesystem Activity code/UX/logic review. | Baseline checks recorded above. |
| 2026-09-15 | Started `FS-001`. | Implementation and validation in progress. |
| 2026-09-15 | Completed `FS-001`; started `FS-002`. | Filter regression tests, scoped ESLint, and production build passed. |
| 2026-09-15 | Completed `FS-002`; started `FS-003`. | Completeness/absolute-hop regression tests, scoped ESLint, and production build passed. |
| 2026-09-15 | Completed `FS-003`; started `FS-004`. | Full 29-test suite, full ESLint, and production build passed; compact graph limit paths inspected. |
| 2026-09-15 | Completed `FS-004`; started `FS-005`. | Full 37-test suite, full ESLint, and Next production build passed; render limit controls verified. |
| 2026-09-15 | Completed `FS-005`; started `FS-006`. | Full 40-test suite, full ESLint, and Next production build passed; pinned outside filter & 0/N empty states verified. |
| 2026-09-15 | Completed `FS-006`; started `FS-007`. | Full 49-test suite, full ESLint, and Next production build passed; URL sync, popstate, and session expiration verified. |
| 2026-09-16 | Completed `FS-007`; started `FS-008`. | Full 54-test suite, full ESLint, and Next production build passed; live SSE buffer decoupled to 12 items with in-memory caching, keyset pagination & remote search endpoint implemented, deep-link remote lookup verified. |
| 2026-09-16 | Completed `FS-008`; started `FS-009`. | Full 57-test suite, full ESLint, and Next production build passed; multi-session cluster callout disclosure, leader lines to all active routes, sibling inspector switcher, and keyboard navigation verified. |
| 2026-09-16 | Completed `FS-009`; started `FS-010`. | Full 63-test suite, full ESLint, and Next production build passed; 2D world bounds, unscaled plane pixel fitting, Y-centering, element bounds inclusion, and minimap clearance verified. |
| 2026-09-16 | Completed `FS-010`; started `FS-011`. | Full 68-test suite, full ESLint, and Next production build passed; exact vs descendant count semantics, matching directory inspector badges/cards, and ↳branch badges verified. |
| 2026-09-16 | Completed `FS-011`; started `FS-012`. | Full 70-test suite, full ESLint, and Next production build passed; Pi health TTL caching, single-pass action state read, bounded exponential polling backoff, and SSE sessionIsLive acceleration verified. |
| 2026-09-16 | Completed `FS-012`; started `FS-013`. | Full 81-test suite, full zero-warning ESLint, and Next production build passed; transport vs data freshness separation, retained snapshot on error/reconnect, degraded banner with refresh/reconnect actions verified. |
| 2026-09-16 | Completed `FS-013`; started `FS-014`. | Full 96-test suite (15 new combobox unit tests), zero-warning ESLint, and Next production build passed; unified ComboboxPopover primitive and circular typeahead navigation verified. |
| 2026-09-16 | Completed `FS-014`; started `FS-015`. | Full 101-test suite (5 new toolbar hierarchy tests), zero-warning ESLint, and Next production build passed; 4 distinct toolbar domains, atomic non-wrapping groups, and responsive breakpoint behavior verified. |
| 2026-09-16 | Completed `FS-015`; started `FS-016`. | Full 109-test suite (8 new density tests), zero-warning ESLint, and Next.js production build passed; density-aware modes, expand-on-focus subtree expansion, and hidden-item counts verified. |
| 2026-09-16 | Completed `FS-016`; started `FS-017`. | Full 122-test suite (12 new hook unit tests), zero-warning ESLint, and Next.js production build passed; isolated 7 modular hooks, cleanly decoupled FilesystemActivity, TopologyCanvas, and CwdRouteHistory. |
| 2026-09-16 | Completed `FS-017`; started `FS-018`. | Full 139-test suite (17 new persistence tests), zero-warning ESLint, and Next.js production build passed; hardened layout persistence with SecurityError safety, versioned envelopes, bounds validation, isolated keys, and 14-day auto-pruning. |
| 2026-09-16 | Completed `FS-018`; started `FS-019`. | Full 158-test suite (19 new comprehensive coverage tests), zero-warning ESLint, and Next.js production build passed; foundational roadmap (FS-001 through FS-018) 100% complete. |
| 2026-09-16 | Completed `FS-019`; started `FS-020`. | Full 164-test suite (6 new time replay tests), zero-warning ESLint, and Next.js production build passed; time-based scrubber, dwell intervals, dynamic proportional pacing, and interactive scrub range slider verified. |
