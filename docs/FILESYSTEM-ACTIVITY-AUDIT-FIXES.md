---
title: Filesystem Activity audit remediation
status: active
last_updated: 2026-09-16
owner: Dashboard Filesystem workstream
source_review: FS-001 through FS-019 audit
---

# Filesystem Activity audit remediation

This document is the implementation checklist for issues discovered while
auditing the uncommitted FS-001 through FS-019 work. It is intentionally
separate from `FILESYSTEM-ACTIVITY-WORKING-STATE.md` so the original roadmap
and the corrective work are not conflated.

## Working rules

- Address items in priority order unless a dependency is recorded.
- Keep only one item `IN PROGRESS` unless work is intentionally parallelized.
- Do not mark an item `DONE` from compilation or helper-unit tests alone.
- Record browser/component-level evidence where the acceptance criteria concern
  focus, keyboard input, URL history, responsive layout, or animation.
- Preserve the existing live topology behavior while correcting Audit directory
  semantics.
- Update `FILESYSTEM-ACTIVITY-WORKING-STATE.md` after a remediation changes the
  completion status or evidence of an original FS item.
- Do not include credentials, raw attacker data, or private management addresses
  in validation artifacts.

## Status legend

| Status | Meaning |
| --- | --- |
| `TODO` | Accepted remediation that has not started. |
| `IN PROGRESS` | Current implementation or validation focus. |
| `BLOCKED` | Cannot proceed until the recorded dependency is resolved. |
| `DONE` | Acceptance criteria passed and evidence is recorded. |

## Current focus

**In progress:** `FA-001` — make Audit directory filtering and counts authoritative.

## Remediation backlog

| ID | Priority | Status | Original items | Problem | Acceptance criteria | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| `FA-001` | `P0` | `IN PROGRESS` | `FS-001`, `FS-005`, `FS-007` | Audit filter options, `0/N`, totals, and path counts are calculated from the live snapshot plus only 12 recent closed sessions. Remote results remain local to the selector. | Audit totals and filtered results include the complete retained closed-session directory; remote pages become part of one authoritative parent data model; selected/pinned semantics and path options agree with the result set. | — |
| `FA-002` | `P0` | `TODO` | `FS-007` | `hideHome` and `targetPath` are applied after MongoDB pagination, while `totalItems` and `nextCursor` describe the unfiltered query. | Filtering occurs before page slicing, or pagination iterates until it produces a truthful filtered page; `items`, `totalItems`, and `nextCursor` share the same filter scope; empty intermediate pages cannot hide later matches. | — |
| `FA-003` | `P0` | `TODO` | `FS-011` | Response-action polling restarts its effect whenever a new action object is stored, resetting delay and the client deadline. A pending non-live action can poll near 100 ms intervals. | A single polling lifecycle survives state updates; delay increases monotonically to the configured ceiling; polling stops at terminal state or the bounded deadline; changing selected session aborts the prior lifecycle; terminal feedback remains visible. | — |
| `FA-004` | `P0` | `TODO` | `FS-011` | Status polling can expose a false capability error when the 10-second Pi-health cache expires, and each poll still reads action and session state separately. | Pending-action status remains truthful after cache expiry without producing Pi health ping storms; database work per poll is documented and minimized; tests use fake timers to assert request cadence, total requests, timeout, abort, and terminal behavior. | — |
| `FA-005` | `P0` | `TODO` | `FS-006` | A shared `hop` URL is checked only against the first 80 history events and then discarded. | A deep link resolves a retained hop on any page, either through direct event lookup or bounded cursor traversal; invalid/expired hop IDs produce an explicit state; request cancellation and maximum work are defined. | — |
| `FA-006` | `P1` | `TODO` | `FS-012` | Freshness age uses snapshot response-generation time rather than the latest authoritative telemetry timestamp. Manual refresh can make old telemetry appear fresh, and a valid empty snapshot is treated as absent/offline. | Transport state, snapshot retrieval time, and telemetry observation time are separate fields; refresh does not reset telemetry age; an empty valid snapshot can be live and fresh; stale/recovery labels have deterministic tests. | — |
| `FA-007` | `P1` | `TODO` | `FS-013`, `FS-018` | Arrow keys on a closed combobox trigger try to focus unmounted options without opening the popover. The listbox owns search and action controls that are not options. | ArrowDown/ArrowUp open the popover and place focus predictably; Escape and selection restore trigger focus; ARIA ownership follows the chosen combobox/listbox pattern; Session and Path selectors pass keyboard and screen-reader-oriented component tests. | — |
| `FA-008` | `P1` | `TODO` | `FS-006`, `FS-018` | Filter and hop changes use `replaceState`, so Back/Forward cannot traverse user navigation between these states. | User-initiated view, session, filter, and hop changes create intentional history entries without flooding history during automatic synchronization or playback; Back/Forward restore a coherent UI and do not trigger loops. | — |
| `FA-009` | `P1` | `TODO` | `FS-019` | Replay exposes real timestamps, but the scrubber thumb is positioned by hop index, implying uniform spacing. Partial history also displays a duration without identifying it as partial. | Scrubber position maps to elapsed event time, with a documented strategy for equal/missing timestamps; stepping remains hop-based; partial durations are explicitly labelled until retained history is complete; uneven-gap browser tests verify thumb position. | — |
| `FA-010` | `P1` | `TODO` | `FS-002` | History `hasMore` is computed after malformed documents are normalized away, while counts are based on raw documents. | Pagination cursor, page completeness, and totals are based on the same valid-event contract; malformed legacy records cannot end pagination early or create an unreachable remainder. | — |
| `FA-011` | `P2` | `TODO` | `FS-007` | The process-wide closed-session audit-path cache has no size or expiry bound. Searching historical pages grows it for the lifetime of the server process. | Cache has an explicit memory bound or expiry policy; eviction cannot corrupt immutable-session results; cache behavior and operational trade-offs are documented and tested. | — |
| `FA-012` | `P2` | `TODO` | `FS-016` | Hooks were extracted, but the three feature components remain oversized and `CwdRouteHistory` still owns response-action data flow alongside replay presentation. | Response actions, replay orchestration, topology rendering, and page composition have explicit ownership; presentational components receive data/actions through focused props; refactor does not duplicate timers or requests. | — |
| `FA-013` | `P1` | `TODO` | `FS-018` | Current tests predominantly exercise exported helper functions and do not verify the browser/component behaviors claimed by FS-006, FS-013, FS-014, FS-018, and FS-019. | Add component/browser coverage for remote filtered pagination, deep links beyond page one, Back/Forward, combobox focus and keys, polling cadence, empty valid topology, responsive toolbar behavior, reduced motion, and a time-positioned scrubber. | — |
| `FA-014` | `P2` | `TODO` | Tracker hygiene | Working-state metadata/current focus disagree with the completion table, and recorded “clean” evidence does not match the current working tree. | Tracker has one current focus, current date, truthful statuses, and evidence tied to reproducible commands or validation notes; original FS items affected by this audit are reopened or labelled partial. | — |
| `FA-015` | `P2` | `TODO` | Change hygiene | `git diff --check` reports blank-line-at-EOF errors and the full FS-001–FS-019 implementation exists as one large uncommitted change. | `git diff --check`, tests, lint, and production build pass; changes are reviewed and committed in recoverable logical units without overwriting unrelated user work. | — |

## Required validation gate

Before declaring this audit remediation complete, record results for all of the
following:

1. `git diff --check`
2. `npm test`
3. `npm run lint`
4. `npm run build`
5. Component/browser tests covering the interaction criteria in `FA-013`
6. Manual smoke test with more than 12 closed sessions and more than 80 history events
7. Manual response-action test confirming bounded request cadence and terminal feedback

## Audit baseline

Recorded on 2026-09-16 before remediation:

| Check | Result |
| --- | --- |
| Vitest | Passed: 9 files, 164 tests |
| ESLint | Passed |
| Next.js production build | Passed |
| `git diff --check` | Failed: three blank-line-at-EOF findings |
| Browser/component interaction coverage | Insufficient for the claimed acceptance criteria |
| Working tree | Large uncommitted FS-001–FS-019 change set |

## Update log

| Date | Change | Evidence |
| --- | --- | --- |
| 2026-09-16 | Created remediation checklist from the FS-001 through FS-019 audit. | Static code review plus baseline test, lint, build, and diff checks. |
