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

**In progress:** `FA-002` — filter audit sessions before pagination.

## Remediation backlog

| ID | Priority | Status | Original items | Problem | Acceptance criteria | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| `FA-001` | `P0` | `BLOCKED` | `FS-001`, `FS-005`, `FS-007` | Audit filter options, `0/N`, totals, and path counts are calculated from the live snapshot plus only 12 recent closed sessions. Remote results remain local to the selector. | Audit totals and filtered results include the complete retained closed-session directory; remote pages become part of one authoritative parent data model; selected/pinned semantics and path options agree with the result set. | Follow-up remediation on commit `d4b96d5`: scope-safe search lifecycle (aborting and clearing search on filter scope change, rejecting mismatched search cursors, cancelling pending debounce timers on dropdown close or clear); strict gating of summary metrics (`totalSessions`, `homeOnlyCount`, `matchingCount`, `distinctPaths`) ensuring only `summaryStatus === "success"` matching `currentScopeKey` can be used; `auditDirectoryTotalCount` cannot reintroduce stale summary; HTTP 2xx invalid payload handling exits loading with an error; deterministic JSON tuple scope key `[hideHome, targetPath, q]` round-tripping delimiters and Unicode; 32 regression tests in `filesystem-audit-directory.test.ts` (196 passing tests total, 0 ESLint warnings/errors, clean build, clean git diff --check; tests cover query builders, store state machines, and normalization helpers without claiming live MongoDB pipeline runtime coverage). BLOCKED on FA-002 acceptance, since its implementation is accepted but final authoritative-directory acceptance depends on truthful server pagination. |
| `FA-002` | `P0` | `IN PROGRESS` | `FS-007` | `hideHome` and `targetPath` are applied after MongoDB pagination, while `totalItems` and `nextCursor` describe the unfiltered query. | Filtering occurs before page slicing, or pagination iterates until it produces a truthful filtered page; `items`, `totalItems`, and `nextCursor` share the same filter scope; empty intermediate pages cannot hide later matches. Note: the audit-session cursor currently compares an ISO string with `lifecycle.closedAt` stored by Go as BSON Date; this must be corrected and integration-tested during FA-002. | Unified MongoDB aggregation pipeline (`buildAuditSessionsPipeline`, `buildAuditSummaryPipeline`, `buildAuditScopingStages`); filtering applied in MongoDB before facet pagination; keyset cursor decoded to real BSON Date objects and effectiveSessionId tie-breaker; legacy session_id unified across search, sort, cursor comparison, and returned documents; totalItems reflects complete filtered scope; 18 regression tests in `filesystem-audit-pipeline.test.ts` covering all 13 audit scenarios (214 tests passing across 11 files, clean lint, clean build, clean git diff --check). No live MongoDB daemon was run; pipeline query builders and fixture-level execution tested. |
| `FA-003` | `P0` | `TODO` | `FS-011` | Response-action polling restarts its effect whenever a new action object is stored, resetting delay and the client deadline. A pending non-live action can poll near 100 ms intervals. | A single polling lifecycle survives state updates; delay increases monotonically to the configured ceiling; polling stops at terminal state or the bounded deadline; changing selected session aborts the prior lifecycle; terminal feedback remains visible. | — |
| `FA-004` | `P0` | `TODO` | `FS-011` | Status polling can expose a false capability error when the 10-second Pi-health cache expires, and each poll still reads action and session state separately. | Pending-action status remains truthful after cache expiry without producing Pi health ping storms; database work per poll is documented and minimized; tests use fake timers to assert request cadence, total requests, timeout, abort, and terminal behavior. | — |
| `FA-005` | `P0` | `TODO` | `FS-006` | A shared `hop` URL is checked only against the first 80 history events and then discarded. | A deep link resolves a retained hop on any page, either through direct event lookup or bounded cursor traversal; invalid/expired hop IDs produce an explicit state; request cancellation and maximum work are defined. | — |
| `FA-006` | `P1` | `TODO` | `FS-012` | Freshness age uses snapshot response-generation time rather than the latest authoritative telemetry timestamp. Manual refresh can make old telemetry appear fresh, and a valid empty snapshot is treated as absent/offline. | Transport state, snapshot retrieval time, and telemetry observation time are separate fields; refresh does not reset telemetry age; an empty valid snapshot can be live and fresh; stale/recovery labels have deterministic tests. | — |
| `FA-007` | `P1` | `TODO` | `FS-013`, `FS-018` | Arrow keys on a closed combobox trigger try to focus unmounted options without opening the popover. The listbox owns search and action controls that are not options. Note: AuditSessionSelect currently has duplicated close cleanup/onClearSearch paths; cleanup to be addressed during FA-007. | ArrowDown/ArrowUp open the popover and place focus predictably; Escape and selection restore trigger focus; ARIA ownership follows the chosen combobox/listbox pattern; Session and Path selectors pass keyboard and screen-reader-oriented component tests. | — |
| `FA-008` | `P1` | `TODO` | `FS-006`, `FS-018` | Filter and hop changes use `replaceState`, so Back/Forward cannot traverse user navigation between these states. | User-initiated view, session, filter, and hop changes create intentional history entries without flooding history during automatic synchronization or playback; Back/Forward restore a coherent UI and do not trigger loops. | — |
| `FA-009` | `P1` | `TODO` | `FS-019` | Replay exposes real timestamps, but the scrubber thumb is positioned by hop index, implying uniform spacing. Partial history also displays a duration without identifying it as partial. | Scrubber position maps to elapsed event time, with a documented strategy for equal/missing timestamps; stepping remains hop-based; partial durations are explicitly labelled until retained history is complete; uneven-gap browser tests verify thumb position. | — |
| `FA-010` | `P1` | `TODO` | `FS-002` | History `hasMore` is computed after malformed documents are normalized away, while counts are based on raw documents. | Pagination cursor, page completeness, and totals are based on the same valid-event contract; malformed legacy records cannot end pagination early or create an unreachable remainder. | — |
| `FA-011` | `P2` | `TODO` | `FS-007` | The process-wide closed-session audit-path cache has no size or expiry bound. Searching historical pages grows it for the lifetime of the server process. | Cache has an explicit memory bound or expiry policy; eviction cannot corrupt immutable-session results; cache behavior and operational trade-offs are documented and tested. | — |
| `FA-012` | `P2` | `TODO` | `FS-016` | Hooks were extracted, but the three feature components remain oversized and `CwdRouteHistory` still owns response-action data flow alongside replay presentation. | Response actions, replay orchestration, topology rendering, and page composition have explicit ownership; presentational components receive data/actions through focused props; refactor does not duplicate timers or requests. | — |
| `FA-013` | `P1` | `TODO` | `FS-018` | Current tests predominantly exercise exported helper functions and do not verify the browser/component behaviors claimed by FS-006, FS-013, FS-014, FS-018, and FS-019. Note: AuditSessionSelect debounce test currently mirrors behavior rather than rendering the component; full component/browser rendering tests to be added under FA-013. | Add component/browser coverage for remote filtered pagination, deep links beyond page one, Back/Forward, combobox focus and keys, polling cadence, empty valid topology, responsive toolbar behavior, reduced motion, and a time-positioned scrubber. | — |
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
| 2026-09-16 | Remediated FA-002 (in progress): filter audit sessions before pagination, unify scoping pipeline between sessions and summary, decode BSON Date cursors, support legacy session_id, and test execution fixture semantics. | 11 test files / 214 tests passing; clean ESLint (0 errors, 0 warnings); clean Next.js build; clean git diff --check. |
| 2026-09-16 | Follow-up FA-001: closed audit scope gaps, made search lifecycle scope-safe, gated summary metrics on active scope match, replaced scope key with deterministic JSON tuple, and added regression tests. | 10 test files / 196 tests passing; clean ESLint (0 errors, 0 warnings); clean Next.js build; clean git diff --check. |
| 2026-09-16 | Follow-up FA-001 (in progress): isolated search dropdown options from authoritative state, added generation guards, and implemented MongoDB facet pipeline. | 10 test files / 190 tests passing; clean ESLint; clean Next.js build; clean git diff --check. |
| 2026-09-16 | Remediated FA-001 (in progress): made Audit directory filtering, totals, and path options authoritative. | 10 test suites / 176 Vitest tests passing; zero-warning ESLint; Next.js production build clean; clean git diff --check. |
| 2026-09-16 | Created remediation checklist from the FS-001 through FS-019 audit. | Static code review plus baseline test, lint, build, and diff checks. |
