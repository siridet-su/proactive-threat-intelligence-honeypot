---
title: Filesystem Activity audit remediation
status: active
last_updated: 2026-09-17
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

**In progress:** `FA-005` — resolve retained deep-link hops.

## Remediation backlog

| ID | Priority | Status | Original items | Problem | Acceptance criteria | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| `FA-001` | `P0` | `DONE` | `FS-001`, `FS-005`, `FS-007` | Audit filter options, `0/N`, totals, and path counts are calculated from the live snapshot plus only 12 recent closed sessions. Remote results remain local to the selector. | Audit totals and filtered results include the complete retained closed-session directory; remote pages become part of one authoritative parent data model; selected/pinned semantics and path options agree with the result set. | Follow-up remediation on commit `d4b96d5`: scope-safe search lifecycle (aborting and clearing search on filter scope change, rejecting mismatched search cursors, cancelling pending debounce timers on dropdown close or clear); strict gating of summary metrics (`totalSessions`, `homeOnlyCount`, `matchingCount`, `distinctPaths`) ensuring only `summaryStatus === "success"` matching `currentScopeKey` can be used; `auditDirectoryTotalCount` cannot reintroduce stale summary; HTTP 2xx invalid payload handling exits loading with an error; deterministic JSON tuple scope key `[hideHome, targetPath, q]` round-tripping delimiters and Unicode; 32 regression tests in `filesystem-audit-directory.test.ts` (196 passing tests total, 0 ESLint warnings/errors, clean build, clean git diff --check; tests cover query builders, store state machines, and normalization helpers without claiming live MongoDB pipeline runtime coverage). Accepted following FA-002 server pagination acceptance and live MongoDB smoke validation. |
| `FA-002` | `P0` | `DONE` | `FS-007` | `hideHome` and `targetPath` are applied after MongoDB pagination, while `totalItems` and `nextCursor` describe the unfiltered query. | Filtering occurs before page slicing, or pagination iterates until it produces a truthful filtered page; `items`, `totalItems`, and `nextCursor` share the same filter scope; empty intermediate pages cannot hide later matches. Note: the audit-session cursor currently compares an ISO string with `lifecycle.closedAt` stored by Go as BSON Date; this must be corrected and integration-tested during FA-002. | Commit `2257960`: Unified MongoDB aggregation pipeline (`buildAuditSessionsPipeline`, `buildAuditSummaryPipeline`, `buildAuditScopingStages`); filtering applied in MongoDB before facet pagination; keyset cursor decoded to real BSON Date objects and effectiveSessionId tie-breaker; legacy session_id unified across search, sort, cursor comparison, and returned documents; totalItems reflects complete filtered scope; 19 regression tests in `filesystem-audit-pipeline.test.ts` covering all 13 audit scenarios (215 tests passing across 11 files, clean lint, clean build, clean git diff --check). Live MongoDB smoke validation performed against 1,878 closed sessions: filtered pagination, BSON Date cursor behavior, page continuity, target-path filtering, hide-home filtering, malformed cursor handling, and summary aggregation passed without data anomalies. |
| `FA-003` | `P0` | `DONE` | `FS-011` | Response-action polling restarts its effect whenever a new action object is stored, resetting delay and the client deadline. A pending non-live action can poll near 100 ms intervals. | A single polling lifecycle survives state updates; delay increases monotonically to the configured ceiling; polling stops at terminal state or the bounded deadline; changing selected session aborts the prior lifecycle; terminal feedback remains visible. | Accepted on commit `1383a13` (building upon `0f68d70`): extracted dependency-neutral `responseActionTypes.ts` eliminating runtime circular dependency; extracted `ResponseActionLifecycleManager` used directly by `useResponseAction` to enforce strict `(sessionId, actionId)` lifecycle identity where `sessionIsLive` transitions (e.g. `true -> false` when session drops from live topology), `requestedAt`, status updates, and ordinary rerenders never replace or abort the active controller or reset monotonic delay and request bounds; initial timing configuration is captured strictly once at identity inception; `computePollingDeadline` clamps future `requestedAt` against server/client clock skew (`Math.min(reqTime + maxDurationMs, now + maxDurationMs)`) while preserving immediate timeout for genuinely old actions; abort behavior preserved for session change, action change, disable, and unmount; 24 unit and orchestration fake-timer regression tests in `response-action-poller.test.ts` covering corrected requested-to-delivered test data, clock-skew clamping, live-to-non-live continuity, and bounded request counts (239 tests passing across 12 files, clean ESLint with 0 errors/0 warnings, clean Next.js production build, clean git diff --check). |
| `FA-004` | `P0` | `DONE` | `FS-011` | Status polling can expose a false capability error when the 10-second Pi-health cache expires, and each poll still reads action and session state separately. | Pending-action status remains truthful after cache expiry without producing Pi health ping storms; database work per poll is documented and minimized; tests use fake timers to assert request cadence, total requests, timeout, abort, and terminal behavior. | Accepted on commits `6682572` and `854f35a`: separated status query from capability probing in `/api/sessions/[id]/actions/terminate` when `actionId` query parameter is present: status-only polls omit `available` without calling Pi `/v1/health` or reading `responseControlCachedHealth`, preventing pending actions from converting to false capability errors upon 10-second health cache expiry; capability probe without `actionId` retains 10s anti-ping-storm cache via `responseControlHealthy()`; MongoDB aggregation pipeline `$lookup` joins `cwd_session_state` on canonical primary key index `_id_` (`foreignField: "_id"`) and fallback reads use `{ _id: sessionId }`, confirmed via live MongoDB read-only index and execution plan inspection; atomic reconciliation with contention fallback reads ensures losing requests in concurrent reconciliation races return authoritative terminal `verified` or `failed` documents rather than stale pending state; `terminateCapabilityFrom` and `ResponseActionPollingController` fail closed by defaulting missing capability to `"loading"`, never exposing Disconnect controls on unknown capability; unknown and cross-session action IDs return `action: null`, omit `available`, and never leak data, with client poller preserving active pending action; 13 regression tests in `response-action-status.test.ts` plus 24 controller/lifecycle manager tests in `response-action-poller.test.ts` (13 test files / 252 tests passing, clean ESLint with 0 errors/0 warnings, clean Next.js production build, clean git diff --check). Outstanding integration gate: manual response-action smoke test with live response agent. |
| `FA-005` | `P0` | `IN PROGRESS` | `FS-006` | A shared `hop` URL is checked only against the first 80 history events and then discarded. | A deep link resolves a retained hop on any page, either through direct event lookup or bounded cursor traversal; invalid/expired hop IDs produce an explicit state; request cancellation and maximum work are defined. | Authoritative direct lookup via `getSessionCwdHistoryHop` querying canonical `cwd_events` primary index `_id_` with length-bounded inputs (<=300 chars) and cross-session isolation (returns 404 / `item: null` without data leakage); chronological `hopNumber` and `successfulHopNumber` derived server-side to maintain truthful absolute position across paginated window expansions; client-side `SessionHopLifecycleManager` with generation guards, AbortController cancellation on unmount, hop change, or live mode switch, and single-flight resolution; non-silent explicit state machine (`idle`, `resolving`, `resolved`, `not-found`, `error`) where invalid/missing/cross-session hops never silently fall back to latest event; amber alert banner with explicit recovery actions ('Show latest hop', 'Clear hop'); URL preserves `?hop=<id>` until explicit user recovery or selection; 15 unit and orchestration regression tests in `filesystem-hop-resolution.test.ts` (14 test files / 267 tests passing, clean ESLint 0 errors/0 warnings, clean Next.js production build, clean git diff --check). |
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
| `FA-016` | `P1` | `TODO` | `FS-007` | Full-scan summary aggregation and cursor skip on 1,878+ documents | Index optimization and execution plan bounds for large directory collections | — |

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
| 2026-09-17 | Remediated FA-005 (in progress): resolved retained deep-link hops via authoritative indexed lookup on canonical cwd_events _id_, enforced cross-session isolation and input bounds, added SessionHopLifecycleManager with generation guards and cancellation, handled not-found/error states explicitly with UI recovery banner and preserved URL parameter, and added 15 regression tests. | 14 test files / 267 tests passing; clean ESLint (0 errors, 0 warnings); clean Next.js build; clean git diff --check. |
| 2026-09-17 | Follow-up FA-004 (in progress): closed action status consistency gaps, indexed $lookup on canonical primary key _id_, handled concurrent reconciliation races with contention fallback read returning authoritative terminal document, defaulted omitted capability to fail-closed loading, isolated cross-session actions, and added regression tests. | 13 test files / 252 tests passing; clean ESLint (0 errors, 0 warnings); clean Next.js build; clean git diff --check; live read-only MongoDB index inspection confirmed primary key _id_ utilization. |
| 2026-09-17 | Remediated FA-004 (in progress): separated action status from capability health, omitted available from status responses to prevent false capability errors on cache expiry, preserved client capability, minimized MongoDB work to 1 read / 0 writes while pending, and added regression tests. | 13 test files / 248 tests passing; clean ESLint (0 errors, 0 warnings); clean Next.js build; clean git diff --check. (commit 6682572) |
| 2026-09-16 | Follow-up FA-003 (in progress): closed polling lifecycle gaps, extracted ResponseActionLifecycleManager to preserve backoff and deadline across sessionIsLive true->false transitions, clamped clock-skew deadlines, removed circular dependency via responseActionTypes, and added orchestration regression tests. | 12 test files / 239 tests passing; clean ESLint (0 errors, 0 warnings); clean Next.js build; clean git diff --check. |
| 2026-09-16 | Remediated FA-003 (in progress): stabilized response action polling with single-lifecycle controller, monotonic backoff capped at 3.5s, absolute deadline derivation, and exactly-once terminal feedback. | 12 test files / 228 tests passing; clean ESLint (0 errors, 0 warnings); clean Next.js build; clean git diff --check (commit 0f68d70). |
| 2026-09-16 | Remediated FA-002: filter audit sessions before pagination, unify scoping pipeline between sessions and summary, decode BSON Date cursors, support legacy session_id, and test execution fixture semantics. | 11 test files / 215 tests passing; clean ESLint (0 errors, 0 warnings); clean Next.js build; clean git diff --check; live MongoDB smoke validation passed on 1,878 closed sessions (commit 2257960). |
| 2026-09-16 | Follow-up FA-001: closed audit scope gaps, made search lifecycle scope-safe, gated summary metrics on active scope match, replaced scope key with deterministic JSON tuple, and added regression tests. | 10 test files / 196 tests passing; clean ESLint (0 errors, 0 warnings); clean Next.js build; clean git diff --check. |
| 2026-09-16 | Follow-up FA-001 (in progress): isolated search dropdown options from authoritative state, added generation guards, and implemented MongoDB facet pipeline. | 10 test files / 190 tests passing; clean ESLint; clean Next.js build; clean git diff --check. |
| 2026-09-16 | Remediated FA-001 (in progress): made Audit directory filtering, totals, and path options authoritative. | 10 test suites / 176 Vitest tests passing; zero-warning ESLint; Next.js production build clean; clean git diff --check. |
| 2026-09-16 | Created remediation checklist from the FS-001 through FS-019 audit. | Static code review plus baseline test, lint, build, and diff checks. |
