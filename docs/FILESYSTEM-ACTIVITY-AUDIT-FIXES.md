---
title: Filesystem Activity audit remediation
status: active
last_updated: 2026-09-19
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

**In progress:** `FA-013` — add truthful component and browser coverage for the filesystem audit behaviors.

## Remediation backlog

| ID | Priority | Status | Original items | Problem | Acceptance criteria | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `FA-001` | `P0` | `DONE` | `FS-001`, `FS-005`, `FS-007` | Audit filter options, `0/N`, totals, and path counts are calculated from the live snapshot plus only 12 recent closed sessions. Remote results remain local to the selector. | Audit totals and filtered results include the complete retained closed-session directory; remote pages become part of one authoritative parent data model; selected/pinned semantics and path options agree with the result set. | Follow-up remediation on commit `d4b96d5`: scope-safe search lifecycle (aborting and clearing search on filter scope change, rejecting mismatched search cursors, cancelling pending debounce timers on dropdown close or clear); strict gating of summary metrics (`totalSessions`, `homeOnlyCount`, `matchingCount`, `distinctPaths`) ensuring only `summaryStatus === "success"` matching `currentScopeKey` can be used; `auditDirectoryTotalCount` cannot reintroduce stale summary; HTTP 2xx invalid payload handling exits loading with an error; deterministic JSON tuple scope key `[hideHome, targetPath, q]` round-tripping delimiters and Unicode; 32 regression tests in `filesystem-audit-directory.test.ts` (196 passing tests total, 0 ESLint warnings/errors, clean build, clean git diff --check; tests cover query builders, store state machines, and normalization helpers without claiming live MongoDB pipeline runtime coverage). Accepted following FA-002 server pagination acceptance and live MongoDB smoke validation. |
| `FA-002` | `P0` | `DONE` | `FS-007` | `hideHome` and `targetPath` are applied after MongoDB pagination, while `totalItems` and `nextCursor` describe the unfiltered query. | Filtering occurs before page slicing, or pagination iterates until it produces a truthful filtered page; `items`, `totalItems`, and `nextCursor` share the same filter scope; empty intermediate pages cannot hide later matches. Note: the audit-session cursor currently compares an ISO string with `lifecycle.closedAt` stored by Go as BSON Date; this must be corrected and integration-tested during FA-002. | Commit `2257960`: Unified MongoDB aggregation pipeline (`buildAuditSessionsPipeline`, `buildAuditSummaryPipeline`, `buildAuditScopingStages`); filtering applied in MongoDB before facet pagination; keyset cursor decoded to real BSON Date objects and effectiveSessionId tie-breaker; legacy session_id unified across search, sort, cursor comparison, and returned documents; totalItems reflects complete filtered scope; 19 regression tests in `filesystem-audit-pipeline.test.ts` covering all 13 audit scenarios (215 tests passing across 11 files, clean lint, clean build, clean git diff --check). Live MongoDB smoke validation performed against 1,878 closed sessions: filtered pagination, BSON Date cursor behavior, page continuity, target-path filtering, hide-home filtering, malformed cursor handling, and summary aggregation passed without data anomalies. |
| `FA-003` | `P0` | `DONE` | `FS-011` | Response-action polling restarts its effect whenever a new action object is stored, resetting delay and the client deadline. A pending non-live action can poll near 100 ms intervals. | A single polling lifecycle survives state updates; delay increases monotonically to the configured ceiling; polling stops at terminal state or the bounded deadline; changing selected session aborts the prior lifecycle; terminal feedback remains visible. | Accepted on commit `1383a13` (building upon `0f68d70`): extracted dependency-neutral `responseActionTypes.ts` eliminating runtime circular dependency; extracted `ResponseActionLifecycleManager` used directly by `useResponseAction` to enforce strict `(sessionId, actionId)` lifecycle identity where `sessionIsLive` transitions (e.g. `true -> false` when session drops from live topology), `requestedAt`, status updates, and ordinary rerenders never replace or abort the active controller or reset monotonic delay and request bounds; initial timing configuration is captured strictly once at identity inception; `computePollingDeadline` clamps future `requestedAt` against server/client clock skew (`Math.min(reqTime + maxDurationMs, now + maxDurationMs)`) while preserving immediate timeout for genuinely old actions; abort behavior preserved for session change, action change, disable, and unmount; 24 unit and orchestration fake-timer regression tests in `response-action-poller.test.ts` covering corrected requested-to-delivered test data, clock-skew clamping, live-to-non-live continuity, and bounded request counts (239 tests passing across 12 files, clean ESLint with 0 errors/0 warnings, clean Next.js production build, clean git diff --check). |
| `FA-004` | `P0` | `DONE` | `FS-011` | Status polling can expose a false capability error when the 10-second Pi-health cache expires, and each poll still reads action and session state separately. | Pending-action status remains truthful after cache expiry without producing Pi health ping storms; database work per poll is documented and minimized; tests use fake timers to assert request cadence, total requests, timeout, abort, and terminal behavior. | Accepted on commits `6682572` and `854f35a`: separated status query from capability probing in `/api/sessions/[id]/actions/terminate` when `actionId` query parameter is present: status-only polls omit `available` without calling Pi `/v1/health` or reading `responseControlCachedHealth`, preventing pending actions from converting to false capability errors upon 10-second health cache expiry; capability probe without `actionId` retains 10s anti-ping-storm cache via `responseControlHealthy()`; MongoDB aggregation pipeline `$lookup` joins `cwd_session_state` on canonical primary key index `_id_` (`foreignField: "_id"`) and fallback reads use `{ _id: sessionId }`, confirmed via live MongoDB read-only index and execution plan inspection; atomic reconciliation with contention fallback reads ensures losing requests in concurrent reconciliation races return authoritative terminal `verified` or `failed` documents rather than stale pending state; `terminateCapabilityFrom` and `ResponseActionPollingController` fail closed by defaulting missing capability to `"loading"`, never exposing Disconnect controls on unknown capability; unknown and cross-session action IDs return `action: null`, omit `available`, and never leak data, with client poller preserving active pending action; 13 regression tests in `response-action-status.test.ts` plus 24 controller/lifecycle manager tests in `response-action-poller.test.ts` (13 test files / 252 tests passing, clean ESLint with 0 errors/0 warnings, clean Next.js production build, clean git diff --check). Outstanding integration gate: manual response-action smoke test with live response agent. |
| `FA-005` | `P0` | `DONE` | `FS-006` | A shared `hop` URL is checked only against the first 80 history events and then discarded. | A deep link resolves a retained hop on any page, either through direct event lookup or bounded cursor traversal; invalid/expired hop IDs produce an explicit state; request cancellation and maximum work are defined. | Accepted remediation through commit `ac74c8b` (building on commits `a2af57b`, `a8c2ceb`, `849ad01`, and `23c2533`): (1) centralized remote lookup lifecycle in RemoteAuditLookupCoordinator across all navigation scope changes (popstate to known session, Live/Audit mode switch, session selection, component unmount); (2) unified local session scope adoption via single production helper `adoptLocalSessionScope` used by both `FilesystemActivity.selectSession` and `processSnapshotSessionResolution`, enforcing invariant `targetHopId === null` for all Live navigation and local resolutions while preserving normalized hop in Audit mode; (3) implemented local snapshot resolution cancellation aborting in-flight remote requests when a later snapshot contains the target session while adopting the session and preserving requested hop; (4) maintained request deduplication across repeated missing snapshots; (5) unified authoritative UI callbacks via `createRemoteAuditLookupCallbacks` configured in `useEffect` to satisfy React Compiler ref safety; (6) provisioned legacy compound index on `cwd_events` verified on live MongoDB Atlas with IXSCAN 0 docs examined; (7) replaced mock/simulation tests with production orchestration path tests and eliminated arbitrary `setTimeout` waits in favor of deterministic promise completion; (8) 27 regression tests in `filesystem-hop-resolution.test.ts` (14 test files / 279 tests passing total, Go tests passing, clean ESLint with 0 errors/0 warnings, clean Next.js build, clean git diff --check). |
| `FA-006` | `P1` | `DONE` | `FS-012` | Freshness age uses snapshot response-generation time rather than the latest authoritative telemetry timestamp. Manual refresh can make old telemetry appear fresh, and a valid empty snapshot is treated as absent/offline. | Transport state, snapshot retrieval time, and telemetry observation time are separate fields; refresh does not reset telemetry age; an empty valid snapshot can be live and fresh; stale/recovery labels have deterministic tests. | Accepted remediation through commit `2098af3` (building on commits `6038492`, `a04ec9f`, `85ba9e4`, and `0118dca`): (1) added nullable `latestTelemetryAt` to `FilesystemTopologySnapshot` contract; (2) added pure extraction function `deriveLatestTelemetryAt` evaluating active/closed session `observedAt` and `lifecycle.closedAt`; (3) computed and included `latestTelemetryAt` in server snapshot build in `buildFilesystemTopology`; (4) decoupled pure freshness helpers into neutral `@/lib/filesystem-freshness`; (5) recorded client-local `snapshotReceivedAtMs` atomically upon snapshot acceptance; (6) `SnapshotIngestionCoordinator` provides synchronous and deterministic snapshot acceptance, firing ready region status and `onSnapshotApplied` synchronously on genuine acceptance; (7) `FilesystemStreamLifecycleManager` scopes connection lifecycle by generation, discarding superseded callbacks/retries and aborting in-flight fallback requests with `AbortController`; (8) extracted `FilesystemRefreshLifecycleManager` separating manual HTTP snapshot retrieval lifecycle from SSE transport health, scoping refreshes with monotonic generation IDs and `AbortController` cancellation; (9) live SSE stream state is authoritative for transport health when a snapshot is present, preventing failed refreshes from degrading live streams; (10) pure render-time `calculateTelemetryAge` with bounded O(1) `TelemetryTrustMarker`; (11) persistent future skew classification across clock catch-up and manual refresh with same timestamp, recovering on new valid telemetry; (12) corrected page badge precedence via `formatPageBadgeText`; (13) 32 regression tests in `filesystem-freshness.test.ts` (15 test files / 311 tests passing total, Go backend tests passing, clean ESLint with 0 errors/0 warnings, clean Next.js Turbopack production build, clean `git diff --check`). |
| `FA-007` | `P1` | `DONE` | `FS-013`, `FS-018` | Arrow keys on a closed combobox trigger try to focus unmounted options without opening the popover. The listbox owns search and action controls that are not options. Note: AuditSessionSelect currently has duplicated close cleanup/onClearSearch paths; cleanup to be addressed during FA-007. | ArrowDown/ArrowUp open the popover and place focus predictably; Escape and selection restore trigger focus; ARIA ownership follows the chosen combobox/listbox pattern; Session and Path selectors pass keyboard and screen-reader-oriented component tests. | Accepted remediation through commit chain ending at `c4680cd` (building on commits `03ad4f2`, `fd2ddcb`, `4db930e`, and `c4680cd`): (1) centralized debounce, generation scoping, and strictly-once close/search cleanup in `AuditSessionSearchManager`; (2) opened popover on trigger arrow keys (`ArrowDown` -> `"first"`, `ArrowUp` -> `"last"`) and roving DOM focus; (3) composite ARIA popover model: trigger combobox with `aria-controls` pointing to listbox ID, listbox containing only groups and options, search and action buttons outside listbox, direct roving focus; (4) parent-controlled vs standalone search ownership with page one to page two cursor pagination; (5) preserved intentional focus target via `isMeaningfulFocusTarget` (the dedicated control test directly exercises Retry while deliberate/external-focus tests cover shared focus preservation on Load more, Reset filters, search input, trigger, or external controls); (6) fallback to search input when focused option disappears; (7) synchronized option focus via `handleOptionFocus(index, key)` and roving tabindex (`tabIndex={0}` on active option); (8) stabilized identity extractors at module level; (9) 63 unit and real DOM interaction tests in `combobox-popover.test.ts` (16 test files / 361 tests passing total, Go backend tests passing, clean ESLint with 0 errors/0 warnings, clean Next.js Turbopack production build, clean `git diff --check`). |
| `FA-008` | `P1` | `DONE` | `FS-006`, `FS-018` | Filter and hop changes use `replaceState`, so Back/Forward cannot traverse user navigation between these states. | User-initiated view, session, filter, and hop changes create intentional history entries without flooding history during automatic synchronization or playback; Back/Forward restore a coherent UI and do not trigger loops. | Accepted FA-008 implementation chain `760017f` → `bf54095` → `4566131` → `3be0250` → `ef8e3b8` → `bcb36b2` → `ae45832`; supporting documentation in `8c82c7e`; origin/main integration merge `fdca7d6`. Final audit evidence: 17 dashboard test files / 399 Vitest tests passing, zero ESLint errors or warnings, clean production build, clean `git diff --check`, and all five Go modules passing. |
| `FA-009` | `P1` | `DONE` | `FS-019` | Replay exposes real timestamps, but the scrubber thumb is positioned by hop index, implying uniform spacing. Partial history also displays a duration without identifying it as partial. | Scrubber position maps to elapsed event time, with a documented strategy for equal, missing, invalid, and non-monotonic timestamps; stepping remains hop-based; partial durations are explicitly labelled until retained history is complete; uneven-gap browser tests verify the real range input. | Final re-audit accepted the implementation chain `8e6e4c849628c431adddec7d64121be22ae68ae8` → `d3dbbf9309c78bd9d6682a3123891dd9d306cd90`: shared `buildReplayTimeline`, elapsed-time scrubber positioning, deterministic timestamp fallback, explicit partial/complete duration labels, and 18 unit/component regressions. |
| `FA-010` | `P1` | `DONE` | `FS-002` | History `hasMore` is computed after malformed documents are normalized away, while counts are based on raw documents. | Pagination cursor, page completeness, and totals are based on the same valid-event contract; malformed legacy records cannot end pagination early or create an unreachable remainder. | Final audit accepted on commit chain `5c85c6464e4a4fe55a6720c97cb8fc8c7965ca21` → `470c9305e690a08a5954070110233f072256fbee` → `696fb208dfff535a3d0cf448031c79f0515f367b` → `9dec1c0bd5a08e8ad031179d5ca7189170ea5849` → `b2527715956e15a705f2ac7c78e247667cf22a95`; production `getSessionCwdHistory` uses one MongoDB aggregation with a shared valid-event contract, and the final guarded MongoDB validation passed. |
| `FA-011` | `P2` | `DONE` | `FS-007` | The process-wide closed-session audit-path cache has no size or expiry bound. Topology refreshes populate it from `cwd_session_state`'s recent closed-session buffer after `cwd_events` aggregation; historical audit-directory searches use separate pipelines and do not populate this cache. Rolling closed sessions can therefore grow the cache for the lifetime of the server process. | Cache has an explicit memory bound or expiry policy; eviction cannot corrupt immutable-session results; cache behavior and operational trade-offs are documented and tested. | Final audit accepted on commit `d716bd48e504b376482961c555657971c23d4987` (`fix(filesystem): bound closed-session audit cache (FA-011)`). |
| `FA-012` | `P2` | `DONE` | `FS-016` | Hooks were extracted, but the three feature components remain oversized and `CwdRouteHistory` still owns response-action data flow alongside replay presentation. | Response actions, replay orchestration, topology rendering, and page composition have explicit ownership; presentational components receive data/actions through focused props; refactor does not duplicate timers or requests. | Accepted commit chain `356f48d74f64db7019cd622cca424676d42a7e4d` → `5779e32a739a6df1a45322c7172d17dd9086c14b` → `5ec0bf9ee0e28cd4b0eff50519045063e3efe470`: `useAuditReplay` owns the typed `AuditReplayPresentation` contract, `CwdRouteHistory` consumes it without fallback derivation/state/actions, `FilesystemActivity` owns response capability/polling through `useResponseActionController`, and `TopologyCanvas` requires page-owned `freshnessState` without a fallback clock/classifier. Existing production-path happy-dom evidence covers the real timeline/tab composition, response request deduplication/abort/reopen, one autoplay advance after rerender/layout changes, and zero topology fallback timers. |
| `FA-013` | `P1` | `IN PROGRESS` | `FS-018` | Current tests predominantly exercise exported helper functions and do not verify the browser/component behaviors claimed by FS-006, FS-013, FS-014, FS-018, and FS-019. | Add component/browser coverage for remote filtered pagination, deep links beyond page one, Back/Forward, combobox focus and keys, polling cadence, empty valid topology, responsive toolbar behavior, reduced motion, and a time-positioned scrubber. | Implementation and audit evidence in progress. Happy-dom scenarios will be recorded separately from real-browser layout/media-query scenarios; FA-013 remains `IN PROGRESS` pending audit. |
| `FA-014` | `P2` | `TODO` | `Tracker hygiene` | Working-state metadata/current focus disagree with the completion table, and recorded “clean” evidence does not match the current working tree. | Tracker has one current focus, current date, truthful statuses, and evidence tied to reproducible commands or validation notes; original FS items affected by this audit are reopened or labelled partial. | — |
| `FA-015` | `P2` | `TODO` | `Change hygiene` | `git diff --check` reports blank-line-at-EOF errors and the full FS-001–FS-019 implementation exists as one large uncommitted change. | `git diff --check`, tests, lint, and production build pass; changes are reviewed and committed in recoverable logical units without overwriting unrelated user work. | — |
| `FA-016` | `P1` | `TODO` | `FS-007` | Full-scan summary aggregation and cursor skip on 1,878+ documents | Index optimization and execution plan bounds for large directory collections | — |

### FA-008 accepted evidence (2026-09-18)

Commit `3be0250` was audited as a valid single-owner improvement but required
follow-up: arbitrary mutating `RemoteAuditLookupCallback` objects could still be
registered as observers, the in-flight record temporarily exposed a casted null
promise, and popstate transactions were marked terminal before domain
application. The prior remediation commits audited before this change are
`ef8e3b8e97b82569113574b888204e66d911a29b` (`ef8e3b8`),
`fix(filesystem): finalize lookup ownership lifecycle (FA-008)`, and
`bcb36b22a7cf6943ea0a6dc738e68a1ef8b654fc` (`bcb36b2`),
`fix(filesystem): close lookup failure lifecycle gaps (FA-008)`. The new
remediation commit, `fix(filesystem): surface navigation recovery failures
(FA-008)`, wires recoverable application failures through FilesystemActivity
and preserves truthful ownerless network results.

Failure policy: an application exception stores the error on the active
transaction with status `failed`, invokes the explicit application-error
callback, suppresses stale URL synchronization while preserving the popped
URL, and allows the same target to retry or a newer target to supersede it.
FilesystemActivity stores only the canonical failed target and a bounded
user-safe message, renders persistent accessible Retry/Dismiss feedback, and
guards late callbacks after unmount. Dismissal releases the failed transaction
without a history write while retaining a URL guard until state catches up or
new navigation begins. An ownerless lookup resolves its truthful fetched
session (or null for not-found/network error) but performs no domain mutation
and cannot notify terminal-success observers; a later authoritative owner can
claim it before completion.

Evidence: 38 FA-008 scenarios in
`dashboard-v2/tests/filesystem-navigation-history.test.ts`; 17 dashboard test
files / 399 Vitest tests passing; zero ESLint errors or warnings; clean Next.js
production build; clean `git diff --check`; and
`go test -count=1 ./...` passing in all five `agents/` modules. FA-008 remains
`DONE` after final audit. FA-009 is now `IN PROGRESS`; FA-010 and later items remain
`TODO` and untouched.

### FA-009 implementation evidence (2026-09-18)

The production replay timeline is now a single chronological model shared by
the replay hook and route-history component. Its time scale uses elapsed
milliseconds from the first displayed event, maps pointer/input values to the
nearest displayed event with an earliest-event tie-break, and preserves
Previous/Next as discrete hop-index navigation. A valid scale requires every
displayed timestamp to parse and be non-decreasing with positive total span.
Equal timestamps share elapsed positions; all-equal timestamps, missing or
invalid timestamps, and non-monotonic sequences use an explicitly labelled
index fallback (`Timing unavailable`) without invented interpolation. A single
valid event has a stable zero-duration scale.

Keyboard range semantics are explicitly hop-based: ArrowLeft/ArrowDown select
the previous displayed event, ArrowRight/ArrowUp select the next, and Home/End
select the first/last. Handled keys prevent the native millisecond movement;
boundary presses do not wrap, pause, select, or write history. Successful
keyboard and pointer/input selections pause once and select once. Anchored deep
targets remain disabled and report one concise `unloaded gap` label.

The timeline model now carries an explicit duration scope. Partial windows say
`Partial · displayed loaded span …`; complete filtered windows say `Complete
displayed span …`; only complete unfiltered retained history says `Complete
retained duration …`. Filtering out the earliest, latest, both boundaries, or
every event therefore cannot overstate the timestamp scope. Loading earlier
events recomputes the displayed origin while the selected event remains
identified by ID.

Evidence: 16 deterministic timeline/helper regressions in
`dashboard-v2/tests/filesystem-hooks.test.ts` and 14 real DOM production
`CwdRouteHistory` scrubber regressions in
`dashboard-v2/tests/filesystem-replay-scrubber.test.ts`; 18 dashboard test
files / 429 Vitest tests passing; zero ESLint errors or warnings; clean
production build; clean `git diff --check`; and all five Go modules passing.
The accepted implementation chain is `8e6e4c849628c431adddec7d64121be22ae68ae8`
and `d3dbbf9309c78bd9d6682a3123891dd9d306cd90`. FA-009 is `DONE` after final
re-audit. FA-010 is now `IN PROGRESS`; FA-011 and later items remain `TODO` and
untouched.

### FA-010 implementation evidence (2026-09-18)

History pagination now runs a single `cwd_events.aggregate()` operation with
`allowDiskUse: true`. The pipeline first matches the requested session through
`sessionId`/`session_id`, then derives the effective session ID, timestamp, and
event ID before filtering valid actions, sorting newest-first, applying the
decoded keyset cursor, and limiting the page to `HISTORY_PAGE_SIZE + 1` (81).
The same projected population feeds `$facet.totalItems` and
`$facet.totalSuccessfulItems`, with `failed_change` excluded only from the
successful facet. The public cursor is exactly `{ at, id }` from the effective
projection, so canonical and supported legacy fields share one ordering and
cursor identity.

The processor currently provisions `{ sessionId: 1, at: -1, eventId: -1 }`,
`{ session_id: 1, at: -1, eventId: -1 }`, and the `expires_at` TTL index;
MongoDB's built-in `_id_` index remains the fallback identifier lookup. The
leading mixed-schema session `$match` can use the two compound indexes. There
is no `timestamp` index, and no index supports the projected effective fields:
timestamp fallback documents, effective fallback identifiers, the final sort,
and the facet counts are post-projection work that may spill to disk. No
application-side raw scan or raw count remains; the Node.js boundary receives
only the bounded lookahead and facet totals.

The original six application tests in
`dashboard-v2/tests/filesystem-history-pagination.test.ts` now describe facet
decoding and structural checks only; they do not claim MongoDB execution.
The same file contains a gated integration suite that uses a real MongoDB 8.0
engine, captures `commandStarted` aggregate commands, and asserts that the
command pipeline exactly equals `buildSessionCwdHistoryPipeline` for each
production `getSessionCwdHistory` request. It inserts only into the temporary
container's validated unique `pti_fa010_test_<runId>.cwd_events` database and
collection, clears the collection between tests, and drops the validated test
database before closing the client. Run it reproducibly with:

`cd dashboard-v2 && npm run test:filesystem-history-integration`

The wrapper starts a temporary `mongo:8.0` container on an ephemeral localhost
port, waits for `ping`, runs the gated Vitest suite with the validated
`FA010_MONGO_URI`, `FA010_MONGO_TEST_DB`, and `FA010_MONGO_RUN_ID` values, and
force-removes the container in `finally`. The executed fixture covers
canonical/legacy fields, Date and ISO values, ObjectId/string fallbacks,
blank/invalid identifiers and timestamps, unsupported actions, fallback
precedence, malformed records around page boundaries, 84+ valid events,
failed-change totals, equal-timestamp ordering, multi-page cursor traversal,
exact exhaustion, all-malformed data, and post-projection parity with
`normalizeHistoryEvent`. Executed on 2026-09-19: 1 test file and 8 tests
passed against the temporary MongoDB instance, with the container removed
afterward. FA-010 is `DONE` after final audit. FA-011 is now `IN PROGRESS`;
FA-013 is now `IN PROGRESS`; FA-014 and later items remain `TODO` and untouched.

### FA-010 fixture safety follow-up (2026-09-19)

The integration fixture target is now fail-closed. The wrapper generates a
lowercase alphanumeric run token and uses the unique database name
`pti_fa010_test_<runId>`. Before any MongoDB client is created or destructive
operation is possible, the target validator requires all of the following:

- a `mongodb://` URI whose hostname is exactly `127.0.0.1`, `localhost`, or
  `::1`;
- a database name with the `pti_fa010_test_` prefix;
- a run identifier whose derived database name exactly matches the URI path and
  supplied test database name; and
- rejection of `honeypot_db`, non-loopback hosts, missing identifiers, and
  mismatched/unprefixed databases.

The integration suite connects to the validated unique database, while a
test-only client adapter maps the production `db("honeypot_db")` request from
`getSessionCwdHistory` to that validated database. No production database name
is used as a destructive target. Safety tests assert rejected configurations
invoke zero connection/destructive callbacks. The wrapper also removes the
temporary container in `finally` and on SIGINT/SIGTERM. The normal guarded run
executed 14 tests successfully (6 application, 6 safety, 2 MongoDB integration)
and left no `pti-fa010-mongo-*` container running. FA-010 is `DONE` after final
audit. FA-011 is now `IN PROGRESS`; FA-012 and later items remain `TODO` and
untouched.

### FA-011 implementation evidence (2026-09-19)

The production closed-session audit-path cache is now a bounded access-ordered
LRU with a hard maximum of 24 entries, intentionally sized to retain two
complete 12-session topology windows. It has no TTL: closed-session summaries
are immutable, so expiry would add clock complexity without improving
correctness. A cache hit refreshes recency; duplicate writes replace the value
and refresh recency without increasing size; eviction removes only the in-memory
entry. Capacity `0` disables storage, while negative, fractional, non-finite,
or otherwise unsafe capacities fail deterministically at construction.

The cache is populated only by `buildFilesystemTopology`: active session IDs
are always aggregated live, while recent closed session IDs are read from the
cache and uncached IDs are aggregated from `cwd_events`. A closed session with
no aggregation row is stored as a negative-cache `null` entry, because its
closed state is immutable. If a closed session is evicted, the next topology
refresh aggregates it from MongoDB and repopulates the cache. The existing
process-wide in-flight snapshot promise coalesces simultaneous requests, and
ordinary refreshes do not clear the cache.

This trades bounded memory for predictable MongoDB re-fetches: lowering the
bound reduces process memory but increases aggregation work when older closed
sessions re-enter the recent topology window. Nine regressions in
`dashboard-v2/tests/filesystem-audit-cache.test.ts` cover the cache abstraction
and the production `getFilesystemTopology` path, including rolling-window
capacity, deterministic LRU eviction and recency, duplicate writes, immutable
hits, negative results, active-session live aggregation, eviction refetch, and
concurrent request coalescing. FA-011 is `DONE` after final audit on accepted
commit `d716bd48e504b376482961c555657971c23d4987`. FA-012 is now `IN PROGRESS`;
FA-013 and later items remain `TODO` and untouched.

### FA-012 follow-up evidence (2026-09-19)

Preflight started from exact HEAD
`5779e32a739a6df1a45322c7172d17dd9086c14b` on
`feat/cwd-filesystem-telemetry` with a clean working tree. `git fetch origin
--prune` succeeded; `origin/main` was
`4e90071c788ec7f1d61b4756ed527a445d993973`, equal to the merge base, so no
integration merge was required. The root-level `npm test` baseline was recorded
as an environment/layout failure (`ENOENT`: no root `package.json`); the
dashboard package is `dashboard-v2`; the full dashboard validation was run from
that package after the follow-up edits.

The final production ownership contract is:

- `FilesystemActivity` owns page composition and mounts one
  `useAuditReplay`, one `useResponseActionController`, and one
  `useFilesystemStreaming` owner.
- `useAuditReplay` owns replay state, failed-attempt filtering, selected event
  derivation, history metrics, anchored-hop presentation, elapsed-time
  scrubber model, Previous/Next/play/pause/speed/pacing actions, and autoplay.
- `CwdRouteHistory` and `FilesystemTimelinePanel` are request-free and
  timer-free presentation/composition components; route history receives one
  required typed `AuditReplayPresentation` model and no longer computes a
  second replay model or fallback actions.
- `useResponseActionController`/`useResponseAction` owns capability requests,
  polling, terminal feedback, and aborts; `ResponseActionPanel` only renders
  its controlled view model.
- `useFilesystemStreaming` owns freshness calculation and its ticking clock;
  `TopologyCanvas` requires authoritative `freshnessState` and owns only the
  mounted topology viewport/arrangement state. It has no fallback freshness
  interval or independent freshness classification.

`dashboard-v2/tests/filesystem-ownership-boundaries.test.tsx` now renders the
real `FilesystemTimelinePanel` → `CwdRouteHistory` / `ResponseActionPanel`
composition. Its exact scenarios use fake timers and deterministic promises:
inactive Response does not request capability; opening Response makes exactly
one request; an unrelated rerender does not duplicate it; leaving the tab
aborts the active capability lifecycle; reopening creates exactly one new
lifecycle; a presentational width/rerender change still permits exactly one
autoplay advance; and `TopologyCanvas` rendered with authoritative freshness
creates zero fallback timers. Existing replay component tests use a separate
test adapter around `useAuditReplay`, not hidden derivation in production
`CwdRouteHistory`. No browser automation or manual response-agent smoke test
was claimed or run.

The accepted FA-012 commit chain is
`356f48d74f64db7019cd622cca424676d42a7e4d` →
`5779e32a739a6df1a45322c7172d17dd9086c14b` →
`5ec0bf9ee0e28cd4b0eff50519045063e3efe470`; FA-012 is `DONE` pending no
further implementation work under this item.

### FA-013 component/browser evidence (2026-09-19)

The accepted FA-012 ownership boundaries are preserved: `FilesystemActivity`
remains the page composition owner, `useAuditReplay` owns replay state and
autoplay, `useResponseActionController` owns response requests/polling,
`useFilesystemStreaming` owns freshness/ticking, and presentation components
remain request-free and timer-free.

Happy-dom component evidence:

- `fa013-component-evidence.test.tsx` renders production `ResponseActionPanel`
  with `useResponseActionController` and fake timers for monotonic 100 ms then
  150 ms polling, terminal stop, and disable cancellation (E).
- The same file renders `TopologyCanvas` with a valid empty live snapshot and
  with a retained valid empty snapshot under degraded transport. It asserts
  `Live · No activity`, truthful degraded/retained-snapshot messaging, and zero
  freshness timers in both cases (F).
- The same file renders the production `CwdRouteHistory` with the real
  `useAuditReplay` presentation. It verifies elapsed-millisecond range
  positions, nearest-event selection with earliest-event ties, pause/input and
  Home/End behavior, and the explicit index fallback for malformed timing (I).
- `combobox-popover.test.ts` remains the real-DOM component evidence for
  `AuditSessionSelect` and `AuditFilterControls`: keyboard/focus movement,
  Escape and selection restoration, search and option ownership, ARIA state,
  loading/empty/error/retry/reset/load-more controls, identity-preserving focus,
  parent-controlled pagination, and stale page-two cancellation (D).
- `response-action-poller.test.ts` and
  `filesystem-ownership-boundaries.test.tsx` provide the accepted controller
  and production-composition polling/ownership evidence (E). Existing
  `filesystem-replay-scrubber.test.ts` supplements the scrubber timing fallback
  and partial/complete labels (I).
- `filesystem-navigation-history.test.ts` is happy-dom/helper-orchestration
  evidence for coordinator transactions, popstate delivery, stale retained
  lookup cancellation, and history-entry ownership. It is not claimed as
  Chromium browser Back/Forward coverage.
- The former local pagination and deep-link replicas were removed. Their A/B
  evidence now runs through the production page in Chromium below.

Real-browser evidence:

- `tests/browser/filesystem-fa013.spec.mjs` runs the production
  `/filesystem-activity` page with deterministic intercepted APIs. Scenario A
  applies hide-home and `/var/log` filters, performs cursor page-one/page-two
  search with unique append and exhaustion UI, leaves stale page two pending,
  changes query scope, and proves the obsolete response cannot mutate the new
  results or completion state. The production parent-controlled selector path
  is used; no standalone fallback request is installed by the test.
- Scenario B starts at a deep audit URL, retains the requested hop while its
  direct lookup is pending, displays an authoritative anchored target without
  splicing it into page one, loads earlier history for identity reconciliation,
  and preserves the absolute hop/URL. It also exercises explicit unknown-hop
  and lookup-error recovery plus Show latest and Clear hop without silently
  clearing the URL.
- Scenario C starts from the production Live view, builds the Audit → session
  selection → hide-home → target-path → hop stack through production UI, and
  uses actual `page.goBack()`/`page.goForward()` and browser history traversal
  across every traversable audit entry. Each step asserts the canonical URL,
  selected audit state, filters, and visible hop context; it also checks that
  traversal does not add feedback entries. Its delayed retained-session proof
  creates same-document A/B entries, goes Back to start A, goes Forward to B,
  and resolves A without any document navigation; the late A result cannot
  overwrite B's URL, session, hop, filters, or recovery state. The initial
  Live baseline is asserted before the production Audit transition; the first
  Playwright document entry itself is not treated as a traversable history
  entry.
- Scenario G uses a real Chromium layout engine at 375, 768, and 1440 CSS
  pixels. It checks bounding-box reachability, page and toolbar horizontal
  overflow, and actual timeline collapse to an inert/hidden panel followed by
  expansion with replay controls reachable.
- Scenario H uses Chromium `prefers-reduced-motion: reduce` and the production
  replay/Response/Command tabs, asserting immediate zero-duration transitions,
  no running animations, and functional controls. Scenarios G/H are not
  described as happy-dom coverage. D, E, F, and I are component-tier evidence;
  the browser file intentionally does not duplicate those claims.

Hydration and browser failure policy: URL-owned state and persisted timeline
preferences use deterministic server/client initial values, then the mounted
production page applies the original search transaction after hydration. The
navigation coordinator owns transaction protection and canonical URL
deduplication; initial adoption is therefore write-free without a permanent
search-string suppression guard, while later automatic state transitions may
use the existing deduplicated replaceState synchronization. This preserves
deep-link URLs and retains session/hop lookup and navigation transaction
behavior. The browser harness
fails on every `pageerror` and every unexpected `console.error`; the only
narrow allowlist is the intentionally intercepted HTTP 500 for the
`error-hop` recovery scenario. Direct audit, filter, session, and hop URLs are
opened under this policy and passed without hydration/runtime errors.

Browser portability and isolation: `playwright.config.mjs` defaults to the
pinned Playwright-managed Chromium. Machines that require a system browser may
set `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH`; the reproducible managed install is
`npx playwright install chromium`. The suite uses isolated `127.0.0.1:3100`,
intercepts every API used by the scenarios, contacts no production services,
MongoDB, or response agents, and writes Playwright output to
`/tmp/proactive-threat-intelligence-fa013-playwright` so browser reports do not
dirty the repository.

Validation recorded for this follow-up: from `dashboard-v2`, `npm test` passed
22 files with 458 passing and 2 skipped tests (460 total), and
`PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium npm run test:browser`
passed 5 Chromium tests in 25.9 seconds. `npm run lint` passed with 0 errors
and 0 warnings; `npm run build` passed TypeScript, static generation, and route
optimization; `git diff --check` passed; and
`go test -count=1 ./...` passed in each of the five Go modules
(`collector-agent`, `hardware-agent`, `processor-agent`, `response-agent`, and
`ti-worker`). The browser command is the repository's `npm run test:browser`
script; this environment used the documented explicit system-browser override
because its Playwright-managed binary is not installed. Current preflight began
at `bee351b6195d2c44b831a5faa5c0204d138af33d` on
`feat/cwd-filesystem-telemetry` with a clean tree. `git fetch origin --prune`
failed exactly with `git@github.com: Permission denied (publickey).` and
`fatal: Could not read from remote repository.`; the existing local
`origin/main` (`4e90071c788ec7f1d61b4756ed527a445d993973`) was already an
ancestor of HEAD, so no merge was required and the remote was not claimed
current. No manual/live validation was performed. FA-013 remains `IN PROGRESS`
pending audit.
FA-014 and later items remain `TODO` and were not started.

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
| 2026-09-18 | Started FA-009 after final FA-008 acceptance: marked FA-008 `DONE`, set FA-009 `IN PROGRESS`, and implemented the shared elapsed-time replay scale with explicit timestamp fallback and partial-window semantics. | 18 FA-009 unit and real-DOM component regressions; 18 dashboard test files / 417 Vitest tests passing; clean lint, build, and diff checks; all five Go modules passing. |
| 2026-09-17 | Follow-up FA-008 (in progress): closed navigation history ownership gaps: (1) eliminated duplicate history entries from nested commits by separating state-only hop cleanup (`resetRequestedHopState`) from intentional user hop navigation (`clearRequestedHop`), calculating complete canonical destination first and pushing exactly once; (2) covered raw-state actions ("Reset filters" and "Clear selection") with atomic 1-push history writes, in-flight work cancellation, Back-traversability, and deduplication when already default/null; (3) extracted `FilesystemNavigationCoordinator` with durable `PopStateTransaction` lifecycle guarding URL synchronization against stale pre-navigation React state overwrites during pending retained-session lookups until a terminal state is reached, invalidating superseded transactions on rapid Back/Forward without arbitrary timers; (4) 15 production-path regression scenarios in `filesystem-navigation-history.test.ts` (17 test files / 376 tests passing total, Go backend tests passing across all 5 agent modules, clean ESLint with 0 errors/0 warnings, clean Next.js Turbopack production build, clean `git diff --check`). |
| 2026-09-17 | Follow-up FA-007 (in progress): preserved intentional combobox focus, synchronized actual option focus, and stabilized identity extractors: (1) distinguished managed focus loss from intentional user navigation via pure helper `isMeaningfulFocusTarget`, preventing focus stealing from Load more, Retry, Reset filters, search input, trigger, another option, or external controls; (2) when a tracked option disappears, fallback to search input occurs only if that option actually owned focus, while deliberate targets preserve focus with cleared navigation state; (3) synchronized option focus via `handleOptionFocus(index, key)` and roving tabindex (`tabIndex={0}` on active option, `tabIndex={-1}` on other options), tracking actually focused options across reorders; (4) stabilized identity extractors at module level (`getSessionOptionKey`, `getSessionOptionLabel`, `getPathOptionItemKey`, `getPathOptionItemLabel`, `PathOptionItem`); (5) added 8 unit and real DOM regression tests in `combobox-popover.test.ts` (63 tests in file, 16 test files / 361 tests passing total, Go backend tests passing, clean ESLint with 0 errors/0 warnings, clean Next.js Turbopack production build, clean `git diff --check`). |
| 2026-09-17 | Follow-up FA-007 (in progress): resolved standalone combobox pagination ownership and identity-aware focus recovery: (1) eliminated default false prop assignments and dead cursor props (`directoryCursor`, `searchCursor`) in `AuditSessionSelect`, establishing strict ownership between parent-controlled search (consuming parent props without HTTP search) and standalone search (consuming `AuditSessionSearchManager` remote sessions, `hasMoreRemote`, `isLoadingRemote`, and error messages); (2) implemented complete page one to page two pagination lifecycle with cursor dispatch, unique appending, loading UI, and completion banner; (3) added dual scope and generation guards in `AuditSessionSearchManager` protecting against stale network responses ignoring `AbortSignal` or query changes before page two completes; (4) added identity-aware focus tracking via `getKey`, `optionKeyRefs`, and `navigatedKey` in `useComboboxNavigation`, keeping focus on moving items across reorders and canvas path insertions; (5) enforced deterministic fallback to `searchInputRef` when an active item disappears or is replaced with same-length options, guaranteeing `document.activeElement` never drops to `document.body`; (6) added 8 real DOM regression tests in `combobox-popover.test.ts` (55 tests in file, 16 test files / 353 tests passing total, Go backend tests passing, clean ESLint with 0 errors/0 warnings, clean Next.js Turbopack production build, clean `git diff --check`). |
| 2026-09-17 | Follow-up FA-007 (in progress): closed combobox lifecycle, ARIA, and real-DOM test gaps: (1) integrated `AuditSessionSearchManager` directly into `AuditSessionSelect` via `useState` and `useSyncExternalStore`, synchronizing options and eliminating test-double divergence; (2) enforced strictly-once close lifecycle contract with idempotent `close()` guarding against duplicate `onClearSearch` and duplicate resets across option click, Enter/Space on option, Enter from search input, Escape from trigger/input/option, outside click, and trigger toggle; (3) eliminated standalone fallback search races and leaks by binding requests to complete scope `{ openCycle, generation, query, hideHomeOnly, targetPathFilter, cursor }` and aborting in-flight fetches via `AbortController` on query change, clear, close, filter change, or unmount; (4) standardized preferred ARIA popup model: semantically neutral popover container (removed `role="dialog"`), trigger `role="combobox"` with `aria-haspopup="listbox"`, `aria-expanded`, and `aria-controls` pointing to dedicated listbox ID that unconditionally exists whenever expanded, searchbox (`role="searchbox"`) and auxiliary buttons (Retry, Load More, Reset) placed strictly outside `role="listbox"`, direct roving DOM focus without `aria-activedescendant`, and `aria-selected` strictly reflecting selection identity; (5) resolved focus-state edge cases: layout-safe post-mount focus via `useIsomorphicLayoutEffect`, search input focus resetting active option so Enter does not select, filtering/pagination removing active option moving focus deterministically to search input or next option, and shrinking list clamping navigated index; (6) added 17 real DOM component interaction tests in `combobox-popover.test.ts` using happy-dom, `createRoot`, and `act` asserting real keyboard dispatch, pointer events, and `document.activeElement` across all interaction paths (47 tests in file, 16 test files / 345 tests passing total, Go backend tests passing, clean ESLint with 0 errors/0 warnings, clean Next.js Turbopack production build, clean `git diff --check`). |
| 2026-09-17 | Remediated FA-007 (in progress): made Audit Session and Path comboboxes keyboard-accessible, predictable, and ARIA-compliant: (1) extracted `AuditSessionSearchManager` centralizing debounce cancellation, generation scoping, and strictly once `onClearSearch` invocation across all close reasons (`escape`, `select`, `toggle`, `outside`) and clear actions; (2) added pure calculation helper `determineFocusTarget` mapping closed trigger keydowns (`ArrowDown` -> `"first"`, `ArrowUp` -> `"last"`, `Enter`/`Space` -> `"search"`); (3) updated `useComboboxNavigation` to trigger popover opening on closed-trigger keys and apply pending focus intents after mount via `useEffect` without arbitrary `setTimeout` delays; (4) safe active bounds clamping in `useMemo` and option ref truncation on list resize without cascading state effects; (5) complete roving DOM focus supporting ArrowDown/Up, Home, End, Escape, Enter, Space, typeahead, and roving between search input and options; (6) corrected composite ARIA combobox/listbox ownership: popover container is `role="dialog"` with `aria-modal="false"` and `aria-label`, trigger has `role="combobox"` with `aria-controls` pointing to dedicated listbox ID, dedicated `<div role="listbox">` owns only `role="group"` and `role="option"` elements, searchbox (`role="searchbox"`) and auxiliary buttons (Retry, Load More, Reset) are placed cleanly outside `role="listbox"`, and `aria-activedescendant` is omitted in favor of clean roving DOM focus; (7) eliminated duplicate `onClearSearch` effects and arbitrary `setTimeout` calls in `AuditSessionSelect` and `AuditFilterControls`; (8) added 18 unit, lifecycle, and static markup regression tests in `combobox-popover.test.ts` (30 tests in file, 16 test files / 328 tests passing total, Go backend tests passing, clean ESLint with 0 errors/0 warnings, clean Next.js Turbopack production build, clean `git diff --check`). |
| 2026-09-17 | Follow-up FA-006 (in progress): separated manual HTTP refresh lifecycle from SSE transport health: (1) extracted `FilesystemRefreshLifecycleManager` with monotonic generation scoping and per-request `AbortController`, aborting in-flight refreshes on unmount or when superseded by newer manual refreshes; (2) separated auxiliary HTTP snapshot retrieval status (`refreshStatus`, `refreshError`) from real-time stream state (`streamState`), ensuring a failed manual refresh does not degrade a live SSE stream or mutate `regionStatus` to `stale`/`error` when an accepted snapshot exists; (3) updated `getFreshnessState` to treat `streamState === "live"` as authoritative for live transport when a snapshot is present, preventing contradictory `Live stream` / `Degraded · Retained snapshot` UI; (4) passed refresh responses through `SnapshotIngestionCoordinator` to deterministically reject out-of-order responses without resetting receipt time or triggering false degradation; (5) added 7 orchestration tests covering live SSE + failed refresh, late failure discard, refresh superseding, out-of-order refresh rejection, unmount abort, degraded streamState, and missing snapshot offline handling (32 tests in `filesystem-freshness.test.ts`, 15 test files / 311 tests passing total, Go backend tests passing, clean ESLint with 0 errors/0 warnings, clean Next.js Turbopack production build, clean `git diff --check`). |

| 2026-09-17 | Follow-up FA-006 (in progress): closed snapshot acceptance and stream lifecycle races: (1) replaced deferred React state updater closure mutation in `applySnapshot` with synchronous `SnapshotIngestionCoordinator`, determining acceptance synchronously against an atomic transition state, immediately returning boolean result, and synchronously firing `setRegionStatus("ready")` and `onSnapshotApplied`; (2) scoped SSE stream connection lifecycle in `FilesystemStreamLifecycleManager` with monotonically increasing connection generation number, discarding stale `onopen`, `onmessage`, and `onerror` callbacks, retry timers, and delayed fallback responses from superseded generations, preventing active connection nullification and reconnect churn; (3) integrated `AbortController` in `fetchFallbackSnapshot` to abort in-flight fallback requests upon reconnect or disposal; (4) made render-time freshness calculation purely deterministic and free of state mutations, evaluating future-skew trust marker atomically upon snapshot ingestion, keeping trust state bounded to O(1) `TelemetryTrustMarker` (`{ telemetryAt, isFutureSkew }`) without accumulating unbounded historical Sets; (5) preserved `future_skew` classification across clock catch-up, stale threshold expiry, and manual refresh with identical telemetry timestamp, recovering to Fresh upon receipt of genuinely different valid observation; (6) 25 regression tests in `filesystem-freshness.test.ts` (15 test files / 304 tests passing total, Go backend tests passing, clean ESLint with 0 errors/0 warnings, clean Next.js Turbopack production build, clean `git diff --check`). |
| 2026-09-17 | Follow-up FA-006 (in progress): stabilized SSE stream lifecycle and enforced persistent future-skew trust: (1) extracted `FilesystemStreamLifecycleManager` and stabilized `applySnapshot` referential identity (empty dependency array), eliminating connection churn and EventSource recreation across connecting -> live transitions, rerenders, and clock ticks; (2) implemented `TelemetryFreshnessTracker` making excessive future skew validation persistent per telemetry observation, preventing clock catch-up, timestamp arrival, stale threshold expiry, or manual refresh with the same timestamp from falsely transitioning to Fresh; (3) supported recovery to Fresh upon receipt of a genuinely different, valid telemetry timestamp; (4) corrected page badge precedence via `formatPageBadgeText`, guaranteeing `Degraded · Retained snapshot` on degraded transport with retained snapshot regardless of telemetry status, and reserving `Clock skew` and `No timestamp` for live transport; (5) extracted production `processSnapshotTransition` helper testing atomic updates and out-of-order snapshot rejection; (6) 19 regression tests in `filesystem-freshness.test.ts` (15 test files / 298 tests passing total, Go backend tests passing, clean ESLint with 0 errors/0 warnings, clean Next.js production build, clean `git diff --check`). |
| 2026-09-17 | Follow-up FA-006 (in progress): tracked client snapshot receipt time, enforced bounded future clock skew policy, decoupled freshness module, and preserved truthful UI labels: (1) recorded client-local epoch ms `snapshotReceivedAtMs` in `useFilesystemStreaming` atomically with snapshot upon acceptance, rejecting out-of-order snapshots without updating receipt time; (2) derived `snapshotReceiptAgeMs` strictly from `snapshotReceivedAtMs` (never server `generatedAt`); (3) removed raw `setSnapshot` from `useFilesystemStreaming` return; (4) enforced bounded future skew policy `MAX_FUTURE_TELEMETRY_SKEW_MS = 5_000` (skew <= 5s normalized to age 0 with `valid` status, skew > 5s marked `future_skew` and classified as `Stale`); (5) introduced explicit `telemetryStatus` metadata contract (`"none" \| "valid" \| "invalid" \| "future_skew"`); (6) truthful UI labels in page badge ("Stale · Clock skew", "Stale · No timestamp", "Stale · Xs ago") and topology canvas footer, plus explicit degraded snapshot receipt banner ("retained snapshot (received Xs ago)"); (7) decoupled server from UI by extracting pure freshness helpers to neutral `@/lib/filesystem-freshness`; (8) 23 regression tests in `filesystem-freshness.test.ts` covering all 12 re-audit scenarios (15 test files / 302 tests passing total, Go backend tests passing, clean ESLint with 0 errors/0 warnings, clean Next.js production build, clean `git diff --check`). |
| 2026-09-17 | Follow-up FA-005 (in progress): enforced navigation-scope invariant via unified `adoptLocalSessionScope` helper: (1) extracted `adoptLocalSessionScope` ensuring every Live navigation and local resolution has `targetHopId === null`, while preserving normalized requested hop in Audit mode; (2) wired `adoptLocalSessionScope` identically across `FilesystemActivity.selectSession` and `processSnapshotSessionResolution`, preventing path drift; (3) cleared `requestedHopRef.current` in Live mode so old audit hop cannot leak into Live state; (4) eliminated arbitrary `setTimeout` waits in tests in favor of deterministic promise completion; (5) added production helper and snapshot resolution regression tests for Live resolution, Live fallback, and Audit hop preservation. | 14 test files / 279 tests passing; Go tests passing; clean ESLint (0 errors, 0 warnings); clean Next.js build; clean git diff --check. |
| 2026-09-17 | Follow-up FA-005 (in progress): bound remote hop lookup scope and snapshot resolution cancellation: (1) added `notifySessionResolvedLocally` to `RemoteAuditLookupCoordinator` aborting in-flight remote lookups when a subsequent snapshot becomes authoritative while preserving the requested hop; (2) preserved deduplication across repeated missing snapshots; (3) tracked and forwarded actual `viewMode` in `selectSession` (`viewModeRef`), keeping Live topology node clicks in Live mode with null hop; (4) unified callback creation via exported `createRemoteAuditLookupCallbacks` configured in `useEffect` to satisfy React Compiler ref safety; (5) replaced test doubles with production orchestration tests exercising `processAuditPopState`, `processSnapshotSessionResolution`, and `createRemoteAuditLookupCallbacks`. | 14 test files / 276 tests passing; Go tests passing; clean ESLint (0 errors, 0 warnings); clean Next.js build; clean git diff --check. |
| 2026-09-17 | Follow-up FA-005 (in progress): bound remote hop lookup scope in RemoteAuditLookupCoordinator, modeling complete NavigationScope `{ viewMode, sessionId, targetHopId, generation }`; fixed retained-session popstate callback ownership by routing through authoritative UI callbacks (`lookupRemoteAuditSession`); synchronized navigation scope across popstate, user session selection (clearing hop), same-session hop transitions (A/H1 -> A/H2, A/H1 -> A/null), and pre-hydration navigation; added 5 new unit regression tests covering popstate callback path, in-flight A/H1 -> A/H2, A/H1 -> A/null, same-session user selection hop clearing, and pre-hydration invalidation. | 14 test files / 273 tests passing; Go tests passing; clean ESLint (0 errors, 0 warnings); clean Next.js build; clean git diff --check. |
| 2026-09-17 | Follow-up FA-005 (in progress): centralized remote lookup lifecycle in RemoteAuditLookupCoordinator across all navigation scopes (popstate to known session, Live/Audit mode switch, internal session selection, component unmount) with in-flight deduplication on identical target/hop and cancellation on scope change; provisioned legacy compound index `{ session_id: 1, at: -1, eventId: -1 }` on `cwd_events` in processor-agent; live MongoDB `explain("executionStats")` verified IXSCAN index-union on both branches with 0 docs examined; added automated index query contract assertions in Go and Vitest. | 14 test files / 268 tests passing; Go tests passing (0.005s); clean ESLint (0 errors, 0 warnings); clean Next.js build; clean git diff --check. |
| 2026-09-17 | Follow-up FA-005 (in progress): finalized deep-hop lifecycle and replay orchestration: preserved deep-hop scope in remote session lookup via RemoteAuditLookupManager (scoped intent, generation guards, abort on session navigation, discard late lookup), preserved terminal hop-resolution status across history background refreshes in SessionHopLifecycleManager, restored truthful mixed-schema hop numbering in getSessionCwdHistoryHop ($or match, no fan-out catch fallback, exact operation bounds contract: canonical 2, cross-session 1, legacy 3-4, unknown 3, overlength 0), and replaced simulation tests with production behavior tests. | 14 test files / 264 tests passing; clean ESLint (0 errors, 0 warnings); clean Next.js build; clean git diff --check. |
| 2026-09-17 | Follow-up FA-005 (in progress): closed deep-hop replay gaps, one-shot resolution intent clearing without session leakage, contiguous newest-first history with anchored target reconciliation, replay gap protection, independent recovery UI on empty history, deterministic HTTP 400/0-DB-op input bounds, single-field indexed scope, consolidated $facet aggregation, and regression tests. | 14 test files / 265 tests passing; clean ESLint (0 errors, 0 warnings); clean Next.js build; clean git diff --check. |
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
