# FA-016 retained Audit scale validation

Status: implementation complete for re-audit, but FA-016 remains `IN PROGRESS`
until the final audit accepts this evidence. FS-007 remains `PARTIAL`.

## Scope and preflight

The work started from `725102189587477bd9eafe13c8ac2d6e2e97e20c` on
`feat/cwd-filesystem-telemetry`. The working tree was clean. The existing
`origin/main` ref was `4390d886b6fc18420b224464a553e4bfeaab0d8a`, already an
ancestor of HEAD, so no merge was required. `git fetch origin --prune` was
attempted and failed because this managed workspace exposes `.git/FETCH_HEAD` as
read-only; no authentication failure was inferred. The dashboard baseline
before implementation passed: 22 Vitest files, 460 passed, 2 skipped.

## Chosen architecture and ownership

The processor owns a durable `cwd_audit_projection` collection. The source of
truth remains `cwd_session_state` plus `cwd_events`; the projection is a
database-owned read model containing the exact facts needed by the retained
Audit directory:

- canonical `sessionId`, source IP, current `cwdState`, and closed lifecycle;
- deduplicated `auditVisitedPaths`, `auditEventIds`, and `auditEventCount`;
- materialized `auditHomeOnly`, schema/version, and `expires_at`.

The dashboard reads this collection only after the processor writes the
`cwd_audit_projection_meta` completion marker. Until then, it uses the existing
mixed-schema source pipeline as an explicit migration fallback. The fallback is
not the steady-state query path and is documented as potentially fan-out-heavy
until the processor backfill completes.

At startup the processor provisions the indexes, backfills closed source state
and canonical/legacy history, then writes the completion marker. New CWD events
are written to `cwd_events` with the existing `_id`/`$setOnInsert` idempotency
contract and then merged into the projection with atomic `$setUnion` updates.
The projection event-ID set makes retries and duplicate delivery converge to
one event count. A retry after a crash between the event write and projection
write repeats the same safe merge.

Close-before-history creates a closed projection tombstone. A later valid event
updates its paths and event IDs without changing the closed lifecycle. History
before close is projected first and close then adds the retention-bounded
lifecycle. Late events never extend a closed session's `expires_at`. Legacy
state/history documents are canonicalized during backfill; reads remain
compatible until the completion marker exists. The processor does not revive a
closed `cwd_session_state` document on a late event.

## Query and cursor contract

The steady-state page pipeline matches closed, projection-ready documents and
applies filters before a `$facet`. Ordering is
`lifecycle.closedAt DESC, sessionId DESC`; the cursor is the pair
`{ closedAt, sessionId }` and uses the strict lexicographic continuation
predicate. Equal timestamps therefore have a deterministic identity tie-breaker.
The implementation uses no `$skip`. A page fetches `limit + 1` rows for the
lookahead, while exact `totalItems` remains a full count of the filtered
projection population.

Search preserves the existing case-insensitive substring semantics for session
ID, source IP, and current CWD path. Target paths preserve exact-path-or-
descendant semantics. `hideHome` uses the materialized home-only fact. These
common fields are indexable where MongoDB can use the corresponding leading
keys; arbitrary substring search remains a bounded projection-row scan rather
than an unbounded history lookup. The exact summary scans the retained
projection rows and unwinds only materialized path arrays. It is intentionally
not described as O(page size): exact totals and distinct-path counts are
O(number of retained projection rows + materialized path values).

## Exact indexes

The authoritative owner is `agents/processor-agent`:

- `cwd_session_state`: `{ "lifecycle.status": 1, "lifecycle.closedAt": -1, "sessionId": -1 }`;
- `cwd_session_state`: `{ "lifecycle.status": 1, "lifecycle.closedAt": -1, "session_id": -1 }` for legacy state ordering;
- `cwd_audit_projection`: `{ "lifecycle.status": 1, "lifecycle.closedAt": -1, "sessionId": -1 }`;
- `cwd_audit_projection`: `{ "lifecycle.status": 1, "auditHomeOnly": 1, "lifecycle.closedAt": -1, "sessionId": -1 }`;
- `cwd_audit_projection`: `{ "lifecycle.status": 1, "auditVisitedPaths": 1, "lifecycle.closedAt": -1, "sessionId": -1 }`;
- `cwd_audit_projection`: `{ "expires_at": 1 }` with `expireAfterSeconds: 0`;
- existing canonical and legacy `cwd_events` compound indexes remain provisioned.

Go unit tests assert the exact key patterns and TTL option. The isolated
integration verifies the provisioned projection TTL index and real MongoDB
execution plans; declarations alone are not treated as proof of use.

## Before/after execution evidence

The before measurement used the production `buildAuditSessionsPipeline` and
`buildAuditSummaryPipeline` against an isolated `mongo:8.0` database with
1,900 closed states and 5,700 history records (three per session), followed by
`explain("executionStats")`.

| Query | State docs examined | Foreign history docs examined | Keys examined | Result |
| --- | ---: | ---: | ---: | --- |
| first page | 1,900 | 10,830,000 | 1,900 state keys | 26 lookahead rows |
| deep page | 1,900 | 10,830,000 | 1,900 state keys | 26 lookahead rows |
| exact summary | 1,900 | 10,830,000 | 1,900 state keys | full summary facet |

The after measurement used the real production projection pipelines and the
same isolated MongoDB shape. Captured output from the acceptance test was:

| Query | Documents examined | Keys examined | Plan result |
| --- | ---: | ---: | --- |
| first page | 1,900 | 1,900 | index-backed, no `COLLSCAN`, no `$lookup` |
| deep page | 1,900 | 1,900 | index-backed, no `COLLSCAN`, no `$lookup` |
| exact summary | 1,900 | 1,900 | index-backed exact full-population scan |
| filtered page (`hideHome`, `/etc`, IP substring) | 1,425 | 1,426 | index-backed projection scan, no `COLLSCAN`, no `$lookup` |

The 1,900-row page/summary bound is truthful: exact total and summary facets
must inspect the retained projection population. The materialized design removes
the multiplicative foreign-history work and keeps deep pages from repeating
history fan-out. The tests fail if `$skip`, `$lookup`, `COLLSCAN`, or a larger
than-fixture projection-row bound returns.

## Isolated integration safety

`npm run test:filesystem-audit-integration` starts an ephemeral `mongo:8.0`
container on a dynamically assigned loopback port. It validates the URI host,
database name, and lowercase run ID before connecting; the database is strictly
`pti_fa016_test_<runId>` and can never be `honeypot_db`. It runs the real
dashboard `getAuditSessions`/`getAuditDirectorySummary` implementation and the
real processor projection methods, captures aggregate commands, asserts no
`$skip`/`$lookup`, and cleans up in `finally` plus SIGINT/SIGTERM handlers. No
production data or credentials are used. The final rerun passed with 6
dashboard tests and the processor projection integration test.

The dashboard integration covered 1,900 sessions, canonical and legacy
migration fallback records, equal close times, all-page traversal, cursor
exhaustion and invalid cursors, exact totals and distinct paths, hide-home,
target path, session/source/CWD searches, page/deep/summary/filtered plans, and
TTL deletion. The processor integration covered canonical/legacy backfill,
close-before-history, late history after close, duplicate/retried history
idempotency, closed-status preservation, and the TTL index.

No manual/live response-agent validation was performed. That outstanding gate
is unrelated to FA-016 and remains recorded in the audit tracker.

## Final repository validation

- `cd dashboard-v2 && npm test`: 22 files, 463 passed, 8 skipped;
- `cd dashboard-v2 && npm run lint`: passed with zero errors and warnings;
- `cd dashboard-v2 && npm run build`: passed production TypeScript/build output;
- `go test -count=1 ./...`: passed in all five `agents/*` Go modules;
- `git diff --check`: passed;
- no persistent `npm run dev` server was started, no live MongoDB or response
  agent was contacted, and no repository Playwright/test-result artifacts were
  created.
