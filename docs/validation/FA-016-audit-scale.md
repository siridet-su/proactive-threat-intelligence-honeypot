# FA-016 retained Audit scale validation

Status: implementation is ready for re-audit; FA-016 remains `IN PROGRESS` and
FS-007 remains `PARTIAL`.

## Scope and architecture

This remediation starts at `b94b69af2e853a4e43560a7756b932ddba9eb821` and is
implemented in `54c872b` plus the current follow-up on `feat/cwd-filesystem-telemetry`. The processor owns the durable
`cwd_audit_projection` read model; `cwd_session_state` and `cwd_events` remain
authoritative source records. `cwd_audit_projection_meta` is only a readiness
hint, never the sole read-safety condition.

The follow-up migrates the projection contract to `cwd_audit_projection.v2`.
Eligible retained rows are rebuilt from persisted v1 state/projection/event
shapes, the v1 metadata marker is replaced only after every eligible row has a
v2 projection, and obsolete `auditEventIds` data is removed. The dashboard
rejects the v1 marker and verifies the source/projection set before using v2.

The projection separates `cwdState.path` from `auditTransitionPaths`. Public
`auditVisitedPaths` is deterministically recomputed as their union. Only
persisted `entered`/`changed` transition history contributes transition paths;
`failed_change.toPath` and command observations do not. Canonical and legacy
`sessionId`/`session_id` records are canonicalized during backfill.

Event delivery is at-least-once: `cwd_events._id` is the idempotency key, and
duplicate retries reconcile from source history. The projection no longer
stores an unbounded `auditEventIds` array. Distinct transition paths are capped
at 512 per projection document; `auditPathsOverflow=true` causes only that
session's exact reads and summaries to use the source fallback, so truncation
is never presented as authoritative and normal sessions retain projection-backed
pages.
The resulting projection path storage is at most 512 transition paths plus the
current path; source events remain TTL-retained for crash recovery and
reconciliation.

Accepted active observations advance both source and projection expiry. Stale
observations do not change state or expiry; late events after close never move
the closed expiry boundary. Close reconstructs a missing/TTL-deleted
projection from source state and history. Missing legacy expiry is derived from
closed lifecycle time plus retention. The processor repairs an existing
`{expires_at:1}` index when it lacks `expireAfterSeconds: 0`.

Backfill checks every history cursor error before accepting a result, updates
source readiness only after the projection write, verifies that no eligible
closed source state lacks a v2 projection before publishing the marker, and is
safe to retry. Current-state and backfill writes carry `stateSequence` plus
`stateSourceEventId` and use atomic MongoDB guards; closed lifecycle and expiry
boundaries cannot be downgraded by delayed active writes. Duplicate retries
reconcile persisted event history and do not merge untrusted retry payload
paths. A 15-second reconciliation loop converges rows created by rolling/old
writers without requiring a restart. Dashboard readiness rejects v1, ignores
malformed rows under the explicit valid-row contract, scopes overflow fallback
to affected session IDs, and rechecks source completeness after each projection
read.

## Query and cursor contract

Projection item retrieval and exact counting are separate production queries.
The item query applies base/filter match, strict `{closedAt, sessionId}`
keyset continuation, indexed descending sort, and `limit + 1` before returning
documents. It contains no `$skip` or `$lookup`. Equal close timestamps are
resolved by descending canonical session identity. Exact counts and exact
summaries are separate full retained-projection operations. Arbitrary
case-insensitive substring search and complex filtered counts are documented
O(N) projection scans; they are not claimed to be page-sized.

## Exact indexes

The processor provisions and verifies:

- `cwd_session_state`: `{ "lifecycle.status": 1, "updatedAt": -1, "sessionId": -1 }`;
- `cwd_session_state`: `{ "lifecycle.status": 1, "lifecycle.closedAt": -1, "sessionId": -1 }`;
- `cwd_session_state`: `{ "lifecycle.status": 1, "lifecycle.closedAt": -1, "session_id": -1 }`;
- `cwd_session_state`: `{ "lifecycle.status": 1, "auditProjectionVersion": 1 }` for readiness checks;
- `cwd_session_state`: `{ "expires_at": 1 }`, `expireAfterSeconds: 0`;
- `cwd_audit_projection`: `{ "lifecycle.status": 1, "lifecycle.closedAt": -1, "sessionId": -1 }`;
- `cwd_audit_projection`: `{ "lifecycle.status": 1, "auditHomeOnly": 1, "lifecycle.closedAt": -1, "sessionId": -1 }`;
- `cwd_audit_projection`: `{ "lifecycle.status": 1, "auditVisitedPaths": 1, "lifecycle.closedAt": -1, "sessionId": -1 }`;
- `cwd_audit_projection`: `{ "auditPathsOverflow": 1 }` for bounded-readiness checks;
- `cwd_audit_projection`: `{ "expires_at": 1 }`, `expireAfterSeconds: 0`;
- canonical and legacy `cwd_events` session compound indexes plus its TTL index.

Go unit tests assert exact key patterns/options. Integration setup first creates
an incorrect non-TTL projection expiry index and verifies the authoritative
owner repairs it.

## Reproducible explain evidence

The committed isolated integration fixture contains 1,900 closed projection
documents. Its `explain("executionStats")` output is reported independently:

| Operation | Documents examined | Keys examined | Result |
| --- | ---: | ---: | --- |
| unfiltered item | 26 | 26 | `limit + 1` item bound, IXSCAN-backed |
| deep item | 26 | 26 | `limit + 1` item bound, IXSCAN-backed |
| exact total count | 1,900 | 1,900 | truthful full exact count |
| exact summary | 1,900 | 1,900 | truthful full exact summary |
| filtered item | 513 | 513 | filtered projection scan; substring component is O(N) |
| filtered count | 1,425 | 1,426 | truthful exact filtered count |

All steady-state plans contain no `$skip`, `$lookup`, or `COLLSCAN`. The
unfiltered item bound is the page-sized guarantee; count and summary work is
not incorrectly included in that claim. Unsupported exact before numbers have
been removed; the prior full-fan-out behavior remains reproducible through the
legacy production pipeline and is explicitly the migration fallback, not an
accepted steady-state bound.

## Isolated integration safety and validation

`npm run test:filesystem-audit-integration` starts an ephemeral `mongo:8.0`
container on a dynamic loopback port. The wrapper and directly executable Go
test both require `FA016_MONGO_URI`, `FA016_MONGO_DB`, and
`FA016_MONGO_RUN_ID`; validate lowercase alphanumeric run IDs, exact
`pti_fa016_test_<runId>` naming, URI/database equality, `mongodb://`, loopback
host, and reject `honeypot_db`. Rejected Go targets invoke zero connection or
destructive callbacks. Cleanup runs in `finally` and on SIGINT/SIGTERM.

The real dashboard production query implementation and processor projection
methods are exercised. Coverage includes 1,900 sessions, canonical/legacy
records, equal timestamps, complete keyset traversal, cursor exhaustion and
invalid cursors, exact totals/distinct paths, `hideHome`, target path, session
ID, source IP, CWD search, late history, duplicate retries, missing expiry,
TTL deletion, incorrect TTL repair, bounded path storage, migration fallback,
and item/count/summary/filtered execution plans.

No live/production database or manual response-agent validation was used. The
outstanding manual response-agent gate remains unrelated and recorded
truthfully in the trackers.

## Follow-up re-audit evidence (2026-09-19)

Preflight on `feat/cwd-filesystem-telemetry` found a clean worktree at
`a6f9aba`; `git fetch origin --prune` succeeded and `git merge origin/main`
reported `Already up to date.` No fetch or merge failure occurred. The
pre-edit dashboard baseline passed: 22 Vitest files, 463 passing tests, and 8
skipped tests.

The isolated FA-016 integration now seeds real v1 state, projection, and
metadata documents, proves the old marker is not ready, migrates them to v2,
removes `auditEventIds`, and verifies the v2 marker. It also covers equal-time
source-event ordering, delayed current-state writes, close-versus-active and
backfill interleavings, retry payload idempotency, TTL repair, missing expiry,
and a 620-event overflow session. The dashboard overflow fixture proves exact
target-path and summary results for the overflow session, bounded 512-entry
projection storage, projection-backed ordinary pages, and no global fallback
for normal sessions.

Observed isolated command output: `npm run test:filesystem-audit-integration`
passed 7 dashboard tests and both processor FA-016 integration tests. Dashboard
explain evidence remained `26/26` documents for item pages, `1,900/1,900`
for exact count and summary, and no `$skip`, `$lookup`, or `COLLSCAN` in the
projection plans. Full repository validation and final clean-tree checks remain
required before FA-016 can be accepted; FA-016 therefore remains `IN PROGRESS`
and FS-007 remains `PARTIAL`.
