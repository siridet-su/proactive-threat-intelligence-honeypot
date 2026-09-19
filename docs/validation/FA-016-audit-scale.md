# FA-016 retained Audit scale validation

Status: remediation continues; FA-016 remains `IN PROGRESS` and
FS-007 remains `PARTIAL`.

## Scope and architecture

This remediation starts at `b94b69af2e853a4e43560a7756b932ddba9eb821` and is
implemented through audited HEAD `8d9b9e9` plus documentation commit `8efee2b` on
`feat/cwd-filesystem-telemetry`. The processor owns the durable
`cwd_audit_projection` read model; `cwd_session_state` and `cwd_events` remain
authoritative source records. `cwd_audit_projection_meta` is only a readiness
hint, never the sole read-safety condition.

The follow-up migrates the projection contract to `cwd_audit_projection.v2`.
Eligible retained rows are rebuilt from persisted v1 state/projection/event
shapes, the v1 metadata marker is replaced only after eligible rows have durable
v2 projections, and obsolete `auditEventIds` data is removed. The dashboard
rejects the v1 marker and uses separate bounded generation-pending,
event-ownership, and old-writer cutover probes; the processor's per-source
v2/clean marker is written only after the projection write.

The projection separates `cwdState.path` from `auditTransitionPaths`. Public
`auditVisitedPaths` is deterministically recomputed as their union. Only
persisted `entered`/`changed` transition history contributes transition paths;
`failed_change.toPath` and command observations do not. Canonical and legacy
`sessionId`/`session_id` records are canonicalized during backfill.

Event delivery is at-least-once: `cwd_events._id` is the idempotency key, and
each new event carries an event-level pending outbox bit written in the same
upsert as the durable history record. That indexed event bit is the sole
authoritative event-work truth; the retired cross-collection source counter is
not written or used for readiness. A failed pre-upsert reservation therefore
leaves only bounded generation work, while a failed post-insert projection is
rediscovered from the durable event marker. Duplicate retries reconcile from
source history. Event-marker clearing uses `MatchedCount` as an ownership CAS,
so a second reconciler cannot acknowledge another worker's event. The
projection no longer
stores an unbounded `auditEventIds` array. Distinct transition paths are capped
at 512 per projection document; `auditPathsOverflow=true` causes an exact
cursor-aware `$unionWith` composition of every overflow source row with the
normal projection population, so no overflow session is omitted from pages,
filters, or totals. MongoDB computes the global top 100 after combining both
retained populations, while the ordinary no-overflow item pipeline remains
projection-backed with no `$lookup`.
The resulting projection path storage is at most 512 transition paths plus the
current path; source events remain TTL-retained for crash recovery and
reconciliation.

Accepted active observations advance both source and projection expiry. Stale
observations do not change state or expiry; late events after close never move
the closed expiry boundary. Missing legacy expiry is derived from closed
lifecycle time plus retention.

### Deterministic retained-projection protocol

`cwd_session_state` is the sole TTL authority for a retained CWD session.
`cwd_audit_projection.expires_at` is an ordinary indexed cleanup watermark;
the projection collection has no TTL index. Therefore a projection cannot be
TTL-deleted while its source row is retained, regardless of MongoDB's
cross-collection TTL scheduling. Reconciliation runs at startup and every 15
seconds. It examines at most 256 v2-ready source rows per canonical and legacy
session-ID cursor, checks the projection by canonical `_id`, claims missing
work through the existing generation CAS, and rebuilds exact current state,
transition paths, event count, lifecycle, and expiry facts from authoritative
source/history. The resumable cursors are stored in the readiness metadata;
duplicate and concurrent passes are safe because projection history and source
readiness retain their existing CAS rules.

Each reconciliation pass also examines at most 256 expired projection
watermarks through `{ expires_at: 1 }`. It deletes a projection only after an
indexed canonical/legacy source lookup proves `cwd_session_state` is absent;
source TTL lag therefore retains the projection, and orphan cleanup converges
without permanent projection documents. This is the exact invariant:

> A source session is eligible and ready only when its generation is clean and
> its required projection is durable; a retained source row never loses its
> projection to an independent TTL monitor, and any missing projection is
> claimed and reconstructed by the bounded startup/periodic repair cursor
> before that source generation is republished ready.

Close still reconstructs immediately for the normal close path, but recovery
does not depend on another close event. A deliberately deleted projection is
the integration-test crash/TTL-first simulation: reconciliation reconstructs
it before the ready-path assertion. No cross-collection TTL ordering is
claimed.

Backfill checks every history cursor error before accepting a result, selects
separate bounded generation-pending and v1/unversioned cutover branches,
updates source readiness only after the projection write, and publishes the
marker only after bounded pending-source, indexed pending-event, and cutover
probes. Pending events are processed incrementally from the indexed cursor;
they are never materialized in an unbounded slice.
Each source row owns monotonic
`auditProjectionGeneration`, `auditProjectionPendingGeneration`, and
`auditProjectionReadyGeneration` markers; readiness is an exact `_id` plus
generation CAS, so an older writer cannot clear newer work. Current-state and backfill writes carry `stateSequence`
plus `stateSourceEventId` and use atomic MongoDB guards; a monotonic
`auditHistoryRevision` CAS protects transition paths, overflow, visited paths,
home-only, and exact event count as one history generation. Duplicate retries
reconcile persisted event history and do not merge untrusted retry payload
paths. A 15-second reconciliation loop converges rows created by rolling/old
writers without rereading converged history. Dashboard readiness rejects v1,
ignores malformed rows under the shared valid-row contract, uses canonical
trimmed identifiers, and rechecks the bounded source cutover contract after
each projection read.

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
- `cwd_session_state`: partial `{ "lifecycle.status": 1, "auditProjectionPendingGeneration": 1 }` for steady-state generation reconciliation;
- `cwd_session_state`: `{ "lifecycle.status": 1, "auditProjectionVersion": 1, "sessionId": 1 }` and the matching `session_id` index for bounded missing-projection repair cursors;
- `cwd_session_state`: `{ "auditCanonicalSessionId": 1 }` for bounded source-presence checks during orphan cleanup;
- `cwd_session_state`: `{ "expires_at": 1 }`, `expireAfterSeconds: 0`;
- `cwd_audit_projection`: `{ "lifecycle.status": 1, "lifecycle.closedAt": -1, "sessionId": -1 }`;
- `cwd_audit_projection`: `{ "lifecycle.status": 1, "auditHomeOnly": 1, "lifecycle.closedAt": -1, "sessionId": -1 }`;
- `cwd_audit_projection`: `{ "lifecycle.status": 1, "auditVisitedPaths": 1, "lifecycle.closedAt": -1, "sessionId": -1 }`;
- `cwd_audit_projection`: `{ "auditPathsOverflow": 1 }` for bounded-readiness checks;
- `cwd_audit_projection`: `{ "expires_at": 1 }` without `expireAfterSeconds`, used only as the bounded orphan-cleanup watermark;
- `cwd_events`: partial `{ "auditProjectionPending": 1, "_id": 1 }` for the bounded event outbox probe;
- canonical and legacy `cwd_events` session compound indexes, canonical/legacy pending-event indexes, plus its TTL index.

Go unit tests assert exact key patterns/options. Integration setup first creates
the retired projection TTL index and verifies the authoritative owner converts
it to the non-TTL cleanup watermark.

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

The readiness fixture separately provisions the production source and event
indexes and records `executionStats` for the required branches: fully
converged `1,900` rows examined `0` documents and keys; the indexed pending
event probe examined `0/0` for zero pending events, `0/1` for one pending event,
and `0/1` for multiple pending events under its limit-one existence contract;
one pending v2 row examined `1/1`; one stale-version migration row examined
`1/1`; and malformed rows remained outside the eligible contract with `2/2`
bounded examination in the combined pending probe. All plans were
index-backed. A steady-state reconciliation pass performed no authoritative
session/action history reads; only the bounded pending-marker existence probe
remained.

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
source-owned cleanup, bounded missing-projection repair, retired-TTL index
migration, bounded path storage, migration fallback, and item/count/summary/
filtered execution plans.

No live/production database or manual response-agent validation was used. The
outstanding manual response-agent gate remains unrelated and recorded
truthfully in the trackers.

## Follow-up remediation evidence (2026-09-19)

Preflight on `feat/cwd-filesystem-telemetry` found a clean worktree at audited
HEAD `60a73c4`. `git fetch origin --prune` succeeded and `origin/main` was
already an ancestor, so no merge was required. The pre-edit dashboard baseline
passed 22 Vitest files, 463 passing tests, and 14 skipped tests; all five Go
module baselines passed `go test -count=1 ./...`.

The isolated FA-016 integration now seeds real v1 state, projection, and
metadata documents, proves the old marker is not ready, migrates them to v2,
removes `auditEventIds`, and verifies the v2 marker. It also covers equal-time
source-event ordering, generation-owned rolling-writer CAS, close-versus-active
interleavings, stale and accepted event crash barriers with reconciliation,
duplicate retry idempotency, padded canonical/legacy identifiers with a source
`_id` different from the canonical ID, TTL repair, missing expiry, incremental
reconciliation with zero steady-state `cwd_events` reads, and a 620-event
overflow session. The dashboard fixture proves an exact four-page mixed
overflow traversal with equal timestamps, filters, counts, cursor exhaustion,
and older overflow matches outside any bounded sample; it also provisions the
production source indexes and records readiness `executionStats`.

Observed isolated command output: `npm run test:filesystem-audit-integration`
passed 12 dashboard tests and executed 9 production FA-016 Mongo integration
tests plus 2 loopback-target safety tests in the processor (`go test -run
TestFA016 ./...`; 11 named tests executed, none skipped). New deterministic
coverage includes first-write history inspection, pending-before-upsert
close/reconcile/resume, rejected observed payloads against active and close
owners, owner-crash reconciliation, and canonical/legacy old-writer cutover
with zero subsequent `cwd_events` reads. Dashboard explain evidence remained
`26/26` documents for item pages, `1,900/1,900` for exact count and summary,
and no `$skip`, `$lookup`, or `COLLSCAN` in the projection plans; readiness
branches reported `0/0`, `1/1`, `1/1`, and `2/2` examined docs/keys for
converged, pending, stale-version, and malformed fixtures. Full repository
validation passed `npm test`, lint, build, all five Go modules, and
`git diff --check`; the isolated wrapper left no `pti-fa016-mongo-*` container
and no Playwright/test-result artifacts. Final clean-tree status and commit
Implementation commit `8d67ae6` and evidence/tracker commit `05018e1` were
created without modifying prior commits. Final clean-tree status is recorded
after those commits. FA-016 remains
`IN PROGRESS` and FS-007 remains `PARTIAL` pending final re-audit.

## Current event-outbox remediation evidence (2026-09-19)

The required preflight was clean at `7ef06f1`; `git fetch origin --prune`
succeeded, and `origin/main` (`4390d88`) was already an ancestor, so no merge
was required. Baseline processor tests passed and the dashboard baseline was
`22` Vitest files, `463` passing tests, and `14` skipped tests.

The lifecycle protocol now treats `cwd_events.auditProjectionPending=true` as
the authoritative indexed outbox bit. The source event counter is no longer
written, queried, or used for readiness; old copies are removed when a source
row passes the generation CAS. A pre-upsert failure leaves only retryable
generation work. A durable event remains discoverable after a writer crash,
and marker clear is an exclusive `MatchedCount` ownership CAS. Reconciliation
uses an incremental batch cursor, not an unbounded pending-event slice. The
dashboard readiness probe checks the same pending-event marker directly, so a
pending event with no source counter forces truthful source fallback.

The final isolated harness passed `12/12` dashboard integration tests and
executed `11` production FA-016 Mongo tests plus `2` loopback-target safety
tests, with no FA-016 test skipped. Its execution evidence remained
`26/26` for item pages, `1,900/1,900` for exact count and summary, and
`0/0`, `1/1`, `1/1`, and `2/2` for converged, pending, stale-version, and
malformed source readiness branches. Pending-event zero/one/multiple probes
were index-backed and limit-one bounded. The processor race fixtures verified
failed upsert/retry/close, crash after durable insert, concurrent reconcilers,
two pending events for one session, exact marker ownership, exact projection
facts, absent source counter, and no subsequent authoritative history reads.

Final validation passed `npm test`, `npm run test:filesystem-audit-integration`,
`npm run lint`, `npm run build`, and `go test -count=1 ./...` in all five Go
modules. `git diff --check` passed; the isolated wrapper left no
`pti-fa016-mongo-*` containers and no Playwright/test-result artifacts.
Implementation commits are `53c9cc6` and `bd351b1`; tracker/evidence updates
are in `912784f` and `36fa589`. FA-016 remains `IN PROGRESS` and
FS-007 remains `PARTIAL` pending re-audit.

## Retention-ordering remediation evidence (2026-09-19)

Preflight for this continuation started clean on
`5036d03be131572de32476a9422d9f022c58858a`. The branch was
`feat/cwd-filesystem-telemetry`; `git fetch origin --prune` succeeded;
`origin/main` was `4390d886b6fc18420b224464a553e4bfeaab0d8a`, already the merge
base, so no merge was required. The required dashboard baseline passed 22
Vitest files, 463 tests, and 14 skipped tests before edits. The root-level
`npm test` command remains inapplicable because this repository has no root
`package.json`; the dashboard package is `dashboard-v2`.

This continuation removes the independent TTL monitor from
`cwd_audit_projection`. The source-state TTL remains authoritative, while the
projection expiry index is a bounded cleanup watermark. Startup and the 15
second production reconciliation loop now use resumable 256-row canonical and
legacy source cursors to repair v2-ready rows whose projection is absent,
without a close retry. Orphan cleanup examines at most 256 expired projection
rows and deletes only after an indexed source lookup proves the source is
gone. Existing event outbox ownership, generation CAS, history CAS, and
bounded projection-backed dashboard item/count/summary paths are unchanged.

The new production Mongo integration test inserts a closed v2 source and
matching ready projection with no pending markers, deletes only the projection,
runs two concurrent production reconciliation passes, and verifies one exact
projection containing current path, both transition paths, event count,
lifecycle, and the original expiry. It verifies the ready generation is
republished, explains both the 256-row repair and cleanup queries with
`executionStats` and rejects `COLLSCAN`/missing `IXSCAN`, and verifies orphan
cleanup removes a source-less projection while retaining the repaired source
projection. The dashboard integration now verifies projection expiry is not a
TTL deletion contract. The isolated harness passed all 12 dashboard tests and
executed all 11 `TestFA016*` processor tests plus 2 target-safety tests, with
none skipped.

FA-016 remains `IN PROGRESS` and FS-007 remains `PARTIAL` pending re-audit.
