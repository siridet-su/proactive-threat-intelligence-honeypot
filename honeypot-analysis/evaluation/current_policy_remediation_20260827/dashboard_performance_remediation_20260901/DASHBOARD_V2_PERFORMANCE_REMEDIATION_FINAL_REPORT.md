# Dashboard-v2 performance remediation final report

Verification completed: `2026-09-01T15:48:26Z` UTC  
Repository: `/home/rubchek/Desktop/teammate-repo`  
Dashboard source: `/home/rubchek/Desktop/teammate-repo/dashboard-v2`  
Runtime host: `capstone` via SSH alias `honeypot-gcp`

## Result

The primary dashboard data-loading path is remediated without Redis or a
database change. The authenticated landing-page network wall fell from a
10.093-second median to 0.790 seconds across the three-sample diagnostic
benchmark. Sessions fell from 14.850 seconds to 0.524 seconds median, and
events from 7.065 seconds to 0.195 seconds median.

The session-detail page also improved from 17.028 seconds to 8.778 seconds
median. Its remaining cost is the existing bounded compatibility join: six
generic `limit=1000` table reads plus a current-prediction read. Correcting
that join would require a separate monitor/backend query-contract or index
task; no canonical backend or storage-epoch change was made here.

The final status is:

`DASHBOARD_PERFORMANCE_REMEDIATED_NO_REDIS`

## Runtime path verified

```text
browser
  -> 127.0.0.1:3000 honeypot-dashboard-v2.service
  -> Next.js BFF
  -> 127.0.0.1:8090 honeypot-monitor-web.service
  -> MongoDB Atlas / honeypot_canonical_v1
```

`dashboard-v2` makes five concurrent authenticated GET requests on the
landing page, three on the threat-intelligence list, and three on session
detail. The frontend uses `Promise.allSettled`; no API polling or duplicate
effect was found. Browser DOM paint was not automated because protected
operator credentials were not copied to the local browser environment. The
page measurements below are authenticated concurrent network-completion
probes of the exact frontend request graph, not claims about first-paint
timing.

The live services at final verification were:

| Component | Runtime state | Binding / release |
|---|---|---|
| `honeypot-dashboard-v2.service` | active, PID `3903260`, `NRestarts=0` | `127.0.0.1:3000`, `/opt/honeypot-dashboard-v2/releases/20260901-e80b04e6` |
| `honeypot-monitor-web.service` | active | `127.0.0.1:8090` |
| `honeypot-dashboard-api.service` | active | `127.0.0.1:8081` |
| canonical backend release | unchanged | `d61d4cbdf8ce5a4635870b04a72f76d5404e38ac` |

Only `honeypot-dashboard-v2.service` was restarted for the final deployment.
The monitor, dashboard API, ingest, workers, MongoDB Atlas, firewall, DNS,
and Tailscale configuration were not changed.

## Before and after measurements

All values are seconds. Each row has three samples; `p50` is the observed
median and `max` is the observed upper sample. A statistically meaningful p95
was not estimated from only three diagnostic samples.

| Measurement | Before p50 / max | After p50 / max | Observed change |
|---|---:|---:|---:|
| BFF `/api/sessions` | `14.850 / 15.467` | `0.524 / 0.740` | 96.5% lower p50 |
| BFF `/api/events` | `7.065 / 7.219` | `0.195 / 0.202` | 97.2% lower p50 |
| authenticated dashboard request graph | `10.093 / 15.026` | `0.790 / 0.949` | 92.2% lower p50 |
| BFF `/api/session` detail | `10.373 / 10.668` | `8.698 / 8.942` | 16.1% lower p50 |
| authenticated detail request graph | `17.028 / 17.628` | `8.778 / 9.013` | 48.5% lower p50 |
| direct monitor generic `/sessions?limit=100` | `0.569 / 0.572` | `0.516 / 0.529` | unchanged backend class |
| direct monitor generic `/events?limit=100` | `0.184 / 0.198` | `0.189 / 0.195` | unchanged backend class |

Response sizes and public shapes remained stable: sessions `38,467` bytes,
events `30,642` bytes, and detail `7,238` bytes in the BFF probes. The live
contract checks returned `200`, `ok=true`, an empty error field, and
`compatibility_fallback=monitor_generic_table_routes`; the final bounded
detail response contained three events, one report, and three prediction
snapshots for the controlled session.

## Request and query counts

Before the fix, the landing page made five browser requests but the BFF made
seven monitor requests: sessions and events each incurred a structured probe
and a generic fallback, while alerts, jobs, and health made one request each.
After the fix, the same five browser requests make five monitor requests; the
three compatibility keys go directly to the proven generic contract.

For detail, the browser still makes three requests. Before the fix,
`/api/session` made one structured request, six generic table requests, and a
prediction request before the separate prediction and advisory browser
requests: ten monitor requests in total. After the fix, the structured probe
is removed, leaving nine monitor requests. The six generic `limit=1000`
reads are the remaining detail bottleneck.

The isolated monitor `load_snapshot()` trace showed 65 Mongo read commands
for one structured snapshot attempt, including a failed sessions query and
57 enrichment-record lookups. The generic landing routes use one bounded
table read per table; health is liveness-only and does not query Mongo.
No application-level cache was present or added.

The measured decomposition is consistent with a backend-loader, not a BFF,
bottleneck. After the fix, direct monitor generic `/sessions` was 0.516 s p50
versus BFF `/api/sessions` at 0.524 s, and direct generic `/events` was 0.189 s
p50 versus BFF `/api/events` at 0.195 s. The approximately 6–8 ms difference
is the local BFF fetch, bounded projection, and JSON response work. Mongo
explain server execution for the generic first-100 reads was approximately
1–2 ms with 100 documents examined/returned in the sampled sessions/events
plans; the remainder is monitor-side document retrieval, public projection,
and serialization. The structured route cost was in the monitor loader and
its Mongo query, not in Next.js.

The measured Mongo command/query shape was:

| Path | Before | After |
|---|---|---|
| landing sessions/events | two structured `load_snapshot()` attempts, approximately 65 Mongo commands each, then generic fallback reads | one generic read for each table; four storage-backed landing reads including jobs and alerts; health is zero Mongo reads |
| native structured detail attempt | 14 Mongo commands before the session-table failure | not invoked by the final BFF path |
| compatibility detail | six generic table reads plus current prediction | the same seven bounded reads, without the structured probe |

The generic explain plans examined 100 sessions and 100 events for the
landing shapes. Session-scoped plans examined one session, 14 events, one
report, eight snapshots, and 563 analysis jobs; the last was a small
collection scan completing in approximately 1 ms. No index or document was
added, changed, or removed.

Pagination is bounded but not cursor-based: landing routes request 100 rows,
detail compatibility requests 1000 rows, the BFF caps `limit` at 1000, and
the current monitor generic handler does not apply the incoming `offset` to
its table read. The landing response sizes are approximately 38 KiB for
sessions and 30 KiB for events. The detail response is approximately 7 KiB
after BFF projection, although its upstream compatibility fanout transfers
larger bounded table responses before projection.

## Root-cause evidence

1. The active monitor structured `/api/sessions` route returned HTTP 200 with
   an error and zero sessions; `/api/events` returned HTTP 200 with an error;
   `/api/session` returned HTTP 404. The same monitor's generic `/sessions`,
   `/events`, `/reports`, `/prediction-snapshots`, `/jobs`, and `/alerts`
   routes returned compatible bounded projections.

2. The structured snapshot path attempted an unfiltered sessions query sorted
   by `updated_at`. The existing compound index begins with `session_source`,
   but the query did not constrain that field. MongoDB returned code 292:
   sort exceeded the 32 MiB memory limit. Query-level `allowDiskUse` and
   projection-only variants were tested read-only and did not make this Atlas
   query usable.

3. The storage adapter's session-table allowlist omitted `sessions` and
   `events`, producing a structured-detail failure. The snapshot loader also
   performed an enrichment N+1 query pattern. These are backend defects, but
   repairing them in the epoch-bound backend release was outside this
   dashboard-only task.

4. Mongo explain inspection showed the generic `_id`-ordered bounded reads
   using the existing index with approximately 1–2 ms server execution for
   the sampled first 100 rows. The session-scoped analysis-job query used a
   collection scan over only 563 documents and completed in approximately
   1 ms; it was not the latency root cause.

## Remediation and fallback behavior

The BFF now uses compatibility-first routing only when all of the following
are true:

- origin is HTTP `127.0.0.1:8090` with the normalized root path;
- route key is `sessions`, `events`, or `session`;
- the same existing bounded generic-table projection is used.

Other configured origins retain the original structured probe and fallback
behavior. Authentication, query bounds, redirects rejection, `no-store`,
8 MiB response cap, public field projections, and manual-only response
guidance semantics are unchanged.

The first deployed attempt used an empty URL pathname comparison. Live route
logs exposed that WHATWG URL normalizes the root path to `/`; the guard was
corrected in `e80b04e6`, rebuilt, and redeployed. The final monitor trace after
the corrected restart contained zero structured session, event, or detail
probes and only generic compatibility requests. The intermediate release was
not left active.

Source commits:

- `55c700ed` — `dashboard-v2: prefer measured monitor compatibility routes`
- `e80b04e6` — `dashboard-v2: match normalized loopback origin path`

The final build passed ESLint, TypeScript, the four focused dashboard
integration-contract tests, and `npm run build`. No dashboard source outside
the intended BFF/docs/test paths was included in these commits.

## MongoDB, schema, and authority safety

The live target evidence used for this benchmark resolves the production
backend as:

- backend selector: `mongodb` (the local development checkout separately
  resolves to SQLite `production_state.db`);
- transport: `mongodb+srv`;
- redacted Atlas host: `honeypot-db.o4c0xzu.mongodb.net`;
- database: `honeypot_canonical_v1`;
- storage epoch: `mongodb-target-a-honeypot-db-20260831`;
- active backend release: `d61d4cbdf8ce5a4635870b04a72f76d5404e38ac`;
- epoch/release/schema receipt: consistent;
- ping: successful; hello identified a writable primary;
- visible canonical collections: `31`, exact source-manifest set;
- unexpected TTL indexes: none.

The bounded live target check recorded events, sessions, analysis jobs,
reports, and canonical assessments as present. It also proved the controlled
session through the BFF. Existing runtime evidence reports data freshness
separately; this performance task did not create a synthetic event or claim
that historical documents prove current ingest freshness. Atlas writes,
canonical semantics, FINAL_S1/model authority, deterministic trusted lanes,
and response authority were not changed.

The dashboard/API and canonical monitor writer resolve to the same target.
The Go processor remains an active but noncanonical component writing to the
separate `honeypot_db` database with `hardware_metrics`,
`normalized_events`, and `enriched_events`; it was not started, stopped, or
modified here. Its separate-target intentionality remains a deployment
governance question, not a dashboard latency change.

## Cache decision

No process-local TTL/LRU cache and no Redis cache were added.

The landing page now completes its five-request network graph in under one
second median, the BFF and browser explicitly use `no-store`, there is one
dashboard load per mount, and no multi-instance cache requirement was found.
A cache would add staleness, invalidation, memory/privacy, and failure-mode
complexity without improving the first detail load. Redis is therefore not
justified by the measured workload.

Candidate comparison:

| Candidate | Expected benefit | Invalidation/staleness | Complexity/dependency | Decision |
|---|---|---|---|---|
| compatibility-first BFF routing | removes 2 landing probes and 1 detail probe; measured 92.2% landing p50 improvement | none; reads remain `no-store` | one dashboard release; no new memory or service | adopted |
| backend query/index/projection repair | could remove code-292 loader failure and reduce detail fanout | none if semantics/index are preserved | requires a separately reviewed epoch-bound backend release and possible index authority work | not changed here |
| process-local TTL/LRU | could help repeated identical detail loads after the first | explicit TTL/invalidation required; stale derived data possible | low dependency, bounded memory, but no measured polling/reuse | not justified |
| Redis | only useful for repeated shared expensive reads across instances | versioned keys, TTL, invalidation, and cache-failure fallback required | new private operational dependency and memory/eviction policy | not justified |

If a cache is considered later, it must remain disposable, read-only derived
state and fail back to the canonical Mongo/API path. It must not alter trusted
TTP, model, correlation, or response-authority fields.

## Safety ledger

- Mongo documents inserted/updated/deleted: `0`
- Atlas schema, indexes, users, network lists, and settings changed: `0`
- synthetic production events sent: `0`
- credentials printed, copied, or written to this report: `false`
- Mongo credential-bearing URI exposed: `false`
- canonical backend source/release/epoch changed: `false`
- services restarted: `honeypot-dashboard-v2.service` only
- firewall, DNS, Tailscale, Cowrie, Go processor, or API authority changed: `false`

## Terminal status

DASHBOARD_PERFORMANCE_REMEDIATED_NO_REDIS
