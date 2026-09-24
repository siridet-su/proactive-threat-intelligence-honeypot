---
title: Web-corp login telemetry design
status: current
last_verified: 2026-09-25
---

# Web-corp login telemetry design

## Status and intent

This document defines the event contract and operational boundaries for login
attempts against the Odoo-style web-corp decoy. The dedicated local spool →
Redis → MongoDB path is implemented and active on the Pi; deployed verification
is recorded in [validation evidence](../validation/2026-09-24-web-login-pipeline.md).
The intended readers and consumers of credential-bearing records are
honeypot administrators.

The login handler writes one bounded JSONL event to its mounted pending spool.
The current Pi listener is ZeroTier HTTP `:80` → container `:8080`. The direct
TLS app container on Pi `:443` is stopped; publicly trusted HTTPS on a VPS is
target work, not an active listener. The HTTP app no longer emits page/scan
events or calls Deception Core, and Uvicorn access logging is disabled. GETs,
scans, and 404s therefore do not enter the web-login telemetry path. Historical
Core records from the previous implementation are retained as-is. The Go
collector/processor still accept the former `web_http_request` event shape so
any already-spooled or queued events can drain; the current app does not create
new events of that type.

## Goals and boundaries

- Record each submitted login attempt, including submitted field values, to
  study password spraying/brute-force behavior and SQL-injection attempts.
- Always reject the login. Never authenticate against Odoo, execute submitted
  SQL, or forward attacker-controlled values to Odoo/PostgreSQL.
- Preserve enough request context for investigation and later correlation.
- Integrate with the existing collector → Redis → processor → MongoDB event
  pipeline without adding login credentials to Cowrie command/session state.
- Keep the event data available only to authorized honeypot administrators and
  approved service identities.

This design covers login attempts at `web-corp` only. OpenCanary remains a
separate HTTP decoy and is not the web-corp login handler. Page views and bait
path/scan telemetry are intentionally not collected in the current phase. Mock
ERP records, post-login pages, and post-login user actions are future work.
For the broader HTTP current/future boundary—including the distinction between
the existing fake login persona and optional interactive post-login deception—
see [HTTP decoy scope](http-decoy-scope.md).

## Current event path

```text
web-corp login handler
  -> root-only host spool, mounted in container at
     /var/spool/web-corp-login/pending (one mode-0600 JSONL file per attempt)
  -> Go collector: source=web-corp, log_type=web_login
  -> Redis raw:web-login (bounded transient queue)
  -> Go processor: validate, normalize, deduplicate by event_id
  -> MongoDB honeypot_db.events (credential-bearing event, current 30-day retention)
  -> Redis event:canonical (admin-safe projection without login.password)
  -> administrator-only investigation/query tools
```

The Compose bind mount maps host
`/var/lib/decoy-honeypot/web-login-spool/` to container
`/var/spool/web-corp-login/`. Pending event files live in the `pending/`
subdirectory, are atomically renamed into place, and use mode `0600`; the
directory is mode `0700`. The app caps pending data at 64 MiB. Each event is
bounded to 32 KiB at the collector. The spool is a retry queue, not a history
store: the collector validates the event, XADDs it to Redis, then removes the
file. Invalid files move to a restricted `quarantine/` subdirectory. When the
collector/Redis is unavailable, events remain pending until service recovers or
the 64 MiB cap is reached; the app still rejects logins and logs request ID,
source IP, and delivery status, never submitted values.

The host collector polls the mounted spool once per second and writes full
bounded payloads to `raw:web-login` (shared raw-stream cap: 50,000 entries).
This is a size bound, not an age-based TTL; stream entries remain until
max-length trimming removes them.
The processor's consumer group is `processor`; it upserts MongoDB using the
stable request ID as `event_id`, creates no password index, and acknowledges
the raw Redis entry only after the MongoDB upsert and sanitized canonical
stream write succeed. The deployed processor retention is `720h` (30 days);
`expires_at` is based on the observed event time and the `events` collection
uses its TTL index. No Odoo/PostgreSQL database is used for login telemetry.

### Why the login path is separate from Deception Core

Core `/v1/track` is a behavior/session tracking interface, not a dedicated
credential-bearing login-event contract. It updates IP-keyed session state and
records the supplied command for classification. Embedding a login event there
would place submitted credentials in generic command/session data. The current
web-corp app therefore does not call Core at all: login attempts use the
restricted spool pipeline, while ordinary pages and scan paths produce no
application telemetry. Older Core records from before this boundary remain
historical and are not migrated or deleted.

## Event contract

One event represents one HTTP form submission. `event_id` is the request ID
created once for that submission and reused through retries. `event_type` is
`web_login_attempt`; `source` is `web-corp`; `schema_version` is incremented
when the contract changes incompatibly.

| Field | Meaning | Handling |
| --- | --- | --- |
| `event_id` | Stable request ID / deduplication key | Required; same value on retry |
| `timestamp` | Time the app observed the submission, UTC | Required; keep separate `ingested_at` |
| `source`, `log_type`, `event_type`, `schema_version` | Producer and schema identity | Fixed values for this event kind |
| `network.src_ip` | Observed client address | Derive from peer; honor forwarded address only from configured trusted proxies |
| `network.src_port` | Observed TCP client source port (sensor JSON: `source_port`) | Optional integer 1–65535. Use the socket peer port directly; behind a configured trusted proxy, accept only its overwritten `X-Forwarded-Client-Port`. Missing/invalid values remain absent; this is transient connection metadata, not an identity. |
| `http.scheme`, `http.method`, `http.path`, `http.query` | Request transport and target/context | Scheme and method are bounded; query/path may themselves contain attack input; scheme drives destination port 80/443 downstream |
| `http.headers` | Selected Host, User-Agent, Referer, Origin, Accept-Language | Bounded allowlist; do not capture cookies or Authorization |
| `web_login.database`, `web_login.username`, `web_login.password`, `web_login.redirect`, `web_login.remember` | Values submitted in the login form (source JSON uses `odoo_login`) | Raw Redis preserves all bounded values, including plaintext password and empty strings. Mongo normalization preserves non-empty values; the generic compactor currently omits empty strings. |
| `analysis.sqli.indicators` | Heuristic indicator names grouped by submitted field | Hints only; never claim a confirmed exploit from a regex match |
| `outcome` | Decoy response/result | Always `rejected`; no credential validation |

The handler limits individual form values and selected headers to 256
characters, `remember` to 32 characters, and the query/path to 512 characters.
It records field names in `truncated_fields` whenever a value is shortened; the
processor preserves that list. Do not store request bodies from unrelated POST
routes in this event.

The processor places the structured login fields in the dedicated `web_login`
object, not in `activity.command`, identity fields, or free-form service logs.
The Mongo `raw.payload` passthrough still includes non-password fields from the
source `odoo_login` object; its `password` key is removed so the plaintext
password occurs only in `web_login.password`. The bounded raw form values are
already the honeypot evidence; hashing is not a substitute for them and is not
required for the first version. Do not index the password field.

The source event in `raw:web-login` preserves empty form strings. The
processor's generic compaction removes empty strings from Mongo and
`event:canonical`; absence of an optional normalized string therefore means
the source value was empty. A follow-up login validation confirmed this for an
empty `remember` value. Preserve empty-vs-absent distinctions in a future
schema change if downstream analysis requires them.

## Credential handling and access

The design intentionally retains the submitted password as plaintext because
the honeypot's research purpose includes examining what was attempted. This is
a deliberate, scoped exception to the project's general rule that adapters do
not emit passwords by default; it does not authorize collection of credentials
from legitimate users or production systems.

All people permitted to read these records are honeypot administrators. Treat
the password field as credential-sensitive even within that audience:

- Restrict the mounted spool, Redis credentials, MongoDB collection, backups,
  and operational access to the service identities and authorized admins. The
  spool and pending files are host/container mode `0700`/`0600`.
- Do not emit form values in application logs, error messages, metrics, traces,
  test output, documentation, or fixtures. Log event ID and delivery status
  only.
- Keep the raw credential out of normal dashboard/table projections and
  analysis prompts. Provide it only in an explicitly credential-bearing admin
  investigation view/query.
- Reuse the canonical event retention setting (deployed value 30 days) and
  verify TTL deletion and backup expiry. The pending spool has a 64 MiB size
  cap and drains after Redis accepts each event; it is not time-retained.
- Redis is a bounded transient queue, not the canonical archive, but raw
  stream entries still contain sensitive data while queued. The
  `event:canonical` projection intentionally removes `web_login.password`.
- This rollout did not change or independently verify Atlas encryption-at-rest,
  backup expiry, or database role assignments; verify those controls through
  the existing operations process.

HTTPS encrypts the client-to-decoy transport, but does not change storage
handling: the raw spool, Redis, and MongoDB still contain the bounded submitted
password. The Pi's direct-TLS service is stopped; its self-signed ZeroTier-IP
certificate is retained outside Git but is not currently served. The public
VPS certificate/proxy path is a target deployment documented in the
[VPS HTTPS runbook](../../integrations/web-corp/PUBLIC-VPS-HTTPS.md).

No separate password hash/fingerprint is needed while the raw sample is kept.
If a future retention policy removes raw values but needs grouping, evaluate a
keyed HMAC with a documented key lifecycle as a separate decision.

## Brute-force and SQL-injection analysis

The service records all attempts and always rejects them; it does not lock an
account, slow the attacker, or change its response based on the submitted
values. Repeated attempts can be counted from event timestamps, source IP, and
normalized username. A later detector may emit a separate derived finding
linked to the source event IDs. Its sliding window, threshold, account
normalization, and whether IP/account combinations are grouped remain open
policy decisions and must be configurable; do not bake an unapproved threshold
into the login handler.

SQL-injection indicators remain heuristic labels (for example SQL comments,
`UNION SELECT`, tautology-like expressions, time-delay functions, metadata
references, stacked statements, and SQL keywords). Store the original bounded
submitted values alongside the indicator names so an administrator can review
why a rule fired. Detection must never evaluate a submitted expression.

## Delivery and query contract

- Collector writes events to a dedicated bounded Redis stream named
  `raw:web-login`; it must not reuse `raw:cowrie` or `raw:zeek:*`.
- Processor validates required fields, maps network and HTTP context into the
  common event envelope, and writes the dedicated login object to
  `honeypot_db.events` using `event_id` as the idempotent key.
- MongoDB is the durable canonical record that retains `web_login.password`.
  The `event:canonical` Redis projection omits that field while preserving
  non-password context needed by admin dashboards. The raw spool and
  `raw:web-login` queue contain the full bounded event and remain
  credential-sensitive until the spool drains or Redis trims an old entry at
  its configured maximum length; Redis raw-stream retention is not time-based.
- A raw Redis message is acknowledged only after the MongoDB upsert and
  canonical-stream write succeed. The Mongo document is idempotently upserted
  by `event_id`; because Redis delivery is at-least-once, raw stream entries or
  `event:canonical` projections can repeat after a retry. Downstream consumers
  should deduplicate those stream records by `event_id`.
- Do not enqueue web-corp login events for threat-intelligence lookups. They
  have no approved TI use in this phase and must not send credential-bearing
  payloads to external providers.
- Authorized admins should be able to query by time range, source IP,
  username, outcome, event ID, and SQLi indicator, and retrieve the submitted
  password only when specifically needed. The implemented query commands and
  container/Redis access paths are in the
  [web-corp data access guide](../../integrations/web-corp/DATA-ACCESS.md).

## Conformance and remaining decisions

The following implementation requirements are active and covered by unit or
deployed validation:

1. Login attempts use the spool and Redis stream, not Core's generic
   command/session route.
2. The collector validates schema and stable IDs; the processor stores the
   normalized event and redacts the password from the canonical Redis
   projection. Unit tests cover malformed metadata, password placement, SQLi
   markers, and retention parsing.
3. Tests verify truncation metadata, spool capacity handling, and rejection of
   login attempts regardless of submitted values.
4. A synthetic deployed SQLi-shaped attempt appeared in the raw Redis stream
   and redacted canonical stream; the collector drained the spool and the
   processor acknowledged after its MongoDB upsert. See the linked validation
   report for scope and limitations.

Remaining decisions: brute-force threshold/window/grouping and whether a
derived finding should be materialized; Atlas backup/role verification; and
dashboard/API integration for querying web-login events (currently available
through approved Redis/Mongo tools only). After-login ERP data and behavior
remain future work. No brute-force threshold is assigned; repeated attempts
are captured for downstream analysis.

## Related material

- [Corporate web decoy runbook](../../integrations/web-corp/README.md)
- [Web-corp data access guide](../../integrations/web-corp/DATA-ACCESS.md)
- [Decoy-stack telemetry design](decoy-stack-telemetry.md)
- [Data ownership and event-flow contract](../DATA-OWNERSHIP.md)
- [ADR-0005: tracked corporate web-decoy source](../adr/ADR-0005-corporate-web-decoy-source.md)
