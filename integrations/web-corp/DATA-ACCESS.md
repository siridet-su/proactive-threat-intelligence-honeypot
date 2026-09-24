# Web-corp login event access guide

This guide is for authorized honeypot administrators and developers working
under that authorization. Login events intentionally retain the submitted
password as plaintext and may also retain a bounded query from the login URL.
Historical `web_http_request` records may contain bounded literal paths and
queries. The current app emits telemetry only for login POSTs: page views,
scans, unrelated POSTs, and 404s are not captured, and the app does not call
Deception Core. Terminal output, Redis responses, Mongo query results, and
pending spool files can contain credential-sensitive data. Do not paste their
contents into tickets, chat, source control, or ordinary logs.
The GCP dashboard `/http-activity` read-side queries `honeypot_db.events`; it
does not consume Redis directly or write MongoDB. The production projection
and unauthenticated API boundary were checked on 2026-09-25, but authenticated
browser rendering was not exercised. The broad feed omits submitted values;
the exact-session detail API exposes captured fields only to an authenticated
Admin. Use the authorized retrieval steps below if the dashboard is unavailable.

## Where data lives

| Location | Contents | Lifecycle |
| --- | --- | --- |
| web-corp container spool `/var/spool/web-corp-login/pending/` | One JSONL file per login attempt, including the submitted password | Retry queue only; collector removes a file after Redis accepts it |
| Redis `raw:web-login` | Full bounded event in the `payload` field | Transient, bounded stream (maximum length configured by collector, currently 50,000 entries) |
| MongoDB `honeypot_db.events` | Canonical normalized event; login password at `web_login.password`, login URL query at `http.query`; older page events may also have `http.raw_path`/`http.query` | Durable event store with the processor's current 30-day TTL |
| Redis `event:canonical` | Normalized downstream projection without `web_login.password`, `http.query`, or `http.raw_path` | Bounded stream for consumers that do not need literal submitted values |
| GCP dashboard `/http-activity` | Read-only projection of Web-corp login attempts and retained page events; detail endpoint returns captured payload fields only to Admin | Authenticated, no-store API; production projection/auth boundary checked 2026-09-25, authenticated browser render not exercised |
| Deception Core container `/data/events.jsonl` | Historical `/v1/track` records from the prior web-corp implementation; may include credential-bearing login commands and page/scan events | Historical only; the current web-corp app does not call Core |

The event ID/request ID is the same across the app spool filename, raw Redis
payload, MongoDB `event_id`, and canonical Redis event. Use it to correlate
copies and deduplicate Redis stream deliveries: the pipeline is at-least-once,
so a retried raw entry or canonical projection may be repeated even though the
MongoDB record is idempotently upserted. Odoo/PostgreSQL is not the login
telemetry store.

The previous app version also wrote `web_http_request` page/scan events into
the shared spool/Redis path. The collector/processor retain compatibility for
those pre-change events while they drain, but the current web-corp app emits
only `web_login_attempt`. Do not treat older page/scan records as current
collection behavior.

## Inspect pending files in the web-corp container

Run these on the honeypot host, using the running Compose project. The files
inside this container are also visible to the host collector at
`/var/lib/decoy-honeypot/web-login-spool/pending/`.

```sh
docker compose -f /home/cpe27/decoy-honeypot/docker-compose.yml \
  exec -T web-corp sh -lc \
  'find /var/spool/web-corp-login/pending -maxdepth 1 -type f -name "*.jsonl" -printf "%f\n"'
```

To inspect a pending event (this prints its submitted password):

```sh
docker compose -f /home/cpe27/decoy-honeypot/docker-compose.yml \
  exec -T web-corp sh -lc \
  'for f in /var/spool/web-corp-login/pending/*.jsonl; do [ -f "$f" ] && sed -n "1p" "$f"; done'
```

The collector normally drains this queue within a second and deletes each file
after Redis `XADD` succeeds, so an empty directory is the healthy steady state,
not evidence that no events have been collected. Files under the sibling
`quarantine/` directory failed schema validation; inspect them only as an
administrator and do not move them back into `pending/` without correcting the
record. The app caps the pending spool at 64 MiB; on capacity or filesystem
failure it still rejects the login but logs a delivery error containing the
request ID, not the submitted values.

## Inspect raw and canonical Redis streams

Redis is bound to host loopback. Run the commands on the honeypot host; do not
publish Redis to an attacker-facing or overlay interface.

```sh
redis-cli -h 127.0.0.1 -p 6379 XLEN raw:web-login
redis-cli -h 127.0.0.1 -p 6379 XINFO GROUPS raw:web-login
redis-cli -h 127.0.0.1 -p 6379 XREVRANGE raw:web-login + - COUNT 10
```

Use `XLEN` and `XINFO GROUPS` for routine status checks. Avoid `XINFO STREAM`
for routine checks because its first/last entry samples include the payload.
The `payload` value in `raw:web-login` is a JSON string containing the full
bounded login event, including the raw password; `XREVRANGE` and the decode
example below print it. Redis stream entries are processed by the group shown
in `XINFO GROUPS` (default name: `processor`). To check a consumer backlog, use
the actual group name:

```sh
redis-cli -h 127.0.0.1 -p 6379 XPENDING raw:web-login processor
```

To decode the newest raw event with `redis-cli` JSON output and `jq`:

```sh
redis-cli --json -h 127.0.0.1 -p 6379 \
  XREVRANGE raw:web-login + - COUNT 1 \
  | jq -r '.[0][1] as $kv
    | reduce range(0; ($kv | length); 2) as $i ({}; .[$kv[$i]] = $kv[$i + 1])
    | .payload | fromjson'
```

That command reveals the submitted password. The downstream projection is
deliberately different:

```sh
redis-cli -h 127.0.0.1 -p 6379 XREVRANGE event:canonical + - COUNT 10
```

`event:canonical` retains request context and SQLi indicator names but omits
`web_login.password`, `http.query`, and `http.raw_path`; use MongoDB for the
literal submitted fields when authorized.
If Redis authentication is enabled, use the operator-approved interactive
credential method. Do not put a Redis password directly in command arguments.

## Query canonical MongoDB events

Connect using the approved admin MongoDB client and its protected credential
configuration; do not paste the Mongo URI or password into a command line.
Then select recent login attempts without requesting the password field:

```javascript
const webLoginDb = db.getSiblingDB("honeypot_db");
webLoginDb.events.find(
  { source: "web-corp", event_type: "web_login_attempt" },
  {
    _id: 0,
    event_id: 1,
    timestamp: 1,
    "network.src_ip": 1,
    "network.dst_port": 1,
    "network.service": 1,
    "web_login.database": 1,
    "web_login.username": 1,
    "web_login.redirect": 1,
    "web_login.remember": 1,
    "http.scheme": 1,
    "http.method": 1,
    "http.path": 1,
    "analysis.sqli": 1,
    outcome: 1,
    truncated_fields: 1
  }
).sort({ timestamp: -1 }).limit(20).toArray();
```

The raw Redis source event preserves empty strings. The processor's normalized
Mongo/canonical event omits empty strings during compaction, so a missing
optional string such as `web_login.remember` represents an empty source value
in the current schema.

Only when the raw value is specifically needed for an authorized
investigation, retrieve it by a known event ID:

```javascript
webLoginDb.events.findOne(
  { event_id: "<request-id>" },
  { _id: 0, event_id: 1, timestamp: 1, "web_login.password": 1 }
);
```

The processor indexes source/event type/time, source IP/time, and
`web_login.username`/time. It intentionally creates no password index.

## Read legacy records from the Core container

Before the dedicated spool/Redis cutover, the app placed login JSON after the
`web-login ` prefix in a Core `/v1/track` command. Those historical lines may
still contain submitted passwords; the implementation does not migrate or
delete them. New web-corp login events must not be expected in this file.

```sh
docker compose -f /home/cpe27/decoy-honeypot/docker-compose.yml \
  exec -T deception-core sh -lc 'grep -F "web-login " /data/events.jsonl'
```

This prints complete credential-bearing legacy records. Avoid `docker logs`
and application error logs as a data-retrieval method; the app logs event IDs,
source addresses, and indicator names only, not form values.

## Troubleshooting order

1. Check pending files in the web-corp container. A growing queue suggests the
   collector cannot reach Redis or cannot validate the spool files.
2. Check `raw:web-login` length/group state and the processor service logs.
   Mongo failures leave Redis messages pending for retry; the processor must
   not acknowledge before the Mongo upsert succeeds.
3. Query `honeypot_db.events` by `source` and `event_type`. The canonical
   record is retained for the configured 30 days; TTL deletion is asynchronous.
4. Check `event:canonical` only for the redacted downstream projection. It is
   not the place to retrieve the raw password.
