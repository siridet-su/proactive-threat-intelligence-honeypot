# Corporate web / fake ERP decoy

This integration owns the source for the Rattana Trading & Logistics web-corp
decoy. The login page presents an Odoo-style ERP sign-in, but the service is a
honeypot: it always rejects credentials and never forwards input to Odoo or
executes SQL.

## Source and deployment boundary

- This directory is the canonical source and standalone Docker build context.
- The deployment Compose file remains at the sibling
  `../../decoy-honeypot/docker-compose.yml` and points its `web-corp` build at
  `../proactive-threat-intelligence-honeypot/integrations/web-corp` relative to
  that Compose file.
- There is no bind mount from the source tree into the running container.
  Editing files here does not change runtime behavior; a controlled image
  rebuild and service recreation are required.
- The active HTTP listener is ZeroTier-only at `10.58.33.42:80`, mapped to app
  port `8080`. Port `8080` is internal to the container and is not separately
  published on the Pi; do not open it on the host firewall. The direct-TLS app
  container formerly bound to `10.58.33.42:443` is stopped on the Pi. Both
  service definitions remain in the sibling Compose file, outside this repo;
  a full-stack `docker compose up` can restart stopped services.
- The stopped Pi TLS certificate/key files are retained outside Git at
  `/var/lib/decoy-honeypot/web-corp-tls/{tls.crt,tls.key}`. The
  self-signed certificate SAN is `IP:10.58.33.42`, expires 2027-09-24, and is
  not trusted by browsers by default. The directory is root-only, the private
  key is mode `0400`, and the public certificate is mode `0444`.
- The legacy Odoo middleware proxy was decommissioned on 2026-09-24. The Odoo
  backend container is stopped and web-corp never proxies login requests to
  it. When the direct-TLS Pi service was active, TLS terminated in Uvicorn; the
  current Pi listener is HTTP only. The future VPS design terminates TLS at its
  edge proxy and requires separately verified proxy-header trust.

## Behavior and captured data

`GET /web/login` serves the ERP-style login page. `POST /web/login` records one
attempt and always returns a failed-login page. The older `/login.html` page and
`POST /login` endpoint remain available for compatibility. `/admin` retains its
redirect to `/login.html`. Static pages and configured bait paths still
respond, but GET/HEAD, scans, unrelated POSTs, and 404s do not create
application telemetry. Uvicorn access logging is disabled. Only login POSTs
write events to the login spool; web-corp no longer calls Deception Core.

Each login event includes a UTC timestamp, request ID, observed source IP,
HTTP scheme (`http` or `https`), method/path/query, selected request headers
(Host, User-Agent, Referer, Origin, and Accept-Language), and the submitted
database, login, password, redirect, and remember values. Values and headers
are length-bounded. The application does not collect cookies or authorization
headers. Unrelated POSTs return 404 without creating an event, and Uvicorn
access logging is disabled. The collector retains scheme-to-port mapping so a
separately deployed trusted HTTPS edge can record port 443; the current Pi
HTTP listener records port 80.

The service adds heuristic SQLi indicators to the event; they are triage hints,
not a definitive classifier. Every attempt has a timestamp and source IP so
downstream analysis can count repeated attempts, but the web door does not
currently enforce or label a brute-force rate threshold. New events include
SQLi indicators only; page/scan collection and other analyses are future work.

Each login attempt is atomically written as one mode-`0600` JSONL file in the
container's `/var/spool/web-corp-login/pending/` directory. That directory is a
bind mount from the host's root-only
`/var/lib/decoy-honeypot/web-login-spool/`. The pending queue is capped at
64 MiB; app logs contain request ID, source IP, and SQLi-indicator names, never
submitted values. The host Go collector validates each event, writes it to
Redis `raw:web-login`, and removes the spool file after Redis accepts it. The
Go processor then persists the canonical event in MongoDB
`honeypot_db.events` with the configured 30-day TTL. The raw password is
credential-sensitive plaintext in the pending spool, raw Redis stream, and
canonical Mongo event; the `event:canonical` Redis projection omits
`web_login.password`. Only authorized honeypot admins may inspect credential-
bearing copies; do not request the password in routine queries.

The HTTP app writes to this pending directory. It uses a local thread lock plus
a mode-`0600` `.write.lock` file with `flock` to serialize capacity checks and
writes; the collector ignores this hidden lock file. The previously shared
HTTPS container is stopped.

The login path does not use Core `/v1/track` and does not enter its IP-keyed
command/session classifier. Ordinary pages and bait-path requests also no
longer call Core or create app events. Older credential-bearing login or
page/scan records from before this change may remain in Core's
`/data/events.jsonl`; they are historical and are not migrated or deleted.
The collector/processor retain compatibility for any old page/scan events
already in the spool or `raw:web-login`; those are not generated by the current
app.
The Go pipeline persists login records to MongoDB, but the dashboard does not
yet provide a web-login investigation view.

The app ignores `X-Forwarded-For` unless the immediate peer matches a network
listed in `WEB_TRUSTED_PROXY_CIDRS`. The direct ZeroTier listener should leave
that variable unset. Only configure it when a trusted proxy is introduced and
its forwarding behavior has been verified.

The Pi's direct HTTPS listener is stopped. Its self-signed certificate remains
deployment-only and is not publicly trusted. The target procedure for serving
the same decoy through a publicly trusted
certificate on a public VPS IP—with the backend remaining behind WireGuard—is
in the [public-VPS HTTPS runbook](PUBLIC-VPS-HTTPS.md). That target has not been
deployed; writing the runbook did not alter the Pi or VPS.

The event contract and implementation rationale are documented in
[`docs/design/web-login-telemetry.md`](../../docs/design/web-login-telemetry.md).
The active HTTP scope versus future candidates (including post-login ERP
deception, brute-force analysis, SQLi tuning, and certificate trust/renewal) is summarized in
[`docs/design/http-decoy-scope.md`](../../docs/design/http-decoy-scope.md).
For retrieval commands and the distinction between the pending container spool,
raw Redis stream, sanitized canonical stream, MongoDB, and legacy Core records,
see [`DATA-ACCESS.md`](DATA-ACCESS.md).

## Validation

The request-path tests use FastAPI's in-process test client and a temporary
spool; they do not create events in the live event store:

```sh
python3 -m pip install -r integrations/web-corp/requirements.txt
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s integrations/web-corp/tests -v
```

For a future app update, validate the external Compose file and rebuild/recreate
only the active HTTP service from this repository:

```sh
docker compose -f ../decoy-honeypot/docker-compose.yml config --quiet
docker compose -f ../decoy-honeypot/docker-compose.yml build web-corp
docker compose -f ../decoy-honeypot/docker-compose.yml up -d --no-deps web-corp
```

The current Pi smoke check is HTTP only. Port `8080` should not appear as a
host listener; it is the container app port behind the `:80` mapping. The
planned public-IP certificate and VPS proxy path is documented in the
[public-VPS HTTPS runbook](PUBLIC-VPS-HTTPS.md):

```sh
curl -fsS -o /dev/null http://10.58.33.42/web/login
ss -ltnp | rg '10\.58\.33\.42:(80|443)|:8080\b'
```

Use synthetic values only for a login POST. Verify an event in `raw:web-login`
and MongoDB before treating a new login-pipeline deployment as complete; see
the data-access guide for checks. A TLS GET check does not verify the login
event pipeline by itself.

## Rollback and known follow-up

This change affects the web-corp app image only; collector and processor
services are unchanged. Roll back by restoring the previous reviewed web-corp
image and its Compose environment/mount, then recreating only `web-corp`. The
external Compose file is not version-controlled;
record and preserve its previous web-corp block with the deployment backup.
Keep already collected spool, Redis, and MongoDB records intact during a code
rollback. Old records previously sent to Core are not migrated by rollback.

The `web-corp-https` container is currently stopped, but its definition remains
in the external Compose file. Do not start the full stack unless reactivating
that listener is intended. Preserve the protected certificate directory for
future reviewed deployment. Follow-up work:
independently verify a MongoDB record and test from an authorized second
ZeroTier peer; implement the public-VPS HTTPS target only after its network,
certificate-renewal, proxy-header, and data-path gates are reviewed; migrate
the sibling Compose file into this repository; verify Atlas role/backup expiry
for credential-bearing documents; implement a dashboard/API query path; and
decide whether to add a rate-based brute-force detector.
