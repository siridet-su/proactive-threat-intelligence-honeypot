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
- The current listener is ZeroTier-only at `10.58.33.42:80`, mapped to the
  app's container port `8080` through the sibling Compose file. That file uses
  `WEB_CORP_BIND_IP`; verify it resolves to the intended overlay address.
- The legacy Odoo middleware proxy was decommissioned on 2026-09-24. The Odoo
  backend remains a separate loopback-only service and web-corp does not proxy
  login requests to it. Port 443/TLS is not configured.

## Behavior and captured data

`GET /web/login` serves the ERP-style login page. `POST /web/login` records one
attempt and always returns a failed-login page. The older `/login.html` page and
`POST /login` endpoint remain available for compatibility. `/admin` retains its
redirect to `/login.html`; bait paths and ordinary page requests are sent to
the deception core as web telemetry.

Each login event includes a UTC timestamp, request ID, observed source IP,
HTTP method/path/query, selected request headers (Host, User-Agent, Referer,
Origin, and Accept-Language), and the submitted database, login, password,
redirect, and remember values. Values and headers are length-bounded. The
application does not collect cookies or authorization headers. For non-login
POST requests it records method/path/query, not the request body.

The service adds heuristic SQLi indicators to the event; they are triage hints,
not a definitive classifier. Every attempt has a timestamp and source IP so
downstream analysis can count repeated attempts, but the web door does not
currently enforce or label a brute-force rate threshold.

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

Login events no longer use Core `/v1/track` and do not enter its IP-keyed
command/session classifier. Ordinary page and bait-path telemetry still uses
Core `/v1/track` under the `web` door. Older login events created before this
cutover may remain in Core's `/data/events.jsonl`; they are not migrated or
deleted by this change.

The app ignores `X-Forwarded-For` unless the immediate peer matches a network
listed in `WEB_TRUSTED_PROXY_CIDRS`. The direct ZeroTier listener should leave
that variable unset. Only configure it when a trusted proxy is introduced and
its forwarding behavior has been verified.

The event contract and implementation rationale are documented in
[`docs/design/web-login-telemetry.md`](../../docs/design/web-login-telemetry.md).
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

Before a controlled rollout, validate the external Compose file and image build
from the repository's parent directory:

```sh
docker compose -f ../decoy-honeypot/docker-compose.yml config --quiet
docker compose -f ../decoy-honeypot/docker-compose.yml build web-corp
```

Building an image does not activate it. Recreating the service and testing via
the approved ZeroTier path are separate rollout steps; use synthetic values
only and verify an event in `raw:web-login` and MongoDB before treating a new
deployment as complete. See the data-access guide for checks.

## Rollback and known follow-up

The current login-pipeline deployment can be rolled back by restoring the
previous reviewed web-corp source/image and its Compose environment/mount, then
restoring the pre-deployment collector and processor binaries and restarting
only those agent units. The external Compose file is not version-controlled;
record and preserve its previous web-corp block with the deployment backup.
Keep already collected spool, Redis, and MongoDB records intact during a code
rollback. Old records previously sent to Core are not migrated by rollback.

Follow-up work: independently verify a MongoDB record and test from an
authorized second ZeroTier peer; migrate the sibling Compose file into this
repository; verify Atlas role/backup expiry for credential-bearing documents;
configure TLS before adding port 443; and decide whether to add a rate-based
brute-force detector.
