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

Events are sent to the existing Core `/v1/track` interface using the `web`
door. To preserve compatibility with that contract, the structured login JSON
is embedded after the `web-login ` prefix in the Core `cmd` field. The Core
persists its event stream on the shared data volume; the raw submitted password
is therefore credential-sensitive plaintext. Restrict access and set a
retention policy before exposing the service. The web door's own log only emits
request ID, source IP, and SQLi-indicator field names, not submitted values.

The app ignores `X-Forwarded-For` unless the immediate peer matches a network
listed in `WEB_TRUSTED_PROXY_CIDRS`. The direct ZeroTier listener should leave
that variable unset. Only configure it when a trusted proxy is introduced and
its forwarding behavior has been verified.

## Validation

The request-path tests use FastAPI's in-process test client and mock Core
transport; they do not create events in the live event store:

```sh
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
only and confirm the event reaches Core before treating collection as active.

## Rollback and known follow-up

The source move alone does not require a runtime rollback because the container
image was not rebuilt. If the build context must be reverted before deployment,
restore the Compose build path and source from the previous reviewed Git state.
The deployment Compose file remains outside Git, so changes to it must be
preserved in the operator's deployment backup until the full stack is migrated.

Follow-up work: consolidate or parameterize the sibling Compose file, define
Core event parsing into the canonical telemetry schema, review raw credential
retention/access, and add a rate-based brute-force detector if required.
