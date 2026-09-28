---
title: HTTP(S) decoy current scope and future work
status: current
last_verified: 2026-09-28
---

# HTTP(S) decoy: current scope and future work

## Purpose and boundary

The active HTTP decoy is `web-corp`, an Odoo-style ERP login persona. Its
current objective is to record login submissions—especially brute-force and
SQL-injection-shaped input—without authenticating anyone or forwarding values
to Odoo/PostgreSQL. On the Pi, one container is exposed on ZeroTier TCP 80;
a second is bound only to the Pi WireGuard address on TCP 80. Both map to app
port 8080 inside their containers, which is not separately host-published.
The Droplet serves public HTTPS 443 and reaches the second container over
WireGuard. The direct-TLS Pi service on port 443 remains stopped. Odoo is
stopped and is not part of the login path.

The fake login page is already deception: it presents a plausible login
surface, records submissions, and always rejects them. “Post-login deception”
means a later, more interactive fake ERP experience after a submission; that
is future work, not a prerequisite for the current login-collection purpose.
Any such experience must remain synthetic and must not authenticate against
Odoo or execute attacker-supplied SQL.

## Current work

| Capability | Current behavior | Boundary / limitation |
| --- | --- | --- |
| HTTP persona | The Odoo-style ERP login page and compatibility routes are served on ZeroTier `:80` and privately on Pi WireGuard `:80`. Bait paths still receive their configured static response or 404. | Only login POSTs generate application telemetry. GET/HEAD, scans, unrelated POSTs, and 404s are not recorded by the app; Uvicorn access logging is disabled. Zeek records allowed network flows. |
| HTTPS | The Droplet serves a publicly trusted public-IP certificate on `:443` and proxies over WireGuard. HTTP `:80` serves ACME challenges and redirects. | The direct Pi HTTPS container stays stopped. Renewal dry-run and synthetic end-to-end telemetry passed; an actual renewal has not yet occurred. See the [public-VPS HTTPS runbook](../../integrations/web-corp/PUBLIC-VPS-HTTPS.md). |
| Login collection | Each login form submission records a bounded event with UTC timestamp, request ID, source IP, scheme, method/path/query, selected headers (including User-Agent), and submitted login form fields. | Sensitive submitted values, including the password, are retained in the restricted raw spool/Redis/Mongo path as documented in the [login telemetry design](web-login-telemetry.md). Cookies and Authorization headers are not collected. |
| Delivery and storage | The active HTTP app writes login attempts to the restricted host spool; the collector publishes to `raw:web-login` and the processor persists to MongoDB `honeypot_db.events`; `event:canonical` omits credential-bearing fields. | Web-corp no longer calls Deception Core. The GCP dashboard has a read-only `/http-activity` view/API for login and retained historical page events. Its production Mongo projection and unauthenticated API boundary were checked on 2026-09-25, but an authenticated browser render was not exercised. |
| Brute-force evidence | Attempts include time, source IP, and submitted login value, so an analyst can query and count repeated attempts. | No rate threshold, automated brute-force finding, alert, slowdown, or lockout is active. Capturing attempts is not the same as detecting or responding to brute force. |
| SQL-injection evidence | The app attaches heuristic SQLi indicator labels to login events; submitted input is never evaluated as SQL. | Indicators are triage hints, not a complete or precision-validated SQLi detector. No SQL reaches Odoo/PostgreSQL. |
| Response and backend isolation | Login attempts are rejected regardless of credentials or payload. Odoo/PostgreSQL are not contacted by the web-corp login handler. | The decoy does not verify credentials or pass a login through to the real ERP. |
| OpenCanary | A separate HTTP-only OpenCanary login decoy is prepared for loopback staging and currently stopped. | It is not the active web-corp listener and is not connected to the web-corp login event pipeline. |

The login event contract, retention, sensitive-data handling, and retrieval
instructions are maintained in the [web-corp login telemetry design](web-login-telemetry.md),
[web-corp runbook](../../integrations/web-corp/README.md), and
[data-access guide](../../integrations/web-corp/DATA-ACCESS.md).

## Future work (not implemented or approved by this document)

- Design a fake post-submission ERP landing/workspace with synthetic records
  and safe, non-persistent interactions. This is optional post-login
  deception; it must not become real Odoo authentication.
- Verify the authenticated dashboard view with synthetic login events. Any
  configurable brute-force analysis job, derived findings, or alerts remain
  future work; first define time windows, grouping, thresholds, and
  false-positive handling.
- Evaluate and tune SQLi indicator quality against a safe test corpus; keep
  it observational and never execute submitted expressions.
- Decide whether to collect page views, bait-path scans, or other non-login
  HTTP activity. They are intentionally not part of the current telemetry.
- Monitor the short-lived public-IP certificate renewal, proxy reload, and
  public traffic volume; see the
  [public-VPS HTTPS runbook](../../integrations/web-corp/PUBLIC-VPS-HTTPS.md).
- Decide separately whether OpenCanary has a distinct role or should remain
  staged; do not treat it as part of the active web-corp flow until an adapter
  and deployment boundary are reviewed.
- Consider unifying page/bait telemetry with the login event analytics only
  after defining a correlation contract between Core's local event path and
  the canonical MongoDB event path.

These are candidate work items, not commitments. A future change that alters
exposure, event fields, retention, backend interaction, or response behavior
needs its own review, validation, and implementation-log entry.

## Current flow at a glance

```text
HTTPS login POST -> Droplet TLS edge -> WireGuard -> web-corp -> restricted spool -> Go collector
                 -> Redis raw:web-login -> processor -> MongoDB honeypot_db.events
                 -> Redis event:canonical (password omitted)
                 -> read-only GCP dashboard /http-activity

GET / HEAD / scan / 404 -> page response only; no app event or access log
```

The web-corp handler does not send login credentials to Deception Core,
OpenCanary, Odoo, or PostgreSQL. Existing historical Core records are not
rewritten by this change.

## Related documents

- [Web-corp login telemetry design](web-login-telemetry.md)
- [Web-corp runbook](../../integrations/web-corp/README.md)
- [Service catalog](../SERVICE-CATALOG.md)
- [Current architecture](../CURRENT-ARCHITECTURE.md)
