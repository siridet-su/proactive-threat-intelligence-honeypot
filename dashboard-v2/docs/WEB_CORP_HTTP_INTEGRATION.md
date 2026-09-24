# Web-corp HTTP read-side integration (local candidate)

The Web-corp sensor now writes `web_login_attempt` and `web_http_request` to
the existing restricted spool. The Go collector places both on
`raw:web-login`; the processor writes `source=web-corp` records to
`honeypot_db.events`. The dashboard `/api/http-activity` reads only those
source/types with an explicit Mongo field projection. It does not consume
Redis directly, write Mongo, or use the Cowrie SSH session worker. A dashboard
connected to a different Mongo database will show no Web-corp events.

The sensor issues an HttpOnly, SameSite=Lax, host-only signed cookie with a
random `web_session_id`. It rotates after 30 minutes idle or 24 hours total.
The signing key is process-local and rotates on restart, so a restart also
starts new browser-continuity sessions. The ID is not proof of actor identity;
copied cookies can link requests from different clients. Legacy records
without the ID stay ungrouped. The dashboard never joins by source IP alone.

The sensor checks bounded submitted form fields and URL path/query for simple
SQLi/XSS patterns. It records *field names and rule names*, not XSS payloads,
on both event types. Web page events have no raw query or form value; their
path is redacted when it does not match a safe path form. Login events retain
the preexisting raw credential data in the protected spool/Redis/Mongo, but
the dashboard API excludes password, username, `raw.payload`, submitted
query, and submitted payload text. The legacy Core page counter receives a
redacted path with no query, and login data never goes to Core.

SQLi and XSS are **rule-based observations**, not predictions from Model1 or
Model2. A matching request is mapped to `T1190` as a contextual *candidate*
for analyst review, never a trusted finding or confirmed exploitation. A
rejected login response (HTTP 200 page) does not prove an exploit. XSS is
not `T1059.007` merely because JavaScript syntax appears in a request.

Current coverage and limitations:

- Page views and bait-path requests also go to Core `/v1/track` as a legacy
  page counter; they are additionally represented by credential-free HTTP
  records. This is not a Cowrie session and does not make Model1 applicable.
- A cookie-bearing browser can continue a session; stateless clients that do
  not retain cookies create separate request sessions.
- Host access logs or upstream proxies may still record URL queries; this
  change protects the structured spool/Core/dashboard path, not every log.
- No HTTP model artifact, HTTP feature contract, calibration, or labeled
  evaluation set exists in this change. Model-backed Model1 fallback is
  unavailable and abstains; rule hints are not presented as model output.

Before production use, confirm that the dashboard's Mongo URI points to the
same `honeypot_db.events` collection as the Pi processor, that the dashboard
account has read access only as needed, and that the running Pi processor
still writes the same sanitized contract. Verify rollout in dependency order:
processor compatible with both event types, collector compatible with both,
then rebuild/recreate Web-corp; finally deploy dashboard code. Keep previous
binaries/image/release for rollback and preserve all existing events. Validate
one new synthetic page → SQLi/XSS login chain by request IDs and session ID,
without printing credentials. Production service changes have not been made
by this local candidate.
