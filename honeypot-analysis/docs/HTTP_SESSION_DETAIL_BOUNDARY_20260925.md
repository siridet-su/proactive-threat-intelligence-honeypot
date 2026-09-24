# HTTP session detail — read-side boundary (2026-09-25)

The HTTP/Web-corp lane appears inside Threat Intel, but it is not a Cowrie
session. The directory preview groups only sensor-issued 32-hex browser-cookie
session IDs. Exact detail reads `honeypot_db.events` with a field allowlist and a
500-event cap. Legacy events without a session ID remain separate. IP,
username, or User-Agent are never used to infer a session join.

The detail view shows request chronology, source/destination endpoints where
recorded, login outcomes, rule IDs, a contextual T1190 review candidate, a
non-authoritative hypothesis, manual-only investigation guidance, and stored
ETI for the exact single public source IP when the existing monitor's
observable-TI projection has eligible sightings. It omits raw query values,
cookies, credentials, payloads, SSH command panels, Cowrie deception content,
Model1/Model2 predictions, and ungenerated forecasts. The HTTP collector does
not currently retain the source port, so the UI says so rather than inventing
one. Printing is a read-side convenience, not an immutable PDF report.

The current HTTP event producer does **not** register source-IP sightings in
the governed ETI pipeline. Consequently HTTP-only IPs do not yet trigger
provider enrichment and their ETI panel says there is no stored eligible
sighting. Private/test IPs are ineligible. A result from another eligible
sighting of the same exact public IP remains source-IP context, not evidence
about this HTTP request or an attacker identity. No provider call is made by
the dashboard.

SQLi/XSS hints are sensor-computed rule matches on submitted requests. They
do not show that an exploit succeeded. T1190 is a review candidate, not a
canonical finding or Model1 prediction. Neither response guidance nor the
print view authorizes automated action.

Acceptance checks: unauthenticated exact-session API returns 401; malformed
IDs return 400; missing exact sessions return 404; only allowlisted fields
leave Mongo; different browser-cookie IDs or legacy events never merge; a
private or changing source IP never acquires a provider claim; and both
HTTP-specific and Cowrie directories remain navigable from Threat Intel.
