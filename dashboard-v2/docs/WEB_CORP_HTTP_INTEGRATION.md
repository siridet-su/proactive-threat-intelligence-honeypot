# Web-corp HTTP read-side integration (local candidate)

The Pi's Web-corp login pipeline writes `source=web-corp`,
`event_type=web_login_attempt` to `honeypot_db.events`. The dashboard's
`/api/http-activity` reads only that source/type with an explicit Mongo field
projection. It does not consume the Redis raw stream, write to Mongo, or use
the Cowrie SSH session worker. A dashboard connected to a different Mongo
database will correctly show no Web-corp events.

The HTTP Activity page lists recent stored login attempts. It uses the
existing sensor/processor `analysis.sqli.indicators` field for SQLi hints and
checks only the bounded URL path/query for simple XSS hints. It does **not**
inspect credentials or login form fields for XSS. Password, username,
`raw.payload`, and submitted URL/payload text are never returned by the API.
The database read projection includes URL text only for server-side matching.

SQLi and XSS are **rule-based observations**, not predictions from Model1 or
Model2. A matching request is mapped to `T1190` as a contextual *candidate*
for analyst review, never a trusted finding or confirmed exploitation. A
rejected login response (HTTP 200 page) does not prove an exploit. XSS is
not `T1059.007` merely because JavaScript syntax appears in a request.

Current coverage is deliberately narrow:

- Web-corp page views and bait-path signals still go to Core `/v1/track` and
  are not represented by this durable login-events query.
- Web-corp login events have a request ID, not a Cowrie session ID. Do not
  join them to SSH sessions by source IP alone.
- XSS sent only in a form field is not detected here. Adding that requires a
  reviewed, credential-safe sensor-side indicator field and a compatible
  canonical projection, not a browser-side scan of raw Mongo documents.
- No HTTP model artifact, HTTP feature contract, calibration, or labeled
  evaluation set exists in this change. Model-backed TTP output is deferred.

Before production use, confirm that the dashboard's Mongo URI points to the
same `honeypot_db.events` collection as the Pi processor, that the dashboard
account has read access only as needed, and that the running Pi processor
still writes the same sanitized contract. Validate one new synthetic login
end-to-end without printing credentials. Deploy/restart permissions are not
implied by this local candidate.
