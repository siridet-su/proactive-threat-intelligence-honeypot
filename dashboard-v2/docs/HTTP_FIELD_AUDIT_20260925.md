# Web-corp HTTP fields and local preview — 2026-09-25

Read-only inventory of the eight newest `web-corp` MongoDB events at inspection time (three `web_http_request`, five `web_login_attempt`). Counts describe this small stored sample, not sensor coverage in general.

| Field | GET/page event | POST/login event | Presentation |
| --- | ---: | ---: | --- |
| Source IP; destination IP/port; protocol/service | 3/3 | 5/5 | Session metadata and chronology |
| HTTP method/path/status | 3/3 | Method/path 5/5; login outcome 5/5 | Chronology |
| Literal query/raw path | 1/3 | Login query absent or empty in this sample | Admin-only request evidence; old missing queries cannot be reconstructed |
| User-Agent | 0/3 | 5/5 | Raw Admin-only value plus explicitly self-reported client hint |
| Host | 0/3 | 5/5 | Admin-only request context |
| Referer; Origin; Accept-Language | 0/3 | 2/5 each | Admin-only request context when stored |
| SQLi/XSS rule indicators | XSS on 2/3 | SQLi on 4/5 | Attempt hints only, not verified exploitation |
| Captured login fields | Not applicable | Username/password 5/5; other fields vary | Admin-only literal form values |

The stored User-Agent examples included Firefox, curl, and Python urllib. All HTTP headers are attacker-controlled claims, not proof of the actual browser. Source ports were absent in this sample. The updated sensor source captures the same bounded context headers on future GET/page events; it does not backfill older records. The sensor change is **not** deployed by the localhost-preview work.

An XSS script submitted in a captured query or form field can be shown as literal text. The detail view keeps the exact percent-encoded query, adds a decoded reading aid when possible, and highlights the matched field as escaped React text. It never inserts the submitted value as HTML or executes it. A pattern match does not show whether an actual browser executed the script.

Preview: `http://127.0.0.1:3100` tunnels to a separate, loopback-only GCP dashboard process on port 3002 using the existing dashboard authentication and Mongo connection. The production dashboard and its release pointer are unchanged. The preview requires an existing Admin login to view literal payloads. The current synthetic session is `dc6e06f02b7e446fa17b34203d783cb1`; its stored GET contains an XSS-shaped query, while its POST contains the captured SQLi-shaped form value. Its GET predates the new GET-header code and therefore has no User-Agent; the POST has curl's reported User-Agent.

Verification: 15 targeted dashboard tests, TypeScript check, targeted ESLint, and nine web-corp sensor tests passed. The preview login returned HTTP 200, while unauthenticated session detail returned HTTP 401. An authenticated browser inspection still requires the operator's login.
