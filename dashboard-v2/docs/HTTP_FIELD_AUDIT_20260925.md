# Web-corp HTTP fields and production rollout — 2026-09-25

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

The stored User-Agent examples included Firefox, curl, and Python urllib. All HTTP headers are attacker-controlled claims, not proof of the actual browser. Source ports were absent in this sample. The updated sensor captures the same bounded context headers on new GET/page events; it does not backfill older records.

An XSS script submitted in a captured query or form field can be shown as literal text. The detail view keeps the exact percent-encoded query, adds a decoded reading aid when possible, and highlights the matched field as escaped React text. It never inserts the submitted value as HTML or executes it. A pattern match does not show whether an actual browser executed the script.

Production dashboard release `ca9d7dd0-http-evidence` is active. The separate localhost preview was stopped. The Pi web-corp container runs image `sha256:37c28e9dd710c9c4f4826ec597cb843ff058945b40ddec2bada3b945dd31d8ee`; the previous image remains tagged `decoy-honeypot-web-corp:rollback-ca9d7dd0`. The Pi's dirty source checkout was not overwritten: the deployed image was built from a copy of its prior live source with bounded GET header capture added. Consequently, the main-branch sensor file is not byte-identical to the Pi runtime; it still contains legacy Core page-tracking code absent from the Pi image. Reconcile this before a future sensor rebuild from main.

Live synthetic session `87dd24eb680843698d0d1222d8ff1d5b` contains a GET with a literal XSS-shaped query, captured User-Agent/Accept-Language/Host, and a POST with a SQLi-shaped login value. A read-only Mongo probe confirmed both records and both rule hints. These are submitted attempts, not proof that XSS or SQL injection executed. The Admin-only detail URL is `/threat-intel/http/87dd24eb680843698d0d1222d8ff1d5b`.

Verification: 15 targeted dashboard tests, TypeScript check, targeted ESLint, nine web-corp sensor tests, and the production GCP dashboard build passed. Production and public login routes returned HTTP 200; the exact session API returned HTTP 401 without authentication. Production UI was not visually inspected with an authenticated browser because Admin credentials were not available to the operator of this rollout.
