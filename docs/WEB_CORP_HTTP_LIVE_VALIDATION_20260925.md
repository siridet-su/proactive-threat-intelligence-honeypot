# Web-corp HTTP rule lane: live validation

Date: 2026-09-25 Asia/Bangkok. Source candidate: `2e41df41eb1caa71333d6565b123fbe117c53383`; the Pi code files are unchanged from its ancestor `0eec77dc96bcb0cd7048d0198bfbae60b425866e`.

## Active scope

- Pi: Web-corp HTTP and HTTPS containers plus only `honeypot-collector.service` and `honeypot-processor.service` were updated. Existing MongoDB schema, historical records, credentials, firewall, SSH/Cowrie logic, and reviewed TTP policy were not changed. New HTTP events are additive documents in the existing `honeypot_db.events` collection.
- GCP: only `honeypot-dashboard-v2.service` was restarted. Production pointer: `/opt/honeypot-dashboard-v2/releases/2e41df41-http-activity`. Artifact SHA-256: `4f9ddc7e035f7ab613e1c8958185ba2158da1fed213f0b2533229f42d82b225f`.
- A failed first Pi activation was fully rolled back to the prior binary hashes/source hashes/image IDs. It exposed a startup race in the port-80 check and a non-atomic binary rollback. The installer was corrected to poll readiness and atomically replace running binaries; the second activation passed. The prior Pi release remains under `/home/cpe27/web-corp-http-releases/0eec77dc-r2` with the original image IDs and hashes. The failed attempt's original backup is under the sibling `0eec77dc` directory.

## Checks performed

- Local FastAPI tests: 8 passed. Pi Go collector and processor tests/builds passed in an isolated temporary directory. Dashboard HTTP tests: 6 passed; TypeScript and production webpack build passed after merging the latest `main` Malware Vault redesign.
- One synthetic HTTP browser session: GET `/login.html` with an encoded XSS-shaped query, then POST `/web/login` with a SQLi-shaped *synthetic* password. Both returned HTTP 200 (the fake login still rejects authentication) and kept the same sensor-issued browser-continuity ID. No real credentials were used.
- The Pi spool drained to zero; Redis raw-stream pending count was zero. Two canonical events had the same continuity ID: `web_http_request` with `xss.query=script_tag`, and `web_login_attempt` with `sqli.password=[sql_comment, boolean_tautology]`. Canonical projection omitted the password and raw query.
- GCP dashboard's existing Mongo connection read exactly those two new events through an explicit safe projection. The dashboard service is active; `/api/auth/login` returned 405 and unauthenticated `/api/http-activity` returned 401. An authenticated browser render was **not** exercised because no operator session cookie was provided.

## Interpretation and limits

The HTTP labels are rule-based triage hints, not an HTTP-trained Model1 prediction, confirmed SQL injection/XSS execution, canonical finding, or response authorization. `T1190` is a contextual analyst candidate only. No HTTP ML fallback was trained or enabled; forwarding HTTP payloads into the existing SSH command model would be semantically invalid. This synthetic Pi-origin session has no eligible public source IP for ETI validation. Browser continuity is cookie-based, not attacker identity; HTTP and HTTPS currently have separate process-local signing keys, and a container restart rotates them. Existing web server/access logs may still retain raw request URLs; the structured spool/Core/dashboard projection does not.

Rollback: switch the GCP `current` symlink to its prior verified release and restart only `honeypot-dashboard-v2.service`; for Pi restore the backed-up source and binaries via atomic rename, retag the two backed-up image IDs, recreate only Web-corp HTTP/HTTPS, then restart only collector/processor. Do not delete existing telemetry when rolling back code.
