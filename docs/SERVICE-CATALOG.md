---
title: Honeypot service catalog
status: current
last_verified: 2026-09-25
---

# Honeypot service catalog

The catalog records ownership and purpose. It is deliberately separate from
live host commands: port bindings and service state must be re-verified before
an operational change.

| Service or component | Exposure | Lifecycle | Owner/status | Telemetry path | Notes |
| --- | --- | --- | --- | --- | --- |
| Cowrie SSH | attacker-facing | Current | active, systemd-isolated | Sanitized Cowrie JSON → Go pipeline; legacy forwarder in parallel | Primary focus for adaptive shell work. Artifact bytes are reduced to a local SHA-256 ledger. |
| Cowrie Telnet | attacker-facing | Current | inherited foundation | Cowrie JSON → same as SSH | Keep only while its deception value justifies scope. |
| Cowrie management listener | private overlay | Current | operations | operational logs | Not an attacker-facing decoy. |
| Admin SSH | Tailscale/ZeroTier only, port 2222 | Current | operations | host audit logs + fail2ban | Key-only, root-disabled; X11 and TCP/agent forwarding disabled. |
| Legacy web middleware/Odoo facade | None | Middleware removed 2026-09-24; Odoo stopped 2026-09-25 | Decommissioned | n/a | Middleware service was removed; Odoo is not part of web-corp login and currently has no listener on port 8069. |
| Corporate web decoy | HTTP `10.58.33.42:80` → container `:8080` | Current, active | current project | Login POST only: restricted spool → Go collector `raw:web-login` → processor → MongoDB `honeypot_db.events`; GET/scan/404 telemetry disabled | Source/runbook: [`integrations/web-corp/`](../integrations/web-corp/README.md); [data access](../integrations/web-corp/DATA-ACCESS.md); [HTTP current/future scope](design/http-decoy-scope.md). Host `:8080` is not published. Pi direct-TLS `:443` container is stopped; VPS HTTPS is a target. Legacy `web_http_request` events remain supported. |
| OpenCanary HTTP login decoy | HTTP, loopback staging | Prepared, stopped | current project | local rotating JSONL at `/var/log/opencanary/events.jsonl` | HTTP-only `nasLogin`; remote exposure and Redis/Atlas adapter are not enabled. Login fields may contain submitted credentials or SQL payloads. |
| FTP decoy | None currently; external Compose definition retains ZeroTier bindings | Future, stopped 2026-09-25 | source tracked; not in active login scope | No current telemetry; planned adapter must not copy the legacy credential-bearing Core command path | Tracked source: [integrations/ftp](../integrations/ftp/README.md). Dashboard and canonical MongoDB integration are future work. Shared VFS schema remains deployment data outside Git. |
| SMTP sink | None currently; external Compose definition retains loopback `127.0.0.1:25` | Future, stopped 2026-09-25 | source tracked; not in active login scope | No current telemetry; planned normalized adapter | Tracked source: [integrations/smtp](../integrations/smtp/README.md). Dashboard and canonical MongoDB integration are future work. |
| PostgreSQL / Odoo / Deception Core | PostgreSQL `127.0.0.1:5432`; Core `127.0.0.1:9000`; Odoo `127.0.0.1:8069` | PostgreSQL/Core current; Odoo stopped 2026-09-25 | current project | Internal logs; Core/PostgreSQL support Cowrie integrations | Kept active for Cowrie's native `psql.py` and Core hooks. Odoo is not in the web login path. No endpoint is public. |
| Zeek | sensor | Current, active | current project | Go collector | Interface workers feed Redis with zero observed pending lag at verification. |
| Go collector/processor | telemetry | Current, active | current project | Redis → Atlas/canonical stream | Principal ingestion path. The processor emits validated TI jobs when `THREAT_INTEL_ENABLED=true` and bounds the Redis queue. |
| Hardware agent | local telemetry | Current, active | current project | Redis `raw:hardware` → MongoDB `hardware_live` + `hardware_metrics_1m` | One-second samples replace 30 fixed live slots; history receives one rollup per sensor/minute. |
| Retained data backup worker | outbound B2 from Pi | Current, all three retained-data targets active | current project | MongoDB retention sources → gzip archive → private Backblaze B2 | `hardware_metrics_1m`, `filesystem_audit`, and the reviewed sensitive `threat_events` target are active on the Pi. The upload worker has no `readFiles` or `deleteFiles` capability. |
| TI worker | outbound enrichment | Current, active on Pi (verified 2026-09-24) | current project | Redis `ti:jobs` → provider cache/quota → Atlas `threat_intel` | Enabled service; only validated public IP/SHA-256 jobs are processed, with provider credentials kept in the private worker environment. Web-corp login events are excluded. |
| Dashboard Web-corp HTTP activity | GCP dashboard, authenticated | Current, production projection and auth boundary verified 2026-09-25 | current project | Read-only MongoDB query on `honeypot_db.events`; latest 50 Web-corp login/page records | Broad feed omits submitted values; exact-session detail exposes literal request fields only to Admin. Authenticated browser rendering was not exercised. See [dashboard integration](../dashboard-v2/docs/WEB_CORP_HTTP_INTEGRATION.md) and [live validation](WEB_CORP_HTTP_LIVE_VALIDATION_20260925.md). |
| Artifact hash retention | local maintenance | Current, active timer | operations | SHA-256 ledger only | Removes artifact bytes after a stability window; legacy artifacts were swept on 2026-09-09. |
| Legacy sensor forwarder | cloud forwarding | Legacy, currently active | previous team | separate legacy path | Maintain only until an approved migration/parity check. |
| Post-session/cloud analysis | cloud/internal | Target | current project | reads Atlas canonical events | Production workstream under development. |
| Hailo/Ollama | local inference | Experiment | inherited/candidate | no approved Cowrie data path | Re-adopt only through an ADR and safe staging tests. |
| SQLite dashboard, MySQL LLM | legacy | Archive | previous team | none in target path | Do not use as current runbooks. |

## Required catalog fields for every new fake service

Before exposing a new decoy, add its row with:

1. protocol and intended exposure;
2. persona and explicit non-goals;
3. container/service owner and restart policy;
4. input/output logs and the event adapter that publishes to the Go pipeline;
5. synthetic-data and credential policy;
6. resource limit, health check, and rollback procedure;
7. test evidence and the person responsible for the service.

## Event-adapter gap

Cowrie, Zeek, and web-corp login use the Go ingestion route. FTP and SMTP are
currently stopped, and neither has an Atlas adapter or dashboard integration.
Their source behavior and prior local data paths are not evidence of active
collection. Treat FTP/SMTP activity as absent from current Atlas ingestion
until each service is deliberately reactivated with a normalized adapter and
verified dashboard/API path.
