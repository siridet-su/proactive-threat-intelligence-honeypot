---
title: Honeypot service catalog
status: current
last_verified: 2026-09-24
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
| Web middleware/Odoo facade | HTTP | Current | current project | service-event adapter required | Docker decoy stack. |
| Corporate web decoy | HTTP | Current | current project | service-event adapter required | Docker decoy stack. |
| OpenCanary HTTP login decoy | HTTP, loopback staging | Prepared, stopped | current project | local rotating JSONL at `/var/log/opencanary/events.jsonl` | HTTP-only `basicLogin`; remote exposure and Redis/Atlas adapter are not enabled. Login fields may contain submitted credentials or SQL payloads. |
| FTP decoy | FTP + passive range | Current | current project | service-event adapter required | Docker decoy stack. |
| SMTP sink | SMTP | Current | current project | service-event adapter required | Docker decoy stack. |
| PostgreSQL/Odoo/deception-core | loopback/internal | Current | current project | internal application logs | Supporting decoy infrastructure, not public database services. |
| Zeek | sensor | Current, active | current project | Go collector | Interface workers feed Redis with zero observed pending lag at verification. |
| Go collector/processor | telemetry | Current, active | current project | Redis → Atlas/canonical stream | Principal ingestion path. The processor emits validated TI jobs when `THREAT_INTEL_ENABLED=true` and bounds the Redis queue. |
| Hardware agent | local telemetry | Current, active | current project | Redis `raw:hardware` → MongoDB `hardware_live` + `hardware_metrics_1m` | One-second samples replace 30 fixed live slots; history receives one rollup per sensor/minute. |
| TI worker | outbound enrichment | Current, active on Pi (verified 2026-09-24) | current project | Redis `ti:jobs` → provider cache/quota → Atlas `threat_intel` | Enabled service; only validated public IP/SHA-256 jobs are processed, with provider credentials kept in the private worker environment. |
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

Cowrie and Zeek already have an intended Go ingestion route. The Docker decoys
are live but do not yet have a documented common adapter into the same event
contract. Treat this as a planned integration, not as evidence that all
attacker activity is already represented in Atlas.
