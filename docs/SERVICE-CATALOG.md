---
title: Honeypot service catalog
status: current
last_verified: 2026-08-25
---

# Honeypot service catalog

The catalog records ownership and purpose. It is deliberately separate from
live host commands: port bindings and service state must be re-verified before
an operational change.

| Service or component | Exposure | Lifecycle | Owner/status | Telemetry path | Notes |
| --- | --- | --- | --- | --- | --- |
| Cowrie SSH | attacker-facing | Current | inherited foundation + current adaptive work | Cowrie JSON → Go pipeline when enabled; legacy forwarder in parallel | Primary focus for adaptive shell work. |
| Cowrie Telnet | attacker-facing | Current | inherited foundation | Cowrie JSON → same as SSH | Keep only while its deception value justifies scope. |
| Cowrie management listener | private overlay | Current | operations | operational logs | Not an attacker-facing decoy. |
| Admin SSH | restricted management port | Current | operations | host audit logs | Never use for honeypot or LLM test instructions. |
| Web middleware/Odoo facade | HTTP | Current | current project | service-event adapter required | Docker decoy stack. |
| Corporate web decoy | HTTP | Current | current project | service-event adapter required | Docker decoy stack. |
| FTP decoy | FTP + passive range | Current | current project | service-event adapter required | Docker decoy stack. |
| SMTP sink | SMTP | Current | current project | service-event adapter required | Docker decoy stack. |
| PostgreSQL/Odoo/deception-core | loopback/internal | Current | current project | internal application logs | Supporting decoy infrastructure, not public database services. |
| Zeek | sensor | Target, currently paused | current project | Go collector | Start only for staged telemetry work. |
| Go collector/processor | telemetry | Target, currently paused | current project | Redis → Atlas | Principal ingestion path when enabled. |
| Legacy sensor forwarder | cloud forwarding | Legacy, currently active | previous team | separate legacy path | Maintain only until an approved migration/parity check. |
| Post-session/cloud analysis | cloud/internal | Target | current project | reads Atlas canonical events | Production workstream under development. |
| Hailo/Ollama | local inference | Experiment | inherited/candidate | no approved Cowrie data path | Re-adopt only through an ADR and safe staging tests. |
| OpenCanary, SQLite dashboard, MySQL LLM | legacy | Archive | previous team | none in target path | Do not use as current runbooks. |

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
