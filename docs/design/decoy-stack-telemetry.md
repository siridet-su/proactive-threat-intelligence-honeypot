---
title: Docker decoy-stack telemetry design
status: target
last_verified: 2026-08-25
related_adr: ADR-0001
---

# Docker decoy-stack telemetry design

## Context

The live Docker stack supplies the project’s web, Odoo/CloudSQL-like, FTP, and
SMTP deception surface. Its Compose configuration is currently the deployment
source of truth, but its event flow is not yet represented by the same
documented contract as Cowrie and Zeek.

## Objective

Every attacker-visible decoy service produces normalized, privacy-safe events
that can be correlated in MongoDB Atlas with Cowrie and Zeek observations.

## Service roles

| Service | Role | Required telemetry |
| --- | --- | --- |
| Web middleware/Odoo facade | HTTP application persona | request, route, method, response class, decoy session/request ID |
| Corporate web decoy | independent web persona | request, route, response class, request ID |
| FTP door | file-transfer deception | connect/login/command/file metadata/session ID |
| SMTP sink | mail-collection decoy | connect, envelope, message metadata, session ID |
| deception-core | shared state/coordinator | scenario decision, synthetic artifact reference, correlation ID |

No adapter emits passwords, message bodies, uploaded artifact bytes, database
secrets, or internal configuration values by default.

## Adapter contract

Each service writes structured JSON to its own local log or an authenticated
local endpoint. An adapter converts it into a common event before publishing to
the Go collector/Redis path.

```json
{
  "event_id": "stable-dedup-id",
  "timestamp": "RFC3339 timestamp",
  "source": "decoy-ftp",
  "event_type": "session_connect",
  "session": {"id": "service-session-id"},
  "network": {"src_ip": "observed", "dst_port": 21},
  "activity": {"operation": "login"},
  "correlation": {"request_id": "optional", "deception_id": "optional"},
  "schema_version": 1
}
```

The service name and event schema version are mandatory. The adapter is the
only component allowed to translate service-specific data into shared fields.

## Correlation rules

- Cowrie session IDs remain authoritative for shell activity.
- Docker services retain their own session/request IDs.
- Correlate across services only with an explicit shared correlation ID or a
  documented time/network heuristic; label heuristic links as inference.
- Zeek UID is retained as network evidence, never overwritten by application
  identifiers.

## Resource and safety controls

- Every container declares resource limits, health check, log rotation, and
  restart policy before new public exposure.
- Supporting PostgreSQL/Odoo/deception-core endpoints remain internal or
  loopback unless a documented persona requires exposure.
- Docker service logs must be bounded; adapters must not introduce unbounded
  queues or duplicate raw payload storage.

## Delivery gates

1. Add one service adapter at a time, beginning with the Odoo/web facade.
2. Test synthetic traffic against the service and verify one canonical Atlas
   event with a stable id.
3. Test restart, duplicate event, malformed log, and backpressure behavior.
4. Update the service catalog and report evidence before exposing a new decoy.
