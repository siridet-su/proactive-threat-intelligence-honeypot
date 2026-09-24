---
title: Docker decoy-stack telemetry design
status: target
last_verified: 2026-09-25
related_adr: ADR-0001
---

# Docker decoy-stack telemetry design

## Context

The external Docker Compose file defines the project’s web, Odoo/CloudSQL-like,
FTP, and SMTP deception surface. The current runtime has web-corp HTTP active;
Odoo, direct-Pi HTTPS, FTP, and SMTP are stopped. Deception Core and PostgreSQL
remain active for Cowrie dependencies. Compose is outside this repository, so
the service definitions still need a deliberate lifecycle/profile cleanup.

## Objective

Every attacker-visible decoy service produces normalized, privacy-safe events
that can be correlated in MongoDB Atlas with Cowrie and Zeek observations.

## Service roles

| Service | Role | Required telemetry |
| --- | --- | --- |
| Web middleware/Odoo facade | HTTP application persona | request, route, method, response class, decoy session/request ID |
| Corporate web decoy | independent web persona | login POST only in current scope; page/scan telemetry is future work |
| FTP door | file-transfer deception | connect/login/command/file metadata/session ID |
| SMTP sink | mail-collection decoy | connect, envelope, message metadata, session ID |
| deception-core | shared state/coordinator | scenario decision, synthetic artifact reference, correlation ID |

New adapters must not emit passwords, message bodies, uploaded artifact bytes,
database secrets, or internal configuration values by default. The old FTP
Core command route is an exception with credential-bearing data and must not
be reused.

## FTP and SMTP source behavior (services stopped)

Both containers were stopped on 2026-09-25 and are future work, not active
decoys in the current runtime. Their tracked sources describe behavior if the
external Compose services are reactivated; current collection and dashboard
integration are not available.

- FTP posts login/activity strings to Deception Core /v1/track and uses
  /v1/decide for bait-file retrieval. Failed-login strings currently include
  the attempted username and password, and therefore Core's event/session
  stores are credential-sensitive. This legacy behavior is not the target
  contract; do not copy it into new adapters. FTP has no normalized Go
  collector/Redis/Atlas adapter yet.
- SMTP accepts and discards messages. Its application log contains peer IP,
  envelope sender/recipients, and body byte count, not the message body. It
  has no normalized telemetry adapter yet.
- The fake web login is the only active web telemetry scope. Login attempts
  use the dedicated spool/Redis/Mongo path and do not go to Deception Core;
  ordinary pages, scans, and 404s are not logged by the app.

The fake ERP login honeypot is an explicit, narrowly scoped exception to that
default: its [web-login telemetry design](web-login-telemetry.md) retains
submitted login values, including passwords, for honeypot research. Those
credential-bearing events are restricted to authorized honeypot admins and
must not be copied into generic command/session data or external enrichment.

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

1. Add one service adapter at a time, beginning with dashboard/API access to
   the already persisted web-login events.
2. Test synthetic traffic against the service and verify one canonical Atlas
   event with a stable id.
3. Test restart, duplicate event, malformed log, and backpressure behavior.
4. Update the service catalog and report evidence before reactivating FTP,
   SMTP, Odoo, or direct-Pi HTTPS.
