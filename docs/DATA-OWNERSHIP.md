---
title: Data ownership and event-flow contract
status: current
last_verified: 2026-09-25
---

# Data ownership and event-flow contract

## Ownership model

| Data | Authoritative owner | Consumers | Retention intent |
| --- | --- | --- | --- |
| Raw Cowrie/Zeek/service logs | origin service | collector/adapter | local, bounded and rotated |
| Web-corp login spool | web-corp app | host collector | root-only, max 64 MiB pending; delete after successful Redis enqueue |
| Redis streams | Go telemetry plane | processor and workers | transient, bounded queue |
| Canonical security events | MongoDB Atlas `events` | dashboard, cloud analysis, report jobs | 30-day TTL; optional `threat_events` B2 archive because restricted web-login records may contain credentials |
| Live hardware samples | MongoDB Atlas `hardware_live` | dashboard snapshot and SSE | fixed ring of 30 documents per sensor |
| Hardware history | MongoDB Atlas `hardware_metrics_1m` | dashboard history endpoint and reporting | one compact upserted row per sensor/minute, 30-day TTL |
| Filesystem audit events | MongoDB Atlas `cwd_events` | filesystem activity history and audit replay | authoritative CWD transitions, 30-day TTL; optional `filesystem_audit` B2 archive |
| Filesystem session state | MongoDB Atlas `cwd_session_state` | live topology and retained session directory | authoritative latest state, 30-day TTL; archived with filesystem audit source |
| Filesystem audit projection | MongoDB Atlas `cwd_audit_projection` | derived audit directory/read model | rebuildable indexed cleanup watermark; not an independent backup source |
| Backup manifests, requests, and target status | MongoDB Atlas `hardware_backup_manifests`, `hardware_backup_requests`, `backup_target_status` | dashboard and Pi worker | operational control/audit records; do not mix with retained evidence archives |
| Threat-intelligence results | Atlas enrichment records/projections | dashboard, cloud analysis | cache-aware with expiry |
| Session analysis and report output | Atlas analysis/report records | dashboard and report export | evidence-linked, versioned |
| Raw malware artifact | none by default | no runtime consumer | delete after hash/metadata capture unless explicitly quarantined |

## Event flow when the Go pipeline is enabled

```text
source log or service adapter
        -> collector
        -> raw Redis stream
        -> processor/normalizer
        -> Atlas canonical event
        -> canonical/event-specific stream
        -> asynchronous enrichers and post-session analysis
```

The processor must persist the canonical event before acknowledging its raw
Redis message. A third-party API timeout must never prevent baseline telemetry
from reaching Atlas.

## Event identity and correlation

- Use a stable event identifier for idempotent persistence.
- Preserve the source session identifier (Cowrie session or Zeek UID) alongside
  a project-level correlation identifier where sources can be linked.
- Store source, timestamp, observable, and schema version with every event.
- Treat Cowrie as authoritative for its shell/session events and Zeek as
  authoritative for network observations.
- A Docker service adapter must identify its own service and request/session
  identifier before emitting an event.

## Privacy and report boundary

- Sanitization happens before attacker credentials or sensitive values leave
  the source service by default. The scoped web-corp login exception retains
  submitted values for honeypot research in the admin-only local telemetry path;
  see [web-login telemetry design](design/web-login-telemetry.md). It must not
  flow to external providers or normal dashboard projections.
- Dashboard and report APIs expose a least-privilege projection, not arbitrary
  raw event documents.
- Cloud analysis receives only fields required for the approved analysis task.
- Provider API keys, deployment secrets, and raw malware artifacts never enter
  event documents or LLM prompts.

## Hardware telemetry exception

Each valid raw hardware entry replaces one of 30 `hardware_live` slots before
its consumer-group acknowledgement. An independent minute worker reads the
bounded Redis stream and upserts completed rollup buckets. Hardware samples are
not canonical security events.

## Retained-data backup boundary

The Pi backup worker defaults to `hardware_metrics_1m` so installing the
multi-target code does not change the active host policy. `threat_events`
archives the canonical `events` collection only after an explicit sensitive-data
opt-in and a scoped private B2 key review. `filesystem_audit` archives the two
authoritative filesystem collections; `cwd_audit_projection` and its readiness
metadata are excluded because the processor rebuilds them from source records.
The dashboard's target map reads the worker's `backup_target_status` record, so
repository support is not presented as host activation.
