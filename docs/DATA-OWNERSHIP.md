---
title: Data ownership and event-flow contract
status: target
last_verified: 2026-08-25
---

# Data ownership and event-flow contract

## Ownership model

| Data | Authoritative owner | Consumers | Retention intent |
| --- | --- | --- | --- |
| Raw Cowrie/Zeek/service logs | origin service | collector/adapter | local, bounded and rotated |
| Redis streams | Go telemetry plane | processor and workers | transient, bounded queue |
| Canonical security events | MongoDB Atlas `events` | dashboard, cloud analysis, report jobs | durable project record |
| Hardware samples | MongoDB Atlas `hardware_metrics` | operational dashboard | durable but retention-managed |
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
  the source service.
- Dashboard and report APIs expose a least-privilege projection, not arbitrary
  raw event documents.
- Cloud analysis receives only fields required for the approved analysis task.
- Provider API keys, deployment secrets, and raw malware artifacts never enter
  event documents or LLM prompts.

## Current temporary exception

The Go pipeline is intentionally stopped while the Pi is allocated to adaptive
POC testing. This is an operational pause, not a change in ownership or the
target data architecture.
