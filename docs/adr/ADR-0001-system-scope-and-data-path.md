---
title: ADR-0001 — Unified project scope and principal data path
status: accepted
date: 2026-08-25
---

# ADR-0001 — Unified project scope and principal data path

## Context

The project was inherited from a previous team. It contains legacy services
and documentation alongside current work on adaptive Cowrie and Docker decoy
services. A legacy sensor forwarder remains active while the Go telemetry
pipeline is intentionally paused for Pi resource allocation.

## Decision

Treat Cowrie, Zeek, Docker fake services, adaptive deception, and cloud
post-session analysis as one project. The Go Collector → Redis → Go Processor
→ MongoDB Atlas route is the principal telemetry/data architecture when
enabled. The legacy sensor forwarder is a bounded migration dependency, not
the foundation for new work.

## Consequences

- New decoys require an adapter into the common event contract.
- Atlas-backed canonical events are the basis for dashboard and cloud analysis.
- The temporary pause of Go services is documented as a resource decision, not
  a failed deployment.
- Legacy documentation is retained as archive evidence until migration is
  verified.
