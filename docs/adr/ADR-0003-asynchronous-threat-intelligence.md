---
title: ADR-0003 — Asynchronous VirusTotal and AbuseIPDB enrichment
status: proposed
date: 2026-08-25
---

# ADR-0003 — Asynchronous VirusTotal and AbuseIPDB enrichment

## Context

The current prototype calls third-party APIs from the processor before durable
event persistence. Unique observables or provider delays can slow Redis
acknowledgement and delay baseline telemetry.

## Proposed decision

The processor persists canonical events and emits deduplicated enrichment jobs.
A dedicated TI worker owns provider requests, persistent cache, quota budget,
timeout handling, and enrichment updates. Cowrie and the adaptive shell only
read already-available summaries; they never wait for a provider.

## Acceptance criteria

- Provider timeout or outage does not block canonical event persistence.
- Cache and quota state survive worker restart.
- Only public source IPs and valid SHA-256 observables are queried.
- Dashboards distinguish pending, found, not found, expired, and failed lookup.
