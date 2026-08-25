---
title: Project roadmap
status: target
last_verified: 2026-08-25
---

# Project roadmap

## Phase 0 — Establish project truth

- Maintain this documentation spine and service catalog.
- Classify inherited implementation and documentation without deleting it.
- Record ports, ownership, data flow, and approved scope before a new service
  is exposed.

## Phase 1 — Adaptive Cowrie shell

- Keep the deterministic virtual world state authoritative.
- Convert the Cowrie fork POC into a version-pinned, reviewable patch series.
- Use a hardened local transport and repeat transcript, cancellation, timeout,
  backpressure, and rollback tests on a non-public listener.
- Do not attach the adaptive gateway to the live listener until explicit staging
  acceptance criteria pass.

## Phase 2 — Principal telemetry pipeline

- Re-enable Redis, Zeek, collector, and processor only in a staged test window.
- Verify Go pipeline delivery to Atlas and document resource use.
- Define and implement service adapters for Docker decoys.
- Establish migration/parity criteria before retiring the legacy sensor
  forwarder.

## Phase 3 — Threat intelligence

- Introduce a separate asynchronous TI worker, not synchronous calls inside
  the processor hot path.
- Query AbuseIPDB only for validated public source IPs.
- Query VirusTotal by observed SHA-256 first; no automatic file upload.
- Persist normalized, cache-expiring enrichment and expose status to the
  dashboard.

## Phase 4 — Post-session/cloud analysis

- Consume Atlas canonical events and session summaries.
- Keep observed facts, inference, and hypothesis separate.
- Store model/version, evidence references, timestamps, and limitations with
  every analysis result.

## Phase 5 — Reporting and evaluation

- Build reproducible staging fixtures and replay tests.
- Measure delivery, enrichment, analysis, resource use, and deception quality.
- Generate report tables and figures only from versioned evidence.

## Scope-control rule

Adding a new exposed decoy is allowed only when its persona, telemetry adapter,
resource ceiling, rollback, and test plan are documented. Otherwise it remains
planned rather than active scope.
