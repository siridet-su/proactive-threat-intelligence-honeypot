---
title: Mongo-only cloud hardware live ring
date: 2026-09-10
environment: loopback
commit: uncommitted-worktree
status: passed
---

## Objective

Make MongoDB the only hardware source required by a cloud dashboard while
retaining one-second updates without unbounded document growth. Keep local
Redis bounded, minute history enabled, and the TI worker disabled.

## Implementation

- The processor maps each valid sample to
  `slot = sample_unix % HARDWARE_LIVE_SLOTS`.
- `HARDWARE_LIVE_SLOTS` defaults to 30.
- `ReplaceOne(..., upsert=true)` writes
  `hardware_live/<sensor_id>:<slot>` before acknowledging the Redis message.
- The minute worker continues idempotent `hardware_metrics_1m` upserts.
- Dashboard snapshot reads `hardware_live`, then falls back to the minute
  rollup and legacy collection.
- A process-shared MongoDB watcher observes insert/replace events and fans one
  change stream out to all SSE clients in that Node.js process.
- The obsolete dashboard Redis client, tests, environment variables, and npm
  dependency were removed.

## Validation

- Processor Go tests passed, including slot reuse after 30 seconds.
- Dashboard lint passed.
- Dashboard tests passed: 2 files, 7 tests.
- Next.js production build passed with both hardware routes.
- Processor binary SHA-256:
  `681cb6ba50433017b4c3b48b891ddb4c3c07b36ffd22af8f34a78a6b3b4db291`.
- Processor service was active with zero restarts after deployment.
- The hardware consumer group had zero pending entries and zero lag; processor
  logs had no warning-level entries after deployment.
- `hardware_live` reached exactly 30 documents for
  `ubuntu-pi-server`.
- At 2026-09-09T21:27:52Z the first check covered the immediately preceding
  30 seconds.
- At 2026-09-09T21:35:12Z a second check still had exactly 30 documents and
  covered 2026-09-09T21:34:43Z through 2026-09-09T21:35:12Z.
- MongoDB had the expected `sensor_id + timestamp` index.
- A temporary direct change-stream check received a `replace` event at
  2026-09-09T21:28:25Z with the expected sensor and ring-slot identity.
- Legacy `hardware_metrics` remained unchanged at 90,474 documents with
  latest timestamp 2026-09-09T20:21:36Z.
- `hardware_metrics_1m` continued updating; its measured latest bucket had
  60 samples.
- `honeypot-ti-worker.service` remained inactive.

## Storage behavior

For one sensor, the live collection remains at 30 documents regardless of
runtime. MongoDB still receives one replacement write per second, but live
document count and retained live history remain constant. The 30-day minute
rollup remains bounded by TTL at approximately 43,200 documents per sensor.

## Limitations

- There is no deployed dashboard listener on this Pi, so the authenticated
  browser SSE route was production-built but not exercised through a web
  service.
- One watcher is shared per Node.js process, not across multiple cloud
  instances. Keep deployed instance count within the Atlas change-stream
  budget.
- The npm audit currently reports 11 dependency findings: 3 moderate, 7 high,
  and 1 critical. No forced or breaking audit remediation was performed.
- This change does not delete the legacy collection; migration remains a
  separate recoverable operation.
