---
title: One-second hardware telemetry with bounded storage
date: 2026-09-10
environment: loopback
commit: uncommitted-worktree
status: passed
---
Superseded later the same day by
[`2026-09-10-mongo-hardware-live-ring.md`](./2026-09-10-mongo-hardware-live-ring.md).


## Objective

Deliver hardware updates to dashboard code every second without inserting one
MongoDB document per sample. Keep the TI worker disabled and preserve the
hash-only malware artifact policy.

## Procedure

1. Changed the hardware agent to publish a sensor identity and use configurable
   approximate Redis stream trimming.
2. Changed the processor to acknowledge raw hardware messages without inserting
   them one-for-one and independently upsert completed minute buckets.
3. Changed the authenticated dashboard snapshot and SSE routes to read Redis
   server-side, with MongoDB rollups as snapshot fallback.
4. Ran Go tests/builds, dashboard lint/tests/build, deployed the two Go binaries,
   set the service interval to one second, and restarted only hardware/processor.
5. Checked Redis bounds, processor logs, MongoDB counts/indexes, and TI service
   state. No credentials or raw artifact bytes were captured in this note.

## Expected result

- Hardware samples arrive at one-second intervals.
- `raw:hardware` remains near 900 entries.
- `hardware_metrics` stops receiving raw samples.
- `hardware_metrics_1m` receives one idempotent document per sensor/minute
  with a 30-day TTL.
- The TI worker remains disabled and inactive.

## Observed result

- Hardware and processor services were active with zero restarts after deploy.
- Startup logged `interval=1s maxlen=900 sensor_id=ubuntu-pi-server`.
- The latest Redis message reported
  `network_sample_interval_seconds=1.000`.
- Redis stabilized at 900 entries and 1,796,840 bytes for `raw:hardware`.
- A completed rollup contained 60 samples and `resolution_seconds=60`.
- MongoDB had the expected sensor/timestamp index and `expires_at` TTL index.
- Two checks showed legacy `hardware_metrics` unchanged at 90,474 documents;
  its latest timestamp remained 2026-09-09T20:21:36Z.
- During the same checks, `hardware_metrics_1m` increased from 21 to 25
  documents as completed minute buckets were written.
- `honeypot-ti-worker.service` remained disabled and inactive.
- The dashboard Redis client read the latest three samples successfully.

## Validation commands

- `go test ./...` in hardware-agent and processor-agent: passed.
- `npm run lint`: passed.
- `npm test`: 2 files and 7 tests passed.
- `npm run build`: passed, including both hardware API routes.
- `git diff --check`: passed.

## Limitations

No dashboard service or listener was installed on this Pi, so authenticated
browser SSE was not exercised against a deployed Next server. The source build,
Redis client, route contract, and live backend path were validated locally.
Legacy MongoDB deletion/backfill is intentionally a separate migration.

## Follow-up

Deploy dashboard-v2 through its approved staging artifact workflow, then verify
an authenticated browser receives approximately one SSE update per second.
