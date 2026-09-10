# Atlas Free Tier data lifecycle

## Status

Implemented for new hardware telemetry on 2026-09-10. One-second samples remain
in a bounded local Redis stream, while the processor replaces 30 fixed
`hardware_live` MongoDB slots and upserts completed one-minute rollups.
Existing legacy `hardware_metrics` documents without `expires_at` still
require a deliberate migration before TTL can remove them.

## Context

The project is an educational demonstration, not a continuously operated SOC.
MongoDB Atlas Free Tier storage must therefore prioritize compact investigation
data over raw telemetry. The Atlas snapshot from 2026-08-26 showed that
`hardware_metrics` had roughly 204K documents and 209 MB of logical data,
while `events` had about 32K documents and 56 MB. Hardware metrics are the
first retention priority.

## Data path

```text
Cowrie / Zeek / hardware sample
  → local raw log or Redis stream (bounded, transient)
  → processor-agent
      → canonical security events with expires_at
      → hardware_live fixed 30-slot ring
      → hardware_metrics_1m min/avg/max rollup
      → ti:jobs for validated IP/SHA-256 observables
  → ti-worker (intentionally disabled until approved)
  → cloud dashboard reads live hardware and history from MongoDB
```

Raw Cowrie JSON, Zeek logs/PCAP, unbounded shell transcripts, malware binaries,
and raw provider responses must not be stored in Atlas by default.

## Canonical database

The project database is `honeypot_db`. The dashboard already reads this name;
the Processor and TI worker now use it as their default. Production environment
files must set the same `MONGO_DATABASE` explicitly to avoid accidental data
splits.

## Collection policy

| Collection | Purpose | Retention / bound |
|---|---|---|
| `events` | compact canonical event for live activity and timelines | 30 days via TTL; future hard cap of 50K documents |
| `sessions` | one redacted, bounded summary per SSH session | 90 days |
| `attacker_profiles` | upserted IP-level counts and risk summary | 180 days or 10K profiles |
| `threat_intel` | provider-shared lookup cache | per-record provider expiry |
| `hardware_metrics` | legacy native hardware samples; no new writes | existing TTL where present; migration required |
| `hardware_live` | last 30 one-second samples per sensor | fixed ring; documents are replaced |
| `hardware_metrics_1m` | one deterministic min/avg/max rollup per sensor/minute | 30 days via TTL |
| `daily_rollups` | future dashboard/report aggregates | long-lived and compact |
| debug normalised/enriched events | temporary troubleshooting only | disabled by default or 24 hours |

## Implemented retention controls

The Processor reads these duration variables:

| Variable | Default | Applies to |
|---|---:|---|
| `EVENT_RETENTION` | `720h` | canonical `events` |
| `HARDWARE_LIVE_SLOTS` | `30` | fixed live documents per sensor |
| `HARDWARE_ROLLUP_RETENTION` | `720h` | `hardware_metrics_1m` |
| `HARDWARE_ROLLUP_BACKFILL_MINUTES` | `10` | completed Redis minute buckets recomputed at startup |

Each new document receives an `expires_at` timestamp derived from the observed
event/bucket time, not from dashboard read time. The Processor creates TTL
indexes on `events.expires_at` and `hardware_metrics_1m.expires_at` when it starts.
MongoDB TTL cleanup is asynchronous, so expiry is not an exact deletion timer.

## Index budget

Indexes use Free Tier storage too. Keep only indexes demonstrated by dashboard
or investigator queries:

```text
events.timestamp desc
events.network.src_ip + timestamp
events.session.id + timestamp
events.expires_at (TTL)
hardware_live.sensor_id + timestamp desc
hardware_metrics_1m.sensor_id + timestamp desc
hardware_metrics_1m.expires_at (TTL)
```

Review and drop superseded legacy indexes separately after confirming the live
query paths. Do not drop indexes as part of an automatic startup action.

## Existing-data migration

TTL indexes only affect documents that have `expires_at`. Before enabling the
pipeline for a demonstration:

1. record the Atlas database size and collection counts;
2. backfill `expires_at` in bounded batches, starting with
   `hardware_metrics`;
3. let TTL monitor delete old data asynchronously;
4. verify dashboard hardware endpoints still receive recent samples;
5. only then consider removing duplicate legacy collections or indexes.

Backfill must be dry-run by default and must not run automatically on the Pi.

## Live hardware storage budget

The hardware agent publishes every second and uses local Redis `MAXLEN ~ 900`.
The processor performs one MongoDB replacement per sample, cycling through 30
deterministic `hardware_live` slots per sensor. The stored live document count
therefore remains constant. The cloud dashboard opens one change stream per
Node.js process and fans updates out to its SSE clients. One-minute history
creates about 43,200 documents over 30 days instead of about 2.59 million raw
one-second documents.
