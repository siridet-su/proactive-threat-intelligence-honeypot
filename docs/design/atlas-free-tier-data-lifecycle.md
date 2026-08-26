# Atlas Free Tier data lifecycle

## Status

Target architecture. The processor now assigns expiry timestamps and creates
TTL indexes for newly written canonical events and hardware metrics. Existing
documents without `expires_at` require a deliberate backfill before TTL can
remove them.

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
      → canonical events or hardware metrics with expires_at
      → ti:jobs for validated IP/SHA-256 observables
  → ti-worker → threat_intel shared cache + event summary
  → dashboard reads events, summaries, and future rollups
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
| `hardware_metrics` | native hardware samples for immediate health view | 48 hours via TTL |
| `hardware_metrics_5m` | future 5-minute min/avg/max rollup | 180 days |
| `daily_rollups` | future dashboard/report aggregates | long-lived and compact |
| debug normalised/enriched events | temporary troubleshooting only | disabled by default or 24 hours |

## Implemented retention controls

The Processor reads these duration variables:

| Variable | Default | Applies to |
|---|---:|---|
| `EVENT_RETENTION` | `720h` | canonical `events` |
| `HARDWARE_METRICS_RETENTION` | `48h` | `hardware_metrics` |

Each new document receives an `expires_at` timestamp derived from the observed
event/sample time, not from dashboard read time. The Processor creates TTL
indexes on `events.expires_at` and `hardware_metrics.expires_at` when it starts.
MongoDB TTL cleanup is asynchronous, so expiry is not an exact deletion timer.

## Index budget

Indexes use Free Tier storage too. Keep only indexes demonstrated by dashboard
or investigator queries:

```text
events.timestamp desc
events.network.src_ip + timestamp
events.session.id + timestamp
events.expires_at (TTL)
hardware_metrics.timestamp desc
hardware_metrics.expires_at (TTL)
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

## Next implementation phase

Implement a 5-minute `hardware_metrics_5m` rollup before increasing hardware
retention. The dashboard should query the latest native samples for the live
sparkline and rollups for long-range charts. This removes the need to retain
every 30-second sample in Atlas.
