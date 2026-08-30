---
title: Threat-intelligence enrichment design
status: current
last_verified: 2026-08-27
related_adr: ADR-0002, ADR-0003
---

# Threat-intelligence enrichment design

## Goal

Enrich observed attacker IPs and payload hashes without slowing Cowrie, Zeek,
Redis ingestion, or canonical Atlas persistence. The design supports dashboard
triage and post-session analysis; it does not block attackers or execute
payloads.

## Non-goals

- No malware execution, detonation, or automatic VirusTotal upload.
- No provider call in Cowrie, adaptive-engine, or processor ingestion path.
- No automatic AbuseIPDB reporting in this phase.
- No provider receives complete commands, credentials, transcripts, or payload
  bytes.

## Observable intake

| Observable | Source | Provider | Priority |
| --- | --- | --- | --- |
| Public source IP | Cowrie connect/login; Zeek connection | AbuseIPDB | Normal |
| SHA-256 | Cowrie file event; Zeek files event | VirusTotal | High |
| Domain/URL/IP found in later service telemetry | approved parser/Zeek | Deferred | Not in first rollout |

Input validation is mandatory:

- AbuseIPDB accepts only public global-unicast IP addresses.
- VirusTotal accepts only a normalized 64-hex-character SHA-256.
- Invalid, private, loopback, link-local, multicast, and sensor addresses do
  not produce a job and are never queried.

## Event flow

```text
canonical event persisted in Atlas
        |
        +--> ti:jobs Redis stream (deduplicated observable reference)
                       |
                       v
                  ti-worker
             cache -> quota -> provider
                       |
                       v
           Atlas enrichment + session-risk projection
                       |
                       +--> dashboard / post-session analysis
```

The processor emits a job only after its canonical event is durable. If job
publication fails, the raw message remains unacknowledged and is retried through
the existing at-least-once path. The TI worker must make updates idempotently.

### Public-traffic controls

One SSH scanner can produce many Cowrie telemetry events for the same source IP.
Before publishing, the processor therefore takes a Redis `SETNX` dispatch lock
at `ti:queued:<job_id>`. The `TI_ENQUEUE_DEDUP_TTL` is one minute by default,
so an observable is sent to the worker at most once in that window. This limits
provider requests and queue growth; it does not discard the canonical Cowrie or
Zeek events in Atlas.

`TI_JOBS_STREAM_MAXLEN` is bounded (default: 5,000 approximate entries) to
protect Redis on the Pi. Use a dashboard health view to alert well before this
cap is approached; it is a safety cap, not durable long-term storage.

## Job contract

```json
{
  "job_id": "sha256(provider|type|normalized-observable)",
  "provider": "virustotal",
  "observable_type": "sha256",
  "observable": "normalized-value",
  "source_event_id": "atlas-event-id",
  "session_id": "optional-source-session",
  "priority": "high",
  "requested_at": "RFC3339 timestamp",
  "schema_version": "v1"
}
```

`job_id` is the SHA-256 digest of the provider, observable type, and normalized
observable. The observable value is retained only for the provider request and
analyst correlation.

## Storage contract

Store provider results separately from canonical events so a delayed lookup does
not rewrite or duplicate raw telemetry.

```json
{
  "_id": "sha256(provider|type|normalized-observable)",
  "provider": "abuseipdb",
  "observable_type": "ip",
  "observable": "example",
  "status": "complete|not_found|skipped|deferred",
  "summary": {
    "risk_level": "unknown|low|medium|high",
    "abuse_confidence_score": 0
  },
  "queried_at": "BSON date",
  "expires_at": "BSON date"
}
```

Canonical event documents contain a small time-stamped projection under
`threat_intel.<provider>`. The dashboard must represent an absent projection
(`pending`), `not_found`, `deferred`, and an expired result distinctly from a
benign verdict.

## Cache and quota policy

| Provider/result | Current cache TTL | Request policy |
| --- | --- | --- |
| Successful or not-found provider result | `TI_CACHE_TTL`, 7 days by default | Redis cache backed by `threat_intel` in Atlas |
| Provider key missing | 1 hour | `skipped`; no provider request |
| Invalid/private observable | no record | rejected before a job is published |
| Local budget exhausted or provider HTTP 429 | until the next configured window | `deferred` record is stored and the stream entry is acknowledged |
| Transient network or provider 5xx failure | no result cache | Leave the stream entry pending for the bounded recovery loop |

The worker keeps per-provider, UTC minute and day counters in Redis and stops
requests at the configured local budget. Production configuration is deliberately
low for this educational public honeypot: 2 requests/minute and 200/day for
each provider. The values are environment configuration and must be adjusted to
the actual provider plan. Provider rate-limit headers are not yet interpreted;
an HTTP 429 is conservatively deferred for one minute.

## Secrets and network boundary

- API keys belong only to `ti-worker` credentials, never Cowrie or dashboard.
- Store credentials through a root-readable systemd credential mechanism or a
  protected environment file; do not commit them.
- The worker has an explicit outbound allowlist to provider APIs.
- Log provider status and identifiers, never keys or full authorization headers.

## Dashboard and cloud-analysis projection

The dashboard receives provider-neutral fields: risk level, status, timestamp,
cache freshness, malicious/suspicious counts where applicable, and evidence
reference. The cloud analysis consumes the same projection plus session facts;
it does not make provider calls itself.

## Test and rollout gates

1. Unit test public-IP/hash validation, cache hit/miss, malformed response,
   timeout, 404, 429, Retry-After, and restart recovery.
2. Replay synthetic Cowrie/Zeek fixtures through a staging Redis stream.
3. Prove canonical event persistence succeeds with provider disabled or failed.
4. Run with low configurable budgets and inspect cache/queue metrics.
5. Enable only hash lookup and source-IP lookup after review; URL/domain and
   AbuseIPDB reporting require separate ADRs.
