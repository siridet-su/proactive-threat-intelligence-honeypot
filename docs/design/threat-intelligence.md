---
title: Threat-intelligence enrichment design
status: target
last_verified: 2026-08-25
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
- Invalid, private, loopback, link-local, multicast, and sensor addresses are
  recorded as skipped and never queried.

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

## Job contract

```json
{
  "job_id": "provider:type:value_hash",
  "provider": "virustotal",
  "observable": {
    "type": "sha256",
    "value": "normalized-value"
  },
  "source_event_id": "atlas-event-id",
  "session_id": "optional-source-session",
  "priority": "high",
  "requested_at": "RFC3339 timestamp",
  "schema_version": 1
}
```

`value_hash` is a hash of the normalized observable used as the persistent
deduplication key. The observable value remains available only where required
for the provider request and analyst correlation.

## Storage contract

Store provider results separately from canonical events so a delayed lookup does
not rewrite or duplicate raw telemetry.

```json
{
  "_id": "provider:type:value_hash",
  "provider": "abuseipdb",
  "observable_type": "ip",
  "observable": "example",
  "status": "found|not_found|skipped|failed|rate_limited",
  "summary": {
    "risk_level": "unknown|low|medium|high",
    "abuse_confidence_score": 0
  },
  "retrieved_at": "BSON date",
  "expires_at": "BSON date",
  "schema_version": 1
}
```

Canonical event documents contain only enrichment references or a small
time-stamped projection. The dashboard must represent `pending`, `not_found`,
`failed`, and `expired` distinctly from a benign verdict.

## Cache and quota policy

| Provider/result | Initial cache TTL | Request policy |
| --- | --- | --- |
| AbuseIPDB IP result | 24 hours | Redis + Atlas persistent cache; configurable daily budget |
| VirusTotal known SHA-256 | 7–30 days | shared token bucket; single worker/concurrency one for community-tier safety |
| VirusTotal hash not found | 24 hours | negative cache; unknown, never benign |
| Transient failure | short bounded backoff | no busy retry; retain failure metadata |

The worker reads provider rate-limit headers, honors `Retry-After`, exposes
remaining budget metrics, and stops requests when the configured budget is
exhausted. The exact provider plan/limits are configuration, not hard-coded
assumptions.

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
