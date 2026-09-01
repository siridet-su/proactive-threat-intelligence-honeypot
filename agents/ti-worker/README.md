# Threat-intelligence worker

This worker consumes `ti:jobs`, queries VirusTotal or AbuseIPDB asynchronously,
caches the selected result in MongoDB and Redis, then attaches a compact
provider-specific summary to the canonical event in MongoDB.

It does not execute files, download samples, upload observables, or report an
IP to either provider. VirusTotal is queried only with validated SHA-256 hashes.

## Enablement

1. Set `THREAT_INTEL_ENABLED=true` on the processor so it emits jobs.
2. Set shared Redis/MongoDB/stream values in `/etc/honeypot-agent.env`.
3. Set `VIRUSTOTAL_API_KEY` and/or `ABUSEIPDB_API_KEY` in the private
   `/etc/honeypot/ti-worker.env`. Missing provider keys cause a short-lived
   `skipped` result rather than a request retry loop.
4. Build and run this agent, preferably with the supplied systemd template.

The default request limits are intentionally conservative: 2 requests/minute
and 200/day for each provider. Override them only after checking the plan limits
for the actual API credentials.

## Runtime variables

Set `TI_JOBS_STREAM`, `TI_CONSUMER_GROUP`, and `TI_CONSUMER_NAME` explicitly.
`TI_CACHE_TTL` defaults to seven days. See `.env.example` for the worker-only
contract.

On the processor's shared environment, set `TI_ENQUEUE_DEDUP_TTL=1m` and
`TI_JOBS_STREAM_MAXLEN=5000` (the safe defaults). The first limits a repeated
observable to one dispatch per minute; the second bounds Redis stream growth.
When a local quota or provider HTTP 429 is reached, the worker stores a short
`deferred` result and acknowledges the job rather than letting the pending-entry
list grow indefinitely.

The data contract and lifecycle are in
[`docs/design/threat-intelligence.md`](../../docs/design/threat-intelligence.md).
