# Threat-intelligence worker

This worker consumes `ti:jobs`, queries VirusTotal or AbuseIPDB asynchronously,
caches the selected result in MongoDB and Redis, then attaches a compact
provider-specific summary to the canonical event in MongoDB.

It does not execute files, download samples, upload observables, or report an
IP to either provider. VirusTotal is queried only with validated SHA-256 hashes.

## Enablement

1. Set `THREAT_INTEL_ENABLED=true` on the processor so it emits jobs.
2. Set `MONGO_URI`, `VIRUSTOTAL_API_KEY`, and/or `ABUSEIPDB_API_KEY` for this
   worker. Missing provider keys cause a short-lived `skipped` result rather
   than a request retry loop.
3. Build and run this agent, preferably with the supplied systemd template.

The default request limits are intentionally conservative: VirusTotal 3/minute
and 400/day, AbuseIPDB 10/minute and 800/day. Override them only after checking
the plan limits for the actual API credentials.

## Runtime variables

`TI_JOBS_STREAM` defaults to `ti:jobs`. `TI_CONSUMER_GROUP` defaults to
`ti-worker`; `TI_CONSUMER_NAME` defaults to the host name. `TI_CACHE_TTL`
defaults to seven days. See `.env.example` for the complete non-secret contract.

The data contract and lifecycle are in
[`docs/design/threat-intelligence.md`](../../docs/design/threat-intelligence.md).
