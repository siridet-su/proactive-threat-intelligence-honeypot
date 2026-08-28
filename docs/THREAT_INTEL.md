> **Status: superseded prototype.**
>
> The current implementation uses a Redis-backed asynchronous worker; see [the TI design](design/threat-intelligence.md). Direct provider calls in the `processor-agent`, the in-memory cache, and the field layout below are historical only.
>
> **Current configuration boundary.**
>
> `/etc/honeypot-agent.env` is shared operational configuration and contains
> no credentials. `MONGO_URI` and Redis authentication are provided to the
> Processor through `/etc/honeypot/processor.env`; provider keys are provided
> only to the TI worker through `/etc/honeypot/ti-worker.env`. The hardware
> agent receives only its Redis authentication through
> `/etc/honeypot/hardware.env`. These root-owned files are mode `0600`.
>
> The historical configuration section below is not an installation guide.
>
# Threat Intelligence Enrichment Pipeline

This document outlines the architecture and implementation details for the automated Threat Intelligence (TI) enrichment pipeline integrated into the Honeypot's Go-based `processor-agent`.

## Overview
Instead of querying third-party threat intelligence APIs directly from the frontend (which is slow, blocks rendering, and easily exhausts API rate limits), the TI lookups are deeply integrated into the backend ingestion pipeline. 

When an event is consumed from Redis by the `processor-agent`, the agent immediately queries external Threat Intelligence providers before writing the enriched event to MongoDB.

## Features
1. **AbuseIPDB Integration:** Automatically retrieves the abuse confidence score, ISP, and historical reporting data for any attacking IP address.
2. **VirusTotal Integration:** Automatically verifies the SHA-256 hash of any payload downloaded by an attacker (via `wget`, `curl`, `sftp` in Cowrie) to determine if it is a known malware strain.
3. **In-Memory Caching:** Both API integrations utilize an asynchronous in-memory locking cache (`sync.RWMutex`). If an attacker blasts the honeypot with 10,000 SSH brute-force attempts in a minute, the agent only queries AbuseIPDB **once** and serves the cached result for the remaining 9,999 events. This guarantees high throughput and zero API rate-limiting issues.
4. **Global Circuit Breaker (Rate Limit Protection):** To fully protect Free Tier API keys, the system monitors HTTP 429 (Too Many Requests) responses. If the VirusTotal limit (4/min) is reached, all VT lookups are paused globally for 1 minute. If the AbuseIPDB limit (1000/day) is reached, lookups pause for 1 hour.

## Data Structure
Enriched events in MongoDB will now contain two new top-level JSON objects when applicable:

```json
{
  "event_id": "...",
  "network": { "src_ip": "202.28.41.152", ... },
  "abuseipdb": {
    "abuseConfidenceScore": 100,
    "countryCode": "TH",
    "domain": "...",
    "isp": "..."
  },
  "virustotal": {
    "meaningful_name": "mirai.arm7",
    "reputation": -88,
    "stats": { "malicious": 45, "undetected": 10 }
  }
}
```

## Configuration
To enable these features, ensure the following environment variables are present in the `.env` file of the processor-agent (or `/etc/honeypot-agent.env`):

- `ABUSEIPDB_API_KEY`: Your v2 API key from AbuseIPDB.
- `VIRUSTOTAL_API_KEY`: Your v3 API key from VirusTotal.

*(If the keys are missing or blank, the agent will gracefully skip enrichment and process events normally.)*
