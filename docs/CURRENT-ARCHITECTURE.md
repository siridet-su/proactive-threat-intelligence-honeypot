---
title: Current honeypot architecture
status: current
last_verified: 2026-09-25
---

# Current honeypot architecture

## Purpose and scope

This is one inherited-and-evolving multi-service honeypot project. The present
development focus is the adaptive SSH shell delivered through Cowrie. The
active web scope is limited to capturing rejected ERP-style login attempts;
Odoo, direct-Pi HTTPS, FTP, and SMTP are stopped/future work.

The project does not execute attacker-controlled commands or malware on the
Raspberry Pi host.

## System view

Cowrie SSH/Telnet and Zeek observations flow through the Go collector, Redis,
and processor to MongoDB Atlas; TI enrichment and analysis are separate
downstream consumers.

Web-corp serves HTTP on ZeroTier `10.58.33.42:80` → container `:8080`; `8080`
is not a host-published listener. Only login POSTs produce app telemetry and
flow through the restricted spool, Go pipeline, Redis, and MongoDB Atlas.
Page/scan requests receive page responses without app telemetry or Uvicorn
access logs. The Pi's direct-TLS `:443` container is stopped; a trusted VPS
HTTPS edge is target work. FTP, SMTP, and Odoo containers are stopped. Deception
Core on loopback `:9000` and PostgreSQL on loopback `:5432` remain active as
Cowrie dependencies; neither is exposed as a public database/web service.

The legacy sensor forwarder remains active as an inherited parallel path. It
must not be expanded as part of new features. Its retirement or migration is a
separate, verified change once the Go pipeline and cloud receiver have parity.

## Runtime posture at last verification

| Component | State | Notes |
| --- | --- | --- |
| Cowrie SSH/Telnet | Active | Attacker-facing deception service with manifest-bound sanitized output and hash-only artifact retention. |
| Docker decoy stack | Partial | Web-corp HTTP, PostgreSQL, and Deception Core containers active; direct HTTPS, Odoo, FTP, and SMTP containers stopped. |
| Web-corp HTTP login decoy | Active | ZeroTier `:80` → container `:8080`; only login POSTs generate new app telemetry. Restricted spool → `raw:web-login` → processor → MongoDB `honeypot_db.events`; raw password stays out of Core commands and `event:canonical`. Old `web_http_request` records remain ingestible. |
| Web-corp HTTPS | Stopped on Pi | Direct self-signed TLS container on ZeroTier `:443` stopped 2026-09-25. Public-VPS HTTPS/WireGuard runbook is a not-deployed target. |
| Odoo, FTP, SMTP | Stopped / future | Odoo and the FTP/SMTP containers are stopped. Tracked FTP/SMTP sources remain future work pending event adapters and dashboard integration. |
| OpenCanary HTTP login | Prepared, stopped (2026-09-24) | HTTP-only `nasLogin` staging on loopback port 8081; local rotating JSONL log; no firewall exposure or central event adapter. |
| Sensor forwarder | Active, legacy | Inherited cloud-forwarding path. |
| Go collector/processor/hardware agents | Active | Login pipeline uses collector/processor; hardware uses a 30-document MongoDB live ring plus one-minute rollups; Pi Redis remains bounded and internal. The processor emits validated TI jobs only for eligible observables when `THREAT_INTEL_ENABLED=true`. |
| Redis and Zeek | Active | Redis streams and all configured Zeek workers were healthy at the last verification. |
| TI worker | Active (verified 2026-09-24) | `honeypot-ti-worker.service` is enabled and running on the Pi. It consumes validated jobs from Redis `ti:jobs` under queue, cache, and provider-quota controls. Web-corp login is excluded. |
| Dashboard Web-corp HTTP activity | Active on GCP (validated 2026-09-25) | Read-only MongoDB integration; production projection and unauthenticated API boundary were checked. Authenticated browser rendering was not exercised. |
| Dashboard Filesystem Activity | Source retirement prepared; production deployment pending | The current branch removes session termination and keeps Route Replay/Evidence, but the production Dashboard has not been redeployed and may still serve its earlier UI/API. The Pi agent is unavailable. Tailnet ACL cleanup and the next Cowrie restart are pending; see [ADR-0007](adr/ADR-0007-retire-dashboard-session-termination.md) and the [retirement runbook](RESPONSE-CONTROL-PLANE.md). |
| Adaptive raw-command gateway | Experiment | Loopback POC only; not attached to the live Cowrie listener. |
| Post-session/cloud analysis | Target workstream | Under active development. |
| Hailo/Ollama runtime | Experimental candidate | Not the current Cowrie execution path. |

Real administrative SSH listens on port 2222 but host-firewall access is limited to the Tailscale and ZeroTier interfaces. Password and root authentication are disabled.

## Architectural boundaries

- **Deception plane:** Cowrie and Docker fake services expose only synthetic
  state and responses.
- **Telemetry plane:** Go collector, Redis, processor, Zeek, and MongoDB Atlas
  move and persist events when enabled.
- **Analysis plane:** Cloud/post-session analysis consumes persisted telemetry;
  it does not execute attacker input on the Pi.
- **Management plane:** SSH administration plus Tailscale/ZeroTier are for
  developers and operations, not attacker-facing application services.
- **Dashboard boundary:** Dashboard Filesystem Activity reads telemetry and
  retained evidence; it has no action channel into Cowrie. Tailscale remains a
  host-administration path, not a Dashboard response transport.
- **Legacy plane:** inherited SQLite/MySQL-LLM/old dashboard material remains
  historical evidence. The isolated OpenCanary HTTP login decoy is re-adopted
  for loopback staging under [ADR-0004](adr/ADR-0004-opencanary-http-login.md);
  its archived configuration is not reused.

## Current integration priorities

1. Stabilize the adaptive Cowrie boundary on a non-public staging listener.
2. Maintain the active Go telemetry pipeline and monitor Redis consumer lag.
3. Operate asynchronous VirusTotal/AbuseIPDB enrichment through the active worker with bounded queue/cache and provider-quota controls.
4. Verify authenticated dashboard review of web-corp login events; keep FTP/SMTP adapters as future work.
5. Deliver post-session/cloud analysis against Atlas-backed canonical events.

## Out of scope for the current phase

- Running attacker payloads or malware on the Pi.
- Treating old SQLite or dashboard data as canonical.
- Moving an experimental LLM directly into the Cowrie shell critical path.
- Replacing the live Cowrie installation without a staging transcript,
  rollback plan, and explicit approval.
