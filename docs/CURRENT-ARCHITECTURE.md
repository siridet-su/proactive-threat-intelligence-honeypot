---
title: Current honeypot architecture
status: current
last_verified: 2026-09-24
---

# Current honeypot architecture

## Purpose and scope

This is one inherited-and-evolving multi-service honeypot project. The present
development focus is the adaptive SSH shell delivered through Cowrie. Existing
and future web, Odoo/CloudSQL-like, FTP, and SMTP decoys remain part of the
same deception surface.

The project does not execute attacker-controlled commands or malware on the
Raspberry Pi host.

## System view

```text
Attacker
  |
  +-- Cowrie SSH / Telnet ---------------------------+
  +-- Docker decoy services (web, FTP, SMTP, Odoo) --+-- telemetry --> Go pipeline
  +-- Network traffic observed by Zeek --------------+                     |
                                                                      Redis streams
                                                                           |
                                                                      Go processor
                                                                           |
                                                                     MongoDB Atlas
                                                                           |
                                                             post-session/cloud analysis
                                                                           |
                                                                      dashboard/report
```

The legacy sensor forwarder remains active as an inherited parallel path. It
must not be expanded as part of new features. Its retirement or migration is a
separate, verified change once the Go pipeline and cloud receiver have parity.

## Runtime posture at last verification

| Component | State | Notes |
| --- | --- | --- |
| Cowrie SSH/Telnet | Active | Attacker-facing deception service with manifest-bound sanitized output and hash-only artifact retention. |
| Docker decoy stack | Active | Web, FTP, SMTP, Odoo/PostgreSQL, and deception-core services. |
| OpenCanary HTTP login | Prepared, stopped (2026-09-24) | HTTP-only `basicLogin` staging on loopback port 8081; local rotating JSONL log; no firewall exposure or central event adapter. |
| Sensor forwarder | Active, legacy | Inherited cloud-forwarding path. |
| Go collector/processor/hardware agents | Active | Hardware uses a 30-document MongoDB live ring plus one-minute rollups; Pi Redis remains bounded and internal. The processor emits validated TI jobs when `THREAT_INTEL_ENABLED=true`. |
| Redis and Zeek | Active | Redis streams and all configured Zeek workers were healthy at the last verification. |
| TI worker | Active (verified 2026-09-24) | `honeypot-ti-worker.service` is enabled and running on the Pi. It consumes validated jobs from Redis `ti:jobs` under queue, cache, and provider-quota controls. |
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
- **Legacy plane:** inherited SQLite/MySQL-LLM/old dashboard material remains
  historical evidence. The isolated OpenCanary HTTP login decoy is re-adopted
  for loopback staging under [ADR-0004](adr/ADR-0004-opencanary-http-login.md);
  its archived configuration is not reused.

## Current integration priorities

1. Stabilize the adaptive Cowrie boundary on a non-public staging listener.
2. Maintain the active Go telemetry pipeline and monitor Redis consumer lag.
3. Operate asynchronous VirusTotal/AbuseIPDB enrichment through the worker with bounded queue/cache and provider-quota controls.
4. Define a common event contract for Cowrie, Zeek, and each Docker decoy.
5. Deliver post-session/cloud analysis against Atlas-backed canonical events.

## Out of scope for the current phase

- Running attacker payloads or malware on the Pi.
- Treating old SQLite or dashboard data as canonical.
- Moving an experimental LLM directly into the Cowrie shell critical path.
- Replacing the live Cowrie installation without a staging transcript,
  rollback plan, and explicit approval.
