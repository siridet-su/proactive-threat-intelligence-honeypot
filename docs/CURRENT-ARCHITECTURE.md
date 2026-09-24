---
title: Current honeypot architecture
status: current
last_verified: 2026-09-25
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

Retained MongoDB sources with an enabled target
  -> Pi backup control/scheduled worker
  -> gzip Extended JSON Lines
  -> private Backblaze B2 archive
```

The legacy sensor forwarder remains active as an inherited parallel path. It
must not be expanded as part of new features. Its retirement or migration is a
separate, verified change once the Go pipeline and cloud receiver have parity.

## Runtime posture at last verification

| Component | State | Notes |
| --- | --- | --- |
| Cowrie SSH/Telnet | Active | Attacker-facing deception service with manifest-bound sanitized output and hash-only artifact retention. |
| Docker decoy stack | Active | Web, FTP, SMTP, Odoo/PostgreSQL, and deception-core services. |
| Web-corp login telemetry | Active | Dedicated pending spool → `raw:web-login` → processor → MongoDB `honeypot_db.events`; raw password stays out of Core commands and the `event:canonical` projection. |
| OpenCanary HTTP login | Prepared, stopped (2026-09-24) | HTTP-only `nasLogin` staging on loopback port 8081; local rotating JSONL log; no firewall exposure or central event adapter. |
| Sensor forwarder | Active, legacy | Inherited cloud-forwarding path. |
| Go collector/processor/hardware agents | Active | Hardware uses a 30-document MongoDB live ring plus one-minute rollups; Pi Redis remains bounded and internal. The processor emits validated TI jobs when `THREAT_INTEL_ENABLED=true`. |
| Retained data backup worker | Active for `hardware_metrics_1m`; multi-target binary deployed, additional targets inactive | The Pi worker writes hardware rollups to private B2 and reports storage/manifest state. `threat_events` and `filesystem_audit` remain inactive because the current upload key is restricted to the `hardware_metrics_1m/` prefix. |
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
4. Complete telemetry adapters for the remaining Docker decoys; web-corp login is integrated.
5. Deliver post-session/cloud analysis against Atlas-backed canonical events.
6. Activate additional retained-data backup targets only after the B2 key and
   sensitive-event policy review described in [ADR-0006](adr/ADR-0006-retained-data-backup-boundaries.md).

## Out of scope for the current phase

- Running attacker payloads or malware on the Pi.
- Treating old SQLite or dashboard data as canonical.
- Moving an experimental LLM directly into the Cowrie shell critical path.
- Replacing the live Cowrie installation without a staging transcript,
  rollback plan, and explicit approval.
