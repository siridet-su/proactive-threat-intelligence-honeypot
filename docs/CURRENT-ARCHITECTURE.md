---
title: Current honeypot architecture
status: current
last_verified: 2026-08-25
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
| Cowrie SSH/Telnet | Active | Attacker-facing deception service. Admin SSH uses a separate port. |
| Docker decoy stack | Active | Web, FTP, SMTP, Odoo/PostgreSQL, and deception-core services. |
| Sensor forwarder | Active, legacy | Inherited cloud-forwarding path. |
| Go collector/processor/hardware agents | Intentionally stopped | Resource was released to test the adaptive-honeypot POC. |
| Redis and Zeek | Intentionally stopped with the Go pipeline | Resume only when the pipeline workstream is being tested. |
| Adaptive raw-command gateway | Experiment | Loopback POC only; not attached to the live Cowrie listener. |
| Post-session/cloud analysis | Target workstream | Under active development. |
| Hailo/Ollama runtime | Experimental candidate | Not the current Cowrie execution path. |

## Architectural boundaries

- **Deception plane:** Cowrie and Docker fake services expose only synthetic
  state and responses.
- **Telemetry plane:** Go collector, Redis, processor, Zeek, and MongoDB Atlas
  move and persist events when enabled.
- **Analysis plane:** Cloud/post-session analysis consumes persisted telemetry;
  it does not execute attacker input on the Pi.
- **Management plane:** SSH administration plus Tailscale/ZeroTier are for
  developers and operations, not attacker-facing application services.
- **Legacy plane:** inherited SQLite/OpenCanary/MySQL-LLM/old dashboard material
  is retained as historical evidence only unless a future ADR explicitly
  re-adopts a component.

## Current integration priorities

1. Stabilize the adaptive Cowrie boundary on a non-public staging listener.
2. Restore the Go telemetry pipeline only when required for its own staged test.
3. Add asynchronous VirusTotal/AbuseIPDB enrichment to the Go data path.
4. Define a common event contract for Cowrie, Zeek, and each Docker decoy.
5. Deliver post-session/cloud analysis against Atlas-backed canonical events.

## Out of scope for the current phase

- Running attacker payloads or malware on the Pi.
- Treating old SQLite or dashboard data as canonical.
- Moving an experimental LLM directly into the Cowrie shell critical path.
- Replacing the live Cowrie installation without a staging transcript,
  rollback plan, and explicit approval.
