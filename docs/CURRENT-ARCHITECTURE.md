---
title: Current honeypot architecture
status: current
last_verified: 2026-09-28
last_updated: 2026-09-28
---

# Current honeypot architecture

## Purpose and scope

This is one inherited-and-evolving multi-service honeypot project. The next
documentation focus is the installation manual. The adaptive SSH shell remains
a separate target workstream. The active web scope is limited to capturing
rejected ERP-style login attempts;
Odoo, direct-Pi HTTPS, FTP, and SMTP are stopped/future work.

The project does not execute attacker-controlled commands or malware on the
Raspberry Pi host.

## System view

Cowrie SSH/Telnet and Zeek observations flow through the Go collector, Redis,
and processor to MongoDB Atlas; TI enrichment and analysis are separate
downstream consumers.

Web-corp serves HTTP on ZeroTier `:80` and through a separate Pi WireGuard
backend `:80` reached by the Droplet's public HTTPS `:443` proxy. Only login POSTs produce app telemetry and
flow through the restricted spool, Go pipeline, Redis, and MongoDB Atlas.
Page/scan requests receive page responses without app telemetry or Uvicorn
access logs. The Pi's direct-TLS `:443` container is stopped; the Droplet uses
a short-lived public-IP certificate with automated renewal. FTP, SMTP, and Odoo containers are stopped. Deception
Core on loopback `:9000` and PostgreSQL on loopback `:5432` remain active as
Cowrie dependencies; neither is exposed as a public database/web service.

Retained MongoDB sources with an enabled target flow through the Pi backup
control/scheduled worker into gzip Extended JSON Lines in the private
Backblaze B2 archive.

The legacy sensor forwarder remains active as an inherited parallel path. It
must not be expanded as part of new features. Its retirement or migration is a
separate, verified change once the Go pipeline and cloud receiver have parity.
The [forwarder explanation](LEGACY-SENSOR-FORWARDER.md) records its GCP ingest
purpose and the Dashboard read-path reason it remains active on the existing
Pi. A new Pi installation omits it.

The active decoy stack has a tracked [Compose source](../deploy/decoy-honeypot/README.md)
and Deception Core build context in this repository. The existing Pi still
runs its earlier external Compose file with a host-local override for the
additional WireGuard Web-corp container. The original ZeroTier container was
not rebuilt.

The clean-host target in [ADR-0015](adr/ADR-0015-fresh-pi-local-decoys.md)
differs from that existing Pi: Cowrie defaults to the Pi Wi-Fi address at
TCP 2222/2223 while administrator SSH remains on 22. Zeek captures that Wi-Fi interface
with a narrow port filter, and Web-corp/Core/PostgreSQL bind to loopback. The
disposable ARM64 VM verified these services with loopback test ports and
synthetic private input. It did not validate Go/Atlas/B2 end to end, and it
does not change the current Pi or public Droplet.
The clean-host installer leaves its B2 backup control unit stopped and
disabled by default. The owner must provide their own write-capable bucket
key and explicitly enable backup; historical object read access is separate.

## Runtime posture at last verification

| Component | State | Notes |
| --- | --- | --- |
| Cowrie SSH/Telnet | Active | Attacker-facing deception service with manifest-bound sanitized output and hash-only artifact retention. |
| Cowrie service watchdog | Active on Pi | The 30-second timer checks the service state and passively confirms an IPv4 port 22 listener through `/proc/net/tcp`. It no longer opens a local SSH connection. The earlier probe's exact-pair MongoDB rows were cleaned separately; see the [watchdog runbook](../deploy/service-watchdog/README.md). |
| Docker decoy stack | Partial | ZeroTier and WireGuard Web-corp HTTP containers, PostgreSQL, and Deception Core active; direct Pi HTTPS, Odoo, FTP, and SMTP containers stopped. |
| Web-corp HTTP login decoy | Active | ZeroTier `:80` → container `:8080`; only login POSTs generate new app telemetry. Restricted spool → `raw:web-login` → processor → MongoDB `honeypot_db.events`; raw password stays out of Core commands and `event:canonical`. Old `web_http_request` records remain ingestible. |
| Web-corp HTTPS | Active on Droplet | Nginx serves public-IP TLS on `:443`, uses `:80` for ACME and redirect, and proxies only over WireGuard to the Pi. Direct self-signed Pi TLS remains stopped. A synthetic login was rejected and persisted with HTTPS/443 metadata. Renewal dry-run passed; real renewal has not yet occurred. |
| Odoo, FTP, SMTP | Stopped / future | Odoo and the FTP/SMTP containers are stopped. Tracked FTP/SMTP sources remain future work pending event adapters and dashboard integration. |
| OpenCanary HTTP login | Prepared, stopped (2026-09-24) | HTTP-only `nasLogin` staging on loopback port 8081; local rotating JSONL log; no firewall exposure or central event adapter. |
| Sensor forwarder | Active, legacy | Inherited cloud-forwarding path. |
| Go collector/processor/hardware agents | Active | Login pipeline uses collector/processor; hardware uses a 30-document MongoDB live ring plus one-minute rollups; Pi Redis remains bounded and internal. The processor emits validated TI jobs only for eligible observables when `THREAT_INTEL_ENABLED=true`. |
| Retained data backup worker | Active for `hardware_metrics_1m`, `filesystem_audit`, and `threat_events` | On 2026-09-27 the Pi worker was advanced to the schedule-capable binary from `b75749e`. Its enabled control service schedules the daily Bangkok run at the default 03:30, reads append-only Dashboard schedule revisions, and claims one run per local day. The former fixed timer is disabled and inactive. The first scheduler catch-up completed all three targets on 2026-09-27 without a duplicate run; the source window ended 2026-09-25. The prior archive verification found 29 successful bucket-tagged manifests per target, with 21 threat-event days containing 53,496 records and eight empty days. Older bucket-less manifests and B2 versions were retained. `cwd_audit_projection` remains excluded because it is rebuildable. The sensitive threat-event target remains enabled under the reviewed private-bucket policy; production Dashboard deployment and read-only restore verification remain unverified. |
| Redis and Zeek | Active | Pi Zeek has `wlan0`, ZeroTier, and `wg0` workers. The filter admits Cowrie TCP 22/23 on the first two interfaces and Web-corp TCP 80 on ZeroTier and `wg0`; other development/management traffic is excluded. Synthetic public HTTPS traffic produced `wg0` conn/http events in MongoDB. Tailscale inner traffic remains outside Zeek capture. |
| TI worker | Active (verified 2026-09-24) | `honeypot-ti-worker.service` is enabled and running on the Pi. It consumes validated jobs from Redis `ti:jobs` under queue, cache, and provider-quota controls. Web-corp login is excluded. |
| Dashboard Web-corp HTTP activity | Active on GCP (validated 2026-09-25) | Read-only MongoDB integration; production projection and unauthenticated API boundary were checked. Authenticated browser rendering was not exercised. |
| Dashboard Filesystem Activity | Local UI target; local-to-GCP path unqualified | `main` retains Route Replay and Admin-only command/download Evidence after retiring session termination. The GCP production and staging Dashboard v2 services were stopped and disabled on 2026-10-08. A local authenticated BFF-to-GCP path, session details, command evidence, reports, and PDF generation have not been requalified. Do not copy a production MongoDB URI into browser code or open a public API listener. The Artifact Intelligence link destination remains unverified. The Pi response agent remains retired; tailnet ACL cleanup and the next Cowrie restart remain pending. See [ADR-0007](adr/ADR-0007-retire-dashboard-session-termination.md), [ADR-0016](adr/ADR-0016-hosted-dashboard-command-evidence.md), [ADR-0017](adr/ADR-0017-local-dashboard-gcp-backend.md), the [retirement runbook](RESPONSE-CONTROL-PLANE.md), and the [Filesystem working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md). |
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
6. Monitor all enabled retained-data backup targets, manifests, and B2 storage
   health; revisit the sensitive-event policy before changing the `threat_events`
   scope.

## Out of scope for the current phase

- Running attacker payloads or malware on the Pi.
- Treating old SQLite or dashboard data as canonical.
- Moving an experimental LLM directly into the Cowrie shell critical path.
- Replacing the live Cowrie installation without a staging transcript,
  rollback plan, and explicit approval.
