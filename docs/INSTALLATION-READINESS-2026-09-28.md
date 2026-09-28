---
title: Installation readiness audit
status: current
last_verified: 2026-09-28
---

# Installation readiness audit — 2026-09-28

The selected installation target is a **fresh Raspberry Pi from a clean OS**.
This is a read-only comparison of repository contracts and the `pi-t` host,
plus one permission correction recorded below. It is not an installation
manual or approval to run the proposed customer appliance installer. The
Dashboard production host and its private environment were not accessed.

## Verified inventory

| Area | Observed state | Installation consequence |
| --- | --- | --- |
| Source repository | Local `main` was clean at `ec241e6`. | Build releases from a fixed clean commit, not a mutable checkout. |
| Current Pi | Ubuntu 24.04 on ARM64; 7.8 GiB RAM and about 53 GiB free on `/` at inspection. | A fresh-host guide needs an explicit ARM64 and OS test matrix; these numbers are observations, not minimum requirements. |
| Pi source checkout | `feat/opencanary-web-login-honeypot` at `4b0d67d1`, 23 commits ahead of its configured upstream, with a modified `integrations/web-corp/main.py`. | Do not install or upgrade by running `git pull` in the live checkout. Inventory and preserve its local state before any migration. |
| Pi systemd | Cowrie, Redis, Zeek, collector, processor, hardware agent, TI worker, backup control loop, and legacy sensor forwarder were active and enabled. OpenCanary was disabled and inactive. | An installation guide must declare required versus optional services and start dependencies explicitly. |
| Pi Docker | Web-corp, Deception Core, and PostgreSQL containers were running. Compose and its private `.env` are in `~/decoy-honeypot`, outside this repository. | The current deployment cannot be reproduced from this repository alone. The Compose source, image digests, mounts, and env contract need a versioned release boundary. |
| Cowrie and Go release paths | Cowrie starts through the versioned sanitized-output `current` release; Go agents execute binaries inside the mutable Pi checkout. | Preserve the existing Cowrie release/rollback contract and package Go binaries as immutable ARM64 artifacts before a fresh install. |
| Dashboard location | No monitor-web, dashboard API, or Dashboard staging systemd unit was installed on the Pi. Repository docs place Dashboard production and staging on a separate host. | Install the Dashboard separately from the sensor Pi; do not add it to the Pi service sequence by assumption. |

### Unmerged installer work

The repository also has an unmerged `feat/appliance-installer` branch at
`ddf4f3c`, based on an older `main` revision. It contains
`scripts/pti_install.py`, ARM64 sensor profiles, a release builder, tests, and
draft installation manuals. The CLI deliberately supports read-only `plan`,
`preflight`, and `package-audit` work; its profile sets `install_enabled=false`.
The Thai manual covers host-foundation testing on a disposable ARM64 VM and is
not an accepted full Pi installation procedure. Rebase and review this branch
against current `main` and the findings here before using it as the next
implementation base. Its existence does not clear the installation blockers
below.

### Environment boundaries

- Pi systemd uses private files under `/etc/honeypot/` and
  `/etc/honeypot-agent.env`. The inspected agent, processor, hardware, TI, and
  backup files were mode `0600`; the legacy forwarder file was mode `0640`.
  The host-specific files contain Mongo, Redis, TI-provider, B2, and decoy
  credentials. Only key names and file modes were inspected; no values were
  copied into this repository.
- The external Compose `.env` was mode `0600`. Its contract includes database,
  web bind, and optional service settings. Keep it outside release artifacts.
- The Pi checkout's `dashboard-v2/.env.local` contained `MONGODB_URI` and was
  mode `0664`. It was changed to `0600` on 2026-09-28 and verified. No value or
  service setting was changed. The local development workspace's corresponding
  file was already mode `0600`.
- The local development Dashboard `.env.local` contained `MONGODB_URI`,
  `PTI_LOCAL_ADMIN_COMMANDS_FROM_MONGO`, and `ABUSEIPDB_API_KEY` names. The
  current Dashboard source does not reference `ABUSEIPDB_API_KEY`; the TI
  worker has its own provider credential. `AUTH_SESSION_SECRET` was absent
  from this local file, so development uses its documented fallback; a
  production runtime must set a distinct secret.
- Current Dashboard source reads `MONGODB_URI`, `AUTH_SESSION_SECRET`, and
  `PTI_ADMIN_PASSWORD` for Mongo-backed Admin authentication. Its monitor
  routes use `DASHBOARD_MONITOR_BASE_URL` and optionally
  `DASHBOARD_MONITOR_READ_TOKEN`; raw command review uses an owner-only token
  file via `MONITOR_RAW_COMMANDS_TOKEN_FILE`. These are server-only settings.
  The [Dashboard README](../dashboard-v2/README.md) and
  [API contract](../dashboard-v2/docs/API.md) still mention older
  `DASHBOARD_API_*` names, so source behavior must govern the install contract
  until those documents are reconciled.

## Installation blockers found

1. There is no runnable unified installer for the complete current system on
   `main`. The unmerged installer branch is plan-only. The
   [customer appliance blueprint](HONEYPOT-PORTAL-INSTALLER-GUIDE.md) is
   proposed, includes retired response-control history, and is not runnable.
2. The Dashboard staging bootstrap/template still generates
   `DASHBOARD_V2_ACCESS_KEY` and `DASHBOARD_V2_SESSION_SECRET`; current source
   reads `PTI_ADMIN_PASSWORD` and `AUTH_SESSION_SECRET`. Its staging env
   template also excludes `MONGODB_URI`, while current auth requires Mongo.
   CI builds the artifact but does not prove this runtime env contract.
3. Production Dashboard runtime env and deployed release identity were not
   audited from the Dashboard host in this inspection. Existing documentation
   records a separate production service and staging release wrapper, but
   those records are not a live host check.
4. The Pi Go agents run from a dirty, divergent checkout and the Docker
   Compose deployment is outside the source repository. Neither should be
   silently captured as a reproducible clean install.
5. A clean OS installation and a migration of the existing Pi require
   different procedures and rollback evidence. The read-only backup restore
   rehearsal remains unverified in the current architecture snapshot.

## Recommended installation sequence

The accepted responsibility boundary is [ADR-0009](adr/ADR-0009-installer-operator-managed-credentials.md).
The installer prepares dependencies, versioned artifacts, service units, and
non-secret configuration. It leaves application services stopped and does not
create or modify private env files. Operators add credentials separately;
validation and activation follow as an explicit second phase.

### Selected path: fresh Pi, after the blockers above are resolved

1. Freeze a reviewed release manifest: exact Git revision, ARM64 Go binary
   hashes, Cowrie bundle revision, Compose image digests, Dashboard standalone
   artifact and Node runtime version, and configuration schema versions.
2. Preflight a supported clean OS: architecture, disk/RAM, clock, outbound
   Mongo/B2/TI reachability, port ownership, firewall, and a separately proven
   administrative SSH route. Do not replace the working SSH route during
   staging.
3. Install versioned packages and base services in dependency order: Redis and
   sensor prerequisites; Cowrie and its sanitized-output/retention boundary;
   Zeek and Go collector/processor; optional hardware, TI, and backup workers;
   then the reviewed Docker decoys. Install units and non-secret config, but
   leave application services stopped; keep future decoys uninstalled.
4. Install the Dashboard on its separate host from an immutable standalone
   artifact, also without credentials. Correct its current env contract before
   activation. Restrict monitor access to the intended private/loopback route.
5. On each host, the operator provisions private env files outside Git with
   service-appropriate owner-only permissions. Use separate Mongo roles and
   provider/B2 keys for Pi workers and Dashboard. Do not copy the existing
   Pi's private files into a customer appliance image. Validate private file
   ownership, required key names, and connectivity without displaying values;
   stop if any required input is missing.
6. Explicitly activate only selected services, then run synthetic, non-public
   smoke tests for session telemetry, canonical
   events, Dashboard login and Evidence, TI hash lookup, backup scheduling,
   and a read-only restore. Expose trap ports only after those checks pass.
7. Record a sanitized installation receipt and retain the previous release,
   config backup, service/unit hashes, and a tested rollback path. Uninstall
   must preserve telemetry and logs by default.

### Existing Pi migration

Keep this as a separate maintenance procedure. First capture the live unit
definitions, binary hashes, Compose configuration, protected env-file
metadata, active release pointers, database/backup state, and the dirty
checkout diff in a protected backup. Build a clean candidate from a pinned
revision off-host; compare its telemetry contract and run it on a non-public
listener. Only then schedule a service-by-service cutover with a restore
receipt and explicit rollback. Do not use the fresh-install script, reset the
checkout, overwrite private env, or switch all services at once.

## Next documentation step

The installation manual should cover the selected clean-OS ARM64 Pi first.
Reconcile the Dashboard runtime env/template mismatch, define the minimum
supported feature set, and version the external Compose deployment before
turning the sequence above into commands that an operator can run. Existing-Pi
migration remains a separate later manual.

## 2026-09-28 staging addendum

The subsequent decoy staging slice now provides a reviewed source bundle,
exact Ubuntu Docker/Compose package requests, blank private env skeleton,
and an inactive final runtime on the disposable ARM64 VM; a separate
disposable image build and loopback smoke check also passed. The Dashboard staging
bootstrap and deployment gate now use the current source env names and pause
until the operator fills the private values. These changes resolve only the
named staging preparation gaps; persistent container activation, production
Dashboard identity, and complete fresh-Pi installation remain unverified.
