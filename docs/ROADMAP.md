---
title: Project roadmap
status: target
last_verified: 2026-09-24
last_updated: 2026-09-28
---

# Project roadmap

## Current delivery focus — installation manual

The current Filesystem Activity implementation round closed on 2026-09-28.
The accepted local Evidence slice and deferred FS additions are recorded in
[Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md).
Production Dashboard deployment remains unverified; closure does not claim a
production rollout.

The next documentation workstream is the installation manual for a **fresh
ARM64 Raspberry Pi from a clean OS**. Start from the verified
[current architecture](CURRENT-ARCHITECTURE.md) and the proposed
[installer blueprint](HONEYPOT-PORTAL-INSTALLER-GUIDE.md), using the
[installation readiness audit](INSTALLATION-READINESS-2026-09-28.md) to resolve
the current release/env gaps. Separate runnable
instructions from future appliance design. The blueprint's retired
Dashboard-to-Pi disconnect/control path is historical, not an installation
requirement. Existing-Pi migration is a later, separate procedure. No
customer installer is currently declared ready to run.

The first implementation slice stages checked Linux ARM64 Go-agent artifacts,
inactive systemd units, and blank private env skeletons through
[Ansible](../deploy/ansible/README.md). On a disposable Ubuntu 24.04 ARM64 VM,
the first prepare, missing-env pause, and unchanged-file retry passed; see the
[VM evidence](validation/2026-09-28-azure-arm64-installer-first-run.md). It does
not invoke the separate Cowrie-source and Zeek staging playbooks, or install
the Docker decoys or Dashboard. Zeek packages and patched Cowrie source/venv
were staged on the disposable VM without active services; see the
[dependency evidence](validation/2026-09-28-azure-arm64-cowrie-zeek-staging.md).
Activation has not been qualified on a VM or Pi. Complete Cowrie's fresh-host
sanitized output boundary, service access rules, operator credential checks,
and activation sequence before
calling the installer runnable for a fresh Pi.

The active PostgreSQL, Deception Core, and Web-corp HTTP
[Compose source](../deploy/decoy-honeypot/README.md) and Core build inputs are
now tracked. This removes the sibling-folder source dependency for a future
fresh install, but the first Ansible slice does not consume or activate them.
The current Pi still uses its existing external Compose file.

The accepted installer boundary is in
[ADR-0009](adr/ADR-0009-installer-operator-managed-credentials.md) and
[ADR-0011](adr/ADR-0011-installer-private-env-skeletons.md): prepare versioned
dependencies, service units, non-secret configuration, and missing blank
private `.env` skeletons; leave application services stopped while the operator
fills private values; validate and activate in a separate step. The installer
must not generate or copy credentials.

## Phase 0 — Establish project truth

- Maintain this documentation spine and service catalog.
- Classify inherited implementation and documentation without deleting it.
- Record ports, ownership, data flow, and approved scope before a new service
  is exposed.

## Phase 1 — Adaptive Cowrie shell

- Keep the deterministic virtual world state authoritative.
- Convert the Cowrie fork POC into a version-pinned, reviewable patch series.
- Use a hardened local transport and repeat transcript, cancellation, timeout,
  backpressure, and rollback tests on a non-public listener.
- Do not attach the adaptive gateway to the live listener until explicit staging
  acceptance criteria pass.
- Keep reset-per-login virtual filesystems as the default. The bounded
  [returning-attacker continuity](design/returning-attacker-continuity.md)
  overlay remains future work until runtime ownership, actor identity,
  filesystem telemetry, retention, and isolation gates pass.

## Phase 2 — Principal telemetry pipeline

- Re-enable Redis, Zeek, collector, and processor only in a staged test window.
- Verify Go pipeline delivery to Atlas and document resource use.
- Define and implement service adapters for Docker decoys.
- Establish migration/parity criteria before retiring the legacy sensor
  forwarder.

## Phase 3 — Threat intelligence (baseline implemented)

- Operate the separate asynchronous TI worker, not synchronous calls inside
  the processor hot path.
- Query AbuseIPDB only for validated public source IPs.
- Query VirusTotal by observed SHA-256 first; no automatic file upload.
- Persist normalized, cache-expiring enrichment and expose status to the
  dashboard.
- Keep Redis queue bounds, deduplication, cache expiry, and provider quotas
  under explicit operational review as traffic and provider plans change.

## Phase 4 — Post-session/cloud analysis

- Consume Atlas canonical events and session summaries.
- Keep observed facts, inference, and hypothesis separate.
- Store model/version, evidence references, timestamps, and limitations with
  every analysis result.

## Phase 5 — Reporting and evaluation

- Build reproducible staging fixtures and replay tests.
- Measure delivery, enrichment, analysis, resource use, and deception quality.
- Generate report tables and figures only from versioned evidence.

## Scope-control rule

Adding a new exposed decoy is allowed only when its persona, telemetry adapter,
resource ceiling, rollback, and test plan are documented. Otherwise it remains
planned rather than active scope.
