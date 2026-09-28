# Documentation index

This directory is the documentation entry point for the active honeypot
project. It separates deployed facts, accepted design, experimental evidence,
and historical material inherited from the previous team.

## Reading order

1. [Current architecture](CURRENT-ARCHITECTURE.md) — deployed components and
   intentional temporary states.
2. [Implementation log](IMPLEMENTATION-LOG.md) — append-only record of repository
   changes, host application, active state, and deferred verification.
3. [Service catalog](SERVICE-CATALOG.md) — every exposed or supporting service,
   its owner, telemetry, and lifecycle status.
4. [Data ownership](DATA-OWNERSHIP.md) — which system owns each stage of data.
5. [Roadmap](ROADMAP.md) — current work ordered by dependency.
6. [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md) — accepted current scope, deferred product additions, and completion evidence.
7. [Security and malware policy](SECURITY-AND-MALWARE-POLICY.md) — containment,
   artifact handling, and threat-intelligence boundaries.
8. [Architecture decisions](adr/) — durable decisions and their rationale.
   [ADR-0007](adr/ADR-0007-retire-dashboard-session-termination.md) records
   the retirement of Dashboard session termination and its Pi control path.
   [ADR-0008](adr/ADR-0008-dashboard-backup-daily-schedule.md) defines the
   Dashboard-controlled daily backup schedule and Pi execution boundary.
   [ADR-0009](adr/ADR-0009-installer-operator-managed-credentials.md) defines
   what the installer prepares and what the operator provisions before activation.
   [ADR-0010](adr/ADR-0010-track-active-decoy-compose.md) records the tracked
   active decoy Compose source and the separate Pi cutover boundary.
   [ADR-0011](adr/ADR-0011-installer-private-env-skeletons.md) permits blank
   Pi env skeletons while preserving operator-managed credentials.
9. [Honeypot Portal & Customer Installer Blueprint](HONEYPOT-PORTAL-INSTALLER-GUIDE.md) — proposed appliance design and delivery gates; the installation manual is the next workstream and must follow current-state documents where this blueprint describes retired controls.
10. [Installation readiness audit](INSTALLATION-READINESS-2026-09-28.md) — verified Pi/repository environment boundaries, clean-OS installation path, and blockers before writing runnable instructions.
11. [Validation evidence](validation/README.md) — bounded staging checks and inventory snapshots.

The first [Ansible Pi preparation slice](../deploy/ansible/README.md) has
[partial ARM64 VM validation](validation/2026-09-28-azure-arm64-installer-first-run.md)
through the blank-configuration pause and same-release retry; activation and
the full installer remain unqualified. Separate Cowrie source and Zeek staging
were also tested on that VM; see the
[dependency evidence](validation/2026-09-28-azure-arm64-cowrie-zeek-staging.md).
Its [VM test target](INSTALLER-VM-TEST-TARGET.md)
and the [Thai](INSTALLATION-MANUAL-WORD-TH.md) and
[English](INSTALLATION-MANUAL-WORD.md) manual drafts remain incomplete.

The event contract and retrieval steps for fake ERP login attempts are in
[Web-corp login telemetry](design/web-login-telemetry.md), the
[web-corp runbook](../integrations/web-corp/README.md), and its
[data-access guide](../integrations/web-corp/DATA-ACCESS.md).
The optional Web-corp client source-port capture and trusted-proxy boundary are
recorded in [ADR-0006](adr/ADR-0006-web-client-source-port.md).
The status boundary between the active HTTP decoy work and candidate future
work is summarized in [HTTP decoy scope](design/http-decoy-scope.md).
The not-yet-deployed public-IP HTTPS/VPS/WireGuard target procedure is in the
[web-corp public-VPS HTTPS runbook](../integrations/web-corp/PUBLIC-VPS-HTTPS.md).

The tracked decoy source runbooks are [FTP](../integrations/ftp/README.md) and
[SMTP](../integrations/smtp/README.md). Both services are stopped/future work;
their intended behavior and adapter gaps are recorded in the
[service catalog](SERVICE-CATALOG.md).

## Document status labels

| Label | Meaning |
| --- | --- |
| **Current** | Verified deployed state or an operating policy. |
| **Target** | Accepted direction that is not yet fully deployed. |
| **Experiment** | POC or test evidence; not approved for production by itself. |
| **Legacy** | Inherited implementation that is not the target architecture. |
| **Archive** | Historical evidence; never use as a current runbook. |

## Rules

- Each concern has one canonical document in this directory.
- `CURRENT-ARCHITECTURE.md` is a snapshot, not a chronological log.
- For every implementation, append a dated entry to
  `IMPLEMENTATION-LOG.md` in the same change. Record repository edits and
  deployed state separately; label changes that are prepared but not active.
- Keep the log factual and append-only. Correct prior entries with a dated
  addendum instead of silently rewriting audit history.
- Record decisions in an ADR before a cross-component change is implemented.
- Put reproducible test results in `validation/evidence/`; promote only their
  conclusion to a design or ADR.
- Do not put secrets, real API keys, raw attacker credentials, raw payloads, or
  private endpoint details in documentation.
- Do not delete inherited documents while consolidating them. Classify and link
  them from [archive/README.md](archive/README.md) first.

## Existing documents awaiting consolidation

- `../adaptive-honeypot/` is the adaptive-shell POC and its test evidence.
- `honeypot-analysis/` is the active post-session/cloud-analysis workstream.
- `old-dashboard-2025/`, `maintenance/`, and `docs/logs/` contain inherited
  history and snapshots, not current operational instructions.
- The existing Pi still runs its external Compose file. The versioned source
  for the active PostgreSQL, Deception Core, and Web-corp HTTP stack is now
  [deploy/decoy-honeypot](../deploy/decoy-honeypot/README.md); host cutover is
  deferred. [ADR-0005](adr/ADR-0005-corporate-web-decoy-source.md) records the
  earlier Web-corp source move, and [ADR-0010](adr/ADR-0010-track-active-decoy-compose.md)
  records the current source boundary.
