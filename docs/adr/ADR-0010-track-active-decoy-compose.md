# ADR-0010: Track the active decoy Compose source in the project repository

- Status: Accepted
- Date: 2026-09-28
- Supersedes: the temporary external-Compose placement in [ADR-0005](ADR-0005-corporate-web-decoy-source.md)

## Context

ADR-0005 moved Web-corp application source into this repository but left the
Compose file and Deception Core build source in an unversioned sibling folder.
The fresh-Pi installer therefore could not build the active decoy stack from
one reviewed checkout. The old Compose folder also contains stopped services,
private configuration, runtime data, and historical backups.

## Decision

- Track a Compose definition for the currently active PostgreSQL, Deception
  Core, and Web-corp HTTP services under `deploy/decoy-honeypot/`.
- Track only the Deception Core build inputs required by that definition under
  `integrations/deception-core/`. Keep private env files, certificates, runtime
  volumes, attacker records, and backups outside Git.
- Keep the Compose project name stable. Omit stopped Odoo, FTP, SMTP, and direct
  Pi HTTPS from the fresh-install stack; restoring any of them is a separate
  decision and deployment.
- Treat source consolidation separately from host cutover. The current Pi's
  running Compose file, containers, and volumes remain unchanged until a
  reviewed migration or clean-host acceptance.

## Consequences

The installer can consume a reviewable Compose source and local build contexts,
but image pinning, operator-input validation, host-path ownership, clean ARM64
VM testing, and activation are still required. The old Pi keeps its existing
external Compose project until a separate cutover is completed.
