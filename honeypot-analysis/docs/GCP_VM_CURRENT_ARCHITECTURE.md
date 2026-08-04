# Current GCP VM architecture and rebuild boundary

This document is the repository-safe description of the GCP backend.  Exact
resource identifiers, addresses, firewall source ranges, service-account
details, secret paths, and database receipts are kept in the owner-only
migration inventory outside Git.  A replacement host must be populated from a
new private inventory; placeholders in this document are intentional.

## Evidence and decision

The audit was performed on 2026-08-04 against the clean checkout on branch
`professor-approved-poc-evaluation` at commit
`7ceb2171898b4d2d9a61d03144d44915f850722f`.

The active release is an earlier immutable release whose release-relevant
files, effective policies, model references, and managed-unit policy match the
current checkout.  The later checkout commits contain documentation, tests,
evaluation material, CI, and ignore-rule changes, but no packaged runtime
behavior.  The deployment decision is therefore:

`RUNTIME_EQUIVALENT_TO_CURRENT_HEAD`

No release was rebuilt or activated merely to make the Git revision strings
equal.  The active and recovery releases remain the rollback boundary.

The comparison baseline was recorded before this rebuild record was committed.
The repository-safe record is now carried by commits
`d1ea27c8c43939878ac3095221d5c1c8ffaf4b57`,
`c4e4dfcbb2047d605e1c778f0615b68785cf0da8`, and
`3d81c14045a164046cfbb11525b84c0991add257`.  Those commits add only
documentation, a redacted inventory collector, a manifest verifier, and
tests; none is imported by the active application services and no application
redeploy is required for them.

The exact live comparison, resource inventory, database backup, integrity
receipt, and isolated restore result are in the private owner-only migration
directory recorded at execution time.  Nothing in that directory contains
credential values, tokens, private keys, or secret environment contents.

## Data flow and authority

```text
Internet client
  -> approved GCP firewall rule (TCP/2222)
  -> HAProxy TCP frontend with PROXY protocol
  -> Tailscale backend link
  -> Raspberry Pi Cowrie and privacy-boundary forwarder
  -> authenticated ingest API
  -> durable SQLite events and session reconstruction
  -> session worker and canonical evidence
  -> classification / session_assessment.v4
  -> advisory Transformer prediction and response_guidance.v3
  -> dashboard, monitor, JSON, Markdown, PDF, and STIX artifacts
```

Cowrie evidence and the canonical evidence snapshot are authoritative.  The
Transformer, enrichment feeds, correlations, and optional prose are
non-authoritative context.  `response_guidance.v3` is advisory only,
requires manual approval, and cannot execute an action, create an alert, or
create a webhook.  SQLite is the only active runtime backend; historical
records are read through compatibility adapters and are not rewritten.

## Immutable and mutable boundaries

The active application is an extracted, content-addressed release under
`/opt/honeypot-releases/<REVISION>` and is selected through `/opt/honeypot`.
Its `DEPLOYED_COMMIT`, deployment manifest, release-tree hash, policy hashes,
dependency identity, managed-unit policy, and package hash are verified as a
single release identity.  The retained recovery release is independently
manifest-bound.

The frozen Transformer/SecureBERT assets are a separate owner-only,
content-addressed model bundle under `/opt/honeypot-model-bundles/`.  The
bundle manifest binds the checkpoint, specification, vocabulary, calibration,
preprocessing, and classifier artifacts.  A replacement VM must restore this
bundle from its verified archive; it must not follow a model link into an old
application release.

The following are mutable runtime state and are not part of the immutable
release-tree identity:

- `/var/lib/honeypot/production_pilot.db`, queues, leases, reports, spool,
  feed caches, and feed provenance;
- `/var/backups/honeypot` and isolated restore material;
- journals, logs, and temporary files;
- service-scoped secret files under `/etc/honeypot` or systemd credentials;
- the Python environment, which must be rebuilt or separately verified on a
  replacement host rather than silently sharing an older release directory.

Runtime feed caches remain non-authoritative and are checked through
`runtime_feed_provenance.v1` (version, checksum, retrieval time, and importer
revision) outside the immutable manifest.  They cannot create findings,
guidance, alerts, or response actions.

## Services and operational state

The GCP profile manages these application services:

- `honeypot-ingest-api.service`
- `honeypot-session-worker.service`
- `honeypot-enrichment-worker.service`
- `honeypot-analysis-worker.service`
- `honeypot-dashboard-api.service`
- `honeypot-monitor-web.service`
- `honeypot-threat-hunt-worker.service`
- `honeypot-webhook-dispatcher.service`

The managed timers are feed refresh and session-count monitoring.  Calibration
and prediction-retention units are not part of the current runtime.  All
managed units are expected to be enabled, active where applicable, hardened,
and configured with `UMask=0077`; a managed-unit policy validation is a
replacement-host gate.

The ingest endpoint is bound to its authorized backend interface.  Dashboard
and monitor endpoints remain local or management-network endpoints.  HAProxy
is the only GCP-to-Pi TCP relay; no additional public listener is introduced
by a rebuild.  The replacement inventory must record the exact firewall rule,
target tag, route, Tailscale peer, and backend port privately.

## Capacity and current risk

The migration backup and restore rehearsal are mandatory before a VM change.
The audit observed a near-full root filesystem after preserving the backup,
with large retained backups, old release trees, journals, and an older shared
virtual-environment target.  This is an operational blocker for creating a
second large release on the current disk, not a reason to delete production
data or rollback material.  A replacement must pass its capacity calculation
before package extraction and must retain both the active and recovery release
until post-cutover acceptance completes.

## Replacement requirements

The replacement must be built from a clean `git archive` and a separately
verified model-bundle archive.  It must use the concrete form of
`deployment/gcp/rebuild_manifest.example.json`, record all hashes and private
resource bindings in an owner-only receipt, and pass the runbook and verifier
before any public cutover.  Secrets are provisioned separately through the
approved secret mechanism and are never included in a release, manifest
example, inventory, or backup bundle.
