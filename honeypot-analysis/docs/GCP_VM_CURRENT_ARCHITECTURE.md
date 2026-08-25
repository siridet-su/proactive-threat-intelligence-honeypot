# Current GCP VM architecture and rebuild boundary

This document is the repository-safe description of the GCP backend. The
canonical active backend is `capstone`: public management address
`34.142.229.209`, Tailscale application address `100.85.50.74`, and production
ingest endpoint `http://100.85.50.74:8080/events`. Exact firewall source
ranges, service-account details, secret paths, and database receipts remain in
the owner-only migration inventory outside Git.

## Evidence and decision

The current target was verified read-only on 2026-08-10 against the clean
checkout on branch `professor-approved-poc-evaluation`. The live hostname,
Tailscale address, active link, and `DEPLOYED_COMMIT` all identify revision
`c3bd2456e6e4693f669c9e48385a62242209afbc`. The deployment decision is:

`CAPSTONE_IS_ACTIVE_PRODUCTION`

The former VM at Tailscale IPv4 `100.122.213.37` is preserved solely as a
rollback/reference host. It must not be selected by normal deployment,
management, validation, monitoring, database, or SSH workflows. Historical
receipts retain its identity as evidence and are not rewritten.

The exact resource inventory, database backups, integrity receipts, and
isolated restore results remain in owner-only migration directories. Those
records do not belong in the source release and must not contain credential
values, tokens, private keys, or secret environment contents.

## Data flow and authority

```text
Internet client
  -> approved GCP firewall rule (TCP/2222)
  -> HAProxy TCP frontend with PROXY protocol
  -> Tailscale backend link
  -> Raspberry Pi Cowrie and privacy-boundary forwarder
  -> authenticated ingest API
  -> current canonical storage epoch and session reconstruction
  -> session worker and canonical evidence
  -> classification / session_assessment.v4
  -> advisory Transformer prediction and response_guidance.v3
  -> dashboard, monitor, JSON, Markdown, PDF, and STIX artifacts
```

Cowrie evidence and the canonical evidence snapshot are authoritative.  The
Transformer, enrichment feeds, correlations, and optional prose are
non-authoritative context.  `response_guidance.v3` is advisory only,
requires manual approval, and cannot execute an action, create an alert, or
create a webhook. A MongoDB epoch, if activated by a separate reviewed
cutover, contains only post-cutoff canonical data and synchronously mirrors
each ACK-eligible event to a new SQLite rollback file. The pre-cutoff SQLite
database remains a distinct read-only historical archive and is not rewritten
or silently federated into current APIs.

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

- the current canonical database, post-cutover SQLite rollback mirror, queues,
  leases, reports, spool, feed caches, and feed provenance;
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

## Capacity boundary

A backup and isolated restore rehearsal remain mandatory before a VM change.
Every future deployment must recalculate capacity from the live database and
retain the active release, rollback release, verified backup, WAL/temporary
margin, and operating safety margin. Current free space is a live operational
fact and is not inferred from the completed migration or from this document.

## Replacement requirements

The replacement must be built from a clean `git archive` and a separately
verified model-bundle archive.  It must use the concrete form of
`deployment/gcp/rebuild_manifest.example.json`, record all hashes and private
resource bindings in an owner-only receipt, and pass the runbook and verifier
before any public cutover.  Secrets are provisioned separately through the
approved secret mechanism and are never included in a release, manifest
example, inventory, or backup bundle.
