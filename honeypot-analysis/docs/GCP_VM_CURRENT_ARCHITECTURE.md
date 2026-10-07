# Current GCP VM architecture and rebuild boundary

This document is the repository-safe description of the GCP backend. The
canonical active backend hostname is `capstone`; public/private addresses,
overlay identities, exact endpoint, firewall source ranges, service-account
details, secret paths, and database receipts remain in the owner-only inventory
outside Git.

## Evidence and decision

The current VM was verified read-only on 2026-10-08. Its active release is
`dcaa63b606da637a41b78e6c123a2df62d63de56`; runtime-code candidate
`d391ccb503520c6a4d9259f4e9e8626b818004fb` on repository `main` is not
installed. The VM's
ingest service is bound to a private overlay interface. Exact route identities
remain in the owner-only inventory. The deployment decision is:

`CAPSTONE_IS_ACTIVE_PRODUCTION`

The owner reported that the former VM was shut down to avoid cost. Its power
state was not independently checked through the GCP control plane, and it is
not a verified rollback/reference host. Do not select it for deployment,
management, validation, monitoring, database, or SSH workflows. Historical
receipts remain evidence and are not rewritten.

The exact resource inventory, database backups, integrity receipts, and
isolated restore results remain in owner-only migration directories. Those
records do not belong in the source release and must not contain credential
values, tokens, private keys, or secret environment contents.

## Data flow and authority

```text
Internet client
  -> approved GCP firewall rule (TCP/2222)
  -> HAProxy TCP frontend with PROXY protocol
  -> approved private overlay backend link
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
create a webhook. The active MongoDB epoch contains only post-cutoff canonical
data and synchronously mirrors each ACK-eligible event to its epoch-bound
SQLite rollback file. The pre-cutoff SQLite database remains a distinct
read-only historical archive and is not rewritten or silently federated into
current APIs.

## Immutable and mutable boundaries

The active application is an extracted, content-addressed release under
`/opt/honeypot-releases/<REVISION>` and is selected through `/opt/honeypot`.
Its `DEPLOYED_COMMIT`, deployment manifest, release-tree hash, policy hashes,
dependency identity, managed-unit policy, and package hash are verified as a
single release identity.  The retained recovery release is independently
manifest-bound.

The active VM has a separately managed Model1 artifact bundle; its artifact
files were mode `0600` and owned by the service account during the 2026-10-08
check. Next-Distinct and Model2 use independent shadow runtimes and are
non-authoritative. Their artifact/runtime identities must be checked against
their own receipts; a model directory's presence is not proof of successful
inference. Full model-bundle smoke verification was not performed during the
2026-10-08 host check.

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

The Next-Distinct shadow service and its passive feeder are explicitly
installed, enabled, and required active in managed-unit policy revision
`2026-10-08`. They remain non-authoritative. Model2 v7 uses separate
`model2-v7-*` units and protected runtime files; those units are not inventoried
by the current `honeypot-` prefix validator and need a separate reviewed
receipt before being treated as manifest-bound deployment content.

On 2026-10-08 the eight core daemons, Next-Distinct shadow/feeder, and Model2
v7 services were active with zero failed units. The feed and session-count
timers were active. The production Dashboard service and service-watchdog timer
remain stopped/disabled. The staging Dashboard service was subsequently enabled
for loopback-only workstation access and is active at `127.0.0.1:3001`; access
uses an SSH local forward. Its staging environment allows a non-Secure cookie
only for that HTTP-over-loopback mode. No public listener/firewall change was
made. The watchdog timer remains disabled because its protected target list
includes the Dashboard services; its host program and configuration were not
changed. The revised managed-unit policy passed against the `gcp_backend`
inventory, but does not validate the independent Model2 v7 units. The AI
advisory worker was inactive.

The ingest endpoint is bound to its authorized private overlay interface and
returned HTTP 200 on that binding; Dashboard API and monitor health returned
HTTP 200 on their local bindings. The forwarded staging login page returned
HTTP 200. This confirms reachability/authentication smoke only, not complete
session analysis: stored Response Guidance referencing policy 3.8.0 is
rejected, and the corresponding PDF request returns 503. Exact firewall rule,
target tag, overlay peer, and backend port remain in the owner-only inventory.
This check did not enumerate all public listeners or verify the GCP firewall
control plane. The native-local Dashboard target remains unqualified.

## Capacity boundary

A backup and isolated restore rehearsal remain mandatory before a VM change.
The 2026-10-08 snapshot/restore covered the SQLite rollback mirror only; it did
not back up canonical MongoDB. A provider-supported MongoDB snapshot and
restore test remains required for a data-changing cutover. Every future
deployment must recalculate capacity from live data and retain the active
release, verified rollback release, backups, WAL/temporary margin, and operating
safety margin. Current free space is a live operational fact and is not
inferred from this document.

## Replacement requirements

The replacement must be built from a clean `git archive` and a separately
verified model-bundle archive.  It must use the concrete form of
`deployment/gcp/rebuild_manifest.example.json`, record all hashes and private
resource bindings in an owner-only receipt, and pass the runbook and verifier
before any public cutover.  Secrets are provisioned separately through the
approved secret mechanism and are never included in a release, manifest
example, inventory, or backup bundle.
