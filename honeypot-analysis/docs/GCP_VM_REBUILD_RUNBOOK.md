# GCP VM replacement runbook

This runbook describes a reversible replacement of the GCP backend.  It is a
procedure, not authorization to destroy, resize, stop, or cut over a VM.  The
exact project, zone, instance, addresses, firewall identifiers, private
overlay peer, secret locations, and current backup paths must come from the private
owner-only inventory for the change window.

At the time of this repository record, the active production VM is `capstone`
as identified in [CURRENT_PRODUCTION_STATE.md](CURRENT_PRODUCTION_STATE.md).
In this procedure, "current VM" means the active target at execution time.
Do not assume a prior VM is available as rollback: the owner reported the
former VM shut down on 2026-10-08, and that state was not independently checked
through the GCP control plane. A rollback target must be separately verified
and recorded in the private inventory.

## Invariants and stop conditions

- Cowrie evidence remains authoritative; prediction and enrichment remain
  contextual only.
- `session_assessment.v4` and `response_guidance.v3` remain the canonical
  report contracts.  Guidance is manual-only and never executable.
- The selected canonical epoch must match its reviewed receipt. Pre-MongoDB
  SQLite history and historical v1/v2/v3 records remain readable and unchanged;
  a MongoDB epoch requires its separate exact SQLite rollback mirror.
- Do not retrain, recalibrate, replace, or silently switch the Transformer.
- Do not add public ports, broaden the TCP/2222 firewall rule, or expose
  secrets.  Do not modify the Raspberry Pi as part of a VM rebuild.
- Leave the active release and services untouched if any hash, policy, privacy,
  route, database backup/restore, health, or rollback gate is not determinable.

## 1. Freeze and inventory

1. Confirm the requested source commit is a full 40-hex revision and that the
   source worktree is clean.
2. Run focused deployment, manifest, policy, schema, privacy, and SQLite
   backup tests, followed by the full feasible local suite.
3. Capture the current VM, active release, recovery release, model artifacts,
   policies, services, timers, network roles, capacity, and database counts in
   a new private inventory directory (`0700` directory, `0600` files).
4. Back up the selected canonical database with its approved provider-native
   method and qualify an isolated restore. For an active MongoDB epoch, also
   create a non-overwriting SQLite backup of the exact receipt-bound rollback
   mirror using `production.tools.sqlite_backup_restore`; its receipt must
   record SHA-256, schema version, quick/integrity checks, table counts, and
   isolated restore result. The SQLite mirror is not a substitute for a
   MongoDB backup. For a SQLite-only runtime, back up that canonical database
   with the same tool. Keep the prior verified rollback backup as well.

The backup must be complete before any active host or release is changed. If
free space cannot hold the release archive, backup, rollback release, WAL
growth, isolated restore, extraction temporary space, and safety margin, stop
and obtain an approved capacity change.

## 2. Create the replacement instance

Using the privately recorded project, region, zone, machine type, disk,
network, subnet, tags, scheduling, Shielded VM, and service-account settings:

1. Create a new instance with a disk large enough for the capacity gate.  Keep
   deletion protection, automatic restart, maintenance behavior, and Shielded
   settings equal to the approved inventory.
2. Apply only the reviewed firewall rules and routes.  The public Cowrie relay
   remains the existing TCP/2222 path; dashboard, monitor, and ingest scopes
   remain unchanged.
3. Record the new resource identity and disk/filesystem expansion in the
   private inventory.  Do not place identifiers or addresses in Git.

If provisioning fails, delete only the incomplete replacement after recording
the failure; the current VM and Pi remain untouched.

## 3. Install the host boundary

Install the approved OS family and package prerequisites, then configure:

```text
/opt/honeypot                 immutable active pointer
/opt/honeypot-releases        extracted immutable releases
/opt/honeypot-packages        owner-only release archives
/opt/honeypot-model-bundles   owner-only frozen model bundles
/var/lib/honeypot             selected database or rollback mirror, queues, leases, reports, feeds
/var/backups/honeypot         owner-only backup and rollback receipts
/etc/honeypot                 configuration and service-scoped secrets
```

Create the `honeypot` service account and groups with the exact ownership and
modes from the private inventory. Use a fresh Python environment or a
separately verified immutable dependency bundle; do not symlink it to an old
release directory. Validate Python, SQLite, HAProxy, the approved private
overlay client, and systemd versions before installing application files.

## 4. Install network and secrets separately

Install the approved private-overlay client using its enrollment procedure
without putting an auth key in a command line, unit file, release, or receipt.
Install HAProxy from the reviewed template, bind the frontend/backend roles, require the
PROXY-protocol behavior needed by the Pi route, and run the configuration
validator.  Confirm the backend is `UP` without changing the Pi.

Provision each service-scoped secret through the approved secret manager or
owner-only file path.  Verify owner/group/mode and reject plaintext plus
`*_FILE` duplicates.  Record only purpose, consumer, path, mode, rotation
owner, and restart requirement in the private secret inventory.

## 5. Install and verify immutable content

1. Build a clean archive with `git archive` from the exact source commit.
2. Generate the concrete release manifest and verify the release-tree,
   policy, dependency, managed-unit, and package hashes.
3. Restore the separately managed frozen model-bundle archive and verify its
   manifest, artifact sizes/hashes, model identity, vocabulary, calibration,
   preprocessing, and runtime smoke test.
4. Extract the release into a new revision directory.  Do not edit an
   extracted release.  Install model links only after the bundle verification
   passes and confirm no link resolves into an older release.
5. Run `deployment/gcp/verify_rebuilt_vm.py` against the concrete rebuild
   manifest from the new host.  Preserve the verifier receipt with the private
   inventory.

The active pointer and `DEPLOYED_COMMIT` are written only after every hash has
been independently read back.  Keep the previous active and recovery release
directories intact.

## 6. Restore or verify storage and start services

Read the reviewed storage-epoch receipt first. If the canonical backend is
MongoDB, verify the provider/cluster identity, database/schema receipt, server
version, writable primary, and the approved canonical-database backup/restore.
Restore the separate epoch-bound SQLite rollback mirror only to a new,
non-existing path using the existing backup/restore tooling; verify its mirror
identity, epoch binding, owner-only permissions, schema version, quick-check,
full integrity, counts, and WAL/SHM behavior. Never restore the pre-cutoff
SQLite archive over MongoDB or treat that archive/mirror as a full MongoDB
backup. For a SQLite-only profile, restore the selected migration backup to a
new path and apply the same integrity and permission checks. In both profiles,
verify queue bounds and worker leases before starting services.

Install the managed systemd units and timers, run `daemon-reload`, and validate
the `gcp_backend` managed-unit profile.  Start the eight application services
and approved timers in dependency order.  Confirm zero failed units, bounded
restart counts, `UMask=0077`, writable paths, and expected ports.

## 7. Qualification before cutover

The replacement must pass all of these in isolation:

- three health endpoints and HAProxy backend status;
- authenticated ingest, deduplication, queue/lease recovery, and a bounded
  restart test;
- a synthetic session through the existing Pi-to-GCP route;
- canonical full-session evidence reconstruction and classification
  provenance;
- Transformer smoke inference using the frozen artifact identity;
- v4/v3 report, JSON, Markdown, PDF, and STIX validation;
- credential/privacy marker scans across new spool, database/WAL/SHM,
  reports, artifacts, logs, and backup;
- no prediction/enrichment-only finding, guidance, alert, webhook, or action;
- isolated backup restore and deterministic artifact repeatability;
- a rollback rehearsal using the retained prior release and a pointer-only
  switch (without interrupting the healthy source VM).

Record every result and hash in the private qualification receipt.  A failure
is a stop condition; correct only repository-owned reversible defects in a new
reviewed commit and rebuild from a clean archive.

## 8. Controlled cutover and observation

After written approval and a fresh production backup:

1. Drain or pause only the reviewed application boundary as specified by the
   deployment guard; do not stop the Pi.
2. Activate the replacement pointer atomically and re-read the marker,
   manifest, model bundle, and policy hashes.
3. Run health, queue, privacy, E2E, report/artifact, and API/monitor checks.
4. Observe for at least 15 minutes with bounded load and no failed units,
   duplicate events, unsafe guidance, new prediction alerts, or webhook
   side-effects.

If any mandatory gate fails, invoke the tested guard immediately: restore the
verified recovery pointer and units, re-read its manifest and model hashes,
verify the selected database and health, and stop. If no valid recovery target
is available, do not activate or restart the replacement. Preserve the failed
candidate for diagnosis; do not patch it in place.

## 9. Rollback and decommissioning boundary

Rollback is limited to the tested pointer/unit restoration and the retained
canonical-database backup plus any epoch-bound mirror. It does not rewrite
historical records, model bytes, feed-cache provenance, or policies. Keep the
active release, a verified recovery release, model artifacts, package
archives, and receipts until a separate review proves the replacement stable
and explicitly authorizes decommissioning of any retained host.

## Replacement acceptance checklist

The private receipt must mark each item `PASS` or `NOT_DETERMINABLE`:

1. exact OS, package, Python, SQLite, HAProxy, private-overlay, and systemd versions;
2. disk/free-space and inode capacity gate;
3. directory, release, model, database, log, and secret permissions;
4. exact firewall scope, routes, private-overlay reachability, and HAProxy `UP`;
5. eight active services, approved timers, zero failed units, hardened units;
6. three healthy endpoints and expected listening ports;
7. canonical-database backup/restore; epoch-bound mirror integrity/counts;
   queues, leases, and retry recovery;
8. Transformer checkpoint/policy/model-bundle verification and smoke test;
9. privacy marker, replay deduplication, and redacted-artifact checks;
10. canonical v4/v3 outputs and JSON/Markdown/PDF/STIX validation;
11. zero prediction-created alerts/webhooks and no automatic response;
12. clean restart, 15-minute observation, and tested rollback.
