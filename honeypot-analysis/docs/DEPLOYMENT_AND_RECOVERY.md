# Deployment and recovery (canonical summary)

Production releases are built from a clean `git archive` of one commit. A
release manifest binds the Git revision, release-tree hash, code/configuration
hashes, dependency identity, policy hashes, classifier-environment identity,
and model references. Mutable
databases, queues, reports, secrets, feed caches, virtual environments, and
the separately managed frozen model bundle are outside the source archive.

> **Current-runtime note (2026-08-31).** The active capstone profile is
> MongoDB-backed (`honeypot_canonical_v1`) on the verified Atlas Flex
> `Honeypot-DB` cluster (5-GB limit, AWS `AP_EAST_1`); the epoch-bound SQLite
> file is a recovery mirror only. The older SQLite-default and custom
> cold-storage procedures below are retained as historical/recovery guidance
> and must not be read as evidence that Pi cold storage or an automatic
> retention timer is active.

## Manifest-bound release boundary

Require a clean worktree whose `HEAD` is the full requested revision, run
focused checks and `pytest tests -q`, and build the source package with
`git archive`. Never deploy a working-tree copy, retain a mutable source
overlay, or edit a release after manifest creation. The archive excludes
bytecode, caches, temporary files, databases/WAL/SHM, logs, spools, generated
reports, host artifacts, and mutable runtime state.

Effective CISA, Sigma, and MITRE feed caches are separately managed mutable,
non-authoritative inputs and are verified through
`runtime_feed_provenance.v1` after refresh, not included in the immutable
release identity. The one exception is the independently hash-bound historical
MITRE snapshot required by the frozen classifier environment; it is a model
artifact, not the effective production feed.

Extract each archive into a new `/opt/honeypot-releases/<revision>` directory
and link only the preserved virtual environment before installing verified
model-bundle links. `production.tools.release_manifest create` must receive
every effective immutable policy/configuration, every individual model
artifact, dependency identity, frozen-bundle manifest/archive, and the exact
managed-unit allowlist. Manifest v7 records its immutable-identity exclusion
policy; historical v2-v6 manifests retain their original semantics.

Run `production.tools.release_manifest verify`, then independently verify the
current runtime-feed provenance and cache hashes. Only after both pass may the
deployment write and re-read `DEPLOYED_COMMIT` and atomically repoint
`/opt/honeypot`. The copied `DEPLOYMENT_MANIFEST.json` must retain the v7
`classifier_environment` receipt binding. v3 classifier receipts bind the
immutable classifier content identity rather than a future Git commit; the
release manifest binds the final commit and release tree. Reconcile only
reviewed obsolete units, run systemd validation
and the managed-unit profile, restart only affected services, and verify
health, hashes, queues, inference, reports, APIs/UI, PDF/STIX, and
advisory-only authority. The production gate includes one synthetic-credential
session through the real Pi-to-GCP route with retained evidence identifiers.

## Frozen external model bundle

The Transformer and retained SecureBERT binaries are private runtime assets,
never Git content or a mutable release overlay. FINAL_S1 is the sole learned
command model selected by the final architecture and is advisory-only; the
retained SecureBERT bundle is historical/replay/research compatibility and is
not loaded by the aligned final runtime. A separately managed content-addressed
bundle under `/opt/honeypot-model-bundles/` contains only the receipt-pinned
Transformer checkpoint/specification/vocabulary/calibration files and the
eight classifier files listed by its reviewed environment receipt.

`FROZEN_MODEL_BUNDLE_MANIFEST.json` binds exact byte hashes and sizes,
Transformer policy/final-result identity, vocabulary/calibration identity, and
classifier environment identity. The bundle is owned by the `honeypot` service
account with directory mode `0700` and files mode `0600`; its mode-`0600`
archive under `/opt/honeypot-model-packages/` is a recovery artifact. Bundle
creation first verifies candidate sources against the reviewed policies and
receipts, copies exact bytes, and records the old release only as provenance.

Use `production.tools.frozen_model_bundle` to `create`, `verify` with
`--runtime-check --smoke-test`, `install-release-links`,
`verify-release-links`, and `archive`. The link installer fails closed if any
target/model link already exists. It adds the reviewed Transformer paths and
classifier-model link without changing policy-relative paths. Release-manifest
creation and verification both require every policy-relative Transformer link
and the classifier-model link to resolve to the receipt-bound bundle; a release
with a missing or substituted model path is not prediction-ready.

Keep both bundle and archive while any live or rollback release refers to
them. On a replacement host, verify the archive SHA-256 from the dependent
release manifest before extraction; restore exact ownership/modes, then rerun
bundle verification with runtime and smoke checks before staging a release.
Do not remove the retained source release until a separate retention review
proves that no live or rollback release depends on it.

## Services and operational safety

Reviewed generic units are under `deployment/systemd/`; application daemons
cover ingest, session/analysis/enrichment/threat-hunt work, webhook delivery,
dashboard/monitor, and the sensor forwarder, with timers for feed refresh and
session-count monitoring. Inspect state without changing it:

```bash
systemctl --no-pager --type=service 'honeypot-*'
systemctl --no-pager --type=timer 'honeypot-*'
journalctl --no-pager -u honeypot-session-worker.service -n 100
```

Use the authenticated `/health` endpoint and its `/health/live` and
`/health/ready` probes. Review artifact checks,
leases, redaction, forecast availability, and report failures without printing
secrets. Before a change, record revision, units, configuration/model/policy
hashes, ports, health, queues, and capacity. A SQLite copy is rollback evidence
only after `production.tools.sqlite_backup_restore` has created a
non-overwriting mode-`0600` backup/manifest, verified hashes and integrity/table
counts, and restored it to a new isolated path.

Never broaden networking, firewall, SSH, Tailscale, or Cowrie exposure as part
of an application rollback. Never enter real credentials into Cowrie or print
HMAC keys, bearer tokens, identity-bearing private paths, or unredacted commands
to shared logs. Unrelated failed units are outside scope. The historical local
SQLite profile remains supported for recovery/demo tooling; the current
production profile uses the reviewed MongoDB epoch contract, and an unbound or
unverified backend must fail closed.

## Current repository-recorded production target

The active VM hostname is `capstone`. Read-only verification on 2026-10-08
found release `dcaa63b606da637a41b78e6c123a2df62d63de56`; runtime-code
candidate `d391ccb503520c6a4d9259f4e9e8626b818004fb` on `main` is not
installed. The ingest
service uses a private overlay route. Exact public/private addresses, overlay
identities, SSH principals, and firewall details belong in the owner-only
inventory, not this document.

The owner reported that the former VM was shut down to avoid cost; this was not
independently checked through the GCP control plane. It is not a verified
rollback target. Normal deployment and validation must use the active `capstone`
VM and must not assume the former VM is available for recovery.

The 2026-10-08 check found the active release manifest does not match the
preserved Model2 runtime-configuration hash, and the active and alternate
release directories did not provide a verified manifest-bound rollback target.
In a later bounded host change, the two GCP Dashboard v2 services and the
service-watchdog timer were stopped and disabled; their unit definitions were
archived under the root-only host backup area. The watchdog program and its
protected configuration were not changed. Its target list includes the
Dashboard services, so do not re-enable the timer until its targets are
reviewed for the local-dashboard operating mode. Managed-unit policy revision
`2026-10-08` now includes Next-Distinct shadow/feeder in the required-enabled
set and passed the `gcp_backend` inventory check. That validator does not cover
the separate `model2-v7-*` units. No release pointer, core service, firewall,
database, or protected runtime configuration was changed. See
[CURRENT_PRODUCTION_STATE.md](CURRENT_PRODUCTION_STATE.md) for the current
verification boundary.

Operational addendum, 2026-10-08: the GCP staging Dashboard was subsequently
enabled for limited operator inspection and is active only on VM loopback
`127.0.0.1:3001`; the workstation reaches it through an SSH local forward.
Production Dashboard and the watchdog timer remain disabled. The forwarded
login route passed, but the inspected stored report's policy-3.8 Response
Guidance was rejected and its PDF returned 503. This does not change the
blocked backend release decision or qualify the full user workflow. See the
[staging runbook](../deployment/dashboard-v2-staging/README.md) and
[ADR-0017](../../docs/adr/ADR-0017-local-dashboard-gcp-backend.md).

The machine-readable receipt
`evaluation/next_tactic_final_production_activation_20260802.json` records the
earlier VM's activation and rollback rehearsal. Its revisions, addresses,
package/manifest/tree hashes, database backup, E2E results, and observation
samples remain immutable historical evidence; they are not the current target
selector. Current release manifests, backup receipts, and restore evidence are
owner-only operational records and must be verified live before the next
change.

## Safe procedure

1. Verify a clean commit, package hash, manifest hash, release-tree hash, model
   artifacts, policy hashes, capacity, and current marker.
2. Back up the selected canonical database using its provider-supported method
   and verify an isolated restore. For the active MongoDB epoch, also create a
   separate non-overwriting backup/restore of the exact epoch-bound SQLite
   rollback mirror; the mirror is not a substitute for a MongoDB backup. For a
   SQLite-only profile, use `production.tools.sqlite_backup_restore`.
3. Install the immutable release, update the pointer/marker only after hash
   verification, and restart only affected services.
4. Run health, queue/lease, privacy, v4/v3, artifact, API/monitor, E2E, and
   bounded observation gates.
5. On any mandatory failure, invoke the guard to restore the independently
   verified release and its reviewed units, verify the selected database and
   services, and stop. If no verified rollback release is available, do not
   cut over or restart the active release.

The earlier public-connectivity correction and its before/after hashes remain
historically recorded in
`evaluation/cowrie_public_connectivity_root_cause_20260802.json`. Do not use
that old-VM receipt as a current firewall or backend inventory. Do not patch an
active release in place and do not reuse a failed package.

## Rollback boundaries

Release rollback is a tested pointer operation: stop only affected application
services, repoint `/opt/honeypot` to the manifest-bound recovery release,
restore that release's reviewed units/configuration as one unit, start the same
services, and verify health, hashes, SQLite, queues, predictions, and reports.
Rehearse pointer/unit restoration with an isolated link and restored backup;
do not interrupt a healthy release merely to demonstrate rollback. This does
not mutate the model bundle, database, feeds, model bytes, or model identities.

Predictor rollback to the VOMM is separate and always explicit. Take a fresh
backup; verify its artifact, manifest, policy, and rollback archive; install
the reviewed code/policy/configuration atomically; then generate a controlled
prediction/report confirming VOMM identity and unchanged historical
Transformer snapshots. Never add a cascade, heuristic route, silent fallback,
or automatic VOMM selection during recovery.

## Verification boundary

The repository snapshot was reconciled against a read-only SSH check on
2026-10-08. The private inventory remains authoritative for addresses,
credentials, and provider receipts. The mirror snapshot and isolated restore
passed; a provider-supported backup/restore of canonical MongoDB was not
performed, and no new release or rollback release was qualified. Live capacity
and provider control-plane state remain time-sensitive and must be checked
again before a future cutover.
