# Deployment and recovery (canonical summary)

Production releases are built from a clean `git archive` of one commit. A
release manifest binds the Git revision, release-tree hash, code/configuration
hashes, dependency identity, policy hashes, and model references. Mutable
databases, queues, reports, secrets, feed caches, virtual environments, and
the separately managed frozen model bundle are outside the source archive.

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
`/opt/honeypot`. Reconcile only reviewed obsolete units, run systemd validation
and the managed-unit profile, restart only affected services, and verify
health, hashes, queues, inference, reports, APIs/UI, PDF/STIX, and
advisory-only authority. The production gate includes one synthetic-credential
session through the real Pi-to-GCP route with retained evidence identifiers.

## Frozen external model bundle

Transformer and SecureBERT binaries are private runtime assets, never Git
content or a mutable release overlay. A separately managed content-addressed
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
to shared logs. Unrelated failed units are outside scope. Only `sqlite:///`
database URLs are supported; other backends fail closed.

## Current repository-recorded production target

The canonical active VM is `capstone`, with public management address
`34.142.229.209`, Tailscale application address `100.85.50.74`, and active
release `c3bd2456e6e4693f669c9e48385a62242209afbc`. The production ingest
endpoint is `http://100.85.50.74:8080/events`. See
[CURRENT_PRODUCTION_STATE.md](CURRENT_PRODUCTION_STATE.md) for the verified
SSH identity and verification boundary.

The former VM at `100.122.213.37` is preserved only for rollback/reference.
Normal deployment, management, validation, monitoring, database, backup, and
service workflows must not target it.

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
   bundle, policy hashes, capacity, and current marker.
2. Create a fresh non-overwriting SQLite backup; run integrity/quick checks and
   an isolated restore before activation.
3. Install the immutable release, update the pointer/marker only after hash
   verification, and restart only affected services.
4. Run health, queue/lease, privacy, v4/v3, artifact, API/monitor, E2E, and
   bounded observation gates.
5. On any mandatory failure, invoke the guard to restore the retained release,
   verify services and SQLite, and stop.

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

This summary is derived from committed receipts and does not SSH to either
host. Current live deployment state, capacity, and backup existence are
`NOT_DETERMINABLE_FROM_CURRENT_REPOSITORY` unless a newer signed/hashed receipt
is committed.
