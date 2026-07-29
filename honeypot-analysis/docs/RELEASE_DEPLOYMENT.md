# Manifest-bound release deployment

Production code is deployed only from a clean `git archive` of one full commit.
Do not copy a working tree, retain a runtime overlay, or edit a release after
manifest creation. Runtime databases, reports, secrets, caches, virtual
environments, and frozen model files are not part of the source archive.

For revision `$REVISION`:

1. Require a clean worktree and verify `git rev-parse HEAD` equals the full
   requested revision.
2. Run focused tests and `pytest tests -q`.
3. Create `git archive --format=tar` and record its SHA-256.
4. On GCP, create an online SQLite backup with
   `production.tools.sqlite_backup_restore`, verify it, and restore it to a new
   rehearsal path.
5. Extract the archive into a new `/opt/honeypot-releases/$REVISION` directory.
   Link the preserved virtual environment only. Build or verify the separately
   managed immutable frozen-model bundle, then use its fail-closed link
   installer before release-manifest creation. Do not link models from another
   release directory; see `docs/FROZEN_MODEL_BUNDLE.md`.
6. Create `DEPLOYMENT_MANIFEST.json` using
   `production.tools.release_manifest create`. Pass every immutable effective
   policy, configuration path, and individual model artifact file. Do **not**
   pass CISA, Sigma, or MITRE runtime cache files as immutable configurations:
   the enabled feed-refresh timer updates them outside a release. Pass the
   configured runtime feed-provenance location with
   `--runtime-feed-provenance`; it is checksummed separately after each feed
   refresh and records cache-file/content hashes, feed version, retrieval time,
   and importer provenance as non-authoritative context. Pass the frozen model
   bundle manifest and recovery archive so their exact hashes are release-bound.
7. Run `production.tools.release_manifest verify`. It verifies only immutable
   release inputs; separately validate the current
   `runtime_feed_provenance.v1` record and feed-cache checksums. Only after both
   checks pass, write
   `DEPLOYED_COMMIT`, verify that marker, and atomically repoint
   `/opt/honeypot`.
8. Install reviewed unit/config changes, run `systemd-analyze verify`, restart
   only affected services, and verify health, policy, model hashes, queues,
   inference, reports, APIs, UI, PDF/STIX, and advisory-only authority.
9. Generate one synthetic-credential Cowrie session through the real
   Pi→forwarder→GCP route and retain its session/event/report/prediction IDs.

Rollback is a tested release-pointer operation, not a model change: stop only
affected application services, atomically repoint `/opt/honeypot` to the
manifest’s rollback release, restore the matching prior units/configuration,
start the same services, and verify health and hashes. Rehearse the pointer and
unit/config restoration with an isolated temporary link and extracted backup;
do not interrupt the verified live release merely to demonstrate rollback.
