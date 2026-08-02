# Deployment and recovery (canonical summary)

Production releases are built from a clean `git archive` of one commit. A
release manifest binds the Git revision, release-tree hash, code/configuration
hashes, dependency identity, policy hashes, and model references. Mutable
databases, queues, reports, secrets, feed caches, virtual environments, and
the separately managed frozen model bundle are outside the source archive.

## Last repository-recorded activation

The machine-readable receipt
`evaluation/next_tactic_final_production_activation_20260802.json` records:

- active GCP revision `3c79ae155021ca4cf0ab6d744211d884c4ee039e`;
- recovery revision `19afabd0bb7ed82ac93767301bb0cb1024d0b92e`;
- package SHA-256 `c30c4984a161385210c9fe5559c40c0c4f304351c611f18ec1130ff9d8940068`;
- manifest SHA-256 `c92e4a9e8e837392226c0a633ce067d1de6af718e523ea671567f1fc3314989c`;
- release-tree SHA-256 `de42745d53548390af08315432cdab2d7420dff281708ff22db14b300d47ca31`;
- backup `/var/backups/honeypot/cowrie-connectivity-20260801T231500Z/production_pilot.db`
  with SHA-256 `00ed27d31c32f9b7116514a31d05c77ae91843c4924a866ecfbc973e571ee04b`;
- guard state `ACTIVATION_COMPLETED` and application rollback to the recovery
  revision.

The final narrative is [`NEXT_TACTIC_FINAL_PRODUCTION_ACTIVATION_2026-08-02.md`](NEXT_TACTIC_FINAL_PRODUCTION_ACTIVATION_2026-08-02.md).

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

The public connectivity correction is independently reversible by disabling the
existing `allow-cowrie-relay-2222` rule; the exact before/after receipt hashes
are in [`COWRIE_PUBLIC_CONNECTIVITY_ROOT_CAUSE_2026-08-02.md`](COWRIE_PUBLIC_CONNECTIVITY_ROOT_CAUSE_2026-08-02.md).
Do not patch an active release in place and do not reuse a failed package.

## Verification boundary

This summary is derived from committed receipts and does not SSH to either
host. Current live deployment state, capacity, and backup existence are
`NOT_DETERMINABLE_FROM_CURRENT_REPOSITORY` unless a newer signed/hashed receipt
is committed.
