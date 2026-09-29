# Backend releases after the MongoDB cutover

The `canonical_storage_epoch.v2` receipt is the immutable record of the original
SQLite-to-MongoDB cutover. It must not be rewritten merely because application
code is updated. Its release SHA/tree/manifest identify that historical event.

For a later manifest-bound backend release, an operator with root privileges
first verifies the complete release manifest, including package, model,
configuration and dependency receipts. The tool
`production.tools.storage_release_successor` then creates a new root-owned,
non-group-writable file under `/etc/honeypot/storage_release_successors/`,
named for the exact deployed Git revision. The file pins the original epoch
receipt hash, new revision, release-tree hash, and full manifest hash.

At MongoDB startup, the historical release retains its original exact-binding
path. A successor is accepted only when the active pointer selects the running
source, `DEPLOYED_COMMIT` and the manifest are root-controlled, and all pinned
hashes match the protected receipt. A missing, modified, or wrong-release
receipt fails closed. The unprivileged runtime cannot read the root-only source
package and protected model/configuration inputs; full manifest verification
is therefore a privileged pre-activation requirement, not a startup action.

This receipt authorizes only the named source release. It does not change
MongoDB data/schema, the epoch cutoff, rollback-mirror lineage, classifier
authority, response policy, or the separate Model2 deployment gate. Preserve
the old release and its receipt for rollback. Do not copy historical
`DEPLOYED_COMMIT`, `DEPLOYED_TREE`, or `RELEASE_MANIFEST_SHA256` markers into a
successor release.
