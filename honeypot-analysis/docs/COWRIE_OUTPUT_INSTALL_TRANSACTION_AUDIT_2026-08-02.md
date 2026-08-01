# Cowrie output installation transaction audit — 2026-08-02

## Scope and invariant

This audit covers the repository-owned Cowrie sanitized-output package,
installer, rollback receipt, managed configuration, lifecycle readiness, and
service boundary. It does not change Cowrie, Python, Twisted, the forwarder,
firewall, listener exposure, historical log content, or downstream authority.

Every failure must end in exactly one of these states:

1. the verified starting sanitizer is active with its managed files restored;
2. the fully verified candidate is active after structural and lifecycle gates.

The forwarder must remain active on the PID recorded before installation.

## Transaction review

| Step | Preconditions | Mutation and durable state | Recovery and idempotency | Failure result |
|---|---|---|---|---|
| Package identity | regular archive; full revision; verified starting link; healthy Cowrie and forwarder | none | retryable | baseline remains active |
| Safe staging extraction | root-only unused staging path | closed regular-file inventory extracted with archive modes; files and directories fsynced | exact staging path is removable and never active | baseline remains active |
| Staged verification | v4 manifest; exact component/revision/deployment contract | none | deterministic and repeatable | staging removed; baseline remains active |
| Baseline diagnostics | fresh owner-only receipt path | package/config/unit hashes and service state; diagnostic only | non-authoritative records may be regenerated in a new receipt | baseline remains active |
| Cowrie stop | sealed staging; active forwarder PID recorded | only `cowrie.service` becomes inactive; empty cgroup required | repeated stop is safe | baseline is restarted |
| Active-log quarantine | stable regular unheld text-log inode | atomic move into receipt; inode fsynced; final size/hash bound after move | capture failure restores the exact inode before restart | baseline is restarted |
| Receipt seal | saved managed files, link, metadata, and quarantined log | v2 JSONL receipt and digest fsynced and independently verified | receipt is retryable; incomplete seals are invalidated | baseline is restarted |
| Release installation | sealed verified receipt and verified staging | each file copied with manifest owner/group/mode; file and directory metadata, size, and hash verified before activation | partial exact release is removed; staging retained until install verification | receipt restores baseline |
| Managed configuration | installed release verified | rendered Cowrie config, plugin link, systemd drop-in, rotation policy, and restricted modes | receipt records exact prior content/type/metadata | receipt restores baseline |
| Link activation | installed release and receipt verified | atomic `current.new` replacement | receipt restores exact prior symlink; temporary links are bounded | receipt restores baseline |
| Service activation | structural validation and plugin discovery pass | systemd reload; only Cowrie starts | bounded stop/apply/reload/start is retryable | receipt restores baseline |
| Lifecycle readiness | active Cowrie PID; manifest-bound class and state | owner-only categorical lifecycle state | diagnostic only; cannot contain raw event data | receipt restores baseline |
| Live acceptance | valid session-producing Cowrie path | sanitized events and existing forwarder state only | failures require rollback before correction/retry | candidate is not accepted |

## File-mode correction

The failed installer applied `0600` to all extracted files and then repaired a
hard-coded script list. That made executable coverage depend on installer
source age and caused the new readiness script to be rejected by its own
manifest. Manifest schema v4 now binds source, exact release destination, file
type, bytes, SHA-256, owner, group, mode, executable expectation, and immutable
classification for every closed-inventory file. Installation consumes those
receipts directly and verifies every installed field before changing `current`.

The validator independently enforces the reviewed metadata vocabulary and
recomputes the component identity. Links, special files, duplicates, extra or
missing members, unsafe paths, oversized entries, wrong modes, wrong hashes,
and invented metadata fail while the baseline is still active.

## Rollback-output correction

The sealed receipt and verified saved files are the sole rollback authority.
Receipt verification and application now run independently of stdout and of
auxiliary JSON status files. Status output is bounded, exclusive, optional,
and ignored when its path is missing, rotated, already present, unwritable, or
out of space. Closed stdout also cannot alter the operation result.

Receipt application remains preflight-first, interruption-retryable, and
idempotent after successful completion. A missing or corrupt authoritative
saved file still fails before mutation; that is an integrity boundary, not an
optional logging dependency.

## Generalized verification

- Manifest metadata and component identity reject recomputed invented values.
- Archive staging rejects path traversal, links, special files, duplicates,
  extra/missing files, mode drift, hash drift, and size drift.
- Fault injection after every staged and installed file leaves no partial tree.
- Receipt capture is exercised at every quarantine and seal boundary.
- Receipt application is exercised after every record and after prior success.
- Legacy actual-tab and literal-`\\t` receipts remain read-compatible.
- Cowrie lifecycle, observer registration, valid-session routing, categorical
  privacy, forwarder offset, spool durability, and no-bytecode contracts remain
  covered by the focused and full repository suites.

## Local results before package construction

- focused Cowrie output/receipt/lifecycle/forwarder suite: `152 passed`;
- complete repository suite: `1180 passed, 8 skipped`;
- Python compilation: passed;
- shell syntax: passed;
- `git diff --check`: passed.

The exact-version service-faithful smoke requires the reviewed Pi Cowrie
runtime and therefore remains an isolated post-transfer gate. No production
access or change was made while implementing or testing these corrections.
