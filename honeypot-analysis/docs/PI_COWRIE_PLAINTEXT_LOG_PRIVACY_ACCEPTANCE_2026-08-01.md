# Pi Cowrie plaintext-log privacy acceptance — 2026-08-01

## 1. Executive decision

`ROLLBACK_COMPLETED_AFTER_PI_FAILURE`

The reviewed correction passed local tests, package verification, an isolated
Cowrie/Twisted smoke test, and initial Pi installation checks. The first live
synthetic session then exposed a mandatory failure: the sanitized JSON feed did
not advance, so the sensor forwarder had no event to deliver. Deployment was
stopped immediately and the prior verified Pi state was restored. The retained
GCP candidate was never activated.

## 2. Exact starting state

- Local branch: `professor-approved-poc-evaluation`
- Local revision: `f0edbb940e07259b849843933586ba7267f4d5b1`
- Local worktree: clean
- Pi sanitizer revision: `7f764ab471e8dac555d06277b4613237299aee69`
- Cowrie revision: `575146...` (`v2.6.1-202` from the installed checkout)
- Python: 3.12.3
- Twisted: 25.5.0
- Cowrie and sensor forwarder: active; zero failed Pi units
- GCP recovery revision: `19afabd0bb7ed82ac93767301bb0cb1024d0b92e`
- Retained inactive candidate: `1ad0e49e060843071508fc26aa48e07b2ac4d2b8`

## 3. Previous activation failure

The previous activation found an exact synthetic credential in the active
Cowrie text log and an historical JSON rotation with an unsafe mode. Its spool,
GCP database, reports, artifacts, snapshots, and GCP journals had zero matches.
This localized the blocker to the Pi persistence boundary.

## 4. Baseline log/output inventory

Cowrie used its installed configuration plus systemd drop-ins. The service ran
as the Cowrie account with `UMask=0077`. The forwarder consumed only the
sanitized JSON feed. The spool contained only its lock and offset state. The
active text log was owner-only, while the active JSON feed and multiple
historical JSON rotations were group-readable. Forty-one compressed Cowrie
rotations were later checked as root and all passed `gzip -t`; an earlier
non-root result that reported 39 failures was a permissions artifact.

The inventory recorded path, type, owner, group, mode, size, timestamp, and
SHA-256 without emitting log contents. No credential-bearing content was copied
into this repository or report.

## 5. Rollback boundary

The complete owner-only rollback bundle is:

`/var/backups/honeypot/pi-cowrie-privacy-20260801T111119Z`

- Directory owner/mode: root, `0700`
- Files: `0600`
- Configuration/code archive SHA-256:
  `c6ba4d106aa17bf7c2907413d42878ee62b80d05fb5f007e61ddc09cc67d3976`
- Rollback manifest SHA-256:
  `72a228432484b1d1d922f93061e6af288eb884369cf4f2a7ee2d65338e0bb353`
- Installer receipt:
  `/var/backups/honeypot/cowrie-output-20260801T111119Z`

The bundle contains configuration, units, rotation configuration, forwarder
configuration, sanitizer code/manifest, versions, hashes, metadata, and restore
instructions. It does not duplicate active logs. The installer receipt moved
the prior active credential-bearing text log into the owner-only boundary
instead of making an ordinary plaintext copy.

An earlier incomplete attempt remains at
`/var/backups/honeypot/pi-cowrie-privacy-20260801T110953Z`, owner-only, as
failed-attempt evidence. It is not the rollback authority.

## 6. Plaintext write-path trace

Installed Cowrie authentication code constructs an unstructured, preformatted
login-attempt message before repository-owned output processing. Twisted sends
that event to the text observer. The existing JSON output plugin separately
sanitizes structured fields; it therefore cannot make the independent text sink
safe. A local minimized reproduction proved that an unstructured secret could
survive the old diagnostic projection when no structured credential field was
available.

## 7. Root-cause classification

- `UNSANITIZED_TEXT_LOGGER`
- `SANITIZER_SCOPE_DEFECT`
- `LOG_ROTATION_PERMISSION_DEFECT`

## 8. Selected correction

Revision `a82f821d1e0f8280a67773429518d9f32e536d3b` replaced arbitrary diagnostic
text persistence with a closed categorical projection. Only bounded event
category, outcome, pseudonymous session reference, numeric time, and safe
component data can be emitted. Arbitrary message text, formatting fields,
namespaces, exception text, commands, addresses, usernames, and passwords are
not persisted.

The same revision added explicit rotation preparation/finalization, strict
ownership/type/mode checks, owner-only rotated/compressed files, null service
stdout/stderr, and installer/rollback support.

## 9. Text-logger behavior

The isolated Pi smoke test generated a unique marker inside the actual
Cowrie/Twisted process. The categorical text log contained zero marker matches
and was created as `0600`. Operational lifecycle information remained present
without attacker-controlled text.

## 10. JSON sanitizer behavior

Structured credential registration remained as defense in depth. The isolated
smoke created a live JSON feed at `0640` for the approved forwarder and a daily
rotation at `0600`; neither contained the marker. In the live test, however,
the JSON feed did not advance, which caused the deployment failure.

## 11. Journald behavior

The candidate drop-in routed Cowrie stdout and stderr to null. The live-test
interval contained zero test-nonce journal matches. Later journal matches were
created solely by privileged verification commands whose command arguments
contained the privacy-safe nonce; all are `sudo` audit entries after the test
interval. No raw credential value was printed or retained in this report.

## 12. Rotation and mode correction

The candidate added an explicit logrotate policy and integration commands that
make the current feed private before rename, retain the approved live feed mode,
and leave rotations/compressed files owner-only. Local real-logrotate tests and
the isolated Pi rotation smoke passed. The live forced-rotation acceptance gate
was not reached because event forwarding failed first.

## 13. Historical-log handling

After the owner-only rollback boundary was verified, metadata-only correction
made 160 historical records owner-only without rewriting content. Hashes of
historical contents were preserved. The active prior text log was moved into
the protected installer receipt during installation and restored during
rollback. No historical record was deleted or rewritten.

## 14. Generalized regression tests

Coverage includes successful and failed authentication, spaces, quotes,
Unicode, control characters, bounded long values, split formatting fields,
structured/unstructured logging, active and rotated outputs, compression,
ownership and modes, symlink rejection, forwarder compatibility, service output
policy, and arbitrary-secret non-persistence.

## 15. Commits and hashes

- Implementation: `a82f821d1e0f8280a67773429518d9f32e536d3b`
  (`Close Cowrie diagnostic and rotation privacy gaps`)
- Clean package SHA-256:
  `94e49383006f993b817766af1202faee1473808d88e0fcc1a45b500bfceaf7e3`
- Component:
  `cowrie_output_11cde6d82c91dfae3c012bd809928abb`
- Component manifest SHA-256:
  `350892c414231db40a47b7e2b4cf3d86843232d811093acd2295070bf9a62563`
- Policy SHA-256:
  `439c11f1f88da9873be9ab62ab7f4ae98a7b8a7c73116362a5f4c7a20d47cf76`

## 16. Pi deployment procedure

The exact approved archive was transferred only to
`/tmp/cowrie-output-a82f821.tar`. Its Pi-side SHA-256 matched before extraction.
An isolated extraction and smoke preceded installation. After the rollback
bundle was verified, only Cowrie was stopped for installation, managed files
were installed, hashes were checked, systemd was reloaded, and Cowrie was
started. The forwarder was not reconfigured. Both approved temporary paths were
removed after rollback.

## 17. Service health

Final state: Cowrie `active`, sensor forwarder `active`, zero failed Pi units.
No temporary listener or helper process is retained.

## 18. First synthetic-marker test

The normal existing Cowrie access path accepted a successful synthetic session
with one benign command and a clean close. The candidate categorical text log
grew and contained no privacy-safe nonce match. The live sanitized JSON feed did
not grow at all. Consequently, no event reached the forwarder and this mandatory
failure triggered rollback.

## 19. Rotation test

Local and isolated Pi rotation tests passed. The live post-activation rotation
test was **not run** after the forwarding stop condition.

## 20. Restart test

The candidate initially restarted cleanly, but the required controlled
post-marker restart persistence cycle was **not run** after the forwarding stop
condition. The restored Cowrie and forwarder are active.

## 21. Second synthetic-marker test

**Not run.** Continuing would have violated the mandatory stop condition.

## 22. Installed validator result

The candidate validator was valid immediately after installation. Final
acceptance was never reached. After rollback, the restored baseline validator
reports `invalid` because its bundle contains unmanifested or missing filesystem
entries. This is not represented as a candidate pass.

## 23. Independent active-boundary scan

No privacy-safe nonce match was found in active uncompressed Cowrie logs, the
spool/state boundary, the owner-only backup boundary, managed release/config
files, or decoded Cowrie rotations. The live-test journal interval had zero
matches. Because forwarding failed and rollback occurred before the complete
first-cycle exact-credential scan, the required acceptance result is
`NOT_DETERMINABLE`; it cannot satisfy the valid-boundary criteria.

## 24. Independent whole-Pi scan

The scoped persistent-file scan found zero privacy-safe nonce matches and all 41
Cowrie gzip files were readable and valid. A whole-Pi zero-match claim is not
made: later `sudo` verification commands placed the safe nonce in journal audit
records, and the exact credential value was deliberately not retained for a
post-rollback rescan. Result: `NOT_DETERMINABLE` for the exact credential marker.

## 25. Protected historical-evidence scope

The owner-only installer receipt retains the prior pre-deployment text log and
the failed candidate text log for rollback/audit purposes. The prior file may
contain historical credential material. It is outside the active log tree,
root-owned, mode `0600`, and was not copied to Git. Whether every older protected
record contains a given historical marker is not needed for this failed
candidate decision and remains `NOT_DETERMINABLE` without exposing/decrypting
that evidence.

## 26. Downstream GCP scan

The first session produced no sanitized JSON event, so it could not reach GCP.
A read-only scan of the active database/WAL/SHM and report/artifact/backup
boundary found zero privacy-safe nonce matches. The live-test GCP journal
interval also contained zero matches.

## 27. Rollback verification

The generated rollback program encountered a parser defect: bulk metadata was
written with literal `\\t` sequences but parsed as actual tabs. Critical
configuration, release-link, log, and rotation restoration had already
completed. An owner-only root recovery step parsed both encodings, restored all
160 metadata records (zero invalid or absent), then restarted Cowrie and the
forwarder. Post-restore checks confirmed the prior sanitizer link, configuration
SHA-256, systemd drop-in SHA-256, logrotate SHA-256, service health, empty spool
payload, and zero failed units. The firewall ruleset hash matched immediately
after rollback; later raw ruleset hashes are not stable because counters change.

## 28. Remaining limitations

- The live JSON event-loss defect is not diagnosed or corrected.
- The rollback metadata parser defect remains in the unactivated local
  implementation and must be corrected before any new deployment attempt.
- Live rotation, controlled restart, second marker, duplicate/loss accounting,
  and final validator gates were not reached.
- The restored baseline validator remains invalid.
- A final exact-credential whole-host scan is not determinable after intentional
  secret disposal; only the privacy-safe nonce scan is retained.

## 29. Reactivation readiness decision

`ROLLBACK_COMPLETED_AFTER_PI_FAILURE`

The Pi correction is not ready for controlled reactivation. GCP remains on the
verified recovery release; the retained candidate and its historical deployment
marker remain inactive and unchanged.

## 30. Exact next action

In a new, separately approved local task, reproduce why the candidate JSON
observer emits no live event and fix the rollback receipt parser with generalized
tests. Rebuild a new clean manifest-bound package and repeat the entire Pi
privacy acceptance sequence from a fresh owner-only rollback boundary. Do not
activate the GCP candidate unless that later Pi acceptance independently passes.
