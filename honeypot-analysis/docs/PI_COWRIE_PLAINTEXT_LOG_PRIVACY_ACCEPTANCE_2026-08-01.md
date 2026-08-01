# Pi Cowrie plaintext-log privacy acceptance — 2026-08-01

## 1. Executive decision

`ROLLBACK_COMPLETED_AFTER_PI_FAILURE`

The corrected package passed every local, manifest, compatibility, and
isolated Pi smoke gate. Deployment then stopped before release extraction
because the fresh rollback receipt did not verify against the file it had just
protected. The prior Pi sanitizer and services were recovered. The GCP
candidate was never activated.

## 2. Exact starting state

- Local branch: `professor-approved-poc-evaluation`
- Reviewed package revision: `ff48d8553c116d27cb358feb6fdb2d6e6aa48423`
- Local worktree: clean
- Pi sanitizer: `7f764ab471e8dac555d06277b4613237299aee69`
- Cowrie: `575146bc6b24d70082527d66cd805d9bae0e0db4`
  (`v2.6.1-202-g575146bc-dirty`)
- Python: 3.12.3
- Twisted: 25.5.0
- Cowrie and forwarder: active; zero failed Pi units
- GCP recovery: `19afabd0bb7ed82ac93767301bb0cb1024d0b92e`
- Retained inactive GCP candidate:
  `1ad0e49e060843071508fc26aa48e07b2ac4d2b8`

## 3. Previous activation failure

The earlier `a82f821d...` package protected the categorical text output but
failed to register its sanitized JSON observer. Its generated legacy rollback
parser also disagreed with its metadata delimiter. That attempt was rolled
back before this deployment.

## 4. Baseline log/output inventory

The baseline included active `cowrie.log` mode `0600`, active `cowrie.json`
mode `0640`, and historical Cowrie files. Several older JSON rotations retained
the previously documented `0640` metadata. No log content was copied or emitted.
The forwarder was PID `282926` and remained that exact process throughout this
attempt.

## 5. Rollback boundary

The new non-overwriting receipt was:

`/var/backups/honeypot/cowrie-output-20260801T125934Z`

- owner/group/mode: `root:root`, `0700`
- all retained files: `0600`
- schema: `cowrie_output_rollback_receipt.v2`
- records: 166
- sealed receipt SHA-256:
  `9a62cd57413589290eed7c6abc6b7281b370fdb2a807d6b375eb41c4f228219b`

The receipt is retained as failed-attempt evidence, not as an accepted rollback
authority. With the quarantined log restored to its live location, the receipt
is structurally and cryptographically valid only under the explicit
pending-quarantine diagnostic mode. The earlier verified full rollback bundle
at `/var/backups/honeypot/pi-cowrie-privacy-20260801T111119Z` remains retained.

## 6. Plaintext write-path trace

The established producer remains Cowrie's authentication event formatting
before repository-owned output processing. Twisted fans the event out to the
categorical observer and Cowrie output plugins. The correction uses a closed
categorical projection and a separate structured-event copy for sanitized JSON.

## 7. Root-cause classification

- `UNSANITIZED_TEXT_LOGGER` — corrected in the reviewed package
- `SANITIZER_SCOPE_DEFECT` — corrected in the reviewed package
- `LOG_ROTATION_PERMISSION_DEFECT` — corrected in the reviewed package
- `ROLLBACK_RECEIPT_CAPTURE_RACE` — newly proven deployment blocker
- `IMMUTABLE_RELEASE_BYTECODE_CONTAMINATION` — found during recovery

## 8. Selected correction

Revision `ff48d855...` independently sanitizes JSON and categorical copies,
fail-closes JSON durability failures, isolates non-authoritative text failures,
uses native JSON rename/reopen rotation, and supports sealed v2 plus legacy
rollback receipts. Those changes remain locally verified but were not activated.

## 9. Text-logger behavior

The exact Pi runtime smoke wrote categorical events through the corrected
observer. It retained only closed diagnostic fields, used mode `0600`, and had
zero generated-marker matches.

## 10. JSON sanitizer behavior

The exact Pi runtime smoke emitted ten valid structured events across an output
restart and native rotation. The generated marker was absent, the live feed was
`0640`, and the historical JSON file was `0600`.

## 11. Journald behavior

No live candidate process or synthetic network session was started. The
corrected drop-in still specifies null stdout/stderr, but this deployment did
not reach live journal acceptance.

## 12. Rotation and mode correction

Cowrie-native JSON rotation passed in the isolated Pi runtime. External
`copytruncate` is deliberately limited to the categorical text log. Live
post-install rotation was not run after the rollback-receipt stop condition.

## 13. Historical-log handling

No historical content was rewritten or deleted. The installer stopped before
its historical metadata-normalization stage. The temporarily protected active
text log was hash-verified and restored exactly to the active log path.

## 14. Generalized regression tests

- Focused Cowrie output, rollback, forwarder, durability, and privacy tests:
  `80 passed`
- Complete suite: `1102 passed, 7 skipped`
- Python compilation, shell syntax, JSON validation, manifest verification,
  archive traversal/type checks, and `git diff --check`: passed

## 15. Commits and hashes

- `7914fb6` — preserve sanitized JSON across observers
- `11815f9` — parse rollback metadata deterministically
- `e49117e` — cover output and forwarder durability
- `b12c75f` — bind compatibility and destinations
- `ff48d85` — keep JSON rotation inode-safe
- Component: `cowrie_output_00020b5ccd65366db35bcf8f2de1aedc`
- Manifest SHA-256:
  `94a603d640c7216cbae5aacd61a665b508a07a8c197384453a6114df64fb26f7`
- Policy SHA-256:
  `439c11f1f88da9873be9ab62ab7f4ae98a7b8a7c73116362a5f4c7a20d47cf76`
- Package SHA-256:
  `fd3034e2f61bb2a84c8a7ba07914868791a833160bfccab3cdee70c1014df665`

## 16. Pi deployment procedure

The exact archive was transferred only to
`/tmp/cowrie-output-ff48d85.tar`. Its Pi-side hash matched before extraction.
The closed inventory, manifest, destination contract, expected starting
sanitizer, Cowrie revision, Python, and Twisted all matched. A first preflight
shell probe used the wrong account after owner-only extraction; its fail-safe
removed the archive. The same approved bytes were retransferred to the same
approved path and the corrected Cowrie-account preflight passed.

The installer captured the receipt, stopped Cowrie, and moved the active text
log into the receipt. Receipt verification then failed, so no candidate release
was extracted and no active link or configuration was changed.

## 17. Service health

Final Pi state:

- Cowrie: active
- sensor forwarder: active, original PID `282926`
- failed Pi units: zero
- active sanitizer: `7f764ab...`
- candidate package and release: absent

## 18. First synthetic-marker test

The pre-install isolated Pi smoke generated its marker inside the Cowrie process
and never printed it. Ten records passed with zero marker persistence. The live
network marker test was not run because rollback evidence failed first.

## 19. Rotation test

One Cowrie-native JSON rotation passed in the isolated Pi runtime. Live rotation
was not run after the mandatory stop.

## 20. Restart test

One corrected-output restart passed in the isolated Pi runtime. Live candidate
restart was not run. Recovery restarted the prior Cowrie sanitizer successfully.

## 21. Second synthetic-marker test

Not run after the rollback-evidence stop condition.

## 22. Installed validator result

The corrected candidate was never installed. During recovery, the prior
`7f764ab...` release initially failed validation solely because seven generated
`.pyc` files contaminated its immutable inventory. The three affected
`__pycache__` directories were moved to an owner-only temporary quarantine,
the old release validated, Cowrie restarted, and the reproducible quarantine
was removed. Final prior-release validator status: `valid`.

## 23. Independent active-boundary scan

`NOT_DETERMINABLE` for the corrected candidate because live activation and its
network marker were not reached. The final restored prior boundary passed its
installed structural validator.

## 24. Independent whole-Pi scan

`NOT_DETERMINABLE`. No whole-host claim is made because the acceptance sequence
stopped before creation of a live network marker.

## 25. Protected historical-evidence scope

Previously protected owner-only evidence remains unchanged. The new failed
receipt contains configuration/metadata evidence but no duplicated active text
log after recovery; that exact log was returned to its original active path.

## 26. Downstream GCP scan

No live synthetic candidate session was created, so no candidate validation
event reached GCP. No GCP application code or production data was changed.

## 27. Rollback verification

The captured quarantine record described `cowrie.log` at 127,696 bytes with
SHA-256 `3b1081e5...`. Cowrie remained active during later receipt work and the
file moved after stop was 128,725 bytes with SHA-256 `2166a254...`. The v2
verifier therefore rejected the saved-file mismatch correctly.

Recovery verified the moved file against its post-move sidecar, restored that
exact file and mode, restored the previous active link and unchanged managed
hashes, removed only generated bytecode contaminating the prior immutable
bundle, validated the prior boundary, and started Cowrie. The firewall hash
matched the baseline.

## 28. Remaining limitations

- Receipt capture is not atomic with respect to the active quarantine log.
- The installer stops Cowrie before proving the receipt can restore the exact
  stopped-state file.
- The prior release permitted bytecode inside its immutable directory; the new
  package prevents bytecode generation but was not activated.
- Live JSON forwarding, live restart, real live rotation, two-marker privacy,
  downstream scans, and duplicate/loss gates remain unexecuted.

## 29. Reactivation readiness decision

`ROLLBACK_COMPLETED_AFTER_PI_FAILURE`

The corrected observer implementation remains promising, but this exact package
is not deployment-ready because its installer cannot seal a stable rollback
receipt while Cowrie writes the quarantined log.

## 30. Exact next action

Correct the installer transaction so Cowrie is stopped before the active text
log's final size/hash is bound, or atomically move the log into the owner-only
receipt and then construct and verify the quarantine record. Add a regression
that appends between preliminary capture and stop, prove automatic restoration
from every failure point, rebuild a new manifest-bound package, and request new
hash-specific transfer approval. Do not reuse or deploy the current package.
