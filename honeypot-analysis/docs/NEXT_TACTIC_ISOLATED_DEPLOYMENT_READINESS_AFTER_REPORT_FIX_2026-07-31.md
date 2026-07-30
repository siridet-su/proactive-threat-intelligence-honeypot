# Next-tactic isolated deployment readiness after canonical-report fix

## 1. Executive verdict

Decision: **`READY_FOR_CONTROLLED_ACTIVATION`**.

The isolated blocker was reproduced twice, diagnosed without evidence
disclosure, corrected at the canonical provenance boundary, covered by
generalized regressions, and retested through a fresh manifest-bound release.
The full report/artifact path, restart, forced worker recovery, recovery-release
compatibility, and candidate-to-recovery-to-candidate round trip passed.

This document does not authorize or record activation. Production remained on
`19afabd0bb7ed82ac93767301bb0cb1024d0b92e`; no Raspberry Pi access or
modification occurred.

## 2. Exact starting state

- Branch: `professor-approved-poc-evaluation`.
- Starting HEAD: `47b789d2cc7164952bedfe200d323e6361d34feb`.
- Starting worktree: clean.
- Active GCP recovery release and marker:
  `19afabd0bb7ed82ac93767301bb0cb1024d0b92e`.
- Failed isolated candidate:
  `27a5064ff5501310e6c2b553a773434f4fdadfe7`.
- Staged historical candidate:
  `6964d54326ba59a51cffb2f0d13d9a5b1bd858f2`.
- Recorded Pi sanitizer:
  `7f764ab471e8dac555d06277b4613237299aee69`.
- Production had eight active application services, zero failed units, and
  three healthy endpoints.

The failed candidate manifest remained valid. No pre-existing model,
classification, trust, or prediction compatibility question was reopened.

## 3. Diagnostic design and privacy proof

`analysis_validation_diagnostic.v1` accepts only structured validation errors
and emits an explicit allowlist:

- contract and validator name;
- normalized category, field path, constraint, received type, and state;
- content-addressed safe object ID;
- producer, source revision, safe job ID, and bounded retry attempt.

It never emits exception text, `repr`, serialized records, evidence values,
commands, credentials, addresses, identifiers from evidence, or frame locals.
Arbitrary exceptions produce no diagnostic. The normal error remained
`operation_failed`.

Both isolated journals had zero matches for their synthetic secret marker.
The diagnostic redaction suite passed, including unknown validator messages
containing secret, command, and address sentinels.

## 4. Exact validation field and contract

Both fresh reproductions produced:

- job ID: `job_a29be4fe15cd3f0c358209de85f921e5`;
- diagnostic safe object ID:
  `validation_d48c0c23683eb1fade18cd8d803ad368`;
- contract: `session_assessment.v4`;
- validator: `validate_session_assessment_v4`;
- producer: `build_session_assessment_v4`;
- field: `provenance.evaluator_git_revision`;
- category/state: `missing`;
- constraint: `required_field`;
- received type: `not_recorded`;
- attempts: two retryable pipeline failures, then strict fallback rejection.

The persisted terminal state was again
`job_invalid:ValidationError`, three attempts, and zero reports.

## 5. Minimized reproduction

The generalized regression stages one privacy-safe command observation in a
temporary extracted-release layout. It exercises the entire
`build_session_assessment_v4` producer-to-whole-contract-validator path.

- No Git checkout, deployment marker, or manifest: strict rejection at
  `provenance.evaluator_git_revision`.
- Exact source-bound v7 manifest, without a deployment marker: valid,
  deterministic report.
- Manifest with mismatched evaluator bytes/hash: strict rejection.

The nearby invalid control proves that validation was not weakened.

## 6. Root-cause classification

**`REPORT_CONSTRUCTION_DEFECT`**

A clean Git archive has no `.git` directory. A staged pre-activation release
intentionally has no `DEPLOYED_COMMIT` marker. Although the failed candidate
had an independently verified v7 manifest containing its exact Git revision
and source inventory, `_git_revision()` ignored that manifest and created an
empty provenance value.

The invalid value was first created during report construction. It was absent
from stored reconstructed evidence; serialization did not create it; the
fixture represented a supported manifest-bound staged release; and the
validator correctly enforced the documented required provenance.

Supplying the staged revision explicitly to the unchanged durable job produced
two valid reports with identical assessment IDs, proving that evidence,
storage, policies, and report assembly otherwise remained valid.

## 7. Corrective implementation

The canonical revision resolver now accepts a staged manifest only if all of
the following verify:

- regular, non-symlink manifest, at most 1 MiB and not group/other writable;
- schema `honeypot_release_manifest.v6` or `.v7`;
- full lowercase Git revision;
- manifest release path equals the running release root;
- release identity is `immutable_source_release.v2`;
- this exact evaluator source path is present as a regular file;
- recorded byte length and SHA-256 equal the running evaluator bytes.

Resolution order remains explicit environment, activation marker, verified
staged manifest, then Git checkout. Invalid or incomplete manifests abstain and
the unchanged v4 validator fails closed.

No model, policy, rules, trust boundary, semantic authority, required field,
historical adapter, or external error contract changed.

## 8. Regression tests

- Initial diagnostics: 34 passed.
- Manifest-bound provenance plus adjacent suites: 42 passed.
- Broader report, guidance, hypothesis, artifact, privacy, retry, storage,
  prediction immutability, historical compatibility, and E2E focus:
  88 passed, 1 skipped in the restricted run.
- The two focus failures were only forbidden loopback socket creation; exact
  non-sandbox rerun: 2 passed.

New tests prove structural redaction, arbitrary-exception rejection, retry
context bounds, whole-path failure without provenance, valid staged-manifest
construction, deterministic replay, and strict source-hash rejection.

## 9. Complete suite and validators

- Full local suite with loopback permission: **1,060 passed, 7 skipped** in
  80.83 seconds.
- Prediction policy: passed.
- Reviewed classification rules: passed.
- Response-guidance policy: passed.
- Threat-hypothesis behavior policy: passed.
- Session-correlation policy: passed.
- Persisted and rendered `session_assessment.v4`: no errors.
- Persisted and rendered `response_guidance.v3`: no errors.
- Artifact integrity manifest: no errors.
- STIX validator: no errors.
- Python compilation: passed.
- `git diff --check`: passed.

No test or frozen expected label was weakened or removed.

## 10. Fresh candidate identity and manifest

- Corrective release revision:
  `1ad0e49e060843071508fc26aa48e07b2ac4d2b8`.
- Package:
  `/opt/honeypot-packages/honeypot-release-1ad0e49e060843071508fc26aa48e07b2ac4d2b8.tar`.
- Package bytes: `104120320`.
- Package SHA-256:
  `2076c674e33d490e4a276492b9b8629f8ab2c76ddab2f2706d2e4fe63e46b66c`.
- Release:
  `/opt/honeypot-releases/1ad0e49e060843071508fc26aa48e07b2ac4d2b8`.
- Manifest:
  `/opt/honeypot-releases/1ad0e49e060843071508fc26aa48e07b2ac4d2b8/DEPLOYMENT_MANIFEST.json`.
- Manifest SHA-256:
  `c57766c2e09ba1353fa7a9794ceddb30acbbaddf32f2f4890911f33cf966c881`.
- Release-tree SHA-256:
  `de7a3f9167f70ce1bdbb757efee5e5d73a5ff68b78af8e00e111831240d9adf0`.
- Bound files: `539`.
- Schema: `honeypot_release_manifest.v7`.
- Post-manifest writes: zero.
- `DEPLOYED_COMMIT`: absent, as required for a non-activated candidate.

The root verifier passed before and after testing. The owner-only package
correctly prevents an unprivileged full-package verification; the `honeypot`
runtime user independently resolved the exact staged revision from the
source-bound manifest.

## 11. Backup and restore evidence

Retained rollback backup:

`/var/backups/honeypot/next-tactic-isolated-20260730T202504Z/production_pilot.db`

- bytes: `3932856320`;
- SHA-256:
  `0a86e4ac311e5dbcb3967f8eb228c442734db0734826f18952f7707b18996b93`;
- owner/mode: `root:root`, `0600`;
- schema: 3;
- full integrity: `ok`;
- quick check: `ok`;
- table counts: manifest-exact.

Three new non-overwriting restores were created from this verified backup:
two diagnostic reproductions and the final candidate run. Each restore passed
full and quick integrity plus table-count verification. Derived restores were
removed after evidence capture. The retained source backup was not modified.

## 12. Isolated E2E

The final run used all eight hardened transient services, isolated owner-only
state, loopback ports, external enrichment disabled, no webhooks, and no
`DEPLOYED_COMMIT` environment override.

- authenticated events accepted: 12;
- exact replay duplicates: 12;
- durable events processed: 12;
- late source timestamp: covered;
- same-tactic repetition and tactic change: covered;
- failed command evidence: covered;
- direct Cowrie transfer with SHA-256: covered;
- close event: covered;
- prediction snapshots: 11;
- completed prediction outbox: 11;
- snapshot integrity errors: 0;
- analysis jobs: one, `succeeded`, one attempt;
- reports: one;
- threat-hunt jobs: three, all succeeded;
- enrichment jobs: zero;
- alerts: zero;
- webhook deliveries: zero.

The current selector chose the close-event v3 snapshot. All snapshot IDs were
unique, statuses were `insufficient_history` or `predicted`, and no snapshot
contained recommendations.

## 13. Report and artifact results

Persisted report:

- report ID: `report_81343d3c3f8a9b41fb71f08666cdc62e`;
- assessment ID:
  `session_assessment_23347fae07b018eddf90ac25f8c1b11d`;
- evaluator revision:
  `1ad0e49e060843071508fc26aa48e07b2ac4d2b8`;
- canonical durable manifest: 12 events with an exact terminal event cutoff;
- behavioral findings: five;
- falsifiable hypothesis sets: zero, avoiding unsupported claims;
- guidance actions: three, all manual-only and non-executable.

JSON, Markdown, PDF, STIX, and artifact-manifest files were generated with
owner-only `0600` modes. The JSON report retained the exact assessment and
guidance IDs and passed both contracts. The artifact manifest and STIX bundle
passed their validators. Generated files were removed with the derived restore
after validation, as required.

## 14. API and monitor equivalence

Dashboard and monitor returned the same current snapshot ID and byte-equivalent
`current_prediction` payload. They also returned the same guidance ID, facts,
actions, authority, safety, and provenance.

Their independently rendered guidance objects differed only in `generated_at`,
a non-identity presentation timestamp. This does not change the guidance ID,
action selection, findings, safety, or canonical state.

Prediction wording was explicitly advisory-only:
`may_authorize_action=false`, `may_create_alert_alone=false`,
`may_select_guidance=false`, `automatic_execution=false`, and
`establishes_attacker_intent=false`.

## 15. Privacy and authority checks

The final synthetic plaintext credential had zero matches in:

- SQLite database, WAL, and SHM;
- every report and artifact;
- isolated service journals;
- retained pre-test backup.

The login payload stored redacted username and password fields. All report
files were owner-only. Diagnostic journals from both failing reproductions had
zero secret-marker matches.

The source session created no enrichment job, so no source address reached an
external provider. External enrichment was fail-closed disabled. Predictions
created no alerts, webhooks, guidance, recommendations, or response actions.
Observed evidence remained authoritative; prediction, enrichment, correlation,
and prose authority flags remained false.

## 16. Restart and failure recovery

- Clean stop: 1.178 seconds.
- All eight services healthy after restart: 31.089 seconds.
- Event/report/snapshot counts after restart: 12/1/11, unchanged.
- Duplicate event IDs: zero.
- Queues: prediction outbox 11 completed, analysis one succeeded,
  threat-hunt three succeeded, enrichment empty.
- Forced analysis-worker `SIGKILL`: automatic recovery in 2.203 seconds.
- Restart counter: one.
- Counts and immutable snapshots remained unchanged.
- Post-recovery SQLite integrity: `ok`.

## 17. Rollback compatibility

A non-overwriting SQLite online copy of the stopped candidate state was
created and verified:

- bytes: `3933978624`;
- SHA-256:
  `26f56f38fd11f3ef8129dbb0dbeb37067b837e3a60adab240516084281ae8084`;
- schema: 3;
- full and quick integrity: `ok`.

An initial startup attempt failed closed before application testing because
the verifier-created empty WAL/SHM sidecars were root-only. Ownership was
corrected only on the disposable copy, and the compatibility rehearsal was
restarted from the same verified database bytes.

Recovery revision `19afabd0bb7ed82ac93767301bb0cb1024d0b92e` then:

- started all eight isolated services;
- reached all three health endpoints in 32.115 seconds;
- read the candidate-created v4 record without validation error;
- retained the same assessment ID, one report, and 11 snapshots;
- returned the same current snapshot through dashboard and monitor;
- retained zero credential-marker matches.

Application-only rollback is sufficient for this candidate schema state. The
disposable working copy and its sidecars were removed afterward.

## 18. Candidate–recovery–candidate round trip

The exact isolated sequence passed:

`1ad0e49e… → 19afabd0… → 1ad0e49e…`

The corrected candidate returned healthy in 39.368 seconds. The original
candidate database still had the same assessment ID, one report, 11 immutable
snapshots, the same current snapshot, and no v4 validation errors.

## 19. Remaining limitations

- This was isolated GCP validation, not a live production activation.
- No real Pi-to-GCP event was required or sent; Pi state is therefore unchanged.
- External providers were intentionally disabled, so their availability was
  not tested.
- Exact individual first-health timestamps were not captured; aggregate
  all-endpoint times are reported.
- Recovery code exposes a different internal storage method name, but both
  dashboard and monitor read the candidate snapshot correctly.
- Dashboard and monitor guidance presentation timestamps are generated per
  request; all identity-bound and semantic fields were equal.
- Long-duration production observation after activation remains pending.

## 20. Exact controlled-activation procedure

Activation remains a separate approval:

```sh
REVISION=1ad0e49e060843071508fc26aa48e07b2ac4d2b8
RELEASE=/opt/honeypot-releases/$REVISION
RECOVERY=/opt/honeypot-releases/19afabd0bb7ed82ac93767301bb0cb1024d0b92e

test "$(readlink -f /opt/honeypot)" = "$RECOVERY"
test ! -e "$RELEASE/DEPLOYED_COMMIT"
df -B1 /

cd "$RELEASE"
sudo env PYTHONDONTWRITEBYTECODE=1 ./.venv/bin/python \
  -m production.tools.release_manifest verify \
  --release-root "$RELEASE" \
  --manifest "$RELEASE/DEPLOYMENT_MANIFEST.json"

# Create and verify a fresh, non-overwriting production backup here.

printf '%s\n' "$REVISION" | sudo tee "$RELEASE/DEPLOYED_COMMIT.new" >/dev/null
sudo chown root:root "$RELEASE/DEPLOYED_COMMIT.new"
sudo chmod 0644 "$RELEASE/DEPLOYED_COMMIT.new"
sudo mv "$RELEASE/DEPLOYED_COMMIT.new" "$RELEASE/DEPLOYED_COMMIT"
sudo ln -s "$RELEASE" /opt/honeypot.next
sudo mv -Tf /opt/honeypot.next /opt/honeypot

sudo systemctl restart \
  honeypot-ingest-api.service \
  honeypot-session-worker.service \
  honeypot-analysis-worker.service \
  honeypot-enrichment-worker.service \
  honeypot-threat-hunt-worker.service \
  honeypot-webhook-dispatcher.service \
  honeypot-dashboard-api.service \
  honeypot-monitor-web.service
```

Then verify eight services, three endpoints, exact marker/manifest/model/policy
hashes, database integrity, queues/leases, one controlled Pi-to-GCP session,
report/artifact privacy, API/monitor equivalence, and zero prediction-authorized
alerts or actions. Any failed gate invokes fallback.

## 21. Exact automatic-fallback procedure

```sh
RECOVERY=/opt/honeypot-releases/19afabd0bb7ed82ac93767301bb0cb1024d0b92e

sudo systemctl stop \
  honeypot-ingest-api.service \
  honeypot-session-worker.service \
  honeypot-analysis-worker.service \
  honeypot-enrichment-worker.service \
  honeypot-threat-hunt-worker.service \
  honeypot-webhook-dispatcher.service \
  honeypot-dashboard-api.service \
  honeypot-monitor-web.service

sudo ln -s "$RECOVERY" /opt/honeypot.rollback
sudo mv -Tf /opt/honeypot.rollback /opt/honeypot

sudo systemctl start \
  honeypot-ingest-api.service \
  honeypot-session-worker.service \
  honeypot-analysis-worker.service \
  honeypot-enrichment-worker.service \
  honeypot-threat-hunt-worker.service \
  honeypot-webhook-dispatcher.service \
  honeypot-dashboard-api.service \
  honeypot-monitor-web.service

test "$(readlink -f /opt/honeypot)" = "$RECOVERY"
test "$(cat /opt/honeypot/DEPLOYED_COMMIT)" = \
  19afabd0bb7ed82ac93767301bb0cb1024d0b92e
```

The isolated rehearsal proved application-only fallback for schema 3.
The fresh pre-activation backup remains mandatory protection against unrelated
storage or host failures.

## 22. Final readiness decision

**`READY_FOR_CONTROLLED_ACTIVATION`**

All mandatory isolated gates passed: exact root cause, strict generalized
correction, complete tests, manifest and model verification, canonical report
and artifacts, privacy, current-snapshot equivalence, restart, forced recovery,
rollback compatibility, round trip, backup, capacity, and production
non-interference.

## 23. Commits and hashes

- `d4996334bd7f22f5ceee875f41009c9908354a67` —
  `Add privacy-safe analysis validation diagnostics`.
- `55f9196943384b451e994f958a15650e991c8703` —
  `Bind staged evaluator provenance to the release manifest`.
- `1ad0e49e060843071508fc26aa48e07b2ac4d2b8` —
  `Cover staged release provenance through canonical validation`.
- Evidence/report commit: the commit containing this document and
  `evaluation/next_tactic_isolated_deployment_readiness_after_report_fix_20260731.json`.

Final cleanup left zero isolated units, processes, or listeners. Derived
restores, temporary diagnostic release/package, uploaded archives, transient
unit definitions, and local temporary archives were removed. The final candidate
release/package, failed candidate, recovery releases, manifests, model bundle,
and retained verified backup remain.
