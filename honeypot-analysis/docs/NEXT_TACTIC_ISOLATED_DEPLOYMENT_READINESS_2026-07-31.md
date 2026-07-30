# Corrected next-tactic isolated deployment readiness

## 1. Executive decision

The corrected next-tactic candidate is **`BLOCKED_BY_TEST_FAILURE`**. Packaging,
capacity, backup/restore, schema compatibility, model loading, startup, ingest,
deduplication, session processing, prediction persistence, snapshot integrity,
and privacy checks passed. The real isolated report pipeline did not pass:
the analysis job exhausted three attempts with
`job_invalid:ValidationError` and produced no report.

The stop condition was honored. No live symlink was changed, no production
service was restarted, and no Raspberry Pi state was modified. Restart,
recovery, rollback-compatibility, API/monitor equivalence, and guidance/artifact
acceptance were not attempted after the report failure.

## 2. Exact starting state

- Branch: `professor-approved-poc-evaluation`.
- Starting repository HEAD: `4361d252b3188e74ee4bdb14c27c8228c5a92555`.
- Verified evaluator implementation revision:
  `638f51e77331bf1d7875e228830da7f6862f90a4`.
- The correction chain was present in order: `936892a` durable cutoff,
  `bb2b425` immutable snapshots, `e39b2d1` late chronology, `d683a71` audit
  features, and `638f51e` compatibility evaluation.
- GCP active release and marker before testing:
  `19afabd0bb7ed82ac93767301bb0cb1024d0b92e`.
- Existing staged release:
  `6964d54326ba59a51cffb2f0d13d9a5b1bd858f2`.
- Raspberry Pi sanitizer release, inspected read-only:
  `7f764ab471e8dac555d06277b4613237299aee69`.
- Production had eight active application services, two waiting timers, no
  failed unit, and three healthy HTTP endpoints.
- Production SQLite was 3,932,856,320 bytes, schema version 3, WAL mode,
  4,096-byte pages, and passed `quick_check`.

The model decision remains `COMPATIBLE_WITH_DISCLOSED_LIMITATIONS`. No training
process was present and no locally generated evaluation result was used as a
runtime dependency.

## 3. Commits and tests

Commits created before the readiness report:

- `6a6823c336c41b3d36115ec46af2ae7dc37a3942` —
  `Bind deployment build context explicitly`. Manifest v7 now records and
  fail-closed validates builder identity, database schema version, dependency
  locks, systemd units, and static assets.
- `27a5064ff5501310e6c2b553a773434f4fdadfe7` —
  `Verify releases without traversing model links`. Release inventory now uses
  a non-following filesystem walk, so an owner-only model-directory symlink
  cannot truncate an unprivileged inventory. The symlink itself remains
  hash-bound.

Validation results:

- Initial correction-focused set: 102 passed, 2 skipped.
- Initial full suite: 1,045 passed, 7 skipped.
- Manifest-focused set after both corrections: 19 passed.
- Full suite in the restricted sandbox: 1,045 passed, 7 skipped, with eight
  expected `PermissionError: Operation not permitted` loopback-socket failures.
- Exact rerun with loopback sockets permitted: **1,053 passed, 7 skipped**.
- Prediction, classification, and response policy validators passed.
- `compileall` and `git diff --check` passed.

The first candidate manifest verified as root but failed for the deployment
user because Python 3.11 `Path.rglob()` probed the owner-only model symlink and
silently omitted later sibling trees. Root verification proved that files had
not drifted. The second commit corrected that release-tool defect without
changing prediction semantics.

## 4. Model and policy identities

| Item | SHA-256 |
|---|---|
| Transformer checkpoint | `7fbd73c4bd071336fa52a589bf41e39f5a3122a67aee398dfb8e6dd9cfdfb04a` |
| Model specification, semantic | `82b1a15ec96f5165878ee03639daa61e319f06c4376e0a9a8018f3e1a2b3e512` |
| Vocabulary, semantic | `527a65c6d6cee94a3bbb0af6d5df95981a6438cf703e053484c9e7e116f0306f` |
| Calibration, semantic | `aa27813af96eaa2674b07d76f41565e71835bfa1a5bba8a3232eaa0a396a4e2d` |
| Reviewed classification rules | `33f332946c53578f2e609a3a039dda712355b9e209721bcc073c61a623d6342b` |
| Frozen classifier MITRE snapshot | `33af47bb0a3475cda60c2bea83ce305244bd747021f9e999652dc21520e4e35c` |
| Preprocessing contract | `890569a4597df2f300d7c885a2cf0bd34a9fd9fbdd0ab0938141a8f13f4a25c1` |
| Transformer PoC prediction policy | `3861d6a6edad4d15e147213cf0c4a5e8fb6c74f2a5f90142526df31492ddd90c` |
| Frozen bundle manifest | `609ab334bb5c75295eee2851e2b2b6ae103ce8e0dbc6e43219da8bb5221e4419` |

`frozen_model_bundle verify --runtime-check --smoke-test` passed. It loaded the
existing checkpoint, emitted a valid non-persistent prediction, and reported
`predictive_alert_status=prohibited`.

## 5. Capacity calculation

The host initially had 14,427,414,528 free bytes. Three completed, independently
verified restore-rehearsal copies consumed 11,790,893,056 bytes. Their hashes
matched retained owner-only source backup manifests, no process or open file
referenced them, and the prior handoff identified them as disposable temporary
restores. Only that reproducible restore-rehearsal directory was removed; its
source backups were retained. Free space then became 26,218,237,952 bytes.

Measured peak allowance was approximately 9.1 GB:

- online backup: 3.933 GB;
- isolated restore: 3.933 GB;
- release and package: approximately 0.210 GB;
- staging duplication: approximately 0.210 GB;
- bounded WAL allowance: 0.537 GB;
- logs and verification allowance: 0.268 GB.

After candidate construction and final cleanup, 21,864,648,704 bytes remained
free. The required 10 GiB safety margin was satisfied throughout execution
after the bounded cleanup.

## 6. Backup and isolated restore

Fresh non-overwriting backup:

`/var/backups/honeypot/next-tactic-isolated-20260730T202504Z/production_pilot.db`

- bytes: 3,932,856,320;
- SHA-256:
  `0a86e4ac311e5dbcb3967f8eb228c442734db0734826f18952f7707b18996b93`;
- owner/mode: `root:root`, `0600`;
- backup directory mode: `0700`;
- full integrity and quick checks: `ok`;
- schema: 3;
- source and restore table counts: exact match.

The backup was restored to
`/var/lib/honeypot/isolated-next-tactic-4361d25/production_pilot.db`.
The restored file had the same hash and passed full and quick integrity checks.
It was the only database used by transient services. After the stop-condition
evidence was captured, the derived restore/test directory was removed as
required by final cleanup. The verified source backup above remains retained.

The first backup command was invoked from the wrong working directory and
failed before opening the database. Re-running it from `/opt/honeypot` passed;
no partial backup was accepted.

## 7. Release identity and manifest

- Isolated release revision:
  `27a5064ff5501310e6c2b553a773434f4fdadfe7`.
- Clean package:
  `/opt/honeypot-packages/honeypot-release-27a5064ff5501310e6c2b553a773434f4fdadfe7.tar`.
- Package bytes: 104,939,520.
- Package SHA-256:
  `585536256f69c75264586d2b3c0e21e76a81758a348d30a2aed2c8557f9e1666`.
- Release:
  `/opt/honeypot-releases/27a5064ff5501310e6c2b553a773434f4fdadfe7`.
- Manifest:
  `/opt/honeypot-releases/27a5064ff5501310e6c2b553a773434f4fdadfe7/DEPLOYMENT_MANIFEST.json`.
- Manifest SHA-256:
  `7beb240982d5b8b26f4cfdeece598da0180ae37bc49a9719411d4cea68e77e20`.
- Release tree SHA-256:
  `7065ea5091afb8da2bb3473aeef36f0a2f83f5b5328e36438bfd4d1e0185c8f8`.
- Manifest-bound files: 534.
- Manifest schema: `honeypot_release_manifest.v7`.

Independent root verification passed twice, including after the Transformer
smoke test and after isolated cleanup. No release file was newer than manifest
finalization. No `DEPLOYED_COMMIT` marker was written to the candidate.

## 8. Immutable and mutable boundaries

Code, policies, dependency identities, model identities, the classifier MITRE
snapshot, unit templates, static assets, builder identity, and schema version
are immutable manifest inputs. Frozen model files resolve to the separately
managed owner-only model bundle, not to an older release.

CISA, Sigma, and runtime MITRE caches remain mutable non-authoritative runtime
state. Their version, file/content checksums, retrieval time, and importer
identity remain in:

`/var/lib/honeypot/feeds/runtime_feed_provenance.json`

The runtime feed-provenance receipt SHA-256 at inspection was
`a5c005fa44f92f878621568f38e1e7ccd6e3bdafd3af1b5a120f5ed91736d8e5`.
The session worker loaded stale classifier MITRE content from the frozen cache.
Its log says “refreshing”, but both worker call sites explicitly passed
`allow_network_refresh=False`; the cache was read and no release file was
modified.

## 9. Configuration and filesystem checks

The strict isolated configuration passed as the `honeypot` user:

- database and writable state were under the isolated `/var/lib/honeypot`
  tree;
- release code and model assets were read-only;
- ingest, dashboard, and monitor bound loopback-only ports 18080, 18081, and
  18090;
- production ports were not rebound;
- external enrichment profile was disabled;
- enrichment job creation was disabled;
- webhook URL and target list were empty;
- synthetic sensor tokens and the credential HMAC keyring were owner-only;
- every policy and model path resolved to the candidate or frozen bundle.

Two fail-closed setup errors were found before service startup and corrected
only in disposable isolated configuration: duplicate database path authority,
then an invalid synthetic token-map shape. Neither change affected the release
or production configuration.

## 10. Schema and historical compatibility

The isolated database stayed at schema version 3. Initialization was
idempotent, migration-ledger checksums were unchanged, and historical records
were not rewritten.

Prediction snapshot inventory:

- 61 records without an explicit snapshot schema;
- 21,655 v1 records;
- 7 v2 records;
- 94 v3 records.

All 7,198 sessions with prediction history were scanned through the canonical
selector. Six sessions had no safely selectable current record, and zero
selected v3 records had integrity errors. Invalid declared v3 snapshots sorted
last and were not selected.

Post-E2E rollback-reader compatibility was not run because the mandatory report
failure stopped the test. It remains `NOT_DETERMINABLE`.

## 11. Startup timing

The services were started as hardened transient units with `UMask=0077`,
`NoNewPrivileges=yes`, `PrivateTmp=yes`, a strict read-only filesystem, and
only the isolated state root writable.

| Service | Evidence | Classification |
|---|---:|---|
| Session worker | 26.394 s one-shot; 36.919 s to recovery-ready in the concurrent run; SecureBERT loaded at 31.035 s; 542–559 MB current memory; 0 restarts | `READY_BUT_SLOW` |
| Analysis worker | 9.183 s one-shot; 31–39 MB concurrent memory; 0 restarts | `READY_WITHIN_EXPECTED_TIME` for startup, later semantic failure |
| Enrichment worker | 8.649 s one-shot; 31 MB; 0 restarts | `READY_WITHIN_EXPECTED_TIME` |
| Threat-hunt worker | 9.028 s one-shot; 22 MB; 0 restarts | `READY_WITHIN_EXPECTED_TIME` |
| Webhook dispatcher | 8.730 s one-shot; 28 MB; 0 restarts | `READY_WITHIN_EXPECTED_TIME` |
| Ingest API | Healthy within the 34.648 s concurrent aggregate upper bound; 26 MB; 0 restarts | `READY_WITHIN_EXPECTED_TIME` |
| Dashboard API | Healthy within the 34.648 s concurrent aggregate upper bound; 28 MB; 0 restarts | `READY_WITHIN_EXPECTED_TIME` |
| Monitor web | Healthy within the 34.648 s concurrent aggregate upper bound; 25 MB; 0 restarts | `READY_WITHIN_EXPECTED_TIME` |

The aggregate all-three-HTTP-health time was 34.648 seconds. Individual first
health timestamps for the three HTTP services were not sampled independently,
so exact port-bind and first-health latency below that upper bound is
`NOT_DETERMINABLE`.

## 12. Isolated E2E results

The loopback ingest API authenticated a privacy-safe synthetic batch:

- 12 events accepted;
- an exact replay was reported as one duplicate;
- 12 events processed by the session worker;
- same-tactic repetition, changed tactics, a late source timestamp, failed
  command evidence, direct Cowrie transfer evidence, and session close were
  present;
- 11 prediction snapshots created;
- 11 prediction-outbox rows completed;
- zero prediction-generation errors;
- three threat-hunt jobs succeeded;
- four non-authoritative campaign links were recorded;
- zero alerts, zero enrichment jobs, and zero webhook payloads were associated
  with the synthetic session.

The analysis worker retried at approximately 21:05:08Z and 21:05:42Z, then
failed at approximately 21:06:50Z:

```text
status=failed
attempts=3
error=job_invalid:ValidationError
last_error_code=job_invalid
last_error_type=ValidationError
reports=0
```

The runtime intentionally redacts validation details to `operation_failed`.
No partial report or artifact was left. The exact invalid field is therefore
`NOT_DETERMINABLE` without a new isolated diagnostic run or a focused code fix,
neither of which was authorized after the stop condition.

## 13. Prediction correctness and audit context

All 11 new records used `prediction_snapshot.v3`, had unique IDs, and passed the
whole snapshot integrity validator. Statuses were `insufficient_history` or
`predicted`. The canonical selector chose the close-event snapshot, proving
the final evidence cutoff superseded earlier and late-source-time evidence.

Prediction JSON contained no `recommendations` key, plaintext credential
marker, or raw command fragments. The focused suites separately passed delayed
old-task ordering, exact immutable retry, conflicting retry rejection, equal
timestamp tie-breaking, invalid-v3 exclusion, late timestamp handling, and
current-selector sharing.

SecureBERT loaded the exact frozen checkpoint on CPU. Reviewed rule results
remained trusted phases; model-only results remained audit-only context. The
audit-context tensor tests passed and did not promote audit labels to trusted
phases.

API-versus-monitor current snapshot equivalence was not sampled before the
report stop condition and remains `NOT_DETERMINABLE` for this run.

## 14. Privacy and authority

The synthetic plaintext credential marker had zero matches in:

- the isolated SQLite database;
- the retained pre-test backup;
- isolated prediction snapshots;
- isolated service journals.

WAL/SHM files were absent after clean service stop. No report or artifact was
produced, so report/PDF/STIX privacy validation could not be completed.

Predictions produced zero alerts and zero webhook records. They did not create
recommendations or response actions. Guidance remained manual-only by policy,
but an E2E v3 guidance document could not be verified because v4 report
generation failed.

## 15. Restart and failure recovery

Not run. The report failure is an explicit stop condition and occurred before
the restart/failure-injection stage. Result: `NOT_DETERMINABLE`.

All transient units were stopped and collected. No isolated listener, process,
or unit remained after cleanup.

## 16. Rollback compatibility

The candidate was never activated. The active recovery release and its
manifest remained intact. The fresh database backup is a verified rollback
boundary.

Application-only rollback against the post-test isolated database was not
tested because the report stop condition fired first. Whether the recovery
release can accept the candidate’s post-E2E records remains
`NOT_DETERMINABLE`. Do not assume pointer rollback alone is sufficient.

## 17. Production post-check

After isolated cleanup:

- `/opt/honeypot` still resolved to
  `19afabd0bb7ed82ac93767301bb0cb1024d0b92e`;
- `DEPLOYED_COMMIT` still contained that revision;
- all eight production application services were active;
- there were zero failed units;
- ingest, dashboard, and monitor health endpoints passed;
- the production database contained zero rows for the synthetic session;
- candidate v7 manifest verification still passed;
- the verified backup and candidate package remained present;
- no Pi write, service action, or configuration change occurred.

## 18. Remaining blockers

1. Reproduce the isolated analysis `ValidationError` with validation-field
   diagnostics that contain no evidence or secrets.
2. Decide whether it is a report-contract defect, reconstructed-evidence
   defect, or fixture defect. Do not weaken v4/v3 validation.
3. Add a generalized regression and rerun the full suite.
4. Rebuild a clean manifest-bound release from the corrective commit.
5. Repeat the complete isolated E2E from a fresh verified restore.
6. Only after a report succeeds, run API/monitor equivalence, guidance,
   JSON/Markdown/PDF/STIX, restart, failure injection, and recovery-release
   compatibility checks.

## 19. Controlled activation procedure (prepared, not authorized)

Do not execute this procedure while the decision is blocked.

```sh
REVISION=27a5064ff5501310e6c2b553a773434f4fdadfe7
RELEASE=/opt/honeypot-releases/$REVISION
RECOVERY=/opt/honeypot-releases/19afabd0bb7ed82ac93767301bb0cb1024d0b92e

cd "$RELEASE"
sudo env PYTHONDONTWRITEBYTECODE=1 ./.venv/bin/python \
  -m production.tools.release_manifest verify \
  --release-root "$RELEASE" \
  --manifest "$RELEASE/DEPLOYMENT_MANIFEST.json"

sudo test "$(readlink -f /opt/honeypot)" = "$RECOVERY"
sudo test ! -e "$RELEASE/DEPLOYED_COMMIT"
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

Then verify all eight services, three health endpoints, queues, leases, exact
manifest/model/policy hashes, one controlled Pi-to-GCP session, report
artifacts, privacy, authority boundaries, and disk margin. Any failed gate must
invoke fallback.

## 20. Automatic fallback procedure (prepared, not rehearsed)

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

If the candidate introduced an incompatible database state, stop services and
restore the verified pre-activation database backup using the repository’s
`sqlite_backup_restore` tooling before starting recovery. The need for that
database restore must be established by the still-pending isolated rollback
compatibility test.

## 21. Final readiness verdict

**`BLOCKED_BY_TEST_FAILURE`**

Model compatibility and prediction persistence passed, but readiness cannot be
granted without a successful canonical analysis report and the downstream
restart/rollback checks.

## 22. Cleanup and retained evidence

Retained outside Git:

- the fresh verified database backup and manifest;
- the candidate release and owner-only package;
- the frozen model bundle and recovery package;
- the active and previous recovery releases and provenance manifests.

Removed after verification:

- transient isolated units and listeners;
- the derived restored database/test-state directory;
- transferred and local temporary Git archives;
- earlier reproducible restore-rehearsal copies whose source backups remained
  verified and retained.

The machine-readable receipt is:

`evaluation/next_tactic_isolated_deployment_readiness_20260731.json`
