# Stabilization rollback-compatibility blocker handoff — 2026-07-30

## Outcome and stop condition

Part 1 stopped at the mandatory isolated rollback-compatibility gate. Part 2
(the next-tactic runtime and coverage review) was not started.

The new release candidate is clean, manifest-bound, and passes its isolated
compatibility checks. The required rollback target
`325d136a35f4e9b6cf197cc05565a0798f7b3e14` is not eligible as a known-good
rollback target: its monitor cannot decode existing JSON-backed historical
feedback rows. Exact isolated replay fails with:

```text
NameError: name 'json' is not defined
```

The failure originates in
`production/reporting/feedback_review.py::_json_value`, which calls
`json.loads` and catches `json.JSONDecodeError` without importing `json`.
Workers can start and read schema v3, but the historical monitor reader fails.
This violates the explicit rollback acceptance requirement that historical
records remain readable.

The active GCP release was not switched. No service was restarted. No
production database row, configuration, unit, timer, release pointer, secret,
network rule, backup, model artifact, runtime feed, or Pi file was changed.

## Repository checkpoint

- Branch: `professor-approved-poc-evaluation`
- HEAD at this handoff before adding this document:
  `6964d54326ba59a51cffb2f0d13d9a5b1bd858f2`
- Worktree before adding this document: clean
- Starting HEAD:
  `111872e7132bf37e3635964e4df01246eadbb65d`

Implementation commits created in this continuation:

1. `21f6d99d17d14e10327ad28236ff037d8e93e956` —
   `Separate runtime state from release identity`
2. `bd802c2f30bf02873f886b347ba3033c4dfb6e6c` —
   `Bind the frozen classifier MITRE snapshot explicitly`
3. `6964d54326ba59a51cffb2f0d13d9a5b1bd858f2` —
   `Restore JSON-backed feedback review decoding`

## Change classification relative to `325d136…`

| Class | Files and effect |
| --- | --- |
| GCP runtime | `production/utils/sensitive_data.py` shares the reviewed credential sanitizer; `production/reporting/feedback_review.py` now imports `json`. The latter is required by the current database's historical feedback rows. |
| Pi-only runtime | `production/cowrie_output/`, `production/utils/cowrie_privacy.py`, and `configs/cowrie_output_privacy.v1.json` implement the already deployed pre-persistence Cowrie credential boundary. |
| Pi deployment tooling | `deployment/cowrie_output/` contains the reviewed install, startup, validation, and rollback integration. |
| GCP deployment tooling | `production/tools/release_manifest.py` adds schema v6 and a hash-bound immutable-identity exclusion contract. |
| Tests/evaluation | `tests/test_cowrie_output_privacy.py`, `tests/test_release_manifest.py`, and `tests/test_feedback_review.py` cover the new boundaries and the discovered reader defect. Frozen evaluation labels/results did not change. |
| Documentation/handoff | Cowrie privacy decisions, deployment instructions, and stabilization handoffs were added or updated. |
| Configuration/systemd | No GCP production configuration or systemd template changed relative to `325d136…`. The managed unit policy hash remains unchanged. |

The reviewed HEAD is suitable as a new GCP application release, but it cannot
be activated until a separate eligible rollback release exists.

## Manifest boundary correction

`honeypot_release_manifest.v6` excludes environment-derived runtime state:

- `__pycache__`, `.pyc`, and `.pyo`;
- common test/tool caches;
- temporary/editor/host-created files;
- databases, WAL/SHM, logs, spool, reports, and runtime-state directories;
- mutable CISA, Sigma, and MITRE feed basenames.

The exclusion policy itself is recorded in
`release_identity.policy_id=immutable_source_release.v2` and is strictly
validated. Historical v2-v5 manifests retain their prior inventory semantics.
An exact v5 compatibility regression passes.

The clean source package omits the Git-retained CISA and Sigma cache
snapshots. It retains only `data/feeds/mitre_attack_cache.json` because the
frozen SecureBERT classifier-environment receipt independently requires its
exact historical classifier snapshot. It is not the effective mutable
production MITRE feed and is separately bound as:

```text
model_artifacts.classifier_mitre_snapshot
SHA-256 33af47bb0a3475cda60c2bea83ce305244bd747021f9e999652dc21520e4e35c
```

A regression proves that an excluded file can still be fail-closed when it is
separately declared as an immutable artifact.

## Local validation

At exact implementation HEAD `6964d543…`:

- full suite: `1001 passed, 7 skipped in 75.61s`;
- focused release-manifest suite: `11 passed`;
- focused feedback/monitor suite: `26 passed`;
- focused production/report/model suite: `32 passed`;
- prediction policy: valid;
- reviewed classification policy: valid;
- response-guidance v3 policy: valid;
- threat-hypothesis behavior policy: valid;
- alert-authority policy: valid;
- data-lifecycle policy: valid;
- typed-semantic vocabulary: valid;
- frozen 40-case specification SHA-256: valid;
- frozen 40-case result SHA-256: valid.

The seven local skips are the documented absence of optional ReportLab,
PyTorch, and the private checkpoint on the local workstation. These paths
were exercised successfully with the deployed dependency environment during
the isolated GCP rehearsal.

## Staged exact release candidate

The following candidate is staged but **not active**:

- revision:
  `6964d54326ba59a51cffb2f0d13d9a5b1bd858f2`;
- release:
  `/opt/honeypot-releases/6964d54326ba59a51cffb2f0d13d9a5b1bd858f2`;
- package:
  `/opt/honeypot-packages/honeypot-release-6964d54326ba59a51cffb2f0d13d9a5b1bd858f2.tar`;
- package SHA-256:
  `4d18523f453cad374b0e6f62d6985622e5610ba632b15ea3275c500c15b411f1`;
- manifest:
  `/opt/honeypot-releases/6964d54326ba59a51cffb2f0d13d9a5b1bd858f2/DEPLOYMENT_MANIFEST.json`;
- manifest SHA-256:
  `53034d572ee9593f28840f111293fd1f7db4be439e6990b7b8658d6cb468f770`;
- manifest schema: `honeypot_release_manifest.v6`;
- immutable file count: `512`;
- release-tree SHA-256:
  `0cfe15d6971aebfb8e632bc3bf2c0506dc1a776e488881c84d3bc12022d3a157`;
- manifest verification after all rehearsal cleanup: passed;
- recorded rollback location:
  `/opt/honeypot-releases/325d136a35f4e9b6cf197cc05565a0798f7b3e14`.

That rollback location must be replaced by a verified recovery target before
activation. Do not edit the staged manifest in place. Rebuild the candidate
staging directory and manifest from the same exact package after the recovery
target is selected.

Frozen model evidence:

- bundle:
  `/opt/honeypot-model-bundles/frozen_model_bundle_4957a700e993c76fd94a95bb569f70b0`;
- bundle manifest SHA-256:
  `609ab334bb5c75295eee2851e2b2b6ae103ce8e0dbc6e43219da8bb5221e4419`;
- artifact inventory SHA-256:
  `fb9804a1beb3d62f31bc1fc031a54f031ab3201c062402723b2bf748c80195c7`;
- SecureBERT checkpoint SHA-256:
  `dc3a4e2a57a70c4c7cb5f769b6399f32b2b51f0245025653e0b72f6d025a759b`;
- Transformer checkpoint SHA-256:
  `7fbd73c4bd071336fa52a589bf41e39f5a3122a67aee398dfb8e6dd9cfdfb04a`;
- runtime verification and non-persistent Transformer smoke: passed;
- predictive-alert status in smoke result: `prohibited`;
- SecureBERT load and deterministic fixed-input smoke: passed;
- native ReportLab PDF byte-determinism check: passed, two 2,406-byte
  outputs with SHA-256
  `c8fbc24e7a5b658a8b46bb5590deddf9051e0d293ed9b05f0a95a1acced16242`.

Runtime feed state remained separate and unchanged:

- provenance record SHA-256:
  `a5c005fa44f92f878621568f38e1e7ccd6e3bdafd3af1b5a120f5ed91736d8e5`;
- CISA cache SHA-256:
  `a6cd79a142d3ea796075544162657442bf4bdd481465280bd6b09f63eb9a7923`;
- Sigma cache SHA-256:
  `8c122c50e61a29b2ddac21aaf6aeff448d0650b90736a5a1ed8bf989ed1180c1`;
- mutable MITRE cache SHA-256:
  `297989241716febeefdb8e47f1e56d1a046f66ee9838f2c45c7f6b9454a2b379`.

## Isolated compatibility results

The rehearsal used a private copy of:

```text
/var/backups/honeypot/stabilization-20260730T083800Z/production_pilot.db
```

Backup and copy SHA-256 were both:

```text
818b8351925969d4d13e86160e795af1b9af30ec1dccec2414066b4b4b0f0cce
```

The isolated directory, owner-only credential-keyring copy, logs, generated
PDFs, API response files, and database copy were removed after testing.
Temporary loopback ports `18082` and `18083` are no longer listening.

### Candidate `6964d543…`

Passed:

- SQLite `quick_check` and full `integrity_check`;
- schema `user_version=3`;
- session, analysis, enrichment, threat-hunt, and webhook one-shot startup;
- `0` queued items processed and `0` webhook deliveries attempted;
- SecureBERT and all required local feed assets loaded;
- Transformer runtime identity and non-persistent inference;
- ingest and dashboard loopback health;
- monitor `--check`;
- latest prediction API read;
- JSON-backed feedback review of `121` historical feedback rows;
- deterministic native PDF generation;
- no schema migration or authoritative-row rewrite.

Final isolated core counts remained:

```text
events=49571
sessions=7435
reports=6936
alerts=31611
webhook_deliveries=0
schema_migrations=3
```

### Required rollback `325d136…`

Passed:

- exact v5 manifest verification:
  manifest SHA-256
  `362a0ea361c0b819dcdb69f2a476d67ac2d54d76fdef84302e0b86feaf950f0e`;
- release-tree SHA-256
  `96d7f71ddb165cac3825ce6b8d4a7c9cbf618b96936353e9ebde7a519d3f73a1`;
- schema-v3 read;
- SecureBERT and local feed load;
- session, analysis, enrichment, threat-hunt, and webhook one-shot startup;
- no queued work and no external delivery.

Failed:

- monitor historical-reader check, exit `1`;
- JSON-backed feedback decoding, with the exact `NameError` above.

Therefore `325d136…` is **not** a verified known-good operational rollback
target. It was not activated during this continuation.

## Historical `7125cd8…` status

`7125cd8de64afc1d60cc2920f03eb21e5c8010af` remains:

```text
historical archived release
not eligible for operational rollback
```

The v6 verifier exits `1` with:

```text
ValueError: deployed release files do not match manifest
```

Its preserved v2 manifest SHA-256 is
`ed341968e214d44930e4f660b9041df72fe707987ad635be51d5a8b272533ab6`.
No bytecode was recreated, no byte or manifest was edited, and the release was
not activated or deleted.

## Final live state

GCP remains:

- active release and `DEPLOYED_COMMIT`:
  `325d136a35f4e9b6cf197cc05565a0798f7b3e14`;
- all eight application services active;
- feed-refresh and session-count timers active;
- no failed unit;
- free root bytes: `18,681,417,728`;
- SQLite size: `3,932,856,320` bytes, mode `0600`, owner
  `honeypot:honeypot`;
- WAL: `0` bytes; SHM: `32,768` bytes;
- final full SQLite integrity check: `ok`;
- all `49,617` events processed;
- sessions: `7,434` ended, `5` active/stale;
- analysis jobs: `6,940 succeeded`;
- enrichment jobs: `186 succeeded`, `5 failed`;
- prediction outbox: `60 completed`;
- threat-hunt jobs: `13,856 succeeded`;
- webhook deliveries: `0`;
- one current session-worker lease.

Pi remained at:

- active sanitizer release:
  `7f764ab471e8dac555d06277b4613237299aee69`;
- manifest SHA-256:
  `714d04608d7385490000edef2effddbdad948fd065820e35fdebef29ada0f39d`;
- Cowrie privacy policy SHA-256:
  `439c11f1f88da9873be9ab62ab7f4ae98a7b8a7c73116362a5f4c7a20d47cf76`;
- unsafe Cowrie JSON output disabled;
- sanitized output and forwarder active;
- post-fix authentication events with plaintext credentials: `0`;
- spool absent/empty;
- no Pi service, configuration, firewall, or file was modified.

## Work deliberately not performed

Because the rollback gate failed:

- the candidate was not activated;
- no live rollback or return rehearsal occurred;
- stale sessions and terminal enrichment jobs were not reconciled;
- bounded lock/WAL/lease/restart/spool recovery testing was not continued;
- no production service restart occurred;
- no final credential-marker E2E/privacy replay occurred;
- no final freeze report was claimed;
- Part 2 next-tactic analysis was not started.

## Readiness at this stop

These are evidence-weighted judgments, not test-coverage percentages:

| Dimension | Readiness | Confidence | Limitation |
| --- | ---: | --- | --- |
| Local implementation | 97% | high | Full suite and direct regressions pass; external independent review is incomplete. |
| Candidate isolated deployment | 94% | high | Candidate package, models, readers, PDF, workers, and manifest pass; activation is intentionally blocked. |
| Current deployed system | 88% | medium-high | Active release and data remain healthy, but the live monitor contains the verified feedback-reader defect. |
| Controlled PoC | 90% | medium-high | Prior E2E/privacy evidence remains; final post-candidate replay was not reached. |
| Rollback and recovery | 50% | high | Required `325d…` rollback reader fails; bounded recovery and live round-trip remain incomplete. |
| Production acceptance | 72% | medium | No safe operational rollback, final recovery batch, final privacy replay, soak, or independent model validation. |
| Overall controlled system | 84% | medium-high | Core pipeline remains healthy; the mandatory rollback topology is unresolved. |

## Exact next step and safety gate

Do not activate `6964d543…` and do not start the next-tactic review yet.

The next session must first obtain approval to change the rollback topology.
The smallest evidence-supported option is:

1. Create a separate recovery branch from exact `325d136…`.
2. Cherry-pick only the descriptive feedback-reader fix
   `6964d54326ba59a51cffb2f0d13d9a5b1bd858f2` (the commit contains the
   missing import and its generalized historical-row tests).
3. Run the complete suite and all authority/policy validators on that exact
   recovery commit.
4. Build a separate clean, manifest-bound recovery release.
5. Rehearse it against a new isolated restore with all external delivery
   disabled.
6. Require monitor, dashboard, historical readers, models, schema, units, and
   no-side-effect checks to pass.
7. Rebuild the staged `6964d543…` release directory and v6 manifest from its
   unchanged exact package, recording the verified recovery release—not
   `325d136…`—as `rollback_location`.
8. Only then consider candidate activation, a bounded rollback/return
   rehearsal, remaining recovery checks, and final privacy E2E.

This topology differs from the originally intended exact-`325d…` rollback and
must not be assumed authorized merely because it is technically feasible.

First checks for the next session:

```sh
cd /home/rubchek/Desktop/teammate-repo/honeypot-analysis
git branch --show-current
git rev-parse HEAD
git status --short
git log -4 --oneline
pytest -q tests/test_release_manifest.py tests/test_feedback_review.py
pytest -q
```

Then read-only verify:

```sh
readlink -f /opt/honeypot
cat /opt/honeypot/DEPLOYED_COMMIT
sudo -u root /opt/honeypot/.venv/bin/python \
  -m production.tools.release_manifest verify \
  --manifest /opt/honeypot/DEPLOYMENT_MANIFEST.json \
  --release-root /opt/honeypot
```

Rollback boundaries for local implementation commits, if explicitly chosen:

```sh
git revert 6964d54326ba59a51cffb2f0d13d9a5b1bd858f2
git revert bd802c2f30bf02873f886b347ba3033c4dfb6e6c
git revert 21f6d99d17d14e10327ad28236ff037d8e93e956
```

The staged candidate can be removed only after confirming it is not active:

```sh
test "$(readlink -f /opt/honeypot)" != \
  /opt/honeypot-releases/6964d54326ba59a51cffb2f0d13d9a5b1bd858f2
sudo rm -rf -- \
  /opt/honeypot-releases/6964d54326ba59a51cffb2f0d13d9a5b1bd858f2
sudo rm -f -- \
  /opt/honeypot-packages/honeypot-release-6964d54326ba59a51cffb2f0d13d9a5b1bd858f2.tar
```

Do not run those removal commands merely as routine cleanup; the verified
staging package is useful recovery evidence.

`NOT_DETERMINABLE` at this stop:

- whether an approved replacement rollback release will pass live
  rollback/return rehearsal;
- bounded production restart/retry/recovery behavior after candidate
  activation;
- final post-candidate Pi-to-GCP privacy/E2E acceptance;
- stale-session and failed-enrichment operational disposition;
- long-term soak behavior, independent privacy compliance, and external model
  validity;
- all Part 2 next-tactic runtime/coverage questions, because Part 2 was
  correctly not started.
