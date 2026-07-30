# Stabilization deployment and privacy-blocker handoff — 2026-07-30

## Outcome

The stabilization work advanced through the clean GCP release deployment and a
controlled Pi-to-GCP end-to-end test. It stopped before rollback and bounded
recovery testing because the E2E exposed a P0 privacy-boundary failure:

- the Phase 7 sanitizer removes Cowrie login credentials before forwarder spool
  and GCP persistence;
- the upstream Pi Cowrie JSON source log is written before that sanitizer and
  contains the new synthetic E2E password in plaintext;
- the Pi Cowrie checkout is heavily customized and has a dirty Git worktree, so
  an in-place output-plugin patch would not be an auditable, manifest-bound
  correction.

The raw Cowrie log was not rewritten, truncated, rotated, or deleted. No
attempt was made to hide the failure. The new GCP release remains active
because its manifest, services, database, model bundle, and report path passed
their completed checks; returning to the prior GCP release would not correct
the Pi source-log boundary.

Recommended freeze status: **BLOCKED ON PI SOURCE-LOG CREDENTIAL PRIVACY**.
The deployed pipeline is `PARTIALLY_WORKING`: analytical execution and
downstream privacy worked, but the current all-log privacy acceptance contract
did not.

## Repository and revision state

- Branch: `professor-approved-poc-evaluation`
- Plan starting revision:
  `38d1c5949e25136bb29ac3739aa9e8a6c2c6665d`
- Final deployed implementation revision:
  `325d136a35f4e9b6cf197cc05565a0798f7b3e14`
- Implementation commits created after the starting revision:
  - `110211730200f020404a8589e07682a9543630c5` —
    `Align observability tests with durable evidence reconstruction`
  - `325d136a35f4e9b6cf197cc05565a0798f7b3e14` —
    `Clarify non-authoritative and historical monitor terminology`
- This handoff is committed separately. Its SHA-1 cannot be embedded in its
  own content; use `git rev-parse HEAD` and compare the commit subject with the
  final checkpoint.
- The implementation worktree was clean before this document was added.

No AI/LLM functionality, model, semantic family, automatic response path,
historical-record rewrite, or database migration was introduced.

## Completion matrix

| Stabilization item | State | Evidence |
| --- | --- | --- |
| Alert-authority correction | completed and verified | Explicit policy and producer/webhook boundary tests passed; no E2E alert or webhook was created. |
| Neutral correlation terminology | completed and verified | Existing policy/runtime changes retained; current monitor terminology is non-authoritative. |
| Automatic-alert and webhook boundaries | completed and verified | E2E sessions created zero alerts; `webhook_deliveries` remained zero. |
| Durable fallback reconstruction | completed and verified | Stale observability fixture repaired with durable events and an exact manifest; no-event regression fails closed without artifacts. |
| Managed systemd allowlist | completed and deployed | Manifest-bound policy SHA-256 `069abe87e1b249ab9e5c5a62391eeaccce584f817becd90873e8a2a439f92644`; live validator passed. |
| Obsolete prediction-backtest timer | completed and deployed | Unit archived with rollback receipt; timer disabled and absent; no failed unit remains. |
| Frozen independent evaluation | completed and unchanged | Specification/result hash checks passed; all 33 recorded discrepancies remain. |
| Capacity prerequisite | completed | GCP disk expanded from 80 GB to 96 GB; ext4 root filesystem grew; final observed free space was `18891710464` bytes. |
| Fresh backup and isolated restore | completed and verified | Both copies have the same SHA-256 and passed schema/count/integrity verification. |
| Clean exact release | completed and verified | Git archive package, release tree, policies, configurations, units, and model bundle are manifest-bound. |
| GCP deployment and systemd hardening | completed and verified | Exact revision active; eight affected services restarted; readiness, manifest, allowlist, permissions, ports, and database checks passed. |
| Stale operational-state reconciliation | partially completed | Five long-active sessions and three failed enrichment jobs were documented without evidence rewrite. Existing operational metrics expose queues and leases. No new reconciliation policy was added in this continuation. |
| Dashboard terminology | completed and deployed | “AI Validation” and active calibration/backtest wording were replaced with generated-narrative and historical-evaluation terminology. |
| Pi-to-GCP E2E | pipeline completed; privacy acceptance failed | 25/25 events processed, two reports, 16 completed prediction outbox rows, valid v4/v3/artifacts, zero alerts/webhooks; raw Pi Cowrie source log retained plaintext synthetic credential. |
| Rollback rehearsal | not started due P0 stop | Prior release and configuration/unit receipts remain present. Safety was not claimed without rehearsal. |
| Bounded load/restart/recovery | not started due P0 stop | Existing local tests remain green; no additional production restart or load was permitted after the privacy failure. |
| Final project freeze | blocked | Requires the source-log privacy boundary, then rollback and bounded recovery acceptance. |

## Local changes and tests

### Durable observability correction

`tests/test_observability_lifecycle_phase12.py` now constructs durable session
events and an exact durable-event manifest before expecting analysis latency
and correlation logs. A nearby regression proves that a job with no durable
events reports `canonical_evidence_status=unavailable`, creates no partial
canonical record, and writes no artifacts. Runtime fail-closed reconstruction
was not weakened.

### Monitor terminology

- `production/api/monitor_web.py` uses “Generated Narrative Validation” and
  explicitly labels it non-authoritative.
- `production/api/static/monitor.html` labels calibration and backtest panels
  as historical records/evaluations and states that they have no current
  authority.
- `tests/test_phase7_operational_contracts.py` binds the revised wording.

### Test and validator results

- Exact stale test and focused fallback/observability suites: passed.
- Alert, webhook, frozen-evaluation, managed-unit, and release focus:
  `55 passed`.
- Monitor terminology focus: `21 passed`.
- Final full local suite at deployed implementation revision:
  `982 passed, 7 skipped`.
- A final sandboxed rerun produced eight expected loopback-socket
  `PermissionError` failures (`974 passed, 7 skipped, 8 failed`). Re-running
  the identical suite with local loopback socket creation permitted passed:
  `982 passed, 7 skipped in 75.86s`.
- Transformer prediction policy: passed.
- Reviewed classification policy: passed.
- Response-guidance policy: passed.
- Threat-hypothesis behavior policy: passed.
- Typed-semantic vocabulary validation: passed.
- Frozen independent evaluation specification/results SHA-256 checks: passed.
- Release systemd templates: `systemd-analyze verify` passed.
- Frozen model bundle runtime verification and non-persistent Transformer smoke
  test: passed.

The frozen evaluation metrics remain:

| Layer | Precision | Recall | F1 |
| --- | ---: | ---: | ---: |
| Classification micro | 0.461538 | 0.342857 | 0.393443 |
| Typed operations micro | 0.803571 | 0.818182 | 0.810811 |
| Eligible families micro | 1.000000 | 0.875000 | 0.933333 |
| Findings micro | 1.000000 | 0.875000 | 0.933333 |
| Guidance micro | 1.000000 | 0.166667 | 0.285714 |

All 40 frozen cases retained deterministic repeatability, persistence,
reference, artifact, abstention, and integrity checks. No label or expected
outcome was changed.

## Capacity, database backup, and restore

### Capacity change

- GCP project: `test-midterm-495611`
- Zone: `asia-southeast1-c`
- instance and boot disk: `honeypot-gcp-test`
- discovered live filesystem: ext4 on `/dev/sda1`
- requested disk size: `96GB`
- observed filesystem bytes after growth: `101199970304`
- final observed available bytes after release and E2E: `18891710464`

The production-changing capacity commands were:

```sh
gcloud compute disks resize honeypot-gcp-test \
  --project=test-midterm-495611 \
  --zone=asia-southeast1-c \
  --size=96GB --quiet
sudo /usr/sbin/parted -s -f /dev/sda resizepart 1 100%
printf 'Yes\n' |
  sudo /usr/sbin/parted ---pretend-input-tty /dev/sda resizepart 1 100%
sudo /usr/sbin/resize2fs /dev/sda1
```

The first noninteractive `parted` invocation repaired the backup GPT location
but did not resize the partition; the explicit confirmed invocation resized
partition 1. `resize2fs` then expanded the live filesystem. No cleanup was
used as a substitute for capacity.

### Verified backup

- Backup:
  `/var/backups/honeypot/stabilization-20260730T083800Z/production_pilot.db`
- Manifest:
  `/var/backups/honeypot/stabilization-20260730T083800Z/production_pilot.db.manifest.json`
- Backup bytes: `3930820608`
- Backup SHA-256:
  `818b8351925969d4d13e86160e795af1b9af30ec1dccec2414066b4b4b0f0cce`
- Mode/owner: `0600 root:root`
- SQLite `quick_check`: `ok`
- SQLite full integrity check: `ok`
- schema user version: `3`
- application table counts: matched source at backup time

### Isolated restore

- Restored database:
  `/var/lib/honeypot/restore-rehearsal/stabilization-20260730T083800Z/production_pilot.db`
- Restore SHA-256:
  `818b8351925969d4d13e86160e795af1b9af30ec1dccec2414066b4b4b0f0cce`
- Mode/owner: `0600 root:root`
- `quick_check`, full integrity check, schema version, and critical row counts:
  matched the backup.

Commands:

```sh
sudo install -d -m 0700 -o root -g root \
  /var/backups/honeypot/stabilization-20260730T083800Z \
  /var/lib/honeypot/restore-rehearsal/stabilization-20260730T083800Z

sudo env PYTHONPATH=/opt/honeypot /opt/honeypot/.venv/bin/python \
  -m production.tools.sqlite_backup_restore backup \
  --source /var/lib/honeypot/production_pilot.db \
  --destination /var/backups/honeypot/stabilization-20260730T083800Z/production_pilot.db

sudo env PYTHONPATH=/opt/honeypot /opt/honeypot/.venv/bin/python \
  -m production.tools.sqlite_backup_restore verify \
  --backup /var/backups/honeypot/stabilization-20260730T083800Z/production_pilot.db \
  --manifest /var/backups/honeypot/stabilization-20260730T083800Z/production_pilot.db.manifest.json

sudo env PYTHONPATH=/opt/honeypot /opt/honeypot/.venv/bin/python \
  -m production.tools.sqlite_backup_restore restore \
  --backup /var/backups/honeypot/stabilization-20260730T083800Z/production_pilot.db \
  --manifest /var/backups/honeypot/stabilization-20260730T083800Z/production_pilot.db.manifest.json \
  --destination /var/lib/honeypot/restore-rehearsal/stabilization-20260730T083800Z/production_pilot.db
```

This backup predates the new controlled E2E. A second post-E2E backup was not
created after the privacy failure.

## Release and deployment receipt

### Active release

- Active link target:
  `/opt/honeypot-releases/325d136a35f4e9b6cf197cc05565a0798f7b3e14`
- `DEPLOYED_COMMIT`:
  `325d136a35f4e9b6cf197cc05565a0798f7b3e14`
- Release package:
  `/opt/honeypot-packages/honeypot-release-325d136a35f4e9b6cf197cc05565a0798f7b3e14.tar`
- Package bytes: `104427520`
- Package SHA-256:
  `0ae679a7bc5eeef254feea73a01dd46d4d4204c6848a8a95a164d53e84e66c8c`
- Manifest:
  `/opt/honeypot-releases/325d136a35f4e9b6cf197cc05565a0798f7b3e14/DEPLOYMENT_MANIFEST.json`
- Manifest SHA-256:
  `362a0ea361c0b819dcdb69f2a476d67ac2d54d76fdef84302e0b86feaf950f0e`
- Release-tree SHA-256:
  `96d7f71ddb165cac3825ce6b8d4a7c9cbf618b96936353e9ebde7a519d3f73a1`
- Deployment time recorded by manifest:
  `2026-07-30T08:49:27.122249+00:00`
- Rollback release:
  `/opt/honeypot-releases/7125cd8de64afc1d60cc2920f03eb21e5c8010af`

The local-to-GCP temporary-package transport command was not retained in an
auditable local command receipt after context compaction. Its destination,
byte count, SHA-256, owner, and mode are manifest-bound above. The exact
transport command is therefore
`NOT_DETERMINABLE_FROM_RETAINED_COMMAND_RECEIPTS`.

### Frozen model bundle

- Bundle:
  `/opt/honeypot-model-bundles/frozen_model_bundle_4957a700e993c76fd94a95bb569f70b0`
- Bundle manifest SHA-256:
  `609ab334bb5c75295eee2851e2b2b6ae103ce8e0dbc6e43219da8bb5221e4419`
- Artifact inventory SHA-256:
  `fb9804a1beb3d62f31bc1fc031a54f031ab3201c062402723b2bf748c80195c7`
- Bundle package SHA-256:
  `a32119bdb866b0a0c56b274ea19d4dfdc1507406eac20084a4a3916073467889`
- SecureBERT checkpoint:
  `dc3a4e2a57a70c4c7cb5f769b6399f32b2b51f0245025653e0b72f6d025a759b`
- Transformer checkpoint:
  `7fbd73c4bd071336fa52a589bf41e39f5a3122a67aee398dfb8e6dd9cfdfb04a`
- Transformer model specification:
  `2f4ea5531ce08adbd78f53832d7a6e23ba34617549c56aa50f04d069dee6ccc6`
- Transformer vocabulary:
  `1b46db302d2a92f80f1385e63fa01968cc23a9ce50cb77ef24f20ce8a9e494e9`
- Transformer calibration:
  `528bbdd8f21d7e0a5f4446657639ccbc994b9d469876e8f026eb716e9a8d7cc9`

The new release resolves model files through this immutable bundle and does
not depend on an older release for model behavior. Its Python environment is
the retained `97db7b…/.venv`; that dependency is explicit in the release
manifest.

### Configuration/unit rollback receipt

- Directory:
  `/var/backups/honeypot/stabilization-deploy-20260730T084800Z`
- Prior active-release marker:
  `active-release.before`
- Configuration/unit archive:
  `config-and-units.before.tar.gz`
- Archive bytes: `24217`
- Archive SHA-256:
  `9a8f0e9226089760ebf014f43609463c583ebb99d959c6ee5e48bcca2f77f0f3`
- Obsolete unit archive:
  `obsolete-prediction-backtest/`
- The archive contains hashes and before/after state for the removed
  `honeypot-prediction-backtest.service` and timer.

The production-changing deployment commands were:

```sh
sudo install -o root -g root -m 0600 \
  /tmp/honeypot-release-325d136a35f4e9b6cf197cc05565a0798f7b3e14.tar \
  /opt/honeypot-packages/honeypot-release-325d136a35f4e9b6cf197cc05565a0798f7b3e14.tar
sudo install -d -o root -g root -m 0755 \
  /opt/honeypot-releases/325d136a35f4e9b6cf197cc05565a0798f7b3e14
sudo tar -xf \
  /opt/honeypot-packages/honeypot-release-325d136a35f4e9b6cf197cc05565a0798f7b3e14.tar \
  -C /opt/honeypot-releases/325d136a35f4e9b6cf197cc05565a0798f7b3e14
sudo ln -s /opt/honeypot-releases/97db7b495d3f4fb8c14286dff873ef5d07d0fb73/.venv \
  /opt/honeypot-releases/325d136a35f4e9b6cf197cc05565a0798f7b3e14/.venv
sudo env PYTHONPATH=/opt/honeypot-releases/325d136a35f4e9b6cf197cc05565a0798f7b3e14 \
  /opt/honeypot-releases/325d136a35f4e9b6cf197cc05565a0798f7b3e14/.venv/bin/python \
  -m production.tools.frozen_model_bundle install-release-links \
  --release-root /opt/honeypot-releases/325d136a35f4e9b6cf197cc05565a0798f7b3e14 \
  --bundle-root /opt/honeypot-model-bundles/frozen_model_bundle_4957a700e993c76fd94a95bb569f70b0
```

Repository unit templates for the analysis, dashboard, enrichment,
feed-refresh service/timer, ingest, monitor, session-count service/timer,
session worker, threat-hunt, and webhook services were installed with:

```sh
sudo install -o root -g root -m 0644 \
  /opt/honeypot-releases/325d136a35f4e9b6cf197cc05565a0798f7b3e14/deployment/systemd/UNIT \
  /etc/systemd/system/UNIT
```

The obsolete timer was archived through the reviewed entrypoint:

```sh
sudo /opt/honeypot-releases/325d136a35f4e9b6cf197cc05565a0798f7b3e14/deployment/systemd/reconcile-obsolete-units.sh \
  archive \
  /var/backups/honeypot/stabilization-deploy-20260730T084800Z/obsolete-prediction-backtest
```

The expanded manifest-creation command is retained in the GCP sudo journal and
binds all files enumerated in `DEPLOYMENT_MANIFEST.json`. Activation was:

```sh
sudo ln -s \
  /opt/honeypot-releases/325d136a35f4e9b6cf197cc05565a0798f7b3e14 \
  /opt/honeypot.stabilization-next
sudo mv -Tf /opt/honeypot.stabilization-next /opt/honeypot
sudo systemctl daemon-reload
sudo systemctl restart \
  honeypot-ingest-api.service \
  honeypot-session-worker.service \
  honeypot-enrichment-worker.service \
  honeypot-analysis-worker.service \
  honeypot-dashboard-api.service \
  honeypot-monitor-web.service \
  honeypot-webhook-dispatcher.service \
  honeypot-threat-hunt-worker.service
```

The short five-second readiness probes raced the expected 1–2 minute
large-SQLite startup and produced client-disconnect/BrokenPipe diagnostics.
Later 45-second probes passed: ingest immediately, dashboard in about 9.1
seconds, and monitor in about 8.9 seconds.

All deployed managed application services reported:

- `UMask=0077`
- intended `User=honeypot`, `Group=honeypot`
- `NoNewPrivileges=yes`
- `PrivateTmp=yes`
- `ProtectSystem=full`
- explicit `/var/lib/honeypot` write access

There were no failed systemd units and no unknown enabled honeypot unit after
deployment.

## Controlled E2E

The test used two real Cowrie sessions through the Pi sensor forwarder into the
GCP ingest/session/prediction/report path.

### Direct SFTP transfer session

- Session: `a6a7162440a5`
- Events: `7 received`, `7 distinct`, `7 processed`
- Direct Cowrie event: `cowrie.session.file_upload`
- Uploaded object SHA-256:
  `1aeec0d362dfaa2cb79846b1a9325678b7788b41870a397544df3751585634a9`
- Analysis job:
  `job_037c0c526e4a4586f4677064fe87a2c0`, succeeded on attempt 1
- Report:
  `report_0e1bb7647c8ac7b59e81f76297456564`
- Prediction snapshots/outbox: `4`, all completed
- Conservative semantic result: the exact transfer/hash observation is
  canonical, but the Cowrie-internal destination path is relative and
  unresolved, so no specialized finding, hypothesis, or guidance was emitted.

### Command session

- Session: `a061dcd61768`
- Events: `18 received`, `18 distinct`, `18 processed`
- Commands covered:
  - `uname -a`
  - failed read of an absolute SSH private-key path
  - `wget` transfer attempt to a reserved invalid DNS name
  - shell redirect creating `/tmp/stabilization-note`
  - `/bin/sh /tmp/stabilization-stage` execution attempt
  - malformed trailing pipeline
  - compound inspection and deletion command
- Direct redirect-content Cowrie event SHA-256:
  `f379ccb92b9116442dc65bdc35648a85d3786b34779db7f704a901fa07b00cb6`
- Analysis job:
  `job_a88e664c08108906079da7f276591251`, succeeded on attempt 1
- Report:
  `report_931d6e976987b9525afb9fc2b4d79213`
- Prediction snapshots/outbox: `12`, all completed
- All prediction snapshots were `prediction_snapshot.v3`, contained no
  `recommendations`, and retained
  `predictive_alert.status=prohibited`.
- Unknown outcomes did not create successful real-host effects. No specialized
  finding or threat hypothesis was emitted. The only guidance was generic
  observed-source corroboration, manual-only and non-executable.

Across both sessions:

- `25/25` events arrived once and were processed;
- two analysis reports succeeded;
- 16 prediction outbox rows completed;
- zero alerts were created for the sessions;
- total webhook deliveries remained zero;
- `session_assessment.v4` validation passed;
- `response_guidance.v3` validation passed;
- JSON, Markdown, native PDF, STIX, and integrity-manifest validation passed;
- every artifact was owner-only mode `0600`;
- the reports record evaluator revision `325d136…`, exact durable-event
  manifests, exact policy hashes, exact model hashes, and valid typed semantic
  provenance;
- v3 safety fields prohibit alert side effects, automatic execution, and
  response-action side effects and require manual approval.

HAProxy remained:

```text
bind 0.0.0.0:2222
server pi_cowrie 100.118.43.30:2224 send-proxy
```

Live HAProxy configuration SHA-256:
`c2654f4919bbac3be86a50161c7f47815187a17713baa5c4117340a0d34781f4`.
The Pi Cowrie configuration SHA-256 was
`0aca806473d7b64106aebe96161d63588d8587333e3a6a798e3be15cfcb0a6a6`
and contains:

```text
listen_endpoints = tcp:22:interface=0.0.0.0 haproxy:tcp:2224:interface=100.118.43.30
```

UFW continues to allow port 2224 on `tailscale0` only from GCP
`100.122.213.37`. The controlled E2E used the Pi's direct private listener, so
source handling is configuration- and existing-test-verified, not a new
external-origin PROXY observation.

## Privacy evidence and blocker

### Boundaries that passed

- Pi forwarder:
  `/opt/honeypot-forwarder/production/sensor_forwarder.py`
- Forwarder SHA-256:
  `ebe4365e2ee045358758ef941e8cd0be018c89d6b204ebf24f7b5b9e7f15905c`
- Pi deployment receipt SHA-256:
  `866b427f0cba3e7956d6973452dc82c0d0410bcf22d651a12bef414ec92b5449`
- Pi rollback archive SHA-256:
  `c3049e91871b904de932e23c95854cea7e1bee5a5d4b4dd797ef60e7e0074067`
- Forwarder remained active and hardened with `UMask=0077`,
  `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectSystem=full`, and an explicit
  `/var/lib/honeypot-forwarder` write path.
- Spool data was fully acknowledged; only the private lock and offset files
  remained.
- Synthetic username/password markers were absent from the forwarder spool.
- Login username, password, and message were redacted in new SQLite events.
- The synthetic markers were absent from SQLite DB/WAL/SHM bytes and both
  sessions' report artifacts.
- No application service emitted the password marker.

### Boundary that failed

The Pi file:

```text
/home/cowrie/cowrie/var/log/cowrie/cowrie.json
```

contains the synthetic E2E password because Cowrie's JSON output plugin writes
the `cowrie.login.*` event before the forwarder can call the shared sanitizer.
This is not a false positive: the exact marker was matched. The file is the
forwarder's configured authoritative source.

The repository's Phase 7 acceptance contract promised sanitization before
spool and SQLite; it did not claim pre-source-log redaction. The resumed
stabilization acceptance explicitly requires credential plaintext to be absent
from logs as well, so the current system cannot satisfy it.

The live Cowrie checkout at `/home/cowrie/cowrie` is based on revision
`575146bc6b24d70082527d66cd805d9bae0e0db4` but contains numerous tracked
modifications and untracked deployment/honeyfs files. Modifying
`src/cowrie/output/jsonlog.py` or `src/cowrie/core/output.py` in place would
create another undocumented overlay and would violate clean packaging,
manifest, rollback, and historical-evidence boundaries.

The first privacy probe also passed the synthetic marker literally in a
privileged `grep` command. `sudo` consequently recorded that command in two
GCP journal messages. A follow-up origin check proved both matches came from
`sudo` in the operator session, not honeypot application services. Those
journal messages were not removed. Future privacy acceptance must load the
test credential and scanner pattern from owner-only files or standard input
so the verification procedure does not put the marker in command arguments.

No raw Cowrie log, GCP journal, historical row, backup, or artifact was
rewritten to conceal these results.

## Operational state at stop

- Active GCP release: `325d136…`
- Deployed marker: `325d136…`
- Available root bytes: `18891710464`
- GCP failed units: none
- App services: all expected services active after readiness convergence
- Events before E2E: `49571`
- Controlled E2E events: `25`
- Controlled E2E reports: `2`
- Controlled E2E prediction snapshots/outbox completions: `16/16`
- Controlled E2E alerts: `0`
- Total webhook deliveries: `0`
- Database `quick_check` and full integrity check after deployment: `ok`
- Existing stale state retained unchanged:
  - five sessions active for weeks;
  - three failed enrichment jobs;
  - no queued authoritative analysis/prediction work at the last check;
  - active worker leases were valid.

The runtime feed sidecar remained
`runtime_feed_provenance.v1`, explicitly non-authoritative, with its previously
verified cache SHA-256. Mutable feed caches remain outside release-tree
identity.

## Rollback boundaries

Local implementation rollback is additive and should not rewrite history:

```sh
git revert 325d136a35f4e9b6cf197cc05565a0798f7b3e14
git revert 110211730200f020404a8589e07682a9543630c5
```

The GCP rollback inputs are present:

- prior release:
  `/opt/honeypot-releases/7125cd8de64afc1d60cc2920f03eb21e5c8010af`
- predeployment configuration/unit archive:
  `/var/backups/honeypot/stabilization-deploy-20260730T084800Z/config-and-units.before.tar.gz`
- fresh verified SQLite backup:
  `/var/backups/honeypot/stabilization-20260730T083800Z/production_pilot.db`

The requested rollback rehearsal was deliberately not started after the P0
privacy stop. Database compatibility, unit restoration ordering, and
round-trip return to `325d136…` are therefore
`NOT_DETERMINABLE_FROM_COMPLETED_ACCEPTANCE`. Do not claim or perform a
rollback from this handoff without first re-verifying the active release,
manifest, database integrity, unit receipt, disk margin, and service set.

Pi forwarder rollback remains:

```sh
sudo tar -C / -xzf \
  /var/backups/honeypot-forwarder/phase8c-20260729T093000Z/predeploy-forwarder.tar.gz
sudo systemctl restart honeypot-sensor-forwarder
```

It was not run because the forwarder sanitizer worked and reverting it would
reintroduce plaintext into the spool/GCP path.

## Readiness recalculation

These are bounded estimates, not test-coverage percentages. They retain
penalties for weak independent classification results, long-term observation,
privacy compliance, the unperformed rollback/load exercises, external model
validation, and the absence of a new external-origin source-IP test.

| Readiness dimension | Before this continuation | At P0 stop | Confidence | Main evidence/cap |
| --- | ---: | ---: | --- | --- |
| Local implementation completeness | 88% | 94% | high | Full suite green; stale test and terminology corrected; no local known failing test. |
| Controlled PoC readiness | 80% | 84% | medium | Real 25-event E2E and all artifacts passed; raw source-log privacy and no rollback/load cap the score. |
| Thesis presentation readiness | 84% | 88% | medium | Traceable release and honest independent metrics improve demonstrability; privacy limitation must be disclosed. |
| Isolated deployment readiness | 82% | 90% | high | Capacity, backup/restore, clean release, manifests, model bundle, and systemd hardening passed. |
| Current deployed-system readiness | 80% | 84% | medium | Services and real pipeline passed; Pi raw log, stale operational records, and startup latency remain. |
| Production acceptance readiness | 68% | 70% | medium-low | No credit for unrun rollback/load/soak; privacy requirement failed. |

Subsystem estimates:

| Subsystem | Readiness |
| --- | ---: |
| Pi collection/forwarding | 70% |
| GCP ingest and SQLite durability | 91% |
| Canonical reconstruction/classification | 82% |
| Typed semantics and `session_assessment.v4` | 86% |
| Transformer prediction/provenance | 83% |
| `response_guidance.v3` and alert authority | 93% |
| Reports, JSON/Markdown/PDF/STIX, API/monitor | 90% |
| Deployment, backup, and manifest operations | 88% |
| Rollback/load/recovery operations | 62% |
| Privacy/retention compliance | 54% |
| Overall controlled system | 78% |

The overall controlled-system score is lower than the narrow PoC demonstration
score because privacy compliance is a hard boundary rather than a cosmetic
limitation.

## Supported thesis claims

The evidence supports these bounded claims:

- the modular-monolith pipeline can durably forward and deduplicate Cowrie
  events, reconstruct the complete session, and generate deterministic
  canonical reports;
- Cowrie evidence is authoritative while SecureBERT mappings, Transformer
  prediction, enrichment, and correlation remain contextual;
- six typed-semantic families are active:
  `sensitive_read`, `transfer`, `transfer_attempt`, `inspection`,
  `filesystem`, and `execution`;
- uncertain, failed, malformed, or unresolved operations abstain from
  specialized findings and guidance;
- v4 findings/hypotheses and v3 guidance are integrity- and
  provenance-bound;
- v3 guidance is advisory, manual-only, non-executable, and independent of
  prediction;
- no automatic alert, webhook, actor claim, or response action was produced by
  the controlled E2E;
- the GCP release, policies, units, model bundle, backup, and isolated restore
  are hash-verifiable.

The evidence does **not** support:

- a claim that plaintext credentials are absent from all Pi logs;
- production-grade classification accuracy;
- general Internet source-IP preservation from a new external-origin test;
- completed rollback safety;
- bounded-load, restart, lock, saturation, or spool-recovery performance at
  production scale;
- long-term operational reliability, privacy compliance, external model
  validity, or enterprise readiness.

## Exact next stabilization step

Do not resume rollback, load, or final-freeze testing first. The dependency
order is:

1. Design a repository-owned, versioned Cowrie JSON output boundary that
   sanitizes `cowrie.login.*` username, password, and summary message before
   the first durable log write.
2. Preserve the existing raw log and all historical records unchanged.
3. Package the output component and its supported Cowrie-version identity in a
   clean, immutable Pi release or plugin bundle; do not patch the dirty Cowrie
   checkout in place.
4. Bind exact code/config hashes, owner-only permissions, installation steps,
   and a rollback archive in a Pi deployment manifest.
5. Add tests proving:
   - credential redaction occurs before JSON log persistence;
   - non-login Cowrie evidence is lossless;
   - event/session IDs, timestamps, source addresses, commands, transfer
     hashes, and close events are unchanged;
   - the forwarder sanitizer remains a defense-in-depth second boundary;
   - malformed events fail closed without leaking their raw values;
   - log rotation/restart does not bypass sanitization.
6. Run a new controlled credential test using owner-only credential/pattern
   files or standard input, never a privileged command-line literal.
7. Verify the new marker is absent from the new Cowrie source log, spool,
   transport-side application logs, SQLite/WAL/SHM, reports, artifacts, and a
   capacity-approved post-test backup.
8. Only then resume:
   - rollback to `7125cd8…` and return to the exact new release;
   - bounded isolated load/restart/retry/recovery testing;
   - final current-state matrix, readiness scoring, and project freeze.

## First checks for the next session

Local:

```sh
cd /home/rubchek/Desktop/teammate-repo/honeypot-analysis
git branch --show-current
git rev-parse HEAD
git status --short
git log -8 --oneline
pytest -q
```

GCP, read-only:

```sh
readlink -f /opt/honeypot
cat /opt/honeypot/DEPLOYED_COMMIT
sha256sum /opt/honeypot/DEPLOYMENT_MANIFEST.json
df -B1 /
systemctl --failed
```

Pi, read-only:

```sh
sha256sum \
  /opt/honeypot-forwarder/production/sensor_forwarder.py \
  /var/backups/honeypot-forwarder/phase8c-20260729T093000Z/DEPLOYMENT_MANIFEST.json
systemctl is-active cowrie.service honeypot-sensor-forwarder.service
git -C /home/cowrie/cowrie status --short
```

Safety conditions before continuing:

- no deletion, truncation, rewrite, or rotation solely to conceal the source
  log finding;
- no in-place patch to the dirty Cowrie checkout;
- clean manifest-bound installation and rollback evidence;
- at least 10 GiB free on GCP before any new database-sized backup/restore;
- exact GCP and Pi revisions/hashes reverified;
- no automatic alert, response, or authority expansion;
- full focused and feasible suites green;
- credential verification inputs kept out of privileged process arguments and
  operator journals.
