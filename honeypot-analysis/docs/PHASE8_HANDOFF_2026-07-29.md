# Phase 8C handoff — 2026-07-29

## Final state

- **Active GCP release:** `bf53edf640de9f8dbfd8002d91b383e55ceb9187`
- **Active path:** `/opt/honeypot-releases/bf53edf640de9f8dbfd8002d91b383e55ceb9187`
- **Release manifest:** `/opt/honeypot/DEPLOYMENT_MANIFEST.json`
  - SHA-256: `d25c459c3f388fedd32048c83115f4af2a6e67beaa65603d5c41846530bd3b5d`
  - release-tree SHA-256: `bc0e9d6421e91d0112756a7105d38a9d7e309a9ffd525c47344a05a45dafebaf`
  - verified file count: `417`
- **Release package:**
  `/opt/honeypot-packages/honeypot-release-bf53edf640de9f8dbfd8002d91b383e55ceb9187.tar`
  - SHA-256: `c2b0d8bfe3b5d60826dcd8502500ae660b628cb53dce3a43a837b7f6e5b3fb29`
  - bytes: `103331840`; mode `0600 root:root`
- **Required rollback release:**
  `/opt/honeypot-releases/7125cd8de64afc1d60cc2920f03eb21e5c8010af`
  - rehearsed successfully during Phase 8C and then returned to the active release.
- **Immediate preceding release retained:**
  `/opt/honeypot-releases/99836617e08d41a48ba7d8350a0cfdb1331ed13b`

All eight application services are active. The expected listeners are only
`100.122.213.37:8080`, `127.0.0.1:8081`, and `127.0.0.1:8090`. The stale
calibration and prediction-retention units/timers are absent. The repaired
session-count monitor runs successfully with `UMask=0077` and an explicit
`ReadWritePaths=/var/lib/honeypot` state location.

## Phase 8C commits

| Commit | Purpose |
| --- | --- |
| `21c24b9` | Immutable frozen-model-bundle tooling |
| `ccfe9fc` | Release binding to frozen bundles |
| `1300387` | Frozen-bundle deployment documentation |
| `0160b07` | Classifier environment receipt refresh |
| `46a12b9` | Runtime receipt/model-bundle identity binding |
| `1509484` | Canonical assessment pipeline compatibility fix |
| `9983661` | Durable event-manifest preservation in primary reports |
| `bf53edf` | Fail-closed Cowrie login-message credential sanitization |

`bf53edf` is the deployed code revision. This handoff document is a separate
local documentation commit and is not part of the deployed release package.

## Frozen Transformer bundle

The runtime no longer resolves Transformer files through an old release
directory. The active release links its four Transformer paths and the
SecureBERT directory only to this owner-only immutable bundle:

`/opt/honeypot-model-bundles/frozen_model_bundle_4957a700e993c76fd94a95bb569f70b0`

- Bundle manifest SHA-256:
  `609ab334bb5c75295eee2851e2b2b6ae103ce8e0dbc6e43219da8bb5221e4419`
- Artifact-inventory SHA-256:
  `fb9804a1beb3d62f31bc1fc031a54f031ab3201c062402723b2bf748c80195c7`
- Recovery archive:
  `/opt/honeypot-model-packages/frozen_model_bundle_4957a700e993c76fd94a95bb569f70b0.tar`
  - SHA-256: `a32119bdb866b0a0c56b274ea19d4dfdc1507406eac20084a4a3916073467889`
  - bytes: `606300160`; mode `0600 root:root`
- Bundle directory mode/owner: `0700 honeypot:honeypot`; artifact files are
  `0600 honeypot:honeypot`.

Verified Transformer artefacts:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| checkpoint | 27,400 | `7fbd73c4bd071336fa52a589bf41e39f5a3122a67aee398dfb8e6dd9cfdfb04a` |
| model specification | 2,348 | `2f4ea5531ce08adbd78f53832d7a6e23ba34617549c56aa50f04d069dee6ccc6` |
| vocabulary | 2,029 | `1b46db302d2a92f80f1385e63fa01968cc23a9ce50cb77ef24f20ce8a9e494e9` |
| calibration | 813 | `528bbdd8f21d7e0a5f4446657639ccbc994b9d469876e8f026eb716e9a8d7cc9` |

The SecureBERT checkpoint SHA-256 is
`dc3a4e2a57a70c4c7cb5f769b6399f32b2b51f0245025653e0b72f6d025a759b`.
`frozen_model_bundle verify --runtime-check --smoke-test` passed against the
active release: Transformer inference returned `prediction_status=predicted`
and `predictive_alert_status=prohibited`.

The source release `97db7b495d3f4fb8c14286dff873ef5d07d0fb73` remains only
as retained recovery provenance and a preserved virtual-environment source; no
active model link resolves into it.

## Runtime feed provenance

Mutable CISA, Sigma, and MITRE caches are excluded from immutable release-file
hashes. Their separate record is:

`/var/lib/honeypot/feeds/runtime_feed_provenance.json`

It is `runtime_feed_provenance.v1`, non-authoritative context only. At final
verification, all three cache-file SHA-256 values matched the sidecar,
each status was `fresh`, and MITRE reported version `14.1`. Their importer
receipts record evaluator revision `99836617…`, because the caches were last
retrieved before the later code-only sanitization release; this is expected and
does not change their non-authoritative status.

## Backups, restore, and capacity

Required backup retained unchanged:

- `/var/backups/honeypot/phase8b-20260729T064717Z/production_pilot.db`
  - SHA-256: `c27d172420903418fcb48b142b5d1f78e8afac3dc2daa070c81eccabb5efb69b`
  - bytes: `3929804800`; `integrity_check=ok`; mode `0600 root:root`

Fresh pre-activation Phase 8C backup and isolated restore rehearsal:

- `/var/backups/honeypot/phase8c-20260729T083200Z/production_pilot.db`
  - SHA-256: `4ed779f68ff0ff89ae9fa889cf4e277764c65d6966d056366229da07eaa4ceb7`
  - bytes: `3930181632`; `integrity_check=ok`; mode `0600 root:root`
- `/var/lib/honeypot/restore-rehearsal/phase8c-20260729T083200Z/production_pilot.db`
  - isolated restored copy, bytes `3930181632`, mode `0600 root:root`

The GCP root disk is the expanded 80 GiB ext4 `/dev/sda1`; final free space was
`10853945344` bytes (about 10.1 GiB). Do not make another 3.9 GiB backup or
restore rehearsal without first obtaining additional capacity or an approved,
evidence-backed retention action.

## Pi forwarder privacy deployment

The Pi used a small legacy forwarder package outside the GCP release tree. It
had no pre-spool sanitizer. It was changed only to sanitize Cowrie credential
fields and redact every `cowrie.login.*` summary message before spool writes.

- Changed file:
  `/opt/honeypot-forwarder/production/sensor_forwarder.py`
  - SHA-256: `ebe4365e2ee045358758ef941e8cd0be018c89d6b204ebf24f7b5b9e7f15905c`
- Pi deployment receipt:
  `/var/backups/honeypot-forwarder/phase8c-20260729T093000Z/DEPLOYMENT_MANIFEST.json`
  - SHA-256: `866b427f0cba3e7956d6973452dc82c0d0410bcf22d651a12bef414ec92b5449`
- Pi rollback archive:
  `/var/backups/honeypot-forwarder/phase8c-20260729T093000Z/predeploy-forwarder.tar.gz`
  - SHA-256: `c3049e91871b904de932e23c95854cea7e1bee5a5d4b4dd797ef60e7e0074067`

The patched Pi forwarder compiled, passed a non-persistent sanitizer check,
and is active. Its durable spool was empty after the final E2E session.

## Final controlled E2E evidence

A real Cowrie session was sent through Pi → forwarder → GCP ingest → session
worker → Transformer/report path after the privacy repair.

- Session ID: `7ec29e17ba10`
- Received events: `13`; processed events: `13`
- Receipt window: `2026-07-29T09:41:43.461543+00:00` through
  `2026-07-29T09:41:45.696443+00:00`
- Pi forwarder batches: `5 + 8` sent; zero remaining spool bytes
- Analysis job: `job_2ee9813c9d89f87698661ba35e4597c1`, succeeded on attempt 1
- Report: `report_f009b626aef7918e97d67ada97f01f69`
- Assessment: `session_assessment_a8b5be465584e07c505d319e762c60c5`
- Canonical durable-event manifest: 13 events, SHA-256
  `7e955eec63233a52be293a6d18f44d107a87b641a362c9607e1453b57ebdad9e`
- Prediction snapshots: `6`; all are `prediction_snapshot.v3`, contain no
  `recommendations`, and have `predictive_alert.status=prohibited`.
- Prediction outbox: six completed entries.
- Response guidance:
  `response_guidance_v3_bf47be0e432edf7f2298e14bf31b311c`; deterministic
  observed-evidence authority; manual approval required; automatic execution,
  response actions, and alert side effects are false/prohibited.
- JSON, Markdown, PDF, STIX, and report-artifact integrity-manifest validation
  all passed.
- The report’s canonical evidence, policy hashes, evaluator revision, and all
  required Transformer/SecureBERT artefact hashes were verified. The report
  evaluator revision is `bf53edf…`.

For the repaired session, a byte-level search for its synthetic credential
found zero matches in its SQLite event/outbox/report/session/job rows, WAL,
SHM, JSON, Markdown, PDF, STIX, and integrity manifest. The Pi spool was
empty after acknowledgement. The source IP was loopback/non-external; no new
source-IP enrichment job was enqueued, and the active external-enrichment
profile is `disabled`.

## Tests and operational checks

- Focused privacy suite: `6 passed`
- Focused ingest/session/canonical-runtime suites: `32 passed`
- Full local suite: `754 passed, 7 skipped` in 12.86 seconds
- Active release manifest verification: passed
- Frozen bundle runtime/hash/smoke verification: passed
- Prediction and response-guidance policy validation: passed
- Active SQLite: `integrity_check=ok`, WAL mode, three migrations, zero
  unprocessed events, zero expired event/analysis/outbox claims.
- Session-count monitor: successful; state file mode `0600 honeypot:honeypot`.
- Rollback rehearsal: `7125cd8…` served ingest, dashboard, and monitor
  readiness; final `bf53edf…` was then restored and verified.

## Rollback commands

GCP release rollback (only with approved operational authority):

```sh
sudo ln -s /opt/honeypot-releases/7125cd8de64afc1d60cc2920f03eb21e5c8010af /opt/honeypot.phase8c-next
sudo mv -Tf /opt/honeypot.phase8c-next /opt/honeypot
sudo systemctl restart honeypot-ingest-api honeypot-session-worker honeypot-enrichment-worker honeypot-analysis-worker honeypot-dashboard-api honeypot-monitor-web honeypot-webhook-dispatcher honeypot-threat-hunt-worker
```

Then verify all three readiness endpoints and the release marker. Do not alter
the model bundle, model archive, database, feed sidecar, or backup paths.

Pi forwarder rollback (only with approved operational authority):

```sh
sudo tar -C / -xzf /var/backups/honeypot-forwarder/phase8c-20260729T093000Z/predeploy-forwarder.tar.gz
sudo systemctl restart honeypot-sensor-forwarder
```

## Remaining limitations and next steps

1. The pre-fix controlled session `f5bdecb6ce4a` has one plaintext synthetic
   credential in `events.payload_json.message` and its corresponding
   `prediction_outbox.payload_json.event.message`. It was produced before
   `bf53edf`; it remains by design because this work was explicitly forbidden
   from rewriting or deleting historical credential-bearing records.
2. Existing pre-fix backups can therefore also contain historical plaintext.
   No post-fix fresh backup/restore was created: another database-sized copy
   would reduce free disk space below the approved 10 GiB safety margin.
   Obtain capacity and explicit data-remediation approval before creating a
   sanitized replacement/backups-retention plan.
3. The final E2E’s non-authoritative `hassh` enrichment job exhausted retries
   with `LeaseExpired`. It did not affect ingest, canonical v4 assessment,
   Transformer inference, guidance, report generation, or alerts; investigate
   it before treating enrichment reliability as production-complete.
4. Startup after a full service restart can take roughly 1–2 minutes with the
   current large SQLite database. Short readiness probes may produce harmless
   BrokenPipe log entries after timing out. Long-duration load/soak testing and
   independent model validation remain outstanding.
5. The Pi forwarder is now protected and receipt-tracked, but remains a small
   legacy package rather than a manifest-bound Git release. A future scoped
   migration should make its release packaging consistent with GCP without
   changing its single-purpose architecture.

## Evidence-based readiness

| Area | Readiness |
| --- | ---: |
| Frozen model provenance and recoverability | 95% |
| Ingest, SQLite durability, and canonical assessment | 88% |
| Transformer, v4/v3 authority boundaries, and artifacts | 90% |
| Deployment/rollback operations | 82% |
| Privacy/retention | 62% |
| Controlled-PoC overall | 80% |

The lower privacy score is intentional: the new write path is verified clean,
but preserved pre-fix plaintext rows/backups and the lack of a post-fix backup
rehearsal prevent a stronger claim.

**Final status: `PARTIALLY_WORKING`**
