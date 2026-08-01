# Next-tactic controlled production activation

## 1. Executive decision

Decision: **`FALLBACK_COMPLETED_AFTER_ACTIVATION_FAILURE`**.

The verified next-tactic candidate was activated atomically, passed its GCP
identity, startup, health, database, queue, canonical-analysis, prediction,
artifact, API/monitor, GCP privacy, and authority gates, and processed one
controlled Pi-to-GCP Cowrie session successfully. The overall privacy gate then
failed on the Pi: the installed Cowrie output boundary validator reported an
unsafe rotated-log mode, and an independent exact-marker scan found the
synthetic credential marker in the Cowrie text log.

No Pi state was changed to repair or conceal the failure. The preinstalled
automatic guard restored the verified recovery release and independently
verified recovery service health, HTTP health, SQLite quick-check, and queue
readability. Production is running on the recovery revision.

## 2. Repository and production starting state

- Branch: `professor-approved-poc-evaluation`.
- Evidence HEAD: `7cd9bc678db49fe29cebbc370649c812871538b8`.
- Starting worktree: clean.
- Starting active release and marker:
  `19afabd0bb7ed82ac93767301bb0cb1024d0b92e`.
- Candidate: `1ad0e49e060843071508fc26aa48e07b2ac4d2b8`.
- Eight application services active, zero failed units, and three healthy HTTP
  endpoints.
- Database: `/var/lib/honeypot/production_pilot.db`, 3,933,114,368 bytes,
  SQLite schema 3, WAL mode, mode `0600`, owner `honeypot:honeypot`.
- Pre-activation SQLite quick-check: `ok`.
- Pre-activation queues had no pending or running work. Five enrichment
  failures were historical terminal rows. One current session-worker lease was
  present and not stale.
- Initial free space: 21,654,106,112 bytes; free inodes: 6,009,495.

No training, fine-tuning, calibration, or model-management process was running.

## 3. Readiness evidence verified

The readiness receipt parsed as
`READY_FOR_CONTROLLED_ACTIVATION`. Its candidate, package, release-tree,
manifest, recovery, model, test, and rollback identities matched the retained
report and live host.

- Candidate manifest SHA-256:
  `c57766c2e09ba1353fa7a9794ceddb30acbbaddf32f2f4890911f33cf966c881`.
- Candidate release-tree SHA-256:
  `de7a3f9167f70ce1bdbb757efee5e5d73a5ff68b78af8e00e111831240d9adf0`.
- Candidate package SHA-256:
  `2076c674e33d490e4a276492b9b8629f8ab2c76ddab2f2706d2e4fe63e46b66c`.
- Manifest-bound files: 539.
- Recovery manifest SHA-256:
  `46ef29d47807e48aca7cdddd6086904381a9db250a169521237ed2903d4cbd76`.
- Recovery release-tree SHA-256:
  `a595efaac5b7b09d9a435e26ed46c9dc96fb8662de0fad11fd48c1494ff69142`.

Both release inventories verified independently with the current verifier.
Candidate unit templates matched all eight installed units. There were zero
post-manifest writes before activation. The service account could not modify
the root-owned source files.

## 4. Pre-activation production health

All mandatory GCP pre-state gates passed:

- active symlink and marker matched recovery;
- eight services active and zero failed units;
- ingest, dashboard, and monitor health passed;
- schema 3 and WAL mode confirmed;
- SQLite quick-check returned `ok`;
- queues were readable and settled;
- the sole worker lease was current;
- managed-unit policy validation returned `status=valid` with no missing,
  prohibited, or unknown enabled units;
- production configuration passed strict unknown-key validation;
- effective service state used service-specific database credential files,
  `/var/lib/honeypot/reports`, and candidate-resolving policy paths;
- external enrichment profile was disabled and webhook target count was zero.

## 5. Fresh activation backup

The supported online SQLite backup tool created a new non-overwriting backup:

`/var/backups/honeypot/next-tactic-activation-20260801T072805Z/production_pilot.db`

- Start: `2026-08-01T07:28:18Z`.
- Tool completion receipt: `2026-08-01T07:29:10.330768+00:00`.
- Bytes: 3,933,114,368.
- SHA-256:
  `ea98daf597852690d75b9e01112891091a40f057dc73dd12470b4cc2111857f3`.
- Backup directory: `0700 root:root`.
- Backup and manifest: `0600 root:root`.
- Full integrity: `ok`.
- Quick-check: `ok`.
- Schema: 3.
- Key source counts matched the backup: 49,629 events, 7,445 sessions,
  21,823 prediction snapshots, 6,940 reports, and 31,611 alerts.
- Backup manifest SHA-256:
  `e0dec70fbb8cde7098576e8cfda507d69b3c38fe48ce085282e9af7b4936a43c`.

An isolated non-overwriting restore produced the same SHA-256, schema, full and
quick integrity, and all table counts. The derived restore was removed. The
source backup remains retained.

## 6. Candidate manifest, policies, feeds, and model

Immediately before activation:

- the candidate had no deployment marker;
- the 539-file manifest, package, model artifacts, effective configurations,
  dependency locks, unit files, dashboard assets, rollback path, and frozen
  model receipt verified;
- prediction, classification, response-guidance, threat-hypothesis, and
  session-correlation policy validators passed;
- configured runtime feed files and their content checksums exactly matched
  `runtime_feed_provenance.v1`;
- CISA, Sigma, and MITRE feed states were fresh and non-authoritative;
- MITRE version was 14.1.

Policy hashes:

- prediction: `3861d6a6edad4d15e147213cf0c4a5e8fb6c74f2a5f90142526df31492ddd90c`;
- classification: `33f332946c53578f2e609a3a039dda712355b9e209721bcc073c61a623d6342b`;
- response guidance: `91d5241a0c54daefd8e8371cf692cd5838737fcb08a7221fbd77a86f730ec6c7`;
- threat hypothesis: `931c5c8a6faef9ea2c7bb711631fd97a969766657e402c294708e68c4d6fd5a0`;
- session correlation: `81038c02168f8ddc105bfe7296ea7c09d13392eab4fbabaeeb1a8875b9493439`.

Frozen bundle:

- ID: `frozen_model_bundle_4957a700e993c76fd94a95bb569f70b0`;
- manifest SHA-256:
  `609ab334bb5c75295eee2851e2b2b6ae103ce8e0dbc6e43219da8bb5221e4419`;
- artifact inventory SHA-256:
  `fb9804a1beb3d62f31bc1fc031a54f031ab3201c062402723b2bf748c80195c7`;
- Transformer checkpoint SHA-256:
  `7fbd73c4bd071336fa52a589bf41e39f5a3122a67aee398dfb8e6dd9cfdfb04a`.

Runtime verification and the non-persistent Transformer smoke test passed. The
smoke produced `prediction_status=predicted` and
`predictive_alert_status=prohibited`. No artifact was modified.

## 7. Automatic fallback preparation

An owner-only guard outside the release was started before activation. It was
independent of candidate code and bound to:

- exact candidate and recovery paths;
- the eight-service allowlist;
- all three health endpoints;
- the production database and fresh backup;
- exact marker and symlink expectations;
- a 90-second initial readiness window;
- a bounded monitoring window;
- an explicit mandatory-gate fallback trigger.

Fallback stopped the eight services, atomically restored the recovery symlink,
started the services, verified the recovery marker and symlink, waited for all
services and endpoints, ran SQLite quick-check, and read all five durable job
queues. Its retained log is:

`/var/backups/honeypot/next-tactic-activation-20260801T072805Z/activation_guard.log`

Log SHA-256:
`3727ae4659fe71d4f802dca4d6f8883ee58429c865ed3973ca79f17c90b967ef`.

## 8. Atomic activation

- Activation started: `2026-08-01T07:37:29Z`.
- Restart requested: `2026-08-01T07:37:29Z`.
- Restart command returned: `2026-08-01T07:37:35Z`.

The candidate marker was written through a temporary file with `root:root`
ownership and `0644` mode, then atomically installed. A temporary symlink was
atomically moved over `/opt/honeypot`. The resulting target and marker both
matched `1ad0e49e060843071508fc26aa48e07b2ac4d2b8` before service restart.

The candidate retains its deployment marker as activation evidence even though
it is no longer active.

## 9. Candidate service readiness

Measured from activation start:

| Service | Systemd active | Readiness evidence |
|---|---:|---:|
| ingest API | 6 s | health/listener 62 s |
| session worker | 6 s | active-session recovery complete 75 s |
| analysis worker | 0 s | active, zero restart/warning |
| enrichment worker | 0 s | active, zero restart/warning |
| threat-hunt worker | 6 s | active, zero restart/warning |
| webhook dispatcher | 0 s | active, zero restart/warning |
| dashboard API | 0 s | health/listener 71 s |
| monitor web | 0 s | health/listener 1 s |

The guard recorded candidate initial health at `2026-08-01T07:38:43Z`, inside
the 90-second bound. All eight services had zero automatic restarts, zero
failed units, and zero warning-level startup messages.

Exact per-service memory, dependency-wait, model-load, and database-open
durations were not retained as separate measurements in the final activation
evidence. The bounded readiness timestamps above, restart counters, journals,
health results, and absence of OOM or crash-loop evidence are retained; exact
values for those finer-grained measurements are
`NOT_DETERMINABLE_FROM_RETAINED_ACTIVATION_EVIDENCE` and are not treated as
passed success gates.

## 10. Immediate candidate health

The candidate passed:

- exact symlink and marker;
- eight active services and zero failed units;
- all three health endpoints;
- post-activation manifest verification;
- schema 3 and SQLite quick-check `ok`;
- settled queues and current lease;
- no unexpected migration;
- 17.72 GB free-space margin;
- exact model, policy, and runtime-feed provenance already verified against the
  same unchanged bytes immediately before the atomic switch.

## 11. Controlled Pi-to-GCP session

Public reachability from the execution network timed out, matching the prior
documented limitation. The test therefore used the existing GCP HAProxy
listener internally. HAProxy remained unchanged and forwarded with PROXY
protocol to the existing Pi Cowrie listener. No Pi configuration was changed.

- Interaction: `2026-08-01T07:44:12Z` to `07:44:15Z`.
- Safe marker SHA-256:
  `832c8885b1a47e7e1a4d8afc61f1d287ab4dac0d387a50460e1c82c6227c7df9`.
- Sensor ID: `pi5-cowrie-01`.
- Privacy-safe session ID: `e7cc28f959b4`.
- Events accepted and processed: 11/11.
- Event attempts: one each; outcomes: succeeded.
- Exact replay: accepted 0, duplicate 1, rejected 0, with the same event ID.
- Session close was the terminal durable event.

The current HAProxy configuration SHA-256 remained
`c2654f4919bbac3be86a50161c7f47815187a17713baa5c4117340a0d34781f4`.

## 12. Prediction, report, and artifacts

- Prediction snapshots: 8.
- Completed prediction outbox rows: 8, all first attempt.
- Snapshot integrity errors: zero.
- Statuses: two `insufficient_history`, six `predicted`.
- Current snapshot:
  `prediction_02e47f26081657454b5736575ae9f53f`.
- Current snapshot was bound to the terminal close-event cutoff.
- Snapshot `recommendations` keys: zero.
- Analysis job: succeeded on its first normal attempt.
- Report: `report_76d0f799ba2a88bba8681b4cdf546fd9`.
- Assessment:
  `session_assessment_4e9dd5ff6ba73180e7340ff82c356bc3`.
- Evaluator revision:
  `1ad0e49e060843071508fc26aa48e07b2ac4d2b8`.
- `session_assessment.v4` validation errors: zero.
- `response_guidance.v3` validation errors: zero.
- The benign controlled evidence produced zero behavioral findings and zero
  hypothesis sets; one generic manual-only, non-executable guidance action was
  emitted.

The durable event manifest recomputed exactly from all 11 stored event payload
hashes through the terminal event. Its SHA-256 was
`d0ddf30a92cb4f202c9b626d8796ad3c33dea6dbbb3a178b02dae7f77736989c`.
Classification provenance recorded the exact reviewed 111-rule policy hash;
four trusted candidates came from five command observations. Typed semantic
provenance was valid. ATT&CK, prediction, enrichment, correlation, and prose
remained non-authoritative.

JSON, Markdown, native PDF, STIX, and integrity-manifest artifacts existed at
mode `0600`. The artifact manifest, STIX bundle, JSON v4/v3 contracts, native
PDF header, and decoded PDF stream passed validation.

## 13. API and monitor equivalence

The first 15-second client request timed out while the large database read was
still executing. A bounded parallel retry completed both responses in roughly
9 seconds.

- Current prediction payload: byte-equivalent JSON values.
- Current snapshot ID: equal.
- Guidance ID, findings, actions, triage, authority, safety, provenance, and
  canonical evidence: equal.
- Only guidance presentation difference: per-request `generated_at`.
- Prediction wording explicitly retained advisory-only authority.

## 14. GCP privacy and authority checks

The exact marker, username, and password had zero plaintext matches in:

- production SQLite, WAL, and SHM;
- the fresh pre-activation backup;
- all five controlled-session artifacts;
- report, prediction, enrichment, webhook, and diagnostic data represented in
  SQLite;
- HAProxy and all eight application journals;
- the decoded PDF content stream.

The GCP scan covered 10 files and 7,866,877,942 bytes plus 121,347 journal
bytes. It found zero matching paths and zero journal or decoded-PDF matches.
Both stored login records contained no synthetic credential value.

Controlled-session alerts: zero. Webhook deliveries: zero. Prediction
authority fields prohibited action authorization, alert creation, guidance
selection, automatic execution, and attacker-intent claims. Guidance required
manual approval and prohibited response side effects.

## 15. Mandatory Pi privacy failure

The installed Pi sanitizer release was unchanged at:

`7f764ab471e8dac555d06277b4613237299aee69`

Cowrie and the forwarder remained active with zero restarts and zero failed Pi
units. Nevertheless, the mandatory privacy gate failed in two independent
ways:

1. The installed `cowrie_output_boundary_validation.v1` validator returned
   `status=invalid` because
   `/home/cowrie/cowrie/var/log/cowrie/cowrie.json.2026-07-31` had an unsafe
   historical mode.
2. The exact-marker scan covered 398 Pi files, 4,852,697,187 bytes, and 5,011
   journal bytes. It found the synthetic credential marker in
   `/home/cowrie/cowrie/var/log/cowrie/cowrie.log`.

There were zero journal matches and zero unreadable scan paths. The downstream
spool, GCP ingest, database, reports, and artifacts remained sanitized, but
upstream Cowrie plaintext persistence violates the activation privacy
requirement. No log was rewritten, removed, truncated, chmodded, or rotated.

## 16. Fallback

- Mandatory fallback requested: `2026-08-01T07:57:28Z`.
- Guard fallback started: `2026-08-01T07:57:31Z`.
- Guard fallback completed: `2026-08-01T07:58:53Z`.
- Reason: `pi_privacy_validator_invalid`.

The guard stopped all eight services, atomically restored `/opt/honeypot` to
the recovery release, restarted the eight services, verified the recovery
symlink and marker, verified all services and three endpoints, ran SQLite
quick-check, and read all durable queues. Database restore was not required.

The recovery release successfully reads the candidate-created schema-3 state:
the controlled session retains 11 processed events, 8 immutable snapshots, 8
completed outbox rows, one first-attempt successful analysis job, one report,
zero alerts, and zero webhook deliveries.

## 17. Skipped gates after stop condition

The clean candidate restart and 15-minute candidate observation were not run.
Continuing would have contradicted the mandatory privacy stop condition. The
fallback itself was observed through complete recovery readiness and final
post-checks.

## 18. Final production state

- Active symlink and marker:
  `19afabd0bb7ed82ac93767301bb0cb1024d0b92e`.
- Recovery manifest and 495-file source tree: verified.
- Eight application services: active/running.
- Service restart counters: zero.
- Failed units: zero.
- Health endpoints: 3/3.
- Warning-level messages after recovery readiness: zero.
- SQLite schema: 3.
- SQLite quick-check: `ok`, verified by the independent guard.
- Durable queues: readable and settled.
- Stale leases: zero.
- Final free space: 17,719,767,040 bytes.
- Final free inodes: 6,009,483.

The fresh source backup, candidate, candidate package, candidate marker,
candidate manifest, recovery release, recovery manifest, model bundle, and
fallback log remain retained. Temporary guard state, API response copies,
synthetic credentials, client logs, derived restores, scanners, helper files,
and temporary symlinks were removed.

## 19. Production and Pi changes

GCP changes were limited to the approved backup, candidate deployment marker,
atomic activation, service restarts, automatic recovery symlink restoration,
and the retained privacy-safe guard log. The production database was not
rewritten or restored; it contains only the authorized controlled session in
addition to normal runtime state.

The Pi received only the authorized synthetic Cowrie interaction and read-only
validation/scan. Its configuration, software, services, firewall, and
historical data were not modified. Temporary scan files were removed.

## 20. Remaining blocker and exact next step

Production activation remains blocked on the Pi credential-persistence
boundary. A separate reviewed task must:

1. determine why the active Cowrie text logger persists authentication
   credentials despite the sanitized JSON output boundary;
2. correct the logger/output configuration at the earliest upstream boundary;
3. restore owner-only modes for rotated Cowrie logs without rewriting their
   contents and with a verified rollback copy;
4. run the installed boundary validator and an independent exact-marker scan;
5. freeze a new privacy acceptance receipt;
6. only then prepare a new controlled activation attempt with a new fresh
   backup and explicit handling of the candidate's retained prior-activation
   marker.

Do not reactivate the candidate until both the validator and independent Pi
marker scan pass. No next-tactic model or GCP application change is indicated
by this failure.

## 21. Final decision

**`FALLBACK_COMPLETED_AFTER_ACTIVATION_FAILURE`**
