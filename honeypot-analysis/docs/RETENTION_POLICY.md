# Retention policy and safety status

Retention commands are non-destructive unless an operator supplies `--apply`.
The installed prediction-retention timer is deliberately an audit: it reports
counts and never deletes records. No remediation or deployment procedure may
add `--apply` to that timer without a separately approved data-lifecycle policy,
backup, maintenance window, and restore test.

## Supported deletion scope

`prediction_snapshots` is `COMPLETE_AND_VERIFIED` for local SQLite and mocked
MongoDB. A dry run reports the cutoff, total rows, age candidates, feedback
protections, latest-per-session protections, eligible rows, and zero deletions.
Only explicit `--apply` deletes eligible rows. Analyst-feedback references are
always preserved. The latest snapshot per session is preserved by default with
a deterministic `(created_at, snapshot_id)` tie break.

MongoDB also marks a snapshot before feedback is recorded and includes that
marker in the delete predicate. The marker is a conservative additional guard
against a cross-collection race. PostgreSQL implements the same selection and
report contract, but has not been exercised against an authorized live server.

An apply run requires all prediction writers and feedback writers to be stopped
for the maintenance window. This closes the remaining cross-transaction race in
which new feedback could be submitted for a snapshot selected immediately
before deletion. Take a backend-consistent backup first. Rollback is restoration
of that backup; deleted snapshots cannot be reconstructed from the retention
report alone.

## Explicit retain policies

The following durable entities are `INTENTIONALLY_DEFERRED` from age-based
deletion and therefore retained indefinitely. This is an affirmative
non-deletion policy, not an unimplemented implicit cleanup:

| Entity | Current policy | Reason |
|---|---|---|
| `events`, `sessions` | retain | Authoritative telemetry and session provenance require a separately approved forensic lifetime and cascade order. |
| `alerts`, `reports` | retain | Operator/audit outputs reference sessions, jobs, predictions, and artifacts. |
| `analysis_jobs`, `enrichment_jobs`, `threat_hunt_jobs` | retain | Attempt and failure history is operational evidence; terminal-state purge rules are not approved. |
| `webhook_deliveries` | retain | Idempotency and delivery audit state must outlive any receiver retry horizon. |
| `observables`, `observable_sightings` | retain | Cross-session threat-hunt evidence has unresolved campaign/reference lifetimes. |
| `enrichment_records` | TTL-read semantics only | Expiry controls whether cached data is treated as fresh; expired records are retained for provenance until a purge policy is approved. |
| `feed_status` | overwrite singleton | The current named status record is replaced; no history cleanup is needed. |
| `campaigns`, `campaign_sessions`, `session_links` | retain | Graph membership and linkage must be pruned as one reference-safe unit. |
| `prediction_backtest_runs`, `prediction_calibration_runs` | retain | Model/evaluation provenance must remain aligned with active policy versions. |
| `analyst_feedback`, `classification_review_labels` | retain | Human labels are authoritative training and audit evidence. |
| `worker_leases` | runtime-managed | Lease renewal/release/recovery owns these rows; age retention must not race active workers. |

Filesystem reports, exported STIX/PDF/JSON artifacts, feed caches, databases,
spools, models, evaluation outputs, and backups are outside the database
retention command. Feed caches use atomic last-good replacement. Every other
filesystem category remains `INTENTIONALLY_DEFERRED` from automatic deletion
until storage ownership, reference tracking, and restore behavior are defined.

## Operator procedure

1. Run the command without `--apply` and retain the JSON report.
2. Confirm `dry_run: true`, `deleted: 0`, and review every protection/eligible
   count.
3. Take and verify a backend-consistent backup.
4. Stop prediction and feedback writers for an approved maintenance window.
5. Re-run the identical command with `--apply`.
6. Verify protected snapshot IDs still resolve, start writers, and monitor
   storage/service health.
7. Restore the backup if protected data is missing or counts are inconsistent.
