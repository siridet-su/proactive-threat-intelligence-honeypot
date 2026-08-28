# Security and privacy (canonical summary)

This summary consolidates the current security boundary. The dated acceptance
records remain authoritative for exact hashes, receipts, and failure states.

## Collection and persistence

Cowrie output is sanitized before the forwarder reads it. The repository-owned
observer writes a bounded structured JSON projection; categorical text and
lifecycle diagnostics use closed vocabularies and cannot persist arbitrary
event or exception text. TTY replay is disabled because its shell prompt can
persist attacker-controlled identity data. Credential-bearing historical
records are restricted and receipt-bound but are not rewritten or deleted.

The accepted Pi revision recorded by final production evidence is
`5bb3b97fbe3b9034c70fc6ca2aba0ad9d159bb02`. Its installer uses a closed
manifest inventory, verifies the Cowrie/Python/Twisted binding, stops only
Cowrie, preserves the forwarder process, seals a non-overwriting owner-only
rollback receipt, and rejects release bytecode. Native JSON rotation leaves a
bounded group-readable handoff interval so the unchanged forwarder can drain
the renamed inode before it is sealed owner-only; categorical rotation is a
separate policy. These are repository-recorded acceptance properties, not a
claim about current live files.

SQLite, spools, reports, TTY evidence, keys, and deployment metadata are
outside the source release and use owner/group-restricted modes. The retained
final activation receipt records zero fresh credential-marker findings in the
new pipeline and no packet payload retention.

## Network and access controls

- Sensor batches require sensor-bound authentication and schema validation.
- The public Cowrie dependency is only the intended TCP/2222 path; the final
  correction enabled the existing scoped GCP rule rather than adding a port or
  widening a rule. HAProxy sends the required PROXY header to the Pi backend.
- Ingest and management routes are not public application interfaces.
- Secrets use service-specific credential files and centralized redaction;
  raw credentials, private keys, and source deployment metadata are not Git
  artifacts.
- The lifecycle policy prohibits automatic deletion and unauthorized external
  source-IP sharing. Optional enrichment is fail-closed and non-authoritative.

## Analytical safety

Observed evidence remains authoritative. Predictions, enrichment, ATT&CK-only
context, and optional prose cannot select findings, hypotheses, guidance,
alerts, or actions. New guidance always requires manual approval, is never safe
to auto-execute, and has no response or alert side effects. Historical v1/v2/v3
records remain readable through adapters without rewriting them.

## Lifecycle and deletion safety

`configs/data_lifecycle_policy.v1.json` is the machine-validated authority. Its
exact SHA-256 is recorded in `data_lifecycle_policy_ledger` when the session
worker starts. A missing, invalid, or runtime-inconsistent policy prevents that
writer from starting. The policy binds processing to honeypot security
research, prohibits credential-plaintext storage, requires artifact redaction,
and prohibits both automatic deletion and unauthorized external sharing of
source-IP data.

Retention commands are dry-run unless an operator supplies `--apply`. The
installed prediction-retention timer is audit-only: it reports counts and
never deletes. Adding `--apply` requires a separately approved lifecycle
policy, backend-consistent backup, maintenance window, and verified restore.
There is no supported scheduled deletion entrypoint.

Only SQLite prediction-snapshot selection is implemented. A dry run reports
the cutoff, age candidates, feedback and latest-per-session protections,
eligible rows, and zero deletions. Analyst-feedback references are always
preserved; by default, the latest snapshot per session is preserved using the
deterministic `(created_at, snapshot_id)` order. An apply run requires all
prediction and feedback writers to be stopped so new feedback cannot race the
deletion transaction. Deleted snapshots are recoverable only by restoring the
pre-change backup, not from the retention report.

Age-based deletion is affirmatively deferred for events, sessions, alerts,
reports, job and webhook history, observables/sightings, campaign and session
links, model-evaluation runs, human labels, and all other reference-coupled
durable records. Expired enrichment is stale for reads but remains provenance;
feed status is a replaced singleton; worker leases are owned by runtime lease
semantics. Databases, reports/exports, feeds, spools, models, evaluation
outputs, and backups are also outside automatic deletion until ownership,
reference tracking, and restore behavior receive separate approval.

Before any explicitly approved apply operation, retain the dry-run JSON, take
and verify a non-overwriting SQLite backup, rehearse restore to a new path,
stop writers, re-run the identical selection with `--apply`, verify protected
IDs, restart writers, and monitor health. The
`production.tools.sqlite_backup_restore` commands enforce mode `0600`, hashes,
byte counts, SQLite quick/integrity checks, schema version, and table counts;
backup and restore refuse to overwrite an existing target.

## Residual limitations

Earlier observer, rollback-receipt, rotation, and marker-scan failures are
summarized in [`HISTORICAL_IMPLEMENTATION_RECORD.md`](HISTORICAL_IMPLEMENTATION_RECORD.md)
and preserved byte-for-byte in Git history. Live state is not re-verified by
this local-only cleanup; any conclusion about current host contents beyond the
committed receipts is
`NOT_DETERMINABLE_FROM_CURRENT_REPOSITORY`.
