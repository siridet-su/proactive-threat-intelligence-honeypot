# Retained data backup worker

This worker archives selected MongoDB retention sources to a private Backblaze
B2 bucket. It runs separately from the realtime hardware agent and processor so
a slow cloud upload cannot block telemetry.

The default configuration remains hardware-only for backwards-compatible
activation:

```text
BACKUP_TARGETS=hardware_metrics_1m
```

The current Pi activation is deliberately broader than the code default:

```text
BACKUP_TARGETS=hardware_metrics_1m,filesystem_audit,threat_events
BACKUP_ALLOW_SENSITIVE=true
```

This was verified on 2026-09-25 after a successful manual run and the
explicit sensitive-data policy review. The `threat_events` target archives the
canonical `events` collection only after records leave the late-write safety
hold; the current event window may therefore produce successful zero-document
manifests until older events become eligible.

The supported logical targets are:

| Target | Authoritative sources | B2 prefix | Default |
| --- | --- | --- | --- |
| `hardware_metrics_1m` | `hardware_metrics_1m` | `hardware_metrics_1m/` | enabled |
| `threat_events` | `events` | `threat_events/` | opt-in |
| `filesystem_audit` | `cwd_events`, `cwd_session_state` | `filesystem_audit/` | opt-in |

`cwd_audit_projection` and `cwd_audit_projection_meta` are intentionally not
archived. They are derived/readiness data and the processor can rebuild them
from the two authoritative filesystem sources.

Each target run:

1. selects whole UTC days older than `BACKUP_SAFETY_DAYS`;
2. skips days already marked successful in `hardware_backup_manifests`;
3. writes BSON documents as canonical Extended JSON Lines inside a gzip archive;
4. uploads the archive under the target's B2 prefix;
5. records target, source collections, counts, hashes, object name, and status;
6. refreshes the retained B2 storage snapshot in `b2_storage_snapshots`.

The archive header identifies the logical target and each record identifies its
source collection. This is required for the filesystem target, which contains
two source collections in one daily archive. Existing hardware objects keep the
`rollup.jsonl.gz` filename; newly created non-hardware objects use
`archive.jsonl.gz`.

The default window is the previous 28 completed days (`BACKUP_LOOKBACK_DAYS=30`
and `BACKUP_SAFETY_DAYS=2`). The current and immediately previous day are left
alone so late writes are not archived prematurely. Set `BACKUP_FORCE=true` for
an intentional re-upload of existing days.

## Sensitive threat events

The `events` source is marked sensitive because the project deliberately keeps
credential-bearing web-login fields in the restricted MongoDB event record.
It cannot be enabled accidentally. After the private B2 bucket, scoped
application-key prefixes, encryption, and restore access have been reviewed,
activate it explicitly:

```text
BACKUP_TARGETS=hardware_metrics_1m,threat_events,filesystem_audit
BACKUP_ALLOW_SENSITIVE=true
```

Do not put credentials or raw event values in this repository or in service
logs. The upload key must have `writeFiles` and `listFiles` and authorize every
configured target prefix. Because a B2 application key has one `namePrefix`,
several target prefixes require either a reviewed bucket-scoped key or separate
worker/key deployments. The restore operator uses a separate read-only key
with `readFiles`; the upload worker does not receive `deleteFiles`.

## Required environment

```text
MONGO_URI=mongodb://...
B2_BUCKET=pti-honeypot-archives
B2_KEY_ID=...
B2_APPLICATION_KEY=...
```

Optional environment includes `MONGO_DATABASE`, `BACKUP_TARGETS`, the legacy
`BACKUP_COLLECTION`, `BACKUP_ROOT`, `BACKUP_LOOKBACK_DAYS`,
`BACKUP_SAFETY_DAYS`, `BACKUP_CONTROL_POLL_SECONDS`, `BACKUP_FORCE`, and
`BACKUP_ALLOW_SENSITIVE`. `B2_ENDPOINT` may be kept in the host environment as
region metadata; the worker uses the Backblaze Native API and follows the API
URL returned during authorization.

## Bucket rollover

The prepared worker records each new manifest under a bucket, target, and UTC
day identity. Its skip, missing-day, and failed-day queries count only the
configured `B2_BUCKET`. New storage snapshots also retain separate identities
per bucket and target. Old manifests and snapshots stay in MongoDB; the worker
does not copy, rewrite, or delete old B2 objects.

Before activating a new bucket, verify its private-bucket policy, scoped key,
target prefixes, and read-only restore path. Set `B2_BUCKET` to the new bucket
only on the reviewed worker deployment. Set optional
`BACKUP_LEGACY_MANIFEST_BUCKET` to the bucket that holds older manifests with
no `bucket` field. This attributes those old rows only to that named bucket.
For an in-place worker upgrade, set it to the unchanged `B2_BUCKET` to avoid
re-uploading completed legacy days. During a rollover to a different bucket,
the old rows remain visible as history but do not satisfy the new bucket's
coverage; eligible days are archived again in the new bucket.

The Dashboard reads the active bucket from `backup_target_status` unless
`HARDWARE_BACKUP_BUCKET` is set. The optional
`HARDWARE_BACKUP_LEGACY_MANIFEST_BUCKET` must match the worker's legacy bucket
setting if old bucket-less manifests should count. Keep these names aligned
with the deployed worker; the Dashboard never receives B2 credentials.
Verify a new-bucket manifest and storage snapshot, inspect the Backup &
Retention coverage for that bucket, and rehearse a read-only restore before
retiring any old bucket or access key. This repository change does not perform
those host or cloud actions. A restore verification must record its bucket;
the Dashboard does not carry an old bucket's verification into a new bucket.

The systemd service and timer are in `systemd-services/`. The local temporary
archive root is mode `0700` and archives are removed after upload.

## Dashboard-triggered runs

The `honeypot-hardware-backup-control.service` unit runs the same binary in
`BACKUP_MODE=control`. It polls `hardware_backup_requests`, atomically claims
the oldest pending request for an enabled target, and keeps B2 credentials on
the Pi. The dashboard only inserts an audited request; it never opens SSH or
talks to B2 directly.

Supported actions are:

- `run_missing`: archive days in the backup window that have no manifest;
- `retry_failed`: retry days whose manifest is currently marked `failed`.

While a request is running, the worker updates `progress` and `heartbeat_at`
after each UTC day. The request document contains `source`, `status`,
`completed_at`, `worker_id`, and an error message when the run fails. A stale
running request can be reclaimed after 30 minutes without a heartbeat. The
scheduled service and control service share a local file lock so they cannot
upload the same archive concurrently.

The worker publishes enabled targets to `backup_target_status`; the dashboard
uses that record to distinguish a target activated on the Pi from a target
that is only supported by repository code. In control mode, the worker
refreshes `last_seen_at` on every control poll so the dashboard can report a
real heartbeat; scheduled mode reports its last run rather than pretending to
be continuously connected.

The dashboard source cards aggregate `hardware_backup_manifests` per target
and day so activation status is shown separately from actual archive coverage,
document counts, compressed bytes, empty days, failed/missing days, and lag.
The Backup & Retention page also shows a bounded exception preview, recent
audited requests from `hardware_backup_requests`, B2 snapshot freshness, and
policy details. Restore readiness is intentionally evidence-based: without a
record in the optional `backup_restore_verifications` collection it displays
`Not tested`; the page never infers restore success from an upload manifest.
Only the existing hardware action endpoint can queue manual actions. Other
targets remain review-only until a target-specific action contract is added.
