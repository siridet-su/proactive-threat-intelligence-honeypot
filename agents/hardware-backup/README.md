# Hardware rollup backup worker

This worker archives completed `hardware_metrics_1m` rollups from MongoDB to a
private Backblaze B2 bucket. It is intentionally separate from the realtime
hardware agent and processor so a slow cloud upload cannot block telemetry.

Each run:

1. selects whole UTC days older than `BACKUP_SAFETY_DAYS`;
2. skips days already marked successful in `hardware_backup_manifests`;
3. writes BSON documents as canonical Extended JSON Lines in a gzip archive;
4. uploads the archive to `hardware_metrics_1m/YYYY/MM/DD/rollup.jsonl.gz`;
5. records counts, hashes, object name, and status in MongoDB;
6. refreshes the retained B2 storage snapshot in `b2_storage_snapshots`.

The default window is the previous 28 completed days (`BACKUP_LOOKBACK_DAYS=30`
and `BACKUP_SAFETY_DAYS=2`). The current and immediately previous day are left
alone so late rollups are not archived prematurely. Set `BACKUP_FORCE=true` for
an intentional re-upload of existing days.

Required environment:

```text
MONGO_URI=mongodb://...
B2_BUCKET=pti-hardware-backups
B2_KEY_ID=...
B2_APPLICATION_KEY=...
```

The B2 application key must also include the `listFiles` capability so the
worker can report retained storage usage. The storage snapshot sums all
uploaded file versions, including older versions retained by the bucket.

Optional environment includes `MONGO_DATABASE`, `BACKUP_COLLECTION`,
`BACKUP_ROOT`, `BACKUP_LOOKBACK_DAYS`, `BACKUP_SAFETY_DAYS`, and `BACKUP_FORCE`.
`B2_ENDPOINT` may be kept in the host environment as region metadata; the
worker uses the Backblaze Native API and follows the API URL returned during
authorization.

The systemd service and timer are in `systemd-services/`.

## Dashboard-triggered runs

The `honeypot-hardware-backup-control.service` unit runs the same binary in
`BACKUP_MODE=control`. It polls the `hardware_backup_requests` collection every
15 seconds, atomically claims the oldest pending request, and keeps the B2
credentials on the Pi. The dashboard only inserts an audited request; it never
opens SSH or talks to B2 directly.

Supported actions are:

- `run_missing`: archive days in the backup window that have no manifest;
- `retry_failed`: retry days whose manifest is currently marked `failed`.

While a request is running, the worker updates `progress` and `heartbeat_at`
after each UTC day. The request document contains `status`, `completed_at`,
`worker_id`, and an error message when the run fails. A stale running request
can be reclaimed after 30 minutes without a heartbeat. The scheduled service
and control service share a local file lock so they cannot upload the same
archive concurrently.
