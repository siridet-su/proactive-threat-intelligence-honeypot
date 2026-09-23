# Hardware rollup backup worker

This worker archives completed `hardware_metrics_1m` rollups from MongoDB to a
private Backblaze B2 bucket. It is intentionally separate from the realtime
hardware agent and processor so a slow cloud upload cannot block telemetry.

Each run:

1. selects whole UTC days older than `BACKUP_SAFETY_DAYS`;
2. skips days already marked successful in `hardware_backup_manifests`;
3. writes BSON documents as canonical Extended JSON Lines in a gzip archive;
4. uploads the archive to `hardware_metrics_1m/YYYY/MM/DD/rollup.jsonl.gz`;
5. records counts, hashes, object name, and status in MongoDB.

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

Optional environment includes `MONGO_DATABASE`, `BACKUP_COLLECTION`,
`BACKUP_ROOT`, `BACKUP_LOOKBACK_DAYS`, `BACKUP_SAFETY_DAYS`, and `BACKUP_FORCE`.
`B2_ENDPOINT` may be kept in the host environment as region metadata; the
worker uses the Backblaze Native API and follows the API URL returned during
authorization.

The systemd service and timer are in `systemd-services/`.
