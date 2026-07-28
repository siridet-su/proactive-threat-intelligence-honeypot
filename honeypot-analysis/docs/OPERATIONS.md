# Operations

## Services

Reviewed generic units are under `deployment/systemd/`. Runtime daemons cover
ingest, session/analysis/enrichment/threat-hunt workers, webhook delivery,
dashboard/monitor, and the sensor forwarder. Timers cover feed refresh and
session-count monitoring.

List state without changing it:

```bash
systemctl --no-pager --type=service 'honeypot-*'
systemctl --no-pager --type=timer 'honeypot-*'
journalctl --no-pager -u honeypot-session-worker.service -n 100
```

Health endpoints are `/healthz` and `/readyz` on the configured authenticated
APIs. Check logs for artifact verification, queue leasing, redaction, forecast
availability, and report errors without printing secrets.

## Change procedure

1. Record deployed revision, units, configuration metadata, model/policy
   hashes, ports, service health, queues, and free disk.
2. Produce a consistent SQLite online backup while respecting the approved
   maintenance boundary.
3. Verify backup SHA-256, permissions, `PRAGMA integrity_check`, and restore it
   to an isolated rehearsal path.
4. Stage reviewed code/config/artifacts atomically.
5. Restart only affected application services.
6. Verify queues, SQLite, hashes, reports, API/UI, logs, and a controlled event.
7. Roll back immediately on semantic, artifact, compatibility, or health
   failure.

Use `python -m production.tools.sqlite_backup_restore` for the backup,
verification, and rehearsal steps. It creates mode-0600 outputs with a SHA-256
manifest, refuses overwrite, checks SQLite integrity and table counts, and
restores only to a new path. A copied database that has not passed both
`verify` and an isolated restore is not rollback evidence.

The exact most recent deployment and rollback rehearsal, including commands and
hashes, is [GCP_TRANSFORMER_POC_DEPLOYMENT_20260727.md](GCP_TRANSFORMER_POC_DEPLOYMENT_20260727.md).
Do not infer current host state solely from repository templates.

## Transformer rollback

Rollback is explicit, never automatic:

1. take a fresh post-change backup;
2. verify the retained VOMM artifact, manifest, policy, and rollback archive;
3. stop only affected application services;
4. restore the prior reviewed code/policy/configuration as one unit;
5. start affected services;
6. generate a controlled prediction and report;
7. verify the snapshot identifies VOMM and historical Transformer snapshots
   remain unchanged.

Never introduce a cascade or silent fallback during incident recovery.

## Incident-safe rules

- Do not modify networking, firewall, SSH, Tailscale, Cowrie exposure, or
  unrelated units as part of an application rollback.
- Never enter real credentials into Cowrie.
- Never print HMAC keys, bearer tokens, private paths containing identities, or
  unredacted commands into shared logs.
- Treat `python_script.service` and other unrelated failed units as outside
  scope.
- Configure only `sqlite:///` database URLs. Other backends fail closed.
