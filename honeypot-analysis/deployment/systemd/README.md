# systemd Deployment Templates

These files are templates for running the production pilot continuously on a VM
or Raspberry Pi. They assume the project lives at `/opt/honeypot`, runtime data
lives under `/var/lib/honeypot`, and configuration lives under `/etc/honeypot`.
Adjust those paths if your VM uses a different checkout location.

## GCP VM Backend

1. Create a restricted service user.

```bash
sudo useradd --system --home /opt/honeypot --shell /usr/sbin/nologin honeypot
sudo install -d -o honeypot -g honeypot -m 0750 /opt/honeypot /var/lib/honeypot /var/lib/honeypot/feeds
sudo install -d -o honeypot -g honeypot -m 0700 /var/lib/honeypot/reports
sudo install -d -o root -g honeypot -m 0750 /etc/honeypot
```

For an existing deployment, run the same `install -d` commands before the
artifact-writer upgrade so the configured directory is owned by the service
account and mode `0700`. Migrate existing artifact permissions before the
analysis worker is restarted:

```bash
sudo find /var/lib/honeypot/reports -xdev -type d -exec chmod 0700 {} +
sudo find /var/lib/honeypot/reports -xdev -type f -exec chmod 0600 {} +
sudo chown -R honeypot:honeypot /var/lib/honeypot/reports
```

Back up the report directory and verify available disk space before this
migration. Deploy the directory migration, worker unit, configuration, and
artifact code as one reviewed change; otherwise the strict writer will fail
closed on the old public modes.

2. Put the project in `/opt/honeypot`.

Copy a reviewed checkout into the service directory:

```bash
sudo cp -a /path/to/honeypot-threat-intelligence/. /opt/honeypot/
sudo chown -R honeypot:honeypot /opt/honeypot
```

3. Create the Python environment from the project directory.

```bash
cd /opt/honeypot
python3 -m venv .venv
sudo chown -R honeypot:honeypot .venv
sudo -u honeypot .venv/bin/pip install --upgrade pip
sudo -u honeypot .venv/bin/pip install requests reportlab google-genai torch transformers psycopg[binary]
```

4. Install config and secrets.

```bash
sudo install -o root -g honeypot -m 0640 configs/production_config.example.json /etc/honeypot/production_config.json
sudo cp deployment/systemd/honeypot.env.example /etc/honeypot/honeypot.env
sudo chmod 600 /etc/honeypot/honeypot.env
sudo chown root:root /etc/honeypot/honeypot.env
```

Edit `/etc/honeypot/production_config.json` and `/etc/honeypot/honeypot.env`.
Create `/etc/honeypot/credential-hmac-keyring.json` through the deployment
secret manager as `root:root` mode `0600`. Never put its contents in the
shared environment file, project checkout, shell history, logs, or command
output. The document contract is:

```json
{
  "schema_version": "credential_hmac_keyring.v1",
  "active_key_id": "ROTATION_ID",
  "keys": {
    "ROTATION_ID": "BASE64_OF_32_OR_MORE_RANDOM_BYTES"
  },
  "correlation_key_ids": []
}
```

The session-worker unit copies this file into its private systemd credential
directory. No other backend service and no Raspberry Pi service receives the
keyring. Set `credential_policy.hash_algorithm` to `hmac-sha256-v1`; the worker
fails before opening storage if the policy or keyring is unsafe.

For routine rotation, install a replacement file atomically with a new active
key and retain at most two prior key IDs in `correlation_key_ids` for the
defined correlation-retention window, then restart only the session worker.
Each listed prior key must also be present in `keys`. For a suspected key
compromise, do not retain the compromised key as a correlation alias.

For a production pilot, set `DATABASE_URL` to Cloud SQL Postgres unless the
MongoDB adapter has been implemented and tested. MongoDB is a reasonable target
for this document-heavy pipeline, but it is not a drop-in replacement yet
because the storage layer also claims durable worker jobs. Keep
`ANALYSIS_SKIP_EMPTY_SESSIONS=true`, and keep `ANALYSIS_SUPPRESS_STDOUT=true`.

5. Install backend services.

```bash
sudo cp deployment/systemd/honeypot-ingest-api.service /etc/systemd/system/
sudo cp deployment/systemd/honeypot-session-worker.service /etc/systemd/system/
sudo cp deployment/systemd/honeypot-enrichment-worker.service /etc/systemd/system/
sudo cp deployment/systemd/honeypot-analysis-worker.service /etc/systemd/system/
sudo cp deployment/systemd/honeypot-dashboard-api.service /etc/systemd/system/
sudo cp deployment/systemd/honeypot-webhook-dispatcher.service /etc/systemd/system/
sudo cp deployment/systemd/honeypot-prediction-backtest.service /etc/systemd/system/
sudo cp deployment/systemd/honeypot-prediction-backtest.timer /etc/systemd/system/
sudo cp deployment/systemd/honeypot-calibration-worker.service /etc/systemd/system/
sudo cp deployment/systemd/honeypot-calibration-worker.timer /etc/systemd/system/
sudo cp deployment/systemd/honeypot-prediction-retention.service /etc/systemd/system/
sudo cp deployment/systemd/honeypot-prediction-retention.timer /etc/systemd/system/
sudo cp deployment/systemd/honeypot-session-count-monitor.service /etc/systemd/system/
sudo cp deployment/systemd/honeypot-session-count-monitor.timer /etc/systemd/system/
sudo systemctl daemon-reload
```

6. Start the services.

```bash
sudo systemctl enable --now honeypot-ingest-api
sudo systemctl enable --now honeypot-session-worker
sudo systemctl enable --now honeypot-enrichment-worker
sudo systemctl enable --now honeypot-analysis-worker
sudo systemctl enable --now honeypot-dashboard-api
sudo systemctl enable --now honeypot-webhook-dispatcher
sudo systemctl enable --now honeypot-prediction-backtest.timer
sudo systemctl enable --now honeypot-calibration-worker.timer
sudo systemctl enable --now honeypot-prediction-retention.timer
sudo systemctl enable --now honeypot-session-count-monitor.timer
```

7. Verify operation.

```bash
systemctl status honeypot-ingest-api --no-pager
systemctl status honeypot-session-worker --no-pager
journalctl -u honeypot-analysis-worker -f
curl http://127.0.0.1:8081/sessions
curl http://127.0.0.1:8081/jobs
curl http://127.0.0.1:8081/reports
curl "http://127.0.0.1:8081/predictions/current?session_id=SESSION_ID"
```

Prediction snapshots are written after every processed event. The retention
timer audits eligible old intermediate snapshots without deleting them, while
reporting feedback-linked and latest-per-session reference protections. Review
the journal output, take a database backup, and run the command manually with
`--apply` only after the eligible count and rollback path are approved. Configure retention with
`PREDICTION_SNAPSHOT_RETENTION_DAYS` and
`PREDICTION_SNAPSHOT_KEEP_LATEST_PER_SESSION`.

The session-count monitor is a daily oneshot timer. It queries completed
sessions from the production database and writes warning-level journal lines
when the first completed session and the 30-session threshold are crossed. Its
state file is `/var/lib/honeypot/session_count_monitor_state.json`.

## Signed Webhook Delivery

Webhooks are disabled when both `WEBHOOK_URL` and `WEBHOOK_TARGETS_JSON` are
empty. Enabling a target also requires `WEBHOOK_SIGNING_KEY_FILE` (or a
per-target `signing_key_file`) naming a regular, non-symlink key file with at
least 32 bytes and no group/other permissions. Do not put the key value in the
environment or JSON configuration. HTTPS is the only allowed scheme by
default; private, loopback, link-local, or otherwise non-global destinations
require the explicit `allow_private_networks` target setting or
`WEBHOOK_ALLOW_PRIVATE_NETWORKS=true`.

Each exact JSON body is signed as HMAC-SHA256 over the byte sequence
`v1 + "\n" + timestamp + "\n" + idempotency_key + "\n" + body`. Receivers
must verify `X-Honeypot-Signature` (`v1=<lowercase hex digest>`), reject stale
`X-Honeypot-Timestamp` values, and deduplicate
`X-Honeypot-Idempotency-Key`. The same logical alert/target key is retained
across crash recovery. Redirects are not followed. Response bodies are never
stored verbatim; only a configured bounded byte count, truncation flag, and
SHA-256 digest are recorded.

For multiple destinations, configure `WEBHOOK_TARGETS_JSON` as a list of
objects containing `target_id`, `url`, optional `signing_key_file`, and optional
`allow_private_networks`. Delivery completion, attempt count, retry time, and
lease state are tracked independently for every alert/target pair.

## Raspberry Pi Sensor

Install only the forwarder service on the Pi. Cowrie should keep writing
`cowrie.json`; the forwarder tails that file and posts outbound batches to the
GCP ingest API.

```bash
sudo useradd --system --home /var/lib/honeypot-forwarder --shell /usr/sbin/nologin honeypot-forwarder
sudo mkdir -p /opt/honeypot /etc/honeypot /var/lib/honeypot-forwarder
sudo chown -R honeypot-forwarder:honeypot-forwarder /var/lib/honeypot-forwarder
sudo cp deployment/systemd/honeypot-sensor-forwarder.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now honeypot-sensor-forwarder
```

The Pi environment needs `HONEYPOT_API_TOKEN`, `SENSOR_ID`,
`COWRIE_LOG_PATH`, `FORWARDER_SPOOL_PATH`, and `INGEST_URL`. It does not need
database credentials, Vertex credentials, SecureBERT, or enrichment provider
API keys.

## Read-Only Web Monitor

`production.api.monitor_web` provides a separate read-only view of the VM-side
pipeline. It defaults to `127.0.0.1:8090`, reads the production database, and
must not print API tokens or enrichment-provider keys.

Install and verify it on the VM:

```bash
sudo cp deployment/systemd/honeypot-monitor-web.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now honeypot-monitor-web
sudo systemctl status honeypot-monitor-web --no-pager
curl http://127.0.0.1:8090/health
```

Keep port `8090` private. Reach it through the existing private management path:

```bash
ssh -L 8090:127.0.0.1:8090 ADMIN_USER@VM_PRIVATE_ADDRESS
```

Then open `http://127.0.0.1:8090`. The page shows session state, classification
evidence, stored prediction snapshots, job/report status, and recent events.
