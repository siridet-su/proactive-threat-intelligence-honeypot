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
sudo -u honeypot .venv/bin/pip install -r requirements.txt
# Install only explicitly enabled optional groups, for example:
sudo -u honeypot .venv/bin/pip install -r requirements-artifacts.txt
```

4. Install config and service-specific secrets.

```bash
sudo install -o root -g honeypot -m 0640 configs/production_config.example.json /etc/honeypot/production_config.json
sudo install -o root -g root -m 0644 deployment/systemd/common.env.example /etc/honeypot/common.env
sudo install -d -o root -g root -m 0755 /etc/honeypot/services
sudo install -d -o root -g root -m 0711 /etc/honeypot/credentials
# Install only each enabled service's matching *.env.example as *.env.
# Create each referenced credential as owner honeypot, mode 0600, in that
# service's private 0700 credential directory.
```

Edit `/etc/honeypot/production_config.json`, `/etc/honeypot/common.env`, and
only the enabled files under `/etc/honeypot/services/`. Shared settings contain
no secrets. Secret values are read from the service-scoped `*_FILE` paths;
plaintext and file environment variables for the same secret are rejected,
as are symlinks, empty files, and files with group/other permissions.
Create `/etc/honeypot/credential-hmac-keyring.json` through the deployment
secret manager as `root:root` mode `0600`. Never put its contents in the
environment files, project checkout, shell history, logs, or command
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

SQLite is the only supported runtime backend. Set `DATABASE_BACKEND=sqlite`
and provide a `sqlite:///` URL through each service-specific credential; any
other backend fails closed. Keep
`ANALYSIS_SKIP_EMPTY_SESSIONS=true`, and keep `ANALYSIS_SUPPRESS_STDOUT=true`.

5. Install backend services.

```bash
sudo cp deployment/systemd/honeypot-ingest-api.service /etc/systemd/system/
sudo cp deployment/systemd/honeypot-session-worker.service /etc/systemd/system/
sudo cp deployment/systemd/honeypot-enrichment-worker.service /etc/systemd/system/
sudo cp deployment/systemd/honeypot-feed-refresh.service /etc/systemd/system/
sudo cp deployment/systemd/honeypot-feed-refresh.timer /etc/systemd/system/
sudo cp deployment/systemd/honeypot-analysis-worker.service /etc/systemd/system/
sudo cp deployment/systemd/honeypot-dashboard-api.service /etc/systemd/system/
sudo cp deployment/systemd/honeypot-webhook-dispatcher.service /etc/systemd/system/
sudo cp deployment/systemd/honeypot-monitor-web.service /etc/systemd/system/
sudo cp deployment/systemd/honeypot-threat-hunt-worker.service /etc/systemd/system/
sudo cp deployment/systemd/honeypot-session-count-monitor.service /etc/systemd/system/
sudo cp deployment/systemd/honeypot-session-count-monitor.timer /etc/systemd/system/
sudo systemctl daemon-reload
```

6. Start the services.

```bash
sudo systemctl enable --now honeypot-ingest-api
sudo systemctl enable --now honeypot-session-worker
sudo systemctl enable --now honeypot-enrichment-worker
sudo systemctl enable --now honeypot-feed-refresh.timer
sudo systemctl enable --now honeypot-analysis-worker
sudo systemctl enable --now honeypot-dashboard-api
sudo systemctl enable --now honeypot-webhook-dispatcher
sudo systemctl enable --now honeypot-monitor-web
sudo systemctl enable --now honeypot-threat-hunt-worker
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

Prediction snapshots are retained under the manual-only data-lifecycle policy.
No calibration, backtest, or prediction-retention timer is part of the current
deployment. Any future deletion requires a separately reviewed policy, verified
backup, restore rehearsal, and explicit manual approval.

The session-count monitor is a daily oneshot timer. It queries completed
sessions from the production database and writes warning-level journal lines
when the first completed session and the 30-session threshold are crossed. Its
state file is `/var/lib/honeypot/session_count_monitor_state.json`.

### Managed-unit validation and retiring archived one-shot units

`deployment/systemd/managed_units.v1.json` is the exact, hash-bound allowlist
for GCP and Pi deployment profiles. Validate GCP after unit installation:

```bash
/opt/honeypot/.venv/bin/python -m production.tools.managed_systemd_units \
  --policy /opt/honeypot/deployment/systemd/managed_units.v1.json \
  --profile gcp_backend
```

The command fails on missing required services, inactive required services,
unknown enabled `honeypot-*` units, or any installed obsolete
calibration/backtest/retention unit. The Pi profile manages only the forwarder
and checks Cowrie as an active external dependency; other retained Pi services
remain outside this deployment boundary.

After taking a configuration/unit backup as part of a reviewed deployment,
retire the old calibration and prediction-retention pairs if present. The
current confirmed GCP drift is the prediction-backtest pair; archive and remove
it with the exact non-overwriting reconciler:

```bash
sudo systemctl disable --now honeypot-calibration-worker.timer honeypot-prediction-retention.timer
sudo rm -f /etc/systemd/system/honeypot-calibration-worker.service /etc/systemd/system/honeypot-calibration-worker.timer
sudo rm -f /etc/systemd/system/honeypot-prediction-retention.service /etc/systemd/system/honeypot-prediction-retention.timer
sudo systemctl daemon-reload
sudo systemctl reset-failed honeypot-calibration-worker.service honeypot-prediction-retention.service

sudo deployment/systemd/reconcile-obsolete-units.sh archive \
  /var/backups/honeypot/systemd-units/DEPLOYMENT_TIMESTAMP
```

The archive contains the exact former unit files, before/after properties and
SHA-256 checksums. `restore-files` verifies and restores only those files for
forensics or rollback inspection; it deliberately does not re-enable the
obsolete writer. Do not restore removed Python producers. The session-count
monitor is retained and writes only beneath `/var/lib/honeypot`.

## Signed Webhook Transport (not currently authorized)

The reviewed `alert_authority_policy.v1` prohibits automatic alert creation and
external delivery. Configured webhook targets are validated but are not
dispatched. A future policy change would require a separate review and must not
be inferred from target configuration alone. The retained transport contract
requires `WEBHOOK_SIGNING_KEY_FILE` (or a
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
database credentials, SecureBERT, or enrichment provider
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

The monitor's sensitive command view is a separate administrator-only route:
`/api/internal/session-commands?session_id=...`. Provision
`MONITOR_RAW_COMMANDS_TOKEN_FILE` in the monitor service environment with an
owner-only credential, and present it as a Bearer token from the private
localhost/Tailscale management path. The route returns only the persisted
Cowrie command input, timestamp, event ID, and bounded classification metadata;
it is marked sensitive and is never used by public APIs, reports, exports,
STIX, webhooks, logs, or prediction snapshots. The value is the command text
remaining after the sensor privacy boundary, so text scrubbed before
persistence cannot be recovered.
