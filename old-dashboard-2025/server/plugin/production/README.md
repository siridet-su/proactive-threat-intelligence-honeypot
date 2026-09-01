# Honeypot Sensor Forwarder

Production-ready sensor forwarder for forwarding Cowrie honeypot logs to GCP ingest_api with local disk-based resilience.

## Architecture

The sensor_forwarder runs independently as a separate pipeline from the existing Cowrie → SQLite → Dashboard flow:

```
Cowrie ──┬─→ Honeypot_Log_Processor.py ──→ SQLite ──→ Node/Prisma ──→ WebSocket ──→ Dashboard
         │
         └─→ sensor_forwarder ──→ GCP ingest_api ──→ GCP Backend (sessions/analysis/reports)
```

Both pipelines read from the same `cowrie.json` file but operate independently with separate offset tracking and disk spools.

## Features

- **Tail-mode reading**: Efficient line-by-line reading with persistent byte offset tracking
- **Disk spool resilience**: Local NDJSON queue when GCP ingest_api is temporarily unavailable
- **Automatic replay**: Queued events are forwarded automatically when connection is restored
- **Batch posting**: Events are sent in configurable batches (default: 100 events/POST)
- **Bearer token auth**: Secure authentication with GCP ingest_api
- **Validation mode**: `--once` flag for testing before enabling continuous tail-mode

## Directory Structure

```
production/
├── __init__.py                 # Package initialization
├── config.py                   # Configuration management (ProductionConfig)
├── serialization.py            # Utility functions (utc_now)
├── sensor_forwarder.py         # Main forwarder code
├── test_connection.py          # Connectivity test script
├── setup.sh                    # Raspberry Pi setup script
├── example.env                 # Example environment variables
└── README.md                   # This file
```

## Configuration

Configuration is loaded from environment variables (takes precedence) or a JSON config file.

### Required Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `SENSOR_ID` | Unique sensor identifier | `pi5-cowrie-01` |
| `INGEST_URL` | GCP ingest_api endpoint | `http://34.124.181.196:8080/events` |
| `HONEYPOT_API_TOKEN` | Bearer token for authentication | `<actual_gcp_token>` |
| `COWRIE_LOG_PATH` | Path to Cowrie JSON log | `/home/cowrie/cowrie/var/log/cowrie/cowrie.json` |
| `FORWARDER_SPOOL_PATH` | Path for disk spool queue | `/var/lib/honeypot-forwarder/sensor_spool.ndjson` |

### Optional Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FORWARDER_TIMEOUT_SECONDS` | 30 | HTTP request timeout |
| `FORWARDER_BATCH_SIZE` | 100 | Max events per POST |
| `FORWARDER_POLL_SECONDS` | 5 | Polling interval (tail-mode) |

## Usage

### Quick Setup on Raspberry Pi

```bash
# 1. Run setup script (creates user, directory, permissions)
sudo /home/cpe27/dashboard-honeypot/server/plugin/production/setup.sh

# 2. Copy systemd service file
sudo nano /etc/systemd/system/honeypot-sensor-forwarder-main.service
# (Edit with your actual GCP token in HONEYPOT_API_TOKEN)

# 3. Test configuration and connectivity
PYTHONPATH=/home/cpe27/dashboard-honeypot/server/plugin \
python3 -m production.test_connection

# 4. Run --once test to verify GCP connection
PYTHONPATH=/home/cpe27/dashboard-honeypot/server/plugin \
python3 -m production.sensor_forwarder --once

# 5. Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable honeypot-sensor-forwarder-main.service
sudo systemctl start honeypot-sensor-forwarder-main.service

# 6. Monitor logs
sudo journalctl -u honeypot-sensor-forwarder-main -f
```

### Command-Line Usage

#### Validation Mode (--once)

```bash
export HONEYPOT_API_TOKEN=<your_token>
export INGEST_URL=http://34.124.181.196:8080/events
export SENSOR_ID=pi5-cowrie-01
export COWRIE_LOG_PATH=/home/cowrie/cowrie/var/log/cowrie/cowrie.json
export FORWARDER_SPOOL_PATH=/var/lib/honeypot-forwarder/sensor_spool.ndjson

PYTHONPATH=/home/cpe27/dashboard-honeypot/server/plugin \
python3 -m production.sensor_forwarder --once
```

Output:
```json
{"sent": 5, "remaining": 0, "error": "", "timestamp": "2026-05-13T12:34:56+00:00"}
```

#### Tail-Mode (Continuous Forwarding)

```bash
# Set up environment variables as above, then:

PYTHONPATH=/home/cpe27/dashboard-honeypot/server/plugin \
python3 -m production.sensor_forwarder
```

Output (continuous):
```json
{"service": "sensor_forwarder", "sent": 5, "remaining": 0, "error": "", "timestamp": "2026-05-13T12:34:56+00:00"}
{"service": "sensor_forwarder", "sent": 3, "remaining": 0, "error": "", "timestamp": "2026-05-13T12:34:61+00:00"}
...
```

Press Ctrl+C to stop.

### Configuration File (JSON)

Alternatively, use a JSON config file:

```bash
python3 -m production.sensor_forwarder --config /etc/honeypot/forwarder-config.json
```

Example JSON file:
```json
{
  "sensor_id": "pi5-cowrie-01",
   "ingest_url": "http://34.124.181.196:8080/events",
  "api_token": "actual-gcp-bearer-token",
  "cowrie_log_path": "/home/cowrie/cowrie/var/log/cowrie/cowrie.json",
  "spool_path": "/var/lib/honeypot-forwarder/sensor_spool.ndjson",
  "forwarder_timeout_seconds": 30,
  "forwarder_batch_size": 100,
  "forwarder_poll_seconds": 5
}
```

## Testing

### Test Connection Script

Verify configuration and connectivity without starting the forwarder:

```bash
PYTHONPATH=/home/cpe27/dashboard-honeypot/server/plugin \
python3 -m production.test_connection

# Output:
# ==========================================
# Honeypot Sensor Forwarder - Connection Test
# ==========================================
# [1/5] Testing configuration loading...
#   ✓ Config loaded successfully
#     Sensor ID: pi5-cowrie-01
#     Ingest URL: http://34.124.181.196:8080/events
#     ...
# [2/5] Testing Cowrie log accessibility...
#   ✓ Cowrie log readable: /home/cowrie/cowrie/var/log/cowrie/cowrie.json
#     First event: {"eventid": "cowrie.client.version", ...
# ...
# ==========================================
# Results: 5/5 checks passed
# ==========================================
# ✓ All checks passed! Ready for deployment.
```

### Test Individual Components

```python
from production.config import ProductionConfig
from production.sensor_forwarder import CowrieLogTailer, DiskSpool, forward_once

# Load config
config = ProductionConfig.from_env()

# Test reading from Cowrie log
tailer = CowrieLogTailer(config.cowrie_log_path, "/tmp/test.offset")
events, offset = tailer.read_new_events()
print(f"Read {len(events)} new events")

# Test spool
spool = DiskSpool(config.spool_path)
count = spool.count()
print(f"Spool has {count} pending events")

# Test single forward cycle
result = forward_once(config)
print(f"Sent: {result.sent}, Remaining: {result.remaining}")
```

## Systemd Service

Example systemd service file (created by setup.sh or manually):

```ini
[Unit]
Description=Honeypot Sensor Forwarder (Forward Cowrie logs to GCP)
After=network-online.target cowrie.service
Wants=network-online.target
Requires=cowrie.service

[Service]
Type=simple
User=honeypot-forwarder
Group=honeypot-forwarder

Environment=HONEYPOT_API_TOKEN=<INSERT_GCP_API_TOKEN_HERE>
Environment=INGEST_URL=http://34.124.181.196:8080/events
Environment=SENSOR_ID=pi5-cowrie-01
Environment=COWRIE_LOG_PATH=/home/cowrie/cowrie/var/log/cowrie/cowrie.json
Environment=FORWARDER_SPOOL_PATH=/var/lib/honeypot-forwarder/sensor_spool.ndjson
Environment=PYTHONPATH=/home/cpe27/dashboard-honeypot/server/plugin

ExecStart=/opt/honeypot/.venv/bin/python -m production.sensor_forwarder

Restart=always
RestartSec=5

StandardOutput=journal
StandardError=journal
SyslogIdentifier=honeypot-forwarder

[Install]
WantedBy=multi-user.target
```

## GCP Integration

### Expected GCP Ingest API Endpoint

```
POST /events
Content-Type: application/json
Authorization: Bearer <token>

{
  "sensor_id": "pi5-cowrie-01",
  "events": [
    {"eventid": "cowrie.client.version", "timestamp": "...", ...},
    {"eventid": "cowrie.login.success", "timestamp": "...", ...},
    ...
  ]
}
```

### Expected Response

```
HTTP 202 Accepted
Content-Type: application/json

{
  "accepted": 5,
  "stored": 5,
  "status": "received"
}
```

### GCP Firewall Rules

Allow only the Pi's IP to reach GCP port 8080:

```bash
gcloud compute firewall-rules create allow-pi-to-ingest-api \
  --allow=tcp:8080 \
  --source-ranges=<PI_PUBLIC_IP>/32 \
  --target-tags=gcp-ingest-api \
  --direction=INGRESS
```

**Important:** Keep Bearer token authentication enabled; firewall is supplemental, not a replacement.

## Troubleshooting

### Connection Failures

1. **Check network connectivity:**
   ```bash
   ping 34.124.181.196
   ```

2. **Verify GCP VM is accepting connections:**
   ```bash
   curl -X POST http://34.124.181.196:8080/events \
     -H "Authorization: Bearer test-token" \
     -H "Content-Type: application/json" \
     -d '{"sensor_id":"test","events":[]}'
   ```

3. **Check GCP firewall rules:**
   ```bash
   gcloud compute firewall-rules list --filter="name:allow-pi*"
   ```

### Permission Issues

1. **honeypot-forwarder cannot read cowrie.json:**
   ```bash
   # Check file ownership
   ls -la /home/cowrie/cowrie/var/log/cowrie/cowrie.json
   
   # Add forwarder user to cowrie group
   sudo usermod -aG cowrie honeypot-forwarder
   
   # User must logout/login for group changes
   ```

2. **honeypot-forwarder cannot write to spool:**
   ```bash
   # Check spool directory ownership
   ls -la /var/lib/honeypot-forwarder/
   
   # Fix if needed
   sudo chown honeypot-forwarder:honeypot-forwarder /var/lib/honeypot-forwarder
   sudo chmod 700 /var/lib/honeypot-forwarder
   ```

### No Events Being Forwarded

1. **Check if Cowrie is running:**
   ```bash
   sudo systemctl status cowrie.service
   ```

2. **Check if cowrie.json has new events:**
   ```bash
   tail -f /home/cowrie/cowrie/var/log/cowrie/cowrie.json
   ```

3. **Run --once test:**
   ```bash
   PYTHONPATH=/home/cpe27/dashboard-honeypot/server/plugin \
   python3 -m production.sensor_forwarder --once
   ```

4. **Check spool for pending events:**
   ```bash
   cat /var/lib/honeypot-forwarder/sensor_spool.ndjson | wc -l
   ```

### Service Won't Start

1. **Check systemd errors:**
   ```bash
   sudo systemctl status honeypot-sensor-forwarder-main.service
   sudo journalctl -u honeypot-sensor-forwarder-main -n 50
   ```

2. **Verify PYTHONPATH:**
   ```bash
   PYTHONPATH=/home/cpe27/dashboard-honeypot/server/plugin \
   python3 -c "from production.config import ProductionConfig; print('OK')"
   ```

3. **Test manual execution:**
   ```bash
   sudo -u honeypot-forwarder \
     PYTHONPATH=/home/cpe27/dashboard-honeypot/server/plugin \
     /opt/honeypot/.venv/bin/python -m production.sensor_forwarder --once
   ```

## Monitoring

### View Service Logs

```bash
# Last 50 lines
sudo journalctl -u honeypot-sensor-forwarder-main -n 50

# Follow in real-time
sudo journalctl -u honeypot-sensor-forwarder-main -f

# Since service started
sudo journalctl -u honeypot-sensor-forwarder-main -S -1h
```

### Monitor Spool File

```bash
# Count pending events
wc -l /var/lib/honeypot-forwarder/sensor_spool.ndjson

# Watch spool size changes
watch -n 1 'wc -l /var/lib/honeypot-forwarder/sensor_spool.ndjson'

# View recent events
tail -5 /var/lib/honeypot-forwarder/sensor_spool.ndjson
```

### Performance Tuning

Adjust polling and batch settings for your network conditions:

```ini
# Faster: More frequent checks, smaller batches
Environment=FORWARDER_POLL_SECONDS=2
Environment=FORWARDER_BATCH_SIZE=50

# Slower: Less frequent checks, larger batches
Environment=FORWARDER_POLL_SECONDS=10
Environment=FORWARDER_BATCH_SIZE=500
```

## Important Notes

### Current Limitations

- **cowrie.json only**: Currently forwards standard Cowrie events from `cowrie.json`
- **cowrie_custom.json deferred**: Custom events pending schema validation with GCP backend
- **No local processing**: Pi runs only the forwarder; database/analysis happens on GCP side

### Security Considerations

- **Change bearer token before production**: Default "test-token-change-me" is unsafe
- **Restrict firewall to Pi IP**: Use `source-ranges=<PI_IP>/32` instead of `0.0.0.0/0`
- **HTTPS recommended**: Consider using HTTPS instead of HTTP in production
- **Keep service updated**: Monitor for security updates to dependencies

### Disk Spool Behavior

- **Resilience**: Events queue locally if GCP ingest_api is down
- **Replay**: Queued events are forwarded when connection is restored
- **Disk usage**: Monitor `/var/lib/honeypot-forwarder/` if you expect frequent disconnections
- **Clear old spool**: `rm /var/lib/honeypot-forwarder/sensor_spool.ndjson` if needed (deletes pending events)

## Related Files

- [Raspberry Pi Setup Documentation](../../docs/raspberry_pi_setup.md)
- [Honeypot Log Processor](../convertData/Honeypot_Log_Processor.py) - Local SQLite pipeline
- [Node Backend Socket Server](../API/socket/server.js) - WebSocket relay for Dashboard

## Contributing

For bug reports or feature requests, see the main project repository.
