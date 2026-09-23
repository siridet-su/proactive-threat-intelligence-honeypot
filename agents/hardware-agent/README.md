# Hardware Metrics Agent

The hardware agent samples Raspberry Pi system metrics and writes them to the
local Redis stream `raw:hardware`. The processor replaces one of 30 fixed
`hardware_live` MongoDB slots per sensor every second, so the cloud dashboard
can read MongoDB without an ever-growing live collection. It also upserts one
compact min/avg/max document per sensor and minute into
`hardware_metrics_1m`. Redis remains internal to the Pi.

## Network metrics

Network availability and throughput are collected per configured interface. The
recommended production configuration is:

- `wlan0`: primary physical/uplink interface
- optional `tailscale0` or `zt*`: diagnostic-only overlay interface when it is
  explicitly needed

Overlay traffic is carried by the physical uplink, so overlay and `wlan0`
throughput must not be summed. The live ring and minute history store only
`wlan0` throughput; overlay fields are useful only for a short local
diagnostic window.

Loopback, Docker bridges, and veth interfaces are not collected by default.
ZeroTier can be added temporarily during migration through configuration, but
is not part of the production defaults.

### Configuration

The agent reads these optional environment variables:

```ini
NETWORK_INTERFACES=wlan0
NETWORK_PRIMARY_INTERFACE=wlan0
NETWORK_SAMPLE_SECONDS=1
HARDWARE_SENSOR_ID=ubuntu-pi-server
HARDWARE_STREAM_MAXLEN=900
```

`NETWORK_INTERFACES` is a comma-separated allowlist. Interface names are
sanitized before being used in metric field names.

`HARDWARE_STREAM_MAXLEN` defaults to 900 and uses approximate Redis stream
trimming. At one sample per second this retains about 15 minutes of live data
without unbounded growth. `HARDWARE_SENSOR_ID` defaults to the host name.

### Fields

For each configured interface, the agent emits:

```text
net_<interface>_up
net_<interface>_rx_mbps
net_<interface>_tx_mbps
net_<interface>_rx_packets_per_second
net_<interface>_tx_packets_per_second
```

The agent keeps kernel counters only in process memory to calculate rates; it
does not write monotonic counters, duplicate byte-per-second fields, interface
configuration metadata, or the legacy unqualified network aliases to Redis.
The first sample after process startup contains availability but no rates. A
rate requires two samples. If a counter decreases because an interface
restarted or wrapped, that rate family is skipped rather than emitting an
invalid spike.

Rates use the actual elapsed time between samples:

```text
bytes_per_second = (current_bytes - previous_bytes) / elapsed_seconds
Mbps             = bytes_per_second * 8 / 1,000,000
```

## Memory semantics

New samples use one explicit memory definition:

```text
mem_total_bytes
mem_available_bytes
mem_pressure_percent
```

The pressure percentage deliberately calculates `(total - available) / total`.
Used bytes are derived from the capacity fields. Older live
documents may still contain `mem_percent` and `mem_used_bytes`; the processor
and dashboard can read those documents, but new writes do not emit the
ambiguous legacy pair.

## Bounded live dashboard projection

The processor projects only the fields required by the real-time System Health
screen into the 30-slot `hardware_live` ring. It is not a raw audit store. The
current projection includes:

```text
cpu_percent
cpu_core_percent
mem_total_bytes
mem_available_bytes
mem_pressure_percent
disk_percent
disk_total_bytes
disk_free_bytes
temperature
net_wlan0_rx_mbps
net_wlan0_tx_mbps
```

`cpu_core_percent` is one current percentage per logical CPU. Capacity fields
are retained so the dashboard can reveal exact current values behind compact
percentage cards. Raw counters and audit-oriented collector fields are not
copied into `hardware_live`. New documents use `hardware_live.v3`; the fixed
ring identity and timestamp are sufficient to derive the slot time, so a
duplicate `sample_unix` field is not written.

## Minute history projection

The processor also reads the bounded `raw:hardware` stream and upserts one
`hardware_metrics_1m` document per sensor and completed minute. New documents
use `hardware_metrics_1m.v2` and keep only min/avg/max summaries for
`cpu_percent`, `mem_pressure_percent`, `disk_percent`, `temperature`, and
`wlan0` RX/TX Mbps. The history path intentionally excludes raw counters,
per-core values, capacity fields, and virtual-interface rates such as
Tailscale or ZeroTier. The bucket timestamp identifies the one-minute bucket;
redundant `bucket_end` and `resolution_seconds` fields are not written. Existing
rollups remain readable; no migration is required.

## Read-only parity snapshot

The binary can emit one warmed JSON snapshot without requiring Redis configuration
or writing to Redis, MongoDB, or Atlas:

```bash
./hardware-agent \
  --snapshot-json \
  --snapshot-interval 2s \
  --snapshot-interfaces wlan0 \
  --snapshot-primary-interface wlan0
```

This mode is for short parity audits only. It is not a service, does not create
training rows, and does not replace the receipt-bound experimental collector.
Running the agent normally, without `--snapshot-json`, keeps the existing Redis
stream behavior.

## Build and service

```bash
cd /home/cpe27/honeypot-pipeline/agents/hardware-agent
gofmt -w main.go
go test ./...
go build -o hardware-agent .
sudo systemctl restart honeypot-hardware.service
```

Verify the latest Redis sample:

```bash
redis-cli XREVRANGE raw:hardware + - COUNT 1
journalctl -u honeypot-hardware.service -n 30 --no-pager
```
