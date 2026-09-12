# Hardware Metrics Agent

The hardware agent samples Raspberry Pi system metrics and writes them to the
local Redis stream `raw:hardware`. The processor replaces one of 30 fixed
`hardware_live` MongoDB slots per sensor every second, so the cloud dashboard
can read MongoDB without an ever-growing live collection. It also upserts one
compact min/avg/max document per sensor and minute into
`hardware_metrics_1m`. Redis remains internal to the Pi.

## Network metrics

Network counters and throughput are collected per interface. The production
defaults are:

- `wlan0`: primary physical/uplink interface
- `tailscale0`: private overlay used by management and external services

The two interfaces must not be summed. Tailscale traffic is carried by
`wlan0`, so adding both would double-count that traffic.

Loopback, Docker bridges, and veth interfaces are not collected by default.
ZeroTier can be added temporarily during migration through configuration, but
is not part of the production defaults.

### Configuration

The agent reads these optional environment variables:

```ini
NETWORK_INTERFACES=wlan0,tailscale0
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
net_<interface>_rx_bytes_total
net_<interface>_tx_bytes_total
net_<interface>_rx_packets_total
net_<interface>_tx_packets_total
net_<interface>_rx_errors_total
net_<interface>_tx_errors_total
net_<interface>_rx_dropped_total
net_<interface>_tx_dropped_total
net_<interface>_rx_bytes_per_second
net_<interface>_tx_bytes_per_second
net_<interface>_rx_mbps
net_<interface>_tx_mbps
net_<interface>_rx_packets_per_second
net_<interface>_tx_packets_per_second
```

Sample metadata:

```text
network_primary_interface
network_interfaces
network_sample_interval_seconds
```

The legacy fields `net_bytes_sent`, `net_bytes_recv`,
`net_packets_sent`, and `net_packets_recv` remain available. They now
represent only the configured primary physical interface instead of a sum of
all interfaces.

The first sample after process startup contains counters but no rates. A rate
requires two samples. If a counter decreases because an interface restarted or
wrapped, one rate sample is skipped rather than emitting an invalid spike.

Rates use the actual elapsed time between samples:

```text
bytes_per_second = (current_bytes - previous_bytes) / elapsed_seconds
Mbps             = bytes_per_second * 8 / 1,000,000
```

## Memory semantics

Existing dashboard fields are preserved to avoid silently changing production charts:

```text
mem_used_bytes
mem_percent
mem_used_semantics=legacy_total_minus_free_buffers_cached
```

For training and collector parity, use the explicit pressure fields instead:

```text
mem_total_bytes
mem_available_bytes
mem_pressure_used_bytes
mem_pressure_percent
mem_pressure_semantics=total_minus_available
```

`gopsutil.VirtualMemory().Used` and Python `psutil.virtual_memory().used` do not have
the same Linux semantics. The pressure fields deliberately calculate
`total - available`, matching the experimental Python collector. Do not mix the
legacy and pressure fields in one feature definition.

## Bounded live dashboard projection

The processor projects only the fields required by the real-time System Health
screen into the 30-slot `hardware_live` ring. It is not a raw audit store. The
current projection includes:

```text
cpu_percent
cpu_core_percent
mem_percent
mem_total_bytes
mem_available_bytes
mem_used_bytes
disk_percent
disk_total_bytes
disk_free_bytes
disk_used_bytes
temperature
net_wlan0_rx_mbps
net_wlan0_tx_mbps
```

`cpu_core_percent` is one current percentage per logical CPU. Capacity fields
are retained so the dashboard can reveal exact current values behind compact
percentage cards. Raw counters and audit-oriented collector fields are not
copied into `hardware_live`.

## Read-only parity snapshot

The binary can emit one warmed JSON snapshot without requiring Redis configuration
or writing to Redis, MongoDB, or Atlas:

```bash
./hardware-agent \
  --snapshot-json \
  --snapshot-interval 2s \
  --snapshot-interfaces wlan0,tailscale0,lo \
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
