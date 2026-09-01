# Hardware Metrics Agent

The hardware agent samples Raspberry Pi system metrics and writes them to the
Redis stream `raw:hardware`. The processor agent converts numeric values and
stores each sample in the MongoDB Atlas `hardware_metrics` collection.

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
NETWORK_SAMPLE_SECONDS=30
```

`NETWORK_INTERFACES` is a comma-separated allowlist. Interface names are
sanitized before being used in metric field names.

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

