# ADR-0013: Limit Pi Zeek capture to active decoy endpoints

- Status: Accepted
- Date: 2026-09-28

## Context

The Pi's Zeek workers on `wlan0` and ZeroTier also observe development and
management traffic on those interfaces. The collector restricts which Zeek
records reach MongoDB, but Zeek still processes and logs unrelated packets
locally. The currently active decoy listeners are Cowrie SSH/Telnet on TCP
22/23 and Web-corp HTTP on ZeroTier TCP 80. FTP 21, SMTP 25, and direct HTTPS
443 are stopped. Admin SSH uses 2222 and is not a decoy.

## Decision

Apply one BPF restriction to both Zeek workers that accepts bidirectional TCP
traffic for the Pi's current `wlan0` address on ports 22/23 and its ZeroTier
address on ports 22/23/80. The filter is generated from current interface
addresses before Zeek starts, so outbound development traffic to services on
the same ports at other hosts is not part of this capture. Do not add stopped
decoy ports merely because their source exists in the repository.

The existing collector destination/port gate remains as a second boundary.
Cowrie and Web-corp application telemetry are independent of Zeek capture.

## Consequences

- Zeek will not analyze unrelated DNS, HTTPS, management SSH, and development
  traffic on the two interfaces. Existing retained records are not changed.
- FTP data connections and any service that moves ports will not be captured
  until the reviewed filter and its verification are updated.
- If a required interface has no unique IPv4 address at startup, Zeek startup
  fails instead of silently capturing broadly. The startup helper waits up to
  40 seconds for network assignment. A later address change requires a Zeek
  restart or reload to regenerate the filter.
- Validate a bounded allowed and excluded test flow after each change; inspect
  `packet_filter.log` if this Zeek version emits it. Keep the prior site policy in a protected host backup for
  rollback; do not copy it into Git.
