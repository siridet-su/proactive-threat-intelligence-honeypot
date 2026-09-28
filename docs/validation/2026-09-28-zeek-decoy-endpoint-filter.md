---
title: Existing Pi Zeek decoy endpoint capture check
date: 2026-09-28
environment: existing Pi and bounded synthetic ZeroTier peer connections
commit: main working tree; commit pending
status: partial
---

## Objective

Check that Zeek on the existing Pi retains active decoy observations while
excluding management and development traffic after the endpoint filter change.

## Procedure

1. Inventory listening TCP ports and active Zeek workers without changing
   firewall or decoy service settings.
2. Compile the generated BPF expression using `tcpdump -d`. Apply it to an
   eight-packet synthetic pcap covering decoy ingress/replies and excluded
   outbound development/management cases. Run `zeekctl check`, then restart
   and reload `zeek.service` through systemd.
3. From a ZeroTier peer, open TCP connections without sending application
   payload to Cowrie 22/23, Web-corp 80, and admin SSH 2222.
4. Inspect only destination-port counts in the fresh Zeek `conn.log` and
   check Zeek, collector, and processor service states.

## Expected result

Zeek records the three active decoy ports and omits admin 2222. No removed
Tailscale worker runs. A systemd reload regenerates the address-bound filter.

## Observed result

- The active listeners were Cowrie TCP 22/23, Web-corp ZeroTier TCP 80, and
  admin SSH TCP 2222. FTP 21 and direct HTTPS 443 were not listening.
- BPF compilation and the eight-packet synthetic test passed: three decoy
  packets matched and five development/management cases did not. `zeekctl
  check`, systemd restart, and systemd reload passed.
  Logger, manager, proxy, `worker-wlan0`, and `worker-zerotier0` were running.
- After each restart/reload test, `conn.log` contained one record each for
  destination ports 22, 23, and 80; no record for 2222. The no-payload TCP
  connects to all four listeners succeeded.
- Zeek, collector, and processor were active after the test. No Zeek systemd
  warning appeared in the bounded journal check.

## Metrics

The bounded test produced three Zeek connection records for the allowed ports
and zero for the excluded admin port. The synthetic filter test accepted three
of eight packets. This is a functional scope check, not a
representative traffic-volume or resource-use measurement.

## Limitations

The `wlan0` worker was healthy, but this test did not send a packet through
its physical interface. A failed outbound development-SSH connection attempt
was not treated as evidence for that exclusion. The installed Zeek version did
not provide a useful `packet_filter.log` entry during this check. A real
address-renewal event and sustained throughput/packet-loss check remain open.

## Follow-up

Compare retained Zeek event volume and resource use after a representative
interval. Recheck this filter before activating another decoy port.
