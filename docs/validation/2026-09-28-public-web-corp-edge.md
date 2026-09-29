---
title: Existing Pi and Droplet public Web-corp HTTPS edge
date: 2026-09-28
environment: production infrastructure, synthetic requests
commit: main working tree before commit
status: passed with monitoring limitation
---

## Objective

Expose the existing fake ERP login over trusted public-IP HTTPS while keeping
the Pi backend private, preserving the ZeroTier listener, and recording both
application and Zeek telemetry.

## Procedure and observed result

- Before deployment, the Droplet forwarded public Cowrie TCP 22 and had no
  HTTP/HTTPS listener; TCP 23 was not forwarded. The Pi's Web-corp listener
  was ZeroTier-only. WireGuard was connected, but no Pi HTTP listener was
  bound to its address.
- Added a separate Pi WireGuard Web-corp container using the existing built
  image and shared restricted spool. The original ZeroTier container stayed
  active. The host-specific Compose override is outside Git. Initial
  synthetic login metadata showed that trusting the Docker gateway did not
  work: the actual socket peer inside the container was the Droplet tunnel
  peer. The trust list was corrected to that peer and the container recreated.
- Installed Nginx and a current Certbot on the Droplet. External ACME
  challenge reachability, staging issuance, production IP-certificate
  issuance, certificate IP SAN, trusted HTTPS GET, and HTTP 308 redirect
  passed. The production certificate was valid for about six days.
- A synthetic HTTPS login was rejected and persisted in MongoDB with an
  external source address, source port, `http.scheme=https`, and normalized
  destination `443/https`. A forged forwarded-header probe to the direct
  ZeroTier container was ignored.
- Added a Pi `wg0` Zeek worker and endpoint-specific TCP 80 filter. A
  no-payload public HTTPS GET appeared as Pi WireGuard TCP 80 in packet
  capture, then in Zeek `conn` and `http` logs. A read-only MongoDB query
  found four recent Zeek records tagged `sensor.interface=wg0`, types
  `conn`/`http`, and destination port 80. The Pi Zeek, collector, and
  processor services were active. Synthetic eight-packet BPF validation
  admitted five approved cases and excluded three unrelated cases.
- Certbot renewal dry-run passed. Its twice-daily timer and the daily local
  expiry-check timer are enabled; the latter service returned success while
  more than 48 hours remained.

## Limits and follow-up

An actual renewal has not yet occurred. The expiry check records a critical
local journal message and service failure but has no off-host notification
receiver. Browser certificate UI, sustained public traffic volume, packet
loss, and long-term storage growth were not measured. The Pi's external
Compose source and protected backups stay outside Git; its dirty local
Web-corp source was not overwritten. A separate checkout sync and a full
fresh-install acceptance are still required.
