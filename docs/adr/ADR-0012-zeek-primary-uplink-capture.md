# ADR-0012: Keep primary uplink and ZeroTier capture on the existing Pi

- Status: Accepted
- Date: 2026-09-28

## Context

The existing Pi ran Zeek as a local cluster with workers on `wlan0`,
`tailscale0`, and the ZeroTier interface. Tailscale and ZeroTier are used for
administration and local Cowrie tests. Hardware telemetry and the Dashboard
already present `wlan0` throughput as the primary network view. The overlay
workers produced 7,437 retained Zeek event documents occupying about 11.8 MB
of BSON document data in a measured 30-day window, before indexes and backups.
Of these, Tailscale accounted for 171 documents and about 0.26 MB; ZeroTier
accounted for 7,266 documents and about 11.6 MB. Thus removing only Tailscale
has a small measured storage benefit.
No Zeek events tagged `wlan0` were found in that same retained window. This
measurement does not prove that `wlan0` captured no packets.

## Decision

Keep the existing Pi's local Zeek cluster with its `wlan0` and ZeroTier workers.
Remove only the Tailscale capture worker. Keep Tailscale, ZeroTier, Cowrie, and
their own application telemetry unchanged. The fresh-Pi
installer's interface selection is still target-specific; this decision does
not enable its staged Zeek service or make it an existing-Pi migration tool.

## Consequences

- Zeek observes packets on the primary uplink and decrypted inner flows on the
  ZeroTier interface. VPN traffic on `wlan0` remains encrypted; Zeek no longer
  sees decrypted Tailscale inner flows.
- Cowrie command and session evidence continues through Cowrie's own logs and
  collector path. Existing retained Zeek records are not deleted by this
  capture change and expire according to their existing retention policy.
- The smaller scope should slightly reduce Zeek work and new Tailscale-derived
  records; actual savings depend on future traffic and must be measured after
  cutover. Most measured overlay-derived records came from ZeroTier and remain.
- If another overlay becomes an approved production observation source, review its
  value, retention cost, and capture boundary before adding a worker again.

## Operations

Back up the Pi's previous `node.cfg` in a root-only host location before
installing the tracked file. Check the new configuration, restart `zeek.service`,
then verify Zeek status, the current log path, and collector health. To roll
back, restore the protected host copy and restart `zeek.service`. The backup's
contents and host-specific interface details stay outside Git.

## 2026-09-28 addendum: public Web-corp path

ADR-0014 adds a `wg0` worker to observe only the private Web-corp HTTP
backend. The Tailscale worker remains removed. The endpoint filter and
collector gate remain required for the new worker.
