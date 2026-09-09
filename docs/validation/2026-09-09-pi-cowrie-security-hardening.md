---
title: Raspberry Pi and Cowrie security hardening report
status: completed-with-follow-up
date: 2026-09-09
timezone: Asia/Bangkok
---

# Raspberry Pi and Cowrie security hardening report

## Scope and operator constraints

This maintenance followed the live-state review performed on 2026-09-09. The
operator explicitly required the threat-intelligence worker to remain stopped
and allowed local artifact bytes to be discarded as long as file hashes were
retained.

No Tailnet Lock initialization was attempted. Tailnet Lock is a tailnet-wide,
recovery-sensitive change that requires planned signing nodes, admin-console
coordination, and secure storage of the generated disablement secrets.

## Changes completed

### Management access

- Replaced the host-wide UFW allow rule for real SSH port 2222 with rules scoped
  to `tailscale0` and `ztxoocdlsi` only. Cowrie ports 22 and 23 remain the
  intentional public deception listeners.
- Kept real SSH key-only with root login disabled. Added a validated SSH drop-in
  that disables X11, TCP, agent, tunnel, gateway, and user-environment
  forwarding; lowers `MaxAuthTries` to 3; and bounds login/session timeouts.
- Installed and enabled fail2ban with a systemd-backed `sshd` jail for port 2222.
- Verified the active management session remained connected after both UFW and
  SSH reloads.

### Cowrie isolation and egress

- Added systemd controls for private devices, protected kernel/control/proc/home
  views, namespace and address-family restrictions, W^X memory, native syscall
  architecture, and removal of IPC objects.
- Cowrie still runs as the dedicated non-root `cowrie` account with
  `NoNewPrivileges` and only `CAP_NET_BIND_SERVICE`.
- `systemd-analyze security cowrie.service` improved from exposure level 6.2
  (`MEDIUM`) to 3.1 (`OK`).
- Replaced unrestricted Cowrie public egress with established/loopback traffic
  plus new outbound TCP 80/443 only. Existing blocks to RFC1918, ULA/link-local,
  and the protected management VM remain ahead of the HTTP(S) allow rule.

### Secrets and decoy services

- Rotated the local decoy PostgreSQL password and Odoo master password.
- Removed database credentials from the world-readable Cowrie systemd drop-in.
  Cowrie now reads `/etc/honeypot/cowrie-decoy.env`, owned by root with mode
  `0600`.
- Changed the decoy Compose `.env` to mode `0600` and restricted historical env
  and Compose backup files that can contain superseded values.
- Removed the AbuseIPDB key from the running decoy containers while TI remains
  disabled. The superseded provider credential must also be revoked in the
  provider account; that external action was not available from this host.
- Recreated PostgreSQL, Odoo, and deception-core and verified PostgreSQL TCP
  authentication with the rotated credential and Odoo HTTP status 200.

### Hash-only artifact retention

- Stopped Cowrie for bounded sweeps, hashed every regular file then removed the
  bytes. The initial inventory was 59,332 files using about 185 MB.
- The final root-owned ledger contains 7,845 unique, structurally valid SHA-256
  values at `/var/lib/honeypot-artifact-retention/sha256.txt` (mode `0600`).
- The download directory contained zero regular files at the final sweep cutover.
- Installed `cowrie-artifact-hash-retention.timer`, which runs every five minutes.
  Hash-named payloads become eligible after five minutes; non-payload decoy
  material becomes eligible after 24 hours to avoid disrupting active sessions.
- The retention script writes and fsyncs a previously unseen hash before deleting
  the corresponding bytes. It uses a non-blocking lock to prevent overlapping
  runs.

### Telemetry pipeline

- Kept `honeypot-ti-worker.service` disabled and inactive as requested.
- Set processor `THREAT_INTEL_ENABLED=false`; no new TI jobs are enqueued.
- Corrected `LOOKUP_DIR` to the repository `lookups/` directory.
- Enabled and started `honeypot-hardware.service`; `raw:hardware` is publishing.
- Corrected the stale collector paths in the committed systemd template.
- Updated the current architecture and service catalog to match live state.

### Packages and Redis durability

- Installed Docker Compose v2 and fail2ban.
- Upgraded all available packages, including Redis, Tailscale 1.102.3, Python,
  system components, and the Ubuntu split firmware packages. `apt` reports no
  remaining upgrades, `dpkg --audit` is clean, and no reboot is requested.
- Preserved the locally managed Redis configuration during the package conffile
  prompt.
- The pre-maintenance Redis configuration had both AOF and RDB schedules disabled.
  Consequently, the Redis package restart reset transient streams, including the
  prior 777-item TI queue. New Cowrie/canonical telemetry resumed immediately;
  historical canonical events are expected to remain in MongoDB by architecture,
  but that historical MongoDB count was not independently audited in this work.
- Enabled Redis AOF with `appendfsync everysec` and RDB schedules
  `900 1 300 10 60 10000`. Verified successful AOF rewrite, RDB save, and files in
  `/var/lib/redis/appendonlydir` to prevent the same restart-loss condition.

## Final verification

Verified at approximately 22:08 Asia/Bangkok:

- No failed systemd units.
- Cowrie active, enabled, no restart loop, sanitized boundary `valid`, live
  readiness `ready`, observer registered, and JSON parses without error.
- A controlled localhost SSH banner probe sent no credential or command. It
  increased `raw:cowrie` from 16 to 36 and `event:canonical` from 84 to 104;
  processor pending remained zero and Cowrie reported 20 write invocations.
- Collector, processor, hardware agent, sensor forwarder, Redis, SSH, fail2ban,
  Tailscale, ZeroTier, WireGuard, Docker decoys, and all configured Zeek workers
  were active. TI worker remained disabled/inactive.
- Processor effective values were `THREAT_INTEL_ENABLED=false` and the corrected
  repository lookup path.
- Redis AOF was enabled, last AOF rewrite and RDB save succeeded, and current
  Cowrie consumer lag/pending were both zero.
- Admin SSH remained listening on 2222 but UFW allowed it only on Tailscale and
  ZeroTier. Root/password/keyboard-interactive login and forwarding remained off.
- Artifact ledger had 7,845 unique valid SHA-256 lines; the timer was enabled,
  waiting, and completed repeated runs without error.
- Disk use was 49% with 58 GB available; inode use was 10%; 5.6 GiB memory was
  available; temperature was 54.3 C; throttling state was `0x0`; no new
## Development-mode session persistence override

At the operator's request on 2026-09-09, post-authentication Cowrie idle
disconnects were effectively disabled for development by setting both
`idle_timeout` and `interactive_timeout` to `2147483647` seconds (about 68
years). The unauthenticated connection timeout remains 120 seconds. Cowrie was
restarted successfully, returned to active/running with no error-level journal
entries, and resumed listening on ports 22 and 23. This is a temporary
development exception; restore bounded post-authentication timeouts after the
development session is complete.

  error-or-higher journal entries were present.

## Remaining follow-up

1. Revoke the superseded AbuseIPDB credential in the provider account before any
   future TI rollout.
2. Plan Tailnet Lock as a separate tailnet-wide change: select signing nodes,
   confirm Device Approval compatibility, initialize from the admin workflow,
   and securely store all disablement secrets. Current status remains not enabled;
   Tailscale Serve and Funnel both remain unconfigured.
3. Confirm the known Tailscale/ZeroTier admin devices and SSH key fingerprints
   against the operator inventory. No public-IP SSH success was observed in the
   reviewed seven-day window.
4. Router NAT/port-forward state was not observable from the Pi. Host firewall
   policy now protects port 2222 even if the router forwards it, but router policy
   should still be reviewed separately.
5. Review MongoDB historical counts if formal proof of pre-restart canonical
   retention is required.

## Repository artifacts

- `scripts/cowrie-artifact-hash-retention.sh`
- `systemd-services/cowrie-artifact-hash-retention.service`
- `systemd-services/cowrie-artifact-hash-retention.timer`
- `systemd-services/honeypot-collector.service`
- `docs/CURRENT-ARCHITECTURE.md`
- `docs/SERVICE-CATALOG.md`
- this report
