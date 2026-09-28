# ADR-0015: Fresh Pi listens on Wi-Fi for Cowrie and keeps Web-corp local

- Status: Accepted for the clean-host installer; existing Pi is unchanged
- Date: 2026-09-28

## Context

The tracked Web-corp Compose stack has a public WireGuard override for the
existing Droplet. A new developer Pi may outlive that Droplet and needs a
simple local installation. The existing Pi also runs a legacy Cowrie sensor
forwarder to GCP alongside the Go collector. The fresh installer should not
copy that parallel path. Cowrie and Zeek were previously only staged, so the
Go activation gate could not complete on a clean host.

## Decision

- On a new Pi, bind Cowrie SSH/Telnet to the current `wlan0` IPv4 address on
  TCP 22/23. The dedicated non-login `cowrie` account owns its source, private
  state, and logs. A systemd capability grants only the low-port bind right.
  Administrator SSH must already be reachable on a different management port;
  the installer refuses a listener collision instead of changing SSH remotely.
- Run one standalone Zeek worker on the same Wi-Fi interface. Its generated
  BPF policy accepts bidirectional TCP traffic only for the Pi's Cowrie
  address and ports. Regenerate and install the policy before every start;
  fail closed if that interface lacks one unambiguous IPv4 address. Web-corp
  loopback traffic is outside Wi-Fi capture; its app login spool remains the
  telemetry source.
- Run PostgreSQL, Deception Core, and Web-corp from the tracked Compose source
  with host binds limited to `127.0.0.1`. Do not activate the public-Web-corp
  override in the fresh installer. Dashboard remains source-based development
  (`npm run dev`) on the developer's host, using separately supplied private
  configuration.
- Install the manifest-bound Cowrie sanitizer with a separate fresh-install
  contract that has no GCP forwarder dependency. Keep the legacy contract
  intact for the existing Pi. The new installer never installs the sensor
  forwarder. The existing Pi's forwarder remains active until its cloud
  consumers are reviewed and a separate retirement is approved.
- Stage blank private env files without replacing operator values. No sensor
  or decoy service starts until required private values pass the local shape
  checks. A same-release retry resumes installation. A fresh host activates
  the four core Go units while the B2 backup control unit stays stopped and
  disabled. Backup is an explicit `--enable-backup` action after the operator
  adds their own destination bucket and write-capable key. Historical archive
  read access is a separate credential that is never used by the Pi worker.

## Consequences

- A clean OS with administrator SSH on TCP 22 stops at the Cowrie collision
  gate. The operator first establishes and verifies a separate management
  route, then reruns the installer. This prevents lockout and impersonating the
  real administrator SSH service.
- The fresh installer has no public HTTP endpoint. Developers can inspect
  Web-corp at `http://127.0.0.1/` on the Pi or through an approved SSH tunnel.
- A Wi-Fi DHCP change requires a restart of Cowrie and Zeek to rebind and
  regenerate the filter. The service procedure must verify their current
  listeners and Zeek's effective filter after that change.
- The Go collector needs read access to Cowrie and Zeek logs; its dedicated
  user joins those service groups. It does not receive their write ownership.
- The fresh host can collect data before B2 is configured, but those days are
  not remotely archived until the operator enables and verifies backup.
- The current Pi's ZeroTier/WireGuard/public-Web-corp decisions in ADR-0012
  through ADR-0014 remain historical and active for that host until a separate
  cutover. This ADR governs only clean-host installation.
