# ADR-0014: Serve public Web-corp through an IP HTTPS edge

- Status: Accepted
- Date: 2026-09-28

## Context

The existing Droplet forwards public TCP 22 through WireGuard to Cowrie on
the Pi. It has no HTTP or HTTPS listener. The Pi's active Web-corp HTTP
container is bound only to ZeroTier. The WireGuard tunnel is active, but the
Droplet has no route to that ZeroTier listener and the Pi has no listener on
its WireGuard address at TCP 80. A public Web-corp endpoint is now requested.

## Decision

- Keep the existing ZeroTier Web-corp container and its telemetry path.
- Add a separate Web-corp container on the Pi, published only on the Pi's
  WireGuard address at TCP 80. Sharing the image and spool preserves the
  application behavior while keeping proxy-header trust out of the ZeroTier
  listener. Permit only the intended WireGuard peer to reach this backend.
- Serve public Web-corp from the Droplet with an IP-address certificate and
  TLS-terminating reverse proxy on TCP 443. Use TCP 80 only for ACME HTTP-01
  and redirect. The proxy overwrites forwarding headers with the actual
  connection details and reaches the Pi backend only over WireGuard.
- Keep the existing public Cowrie TCP 22 forward and real administrator SSH
  port unchanged. Do not expose the Pi backend or data services on the public
  interface. The 6-day IP certificate requires unattended renewal, proxy
  reload, and expiry monitoring.
- The public edge is ready only after the certificate, external HTTPS,
  backend isolation, and login telemetry fields pass validation. Merely
  starting services does not satisfy the public readiness gate.

## Consequences

- The Pi's separate backend can trust only the immediate VPS WireGuard peer
  for forwarded headers, without extending that trust to direct ZeroTier
  requests handled by the original container.
- Zeek's existing `wlan0` worker sees encrypted WireGuard transport, not the
  inner HTTP session. Public Web-corp network observation requires a `wg0`
  worker and a collector mapping for that interface; application login
  telemetry continues through the shared spool independently.
- If external port 80 is blocked by a DigitalOcean Cloud Firewall, the
  operator must add its inbound rule before ACME validation. The VPS host
  firewall and cloud firewall are separate controls.
- Roll back by stopping the VPS HTTPS listener and private backend, restoring
  the prior Pi Compose configuration, then removing only the new public-edge
  firewall rules. Keep the ZeroTier Web-corp listener and Cowrie forward.
