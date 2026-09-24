---
title: Public-VPS HTTPS edge for web-corp (IP-only certificate)
status: target runbook; not deployed
last_reviewed: 2026-09-24
---

# Public-VPS HTTPS edge for web-corp

## Status and purpose

This is a target runbook for serving the existing web-corp login decoy over
publicly trusted HTTPS when clients connect to a **public VPS IPv4 address
directly**, without a DNS name. It moves the public TLS endpoint to a VPS and
keeps the Raspberry Pi behind WireGuard. It does not authorize a public
rollout or imply that any steps below have been applied. The Pi's direct-TLS
container on `:443` was stopped on 2026-09-25; HTTP `:80` remains the active
web-corp listener.

The stopped Pi HTTPS service used a self-signed certificate. It is retained
outside Git for a separately reviewed test, but is not currently served and
browsers do not trust it by default.
For a public-IP endpoint, Let's Encrypt now issues publicly trusted IP-address
certificates. They are short-lived (160 hours, about six days), so reliable
automated renewal and reload are mandatory. See the [Let's Encrypt IP
certificate announcement](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability).

A trusted certificate proves that the certificate matches the public IP and
chains to a trusted CA. It does not prove that the fake ERP is a real Odoo
installation or belongs to a particular company. Use only infrastructure and
a decoy persona that the operator is authorized to run.

## Target request path

```text
Browser: https://<VPS_PUBLIC_IP>/web/login
    │ TLS with a public-CA certificate whose IP SAN matches the URL
    ▼
Public VPS: HTTPS reverse proxy (TCP 443); HTTP-01 challenge/redirect (TCP 80)
    │ HTTP inside the encrypted, authenticated WireGuard tunnel
    ▼
Pi: web-corp private backend listener, reachable from the VPS peer only
    │
    └── existing spool → collector → Redis → processor → MongoDB pipeline
```

TLS terminates at the VPS. The VPS-to-Pi hop may use HTTP because WireGuard
protects that private path; do not publish the Pi backend port on a public
interface. End-to-end TLS inside WireGuard is optional and would need a
separate trust/operations design.

## Prerequisites and exposure boundary

Before deployment, decide and record the exact values for the VPS public IPv4,
VPS WireGuard address, Pi WireGuard address, WireGuard UDP port, private web-corp
backend port, and the operator/admin access path. Do not put private keys,
WireGuard keys, or credential-bearing data in this repository.

- Use a stable, globally routable public IP assigned to the VPS. The URL and
  certificate must use that exact IP. Public CAs cannot issue a publicly
  trusted certificate for the Pi's private ZeroTier/WireGuard address, a
  loopback address, or another non-public IP.
- Confirm current CA and ACME-client support for IP identifiers, the
  `shortlived` profile, and the chosen challenge. Support is newer and not all
  proxy managers handle IP certificates automatically. Certbot 5.4 or later
  supports IP identifiers with the webroot authenticator; check the [current
  Certbot/Let's Encrypt instructions](https://letsencrypt.org/2026/03/11/shorter-certs-certbot)
  before deploying.
- Permit inbound TCP 80 for ACME HTTP-01 validation and redirecting ordinary
  HTTP requests, and TCP 443 for the decoy, at both the DigitalOcean cloud
  firewall and the VPS host firewall. HTTP-01 validation requires port 80 and
  supports IP-address certificates; see [challenge types](https://letsencrypt.org/docs/challenge-types/).
- Permit the configured WireGuard UDP port only as required for the Pi peer.
  Restrict administration separately. Do not expose the Pi backend, Deception
  Core, Odoo, PostgreSQL, Redis, MongoDB, or internal agent ports to the
  public internet.
- On the Pi, bind or publish the web-corp backend only on the WireGuard-facing
  address/interface (or otherwise enforce an equivalent host/container
  firewall rule). Permit access only from the intended VPS peer. Preserve the
  existing ZeroTier listener only if it remains an explicit requirement.

## Deployment procedure

1. **Establish the private path first.** Bring up WireGuard between the VPS and
   Pi. From the VPS, verify that the selected Pi backend address and port are
   reachable over the tunnel. Verify from an unrelated external host that the
   same backend port is not reachable directly. Do not bind the app to a public
   VPS or Pi interface.

2. **Prepare HTTP-01 validation on the VPS.** Install a current Certbot release
   that supports IP addresses and configure the web server's webroot to serve
   `/.well-known/acme-challenge/` from the selected ACME directory on port 80.
   Redirect other HTTP paths to HTTPS; do not leave a login form available in
   plaintext. The CA must be able to reach the public IP on port 80.

3. **Test issuance against the ACME staging service first.** The following is
   the Certbot webroot form documented by Let's Encrypt; replace the placeholder
   with the VPS public IPv4 and the actual challenge directory:

   ```sh
   sudo certbot certonly --staging \
     --preferred-profile shortlived \
     --webroot --webroot-path /var/www/acme \
     --ip-address <VPS_PUBLIC_IPV4>
   ```

   A staging certificate is intentionally not browser-trusted. Use it only to
   confirm the challenge/issuance flow. After that succeeds, request the
   production certificate with the same arguments **without** `--staging`.
   Keep issuance (`certonly`) separate from proxy configuration so a Certbot
   installer cannot silently change an unrelated web-server configuration.

4. **Install the production certificate at the VPS edge.** Configure the
   reverse proxy to use Certbot's current `fullchain.pem` and `privkey.pem`
   paths for the certificate name shown by `certbot certificates`. Keep the
   private key root-readable only and outside Git. The TLS virtual host must
   serve the IP certificate for the exact public-IP URL. Do not copy the key
   to the Pi or place it in the web-corp image.

5. **Proxy to the Pi only over WireGuard.** Forward the web paths to the
   web-corp backend address/port on the Pi's WireGuard side. At the edge,
   overwrite (do not blindly preserve client-supplied) forwarding headers:
   `X-Forwarded-For` with the actual client address and `X-Forwarded-Proto`
   with the external scheme, and `X-Forwarded-Client-Port` with the original
   peer port (for Nginx, `$remote_port`). Keep the backend port inaccessible
   except over the intended tunnel.

6. **Configure and test the trusted-proxy boundary.** The current app records
   `request.url.scheme` in `http.scheme`. Behind a TLS-terminating proxy, its
   direct upstream connection is HTTP, so merely adding an
   `X-Forwarded-Proto` header is not enough. Configure Uvicorn's proxy-header
   handling (or equivalent tested middleware) to trust only the actual
   immediate VPS proxy peer as seen by the app/container, and verify that it
   sets both the original client address and external scheme correctly. The
   app's `WEB_TRUSTED_PROXY_CIDRS` setting governs its custom
   `X-Forwarded-For` and `X-Forwarded-Client-Port` parsing; it does not by
   itself set the request scheme. Configure Uvicorn's `--forwarded-allow-ips`
   with exactly the same immediate proxy peers so its request rewrite and the
   app's proxy-port trust boundary agree; never use `*`. A missing/invalid
   forwarded client port is stored as unknown rather than replaced with the
   proxy's own socket port.
   Account for any Docker/NAT address translation when identifying the peer.
   Uvicorn's `--forwarded-allow-ips` controls which proxy peers it trusts; see
   its [settings documentation](https://www.uvicorn.org/settings/). Never
   trust forwarded headers from every address (`*`).

7. **Automate renewal and proxy reload.** IP certificates expire after about
   six days. Enable the ACME client's unattended renewal mechanism, configure a
   deploy hook that reloads only the VPS reverse proxy after a successful
   renewal, and alert well before expiry. Run the client's renewal dry-run and
   verify that a renewed certificate is actually loaded by the listener. A
   scheduled renewal without a successful reload does not prevent an expired
   certificate from being served.

## Required validation before public traffic

- Inspect the production certificate without printing the private key. Confirm
  its issuer chain, validity window, and `IP Address:<VPS_PUBLIC_IPV4>` subject
  alternative name. Test verification against the IP, for example with a
  browser certificate viewer and an OpenSSL `-verify_ip` check.
- From an external network, confirm `https://<VPS_PUBLIC_IP>/web/login` opens
  without a certificate warning, ordinary HTTP redirects to HTTPS, and the
  ACME challenge still renews successfully. Do not use a self-signed fallback
  as a successful result.
- Verify the VPS can reach the Pi backend over WireGuard and that the Pi
  backend is not reachable from the public internet. Check both the cloud and
  host firewalls; do not rely on the WireGuard tunnel alone as a substitute
  for a backend ingress rule.
- Use synthetic, non-real login values only. Verify that login remains
  rejected and that the resulting event has the real external `source_ip`,
  `http.scheme=https`, and normalized destination port/service `443/https` in
  the existing Redis/Mongo pipeline. The internal WireGuard/backend port must
  not replace the public destination port in the event.
- Confirm the event path still avoids forwarding login values to Deception
  Core, Odoo, PostgreSQL, or external threat-intelligence services. Inspect
  only non-sensitive event metadata/field presence during routine validation;
  raw submitted passwords remain credential-sensitive by design.
- Verify the renewal dry-run and deploy hook, certificate expiry alert, and
  proxy reload before calling the public endpoint ready.

## Rollback and data handling

To end a public test, remove the public web ingress at the VPS firewall or
stop only the VPS reverse-proxy listener, then confirm that the VPS public IP
no longer serves the decoy. Keep the Pi's private ZeroTier service unchanged
unless a separate change requests otherwise. Preserve existing telemetry
according to its retention policy; disabling the listener is not permission to
delete collected records. Revoke a certificate only if its private key is
compromised or policy requires it.

Public exposure materially increases scanning and login-submission volume.
The existing design deliberately stores bounded submitted passwords in the
restricted spool, raw Redis stream, and MongoDB event. Treat those locations,
backups, and admin access as credential-sensitive. Do not solicit or use real
employee/customer credentials, do not reuse passwords, and do not present the
decoy as an unrelated organization's real login service.

## Current state and related docs

This target is not deployed. The active Pi web-corp listener is ZeroTier HTTP
only; direct HTTPS on the Pi is stopped. No public VPS listener, public-IP
certificate, WireGuard proxy route, or public firewall rule was configured by
writing this document.

- [Current web-corp runbook](README.md)
- [HTTP decoy current scope and future work](../../docs/design/http-decoy-scope.md)
- [Web-corp login telemetry design](../../docs/design/web-login-telemetry.md)
- [HTTPS listener validation evidence](../../docs/validation/2026-09-24-web-corp-https.md)
