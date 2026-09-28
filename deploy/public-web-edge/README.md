# Existing Droplet public Web-corp edge

Status: active on the existing Droplet since 2026-09-28. These files are
versioned templates and units. Site addresses, ACME account material, and
private keys remain on the host. Public TCP 22 still forwards to Cowrie;
TCP 23 is closed. Public TCP 80 serves ACME HTTP-01 and redirects to HTTPS;
TCP 443 serves Web-corp through WireGuard to the Pi. Real administrator SSH
and WireGuard UDP rules remain separate.

## Update or reproduce

1. Confirm the WireGuard peer and the Pi private Web-corp backend are healthy.
   Apply the reviewed `compose.public-web.yaml` override only to the Web-corp
   backend. Keep `WEB_CORP_WG_BIND_IP` and `WEB_CORP_PROXY_PEER_IP` in a
   private operator environment. The trusted peer must be the actual socket
   source **seen inside the backend container**; verify it before accepting
   forwarded headers. Do not use a wildcard trusted proxy.
2. Install Nginx and a current Certbot supporting IP certificates (at least
   5.4). The existing Droplet uses a dedicated Python venv at
   `/opt/pti-certbot`; the Debian package version was too old. Make the ACME
   webroot `/var/www/pti-acme`. Render `nginx-acme-bootstrap.conf` with
   the public IP, install it as the Nginx default site, then permit inbound
   TCP 80 and 443 in the VPS host firewall and any separate cloud firewall.
   Confirm an external ACME-path probe reaches Nginx before issuance.
3. Issue with staging first, then production. Use the short-lived profile,
   webroot authenticator, exact public IP, and certificate name
   `pti-ip-public`. Keep the staging configuration in a separate protected
   directory so the production renewal lineage remains unambiguous. See
   [the detailed runbook](../../integrations/web-corp/PUBLIC-VPS-HTTPS.md)
   for the Certbot command shape. Never print or copy the key into Git.
4. Render `nginx-web-corp.conf.template` with the reviewed public and Pi
   WireGuard addresses; install it as the enabled site. Run `nginx -t` and
   reload Nginx. Confirm external HTTP redirects and HTTPS verifies the
   certificate for the exact public IP.
5. Install `pti-nginx-cert-reload` in `/usr/local/sbin` mode `0755` and the
   renewal and expiry-check units in `/etc/systemd/system`. Install
   `pti-cert-expiry-check` in `/usr/local/sbin` mode `0755`. Run
   `systemctl daemon-reload`, enable both timers, start the expiry-check
   service, and run the renewal dry-run below. A successful renewal runs the
   deploy hook to reload Nginx after `nginx -t` passes.

```sh
sudo nginx -t
sudo systemctl is-active nginx.service pti-certbot-renew.timer pti-cert-expiry-check.timer
sudo /opt/pti-certbot/bin/certbot renew --dry-run --no-random-sleep-on-renew --quiet
sudo systemctl show -p Result pti-cert-expiry-check.service
```

The expiry timer checks daily. It fails and writes a critical local journal
entry when less than 48 hours remain or the certificate cannot be read. It
does **not** send an off-host alert. Monitor the timers and journal until a
separate notification receiver is installed. Public-IP certificates are
short lived; an unobserved renewal failure can break the endpoint.

## Acceptance and rollback

Use synthetic login data only. Verify a public HTTPS GET and rejected POST,
HTTP-to-HTTPS redirect, ACME challenge reachability, certificate IP SAN,
Web-corp event `http.scheme=https` and destination `443/https`, and Zeek
`wg0` conn/http ingestion. Send a forged forwarding-header probe to the
direct ZeroTier container and confirm it is ignored. Check that unrelated
admin traffic is excluded by the Zeek filter. The bounded 2026-09-28 result
is in [validation evidence](../../docs/validation/2026-09-28-public-web-corp-edge.md).

For immediate rollback, remove the public TCP 80/443 ingress at the VPS host
firewall or stop the Nginx site, then verify the public HTTPS URL is closed.
Restore the protected pre-edge Nginx/firewall configuration if needed and
stop only the Pi WireGuard Web-corp container. Keep the existing ZeroTier
container, Cowrie forwarding, and collected evidence intact. Root-only
backups of pre-edge firewall and Nginx configuration remain on the Droplet;
root-only Zeek, collector, and Compose backups remain on the Pi. Do not copy
these protected backups into the repository.
