---
title: Web-corp HTTPS listener
date: 2026-09-24
environment: staging
commit: uncommitted working tree
status: passed with scope limitations
---

# Web-corp HTTPS listener validation

## Objective

Serve the existing web-corp persona over ZeroTier HTTPS port 443 while keeping
HTTP port 80 active, and ensure login events can preserve whether they arrived
over HTTP or HTTPS without forwarding login data to Deception Core or Odoo.

## Procedure

- Validated the sibling Compose configuration with
  `docker compose -f ../decoy-honeypot/docker-compose.yml config --quiet`.
- Ran six web-corp request-path tests inside an isolated container with
  networking disabled and the repository source mounted read-only. The new
  regression case used an HTTPS ASGI request with synthetic values and a
  temporary spool.
- Ran `go test ./...` in `agents/collector-agent` and
  `agents/processor-agent`; built both updated binaries to temporary paths,
  preserved the previous deployed binaries under
  `/var/backups/honeypot/web-https-20260924/`, then restarted the two systemd
  units.
- Rebuilt/recreated `web-corp` and started `web-corp-https`. Both use the same
  application source and share the restricted login spool; a filesystem lock
  serializes spool writers across the two containers.
- Checked HTTP and HTTPS `GET /web/login`, the TLS handshake, certificate SAN,
  container status, listener addresses, systemd unit state, and certificate
  file permissions. No live login POST was sent.

## Expected result

- Both listeners serve the same login page, return HTTP 200, and remain bound
  only to the ZeroTier address.
- HTTPS negotiates TLS; the app emits `http.scheme=https`, and the collector
  and processor preserve port/service 443/https.
- Login behavior remains a rejection, with no credential forwarding to Core,
  Odoo, or PostgreSQL.

## Observed result

- HTTP is bound to `10.58.33.42:80` → container port `8080`; HTTPS is bound to
  `10.58.33.42:443` → container port `8443`. Both containers were `Up`, and
  both telemetry systemd units were `active` after restart.
- Both `/web/login` GETs returned HTTP 200 and produced the same body SHA-256:
  `cc5f7459149437d3d6d6b0ff8d9e7c17c2d030f3839a5c0c30bb9c7cc8da31e3`.
- OpenSSL negotiated TLS 1.3. The self-signed RSA certificate has SAN
  `IP:10.58.33.42`, is valid through 2027-09-24, and verification correctly
  reports `self-signed certificate`. Its directory is mode `0700`, private
  key mode `0400`, and certificate mode `0444`; neither key nor certificate is
  stored in Git.
- The Python regression test confirmed an HTTPS-scheme login request still
  receives the decoy's rejected response and writes `http.scheme=https` to a
  temporary spool. Collector and processor tests confirmed mapping to port
  443/service `https` and preserving the scheme in the normalized event.
- One initial Core page-tracking request timed out while services were
  starting. Core health subsequently returned 200 and a later HTTPS
  `/robots.txt` request returned 200 with a successful Core `/v1/track` response.

## Metrics

- Web-corp unit tests: 6 passed.
- Collector-agent tests: passed.
- Processor-agent tests: passed.
- Compose validation: passed.
- HTTP/HTTPS page body hash comparison: equal.
- TLS negotiation: TLS 1.3.
- Telemetry systemd state after restart: both active.

## Limitations

- No live HTTPS login POST or end-to-end HTTPS credential-bearing event was
  written to Redis/MongoDB; no login values were submitted to the live service.
- No second ZeroTier peer test was performed, so this confirms the local host's
  listener binding, not remote overlay reachability.
- The certificate is self-signed. Browsers show a trust warning unless the
  certificate is explicitly trusted; public trust and renewal automation are
  not configured.
- TLS version/cipher metadata is not captured in the app's login event; only
  the HTTP scheme is recorded.

## Follow-up

- Verify a synthetic HTTPS login event end-to-end from an authorized second
  ZeroTier peer if live data-path verification is needed.
- Replace/renew the self-signed certificate before expiry if a trusted DNS
  identity becomes available.
- Track the sibling Compose file in a separate scoped repository change.
