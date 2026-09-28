# Tracked active decoy stack

Status: **repository source prepared; localhost activation of all three
services passed on a disposable ARM64 VM with synthetic private input**. The existing Pi still runs the older external Compose
project. This directory is the source for a future clean-host installation and
controlled cutover.

An opt-in [`compose.public-web.yaml`](compose.public-web.yaml) defines a
second Web-corp HTTP container bound only to the Pi WireGuard address. Set
`WEB_CORP_WG_BIND_IP` and `WEB_CORP_PROXY_PEER_IP` in a private environment,
then use both Compose files with `--profile public-web` for this service.
The existing Pi runs a host-local equivalent override alongside its external
Compose file; the original ZeroTier Web-corp container remains active.
Never use a wildcard bind or trust all forwarded headers. The VPS edge
procedure is in the [public Web-corp runbook](../../integrations/web-corp/PUBLIC-VPS-HTTPS.md).

`compose.yaml` contains the three currently active services: PostgreSQL,
Deception Core, and Web-corp HTTP. The Deception Core image builds from
[`integrations/deception-core/`](../../integrations/deception-core/); Web-corp
builds from [`integrations/web-corp/`](../../integrations/web-corp/). The
Compose project name remains `decoy-honeypot`, preserving expected volume names
when a separate migration is reviewed. This is **not** an existing-Pi migration
procedure: do not point the new Compose file at live volumes without a backup
and a planned cutover.

Odoo, FTP, SMTP, and the direct Pi HTTPS container are stopped and omitted from
this active-stack definition. Their historical definitions remain on the
existing Pi until separately retired; `docker compose up` from this directory
cannot start them. No credential file, private certificate, runtime database,
attacker event, or backup is tracked here.

The operator supplies `POSTGRES_PASSWORD` and any optional service inputs in a
private environment file outside Git and the release tree. `WEB_CORP_BIND_IP`
defaults to loopback; the fresh installer enforces `127.0.0.1` and fills
`ZEEK_LOG_DIR=/opt/zeek/logs/current` when that field is blank. The optional
public-WireGuard override is excluded from the fresh installer. The staging
playbook creates the Web-corp
spool and parent directories as `root:root` mode `0700` before activation;
starting Compose without that preparation can auto-create them too broadly.

For an offline configuration check after supplying an operator-managed file:

```sh
docker compose --env-file /path/to/private-compose.env \
  -f deploy/decoy-honeypot/compose.yaml config --quiet
```

Starting and migrating this stack on the existing Pi remain separate. The
[fresh Pi installer](../ansible/README.md) checks the private env and starts
these services only on loopback. The Core and Web-corp
images built and imported successfully on an x86-64 development host. A
bounded ARM64 VM build and no-network import also passed; the Core import
required its `/data` volume. The VM activation checked an HTTP 200, running
containers, and loopback-only host binds. Mutable base-image tags and live
credential integrations remain to be qualified.

The separate [decoy staging playbook](../ansible/README.md) installs
Docker/Compose and a hash-approved source bundle on a clean ARM64 test host.
It leaves the daemon stopped and disabled and places a blank private env
file at `/etc/honeypot/decoy.env` only if absent. The fresh activation
playbook validates that file without showing values, starts the three services,
and checks Web-corp on loopback. It does not validate real database or external
model credentials.
