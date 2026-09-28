# Tracked active decoy stack

Status: **repository source prepared; locally built on x86-64; source and
Docker/Compose packages staged and Web-corp/Core images built on a disposable
ARM64 VM, with a disposable loopback smoke run cleaned up afterward**. The existing Pi still runs the older external Compose
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
defaults to loopback; activation on an approved overlay address is a separate
step. The Zeek log path defaults to the old Pi location and must be checked on
the target before Core starts. The staging playbook creates the Web-corp
spool and parent directories as `root:root` mode `0700` before activation;
starting Compose without that preparation can auto-create them too broadly.

For an offline configuration check after supplying an operator-managed file:

```sh
docker compose --env-file /path/to/private-compose.env \
  -f deploy/decoy-honeypot/compose.yaml config --quiet
```

Starting, exposing, and migrating this stack remain outside the first
[Ansible Pi preparation slice](../ansible/README.md). The Core and Web-corp
images built and imported successfully on an x86-64 development host. A
bounded ARM64 VM build and no-network import also passed; the Core import
required its `/data` volume. Image pinning, private-input validation, and
service health still need qualification before activation.

The separate [decoy staging playbook](../ansible/README.md) now installs
Docker/Compose and a hash-approved source bundle on a clean ARM64 test host.
It leaves the daemon stopped and disabled and places a blank private env
file at `/etc/honeypot/decoy.env` only if absent. The manual VM image build
passed, but base-image pinning, private-input validation, and activation
remain separate installer gates.
