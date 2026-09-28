# Tracked active decoy stack

Status: **repository source prepared; locally built on x86-64; not deployed
from this path**. The existing Pi still runs the older external Compose
project. This directory is the source for a future clean-host installation and
controlled cutover.

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
the target before Core starts. The Web-corp spool directory must be created
with the reviewed ownership and permissions before activation.

For an offline configuration check after supplying an operator-managed file:

```sh
docker compose --env-file /path/to/private-compose.env \
  -f deploy/decoy-honeypot/compose.yaml config --quiet
```

Starting, exposing, and migrating this stack remain outside the first
[Ansible Pi preparation slice](../ansible/README.md). The Core and Web-corp
images built and imported successfully on an x86-64 development host without
starting listeners. Their Linux ARM64 build, release inputs, image pinning,
private-input validation, and clean ARM64 VM acceptance must be qualified
before the installer activates these services.
