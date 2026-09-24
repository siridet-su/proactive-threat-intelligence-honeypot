# OpenCanary HTTP login decoy

This integration prepares one OpenCanary HTTP service for collecting requests
to a fake login page. It complements Cowrie's command-line telemetry; it does
not run submitted input or connect to a real authentication backend.

## Scope and staged binding

The configuration enables only OpenCanary's HTTP module and its built-in
`nasLogin` skin. The form submits `username` and `password` fields, which
OpenCanary records with the request path, source address, and user agent. A
SQL-injection string submitted in either login field is therefore retained as
attacker-supplied evidence. Other request paths and unsupported HTTP methods
are logged without executing or forwarding them.

The staged listener binds to `127.0.0.1:8081`. Port 80 is already used locally
by the middleware decoy, and the Pi's firewall currently has no HTTP allow
rule. Do not change the bind address, firewall, router forwarding, or service
activation as part of installation. A later exposure change must choose an
interface and port, confirm the existing decoy route, and review the matching
firewall rule first.

The native event log is `/var/log/opencanary/events.jsonl`, rotated at 10 MiB
with seven backups. Login fields may contain real credentials or SQL payloads
chosen by a visitor. Keep the log local and permission-restricted; do not
commit it, copy it into fixtures, or forward it without a separate privacy and
retention review. This local file is not yet part of the Redis-to-Atlas event
pipeline.

## Pi deployment layout

- OpenCanary `0.9.10`, pinned in `/opt/opencanary/venv`.
- System account `opencanary`, with no interactive login.
- Runtime config `/etc/opencanaryd/opencanary.conf`, owned by `root:opencanary`
  with mode `0640`.
- Environment file `/etc/opencanaryd/opencanary.env`, also `root:opencanary`
  mode `0640`. It contains non-secret node/listener values only.
- `systemd-services/opencanary.service` runs the bundled Twisted application
  in the foreground as the unprivileged account.
- The unit is installed but left stopped and disabled until explicitly started.

The committed environment template is
[`opencanary.env.example`](opencanary.env.example); the JSON template is
[`opencanary.conf.example`](opencanary.conf.example). The HTTP port remains an
integer in the JSON configuration because OpenCanary validates port values
before starting.

## Local start and verification

After the service and environment have been installed on the Pi:

```sh
sudo systemctl start opencanary.service
sudo systemctl status opencanary.service --no-pager
curl -iL http://127.0.0.1:8081/
sudo tail -n 20 /var/log/opencanary/events.jsonl
```

The GET request is logged. A form POST to the built-in login page produces an
HTTP login-attempt event. Keep any verification values synthetic. Stop the
staged service with `sudo systemctl stop opencanary.service`.

## Rollback

Stop the unit, remove its enablement if one was added later, and restore the
root-only backup of `/etc/opencanaryd/opencanary.conf` created during Pi setup.
The original config is not stored in this repository because it was
world-writable and may contain deployment-specific values.

The deployment actions, validation results, and deferred exposure work are
tracked in the [repository implementation log](../../docs/IMPLEMENTATION-LOG.md).

## Upstream references

- [OpenCanary installation and configuration](https://github.com/thinkst/opencanary)
- [OpenCanary 0.9.10 on PyPI](https://pypi.org/project/opencanary/0.9.10/)
