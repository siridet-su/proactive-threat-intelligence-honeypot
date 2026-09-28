# Existing Pi service watchdog

Status: active on the existing Pi. The source file here was copied from the
running host on 2026-09-28 and adds the passive `tcp_listen` probe. The
protected host configuration is intentionally outside Git.

The Cowrie target uses `tcp_listen` for `127.0.0.1:22`. The watchdog first
checks that `cowrie.service` is active, then reads `/proc/net/tcp` for a
listening socket bound to loopback or the IPv4 wildcard address on port 22.
This does not open a connection or create a Cowrie session. The existing
failure threshold, bounded restart policy, and 30-second timer still apply.
Other targets retain their configured probe types.

## Existing Pi cutover

The tracked [installer](install-cowrie-listen-probe.py) requires a staged copy
of [the watchdog source](honeypot-service-watchdog.py) on the Pi. It verifies
the current Cowrie probe is exactly TCP `127.0.0.1:22`, checks the staged
source and live listener, saves both old host files under the root-only
`/var/backups/honeypot/service-watchdog/` directory, stops the timer, installs
the new script and changes only Cowrie's probe type in the protected config,
runs the service once, and resumes the timer. If the new run fails, it restores
both files and restarts the timer. It does not print the protected config.

Stage the script in a host-local temporary path and invoke the installer as
root with `--staged-script` pointing to that path. Confirm the Cowrie state
contains `HEALTHY` and `tcp_listening`, the timer is active, and no new
loopback `cowrie.session.connect` events appear across several timer cycles.
The previous host files and the installation manifest remain in the protected
backup directory; restoring those exact files and restarting the timer is the
rollback procedure after a later regression.

Canonical MongoDB sessions produced before the cutover are handled separately
by the [exact-ID cleanup tool](../../honeypot-analysis/production/tools/clear_loopback_cowrie_sessions.py).
