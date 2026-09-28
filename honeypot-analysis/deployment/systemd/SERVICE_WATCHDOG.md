# PTI-Honeypot service watchdog

The watchdog supplements each service's native `Restart=` policy. Every timer
run checks only the targets explicitly listed in the node profile. A target is
restarted after three consecutive failed checks. At most three restarts are
attempted in a rolling 15-minute window; further failures are recorded as
`CRASH_LOOP` instead of causing an unbounded restart loop.

The GCP and Pi profiles are separate because the two nodes run different
services. The Pi profile also checks the web-corp Docker container. The
activation-gated AI advisory worker is intentionally not managed: starting it
requires its own reviewed activation receipt and must never be caused by this
watchdog.

## Operational controls

- Create `/run/honeypot-maintenance.lock` before planned maintenance to keep
  checks running while suppressing recovery actions. Remove it when the
  maintenance window ends.
- The last status is written to
  `/var/lib/honeypot-service-watchdog/status.json` with mode `0640`.
- Structured results are available through
  `journalctl -u honeypot-service-watchdog.service`.
- A normal service deployment must not restart the watchdog's targets. Install
  the files, run one dry check, start the oneshot once, inspect the status, and
  only then enable the timer.

Example dry check:

```text
/usr/bin/python3 /usr/local/libexec/honeypot-service-watchdog.py \
  --config /etc/honeypot/service-watchdog.json \
  --state /tmp/honeypot-service-watchdog-dry-run.json \
  --lock /tmp/honeypot-service-watchdog-dry-run.lock \
  --dry-run
```

`HEALTHY` means the process and any configured local probe passed. `DEGRADED`
means the failure threshold has not yet been reached. `RECOVERED` means a
bounded restart succeeded. `RESTART_FAILED` and `CRASH_LOOP` require operator
inspection. `MAINTENANCE` means recovery was intentionally suppressed.
