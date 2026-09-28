# Authoritative Cowrie CWD telemetry

This integration makes Cowrie's virtual working directory an explicit source
event. The collector and processor do not parse attacker command text or guess
filesystem state.

## Compatibility

The patch is reviewed against Cowrie commit
`575146bc6b24d70082527d66cd805d9bae0e0db4` (the base used by the current
v2.6.1-derived deployment). Apply it to a clean, version-pinned Cowrie staging
checkout first. A dirty or independently patched checkout requires a new patch
review and the same contract tests before deployment.

For a clean Ubuntu 24.04 ARM64 staging host, use
[`build_cowrie_source.py`](../../scripts/build_cowrie_source.py) from the exact
clean checkout and the separate
[`prepare-cowrie.yml`](../../deploy/ansible/prepare-cowrie.yml) playbook. The
builder applies this patch, creates a reproducible source archive, and prints
the patch and archive SHA-256 values. The playbook verifies the approved
archive, stages source and a Python venv, and leaves Cowrie without a service
or listener. It does not install the sanitized JSON writer, configure its
privacy boundary, or qualify Cowrie for activation.

## Event contract

`cowrie.command.input` adds the authoritative CWD immediately before command
execution:

```json
{"eventid":"cowrie.command.input","session":"...","input":"pwd","cwd":"/home/operator","cwd_status":"confirmed"}
```

`cowrie.session.cwd` records every successful or failed `cd` operation:

```json
{"eventid":"cowrie.session.cwd","session":"...","cwd_before":"/home/operator","cwd_after":"/var/tmp","cwd_action":"changed","cwd_status":"confirmed"}
```

For `failed_change`, `cwd_after` equals `cwd_before`. The processor keeps
that confirmed path as current state but stores no unverified target path.

## Staging procedure

1. Check out the pinned Cowrie revision in an isolated staging directory.
2. Verify and apply the patch:

   ```sh
   git apply --check /path/to/proactive-threat-intelligence-honeypot/integrations/cowrie/patches/0001-authoritative-cwd-telemetry.patch
   git apply /path/to/proactive-threat-intelligence-honeypot/integrations/cowrie/patches/0001-authoritative-cwd-telemetry.patch
   ```

3. Run Cowrie's command tests and start a non-public staging listener.
4. Execute a benign `pwd`, a successful `cd /var/tmp`, and a failed
   `cd /does-not-exist`.
5. Confirm the resulting JSON matches
   [the contract fixtures](fixtures/cwd-events.jsonl), then replay those rows
   through collector and processor staging instances.
6. Confirm `cwd_session_state`, `cwd_events`, REST history pagination, and
   SSE updates before switching the live listener.

The repository's sanitized JSON writer preserves these fields. Its privacy
regression test proves that both event shapes survive pre-persistence
sanitization without weakening credential redaction.

Do not apply the patch directly to a live dirty Cowrie checkout. Preserve its
existing patch series and use the project's normal staged deployment and
rollback process.

## Current Pi watchdog probe and loopback cleanup

The existing Pi's `honeypot-service-watchdog.timer` runs about every 30 seconds.
Since the 2026-09-28 cutover, it checks Cowrie's service state and inspects
`/proc/net/tcp` for the port 22 listener without connecting to Cowrie. The
earlier active TCP probe opened `127.0.0.1:22` connections. Cowrie emitted a
`cowrie.session.connect` and `cowrie.session.closed` pair for each check, and
the normal pipeline created canonical sessions with source IP `127.0.0.1`.
Those probes did not authenticate or submit commands. See the
[watchdog runbook](../../deploy/service-watchdog/README.md) for the active
method and rollback.

The [MongoDB cleanup tool](../../honeypot-analysis/production/tools/clear_loopback_cowrie_sessions.py)
selects only closed `production_live` sessions older than two minutes with
exactly one processed connect and one processed closed event, both from
`127.0.0.1`, and a connect destination of `127.0.0.1:22`. It excludes local
sessions with login, command, or other activity and excludes port 2222. It
checks every collection for other references, saves the selected documents in
a verified, root-only Pi backup, then deletes their exact MongoDB `_id` values
in a transaction. Run without `--execute` to inspect the current counts; an
execution requires the protected processor environment file and root access.
The backup directory and counts are printed after the operation. Do not copy
the archive or the processor environment into Git.
After a cleanup, reload the Dashboard page to replace its in-memory live-feed
snapshot. The live feed streams upserts; it does not push MongoDB deletion
events into an already-open browser tab.
