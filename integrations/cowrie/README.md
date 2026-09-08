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
