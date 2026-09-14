# Cowrie response control plane

## Phase 1 scope

Phase 1 supports one operation: terminate one live Cowrie transport by its
12-character Cowrie session ID. It deliberately does not provide a terminal,
arbitrary command string, source-IP block, service restart, file operation, or
configuration mutation.

## Trust path

```text
Admin browser
  -> same-origin dashboard route (session auth, Admin role, confirmation)
  -> response agent over Tailscale (bearer service credential)
  -> Cowrie Unix socket (cowrie group only)
  -> exact in-process transport registry
  -> cowrie.session.closed verification in MongoDB
```

The Pi agent must bind only to its Tailscale address. Tailnet grants should
allow the dashboard service identity to reach the response-agent port and no
other source. The Cowrie hook is disabled unless
`HONEYPOT_COWRIE_CONTROL_SOCKET` is set. The dashboard control remains disabled
unless both `COWRIE_RESPONSE_AGENT_URL` and `COWRIE_RESPONSE_AGENT_TOKEN` are
set server-side.

Example grant (merge with the existing tailnet policy and tag ownership):

```json
{
  "grants": [
    {
      "src": ["tag:pti-dashboard"],
      "dst": ["tag:pti-honeypot"],
      "ip": ["tcp:8788"]
    }
  ]
}
```

Do not grant the operator user group direct access to port 8788. Human access
continues through the dashboard's authenticated action route.

## Pi deployment inputs

- Build `agents/response-agent` as `/usr/local/libexec/honeypot-response-agent`.
- Create the locked service account `cowrie-response` with supplementary group
  `cowrie` and no login shell.
- Install `systemd-services/cowrie-session-control.conf` as a Cowrie drop-in.
- Install `systemd-services/honeypot-response-agent.service`.
- Create `/etc/honeypot/response-agent.token` as `0600 root:root`, containing a
  random value of at least 32 characters.
- Create `/etc/honeypot/response-agent.env` as `0600 root:root` with only
  `RESPONSE_AGENT_LISTEN=<pi-tailscale-ip>:8788`.

Installing or restarting these live services is a separate operational change:
run the Cowrie service-smoke test first, preserve the current sanitized-output
rollback receipt, then deploy in a controlled window. Do not test by terminating
an uncontrolled attacker session; use a known synthetic session and verify its
action record and `cowrie.session.closed` event.

## Action lifecycle

- `requested`: the authenticated dashboard accepted the operator intent.
- `delivered`: the Pi agent accepted the exact session ID.
- `verified`: MongoDB observed that same session transition to closed after the
  request time.
- `failed`: delivery was rejected/unavailable or closure was not verified within
  the bounded window.

Audit records are retained for 90 days in `session_response_actions`.
