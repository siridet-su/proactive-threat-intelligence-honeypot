# Tailscale response-control identity

The response channel uses two non-human tailnet identities:

- `tag:pti-dashboard`: the deployed dashboard host that originates actions.
- `tag:honeypot-pi`: the Pi that exposes the allow-listed response agent.

The production grant is intentionally one-way and one-port:

```text
tag:pti-dashboard -> tag:honeypot-pi tcp/8788
```

Merge [`response-control.policy.hujson`](./response-control.policy.hujson) into
the existing policy instead of replacing the policy file. Keep the included
policy test: it proves the desired port is reachable and catches accidental
SSH or adjacent-port access granted to the dashboard identity.

## Deployment sequence

1. Add both tag-owner entries, the grant, and the policy test. If a tag-owner
   entry already exists, preserve its authorized owners instead of replacing
   the list. Saving must pass before any device identity changes.
2. Join the production dashboard host with a tagged, non-human device identity
   advertising only `tag:pti-dashboard`. Do not apply this tag to a developer
   laptop; a tag replaces the device's user identity.
3. Confirm the Pi remains tagged `tag:honeypot-pi` and the response agent binds
   only to its Tailscale address on port 8788.
4. Copy the response-agent token to a root-owned `0600` file on the dashboard
   host. Load it into the dashboard service with a systemd credential; never
   put it in an application release or a `NEXT_PUBLIC_*` variable.
5. Update the Pi host firewall to allow TCP 8788 on `tailscale0` from the new
   dashboard Tailscale IP. Tailnet tags provide identity authorization; the
   host firewall remains an independent IP-level containment layer.
6. Run a synthetic Cowrie session and terminate that exact session through the
   dashboard. Require a `verified` action record and matching
   `cowrie.session.closed` event before removing the temporary developer-IP
   grant.
7. Remove the temporary `100.102.165.62 -> tag:honeypot-pi tcp/8788` grant and
   its matching Pi firewall rule after the tagged deployment passes.

## Expected dashboard service settings

Use the companion systemd drop-in example at
[`systemd-services/honeypot-dashboard-v2-response.conf.example`](../../systemd-services/honeypot-dashboard-v2-response.conf.example).
Replace the response-agent URL placeholder before installation. The application
will reject a relative path, symlink, group/other-accessible file, malformed
token, or file larger than 4096 bytes.
