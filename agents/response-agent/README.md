# Honeypot response agent

This agent exposes exactly one operation to the private management plane:
terminate one live Cowrie connection by its 12-character transport ID. It has
no shell or generic command endpoint.

The HTTP listener must bind to the Pi's Tailscale address. A bearer credential
is read from a private file, and the action is forwarded to Cowrie over its
local Unix socket.

Required environment:

- `RESPONSE_AGENT_LISTEN`, for example `100.118.43.30:8788`
- `RESPONSE_AGENT_TOKEN_FILE`, preferably a systemd credential path
- `COWRIE_CONTROL_SOCKET`, normally `/run/cowrie-control/control.sock`

Tailnet policy should grant only the dashboard service identity access to this
port; operators never connect to it directly.
