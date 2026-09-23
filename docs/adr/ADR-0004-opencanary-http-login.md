# ADR-0004: Stage an OpenCanary HTTP login decoy

- Status: Accepted
- Date: 2026-09-24

## Context

Cowrie provides the project's command-line deception surface. A separate HTTP
login decoy is needed to record web login attempts, including brute-force and
SQL-injection strings submitted through the login form. The Pi already has a
local web middleware listener on port 80, so OpenCanary must use a distinct
staging port until its eventual exposure path is reviewed.

## Decision

- Use the upstream OpenCanary package pinned to `0.9.10` in a dedicated Python
  virtual environment on the Pi.
- Enable only OpenCanary's HTTP module with the built-in `basicLogin` skin.
- Bind the staged service to `127.0.0.1:8081`; do not add firewall or router
  exposure as part of this preparation.
- Run the foreground Twisted service as a dedicated unprivileged system user.
- Store structured events in a local rotating JSON log with restrictive file
  permissions. The log includes submitted login values and must be treated as
  sensitive attacker-supplied data.
- Keep the unit installed but stopped and disabled until the operator starts
  it. Integrating its events into Redis/Atlas is a separate change.

## Consequences

The staged service can be started and checked locally without taking over the
existing port 80 listener. It will not receive remote attack traffic until a
separate interface, port, firewall, and upstream forwarding decision is made.
The native HTTP module records username/password form fields; arbitrary JSON
bodies are not treated as login credentials by this configuration.

## References

- [OpenCanary upstream documentation](https://github.com/thinkst/opencanary)
- [OpenCanary 0.9.10 package metadata](https://pypi.org/project/opencanary/0.9.10/)
