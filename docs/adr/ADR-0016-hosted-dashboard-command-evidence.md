# ADR-0016: Serve hosted Dashboard command evidence from canonical MongoDB

- Status: Accepted
- Date: 2026-09-28

## Context

The Filesystem Activity Evidence panel uses the Admin-only
`/api/sessions/{id}/commands` route. Its production source previously required
an owner-only token file and a `monitor_web` service on the Dashboard host's
loopback interface. The hosted Dashboard is a separate service and cannot use
the Pi monitor through its own `127.0.0.1`. The deployed panel reports 503 even
though the Dashboard already reads canonical MongoDB for other views. A local
development projection has demonstrated exact-session command retrieval from
that collection.

## Decision

- Keep the existing loopback monitor source for colocated deployments.
- Allow a hosted production Dashboard to select the canonical MongoDB source
  only with the server-only `PTI_ADMIN_COMMANDS_SOURCE=mongo` setting. An absent
  or different value retains the monitor path; a monitor failure never silently
  falls back to MongoDB.
- Keep authentication, Admin role, password-rotation denial, and authenticated
  sensor-local-to-canonical session binding before either source is queried.
- Query only `cowrie.command.input` for the verified canonical session; bound
  query time, row count, payload size, and returned command input. Return the
  existing sensitive, private, no-store response contract. No browser code
  receives a MongoDB credential or chooses a database target.
- Configure the hosted deployment through its private server environment.
  Do not put the MongoDB URI or command contents in repository configuration,
  logs, exports, public APIs, or build-time client variables.

## Consequences

The hosted Dashboard's Admin session and MongoDB access become the command
evidence authority for this opt-in path. Operators must protect those
credentials and restrict database permissions as far as the Dashboard's other
read paths allow. Historical input redacted before persistence remains
unrecoverable. Until the hosted environment setting and deployment are applied
and an authenticated request is checked, the production 503 is not considered
resolved. Disable the setting to return to the monitor-only path.
