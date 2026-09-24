# ADR-0005: Track the corporate web-decoy source in this repository

- Status: Accepted
- Date: 2026-09-24

## Context

The corporate web decoy is built by the Docker stack whose Compose file lives
in the sibling `decoy-honeypot` directory. Its application source was also
there, outside any Git worktree, so the implemented Odoo-style login page and
telemetry changes could not be reviewed or versioned with the active project.
The stack is not being consolidated as part of this change.

## Decision

- Make [`integrations/web-corp/`](../../integrations/web-corp/README.md) the
  canonical, standalone Docker build context for the corporate web decoy.
- Point the sibling Compose service at that build context. Keep the Compose
  file itself outside this repository for now and document the local sibling
  layout it requires.
- Keep the service as a fake login endpoint: it never authenticates against or
  forwards submitted values to the real Odoo service.
- Treat source migration and deployment as separate operations. Do not rebuild,
  recreate, or expose the running service merely because source moved.

## Consequences

The application, page assets, dependency pins, build recipe, tests, and
operating notes can be reviewed in Git. The deployment Compose file remains an
external dependency and must be consolidated or parameterized before this
layout is portable to a fresh checkout. Runtime behavior and network exposure
remain unchanged until a separately verified rollout.

## Alternatives considered

- Leave the implementation beside the external Compose file: rejected because
  the app source would remain outside version control.
- Move the entire multi-service decoy stack into this repository now: deferred;
  it is broader than the requested web source migration and would require a
  separate review of every service, volume, and network path.
