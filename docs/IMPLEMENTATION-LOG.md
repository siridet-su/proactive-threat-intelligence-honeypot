# Implementation log

Append-only record of repository changes, host deployment state, and deferred
verification. Current-state documents remain authoritative for operating rules.

## 2026-09-24 — Renovate backup control-room UI

### Repository changes

- Rebuilt the Backup & Retention page around a single control-room layout.
- Grouped coverage, archive totals, the UTC coverage map, Pi actions, request
  progress, B2 destination, and retention facts into a clear primary/secondary
  hierarchy.
- Added restrained entrance, hover, progress, and request-state transitions
  with reduced-motion handling.
- Shortened operational copy and retained the existing backup API/actions and
  role-based control behavior.

### Host changes

- None. This change is dashboard source only; the Pi backup worker and systemd
  services were not modified or restarted.

### Currently active

- The renovated dashboard is running from the backup worktree on local port
  `3001` for review.

### Not tested or deferred

- `npx tsc --noEmit`, `npm test`, and `npm run build` passed in `dashboard-v2`.
- `npm run lint` passed with one pre-existing warning in the threat-intel
  detail page (`detailData` effect dependencies).
- Authenticated browser screenshot review remains deferred until an operator
  session is available.
