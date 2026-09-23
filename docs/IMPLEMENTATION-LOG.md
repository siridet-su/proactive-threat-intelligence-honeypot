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

## 2026-09-24 — Compact hardware history range picker

### Repository changes

- Reduced the custom history popover footprint and removed unnecessary nested
  calendar framing and padding.
- Placed Start and End time controls side by side with compact quick presets,
  kept the footer visible, and added a bounded viewport for short screens.
- Preserved the existing date validation, custom-range toggle, time precision,
  and apply/cancel behavior.

### Host changes

- None. This is dashboard source only; Pi services and hardware agents were not
  modified or restarted.

### Currently active

- The compact range picker is available from the backup worktree on local port
  `3001` for review.

### Validation performed and outcome

- `npx tsc --noEmit`, `git diff --check`, and `npm run lint` passed.
- Lint retains one pre-existing warning in the threat-intel detail page.

## 2026-09-24 — Stabilize history controls during hydration

### Repository changes

- Made the history range and Refresh controls hydration-safe by exposing their
  disabled state only after the client has hydrated and retained data is
  already present for a refresh operation.
- Prevented the initial server/client render from disagreeing about `disabled`
  attributes while the first history request is still loading.

### Host changes

- None. This is dashboard source only; Pi services and hardware agents were not
  modified or restarted.

### Currently active

- The fix is active in the backup worktree on local port `3001` for review.

### Validation performed and outcome

- `npx tsc --noEmit`, `git diff --check`, and `npm run lint` passed.
- Dev server compiled the updated System Health route without a new hydration
  warning after restart.
- Lint retains one pre-existing warning in the threat-intel detail page.

## 2026-09-24 — Fluid custom calendar layout

### Repository changes

- Changed the custom range calendar from content-sized to fluid layout so the
  weekday columns use the full popover width.
- Reduced the popover max width to keep the calendar and the compact time
  controls visually balanced instead of leaving unused side space around the
  date grid.

### Host changes

- None. This is dashboard source only; Pi services and hardware agents were not
  modified or restarted.

### Currently active

- The revised custom calendar is available from the backup worktree on local
  port `3001` for review.

### Validation performed and outcome

- `npx tsc --noEmit`, `git diff --check`, and `npm run lint` passed.
- Lint retains one pre-existing warning in the threat-intel detail page.

## 2026-09-24 — Renovate System Health control room

### Repository changes

- Reorganized System Health into distinct live telemetry, source activity, and
  retained history regions instead of stacking all data in one dense panel.
- Reworked live hardware cards so CPU, memory pressure, storage, temperature,
  and wlan0 details are visible without a flip interaction, with compact prior
  sample deltas and signal state colors.
- Reworked live charts into a primary system-pressure view plus thermal and
  network signal cards; history now uses Pressure, Thermal, and Network tabs
  with range snapshots showing latest values and retained min / max spread.
- Reworked source IP presentation into ranked activity rows with proportional
  event bars, compact location/technique context, search, and live-feed state.

### Host changes

- None. This is dashboard source only; Pi services and hardware agents were not
  modified or restarted.

### Currently active

- The renovated page is available from the backup worktree on local port
  `3001` for review.

### Validation performed and outcome

- `npx tsc --noEmit` passed.
- `npm test` passed: 61 test files passed, 1 skipped; 784 tests passed, 2
  expected failures, and 14 skipped.
- `npm run lint` passed with one pre-existing warning in the threat-intel
  detail page (`detailData` effect dependencies).
- `npm run build` passed and compiled `/system-health` plus its hardware API
  routes.
- Unauthenticated route check returned the expected redirect to `/login`.

### Not tested or deferred

- Authenticated browser screenshot review remains deferred until an operator
  session is available.
## 2026-09-24 — Reflow System Health source activity

### Repository changes

- Moved `Source activity` below the live telemetry panel as a full-width section so the source, activity, and risk columns have enough horizontal space.
- Added a bounded scroll area for the ranked source table and reduced the panel's minimum height so a large feed does not stretch the entire page.

### Host changes

- None.

### Currently active

- Dashboard worktree: `migrate-data/worktrees/dashboard-backup`
- Branch: `feat/dashboard-backup-status`
- Dev server: `http://localhost:3001`

### Validation

- `npx tsc --noEmit` passed.
- `npm run lint` passed with one pre-existing warning in the threat-intel
  detail page (`detailData` effect dependencies).
- `git diff --check` passed.
- Dev server compiled the updated System Health route on port `3001`.

## 2026-09-24 — Connect custom history range highlight

### Repository changes

- Made each custom calendar day button fill its entire date cell so the selected range renders as one continuous highlighted band.
- Kept the rounded treatment only on the range start and end while preserving the selected-day contrast and hover states.

### Host changes

- None. This is dashboard source only; Pi services and hardware agents were not modified or restarted.

### Currently active

- The connected range highlight is available from the backup worktree on local port `3001` for review.

### Validation

- `npx tsc --noEmit` passed.
- `npm run lint` passed with one pre-existing warning in the threat-intel
  detail page (`detailData` effect dependencies).
- `git diff --check` passed.
- Dev server compiled the updated range picker.
