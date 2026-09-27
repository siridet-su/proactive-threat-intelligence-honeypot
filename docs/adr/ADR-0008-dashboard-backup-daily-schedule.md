# ADR-0008: Dashboard-controlled daily backup schedule

- Status: Accepted
- Date: 2026-09-27

## Context

The Pi currently starts its retained-data backup from a fixed 03:30
Asia/Bangkok systemd timer. Operators want to change the daily time either
permanently or for a bounded date range, then return to the permanent time.
The Dashboard and worker already communicate through MongoDB, while B2 keys
and host administration remain on the Pi.

The archive window uses UTC days and a two-day safety hold. A schedule at
01:00–03:30 Bangkok occurs on the previous UTC date; Dashboard coverage must
be anchored to the most recent scheduled occurrence so it does not claim an
additional UTC day is missing after 07:00 Bangkok.

## Decision

- Keep one daily schedule in `Asia/Bangkok`. Store a permanent `HH:mm` base
  time (default `03:30`) and at most one temporary override with an inclusive
  local start date, a bounded number of days, and its own `HH:mm` time.
- The Dashboard has one Admin-only schedule form. A permanent edit changes
  the base and preserves any active override; a temporary edit replaces the
  override; clearing the override returns to the current base. Show the next
  run and the automatic return date before saving.
- Append complete schedule revisions to a dedicated MongoDB collection. A
  unique predecessor key prevents concurrent Admin edits from silently
  overwriting one another. Each revision records the operator and timestamp;
  no secret or attacker data enters these records.
- The existing Pi control worker reads the latest valid schedule and claims
  at most one scheduled run per Bangkok calendar date. A time moved into the
  past triggers a prompt catch-up if today's scheduled run has not completed.
  A running or completed run is not duplicated, and failed runs retry with a
  bounded delay. Manual backup actions remain separate.
- Disable the fixed 03:30 timer only after the control worker's scheduler is
  deployed and verified. The oneshot backup service remains available for
  operator-triggered recovery. The Dashboard never edits systemd or obtains
  host/B2 credentials.
- Scope the Dashboard's expected UTC coverage window to the most recent
  scheduled local occurrence. Show overdue scheduler state separately from
  manifest coverage.

## Consequences

- Schedule changes depend on the Pi control service and MongoDB; systemd
  restarts the control service if it exits. A missed daily run is caught up
  after the service recovers.
- The temporary override returns to the then-current permanent base, even
  if an Admin updates that base while the override is active.
- Schedule revisions and run claims are audit records; they are not deleted
  when an override expires or a time changes.
- A schedule edit does not change the UTC retention window, safety hold,
  target set, B2 bucket, or sensitive-target policy.
