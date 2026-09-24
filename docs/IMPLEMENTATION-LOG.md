# Implementation log

This is the repository's chronological audit trail for implementation and
deployment work. It supplements, but does not replace, current-state documents,
runbooks, ADRs, commit history, or validation evidence.

## Recording policy

- Add one dated entry for each implementation/deployment change in the same
  repository change. Add an entry even when the code is prepared but deployment
  or activation is intentionally deferred.
- Distinguish repository changes, changes actually applied to a host, and
  runtime state. Use explicit terms such as `prepared`, `installed`, `active`,
  `not deployed`, or `not tested` rather than implying completion.
- Record concise validation commands and outcomes, relevant risks, rollback
  location/procedure, and follow-up work. Link the implementation files, ADR,
  runbook, and commit/PR when available.
- Never record secrets, real attacker credentials, raw attacker payloads,
  private keys, access tokens, or sensitive config contents. Note where a
  protected backup is stored without copying that backup into the repository.
- Append new records under **Entries**. Do not silently edit old records; add a
  dated correction if an earlier fact needs amendment. Keep
  `CURRENT-ARCHITECTURE.md` and service-specific runbooks updated separately
  when the deployed state or operating procedure changes.

## Entry template

Copy this section for a new implementation and replace every prompt with a
verified fact. Remove fields that do not apply, but retain explicit `N/A` or
`not tested` where that distinction matters.

```markdown
### YYYY-MM-DD — Short implementation title

- Status: prepared / installed / active / rolled back
- Scope and intent:
- Repository branch and commit/PR:
- Repository changes:
- Host/environment changes actually applied:
- Runtime/exposure state:
- Validation performed and outcome:
- Not performed / deferred:
- Risks and data handling:
- Rollback:
- Follow-up:
- Related ADR/runbook:
```

## Entries

### 2026-09-24 — Prepare OpenCanary HTTP login honeypot on the Pi

- Status: installed and configured; service intentionally stopped and disabled.
- Scope and intent: add an HTTP login decoy alongside Cowrie for collecting
  web login attempts. Work was limited to OpenCanary; the Pi's OS and unrelated
  services were not upgraded or changed.
- Repository branch and commit/PR: `feat/opencanary-web-login-honeypot`;
  repository changes were not committed at the time of deployment.
- Repository changes: added the OpenCanary HTTP-only config and environment
  templates, service unit, integration runbook, ADR-0004, and updates to the
  service catalog and architecture snapshot.
- Host/environment changes actually applied: installed OpenCanary `0.9.10` in
  `/opt/opencanary/venv`; created the non-login `opencanary` service account;
  installed `/etc/opencanaryd/opencanary.conf`,
  `/etc/opencanaryd/opencanary.env`, and
  `/etc/systemd/system/opencanary.service`. The previous config was preserved
  on the Pi at
  `/etc/opencanaryd/opencanary.conf.pre-http-setup-20260924` with mode `0600`;
  its contents are intentionally not copied into this repository.
- Runtime/exposure state: only the HTTP module is enabled, using `basicLogin`
  at `127.0.0.1:8081`. The unit is `inactive` and `disabled`; there was no
  listener on port `8081` at validation time. No firewall or router exposure
  was added, so this staged configuration does not collect remote traffic.
- Validation performed and outcome: OpenCanary reported version `0.9.10`; its
  config parser resolved the expected node ID, loopback address, HTTP port, and
  skin; the JSON parsed; the service user could read the config and environment
  file; `systemd-analyze verify` passed after removing an unsupported unit
  condition; and `git diff --check` passed.
- Not performed / deferred: the unit was not started, no HTTP request or login
  POST was sent, no external reachability test was performed, and no Redis/Atlas
  event-pipeline integration was implemented.
- Risks and data handling: login values can contain real credentials or
  injection strings. The native log is local at
  `/var/log/opencanary/events.jsonl`, rotated at 10 MiB with seven backups; do
  not commit or forward it without a separate privacy/retention review.
- Rollback: stop the unit if it has since been started, restore the protected
  config backup above, and follow the rollback guidance in
  [`integrations/opencanary/README.md`](../integrations/opencanary/README.md).
- Follow-up: decide separately when and how to expose the listener beyond
  loopback; review interface, port, firewall, and router path before doing so.
- Related ADR/runbook: [ADR-0004](adr/ADR-0004-opencanary-http-login.md) and
  [OpenCanary runbook](../integrations/opencanary/README.md).

### 2026-09-24 — Merge focused filesystem replay visualization into main

- Status: prepared and merged into repository `main`; not deployed to a host.
- Scope and intent: integrate the completed filesystem visualization branch,
  including stable source connector geometry, collision-aware verified CWD
  transition routing, a current-hop-first replay view, and synchronized transfer
  and destination-impact effects.
- Repository branch and commit/PR: source branch
  `feat/filesystem-visualization-semantics`; merge commit recorded in Git history.
- Repository changes: the audit canvas now defaults to the selected current hop,
  provides optional previous-trail and all-transition comparison modes, keeps the
  complete accessible transition sequence, restores the six-layer light packet
  and impact wave, omits the redundant current-hop arrowhead, and retains
  directional arrows for non-current events only in all-transition mode. The
  splitter pointer suite now installs its own in-memory Storage stub so Node 26's
  unavailable global `localStorage` accessor cannot leak state or fail setup.
- Host/environment changes actually applied: none. No dashboard process,
  systemd unit, reverse proxy, database, Pi service, or network exposure was
  changed.
- Runtime/exposure state: repository implementation only; production deployment
  and activation were not performed in this change.
- Validation performed and outcome: focused splitter suite passed 6/6; full
  Vitest passed 797 tests with 2 expected failures and 14 skipped; ESLint passed
  with zero errors; webpack production build passed and generated 19/19 static
  pages; Chromium filesystem browser suite passed 15/15; `git diff --check`
  passed. Add/add conflicts in five hardware-backup files were resolved by
  preserving the newer `main` versions from the completed backup PR.
- Not performed / deferred: no host deployment or external exposure test was
  performed. A later visual refinement may reduce endpoint-ring/glow density;
  it is intentionally not part of this merge.
- Risks and data handling: no telemetry authority, API schema, retained evidence,
  secrets, attacker payloads, or protected configuration were changed. Visual
  density modes change presentation only; event identity and chronology remain
  available to assistive technology.
- Rollback: revert the merge commit on `main`; no host rollback is required for
  this repository-only change.
- Follow-up: visually evaluate whether the animated destination should suppress
  its static endpoint ring while preserving the reduced-motion fallback.
- Related ADR/runbook: filesystem semantics and validation evidence are recorded
  in
[`dashboard-v2/docs/FILESYSTEM_ACTIVITY_VISUALIZATION_IMPLEMENTATION_PLAN.md`](../dashboard-v2/docs/FILESYSTEM_ACTIVITY_VISUALIZATION_IMPLEMENTATION_PLAN.md).

### 2026-09-24 — Refine backup worktree dashboard UI

- Status: prepared for review; not deployed to a host.
- Scope and intent: preserve the backup control-room feature while improving
  the System Health information hierarchy and custom history range interaction.
- Repository branch and commit/PR: `feat/dashboard-backup-status`; UI work is
  based on commits `cd84a77` and `51182f6` and is being reconciled with the
  current `main` branch.
- Repository changes: renovated live hardware telemetry, moved Source activity
  to a full-width section, kept retained history as a separate region, made the
  custom date range highlight continuous across start/middle/end days, and
  retained the backup action/progress and B2 status surfaces.
- Host/environment changes actually applied: none. No Pi service, systemd unit,
  database, reverse proxy, or network exposure was changed.
- Runtime/exposure state: available only from the local dashboard worktree on
  port `3001` for authenticated review.
- Validation performed and outcome: `npx tsc --noEmit`, `npm run lint`,
  `npm test`, `npm run build`, and `git diff --check` passed after the
  main-branch reconciliation. The test suite reported 797 passing tests, 2
  expected failures, and 14 skipped; ESLint has no new errors.
- Not performed / deferred: no host deployment or external exposure test was
  performed.
- Rollback: revert the merge/feature commit on this branch; no host rollback is
  required.
- Follow-up: push the resolved branch for PR review and visually review the
  authenticated dashboard at local port `3001`.

### 2026-09-24 — Renovate Artifact Intelligence workspace

- Status: prepared for review; not deployed to a host.
- Scope and intent: make the hash-only artifact view easier to scan and expose
  more investigation context without expanding retention scope or storing raw
  binaries/payloads.
- Repository branch and commit/PR: `feat/dashboard-backup-status`; dashboard
  source changes are currently uncommitted.
- Repository changes: added indexed-hash, review-flag, evidence-link, and
  provider-coverage summaries; added current-page signal distribution and
  review queue; added status filters; and replaced the dense table rows with
  responsive artifact records showing first/last seen, size, provider expiry,
  evidence/source/session counts, linked sessions, and VirusTotal actions.
- Host/environment changes actually applied: none. No API route, MongoDB
  collection, Pi service, systemd unit, or network exposure was changed.
- Runtime/exposure state: available from the local dashboard worktree at
  `http://localhost:3001/malware-vault` after operator authentication.
- Validation performed and outcome: `npx tsc --noEmit`, `npm run lint`,
  `npm run build`, `npm test`, and `git diff --check` passed. The test suite
  reported 797 passing tests, 2 expected failures, and 14 skipped.
- Not performed / deferred: authenticated browser screenshot review remains
  deferred; the summary cards intentionally describe the currently loaded page
  because the existing API does not expose global status aggregates.
- Risks and data handling: all new presentation values are derived from the
  existing bounded `ArtifactRecord` response; no raw artifact bytes, raw event
  payloads, credentials, or provider secrets are rendered.
- Rollback: revert the Artifact Intelligence page change; no host rollback is
  required.
