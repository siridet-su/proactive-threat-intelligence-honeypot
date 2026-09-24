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

### 2026-09-24 — Confirm canonical backup control-plane decisions

- Status: planning decisions approved; implementation not started.
- Scope and intent: clarify that the canonical backup control database records
  dashboard requests, worker progress, archive manifests, hashes, and
  verification results; it is not a second copy of canonical event data.
- Repository branch and commit/PR: current working branch; documentation is
  uncommitted.
- Repository changes: updated the living canonical backup plan with the
  cloud-neutral activation posture, B2 least-privilege roles, separate
  operational control database direction, illustrative request/manifest
  contracts, and the approved initial archive scope.
- Host/environment changes actually applied: none. No GCP runner, B2 key,
  Mongo role, TTL index, scheduler, or purge operation was changed.
- Runtime/exposure state: code is to be prepared for later cloud activation;
  no canonical archive worker is active.
- Validation performed and outcome: documentation diff checks pass; no data
  export or source-database mutation was performed.
- Not performed / deferred: final control database name, activation cloud,
  prediction snapshot policy, external TI archive profile, restore format, and
  purge approval role remain open decisions.
- Risks and data handling: upload workers must not receive `deleteFiles`; the
  restore role remains read-only. Control records contain no event payloads or
  secrets.
- Rollback: revert the uncommitted documentation changes; no host rollback is
  required.
- Follow-up: implement the policy and control contracts in an isolated branch,
  then run a dry-run selector before any B2 upload.
- Related ADR/runbook: [canonical backup and retention implementation plan](design/canonical-backup-retention-implementation-plan.md).

### 2026-09-24 — Prepare canonical backup and retention implementation plan

- Status: plan prepared; no implementation or retention action activated.
- Scope and intent: define a policy-aware archive lifecycle for
  `honeypot_canonical_v1` so canonical evidence can move to compressed B2
  storage without introducing unsafe database-wide TTL deletion.
- Repository branch and commit/PR: current working branch; plan is currently
  uncommitted.
- Repository changes: added the living
  [`canonical backup and retention implementation plan`](design/canonical-backup-retention-implementation-plan.md)
  and linked it from the design index. The plan records the verified live
  collection inventory, canonical/legacy authority boundaries, archive
  manifest contract, dependency gates, worker placement, rollout phases, and
  purge rollback requirements.
- Host/environment changes actually applied: none. No MongoDB collection,
  TTL index, B2 object, Pi service, systemd unit, scheduler, or purge operation
  was changed.
- Runtime/exposure state: no canonical archive worker is installed or active;
  the existing backup worker remains scoped to `honeypot_db.hardware_metrics_1m`.
- Validation performed and outcome: read-only Mongo metadata and identity
  checks were performed; no document values or secrets were recorded. The plan
  distinguishes exact `event_id` overlap from shared observable values.
- Not performed / deferred: no archive export, B2 upload, restore rehearsal,
  dashboard change, policy activation, or deletion was performed.
- Risks and data handling: the current canonical database has runtime external
  TI collections that are not in the 31-entry schema manifest; reconciliation
  is a Phase 1 gate. Canonical purge remains disabled until backup and restore
  evidence exist.
- Rollback: remove the uncommitted plan/index changes; no host rollback is
  required.
- Follow-up: approve the runner host, retention windows, archive format,
  manifest location, and purge authority before Phase 1 implementation.
- Related ADR/runbook: [canonical backup and retention implementation plan](design/canonical-backup-retention-implementation-plan.md).

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

### 2026-09-24 — Add a square radar canvas to Live Filesystem Activity

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: give the Live topology a full-surface submarine-style radar treatment with square range frames, while leaving the Audit view and telemetry semantics unchanged.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `8e83688`; this work is uncommitted.
- Repository changes: define a standard `1000×1000` logical radar plane; add a live-only square range overlay, square grid, center axes, status readouts, and a sweep that is omitted when reduced motion is requested; add `FS-024` to the Filesystem Activity working state.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js dev server remains active on port `3000`; the edited page was served after HMR compilation. The development server reported that `AUTH_SESSION_SECRET` is unset and used its development-only fallback; this is not production activation.
- Validation performed and outcome: Next.js dev HMR compiled the changed modules and `/filesystem-activity` returned HTTP 200. No automated tests were run.
- Not performed / deferred: authenticated screenshot review across desktop/mobile sizes, light/dark visual review, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only change; no API, MongoDB query, path evidence, or telemetry authority changed. The radar plane is a visual coordinate system, not geographic or filesystem scale.
- Rollback: remove the `LIVE_RADAR_CANVAS_SIZE`/`LiveRadarOverlay` additions and corresponding radar styles while preserving prior uncommitted edits in the same files; no host rollback is required.
- Follow-up: visually review the authenticated Live canvas at supported wide and narrow viewport sizes, including reduced-motion mode, before marking `FS-024` done.
- Related ADR/runbook: no architecture decision or operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-24 — Fill the Live radar plane and rotate its sweep

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: use the remaining Live topology panel height for the empty-state radar plane and make its sweep rotate around the center.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `8e83688`; this work is uncommitted.
- Repository changes: let the Live standby wrapper and canvas grow within the topology panel; animate a circular sweep wedge and beam around the center of the standardized square canvas; disable sweep animation for reduced-motion preferences; update `FS-024` current-state criteria and decision/update records.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js dev server remains active on port `3000`; HMR compiled the edited modules.
- Validation performed and outcome: Next.js dev HMR compiled successfully. No automated tests were run.
- Not performed / deferred: authenticated browser screenshot review, responsive and light/dark visual review, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only change; no API, MongoDB query, path evidence, or telemetry authority changed. The square radar plane is a visual coordinate system, not geographic or filesystem scale.
- Rollback: revert the standby flex sizing and `pti-live-radar-sweep-*` animation rules and markup; no host rollback is required.
- Follow-up: visually review the authenticated Live canvas at supported viewport sizes and confirm reduced-motion behavior before marking `FS-024` done.
- Related ADR/runbook: no operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-24 — Extend the Live sweep across the full canvas

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: rotate a circular radar sweep from the canvas center out to the full responsive canvas bounds, with an energy trail behind its leading line.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `8e83688`; this work is uncommitted.
- Repository changes: measure the Live overlay with `ResizeObserver`; render the rotating sweep in a viewport-sized SVG with a radius reaching beyond the canvas corners; fade the green trail from transparent at its trailing edge toward the beam; remove the beam's front glow; update the `FS-024` current-state record.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js dev server remains active on port `3000`; HMR compiled the edited modules and the authenticated `/filesystem-activity` page returned HTTP 200.
- Validation performed and outcome: HMR compilation and authenticated page response succeeded; `git diff --check` passed for the edited source and documentation files. No automated tests were run.
- Not performed / deferred: new authenticated screenshot review, responsive and light/dark visual review, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only change; the observer only sizes the visual sweep to its container; no API, MongoDB query, path evidence, or telemetry authority changed.
- Rollback: remove the radar overlay size observer and dynamic sweep SVG/gradient styles; no host rollback is required.
- Follow-up: visually review the trail direction, full-canvas coverage, and no-glow beam at supported viewport sizes before marking `FS-024` done.
- Related ADR/runbook: no operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-24 — Anchor Live radar ticks to canvas edges

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: align the four cardinal accent ticks with the full responsive canvas while keeping square radar range frames centered.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `8e83688`; this work is uncommitted.
- Repository changes: replace ticks attached to the outer square frame with four edge-positioned marks spanning inward from the top, right, bottom, and left canvas boundaries; update `FS-024` criteria and decision/update records.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js dev server remains active on port `3000`; HMR compiled the edited modules and the authenticated `/filesystem-activity` page returned HTTP 200.
- Validation performed and outcome: HMR compilation and authenticated page response succeeded; `git diff --check` passed for the edited source and documentation files. No automated tests were run.
- Not performed / deferred: new authenticated screenshot review, responsive and light/dark visual review, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only change; no API, MongoDB query, path evidence, or telemetry authority changed.
- Rollback: restore the SVG frame-bound tick path and remove the `.pti-live-radar-edge-tick` markup/styles; no host rollback is required.
- Follow-up: visually review edge alignment at supported viewport sizes before marking `FS-024` done.
- Related ADR/runbook: no operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-24 — Calculate the radar wake against the canvas boundary

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: make the circular beam end at the first rectangle edge for each heading and shape its trailing energy wake from the same angle-dependent boundary intersections.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `865c23e`; this refinement is uncommitted.
- Repository changes: calculate the beam endpoint from the nearest canvas edge on every animation frame; trace the wake's outer contour along the corresponding rectangle boundary, including crossed corners; use a conic opacity gradient that is strongest at the beam and fades backward; clip the wake bloom behind the beam and keep the beam itself unglowed; render at up to 30 frames per second and stop the canvas animation for reduced-motion users.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js dev server remains active on port `3000`; HMR compiled the edited modules and the authenticated `/filesystem-activity` page returned HTTP 200.
- Validation performed and outcome: Next.js dev HMR compilation and authenticated page response succeeded. No automated tests were run.
- Not performed / deferred: screenshot review at cardinal directions and corners, responsive/light/dark visual review, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only change; no API, MongoDB query, path evidence, or telemetry authority changed. Canvas drawing is limited to the decorative radar sweep.
- Rollback: restore the SVG sweep from commit `865c23e` and remove the boundary-intersection helpers and canvas animation; no host rollback is required.
- Follow-up: visually inspect the wake as the beam crosses all four edge centers and corners before marking `FS-024` done.
- Related ADR/runbook: no operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-24 — Record the accepted Live radar design commit (addendum)

- Addendum: the initial square radar, full-height Live plane, full-canvas sweep, and canvas-edge ticks from the earlier `FS-024` entries were committed on this branch as `865c23e` (`feat(filesystem): add full-canvas radar sweep`). Their earlier `uncommitted` status reflects the state before that commit.
- Current repository state: the rectangle-boundary wake refinement recorded immediately above is a separate uncommitted change based on `865c23e`.
- Host/environment changes actually applied: none; the radar design remains local and is not deployed.

### 2026-09-24 — Smooth the Live radar wake and soften its center axes

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: make the trailing energy glow taper more smoothly and reduce the dashed center axes showing through its transparent edge.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `865c23e`; this refinement is uncommitted.
- Repository changes: add a multi-stop opacity ramp to the trailing wake, remove its extra overlapping fill pass, keep a clipped soft bloom behind the crisp beam, and reduce center-axis contrast; update the `FS-024` current-state criteria and decision/update records.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js development server remains active on port `3000`; HMR compiled the edited modules.
- Validation performed and outcome: Next.js development HMR compilation succeeded. No automated tests were run.
- Not performed / deferred: authenticated screenshot review, responsive/light/dark visual review, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only canvas/CSS change; no API, MongoDB query, path evidence, or telemetry authority changed. The dashed center axes remain decorative radar guides.
- Rollback: restore the radar gradient and axis styles in `TopologyCanvas.tsx` and `globals.css`; no host rollback is required.
- Follow-up: inspect the wake at several headings and canvas aspect ratios before marking `FS-024` done.
- Related ADR/runbook: no operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-24 — Simplify the Live radar frame and status layout

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: reduce visual clutter around the Live radar and keep retained-session access with the Session Audit controls.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `865c23e`; this refinement is uncommitted.
- Repository changes: retain only the outer and one inner square frame; soften the grid and inner frame; remove corner diagnostics and extra center outlines; use one outlined HardDrive beacon; hide the duplicate listening connection label visually while preserving its accessible status; move retained-session access to a compact History/count control beside the view tabs; update the existing component evidence test to cover its new location.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js development server remains active on port `3000`; HMR compiled the changed application modules and `/filesystem-activity` returned HTTP 200 from the authenticated browser session.
- Validation performed and outcome: HMR compilation and authenticated page response succeeded. The existing test was updated but no automated tests were run.
- Not performed / deferred: authenticated screenshot review, responsive/light/dark visual review, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only radar and toolbar changes; no API, MongoDB query, path evidence, or telemetry authority changed. The count uses the same bounded recent-closed-session snapshot already shown by the prior shortcut.
- Rollback: restore the Live range/readout/beacon markup in `TopologyCanvas.tsx`, the retained-session control in `FilesystemPageHeader.tsx`, and matching radar styles; no host rollback is required.
- Follow-up: review the compact Session control and two-frame radar at desktop and narrow viewport sizes before marking `FS-024` done.
- Related ADR/runbook: no operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Center the Live radar emitter

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: make the source of the rotating sweep visibly coincide with the square canvas's geometric center.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `865c23e`; this refinement is uncommitted.
- Repository changes: pin a small outlined Radar icon to the canvas center independently of the listening text; move status copy beneath the beacon; add one faint circular pulse ring that becomes static under reduced-motion preferences; update the `FS-024` current-state criteria and decision/update records.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js development server is active at `http://localhost:3000`; it reports that `AUTH_SESSION_SECRET` is missing and uses its development-only fallback. The protected filesystem route redirects unauthenticated requests to login.
- Validation performed and outcome: `npm run dev` reached `Ready`; an unauthenticated `curl -I http://localhost:3000/filesystem-activity` returned HTTP 307 to `/login`; the authenticated browser session then loaded `/filesystem-activity` with HTTP 200. No automated tests were run.
- Not performed / deferred: screenshot review, responsive/light/dark visual review, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only canvas/CSS change; no API, MongoDB query, path evidence, or telemetry authority changed. The pulse is decorative and does not represent a session event.
- Rollback: restore the standby beacon/status layout in `TopologyCanvas.tsx` and its pulse styles in `globals.css`; no host rollback is required.
- Follow-up: review that the sweep meets the beacon cleanly and that the status block remains legible at narrow viewport sizes before marking `FS-024` done.
- Related ADR/runbook: no operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Add a breathing cue to the Live listening title

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: give the empty Live state a quiet visual cue that it is actively waiting for sessions.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `865c23e`; this refinement is uncommitted.
- Repository changes: animate only the `Listening for sessions` title between 0.88 and full opacity on a 2.8-second cycle coordinated with the emitter pulse; disable the title animation for reduced-motion preferences; update the `FS-024` current-state criteria and decision/update records.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js development server is active at `http://localhost:3000`; development-only auth fallback is in use.
- Validation performed and outcome: HMR compiled the edited page and the authenticated `/filesystem-activity` page returned HTTP 200; `git diff --check` passed. No automated tests were run.
- Not performed / deferred: screenshot review, responsive/light/dark visual review, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only title animation; no API, MongoDB query, path evidence, or telemetry authority changed. The opacity animation communicates the listening state and does not represent a session event.
- Rollback: remove the listening-title animation class in `TopologyCanvas.tsx` and its keyframes/reduced-motion rule in `globals.css`; no host rollback is required.
- Follow-up: visually confirm the title breath remains subtle beside the emitter pulse before marking `FS-024` done.
- Related ADR/runbook: no operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Match the Live radar palette to the dashboard theme

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: make the Live radar feel native to both dashboard themes, using the existing brick-orange primary in light mode and bright-brass primary in dark mode.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `865c23e`; this refinement is uncommitted.
- Repository changes: replace fixed green radar surfaces, grid, frames, axes, hub, edge ticks, status accents, and canvas sweep with system theme tokens; refresh the Canvas sweep color when `data-theme` changes; update the `FS-024` acceptance record and decision/update logs.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js development server remains active at `http://localhost:3000`; development-only auth fallback is in use.
- Validation performed and outcome: Next.js HMR compiled the edited styles and component; the dev server served `/filesystem-activity` with HTTP 200; `git diff --check` passed; a targeted search found no remaining fixed green radar colors. No automated tests were run.
- Not performed / deferred: paired authenticated light/dark screenshot review, responsive visual review, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only CSS and canvas change; no API, MongoDB query, path evidence, or telemetry authority changed.
- Rollback: restore the fixed radar colors in `globals.css` and the sweep palette in `TopologyCanvas.tsx`; no host rollback is required.
- Follow-up: review the radar surface and sweep in both themes at wide and narrow viewport sizes before marking `FS-024` done.
- Related ADR/runbook: no architecture decision or operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Connect Live radar crosshairs and enlarge its emitter

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: make the four cardinal edge ticks read as one radar crosshair through the sweep origin and give the center emitter more visual weight without adding synthetic activity.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `865c23e`; this refinement is uncommitted.
- Repository changes: draw subtle continuous perpendicular crosshairs across the full Live canvas beneath the sweep; remove the redundant square-only axes; enlarge the centered Radar icon and hub; omit transport status from the listening state and replace protocol-specific transient copy with operator-facing text; update `FS-024` current state, decisions, and update history.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js development server remains active at `http://localhost:3000`; development-only auth fallback is in use.
- Validation performed and outcome: Next.js HMR compiled the edited component and styles; `git diff --check` passed; a targeted search found no transport-status text or obsolete square-only axes in the Live radar. No automated tests were run.
- Not performed / deferred: authenticated screenshot review of the crosshair and emitter at wide/narrow sizes, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only CSS and copy change; no API, MongoDB query, path evidence, telemetry authority, or event marker changed.
- Rollback: restore the SVG center axis and original emitter dimensions/status copy in `TopologyCanvas.tsx` and `globals.css`; no host rollback is required.
- Follow-up: visually review crosshair alignment with the four edge ticks and verify the enlarged emitter remains centered under both aspect ratios before marking `FS-024` done.
- Related ADR/runbook: no architecture decision or operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Match Live radar crosshair weight and soften the wake

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: match the crossing axis weight to the cardinal edge markers and keep the sweep wake from appearing as a broad cloud.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `865c23e`; this refinement is uncommitted.
- Repository changes: set both continuous crosshair strokes to `1.5px`, matching the edge ticks; lower the multi-stop wake opacity and reduce its clipped bloom opacity and blur; update the `FS-024` acceptance record and decision/update history.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js development server remains active at `http://localhost:3000`; development-only auth fallback is in use.
- Validation performed and outcome: Next.js HMR compiled the updated styles and Canvas component; the dev server served `/filesystem-activity` with HTTP 200; `git diff --check` passed. No automated tests were run.
- Not performed / deferred: authenticated screenshot review of crosshair weight and wake strength at wide/narrow sizes, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only CSS and Canvas appearance change; no API, MongoDB query, path evidence, telemetry authority, or event marker changed.
- Rollback: restore the crosshair width/height and sweep trail stops/bloom settings in `globals.css` and `TopologyCanvas.tsx`; no host rollback is required.
- Follow-up: confirm the crosshair joins the edge ticks cleanly and the wake remains visible but restrained before marking `FS-024` done.
- Related ADR/runbook: no architecture decision or operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Increase Live radar crosshair visibility

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: make the perpendicular center axes visible while preserving the requested edge-tick stroke thickness.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `865c23e`; this refinement is uncommitted.
- Repository changes: retain `1.5px` crosshair strokes to match the cardinal edge ticks and raise the primary-color axis contrast from 7% to 22%; update the `FS-024` current-state criterion and decision/update history.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js development server remains active at `http://localhost:3000`; development-only auth fallback is in use.
- Validation performed and outcome: Next.js HMR compiled the updated theme styles; `git diff --check` passed. No automated tests were run.
- Not performed / deferred: authenticated screenshot review in both themes and at wide/narrow sizes, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only CSS change; no API, MongoDB query, path evidence, telemetry authority, or event marker changed.
- Rollback: restore `--pti-radar-axis` to its previous 7% mix in `globals.css`; no host rollback is required.
- Follow-up: confirm the crosshairs are visible and remain 1.5px across supported display scales before marking `FS-024` done.
- Related ADR/runbook: no architecture decision or operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Unify the Live radar edge and crosshair strokes

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: make the full-canvas crosshair look exactly as substantial as the short cardinal markers where it reaches the plane boundary.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `865c23e`; this refinement is uncommitted.
- Repository changes: define a shared `2px` radar stroke width and apply the same primary color, 72% opacity, and edge glow to the crosshairs and edge ticks; update the `FS-024` acceptance record and decision/update history.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js development server remains active at `http://localhost:3000`; development-only auth fallback is in use.
- Validation performed and outcome: Next.js HMR compiled the updated styles; the dev server served `/filesystem-activity` with HTTP 200; `git diff --check` passed. No automated tests were run.
- Not performed / deferred: screenshot review to compare the now-shared stroke treatment in both themes, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only CSS change; no API, MongoDB query, path evidence, telemetry authority, or event marker changed.
- Rollback: restore the prior per-element crosshair and edge-tick stroke styles and remove `--pti-radar-stroke-width`; no host rollback is required.
- Follow-up: compare the continuous axes against all four edge ticks in the browser before marking `FS-024` done.
- Related ADR/runbook: no architecture decision or operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Put diagonal radar markers at the canvas corners

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: place the four diagonal registration marks at the full responsive canvas corners, outside the centered square range frame.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `865c23e`; this refinement is uncommitted.
- Repository changes: remove the diagonal marks from the square SVG frame and add short 45-degree accent marks inset from each actual canvas corner; update the `FS-024` current-state record and decision/update history.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js development server remains active at `http://localhost:3000`; development-only auth fallback is in use.
- Validation performed and outcome: Next.js HMR compiled the overlay and styles; the dev server served `/filesystem-activity` with HTTP 200; `git diff --check` passed; a targeted search confirmed the marks are no longer attached to the square SVG frame. No automated tests were run.
- Not performed / deferred: authenticated screenshot review at wide and narrow aspect ratios, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only CSS/SVG overlay change; no API, MongoDB query, path evidence, telemetry authority, or event marker changed.
- Rollback: remove the four `.pti-live-radar-corner-tick` spans and restore the SVG corner path; no host rollback is required.
- Follow-up: verify the marks sit near the actual panel corners at both wide and tall canvas ratios before marking `FS-024` done.
- Related ADR/runbook: no architecture decision or operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Extend diagonal radar marks to the canvas edges

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: remove the visible gap between each diagonal corner mark and the canvas boundary while respecting the rounded canvas corners.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `865c23e`; this refinement is uncommitted.
- Repository changes: reposition and lengthen each diagonal mark so its endpoints meet the adjoining straight canvas edges past the rounded-corner cutout; keep the marks attached to the responsive canvas, outside the square range frame; update the `FS-024` current-state record and decision/update history.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js development server remains active at `http://localhost:3000`; development-only auth fallback is in use.
- Validation performed and outcome: Next.js HMR compiled the updated corner mark styles; `git diff --check` passed. No automated tests were run.
- Not performed / deferred: authenticated screenshot review to confirm the marks meet the rounded canvas boundary across wide and narrow aspect ratios, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only CSS adjustment; no API, MongoDB query, path evidence, telemetry authority, or event marker changed.
- Rollback: restore the previous `.pti-live-radar-corner-tick` inset and length in `globals.css`; no host rollback is required.
- Follow-up: inspect all four corner marks at the actual viewport sizes before marking `FS-024` done.
- Related ADR/runbook: no architecture decision or operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Aim Live radar corner marks inward at 45 degrees

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: make each short diagonal mark emerge inward from an actual responsive canvas corner at a 45-degree angle.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `865c23e`; this refinement is uncommitted.
- Repository changes: rotate and anchor the four corner ticks at the corresponding canvas edges so each points inward; retain the shared accent stroke style and keep the square range frames unchanged; update the `FS-024` current-state record and decision/update history.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js development server remains active at `http://localhost:3000`; development-only auth fallback is in use.
- Validation performed and outcome: Next.js HMR compiled the updated corner-mark styles; `git diff --check` passed. No automated tests were run.
- Not performed / deferred: authenticated screenshot review of the 45-degree rays at wide and narrow aspect ratios, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only CSS adjustment; no API, MongoDB query, path evidence, telemetry authority, or event marker changed.
- Rollback: restore the previous `.pti-live-radar-corner-tick` dimensions and inset transforms in `globals.css`; no host rollback is required.
- Follow-up: visually confirm each ray emerges from its canvas corner and points into the plane at 45 degrees before marking `FS-024` done.
- Related ADR/runbook: no architecture decision or operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Calculate corner rays for the responsive canvas ratio

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: align each short corner ray with the exact sweep direction from the canvas center to its corresponding rectangular canvas corner.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `865c23e`; this refinement is uncommitted.
- Repository changes: measure the Live overlay with `ResizeObserver`, calculate the inward corner angle as `atan2(height, width)`, and expose signed angles to the four corner ticks; recompute on every size change, including reduced-motion mode, so the marks remain collinear with the responsive radar sweep; update the `FS-024` current-state record and decision/update history.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js development server remains active at `http://localhost:3000`; development-only auth fallback is in use.
- Validation performed and outcome: Next.js HMR compiled the updated component and styles; the dev server served `/filesystem-activity` with HTTP 200; `git diff --check` passed; a targeted search confirmed there is no fixed 45-degree corner transform. No automated tests were run.
- Not performed / deferred: authenticated screenshot review at multiple canvas aspect ratios and in reduced-motion mode, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only angle calculation; no API, MongoDB query, path evidence, telemetry authority, or event marker changed.
- Rollback: remove the angle-measuring `useLayoutEffect` in `TopologyCanvas.tsx` and restore fixed corner transforms in `globals.css`; no host rollback is required.
- Follow-up: check that each corner tick overlays its sweep direction at wide and tall canvas ratios before marking `FS-024` done.
- Related ADR/runbook: no architecture decision or operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Soften the Live radar wake again

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: preserve the gentle breathing listening label while making the sweep's trailing haze less prominent.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `865c23e`; this refinement is uncommitted.
- Repository changes: reduce the wake gradient's peak opacity from 0.20 to 0.14, lower its intermediate opacity stops, and reduce the clipped bloom from 0.08 opacity / 12px blur to 0.05 opacity / 8px blur; preserve the crisp 0.9-opacity beam and the existing 2.8-second listening-title breath; update the `FS-024` criterion and decision/update history.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js development server remains active at `http://localhost:3000`; development-only auth fallback is in use.
- Validation performed and outcome: Next.js HMR compiled the changes; the active browser request to `/filesystem-activity` returned HTTP 200; `git diff --check` passed. An unauthenticated direct fetch redirected with HTTP 307. No automated tests were run.
- Not performed / deferred: authenticated screenshot review of wake strength in both themes and at wide/narrow aspect ratios, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only Canvas styling change; no API, MongoDB query, path evidence, telemetry authority, or event marker changed.
- Rollback: restore the prior trail-stop opacity values and clipped bloom to 0.08 opacity / 12px blur in `TopologyCanvas.tsx`; no host rollback is required.
- Follow-up: visually confirm the wake remains visible but quieter than the beam in both themes before marking `FS-024` done.
- Related ADR/runbook: no architecture decision or operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Replace the radar glyph with a rounded-square double pulse

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: make the radar's center and paired outgoing waves use the same rounded-square geometry as the range frames and canvas.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `865c23e`; this refinement is uncommitted.
- Repository changes: remove the center Radar icon and its circular pseudo-element pulse; use a solid 32×32 accent emitter with the canvas's 12px corner radius; animate two outlined rounded-square waves in one 3.2-second cycle, with the outer wave reaching the 924-unit frame quickly and the delayed inner wave reaching the 664-unit frame more slowly; calculate SVG corner radii from the responsive plane scale so both waves align with their range frames; omit both waves when reduced motion is requested; update `FS-024` acceptance and design history.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js development server remains active at `http://localhost:3000`; development-only auth fallback is in use.
- Validation performed and outcome: Next.js HMR compiled the component and styles; the active browser request to `/filesystem-activity` returned HTTP 200; `git diff --check` passed. No automated tests were run.
- Not performed / deferred: authenticated visual review of the double-beat timing, frame alignment, and rounded corners in both themes and at wide/narrow canvas ratios; lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only Canvas/SVG/CSS change; no API, MongoDB query, path evidence, telemetry authority, or event marker changed.
- Rollback: restore the Radar glyph and circular hub pulse in `TopologyCanvas.tsx` and its hub/pulse rules in `globals.css`; remove the paired SVG wave frames and their responsive-radius updates; no host rollback is required.
- Follow-up: inspect the two pulse landings on the existing outer and inner frames, especially on non-square canvas sizes and with reduced motion enabled.
- Related ADR/runbook: no architecture decision or operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Remove the solid center radar emitter

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: leave the center open and let the repeating rounded-square waves define the radar origin.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `865c23e`; this refinement is uncommitted.
- Repository changes: remove the solid center block and its theme-specific emitter styling; preserve the paired rounded-square waves, their responsive frame-aligned corner radii, double-beat timing, reduced-motion behavior, and the breathing listening title; update the `FS-024` current-state criterion and append the superseding design decision.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js development server remains active at `http://localhost:3000`; development-only auth fallback is in use.
- Validation performed and outcome: Next.js HMR compiled the component and styles; the active browser request to `/filesystem-activity` returned HTTP 200; `git diff --check` passed; a targeted search confirmed the removed emitter styles and variables have no remaining references. No automated tests were run.
- Not performed / deferred: authenticated screenshot review of the open center and wave alignment in both themes and at wide/narrow canvas ratios, reduced-motion review, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only Canvas/SVG/CSS change; no API, MongoDB query, path evidence, telemetry authority, or event marker changed.
- Rollback: restore the center emitter element and `.pti-live-radar-hub` rules in `TopologyCanvas.tsx` and `globals.css`; no host rollback is required.
- Follow-up: inspect the open center during both beats and confirm the wave outlines still land on their matching frames before marking `FS-024` done.
- Related ADR/runbook: no architecture decision or operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Remove persistent radar range frames

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: remove the two static square boxes behind the waves while preserving the center emitter and the animated double pulse.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `865c23e`; this refinement is uncommitted.
- Repository changes: restore the solid 32×32 accent emitter without an icon; remove the persistent outer and inner range-frame SVGs and their CSS; keep the paired animated square outlines at their existing 924-unit and 664-unit reaches, with their responsive rounded corners and double-beat timing; update the `FS-024` criterion and append the clarification to design history.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js development server remains active at `http://localhost:3000`; development-only auth fallback is in use.
- Validation performed and outcome: Next.js HMR compiled the component and styles; `git diff --check` passed; a targeted search confirmed no persistent range-frame elements or styles remain and the center emitter is present. No automated tests were run.
- Not performed / deferred: authenticated screenshot review of the waves without static frames, corner alignment in both themes and at wide/narrow canvas ratios, reduced-motion review, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only SVG/CSS change; no API, MongoDB query, path evidence, telemetry authority, or event marker changed.
- Rollback: restore the two `.pti-live-radar-range` SVG rectangles and their CSS rules; remove the center emitter element and styles only if reverting all changes from this refinement is desired; no host rollback is required.
- Follow-up: inspect the two pulse extents after static range frames are removed and ensure the center emitter remains visible before marking `FS-024` done.
- Related ADR/runbook: no architecture decision or operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Slow and lengthen the radar double pulse

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: make both rounded-square wave fronts easier to follow, keep a gradual fade at each full reach, and leave a longer pause before the next pair.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `865c23e`; this refinement is uncommitted.
- Repository changes: extend the wave cycle from 3.2 to 5.6 seconds; move the outer wave to full scale at 34% and fade it linearly through 53%; delay the inner wave by 620ms, move it to full scale at 48%, and fade it linearly through 72%; preserve the outer-first/inner-second cadence, both range extents, the center emitter, rounded corners, and reduced-motion behavior; update the `FS-024` criterion and append the design decision.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js development server remains active at `http://localhost:3000`; development-only auth fallback is in use.
- Validation performed and outcome: Next.js HMR compiled the updated styles; the active browser request to `/filesystem-activity` returned HTTP 200; `git diff --check` passed. No automated tests were run.
- Not performed / deferred: authenticated visual review of both pulse timings, full-reach fades, and the longer pause in both themes and at wide/narrow canvas ratios, reduced-motion review, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only CSS animation change; no API, MongoDB query, path evidence, telemetry authority, or event marker changed.
- Rollback: restore the wave animation duration to 3.2 seconds, inner delay to 480ms, and the previous keyframe stops; no host rollback is required.
- Follow-up: review the two complete cycles visually to confirm the fade feels gradual and the longer interval still reads as a paired pulse.
- Related ADR/runbook: no architecture decision or operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Simplify the Live listening state and sweep glow

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: remove steady-state status copy and the broad sector-shaped sweep haze while keeping a glow attached to the moving beam.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `865c23e`; this refinement is uncommitted.
- Repository changes: omit the “Listening for sessions” title and its empty status wrapper in the steady listening mode while preserving loading/reconnect messages and the reconnect action; remove the sweep's conic/linear gradient sector and clipped fog fill; retain the boundary-calculated crisp sweep stroke with a 9px Canvas shadow glow; remove the static center radial haze and the unused listening-title breath styles; update the `FS-024` criterion and append the design decision.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js development server remains active at `http://localhost:3000`; development-only auth fallback is in use.
- Validation performed and outcome: Next.js HMR compiled the updated component; the active browser request to `/filesystem-activity` returned HTTP 200; `git diff --check` passed. No automated tests were run.
- Not performed / deferred: authenticated screenshot review of the clean listening state, beam glow, loading/reconnect copy, both themes, and reduced-motion behavior; lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only Canvas/SVG/CSS change; no API, MongoDB query, path evidence, telemetry authority, or event marker changed.
- Rollback: restore the listening title and breath styles, centered radial background haze, and sweep-sector gradient/clip fill in `TopologyCanvas.tsx` and `globals.css`; no host rollback is required.
- Follow-up: review that the beam still reads clearly at all sweep angles without a surrounding haze and that reconnect/loading remain legible.
- Related ADR/runbook: no architecture decision or operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Keep the moving radar wake without the broad haze

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: retain the low-opacity wave that follows the rotating beam while removing the broad, separately blurred fog effect; keep the steady listening title absent.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `865c23e`; this refinement is uncommitted.
- Repository changes: restore the clipped 48-degree multi-stop gradient wake behind the beam, fading from 0.14 opacity at the beam to transparent at the tail; do not apply an extra shadow blur to the wake; preserve the 9px shadow glow on the crisp moving beam, the removed static center radial haze, the absent steady-state listening title, and loading/reconnect copy; append a clarification to the `FS-024` design history.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js development server remains active at `http://localhost:3000`; development-only auth fallback is in use.
- Validation performed and outcome: Next.js HMR compiled the updated component and styles; `git diff --check` passed; a targeted source scan confirmed the moving gradient wake remains and the broad fill blur and steady-state listening title are absent. No automated tests were run.
- Not performed / deferred: authenticated screenshot review to confirm the wake remains visible without reading as fog, the listening center stays uncluttered, and loading/reconnect copy remains legible; lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only Canvas/SVG/CSS change; no API, MongoDB query, path evidence, telemetry authority, or event marker changed.
- Rollback: restore the extra clipped wake shadow blur and centered radial haze only if that presentation is preferred; restore the listening title only if the steady-state text is desired again; no host rollback is required.
- Follow-up: visually review the wake through a full 360-degree turn in both themes before marking `FS-024` done.
- Related ADR/runbook: no architecture decision or operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Stop radar scanning when a session is present

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: make the moving radar scan a standby treatment and clear it as soon as the live snapshot contains session activity.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `865c23e`; this refinement is uncommitted.
- Repository changes: pass live snapshot session presence to `LiveRadarOverlay`; when one or more sessions exist, unmount the sweep canvas and both animated pulse outlines and stop their animation effect, while preserving the grid and crosshairs; include scan state in the rounded-corner measurement effect so pulse corners are recalculated if scanning resumes; update the `FS-024` criterion and append the design decision.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js development server remains active at `http://localhost:3000`; development-only auth fallback is in use.
- Validation performed and outcome: Next.js HMR compiled the updated component; the active browser request to `/filesystem-activity` returned HTTP 200; `git diff --check` passed. No automated tests were run.
- Not performed / deferred: authenticated browser review of scan removal on the first arriving session, behavior when session data clears, and loading/standby states; lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only conditional rendering; no API, MongoDB query, path evidence, telemetry authority, or event marker changed.
- Rollback: remove the `scanning` prop and guards from `LiveRadarOverlay` and the live snapshot call site; no host rollback is required.
- Follow-up: confirm the scan stays absent while a session exists and returns only after the live snapshot has no sessions.
- Related ADR/runbook: no architecture decision or operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Hide the entire standby radar plane on live activity

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: treat the full colored radar plane and all of its decoration as empty/standby UI; show the normal map surface once session data is present.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `865c23e`; this refinement is uncommitted.
- Repository changes: derive one `showLiveRadarStandby` state from live mode and an empty session snapshot; apply `pti-live-radar` and mount its grid, crosshairs, edge/corner ticks, sweep, and pulses only in standby; use `bg-surface-subtle` and render no radar overlay when live sessions exist; preserve the audit grid behavior; update the `FS-024` acceptance criterion and append the clarification to design history.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js development server remains active at `http://localhost:3000`; development-only auth fallback is in use.
- Validation performed and outcome: pending HMR confirmation and `git diff --check`; no automated tests were run.
- Not performed / deferred: authenticated browser review of all radar decoration disappearing when live sessions arrive and returning on an empty snapshot; lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only conditional rendering and surface-class change; no API, MongoDB query, path evidence, telemetry authority, or event marker changed.
- Rollback: restore the `pti-live-radar` class and `LiveRadarOverlay` unconditionally in the populated live map; no host rollback is required.
- Follow-up: confirm populated live snapshots show only the standard map canvas while zero-session standby still displays the full radar plane.
- Related ADR/runbook: no architecture decision or operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Restore the View-controlled background grid on active topology

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: preserve the neutral map grid as an operator-controlled canvas option while keeping standby-only radar effects out of populated topology.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `865c23e`; this refinement is uncommitted.
- Repository changes: render the neutral `--border` background grid on populated live topology only while View > Show background grid is enabled; keep the primary-colored standby radar surface, themed grid, crosshairs, corner/edge marks, sweep, and pulse waves limited to the empty standby state; leave Audit grid behavior unchanged; clarify the current `FS-024` acceptance criteria and append a design/update record. This entry records completion of the pending HMR validation from the preceding refinement without rewriting that historical note.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js development server remains active at `http://localhost:3000`; development-only auth fallback is in use.
- Validation performed and outcome: Next.js HMR compiled the edited component and styles; `git diff --check` passed. No automated tests were run.
- Not performed / deferred: authenticated browser review of the View toggle with and without sessions, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only canvas rendering; no API, MongoDB query, path evidence, telemetry authority, or event marker changed.
- Rollback: remove the populated-live `pti-live-radar-grid` branch and restore the no-overlay condition; no host rollback is required.
- Follow-up: confirm in the browser that Show background grid toggles the neutral grid with active sessions while all themed standby radar decoration stays absent.
- Related ADR/runbook: no architecture decision or operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Restore sweep wake strength on a neutral radar plane

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: restore the brighter gradient wake behind the sweep and remove the primary-color wash from the empty-state radar background.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `865c23e`; this refinement is uncommitted.
- Repository changes: restore the Canvas wake's multi-stop gradient to a 0.48 peak opacity while retaining a smooth fade from its trailing edge; replace the layered radar background tints with the solid theme surface token, which is white in light theme and dark in dark theme; update the current `FS-024` criteria and append the decision/update records.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js development server remains active at `http://localhost:3000`; development-only auth fallback is in use.
- Validation performed and outcome: Next.js HMR compiled the edited component and styles; `/filesystem-activity` returned HTTP 200; `git diff --check` passed. No automated tests were run.
- Not performed / deferred: visual review of the stronger wake and plain background in both themes, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only Canvas/CSS change; no API, MongoDB query, path evidence, telemetry authority, or event marker changed.
- Rollback: restore the wake's previous 0.14 peak opacity and the layered primary-color background gradients; no host rollback is required.
- Follow-up: inspect the sweep wake in empty standby in light and dark themes and confirm the solid canvas makes the wake provide the scene's localized brightness.
- Related ADR/runbook: no architecture decision or operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).
