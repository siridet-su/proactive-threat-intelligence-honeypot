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
### 2026-09-25 — Align backup retention header with dashboard pages

- Status: prepared; local development only, not deployed.
- Scope and intent: remove the backup page's `Data protection / operations`
  eyebrow so the header follows the simpler title treatment used by the
  surrounding dashboard pages.
- Repository branch and commit/PR: `feat/artifact-intelligence`; change is
  currently uncommitted.
- Repository changes: removed the eyebrow label from the Backup control room
  header and removed the title's compensating top margin.
- Host/environment changes actually applied: none; no Pi or production
  dashboard files were changed.
- Runtime/exposure state: the local dev server uses the artifact-intelligence
  worktree on port 3100; no production runtime was restarted.
- Validation performed and outcome: the page is available through the local
  dev server; automated dashboard tests are not yet run.
- Not performed / deferred: no production build, deployment, or browser
  regression sweep beyond the local page check.
- Risks and data handling: presentation-only change; no data, API, backup
  state, or secrets were changed.
- Rollback: restore the removed eyebrow element and the previous `mt-2`
  title class, or revert the implementation commit when one is created.
- Follow-up: run the focused dashboard checks before committing or deploying.
- Related runbook: `dashboard-v2/README.md`.

### 2026-09-25 — Remove remaining hardware archive eyebrow

- Status: prepared; local development only, not deployed.
- Scope and intent: remove the `Hardware archive` eyebrow from the Rollup
  backup section and keep the health badge beside the section title.
- Repository branch and commit/PR: `feat/artifact-intelligence`; change is
  currently uncommitted.
- Repository changes: moved the existing status badge alongside `Rollup
  backup` and removed the redundant all-caps section label.
- Host/environment changes actually applied: none; no Pi or production
  dashboard files were changed.
- Runtime/exposure state: the local dev server uses the artifact-intelligence
  worktree on port 3100; no production runtime was restarted.
- Validation performed and outcome: `npm run lint`, `npx tsc --noEmit`, and
  `git diff --check` passed after the header updates; the local backup page
  returned the expected authentication redirect.
- Not performed / deferred: no production build, deployment, or authenticated
  browser regression sweep.
- Risks and data handling: presentation-only change; no data, API, backup
  state, or secrets were changed.
- Rollback: restore the `Hardware archive` label and previous heading wrapper,
  or revert the implementation commit when one is created.
- Follow-up: run the focused dashboard checks before committing or deploying.
- Related runbook: `dashboard-v2/README.md`.

### 2026-09-25 — Align backup retention header with tab layout

- Status: prepared; local development only, not deployed.
- Scope and intent: replace the oversized Backup control room hero card with
  the flat page-header treatment used by the other dashboard tabs.
- Repository branch and commit/PR: `feat/artifact-intelligence`; change is
  currently uncommitted.
- Repository changes: changed the backup page header to a bottom-border layout,
  restored the shared `Backup & retention` title, retained the concise
  description and Pi-connected badge, and removed the decorative hero panel.
  This supersedes the earlier local-only hero-label adjustment in this same
  uncommitted worktree change.
- Host/environment changes actually applied: none; no Pi or production
  dashboard files were changed.
- Runtime/exposure state: the local dev server uses the artifact-intelligence
  worktree on port 3100; no production runtime was restarted.
- Validation performed and outcome: `npm run lint`, `npx tsc --noEmit`, and
  `git diff --check` passed before this final header layout adjustment.
- Not performed / deferred: no production build, deployment, or authenticated
  browser regression sweep.
- Risks and data handling: presentation-only change; no data, API, backup
  state, or secrets were changed.
- Rollback: restore the rounded hero header from the branch base, or revert
  the implementation commit when one is created.
- Follow-up: run the focused dashboard checks again before committing or
  deploying.
- Related runbook: `dashboard-v2/README.md`.
### 2026-09-24 — Correct the HTTP skin and verify local event capture

- Status: corrected and locally verified; service returned to stopped/disabled.
- Scope and intent: fix the root-page failure found during the first loopback
  smoke check and verify that form submissions reach the login-attempt logger.
- Repository branch: `feat/opencanary-web-login-honeypot`; this is a separate
  follow-up implementation record from the initial staging entry.
- Repository changes: changed the configured skin from `basicLogin` to
  `nasLogin` in the config template, ADR-0004, service catalog, and current
  architecture. Updated the runbook's GET example to follow the skin redirect.
- Host/environment changes actually applied: backed up the immediately
  preceding config on the Pi to
  `/etc/opencanaryd/opencanary.conf.pre-naslogin-20260924` with mode `0600`,
  then installed the corrected config with mode `0640` and owner `root:opencanary`.
- Runtime/exposure state: `nasLogin` remains bound to `127.0.0.1:8081`; the
  unit is again `inactive` and `disabled`, and the listener is closed. No
  firewall or remote exposure changed.
- Validation performed and outcome: the service was started only for a local
  smoke check. Following `/` to the login page returned HTTP 200; two synthetic
  POSTs to `/index.html` returned HTTP 200 and appeared as two HTTP
  post-login-attempt events in `/var/log/opencanary/events.jsonl`. The service
  was stopped after verification.
- Not performed / deferred: no real credentials were submitted, no external
  client or firewall path was tested, and no event-pipeline integration was
  added.
- Risks and data handling: the temporary smoke values are attacker-like test
  data in the local log; retain the same sensitive-data handling rules as the
  initial deployment. No raw event contents are stored in this record.
- Rollback: restore the preceding config from the protected backup above or use
  the original pre-setup backup described in the OpenCanary runbook.
- Follow-up: decide separately whether and how to expose the loopback service
  to an approved interface; review firewall and router paths first.
- Related ADR/runbook: [ADR-0004](adr/ADR-0004-opencanary-http-login.md) and
  [OpenCanary runbook](../integrations/opencanary/README.md).

### 2026-09-24 — Prepare Odoo-style corporate web login telemetry

- Status: prepared locally; not deployed or active.
- Scope and intent: reshape the existing Rattana Trading & Logistics login as
  an Odoo-style ERP sign-in and improve capture of login brute-force attempts
  and SQL-injection indicators. No credentials are forwarded to the real Odoo
  service and no submitted value is executed.
- Repository branch and commit/PR: `feat/opencanary-web-login-honeypot`; no
  commit. The web-decoy source is in the sibling
  `/home/cpe27/decoy-honeypot/` directory, which is not a Git worktree; this
  repository contains this audit entry, not the page/backend source.
- Repository changes: appended this implementation record. The prepared source
  changes are `doors/web-corp/main.py` and `doors/web-corp/html/{login,index}.html`
  in the sibling decoy directory.
- Host/environment changes actually applied: none. No container rebuild,
  service restart, firewall change, or real login submission was performed.
- Runtime/exposure state: the source is not bind-mounted into the container, so
  these edits do not alter the running image. Runtime state was not rechecked
  during this change; the prepared version is not active.
- Validation performed and outcome: `python3 -m py_compile main.py` passed. A
  disposable container with networking disabled and read-only source mounts
  passed synthetic GET/POST tests for `/web/login`, captured Odoo fields and
  request metadata, marked a boolean-tautology SQLi test string, serialized the
  event, and preserved `/login` and `/admin` compatibility. Core transport was
  mocked; no event was written.
- Not performed / deferred: live Core delivery, ZeroTier reachability, a full
  regression suite, and deployment/rebuild. The host Python environment lacks
  the web dependencies, so the test used the existing image's dependencies.
- Risks and data handling: the Core event stores submitted database, login,
  password, redirect, and selected HTTP metadata inside the `cmd` JSON string
  in its persistent event stream; treat it as credential-sensitive data. App
  logs emit only request ID, source IP, and indicator field names. SQLi tags
  are heuristic triage indicators, not a definitive classifier. Retention and
  access policy were not reviewed.
- Rollback: no runtime change to roll back. Before any deployment, preserve the
  previous backend and page as a protected source/image backup; the sibling
  directory is not version-controlled.
- Follow-up: put the decoy source under version control, add a repeatable test
  and event parser/consumer for the JSON stored under Core `cmd`, review
  credential retention/access, then separately approve a ZeroTier-only rollout.
- Related ADR/runbook: none added; deployed behavior and Compose configuration
  were not changed.

### 2026-09-24 — Move corporate web-decoy source into the repository

- Status: source moved into the repository working tree and Compose build path
  updated; service not rebuilt or redeployed.
- Scope and intent: make the Odoo-style web-corp application and its telemetry
  changes reviewable/versionable without changing the running decoy stack.
- Repository branch and commit/PR: `feat/opencanary-web-login-honeypot`; no
  commit yet.
- Repository changes: added the standalone build context, FastAPI source,
  pinned requirements, HTML assets, tests, runbook, and ADR-0005 under
  `integrations/web-corp/`; updated this index and service catalog. The
  superseded nginx config was moved under `integrations/web-corp/legacy/`.
- Host/environment changes actually applied: updated the sibling, unversioned
  `decoy-honeypot/docker-compose.yml` so `web-corp` builds from this repository;
  removed the duplicate active source files from `decoy-honeypot/doors/web-corp/`.
  The dated `web-corp.bak.2026-09-20_webcorp` snapshot was left untouched.
- Runtime/exposure state: no image build, service recreation, firewall change,
  or listener change was performed. The existing container does not bind-mount
  this source, so it continues to use its prior image; runtime status was not
  rechecked during this migration.
- Validation performed and outcome: copied `main.py`, requirements, and HTML
  compared equal to the source; the repository's two unittest cases passed in
  a disposable network-isolated container with read-only mounts and mocked Core
  transport; `docker compose config --quiet` passed and resolved the new build
  context to `integrations/web-corp`.
- Not performed / deferred: no image build, live Core delivery, ZeroTier test,
  service restart/recreation, or end-to-end event-store verification.
- Risks and data handling: the external Compose file remains unversioned and
  assumes this repository is its sibling; preserve that file in the operator's
  deployment backup. Login passwords remain credential-sensitive plaintext in
  Core events; follow the access/retention cautions in the web-corp runbook.
- Rollback: runtime has not changed. To restore the old source layout, copy the
  tracked integration files back under `decoy-honeypot/doors/web-corp/` and
  restore the Compose build context to `.` with `doors/web-corp/Dockerfile`.
- Follow-up: review and commit this source migration, later consolidate or
  parameterize the external Compose file, and only then run a separately
  approved ZeroTier rollout.
- Related ADR/runbook: [ADR-0005](adr/ADR-0005-corporate-web-decoy-source.md)
  and [Corporate web decoy runbook](../integrations/web-corp/README.md).

### 2026-09-24 — Inventory Odoo/PostgreSQL data and check filestore references

- Status: read-only inventory captured; no database, filestore, or service
  changes were made.
- Scope and intent: identify the data types and aggregate counts in the running
  Odoo/PostgreSQL stack before deciding how to connect it to the web decoy.
- Repository branch and commit/PR: `feat/opencanary-web-login-honeypot`; no
  commit. Added a dated validation report and index links.
- Repository changes: added
  `docs/validation/2026-09-24-odoo-postgres-data-inventory.md` and linked it
  from the validation and documentation indexes.
- Host/environment changes actually applied: none. Queries used read-only
  PostgreSQL transactions; filesystem checks only counted paths and bytes.
- Runtime/exposure state: Odoo and PostgreSQL remained `Up` on loopback ports
  8069 and 5432. `odoo_production` was 49 MB with 455 public tables. web-corp
  remained separate and was not connected to Odoo.
- Validation performed and outcome: aggregate counts identified 62 installed
  modules and ERP records for partners, products, orders/invoices, HR, stock,
  users, messages, and attachments. Five sales orders and five invoices were
  draft; partner customer/supplier ranks were zero. Of 404 distinct filestore
  paths referenced by attachment rows, 8 existed and 396 were absent at the
  runtime data directory. Full results and limitations are in the report.
- Not performed / deferred: no raw record values, credentials, parameter
  values, message bodies, or attachment contents were read; no database dump,
  HTTP workflow, live event delivery, or repair was performed.
- Risks and data handling: the database includes user/contact, ERP,
  configuration, message, and attachment metadata. The attachment/filestore
  mismatch may make some Odoo attachments unavailable. The inventory cannot
  certify that all live records are synthetic.
- Rollback: N/A; no runtime state changed.
- Follow-up: preserve coordinated PostgreSQL and Odoo-volume backups, then
  investigate missing filestore paths before cleanup or reconnecting the ERP
  to the honeypot gateway.
- Related report: [Odoo/PostgreSQL data inventory](validation/2026-09-24-odoo-postgres-data-inventory.md).

### 2026-09-24 — Decommission the legacy Odoo middleware and move web-corp to port 80

- Status: legacy middleware removed from the active stack; web-corp is active
  on the ZeroTier address at host port 80.
- Scope and intent: replace the old loopback Odoo reverse-proxy entry point
  with the isolated web-corp decoy, while preserving the Odoo backend, Core,
  database, and other Compose services.
- Repository branch and commit/PR: `feat/opencanary-web-login-honeypot`; no
  commit. Updated the web-corp runbook, service catalog, and this log.
- Host/environment changes actually applied: edited the unversioned sibling
  `/home/cpe27/decoy-honeypot/docker-compose.yml`; removed the `middleware`
  service definition, changed web-corp's host mapping to
  `${WEB_CORP_BIND_IP:-127.0.0.1}:80:8080`, and stopped/removed only
  `decoy-honeypot-middleware-1`. No volumes, Odoo, Core, or other containers
  were removed or recreated. The old middleware image and source remain for
  rollback.
- Runtime/exposure state: web-corp is `Up` at `10.58.33.42:80` and maps to
  container port `8080`. The middleware container is absent. Odoo remains
  `Up` on loopback port `8069`; Deception Core remains `Up` on loopback
  port `9000`. No HTTPS listener was added.
- Validation performed and outcome: Compose config validation passed. Before
  removing middleware, `ss` showed its listener at `127.0.0.1:80` coexisting
  with web-corp at `10.58.33.42:80`; after removal only the ZeroTier port-80
  listener remained. Compose status confirmed web-corp, Odoo, and Core stayed
  running. No HTTP request or login POST was sent.
- Not performed / deferred: no TLS certificate or 443 listener, firewall
  change, live event delivery test, or public-interface exposure.
- Risks and data handling: the previous Odoo middleware facade and its
  request interception behavior are no longer reachable at `127.0.0.1:80`.
  Odoo itself remains available only through its loopback port. No persistent
  data or volume was deleted; submitted web-corp credentials remain sensitive
  Core event data as documented in its runbook.
- Rollback: restore the prior Compose service definition (`middleware`, build
  `doors/middleware/Dockerfile`, `127.0.0.1:80:80`, internal network, and
  `ODOO_URL`/`DECEPTION_CORE_URL`), then run `docker compose up -d middleware`.
  The previous container image and source were retained.
- Follow-up: configure and validate TLS before exposing port 443; separately
  verify event arrival with a benign request if live Core delivery needs
  confirmation.
- Related runbook: [Corporate web decoy](../integrations/web-corp/README.md).

### 2026-09-24 — Rebuild and restart the tracked corporate web decoy

- Status: running from the tracked repository source.
- Scope and intent: activate the moved Odoo-style web-corp source in the
  existing ZeroTier-only development stack, without restarting other services.
- Repository branch and commit/PR: `feat/opencanary-web-login-honeypot`; no
  commit yet. This is a deployment follow-up to the source-migration entry.
- Repository changes: appended this deployment record; application source and
  runbook remain under `integrations/web-corp/`.
- Host/environment changes actually applied: built the image through the
  sibling, unversioned `decoy-honeypot/docker-compose.yml` and ran
  `docker compose up -d --no-deps web-corp`. No other container was recreated.
- Runtime/exposure state: `decoy-honeypot-web-corp-1` is running from image
  `sha256:f21d1dbf53c23da214ecbeee6a218b8c69e971ed59a7e5d94f5aa4deefd1968d`,
  bound only to `10.58.33.42:8080`. OpenCanary remains `inactive`/`disabled`;
  it is a separate service and has no integration with this web-corp app. The
  web app sends telemetry to Deception Core `/v1/track` independently.
- Validation performed and outcome: image build completed; Compose reports
  the service `Up`; container inspection confirmed the image and ZeroTier
  binding. The pre-rebuild image
  `sha256:2f7d1573e992db8113b928addcdaaff45a3eb38495edbcbc0c8a79f4f616eb84`
  remains available for rollback. No live HTTP request or login POST was sent,
  so this restart created no test login event and live Core delivery was not
  verified. The isolated application tests and Compose config validation are
  recorded in the source-migration entry above.
- Not performed / deferred: no OpenCanary start, firewall/port change, public
  exposure, or live end-to-end telemetry verification.
- Risks and data handling: login values are still stored in Core events as
  documented in the web-corp runbook; handle them as credential-sensitive.
  The dated legacy source snapshot remains outside Git for rollback.
- Rollback: retag the pre-rebuild image digest above as
  `decoy-honeypot-web-corp`, then recreate only `web-corp` with Compose.
- Follow-up: after reviewing the staged migration, perform a benign GET and
  verify event arrival/retention in Core without submitting credentials.
- Related ADR/runbook: [ADR-0005](adr/ADR-0005-corporate-web-decoy-source.md)
  and [Corporate web decoy runbook](../integrations/web-corp/README.md).

### 2026-09-24 — Document the web-corp login telemetry target design

- Status: design documented; no implementation or deployment performed.
- Scope and intent: define the proposed capture, delivery, storage, credential
  handling, analysis, and validation boundaries for fake ERP login attempts.
- Repository branch and commit/PR: `feat/opencanary-web-login-honeypot`; no
  commit.
- Repository changes: added
  [`docs/design/web-login-telemetry.md`](design/web-login-telemetry.md), linked
  it from the design/documentation indexes and web-corp runbook, and clarified
  the scoped password-retention exception in the generic decoy telemetry
  design.
- Host/environment changes actually applied: none.
- Runtime/exposure state: unchanged. This document does not implement a new
  collector, Redis stream, Mongo schema, credential access control, or runtime
  path; the current web-corp-to-Core behavior remains active as previously
  documented.
- Validation performed and outcome: documentation links and patch whitespace
  checked; no runtime service, database, or live login request was touched.
- Not performed / deferred: no application or Go-agent code changes, no
  deployment/Compose changes, no event-pipeline test, and no credential
  retention or Mongo access-policy change.
- Risks and data handling: the proposed event includes plaintext submitted
  passwords for authorized honeypot-admin research. Existing event data remains
  credential-sensitive; this change added no credentials, payload samples, or
  secrets to the repository.
- Rollback: revert this documentation-only change; no host state requires
  rollback.
- Follow-up: resolve the open design decisions and implement only after the
  spool, access, retention, and replay gates in the design are satisfied.
- Related design/runbook: [Web-corp login telemetry design](design/web-login-telemetry.md)
  and [Corporate web decoy runbook](../integrations/web-corp/README.md).

### 2026-09-24 — Implement and deploy web-corp login telemetry

- Status: active; deployed pipeline checks passed with the scope limitations
  recorded in the validation note.
- Scope and intent: route fake ERP login attempts through the existing
  collector → Redis → processor → MongoDB pipeline, keep the login page
  permanently rejecting attempts, and keep credential-bearing values out of
  Deception Core command/session events.
- Repository branch and commit/PR: `feat/opencanary-web-login-honeypot`; not
  committed.
- Repository changes: added the web-corp atomic credential-bearing spool;
  collector validation and `raw:web-login` ingestion; processor normalization,
  Mongo upsert, password-redacted canonical projection, username/time index,
  and timestamp-based expiry; and focused tests. Updated current architecture,
  service/data ownership docs, web-corp runbook, and the design. Added
  [`web-corp data access guide`](../integrations/web-corp/DATA-ACCESS.md) for
  retrieving pending container spool data, raw/redacted Redis events, MongoDB
  records, and legacy Core events. Added
  [`deployment validation`](validation/2026-09-24-web-login-pipeline.md).
- Host/environment changes actually applied: edited the unversioned sibling
  `/home/cpe27/decoy-honeypot/docker-compose.yml` for web-corp only, setting
  its spool path/cap and mounting
  `/var/lib/decoy-honeypot/web-login-spool/` into the container. Created the
  host pending spool directory as `root:root` mode `0700`. Replaced the
  ignored collector and processor binaries; a final cross-check found and
  fixed a Unicode character-count boundary mismatch, then rebuilt and
  restarted only the collector. Pre-deployment and pre-fix binaries are
  preserved outside the repository under
  `/var/backups/honeypot/web-login-20260924/`.
- Runtime/exposure state: restarted only `honeypot-collector.service` and
  `honeypot-processor.service`, and recreated only the `web-corp` container.
  At final verification both agent units were active; web-corp was `Up` at
  `10.58.33.42:80` → container `8080`. Deception Core, Odoo/PostgreSQL, Redis,
  and other containers were not restarted. No public-interface listener,
  firewall, or TLS/443 change was made.
- Validation performed and outcome: collector and processor `go test ./...`
  passed, including the collector's Unicode length boundary test; five
  web-corp tests passed in the rebuilt image with networking disabled; Compose
  validation and image build passed. The final collector and processor units
  were both active after the collector-only fix. One synthetic
  SQLi-shaped login was rejected and reached `raw:web-login`; the matching
  `event:canonical` record omitted the password. The collector drained the
  pending spool and processor pending count was zero. The processor log is
  emitted after Mongo upsert and canonical Redis write succeed. See the
  validation note for the independent-Mongo-query and remote-peer limitations.
- Not performed / deferred: no separate remote ZeroTier peer test and no
  direct database-shell read; no Atlas role, encryption, backup-expiry, or TTL
  deletion audit; no brute-force threshold/derived finding; no migration or
  cleanup of pre-cutover Core records; no post-login ERP behavior.
- Risks and data handling: submitted passwords are deliberately retained as
  plaintext in the pending spool, `raw:web-login`, and the MongoDB
  `web_login.password` field. The canonical Redis projection omits the field.
  Treat spool, raw stream, MongoDB queries, and backups as credential-sensitive;
  never include submitted values in logs, docs, fixtures, or routine queries.
  A synthetic validation event remains subject to the configured raw-stream
  and Mongo retention lifecycles.
- Rollback: restore the pre-deployment collector/processor binaries from the
  protected backup path and restart only those two units; rebuild/recreate
  web-corp from the prior reviewed source/image and restore the previous
  web-corp Compose settings. Keep existing telemetry intact; do not remove the
  spool, Redis entries, or Mongo records as part of code rollback.
- Follow-up: independently query a synthetic event from MongoDB and test from
  an authorized second ZeroTier peer; verify Atlas role/backup controls; decide
  brute-force analysis policy. Keep the spool and raw Redis query paths
  restricted to authorized administrators.
- Related material: [web-login telemetry design](design/web-login-telemetry.md),
  [web-corp runbook](../integrations/web-corp/README.md),
  [data access guide](../integrations/web-corp/DATA-ACCESS.md), and
  [deployment validation](validation/2026-09-24-web-login-pipeline.md).

### 2026-09-24 — Verify a user-submitted web-corp login event

- Status: read-only end-to-end follow-up validation completed.
- Scope and intent: correlate the user's test login across the raw Redis
  stream, redacted canonical stream, and MongoDB without reading or recording
  credential values.
- Repository branch and commit/PR: `feat/opencanary-web-login-honeypot`; this
  follow-up is included with the implementation commit.
- Repository changes: updated the validation note and clarified empty-field
  normalization in the design and data-access guide; no runtime source change.
- Host/environment changes actually applied: none; no service restart and no
  database write.
- Runtime/exposure state: the event arrived from an address distinct from the
  sensor. Exact client interface/path was not established by the event alone.
- Validation performed and outcome: matching `web_login_attempt` found in
  `raw:web-login`, `event:canonical`, and `honeypot_db.events`; outcome was
  rejected, canonical Redis omitted the password, and Mongo field-existence
  checks confirmed password/username fields without retrieving their values.
  The spool was empty and the raw stream consumer had no pending messages.
  No SQLi indicators were recorded for this login.
- Not performed / deferred: no raw credential read, no interface-level packet
  verification, and no TLS/443 test.
- Risks and data handling: the raw Redis and Mongo records still contain the
  credential-bearing data as designed. Only metadata and field-presence
  results were recorded here.
- Rollback: revert this documentation-only validation entry; runtime data and
  services are unaffected.
- Follow-up: decide whether normalized events must preserve empty-string form
  fields; complete TLS certificate, proxy, and port-80 behavior design before
  implementing 443.
- Related material: [deployment validation](validation/2026-09-24-web-login-pipeline.md),
  [web-login telemetry design](design/web-login-telemetry.md), and
  [data access guide](../integrations/web-corp/DATA-ACCESS.md).

### 2026-09-25 — Prepare multi-target retained-data backup support

- Status: prepared; hardware target remains active on the Pi, additional targets
  are not deployed or activated.
- Scope and intent: extend the existing Pi backup worker and dashboard source
  map so retained threat events and filesystem audit sources can be activated
  deliberately without presenting repository-only support as live coverage.
- Repository branch and commit/PR: `feat/artifact-intelligence`; changes are
  currently uncommitted in the dashboard worktree.
- Repository changes: added target-aware backup configuration for
  `hardware_metrics_1m`, `threat_events`, and `filesystem_audit`; added a
  versioned multi-source gzip JSONL envelope; excluded derived filesystem
  projections; added `backup_target_status` publication and a dashboard API
  that drives Active/Planned source cards from worker state; and added the
  sensitive-target opt-in guard. Updated the backup runbook, current
  architecture, data ownership, service catalog, systemd descriptions, and
  [ADR-0006](adr/ADR-0006-retained-data-backup-boundaries.md).
- Host/environment changes actually applied: none. No Pi binary, systemd unit,
  B2 bucket/key, MongoDB data, or dashboard deployment was changed by this
  repository preparation.
- Runtime/exposure state: the deployed hardware path remains the only active
  target. `threat_events` and `filesystem_audit` remain Planned until the Pi
  environment enables their target IDs, the sensitive-data policy is approved,
  and the B2 application-key prefixes are updated.
- Validation performed and outcome: hardware-backup `go test ./...` passed with
  target/configuration coverage; dashboard `npx tsc --noEmit` and `npm run lint`
  passed; `git diff --check` passed. MongoDB/B2 integration and restore tests
  were not run.
- Not performed / deferred: no sensitive-event archive upload, no filesystem
  archive upload, no restore/readFiles implementation, no Pi deployment, no
  B2 key-policy change, and no production dashboard verification.
- Risks and data handling: `events` may contain restricted credential-bearing
  web-login fields, so the worker rejects that target unless
  `BACKUP_ALLOW_SENSITIVE=true`. Do not copy credentials, raw event values, or
  protected B2 configuration into logs or documentation.
- Rollback: do not enable the new target IDs on the Pi; for repository review,
  revert the implementation commit. Existing hardware manifests and B2 objects
  are not modified by this prepared change.
- Follow-up: review the private B2 encryption/key-prefix policy, update the Pi
  environment, deploy the worker, run a bounded filesystem archive first, then
  verify target status, manifest counts, storage snapshot, and read-only restore
  handling before enabling sensitive threat events.
- Related material: [retained-data backup runbook](../agents/hardware-backup/README.md),
  [ADR-0006](adr/ADR-0006-retained-data-backup-boundaries.md),
  [current architecture](CURRENT-ARCHITECTURE.md), and
  [data ownership](DATA-OWNERSHIP.md).

### 2026-09-25 — Deploy retained-data backup worker to the Pi

- Status: active for `hardware_metrics_1m`; additional targets remain inactive.
- Scope and intent: install the committed multi-target worker and updated
  systemd descriptions on the Pi while preserving the existing hardware-only
  target policy until B2 key scope permits additional prefixes.
- Repository branch and commit/PR: `feat/artifact-intelligence`; implementation
  commit `93670fd` plus the Backblaze API correction in this commit.
- Repository changes: restored Backblaze Native API v4 authorization and
  storage endpoints that are required by the current B2 account; added v4
  authorization-shape tests and prefix-scoped storage usage. The current
  architecture row now reflects the deployed hardware-only state.
- Host/environment changes actually applied: built a static `linux/arm64`
  binary, installed it at
  `/home/cpe27/proactive-threat-intelligence-honeypot/agents/hardware-backup/hardware-backup`,
  installed the updated scheduled/control unit files, reloaded systemd, and
  restarted `honeypot-hardware-backup-control.service`. The previous binary
  and unit files were preserved on the Pi with `.pre-93670fd` suffixes. No
  source branch merge was performed in the Pi repository.
- Runtime/exposure state: the control service is active and the daily timer is
  enabled. `/etc/honeypot/backup.env` continues to use the private
  `pti-honeypot-archives` bucket and the upload key restricted to
  `hardware_metrics_1m/`; `BACKUP_TARGETS` is unset, so the worker defaults to
  the hardware target. `threat_events` and `filesystem_audit` are not active.
- Validation performed and outcome: the deployed binary SHA-256 is
  `72c7ce33174ab2ddcdfd9d93156263c012a69c8bb6d9f30d67a250f902471536`;
  control startup authorized B2 without the previous v2 error; a manual
  scheduled run completed successfully, uploaded the 2026-09-22 hardware
  archive, and refreshed the B2 storage snapshot. Local Go tests passed.
- Not performed / deferred: no filesystem or sensitive threat-event archive
  was uploaded; no restore operation was run; B2 listing from the local
  workstation was unavailable because the regional API hostname did not
  resolve locally. The Pi upload result and service logs were verified.
- Risks and data handling: the first deployed candidate used the obsolete v2
  B2 endpoint and was immediately replaced after the control-service log
  exposed the incompatibility. No credentials or event payloads were copied
  into the repository or logs.
- Rollback: stop/restart the control service with the preserved
  `hardware-backup.pre-93670fd-v2` binary, restore the `.pre-93670fd` unit
  files if needed, then run `systemctl daemon-reload`; no database rollback is
  required.
- Follow-up: create a bucket-scoped upload key or a separately scoped worker
  for `filesystem_audit/` before enabling that target; keep
  `BACKUP_ALLOW_SENSITIVE` disabled until the restricted `events` archive
  policy and restore procedure are approved.
- Related material: [retained-data backup runbook](../agents/hardware-backup/README.md),
  [ADR-0006](adr/ADR-0006-retained-data-backup-boundaries.md), and
  [current architecture](CURRENT-ARCHITECTURE.md).

### 2026-09-25 — Activate filesystem audit archive on the Pi

- Status: active for `hardware_metrics_1m` and `filesystem_audit`; sensitive
  `threat_events` remains inactive.
- Scope and intent: enable the authoritative filesystem audit archive after
  confirming that the B2 upload credential can write both target prefixes
  without granting file deletion or read access.
- Repository branch and commit/PR: `feat/artifact-intelligence`; worker
  implementation commits `93670fd` and `c1b9393`; this entry and the current
  state updates are committed with the operational activation record.
- Repository changes: updated the current architecture, service catalog, data
  ownership contract, and hardware-backup runbook to distinguish the deployed
  filesystem target from the still-disabled sensitive threat-event target.
- Host/environment changes actually applied: preserved the previous Pi
  environment at
  `/var/lib/honeypot/hardware-backups/deploy-backups/backup.env.pre-filesystem-retry-20260925`,
  configured `BACKUP_TARGETS=hardware_metrics_1m,filesystem_audit` in the
  protected `/etc/honeypot/backup.env`, and restarted
  `honeypot-hardware-backup-control.service`. The upload credential remains
  outside the repository; its capability policy is limited to `listFiles` and
  `writeFiles` for the private archive bucket.
- Runtime/exposure state: the control service is active, the daily backup timer
  remains enabled, and the deployed binary SHA-256 is
  `ec0f051e423ef0f03d1a36927d97bdf0d127c2d78a7daba68d59b64610d67cca`.
  `threat_events` was not enabled and `BACKUP_ALLOW_SENSITIVE` remains absent.
- Validation performed and outcome: control startup reported both enabled
  targets. A manual scheduled run completed successfully for
  `hardware_metrics_1m` and `filesystem_audit`; filesystem archives were
  uploaded for 2026-09-09 through 2026-09-22, with empty days skipped, and the
  B2 storage snapshot was refreshed. The oneshot service exited successfully
  while the control loop remained active.
- Not performed / deferred: no sensitive threat-event archive or restore/read
  operation was run; no direct local B2 listing was possible because the
  workstation could not resolve the regional Backblaze API hostname. Pi-side
  authorization and upload logs were verified instead. Dashboard verification
  requiring an authenticated browser session remains deferred.
- Risks and data handling: filesystem archives may contain paths, session
  identifiers, and other audit metadata. The bucket remains private; no
  credential values or protected configuration contents were copied into the
  repository or this log.
- Rollback: restore the protected environment copy above to
  `/etc/honeypot/backup.env`, remove `filesystem_audit` from `BACKUP_TARGETS`,
  and restart the control service. Existing B2 objects are retained unless an
  operator separately applies the cloud lifecycle policy.
- Follow-up: monitor the next scheduled run and separately review the
  sensitive-data policy before enabling `threat_events`.
- Related material: [retained-data backup runbook](../agents/hardware-backup/README.md),
  [ADR-0006](adr/ADR-0006-retained-data-backup-boundaries.md),
  [current architecture](CURRENT-ARCHITECTURE.md), and
  [data ownership](DATA-OWNERSHIP.md).
