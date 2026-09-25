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

### 2026-09-24 — Track FTP and SMTP decoy sources in the repository

- Status: source/build-context migration completed; running containers were not
  recreated.
- Scope and intent: make the FTP and SMTP implementations, dependencies,
  Dockerfiles, and operating notes reviewable in this repository without
  changing their exposure or sending test credentials/mail.
- Repository branch and commit/PR: feat/opencanary-web-login-honeypot; local
  working-tree changes, not committed.
- Repository changes: added integrations/ftp and integrations/smtp with
  pinned dependencies and runbooks; clarified current event ownership and
  updated the stale TI-worker status from disabled to active based on the
  user-confirmed runtime state. The FTP track-failure debug log no longer
  includes the command string, which can contain an attempted password.
- Host/environment changes: changed the unversioned sibling
  /home/cpe27/decoy-honeypot/docker-compose.yml FTP and SMTP build contexts to
  the tracked integration directories. The shared FTP VFS schema remains a
  read-only external mount because it is shared with Core and contains
  credential-like decoy configuration. Original sibling source files were
  left in place; Compose now builds from the repository source.
- Runtime/exposure state: images were built locally from the repository
  sources, but no running container was recreated or restarted. The existing
  FTP service remained bound to ZeroTier port 21 and passive ports 30000-30009;
  SMTP remained loopback-only on host port 25.
  The updated Compose file is outside this Git repository and therefore is
  not itself tracked by this commit/worktree.
- Validation performed and outcome: Compose config validation passed; both
  images built from the new contexts; both image entrypoints passed Python
  syntax compilation in network-disabled temporary containers. Read-only
  checks confirmed the running FTP process, its banner, its Core health
  dependency, and the four bait filenames. No FTP login/LIST/RETR or SMTP
  message test was performed.
- Not performed / deferred: no service restart, no live transaction test, no
  SMTP-to-telemetry adapter, and no migration of the shared VFS schema.
- Risks and data handling: FTP failed-login activity sent to Core includes the
  submitted username/password, so Core event/session stores are sensitive.
  The container still runs as root internally and its FTP banner duplicates
  the 220 code. SMTP records envelope metadata and byte count but discards
  the message body.
- Rollback: restore the sibling Compose build contexts to its previous local
  doors/ftp and doors/smtp directories; running containers and their data
  were not changed.
- Follow-up: decide whether to split the shared VFS credential/config data
  from the Core persona schema, fix the FTP banner and container user,
  configure health checks, add FTP/SMTP event adapters, and version the full
  decoy-stack deployment Compose file.

### 2026-09-24 — Clarify current and future HTTP decoy scope

- Status: documentation-only clarification; runtime behavior unchanged.
- Scope and intent: make the active web-corp login-collection purpose distinct
  from optional future interactive ERP deception and other HTTP enhancements.
- Repository branch and commit/PR: `feat/opencanary-web-login-honeypot`;
  local working-tree changes, not committed.
- Repository changes: added the HTTP current/future scope document and linked
  it from the docs index, web-corp runbook, login telemetry design, and service
  catalog.
- Host/environment changes actually applied: none.
- Runtime/exposure state: unchanged; web-corp continues to accept HTTP on the
  configured ZeroTier listener, always reject login attempts, and keep login
  telemetry separate from Deception Core page/bait events.
- Validation performed and outcome: documentation cross-links and factual
  claims reviewed against the existing runbook, design, service catalog, and
  architecture snapshot; no service or data-path test was run.
- Not performed / deferred: no code, deployment, service restart, TLS setup,
  brute-force detector, SQLi rule tuning, or post-login ERP simulation.
- Risks and data handling: existing raw login events remain credential-
  sensitive; this documentation change did not query or copy event data.
- Rollback: revert this documentation-only entry and the linked HTTP scope
  documentation changes; runtime is unaffected.
- Follow-up: any future HTTP capability requires a separate design and
  implementation-log entry before deployment.
- Related ADR/runbook: [HTTP decoy scope](design/http-decoy-scope.md),
  [web-login telemetry design](design/web-login-telemetry.md), and
  [web-corp runbook](../integrations/web-corp/README.md).

### 2026-09-24 — Add ZeroTier HTTPS listener for web-corp

- Status: deployed and verified; HTTP remains active alongside HTTPS.
- Scope and intent: serve the existing web-corp persona over TLS on ZeroTier
  port 443 without adding a reverse proxy or connecting login requests to Odoo.
- Repository branch and commit/PR: `feat/opencanary-web-login-honeypot`;
  local working-tree changes, not committed.
- Repository changes: added a direct-TLS web-corp app service definition to
  the sibling Compose file; the app records `http.scheme`, coordinates shared
  spool writers with `flock`, and the collector/processor preserve HTTPS scheme
  and destination port/service metadata. Added tests and updated the HTTP
  scope, telemetry design, runbook, architecture snapshot, and service catalog.
- Host/environment changes actually applied: generated a self-signed RSA
  certificate for SAN `IP:10.58.33.42` at
  `/var/lib/decoy-honeypot/web-corp-tls/tls.crt`; its private key is outside
  Git at `tls.key` (directory mode `0700`, key `0400`, certificate `0444`).
  Updated the unversioned sibling
  `/home/cpe27/decoy-honeypot/docker-compose.yml` and rebuilt/recreated
  `web-corp`; started the new `web-corp-https` service. No UFW rule or public
  interface binding was added. Replaced the ignored collector and processor
  binaries after preserving both prior versions under the protected
  `/var/backups/honeypot/web-https-20260924/` directory, then restarted only
  `honeypot-collector.service` and `honeypot-processor.service`.
- Runtime/exposure state: HTTP is still bound to `10.58.33.42:80` → container
  `8080`; HTTPS is bound to `10.58.33.42:443` → container `8443`. The same app
  serves both; HTTPS negotiates TLS 1.3. The certificate expires
  `2027-09-24` and is self-signed, so client verification correctly reports
  `self-signed certificate` until a trusted certificate is installed.
- Validation performed and outcome: Compose config validation passed; six
  web-corp unit tests passed in an isolated, network-disabled container;
  collector-agent and processor-agent Go test suites passed. HTTP and HTTPS
  `/web/login` returned 200 and identical body SHA-256; a later HTTPS
  `/robots.txt` returned 200 and its Core `/v1/track` request succeeded.
  OpenSSL confirmed TLS 1.3 and the IP SAN. No login credentials were sent to
  the live service.
- Not performed / deferred: no end-to-end HTTPS login POST through the live
  Redis/Mongo pipeline, second-peer ZeroTier test, publicly trusted
  certificate, or certificate renewal automation.
- Risks and data handling: the self-signed certificate causes a browser trust
  warning; replace it before expiry if a trusted DNS identity becomes
  available. The private key remains outside Git. Both app containers share
  the credential-bearing spool; a mode-`0600` process lock serializes writes.
  One initial page-tracking request timed out while services were just starting;
  Core health then returned 200 and the later tracking retry succeeded.
- Rollback: stop/remove only `web-corp-https` and its port-443 mapping to
  disable HTTPS while leaving HTTP intact. Preserve the external certificate
  directory and the sibling Compose backup; collected telemetry is unchanged.
- Follow-up: renew/replace the self-signed certificate before expiry, test
  from an authorized second ZeroTier peer, and track the sibling Compose file
  in a separate scoped change.
- Related ADR/runbook: [HTTP decoy scope](design/http-decoy-scope.md),
  [web-login telemetry design](design/web-login-telemetry.md), and
  [web-corp runbook](../integrations/web-corp/README.md) and
  [HTTPS validation evidence](validation/2026-09-24-web-corp-https.md).

### 2026-09-24 — Document publicly trusted HTTPS target on a VPS

- Status: target runbook documented; no deployment or approval to expose a
  public listener was made by this documentation change.
- Scope and intent: explain how a future public-IP certificate and VPS TLS
  edge could serve web-corp while keeping its Pi backend behind WireGuard.
- Repository branch and commit/PR: `feat/opencanary-web-login-honeypot`;
  local working-tree change, not committed.
- Repository changes: added
  [`integrations/web-corp/PUBLIC-VPS-HTTPS.md`](../integrations/web-corp/PUBLIC-VPS-HTTPS.md)
  with prerequisites, IP certificate/renewal steps, exposure boundary,
  forwarding-header requirements, validation, rollback, and credential-data
  cautions. Linked it from the web-corp runbook, HTTP scope, and docs index.
- Host/environment changes actually applied: none. No VPS, Pi, certificate,
  firewall, WireGuard, proxy, or service configuration was changed.
- Runtime/exposure state: unchanged. The Pi remains ZeroTier-only on HTTP/HTTPS;
  HTTPS still uses its self-signed certificate. No public endpoint was created.
- Validation performed and outcome: reviewed the runbook against the current
  web-corp request fields and proxy trust behavior; official Let's Encrypt,
  Certbot, and Uvicorn documentation was checked for IP-certificate lifetime,
  client support, and trusted forwarded headers. Targeted `git diff --check`
  passed for the modified tracked docs; the new untracked runbook was reviewed
  for whitespace and its referenced local documents exist.
- Not performed / deferred: no certificate request, external VPS login,
  WireGuard route/firewall change, proxy deployment, live login POST, or
  renewal dry-run was performed.
- Risks and data handling: a future public endpoint would receive real-world
  scans and potentially credential-bearing submissions. Existing spool, raw
  Redis, MongoDB, and backups remain sensitive; the runbook requires synthetic
  validation and a restricted public exposure boundary.
- Rollback: revert the documentation-only changes; no host state requires
  rollback.
- Follow-up: select a VPS/public IP and peer addresses; verify current ACME
  client support and automated six-day renewal; review firewall and proxy trust
  boundaries; then separately approve and validate implementation.
- Addendum: this target supersedes earlier follow-up wording in this log that
  implied a publicly trusted DNS name was required before replacing the
  self-signed certificate. A publicly trusted IP certificate is now an option;
  its short validity and client-support caveats are recorded in the runbook.
- Related runbooks/design: [public-VPS HTTPS runbook](../integrations/web-corp/PUBLIC-VPS-HTTPS.md),
  [HTTP decoy scope](design/http-decoy-scope.md), and
  [current web-corp runbook](../integrations/web-corp/README.md).

### 2026-09-25 — Narrow web-corp telemetry and stop inactive decoys

- Status: login-only HTTP behavior deployed; out-of-scope web services stopped.
- Scope and intent: retain the web-corp login honeypot for brute-force and
  SQLi observation while removing page/scan telemetry from the active web path.
- Repository branch and commit/PR: `feat/opencanary-web-login-honeypot`;
  changes remain uncommitted.
- Repository changes: removed the web-corp Deception Core `/v1/track` client,
  page/scan spool events, and current XSS indicators; kept static persona and
  login compatibility routes. Disabled Uvicorn access logging. Updated the
  current-state/service docs to classify Pi HTTPS, Odoo, FTP, and SMTP as
  stopped/future work; documented the internal-only `:8080` app port, the
  dashboard query gap, and the external Compose-file restart caveat. Existing
  page/scan compatibility remains in the Go pipeline for prior spool or Redis
  entries; the updated app produces no new events of that type. Removed
  generated `.next`, `next-env.d.ts`, `.pytest_cache`, and Python
  `__pycache__` output; retained node_modules, environment files, binaries,
  backups, archives, and installed packages.
- Host/environment changes actually applied: stopped only the web-corp HTTPS,
  Odoo, FTP, and SMTP containers; rebuilt the web-corp image and recreated only
  the HTTP `web-corp` container. Container data/volumes were not deleted.
  Cowrie, Zeek, collector, processor, TI, hardware, response-agent, PostgreSQL,
  and Deception Core were left running; PostgreSQL and Core are retained for
  Cowrie integrations. No source/deployment file outside this repository was
  edited. Docker reported FTP/SMTP exit code 137 (`OOMKilled=false`), indicating
  they exceeded the graceful stop timeout; Odoo and HTTPS exited with code 0.
- Runtime/exposure state: `10.58.33.42:80` maps to container `:8080`; host
  `:8080` and Pi `:443` have no listener. FTP/SMTP/Odoo containers are exited.
  PostgreSQL and Deception Core remain bound to loopback. The external Compose
  file still declares stopped services, so an unrestricted full-stack `up`
  could reactivate them.
- Validation performed and outcome: rebuilt `decoy-honeypot-web-corp`; all 7
  web-corp tests passed inside that image, including proof that page GETs,
  bait paths, 404s, and unrelated POSTs create no spool events, while SQLi-like
  login input is tagged and always rejected. Live HTTP GET returned 200;
  container command includes `--no-access-log`; `ss` showed only port 80 for
  web-corp (no host 8080 or 443). Cowrie, Zeek, collector, processor, TI,
  hardware, and response-agent units reported active. `go test ./...` passed
  in both Go agent directories; `git diff --check` passed.
- Not performed / deferred: no live login POST was made, to avoid adding a new
  credential-bearing record to Redis/MongoDB; no VPS/HTTPS rollout, FTP/SMTP
  protocol test, Odoo test, dashboard query/view, or full-stack Compose start.
  Host Python lacked FastAPI; the same suite was run successfully inside the
  built application image.
- Risks and data handling: historical Core and Mongo/Redis records are not
  migrated or deleted and may include prior page/scan or credential-bearing
  data. The sibling Compose source remains external and still defines stopped
  services. Port 8080 is an internal app port, not a separate host exposure.
- Rollback: restore the prior web-corp image/source and recreate only the
  `web-corp` HTTP service. Do not start the full Compose stack as a rollback;
  stopped service state is intentional. Existing telemetry and volumes remain
  untouched.
- Follow-up: migrate/clean up the external Compose definitions (including the
  web-corp Core dependency and disabled services); provide an authorized
  dashboard/API path to persisted login events; separately design the VPS
  HTTPS boundary; add graceful shutdown handling for FTP/SMTP before any
  reactivation; keep FTP/SMTP adapters and post-login deception future work.
- Related runbooks/design: [HTTP decoy scope](design/http-decoy-scope.md),
  [web-login telemetry](design/web-login-telemetry.md),
  [web-corp runbook](../integrations/web-corp/README.md), and the
  [service catalog](SERVICE-CATALOG.md).

### 2026-09-25 — Reconcile current-state documentation with active TI worker

- Status: documentation-only reconciliation; no runtime changes.
- Scope and intent: align this branch's current architecture and service
  catalog with the active TI-worker state and operating controls already
  documented on `main`.
- Repository branch and commit/PR: `feat/opencanary-web-login-honeypot`;
  pending scoped commit.
- Repository changes: recorded the worker as enabled/running (last verified
  2026-09-24), documented validated `ti:jobs` processing and queue/cache/
  provider-quota controls, and corrected the stale priority that said to keep
  enrichment disabled. Web-corp login remains outside TI enrichment.
- Host/environment changes actually applied: none.
- Runtime/exposure state: no new runtime check was performed; the documented
  worker state is the existing 2026-09-24 verification and user-confirmed
  normal operation.
- Validation performed and outcome: compared current-state wording with
  `origin/main`; checked the processor's `THREAT_INTEL_ENABLED` and `ti:jobs`
  configuration references; `git diff --check` passed.
- Not performed / deferred: no TI service restart, provider request, queue
  inspection, or host configuration change.
- Risks and data handling: no credentials or event data were accessed or added.
- Rollback: revert this documentation-only reconciliation; runtime is
  unaffected.
- Follow-up: verify runtime status separately before making operational
  changes; retain this current-state wording unless the worker policy changes.
- Related docs: [current architecture](CURRENT-ARCHITECTURE.md),
  [service catalog](SERVICE-CATALOG.md), and
  [TI design](design/threat-intelligence.md).

### 2026-09-25 — Merge latest main and preserve login-only producer scope

- Status: source and documentation merge prepared; no host service changes.
- Scope and intent: bring the feature branch up to the fetched `origin/main`
  (`ca9d7dd0`) while keeping the current web-corp producer limited to rejected
  login POST telemetry.
- Repository branch and commit/PR: `feat/opencanary-web-login-honeypot`;
  merge commit pending at the time of this entry.
- Repository changes: retained main's read-only GCP `/http-activity`
  dashboard/API and dashboard evidence; reconciled current docs to distinguish
  that read-side from the login-only sensor producer. Kept bounded ingestion
  support for older `web_http_request` records, but did not restore page/scan
  event production, Core `/v1/track`, or XSS indicators. TI-worker state remains
  active as documented on main.
- Host/environment changes actually applied: no containers, systemd units,
  firewall rules, or external Compose files changed. Created a byte-verified
  temporary copy of the six pre-existing untracked hardware-backup binaries at
  `/tmp/honeypot-hardware-backup-pre-merge.tcFpE6/`; the originals remained in
  place and unmodified.
- Runtime/exposure state: unchanged by the merge. Web-corp remains HTTP-only on
  the Pi with login-only app telemetry; the dashboard's last production
  projection/auth-boundary validation is captured in the main-branch
  validation record, and authenticated browser rendering remains unverified.
- Validation performed and outcome: collector and processor `go test ./...`
  passed; all 10 web-corp unit tests passed in a network-disabled container;
  five focused dashboard HTTP activity test files passed (18 tests); staged
  diff whitespace checks passed.
- Not performed / deferred: no live login POST, authenticated dashboard
  browser test, provider request, host service restart, or public exposure
  change.
- Risks and data handling: existing local binary backups remain untracked and
  are excluded from commits; the temporary copy contains only those local
  artifacts. Historical page events may still be readable in Mongo/dashboard,
  but the current app creates no new page events.
- Rollback: no runtime rollback is needed. Retain the feature checkpoint
  `3ef9454d`; revert the merge commit only after reviewing its complete upstream
  file set and confirming the backup worktree is preserved.
- Follow-up: verify authenticated dashboard rendering with synthetic login
  data; continue to keep FTP/SMTP, direct-Pi HTTPS, and page/scan telemetry
  outside the active producer scope unless separately approved.
- Related docs: [HTTP decoy scope](design/http-decoy-scope.md),
  [web-corp data access](../integrations/web-corp/DATA-ACCESS.md),
  [dashboard integration](../dashboard-v2/docs/WEB_CORP_HTTP_INTEGRATION.md),
  and [live validation](WEB_CORP_HTTP_LIVE_VALIDATION_20260925.md).

### 2026-09-25 — Preserve Web-corp client source ports

- Status: repository implementation and tests prepared; not deployed.
- Scope and intent: capture the observed client TCP source port for new
  Web-corp login attempts and carry it into MongoDB's `network.src_port`,
  without mislabeling a reverse proxy's own socket port as the client port.
- Repository branch and commit/PR: `feat/opencanary-web-login-honeypot`;
  uncommitted working-tree change.
- Repository changes: added the optional sensor `source_port` field; added
  trusted-proxy-only `X-Forwarded-Client-Port` handling; validated and forwarded
  it as Redis `src_port`; mapped it to MongoDB `network.src_port`; tested the
  existing dashboard projection; and documented the accepted boundary in
  ADR-0006, the telemetry design, runbooks, and data-access guide.
- Host/environment changes actually applied: none. No deployed image/binary,
  container, systemd unit, database, external Compose file, or proxy config was
  changed.
- Runtime/exposure state: no fresh runtime check or restart was performed.
  Existing Web-corp events are unchanged; this additive optional field requires
  no MongoDB migration, and historical records cannot be backfilled.
- Validation performed and outcome: all 14 Web-corp tests passed in a
  network-disabled container with read-only source; collector and processor
  `go test ./...` passed; four focused dashboard HTTP tests passed (16 tests);
  `git diff --check` passed. Tests cover direct, trusted-proxy, and Uvicorn-
  rewritten peer-port behavior, range validation, Mongo normalization, and the
  dashboard projection.
- Not performed / deferred: no new login event was sent to a live sensor,
  Redis, or MongoDB; no live database query, proxy-header configuration test,
  image/binary rollout, or service restart was performed.
- Risks and data handling: source ports are transient and can change under NAT;
  they are not actor identities. Only a peer in configured
  `WEB_TRUSTED_PROXY_CIDRS` may assert a forwarded client port, and Uvicorn's
  `--forwarded-allow-ips` must match that peer set if its middleware rewrites
  the client scope. The proxy must overwrite the header. Missing or invalid
  forwarded ports remain absent.
- Rollback: revert the source, pipeline, tests, ADR, and documentation changes;
  no runtime rollback is needed because deployment was not performed.
- Follow-up: deploy the reviewed Web-corp, collector, and processor changes in
  dependency order, then verify one synthetic event in `honeypot_db.events`
  without retrieving or recording submitted credentials.
- Related material: [ADR-0006](adr/ADR-0006-web-client-source-port.md),
  [web-login telemetry design](design/web-login-telemetry.md),
  [web-corp runbook](../integrations/web-corp/README.md), and
  [data-access guide](../integrations/web-corp/DATA-ACCESS.md).

### 2026-09-25 — Deploy Web-corp client source-port pipeline

- Status: deployed; live login-event verification pending.
- Runtime change: built the `web-corp` image from commit `60125598`, atomically
  replaced the collector and processor binaries, restarted only
  `honeypot-processor.service`, `honeypot-collector.service`, and the `web-corp`
  container. The HTTPS container and unrelated services were left untouched.
- Validation: Compose config check passed; collector and processor Go tests
  passed; 14 Web-corp tests passed in an isolated network-disabled container;
  the running app contains `_client_port` and emits `source_port`; both agents
  are active; `GET /web/login` returned HTTP 200.
- Data impact: no live login POST or DB write was made. The earlier record
  remains without `network.src_port`; it cannot be backfilled. Confirm the field
  with a projected MongoDB query after the next authorized login attempt.
- Rollback: prior collector and processor executables are preserved under
  `/tmp/web-source-port-rollout.ycLTz2/` pending end-to-end confirmation.
- Detailed evidence: [source-port rollout validation](validation/2026-09-25-web-client-source-port-rollout.md).
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

### 2026-09-25 — Add diagonal guides and a circular radar emitter

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: try two corner-to-corner diagonal guides through the radar origin and change the filled center emitter from a square to a circle.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `3173531`; this refinement is uncommitted.
- Repository changes: add two low-contrast SVG diagonal lines that span the canvas corners, pass through its exact center, and adapt to the canvas aspect ratio; render the solid 32×32 primary-color center emitter as a circle; keep the rounded-square pulse waves unchanged; update the current `FS-024` criteria and append design/update records.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js development server remains active at `http://localhost:3000`; development-only auth fallback is in use.
- Validation performed and outcome: Next.js HMR compiled the edited component and styles; `/filesystem-activity` returned HTTP 200; `git diff --check` passed. No automated tests were run.
- Not performed / deferred: visual review of diagonal contrast and circle alignment in both themes, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only SVG/CSS change in empty-state radar; no API, MongoDB query, path evidence, telemetry authority, or event marker changed.
- Rollback: remove the diagonal SVG and style, restore the square emitter radius/class, and revert the corresponding `FS-024` criterion; no host rollback is required.
- Follow-up: inspect the diagonals against the crosshairs and moving sweep and confirm the circle reads clearly at the origin in both themes.
- Related ADR/runbook: no architecture decision or operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Thin the perpendicular radar axes

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: reduce the stroke thickness of the continuous perpendicular crosshairs while preserving their existing color, opacity, glow, and alignment with the connected edge ticks.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `cc45e14`; this refinement is uncommitted.
- Repository changes: reduce the shared crosshair, cardinal edge-tick, and corner-tick stroke width from 2px to 1.5px; keep accent colors and glow unchanged; update the current `FS-024` criterion and append design/update records.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js development server remains active at `http://localhost:3000`; development-only auth fallback is in use.
- Validation performed and outcome: Next.js HMR compiled the edited styles; `git diff --check` passed. No automated tests were run.
- Not performed / deferred: visual review of the slimmer axes at different display scales and themes, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only CSS change; no API, MongoDB query, path evidence, telemetry authority, or event marker changed.
- Rollback: restore `--pti-radar-stroke-width` to `2px` and revert the current-state criterion; no host rollback is required.
- Follow-up: review that the crosshairs remain visible and match the attached edge ticks at supported display scales.
- Related ADR/runbook: no architecture decision or operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Match crosshair opacity to diagonal guides

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: make the perpendicular center axes as faint as the diagonal guides without changing their color or thickness.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `cc45e14`; this refinement is uncommitted.
- Repository changes: set the perpendicular crosshair opacity to 0.2 to match the diagonal SVG lines; preserve the primary accent color, glow, 1.5px stroke width, and brighter edge ticks; update the current `FS-024` criterion and append design/update records.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js development server remains active at `http://localhost:3000`; development-only auth fallback is in use.
- Validation performed and outcome: Next.js HMR compiled the edited styles; `git diff --check` passed. No automated tests were run.
- Not performed / deferred: visual review to confirm the perpendicular axes match diagonal-guide faintness in both themes, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only CSS change; no API, MongoDB query, path evidence, telemetry authority, or event marker changed.
- Rollback: restore the crosshair pseudo-element opacity to 0.72 and revert the current-state criterion; no host rollback is required.
- Follow-up: visually compare the diagonal and perpendicular guide lines at the same zoom level.
- Related ADR/runbook: no architecture decision or operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Disable topology actions in the Live empty state

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: disable canvas toolbar actions while Live has no session topology, with an exception for exiting an already expanded workspace.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `8088dc1`; this refinement is uncommitted.
- Repository changes: derive an empty-live state for snapshots with no sessions or no snapshot; pass it to `TopologyToolbar`; disable zoom, fit, center, View menu and its appearance/layout options; close an open View menu when the empty state begins; disable fullscreen entry in the empty state but keep fullscreen exit enabled when expanded; style disabled buttons; update `FS-024` current-state criteria and append decision/update records.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js development server remains active at `http://localhost:3000`; development-only auth fallback is in use.
- Validation performed and outcome: Next.js HMR compiled the edited component and styles; `git diff --check` passed. No automated tests were run.
- Not performed / deferred: browser review of disabled styling, re-enabling controls after sessions arrive, and fullscreen exit; lint, type-check, production build, and production deployment.
- Risks and data handling: presentation and control-state change only; no API, MongoDB query, path evidence, telemetry authority, or event marker changed.
- Rollback: remove the `isEmptyLiveState` toolbar prop and button guards, restore fullscreen toggle availability, and revert the current-state criterion; no host rollback is required.
- Follow-up: verify that toolbar controls activate after a session arrives and that the expanded canvas can always be exited.
- Related ADR/runbook: no architecture decision or operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Keep fullscreen available in the Live empty state

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: correct the empty-state toolbar behavior so fullscreen can be entered as well as exited.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `8088dc1`; this clarification is uncommitted.
- Repository changes: remove the empty-state disabled condition from the fullscreen toggle; preserve disabled states for zoom, fit, center, View, appearance, and layout actions; clarify the current `FS-024` criterion and append a correction to the decision/update history.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js development server remains active at `http://localhost:3000`; development-only auth fallback is in use.
- Validation performed and outcome: Next.js HMR compiled the edited toolbar and `/filesystem-activity` returned HTTP 200; `git diff --check` passed. No automated tests were run.
- Not performed / deferred: browser review of fullscreen entry and exit from the empty state, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation and control-state change only; no API, MongoDB query, path evidence, telemetry authority, or event marker changed.
- Rollback: restore the `disabled={isEmptyLiveState && !isTopologyExpanded}` condition on the fullscreen toggle and revert the current-state clarification; no host rollback is required.
- Follow-up: confirm both fullscreen entry and exit work while the other Live toolbar actions remain disabled.
- Related ADR/runbook: no architecture decision or operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Make the paired standby radar waves circular

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: change the two expanding empty-state radar pulses from rounded squares to circles without changing their double-beat motion.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `d9f2fbb`; this refinement is uncommitted.
- Repository changes: replace the outer and inner SVG wave rectangles with centered circles of 462 and 332 logical-unit radii; remove responsive corner-radius calculations that only applied to the former rounded rectangles; preserve the 5.6-second cycle, 620ms inner-wave delay, existing expansion/fade keyframes, reduced-motion handling, and empty-state visibility rules; update `FS-024` current criteria and append design/update records.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js development server remains active at `http://localhost:3000`; an unauthenticated request to `/filesystem-activity` redirected to login with HTTP 307.
- Validation performed and outcome: `git diff --check` passed. No authenticated browser rendering or HMR compilation was confirmed for this refinement. No automated tests were run.
- Not performed / deferred: authenticated visual review of the circular pulses, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only SVG change in the empty-state radar; no API, MongoDB query, path evidence, telemetry authority, or event marker changed.
- Rollback: restore the two wave SVG rectangles and their responsive corner-radius calculation, then revert the corresponding current-state criterion; no host rollback is required.
- Follow-up: review pulse alignment and reduced-motion behavior in the authenticated UI in both themes.
- Related ADR/runbook: no architecture decision or operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Use one dissipating wave across the Live canvas

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: replace the two standby pulses with one circular wave that reaches beyond every canvas corner, loses intensity as it expands, then pauses before its next release.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `d9f2fbb`; this refinement is uncommitted.
- Repository changes: render one SVG circle; align its viewBox to measured CSS-pixel canvas dimensions so it remains circular on rectangular planes; calculate its radius as half the canvas diagonal plus 16px; ease the expansion to full reach by 80% of a 7-second cycle; reduce stroke opacity and attached glow from strong at the source to faint at the corner, fade it away after it clears the boundary, and leave approximately 0.6 seconds of invisible hold before restarting; preserve empty-state and reduced-motion gating; update `FS-024` current criteria and append design/update records.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: the local `dashboard-v2` Next.js development server remains active at `http://localhost:3000`; development authentication was active during the `/filesystem-activity` request.
- Validation performed and outcome: Next.js HMR compiled the edited component and styles in 90ms; `/filesystem-activity` returned HTTP 200; `git diff --check` passed. No automated tests were run.
- Not performed / deferred: visual review of the wave on wide and tall canvases, authenticated screenshot review, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only SVG/CSS change in the empty-state radar; no API, MongoDB query, path evidence, telemetry authority, or event marker changed.
- Rollback: restore the paired pulse circles, fixed square viewBox, and previous two-wave keyframes; revert the current-state criterion and appended decision/update records; no host rollback is required.
- Follow-up: inspect circle clipping and the fade/pause cadence at multiple canvas aspect ratios and in both themes.
- Related ADR/runbook: no architecture decision or operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Align the Live topology grid to the radar center

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: phase the neutral Live topology grid so its center intersection overlays the radar's perpendicular crosshair origin.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `ae0eff5`; this refinement is uncommitted.
- Repository changes: define the grid cell and half-cell sizes, offset both CSS grid layers so their repeated lines intersect at the exact canvas center, and update the `FS-024` current-state criterion and append its decision/update records.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: `npm run dev` remains active at `http://localhost:3000`; Next.js HMR compiled the updated styles in 259ms.
- Validation performed and outcome: Next.js HMR compilation succeeded; `git diff --check` passed. No automated tests were run.
- Not performed / deferred: authenticated visual review of the grid/crosshair overlap, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only background-position change; no API, MongoDB query, path evidence, telemetry authority, or event marker changed.
- Rollback: revert the grid cell/half-cell positioning and its current-state/decision/update documentation; no host rollback is required.
- Follow-up: review the center intersection at common viewport sizes and both themes.
- Related ADR/runbook: no architecture decision or operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Keep failed-origin annotations clear of topology nodes

- Status: prepared for review; local development UI active; not deployed.
- Scope and intent: prevent a failed-directory-change warning from overlapping its origin node and keep its position synchronized with topology movement.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `3d2d34d`; this refinement is uncommitted.
- Repository changes: render the warning inside the transformed graph plane so it follows pan and zoom; calculate its anchor from the measured origin-node height and leave 0.75rem clearance above the node; add current-state decision/update records.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: `npm run dev` remains active at `http://localhost:3000`.
- Validation performed and outcome: `git diff --check` passed; an unauthenticated `/filesystem-activity` request redirected to login with HTTP 307. HMR compilation and authenticated browser rendering were not confirmed. No automated tests were run.
- Not performed / deferred: authenticated visual review at different zoom levels, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only positioning change; failure provenance and event content are unchanged.
- Rollback: restore the failed-origin warning to its prior map-surface position and revert the corresponding decision/update records; no host rollback is required.
- Follow-up: confirm that the callout remains fully visible and separate from its node in the authenticated Audit view at narrow and wide canvas sizes.
- Related ADR/runbook: no architecture decision or operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Keep failed-change explanations out of the topology canvas

- Status: prepared for review; local development UI active; not deployed. This entry corrects the preceding same-day annotation-position experiment.
- Scope and intent: remove the duplicate long failure explanation from the topology canvas because it can overlap neighboring session or directory nodes; keep the event's failed-origin marker and full explanation in Forensic Studio.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `3d2d34d`; this correction is uncommitted.
- Repository changes: remove anchored and fallback canvas warning text, retain the Replay/Forensic Studio detail and origin marker, and update the existing failure-visualization assertions to match the canvas-free presentation.
- Host/environment changes actually applied: none. No production dashboard, service, database, reverse proxy, or host configuration was changed.
- Runtime/exposure state: `npm run dev` remains active at `http://localhost:3000`.
- Validation performed and outcome: Next.js HMR compiled in 175ms; the authenticated Audit route returned HTTP 200; `git diff --check` passed. No automated tests were run.
- Not performed / deferred: authenticated screenshot review, lint, type-check, production build, and production deployment.
- Risks and data handling: presentation-only duplication removal; failure provenance and verified/unknown path semantics are unchanged.
- Rollback: restore the canvas-level failed-change warning and previous assertions; retain this dated correction as audit history.
- Follow-up: confirm the remaining failed-origin marker is visible while the full explanation remains readable in Forensic Studio.
- Related ADR/runbook: no architecture decision or operating procedure changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Retire Dashboard session termination and decommission the Pi agent

- Status: Dashboard source changes are uncommitted and not deployed; Pi response agent is decommissioned; one Cowrie restart and tailnet ACL cleanup remain deferred.
- Scope and intent: remove the Filesystem Activity Response/kill feature and its Dashboard-to-Pi control path, retaining Route Replay and Evidence while preserving Tailscale for host administration.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `3810e5b`; this change is uncommitted.
- Repository changes: remove the Response tab, Dashboard terminate API, response-action UI/controller/client and related types/tests; remove the Cowrie control hook integration, agent source/service/drop-in and Tailscale response-grant example; update current and historical docs with retirement status and Evidence provenance guidance. MongoDB action history is retained.
- Host/environment changes actually applied: on `pi-t`, stop and disable `honeypot-response-agent.service`; remove its systemd unit, binary, environment and token files and dedicated `cowrie-response` account; remove Cowrie's `40-session-control.conf` drop-in and run `systemctl daemon-reload`. Port 8788 had no listener after decommission. Cowrie was left running because existing TCP sessions were observed; the already-running process may retain its old environment or hook until a later restart. Tailscale remains active.
- Runtime/exposure state: the Pi response endpoint is unavailable. The Dashboard source no longer contains the terminate API or control UI, but no production Dashboard deployment was performed, so an older deployed app may still show the former UI/API. Local `npm run dev` remains active at `http://localhost:3000`; an unauthenticated Filesystem Activity request redirects to login. The tailnet ACL was not inspected or changed; any former TCP 8788 grant must be removed in the Tailscale Admin Console.
- Validation performed and outcome: read-only host checks confirmed the response unit is absent/inactive, port 8788 has no listener, Cowrie is active, and the response drop-in is absent from its systemd configuration. The unauthenticated local route returned HTTP 307 to login. Static source/reference review and `git diff --check` passed; automated tests, lint, and build were not run.
- Not performed / deferred: restart Cowrie after existing sessions drain to clear the old process environment/hook; remove any stale tailnet ACL grant through Admin Console; deploy the Dashboard source; implement expanded Evidence content. No MongoDB records were deleted.
- Risks and data handling: active Cowrie sessions were not interrupted. Existing response-action records remain in MongoDB. No secret values or attacker data were copied into repository documentation.
- Rollback: restoring this control path would require a deliberate reimplementation/redeployment and newly issued credentials; removed credentials are not retained in the repository.
- Follow-up: remove any old `tcp:8788` tailnet grant, then restart Cowrie during a controlled window and verify the response hook is no longer loaded.
- Related ADR/runbook: see [ADR-0007](adr/ADR-0007-retire-dashboard-session-termination.md), the retirement status in [Cowrie response control plane](RESPONSE-CONTROL-PLANE.md), [Tailscale response-control identity](../integrations/tailscale/README.md), and [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md).

### 2026-09-25 — Add the selected-session CWD Evidence ledger

- Status: prepared for review; local Dashboard only; not deployed.
- Scope and intent: replace the Evidence placeholder with an evidence view grounded in retained Cowrie CWD transition records.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `3810e5b`; this implementation is uncommitted.
- Repository changes: add `CwdEvidenceLedger` with selected session/source scope, latest CWD state and provenance, oldest-first retained transitions, path/action/status/time/hop and source identifiers, loaded-versus-retained counts, earlier-page loading, and selected-hop context. Preserve the exact selected event ID when a replay filter hides that event. Failed destinations are suppressed as unverified. The panel states that CWD transitions do not prove command execution or file access. Update the Filesystem Activity working state and this log.
- Host/environment changes actually applied: none for this Evidence UI change. No production Dashboard, service, database, reverse proxy, or Cowrie configuration was changed.
- Runtime/exposure state: the Pi response agent remains decommissioned as recorded above; Tailscale remains active for administration. The local `npm run dev` Dashboard remains the only UI runtime; this Evidence change has not been deployed.
- Validation performed and outcome: scoped ESLint and `git diff --check` passed. The local `/filesystem-activity` route returned HTTP 307 to login. `npx tsc --noEmit` was attempted but is blocked by stale generated `.next/types` imports for the removed `actions/terminate` route; no source error from the new ledger was reported. No automated tests were run.
- Not performed / deferred: authenticated visual review and production build; correlate admin-only command input to CWD events, render filesystem read/write/create/delete operations, and add forensic export. No test suite was run.
- Risks and data handling: the panel presents retained session path telemetry only and does not infer commands or file access. It displays event identifiers already present in the selected-session history; no raw command input or attacker payload is added.
- Rollback: remove `CwdEvidenceLedger`, restore the former Evidence availability placeholder, and revert the optional selected-event ID in the replay presentation; revert the `FS-025` current-state update. No host rollback is required.
- Follow-up: review the selected-session Evidence view at desktop and narrow widths; retain `FS-025` as in progress until UI and coverage semantics are accepted.
- Related ADR/runbook: no deployed operating procedure or architecture decision changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Replace duplicate CWD Evidence with command input evidence

- Status: prepared for review; local Dashboard only; not deployed.
- Scope and intent: correct the Evidence direction after confirming that another CWD ledger duplicates Route Replay.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics` at `3810e5b`; this correction is uncommitted.
- Repository changes: remove `CwdEvidenceLedger`; use the exact-session Admin-only Cowrie command endpoint from Evidence; validate response scope and session identity; render retained event type, ID, timestamp, command input, and redaction/truncation state; distinguish sign-in, Admin authorization, empty, and unavailable states; state that input is not joined to a CWD hop and does not prove execution or file access. Revert the optional replay-event presentation field and update the Filesystem Activity working state.
- Host/environment changes actually applied: none. No Pi service, Dashboard deployment, database, reverse proxy, Cowrie configuration, or Tailscale setting changed.
- Runtime/exposure state: the existing local `npm run dev` at `http://localhost:3000` was not restarted; no production deployment was performed. Pi response-agent and Tailscale status remain as recorded in the preceding entry.
- Validation performed and outcome: scoped ESLint passed and `git diff --check` passed. `npx tsc --noEmit` remains blocked by three stale generated `.next/types` references to the removed terminate route; it reported no other TypeScript diagnostics. No automated tests or authenticated visual review were run.
- Not performed / deferred: authenticated verification against retained command records, browser review, production build/deployment, command-to-CWD correlation, file-operation event collection, and forensic export.
- Risks and data handling: Cowrie command input is sensitive. The UI uses the existing Admin-only endpoint, requests `no-store`, keeps data in component memory, and does not write command text to logs or documentation. Input is not presented as proof of command execution or file access.
- Rollback: remove `CommandEvidencePanel`, restore the Evidence unavailable placeholder, and revert the `FS-025` current-state correction. No host rollback is required.
- Follow-up: review Evidence with an authenticated Admin session and confirm empty, redacted, truncated, and unavailable states against retained command data.
- Related ADR/runbook: no deployed operating procedure or architecture decision changed; see [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct).

### 2026-09-25 — Resolve Filesystem Evidence session aliases safely

- Status: prepared for review; not deployed.
- Scope and intent: allow the Admin-only Evidence view to load Cowrie commands when Filesystem Activity supplies a sensor-local session ID, while preserving exact canonical session binding.
- Repository branch and commit/PR: `feat/filesystem-visualization-semantics`; uncommitted.
- Repository changes: validate opaque sensor-local IDs; resolve them only from canonical session metadata events whose stored identity binding and canonical hash verify; reject missing or ambiguous mappings; pass only the verified canonical ID to the existing command source; version the response contract and bind the requested ID to the canonical response ID. Update command API and Filesystem Activity data semantics.
- Host/environment changes actually applied: none. No dashboard deployment, MongoDB mutation, monitor service, Cowrie service, Pi configuration, or network setting was changed.
- Runtime/exposure state: no production runtime change. The local development process was not restarted or independently checked for hot reload.
- Validation performed and outcome: scoped ESLint and `git diff --check` passed. The connected MongoDB snapshot contained command events overall but no verified mapping for the selected local ID, so the selected session could not be confirmed against that snapshot.
- Not performed / deferred: no automated tests, type-check, authenticated browser verification, production build, or deployment was performed. A live Evidence check still requires a session with a persisted canonical identity binding.
- Risks and data handling: alias lookup is Admin-gated, exact, time-bounded, restricted to session metadata event types, and fails closed on ambiguous identity. Raw command text remains in the existing bounded `no-store` command projection and is not added to logs or documentation.
- Rollback: revert the alias resolver, response contract update, and corresponding API/data-semantics documentation. No host rollback is required.
- Follow-up: verify Evidence against an authenticated session whose CWD alias has a matching canonical identity event; confirm no-command and unverified-binding states remain distinct.
- Related ADR/runbook: [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md#product-additions-after-the-foundation-is-correct) and [Dashboard API contract](../dashboard-v2/docs/API.md#sensitive-admin-command-evidence).
