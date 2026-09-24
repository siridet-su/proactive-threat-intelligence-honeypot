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
