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
