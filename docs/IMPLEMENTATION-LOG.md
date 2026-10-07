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

### 2026-09-29 — Block the retired GCP Cowrie relay at the Pi

- Status: active Pi firewall change; GCP public ingress closure pending.
- Scope and intent: stop the retired GCP/ZeroTier Cowrie relay from reaching the existing Pi without changing administrator SSH, the DigitalOcean Cowrie forward, or Web-corp.
- Repository branch and commit/PR: `main` working tree; commit pending at entry time.
- Repository changes: update the current architecture, service catalog, and GCP exposure/runbook notes to record the observed partial closure and prevent the older rebuild procedure from recreating the relay.
- Host/environment changes actually applied: removed the Pi UFW allow for the former peer-only ZeroTier Cowrie backend on TCP 2298, then inserted an explicit deny for TCP 2298 on the ZeroTier interface for IPv4 and IPv6. No GCP firewall, HAProxy, VM, ZeroTier controller, or DigitalOcean setting was changed by this step.
- Runtime/exposure state: Pi UFW remains active with default input drop; its effective IPv4 and IPv6 user-input chains drop new TCP 2298 traffic on ZeroTier before other user rules. The retired GCP public TCP 2222 endpoint still accepted a TCP connection after the Pi allow was removed; external closure is not complete. The independent DigitalOcean public TCP 22 route was not changed.
- Validation performed and outcome: inspected numbered UFW rules and effective IPv4/IPv6 user-input chains after the changes; the former allow was absent and the explicit deny was present first. A TCP-only probe still connected to the GCP public TCP 2222 endpoint. At 18:09 UTC, the previously observed source's latest Cowrie connection was still the 17:53 UTC record. No Cowrie login or attacker payload was generated for validation.
- Not performed / deferred: GCP firewall/frontend disablement and post-closure external probe; authenticated GCP access was unavailable from this workspace. No end-to-end decoy test was run.
- Risks and data handling: the GCP frontend remains publicly reachable until its own ingress is disabled. Existing Cowrie evidence was retained; no secret or raw payload was copied into the repository.
- Rollback: remove only the named Pi ZeroTier TCP 2298 deny and restore the former peer-scoped allow from owner-controlled configuration only if the relay is explicitly reapproved; leave unrelated firewall rules intact.
- Follow-up: disable the retired GCP TCP 2222 firewall rule or frontend with authorized GCP access, then verify the external TCP probe fails and update current-state records.
- Related ADR/runbook: [current architecture](CURRENT-ARCHITECTURE.md), [service catalog](SERVICE-CATALOG.md), [GCP architecture record](../honeypot-analysis/docs/GCP_VM_CURRENT_ARCHITECTURE.md), and [GCP rebuild runbook](../honeypot-analysis/docs/GCP_VM_REBUILD_RUNBOOK.md).

### 2026-09-28 — Narrow MongoDB developer handoff after Dashboard auth review

- Status: repository guidance correction prepared; no Atlas account or host changed.
- Scope and intent: prevent a general read-only developer account from exposing Dashboard operator password hashes and session metadata while still allowing selected telemetry inspection.
- Repository branch and commit/PR: `main` working tree; commit pending at entry time.
- Repository changes: update the MongoDB handoff guide to require collection-level read grants for approved telemetry, identify `honeypot_db.users` and `honeypot_db.auth_sessions` as excluded live-auth data, and direct interactive login testing to a separate synthetic test database.
- Host/environment changes actually applied: none. No Atlas user, IP access entry, collection, credential, Pi service, or Dashboard deployment was changed.
- Runtime/exposure state: existing production data and users are unchanged; this entry corrects the future handoff procedure only.
- Validation performed and outcome: repository source review confirmed `users` stores bcrypt password hashes and that Dashboard sessions are written to `auth_sessions`; the guide was checked against those code paths. No live database read was performed.
- Not performed / deferred: creating or editing the successor's Atlas user, selecting the final collection whitelist, sanitized export generation, and a dev login test.
- Risks and data handling: collection read access still reveals every permitted field, including attacker-submitted telemetry. The prior database-wide read recommendation would expose auth collections; correct any pending Atlas form before submitting it. No secret or raw document was recorded.
- Rollback: revert the guidance change if the data-access contract is later redesigned; no host rollback is applicable.
- Follow-up: approve the exact telemetry collection list with the successor, then verify read succeeds only for those collections and is denied for `users` and `auth_sessions`.
- Related ADR/runbook: [MongoDB developer handoff](MONGODB-DEV-HANDOFF.md) and [Dashboard auth implementation](../dashboard-v2/src/lib/auth/session.ts).

### 2026-09-28 — Keep fresh-host B2 backup disabled until owner opt-in

- Status: repository change prepared; not applied to a host.
- Scope and intent: allow the fresh Pi core to run without a B2 credential while preventing writes to the existing owner's archive. Keep any successor access to historical objects read-only and separate from a new backup destination.
- Repository branch and commit/PR: `main` working tree; commit pending at entry time.
- Repository changes: add an explicit backup opt-in to the fresh installer; keep the fresh backup control unit stopped and disabled by default; exclude backup env from the fresh core gate; retain the existing-Pi five-unit default; update the fresh runbook, ADR, current state, blank env notes, tests, and B2 handoff guidance.
- Host/environment changes actually applied: none. The disposable VM was queried through read-only env gates; its files and services were not changed. Existing Pi, B2 account, bucket, application keys, and Dashboard were not changed.
- Runtime/exposure state: the existing Pi backup runtime remains as previously recorded unless changed separately. A future fresh install will activate four core Go units and leave its backup control unit inactive until the operator provides their own destination key and reruns with `--enable-backup`.
- Validation performed and outcome: targeted env-selection tests (10 unittest cases and 3 fresh-installer pytest cases), Python compilation, and Ansible syntax checks passed. The VM env gate with backup disabled reported only missing core MongoDB settings; with backup enabled it also required the backup worker's MongoDB setting. No B2 API call or archive write was made.
- Not performed / deferred: live new-Pi activation, actual B2 upload and restore with owner-managed credentials, historical read-only key creation, and any change to the existing Pi backup service.
- Risks and data handling: the fresh host has no remote archive until opt-in succeeds. A read-only historical key can still disclose object contents. No B2 key, object, private endpoint, or archive content was copied into Git.
- Rollback: revert the repository change before deploying it; on a fresh test host, keep the backup unit stopped and disabled while reviewing its env and destination.
- Follow-up: validate the owner's new destination with a bounded upload and restore after they supply credentials; separately decide whether to issue a bucket/prefix-scoped historical read-only key.
- Related ADR/runbook: [ADR-0015](adr/ADR-0015-fresh-pi-local-decoys.md), [fresh install runbook](../deploy/ansible/README.md), and [B2 handoff](B2-ARCHIVE-HANDOFF.md).

### 2026-09-28 — Prepare fresh Pi local decoys and bounded ARM64 activation

- Status: repository implementation prepared; bounded service activation tested and then stopped on a disposable ARM64 VM. Existing Pi and Droplet remain unchanged.
- Scope and intent: make a clean Ubuntu ARM64 Pi install Cowrie, narrow Zeek, localhost Web-corp/Core/PostgreSQL, and the Go stack through one resumable controller command, while omitting the legacy GCP sensor forwarder. Keep Dashboard as a local source-based developer process.
- Repository branch and commit/PR: `main` working tree; commit pending at entry time.
- Repository changes: add the fresh full-stack installer and non-secret env filler, Cowrie/Zeek/decoy activation playbooks, fresh Cowrie sanitizer contract, Wi-Fi-only collector configuration profile, Dashboard `npm run dev` launcher, targeted tests, ADR-0015, current-state/runbook updates, MongoDB handoff guidance, and legacy forwarder explanation.
- Host/environment changes actually applied: the disposable Azure Ubuntu 24.04 ARM64 VM was used for isolated Cowrie, Zeek, and Compose activation with synthetic inputs and loopback-only test ports. The full installer prepared and retried the same release, then paused at a missing private MongoDB URI. No Go service or Dashboard was activated on that VM. No existing Pi, Droplet, or Dashboard host was changed.
- Runtime/exposure state: after the VM checks, the test Compose stack and volumes were removed, Cowrie/Zeek/Docker services were stopped and disabled, the synthetic database password was cleared, and the provisional Cowrie activation files were removed. Only administrator SSH and local DNS stub listeners remained on the VM. The existing Pi forwarder remains active; a future fresh Pi install will omit it.
- Validation performed and outcome: Cowrie emitted sanitized events from a synthetic SSH connection and a repeat activation made no changes. Zeek's corrected effective filter and connection log admitted only synthetic Cowrie test ports, excluding SSH management and HTTP test traffic. Web-corp returned HTTP 200; Core mounted the reviewed Zeek log path after Compose reconciliation; a further retry made no changes. Targeted Python, Go, syntax, and Ansible checks passed. The full installer pause and same-release preparation retry passed. See the linked validation record.
- Not performed / deferred: completed full-stack activation with private credentials, Wi-Fi port-22/23 cutover on a clean Pi, Go → Redis → Atlas/B2 event and backup verification, Dashboard authenticated browser review, restore test, final sanitizer package rebuilt from the committed revision, and production deployment.
- Risks and data handling: administrator SSH must be moved and verified separately before Cowrie claims Wi-Fi TCP 22. Wi-Fi address changes require reviewed Cowrie/Zeek rebinding. Read-only Atlas access can still expose sensitive fields; no developer database account or credential was created. No secret, raw attacker payload, private endpoint, or private config content was committed.
- Rollback: on a new test host, stop and disable only the fresh services and remove its disposable Compose project after preserving any needed data. Existing Pi rollback is not applicable because it was not changed. Repository code can be reverted before deployment.
- Follow-up: build final release artifacts from the committed tree, run a clean-Pi acceptance test after administrator SSH separation, and verify the data path with operator-managed credentials before using the installation for production.
- Related ADR/runbook: [ADR-0015](adr/ADR-0015-fresh-pi-local-decoys.md), [fresh install runbook](../deploy/ansible/README.md), [VM evidence](validation/2026-09-28-azure-arm64-fresh-activation.md), [MongoDB handoff](MONGODB-DEV-HANDOFF.md), and [forwarder explanation](LEGACY-SENSOR-FORWARDER.md).

### 2026-09-28 — Prepare hosted Dashboard command evidence from canonical MongoDB

- Status: repository change prepared; hosted production setting and deployment not yet applied.
- Scope and intent: make the Admin-only Filesystem Activity Command events panel usable when Dashboard and the private Pi monitor do not share a loopback interface.
- Repository branch and commit/PR: `feature/filesystem-activity-command-evidence-20260928` worktree from `origin/main`; commit/PR pending at entry time.
- Repository changes: add an explicit server-only `PTI_ADMIN_COMMANDS_SOURCE=mongo` production source selection using the existing bounded exact-session canonical command projection; keep the colocated monitor path as the default. Record the hosted source boundary in ADR-0016 and update the Dashboard API, operating instructions, Filesystem Activity working state, and architecture snapshot.
- Host/environment changes actually applied: none. No Railway variable, Dashboard deployment, Pi service, MongoDB document, or credential changed in this repository step.
- Runtime/exposure state: the production screenshot shows the Admin Command events panel reporting the protected source as unavailable. The hosted source remains inactive until the new code is deployed and the private Railway setting is applied. The existing monitor path remains the default.
- Validation performed and outcome: source inspection traced the panel message to HTTP 503 from the command route and confirmed that the current production loader requires a same-host loopback monitor and owner-only token file. The changed route, loader, and documentation were reviewed; `git diff --check` passed. No production response or protected command content was captured.
- Not performed / deferred: automated tests, production deployment, private Railway setting, authenticated 200/403 and no-store checks, and confirmation of command rows for the selected session.
- Risks and data handling: command input can contain attacker-entered secrets. The opt-in Mongo path preserves Admin authorization, canonical session binding, bounded projection, and private no-store responses; no raw command input or credentials were copied into Git. Monitor failures do not silently fall back to MongoDB.
- Rollback: unset `PTI_ADMIN_COMMANDS_SOURCE` to restore the monitor-only source; revert the repository change if needed.
- Follow-up: connect Railway access, apply the private setting and reviewed deployment, then verify a known retained command session through the authenticated Admin view without recording command text.
- Related ADR/runbook: [ADR-0016](adr/ADR-0016-hosted-dashboard-command-evidence.md), [Dashboard runbook](../dashboard-v2/README.md), and [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md).

### 2026-09-28 — Replace Cowrie watchdog TCP connect with passive listener inspection

- Status: active on the existing Pi; final pre-cutover watchdog rows removed from canonical MongoDB.
- Scope and intent: keep the 30-second Cowrie service recovery check while preventing its health probe from creating fake attacker sessions. Clear only the remaining exact-pair probe rows produced before the change.
- Repository branch and commit/PR: `cleanup/loopback-watchdog-mongo-20260928` worktree; commit pending at entry time, no PR opened.
- Repository changes: track the existing host watchdog source with a `tcp_listen` probe that reads `/proc/net/tcp`, add a guarded Pi cutover installer and runbook, and update the current architecture, service catalog, and Cowrie runbook. The prior MongoDB cleanup tool is reused unchanged.
- Host/environment changes actually applied: saved the previous watchdog script and protected config under the root-only Pi directory `/var/backups/honeypot/service-watchdog/20260928T143833111619Z`; changed only the Cowrie probe type from active TCP connect to passive listener inspection, ran the service, and resumed its timer. Backed up the final exact-pair MongoDB set under `/var/backups/honeypot/loopback-cowrie-cleanup/20260928T144854364446Z`, then deleted 32 sessions, 64 events, and 128 observable sightings in one exact-ID transaction. No other probe target, Cowrie service configuration, firewall, WireGuard, or VPS setting was changed.
- Runtime/exposure state: watchdog timer and Cowrie service are active. Cowrie's watchdog state is `HEALTHY` with reason `tcp_listening`; the service still checks and can recover Cowrie according to its existing thresholds. The Dashboard Recent Interceptions feed reads the same canonical sessions collection as the prior cleanup. The live health check no longer opens a Cowrie connection.
- Validation performed and outcome: the installer verified the staged source and the existing port 22 listener before cutover, then confirmed an active timer and a healthy Cowrie result on the new probe. After about ten minutes of timer runs, the Cowrie JSON log had zero `127.0.0.1` connect events since cutover. The final MongoDB cleanup verified its root-only backup and exact deletion IDs; a read-only post-cleanup preflight found zero eligible watchdog sessions and 94 other loopback sessions intentionally retained (87 with other or incomplete activity and seven pairs excluded by safety checks). The canonical sessions query used by Recent Interceptions returned non-loopback origins for its three newest rows; the newest retained loopback row started at 12:45 UTC.
- Not performed / deferred: a forced Cowrie failure/restart exercise, reboot persistence check, Dashboard browser refresh after final cleanup, and removal of retained loopback sessions with activity.
- Risks and data handling: passive listener inspection confirms a socket is listening and the service is active; it does not perform an SSH handshake. The protected host backup and MongoDB archive remain on the Pi; no protected config, credentials, raw attacker event, or archive content was copied into Git.
- Rollback: restore the exact watchdog script and config from the protected service-watchdog backup directory, then restart the watchdog timer and check Cowrie health. The second MongoDB archive has a verified manifest for a separately reviewed exact-document restore if needed.
- Follow-up: observe normal watchdog health and the Threat Intelligence feed after a browser refresh; review retained loopback activity separately if desired.
- Related ADR/runbook: [watchdog runbook](../deploy/service-watchdog/README.md), [Cowrie runbook](../integrations/cowrie/README.md), [current architecture](CURRENT-ARCHITECTURE.md), and [service catalog](SERVICE-CATALOG.md).

### 2026-09-28 — Remove confirmed Cowrie loopback watchdog sessions from canonical MongoDB

- Status: active one-time data cleanup applied to production MongoDB; watchdog service unchanged and still active.
- Scope and intent: clear only closed Cowrie `127.0.0.1:22` sessions with exactly one processed connect event and one processed closed event. Preserve local sessions with login, command, or other activity, and preserve port 2222 sessions.
- Repository branch and commit/PR: `cleanup/loopback-watchdog-mongo-20260928` worktree from `origin/main` at `231ff59`; commit pending at entry time, no PR opened.
- Repository changes: add a guarded exact-ID MongoDB cleanup tool and document the active watchdog probe and cleanup procedure. The separate installation worktree was not modified.
- Host/environment changes actually applied: read the protected Pi MongoDB connection file without exposing its contents; backed up and verified the exact selected documents under the root-only Pi directory `/var/backups/honeypot/loopback-cowrie-cleanup/20260928T142449488526Z`; deleted 1,336 canonical sessions, 2,672 canonical events, 5,344 observable sightings, 10 prediction outbox documents, and 10 prediction snapshots in one MongoDB transaction. No Pi service, timer, environment file, firewall rule, or VPS setting was changed.
- Runtime/exposure state: Cowrie and the 30-second local watchdog probe remain active. A read-only post-cleanup inspection found 96 current `127.0.0.1` sessions: 87 with other or incomplete activity, eight connect/closed pairs excluded by safety checks, and one new eligible watchdog session generated after the deletion. New probe sessions will continue to appear until the watchdog probe changes.
- Validation performed and outcome: preflight classified the live session/event records by session identity, event pair, destination, processed state, and ended state. The tool verified the protected Extended JSON backups before deletion, checked exact document counts inside the transaction, and verified that all selected `_id` values were absent after commit. The post-cleanup read-only preflight confirmed the preserved non-probe groups and one newly generated probe row.
- Not performed / deferred: watchdog probe change, Dashboard deployment or browser refresh check, protected-backup restore exercise, and removal of the remaining loopback sessions with activity. The existing `observables` aggregate was not rewritten because it also represents retained loopback activity and its lifetime sighting count is not a direct count of current sightings.
- Risks and data handling: the protected archive may contain sensitive telemetry and remains only on the Pi. No credentials, raw events, payloads, or archive contents were added to Git. Continued watchdog probes will repopulate MongoDB until the source is corrected.
- Rollback: review the protected archive manifest and its SHA-256 hashes, then restore only the listed exact BSON documents through a reviewed PyMongo Extended JSON import after checking for newer records with the same `_id`. Preserve the archive and audit entry.
- Follow-up: change the watchdog Cowrie check to avoid opening a TCP session, then run the tool's read-only preflight again and review any later exact-pair rows for a separate cleanup.
- Related ADR/runbook: [Cowrie runbook](../integrations/cowrie/README.md), [service catalog](SERVICE-CATALOG.md), and [cleanup tool](../honeypot-analysis/production/tools/clear_loopback_cowrie_sessions.py).


### 2026-09-28 — Stage Docker decoys and correct Dashboard staging env gate

- Status: Docker/Compose and source staged and images built for bounded checks on the disposable ARM64 VM; Dashboard staging changes prepared in repository only.
- Scope and intent: continue the clean-OS installation path without public exposure or generating credentials; align Dashboard staging deployment with the current auth source contract.
- Repository branch and commit/PR: `main` working tree; commit pending at entry time.
- Repository changes: add a clean-Git decoy bundle builder, hash-gated Ansible Docker/Compose staging playbook, blank decoy env example, Dashboard staging env skeleton/checker, validation test and evidence, and installation/runbook updates.
- Host/environment changes actually applied: on the disposable Ubuntu 24.04 ARM64 VM only, installed reviewed exact Ubuntu Docker and Compose packages, staged a source bundle from commit `e719c9095c1a918c5801861652ce96bc68426880`, placed blank decoy env example/actual files, built Web-corp and Deception Core ARM64 images, and ran a disposable loopback Compose smoke test with synthetic database input. The smoke test's containers and volumes were removed. The staging playbook was corrected to create the empty Web-corp spool as root-only after Docker's default directory creation was observed. Docker, its socket, and containerd were stopped and disabled afterward. No existing Pi, Droplet, or Dashboard host changed for this entry.
- Runtime/exposure state: the VM has two built decoy images but no service container or new listener. The existing Pi and Droplet runtime from the prior entry are unchanged. Dashboard staging bootstrap/deploy changes are not installed on a host.
- Validation performed and outcome: decoy bundle hash check and repeat-build digest, Ansible syntax check, VM staging run (`changed=9`, `failed=0`), same-bundle retry (`changed=0`, `failed=0`), root-owned mode-`0600` env check, and no decoy-port listeners passed. ARM64 images built; no-network Web-corp import passed. Deception Core import initially failed without `/data`, then passed with an isolated temporary `/data` filesystem matching its volume requirement. Disposable loopback Compose started all three services, Web-corp returned 200, and Core returned 404 at its root path; cleanup removed test containers and volumes. The spool permission correction was applied and verified mode `0700`; Docker services were stopped afterward. Dashboard staging contract/env unit tests and shell syntax passed.
- Not performed / deferred: persistent ARM64 decoy activation, mutable base-image tag pinning, private credential validation, production Pi migration, Dashboard staging host deployment, Dashboard Mongo connectivity, and full clean-host acceptance.
- Risks and data handling: package versions were reviewed on the VM but transitive Docker dependencies and base images are not pinned as a final release; blank actual env files are never overwritten on retry. No secret, key, raw event, or protected host config was copied into Git.
- Rollback: keep the staged services disabled; on a disposable VM, discard the VM or remove only the new decoy source release and packages after reviewing dependencies. Dashboard staging changes can be reverted in Git before host application. Do not touch existing Pi decoy containers.
- Follow-up: pin image bases and built image identities, add private-env validation and explicit activation with smoke tests, and qualify the Dashboard staging env gate on its separate host. Integrate dependency stages into the one-command installer only after those gates pass.
- Related ADR/runbook: [installer credential boundary](adr/ADR-0009-installer-operator-managed-credentials.md), [Ansible staging runbook](../deploy/ansible/README.md), [decoy source runbook](../deploy/decoy-honeypot/README.md), [Dashboard staging runbook](../honeypot-analysis/deployment/dashboard-v2-staging/README.md), and [validation evidence](validation/2026-09-28-azure-arm64-decoy-staging.md).

### 2026-09-28 — Include HTTP sessions in Threat Intelligence Console rows per page and pagination

- Status: repository Dashboard change prepared; not applied to a host or activated.
- Scope and intent: ensure that the "Rows per page" selector and pagination controls on the Threat Intelligence Console (`threat-intel/page.tsx`) accurately include HTTP sessions across All, SSH, and HTTP views, preventing HTTP sessions from overflowing the page size limit or being excluded from page counts.
- Repository branch and commit/PR: `edit-dashboard` working tree; commit/PR pending.
- Repository changes:
  - In `dashboard-v2/src/lib/threat-intel-session-directory.ts`: implement `calculateDirectoryPagination` to compute unified total sessions, total pages, page clamping, HTTP slice boundaries (`httpOffset`, `httpLimit`), and SSH slice boundaries (`sshOffset`, `sshLimit`) based on the active protocol filter (`all`, `ssh`, `http`) and page size.
  - In `dashboard-v2/src/lib/threat-server.ts`: add `offset` and `limit` support to `ThreatDirectoryFilters` and `normalizeDirectoryFilters`; update `getThreatDirectory` to skip `offset` and take `limit` when provided, returning an empty session slice without extra queries when `limit === 0`.
  - In `dashboard-v2/src/app/api/threats/directory/route.ts`: parse `offset` and `limit` query parameters and pass to `getThreatDirectory`.
  - In `dashboard-v2/src/app/(main)/threat-intel/page.tsx`: use `calculateDirectoryPagination` to derive unified pagination metrics; slice HTTP sessions per page and combine them with fetched SSH sessions so the displayed rows never exceed the selected `pageSize`; enable pagination footer and "Rows per page" dropdown across All, SSH, and HTTP tabs whenever total sessions > 0; safely clamp active page during pagination calculation.
  - In `dashboard-v2/tests/threat-intel-session-directory.test.ts`: add unit tests covering `calculateDirectoryPagination` across all protocol views, page boundary transitions, and rows per page compliance.
- Host/environment changes actually applied: none. Only local tests, type checks, and linting were run.
- Runtime/exposure state: existing deployed host remains unchanged.
- Validation performed and outcome: `npx vitest run tests/threat-intel-session-directory.test.ts tests/dashboard-phase0-threat-semantics.test.ts tests/dashboardTypes.test.ts tests/threat-intel-map-view.test.ts tests/artifact-server.test.ts` passed (40 passed, 1 expected fail); `npx tsc --noEmit` passed with 0 errors; `npm run lint` passed with 0 warnings/errors.
- Not performed / deferred: deployment to production host.
- Risks and data handling: presentation and pagination boundary correction only; no secrets or raw payloads involved.
- Rollback: discard working directory changes with `git restore`.
- Follow-up: none.
- Related ADR/runbook: unified Threat Intelligence session directory implementation.

### 2026-09-28 — Unify honeypot interaction session directory across SSH and HTTP protocols

- Status: repository Dashboard change prepared; not applied to a host or activated.
- Scope and intent: unify the presentation and discovery of honeypot interactions across SSH and HTTP protocols in the Threat Intelligence Console (`threat-intel/page.tsx`), providing cohesive attacker type filtering, unified pagination indicators, multi-protocol CSV exports, and combined activity/attacker type column rendering.
- Repository branch and commit/PR: `edit-dashboard` working tree; commit/PR pending.
- Repository changes:
  - In `dashboard-v2/src/lib/threat-intel-session-directory.ts`: allow `attackerTypeQueryValue` to apply to the unified `all` tab; classify HTTP session rows with `attackerType: "Unknown"`; update `buildSessionDirectoryRows` to accept `attackerType` filter and filter rows accordingly.
  - In `dashboard-v2/src/app/(main)/threat-intel/page.tsx`: show the Attacker Type dropdown on both `All` and `SSH` protocol tabs; enable CSV export on both `All` and `SSH` views; update pagination text to show total sessions with HTTP interaction counts ("Page X of Y (N sessions) · includes M HTTP interactions") and change label to "Rows per page"; update column 5 to display `AttackerTypeBadge` alongside HTTP activity for a cohesive layout in desktop and mobile cards.
  - In `dashboard-v2/tests/threat-intel-session-directory.test.ts`: add unit tests verifying `attackerTypeQueryValue` for `all` tab and attacker type filtering for both SSH and HTTP sessions.
- Host/environment changes actually applied: none. Only local tests, type checks, and linting were run.
- Runtime/exposure state: existing deployed host remains unchanged.
- Validation performed and outcome: `npx vitest run tests/threat-intel-session-directory.test.ts` passed (6 passed); `npx tsc --noEmit` passed with 0 errors; `npm run lint` passed with 0 warnings/errors.
- Not performed / deferred: deployment to production host.
- Risks and data handling: no secrets or sensitive data involved.
- Rollback: discard working directory changes with `git restore`.
- Follow-up: none.
- Related ADR/runbook: N/A.

### 2026-09-28 — Default Threat Intel attacker type to Unknown and populate session dwell time

- Status: repository Dashboard change prepared; not applied to a host or activated.
- Scope and intent: default unclassified/missing attacker types to "Unknown" rather than "ScriptKiddie" on the Threat Intelligence Console and directory API, and extract dwell time from canonical session payload data and timestamps.
- Repository branch and commit/PR: `edit-dashboard` working tree; commit/PR pending.
- Repository changes: in `dashboard-v2/src/lib/threat-server.ts`, default `injectAttackerType` and `normalizeThreat` classification to `Unknown` instead of `ScriptKiddie` when no decision exists in `honeypot_db.deception_decisions`; allow `Unknown` in directory attacker filter and invert filter criteria to exclude known actors; extract `end_time` and `duration` from canonical `payload_json` or compute duration in seconds from terminal timestamps. In `dashboard-v2/src/lib/threat-intel-session-directory.ts`, add `Unknown` to `SESSION_ATTACKER_TYPE_OPTIONS`, default `normalizeAttackerType` to `Unknown`, and support numeric duration strings in `sshDwellTime`. In `threat-intel/page.tsx`, update `AttackerTypeBadge` fallback to `Unknown`. Update unit test suites and add regression tests.
- Host/environment changes actually applied: none. Only local tests and build checks were run.
- Runtime/exposure state: existing Pi and production Dashboard services remain unchanged.
- Validation performed and outcome: `npx vitest run tests/threat-intel-session-directory.test.ts tests/dashboard-phase0-threat-semantics.test.ts tests/dashboardTypes.test.ts` passed (23 passed, 1 expected fail); `npx tsc --noEmit` and `npm run lint` passed with 0 errors.
- Not performed / deferred: production deployment, live MongoDB Atlas query against live honeypot traffic.
- Risks and data handling: displaying "Unknown" ensures unassessed sessions are not falsely labeled as ScriptKiddie. No secrets or attacker payloads are recorded.
- Rollback: revert the working tree changes.
- Follow-up: push to origin branch and verify in staging environment.
- Related ADR/runbook: unified Threat Intelligence session directory implementation.

### 2026-09-28 — Activate public Web-corp HTTPS through the Droplet

- Status: active on the existing Droplet and Pi; repository source and runbooks updated.
- Scope and intent: expose the fake ERP login with trusted public-IP HTTPS while keeping the Pi HTTP backend private, retaining the existing ZeroTier test listener and Cowrie TCP 22 forward, and limiting Zeek to decoy traffic.
- Repository branch and commit/PR: `main` working tree; commit pending at entry time.
- Repository changes: add the opt-in WireGuard Web-corp Compose override, Nginx/Certbot edge templates and units, Zeek `wg0` worker and endpoint filter, collector WireGuard destination mapping and test, ADR-0014, validation evidence, and current-state/runbook updates.
- Host/environment changes actually applied: on the Pi, added a host-local Compose override and separate WireGuard Web-corp container using the existing built image, deployed the reviewed Zeek config/helper and collector ARM64 binary, and added private collector interface settings. Protected backups of previous Zeek, collector, and override files remain on the host. The original ZeroTier container and dirty local Web-corp source were not overwritten. On the Droplet, installed Nginx and current Certbot, opened host-firewall TCP 80/443 while retaining existing SSH/WireGuard rules, issued staging and production IP certificates, installed the HTTPS proxy, and enabled renewal and expiry-check timers. Root-only pre-edge firewall and Nginx backups remain on the host.
- Runtime/exposure state: public TCP 22 still forwards to Cowrie; public TCP 23 remains closed. Public TCP 80 serves ACME HTTP-01 and redirects to HTTPS; TCP 443 serves Web-corp through WireGuard to the Pi. The Pi's direct HTTPS container remains stopped. Zeek's local cluster has `wlan0`, ZeroTier, and `wg0` workers; collector and processor are active.
- Validation performed and outcome: external trusted HTTPS GET returned 200 and HTTP redirected 308; ACME staging/production issuance and `certbot renew --dry-run` passed. A synthetic rejected login persisted with external source and HTTPS/443 metadata. The first login showed a proxy trust mismatch; after correcting the trust peer, a second test passed. Forged forwarding headers on the direct ZeroTier container were ignored. Bounded `wg0` packet capture and Zeek conn/http logs matched the public GET, and MongoDB contained four recent Zeek `wg0` conn/http records. Go tests and synthetic BPF tests passed. The expiry-check service returned success.
- Not performed / deferred: an actual certificate renewal, external expiry notification, authenticated browser review, sustained public traffic/packet-loss measurement, long-term storage growth, Pi repo checkout sync, and clean-host install acceptance.
- Risks and data handling: the certificate is short lived; local timer failure is not an off-host alert. Public exposure may increase credential-sensitive login records. No certificate private key, secret, raw login value, protected backup content, or host-private interface address was committed.
- Rollback: close public TCP 80/443 or disable the Nginx site first; restore protected Droplet firewall/Nginx backups if needed. Stop only the Pi WireGuard Web-corp container and restore protected Zeek/collector copies if reverting telemetry. Preserve the original ZeroTier listener, Cowrie forward, and collected records.
- Follow-up: connect expiry failure to an off-host alert receiver, observe a real renewal and proxy reload, and measure Zeek/storage volume after representative traffic.
- Related ADR/runbook: [ADR-0014](adr/ADR-0014-public-web-corp-ip-https-edge.md), [public edge runbook](../integrations/web-corp/PUBLIC-VPS-HTTPS.md), [edge assets](../deploy/public-web-edge/README.md), and [validation evidence](validation/2026-09-28-public-web-corp-edge.md).

### 2026-09-28 — Restrict Pi Zeek packets to active decoy endpoints

- Status: active on the existing Pi; repository source and operations documentation updated.
- Scope and intent: exclude development and management traffic from Zeek capture while keeping current Cowrie and Web-corp decoy observations.
- Repository branch and commit/PR: `main` working tree; commit/PR pending.
- Repository changes: add a host-address-aware BPF policy renderer and Zeek systemd start/reload drop-in, ADR-0013, validation evidence, and current-state/runbook updates. The tracked node list remains `wlan0` plus ZeroTier.
- Host/environment changes actually applied: on `pi-t`, backed up the prior Zeek site policy in a root-only host location, installed the renderer and systemd drop-in, replaced the broad local filter with a generated-policy load, checked Zeek, restarted it, and tested a subsequent reload. No firewall, VPN, Cowrie, Web-corp, collector, or processor configuration was changed.
- Runtime/exposure state: Zeek's five local cluster nodes are running. Its filter accepts bidirectional Cowrie TCP 22/23 to the Pi on `wlan0` and ZeroTier and Web-corp TCP 80 to the Pi on ZeroTier. Tailscale is not captured. Cowrie, ZeroTier, collector, and processor remain active.
- Validation performed and outcome: verified live listeners for Cowrie 22/23 and Web-corp 80, with FTP 21 and direct HTTPS 443 absent; the generated BPF compiled with `tcpdump -d`, and a synthetic eight-packet pcap admitted three decoy packets while excluding five development/management cases. `zeekctl check`, systemd restart, systemd reload, and node status passed. Bounded no-payload connections from a ZeroTier peer to 22/23/80 produced only those three destination ports in the new `conn.log`; an equivalent connection to admin 2222 did not appear. All four TCP connects succeeded. Zeek, collector, and processor stayed active. See the linked evidence note.
- Not performed / deferred: a live `wlan0` decoy-flow test, sustained packet-loss/CPU measurements, post-change MongoDB volume comparison, and a real interface-address-renewal test. This Zeek version did not emit a usable `packet_filter.log` entry during the bounded check.
- Risks and data handling: a changed interface address while Zeek is running requires a service restart or reload. A newly enabled decoy port requires a reviewed filter update. The generated policy and protected backup remain on the Pi; no private interface address, secret, or raw event was copied into Git.
- Rollback: restore the protected prior `local.zeek` from `/var/backups/honeypot/zeek/`, remove the decoy filter drop-in and generated policy, reload systemd, then restart Zeek and verify node/collector health.
- Follow-up: compare Zeek event volume and resource use after a representative interval and update the filter when a stopped decoy becomes active.
- Related ADR/runbook: [ADR-0013](adr/ADR-0013-zeek-decoy-endpoint-filter.md), [existing-Pi Zeek runbook](../zeek/README.md), and [validation evidence](validation/2026-09-28-zeek-decoy-endpoint-filter.md).

### 2026-09-28 — Limit existing Pi Zeek capture to wlan0 and ZeroTier

- Status: active on existing Pi; Dashboard label correction prepared in repository only.
- Scope and intent: keep primary-uplink and local-test ZeroTier observation, remove only the Tailscale capture worker, and correct the Dashboard's description of `wlan0`.
- Repository branch and commit/PR: `main` working tree; commit/PR pending.
- Repository changes: remove `worker-tailscale0` from tracked `zeek/node.cfg`, update the `wlan0` hardware-card caption, add ADR-0012 and the existing-Pi Zeek runbook, and update current-state docs.
- Host/environment changes actually applied: on `pi-t`, saved the prior node configuration in a root-only protected host backup, stopped Zeek with its old node list, installed the two-worker configuration, checked it, and started Zeek. A first attempt to switch to standalone mode failed `zeekctl check` with a telemetry-port error on the Pi's Zeek version; the original cluster configuration was restored and all original workers restarted before the reviewed two-worker cutover. No VPN, Cowrie, collector, processor, or Dashboard host configuration was changed.
- Runtime/exposure state: Zeek's logger, manager, proxy, `worker-wlan0`, and `worker-zerotier0` are running; no Tailscale Zeek worker remains. Tailscale and ZeroTier connectivity and Cowrie continue unchanged. Collector and processor services are active. The Dashboard source label is not deployed by this change.
- Validation performed and outcome: `zeekctl check` passed for all five configured nodes; `zeekctl status` and process arguments showed the two intended worker interfaces and no stale Tailscale worker. `logs/current` still resolves to the logger spool, `conn.log` had a fresh modification time, collector and processor were active, and the collector journal had no warning since cutover. Targeted ESLint and TypeScript typecheck passed for the Dashboard source.
- Not performed / deferred: live packet-level attribution, post-cutover MongoDB volume comparison, and production Dashboard deployment.
- Risks and data handling: ZeroTier produced most measured overlay Zeek documents, so retaining it preserves most prior event volume. The protected host backup and any packet/event contents were not copied into Git.
- Rollback: restore the protected Pi node configuration from `/var/backups/honeypot/zeek/`, then restart `zeek.service` and verify status. Restore the prior UI source in Git if needed.
- Follow-up: measure retained Zeek volume after a representative interval and review ZeroTier capture only if its observation value or cost changes.
- Related ADR/runbook: [ADR-0012](adr/ADR-0012-zeek-primary-uplink-capture.md) and [existing-Pi Zeek runbook](../zeek/README.md).

### 2026-09-28 — Track Zeek process health through systemd PID

- Status: unit refinement tested on disposable Azure ARM64 VM; service inactive afterward.
- Scope and intent: make the staged Zeek service state reflect its running process rather than a completed ZeekControl command.
- Repository branch and commit/PR: `main` working tree; commit/PR pending.
- Repository changes: change the staged `zeek.service` to `Type=forking` with Zeek's PID file, pre-start configuration check, and failure restart policy; update the staging runbook and VM evidence.
- Host/environment changes actually applied: reapplied only the Zeek staging playbook on the Azure VM, which updated its disabled unit; started and stopped the unit for a bounded check. No production host changed.
- Runtime/exposure state: final VM `zeek.service` inactive/disabled; no Zeek listener. During the bounded check, Broker listened only on loopback.
- Validation performed and outcome: systemd reported `active`, a nonzero Zeek main PID, and a loopback-only Broker listener while running; after stop it reported `inactive` and main PID 0.
- Not performed / deferred: a forced Zeek crash/restart test and ongoing telemetry health monitoring; Cowrie/Go activation remains deferred.
- Risks and data handling: no credentials or attacker data were used. This service unit has not been qualified on a production capture interface.
- Rollback: restore the prior staged unit or discard the disposable VM; no active production service changed.
- Follow-up: include process-state and restart tests in the full sensor acceptance run.
- Related ADR/runbook: [Ansible staging runbook](../deploy/ansible/README.md) and [VM evidence](validation/2026-09-28-azure-arm64-cowrie-zeek-staging.md).

### 2026-09-28 — Stage pinned Zeek and patched Cowrie source on ARM64 VM

- Status: dependency staging tested on disposable Azure ARM64 VM; Cowrie and Zeek inactive; full installation not complete.
- Scope and intent: make Zeek and the project's Cowrie CWD patch reproducible on a clean sensor without exposing a honeypot listener or changing the production Pi.
- Repository branch and commit/PR: `main` working tree; commit/PR pending.
- Repository changes: add `prepare-zeek.yml` with a pinned official package source, loopback Broker binding, disabled metrics, and an inactive unit; regenerate the previously malformed Cowrie CWD patch against its stated upstream commit; add a deterministic Cowrie archive builder and `prepare-cowrie.yml` for source/venv staging; extend CI syntax checks, runbooks, roadmap, and validation evidence.
- Host/environment changes actually applied: on the disposable VM, install Zeek/ZeekControl `1:8.0.10-0`, stage the standalone loopback-capture configuration and systemd unit, and stage patched Cowrie source plus Python venv and a non-login `cowrie` account. The first Cowrie playbook execution stopped during venv preparation; the staged archive and patched files were hash verified, a `preparing` marker was recorded, and the corrected playbook completed. No production host was changed.
- Runtime/exposure state: final VM state has `zeek.service` inactive/disabled, no `cowrie.service`, and no Cowrie, Broker, or metrics listener. The initial manual ZeekControl smoke start briefly exposed Broker and metrics listeners on all interfaces; Zeek was stopped, configured for loopback Broker and no metrics, then restarted for a bounded smoke and stopped again. Management SSH remained available.
- Validation performed and outcome: ZeekControl `check`, systemd start/stop and `ss -lntp` checks passed after binding correction; Zeek playbook repeat reported `changed=0`. The regenerated patch passed `git apply --check` on the exact Cowrie commit; patched Python files compiled; two source archive builds had identical SHA-256. Cowrie staging completed with `pip check` and patched-file SHA-256 checks; the final repeat reported `changed=0`. Local Ansible syntax checks passed.
- Not performed / deferred: fresh-host sanitized Cowrie output integration, Cowrie service/listener, full Python transitive hash lock, collector/processor telemetry, real capture interface, Docker decoys, Go activation, production Pi deployment, Dashboard deployment, and full end-to-end testing.
- Risks and data handling: Cowrie's staged source must not be started before sanitized output and private log controls are installed. The source archive and VM contained no operator credentials. The first Zeek smoke exposure was bounded but was an error; final configuration binds the control socket to loopback. No raw attacker data, private keys, env contents, or tokens were copied into the repository.
- Rollback: stop `zeek.service` if started, then delete the disposable VM and associated test resources after evidence retention. Neither playbook is an existing-Pi migration path.
- Follow-up: build a fresh-install Cowrie sanitized-output/service path, lock Python dependency closure, qualify a reviewed capture interface, then integrate prerequisites into the one-command installer and test Go activation on a fresh VM.
- Related ADR/runbook: [Ansible staging runbook](../deploy/ansible/README.md), [Cowrie CWD integration](../integrations/cowrie/README.md), and [VM evidence](validation/2026-09-28-azure-arm64-cowrie-zeek-staging.md).

### 2026-09-28 — Align current installer roadmap with partial VM acceptance

- Status: documentation current-state correction; no deployment.
- Scope and intent: remove a stale roadmap claim that the first Go-agent slice had not been tested on a VM.
- Repository branch and commit/PR: `main` working tree; commit/PR pending.
- Repository changes: update the roadmap and Thai installation draft to distinguish the passed prepare/blank-env retry from untested activation and full-stack installation.
- Host/environment changes actually applied: none.
- Runtime/exposure state: Azure VM remains prepared with inactive Go/Redis units; production Pi and Dashboard unchanged.
- Validation performed and outcome: cross-checked the dated VM evidence and current Ansible runbook; no runtime test was required for this documentation correction.
- Not performed / deferred: Cowrie, Zeek, decoy, Dashboard, activation, and production-Pi qualification.
- Risks and data handling: no private configuration or endpoint was added to documentation.
- Rollback: revert this documentation correction if contradicted by later evidence.
- Follow-up: maintain current-state documents as the next installer phases are accepted.
- Related ADR/runbook: [VM evidence](validation/2026-09-28-azure-arm64-installer-first-run.md) and [Ansible preparation runbook](../deploy/ansible/README.md).

### 2026-09-28 — ARM64 startup check for strict backup window parsing

- Status: nonproduction VM check passed; installed release unchanged.
- Scope and intent: confirm the updated hardware-backup binary rejects explicit invalid backup-window values on ARM64 before external connections.
- Repository branch and commit/PR: `main` working tree; commit/PR pending.
- Repository changes: include a boundary test for maximum integer safety days and compare lookback directly to safety to avoid addition overflow. No service configuration was changed.
- Host/environment changes actually applied: copied a standalone, locally cross-built ARM64 test binary into the Azure VM's `/tmp` and executed it twice with invalid non-secret values. Did not replace the installed release or touch private env files.
- Runtime/exposure state: installed Redis and hardware-backup-control units remained inactive; no MongoDB or B2 connection was attempted by the test binary.
- Validation performed and outcome: `go test ./...` for hardware-backup and `git diff --check` passed after the boundary fix. On the VM, `BACKUP_LOOKBACK_DAYS=abc` and `BACKUP_SAFETY_DAYS=-1` each produced an error naming the key and exited with status 1.
- Not performed / deferred: reviewed release build, installer upgrade, successful activation, full backup execution, and production Pi rollout.
- Risks and data handling: only synthetic invalid values were used. The test binary remains temporary and is not an installed service.
- Rollback: no running service or installed release changed; discard the temporary test binary with the disposable VM.
- Follow-up: include this code in a new reviewed release after the remaining installer dependencies are qualified.
- Related ADR/runbook: [hardware-backup runbook](../agents/hardware-backup/README.md).

### 2026-09-28 — Reject explicitly invalid backup window settings

- Status: repository change prepared; not deployed to the Azure VM or production Pi.
- Scope and intent: keep the existing 30-day lookback and 2-day safety defaults when the variables are absent, but make explicit operator input fail visibly when invalid.
- Repository branch and commit/PR: `main` working tree; commit/PR pending.
- Repository changes: parse `BACKUP_LOOKBACK_DAYS` and `BACKUP_SAFETY_DAYS` with presence-aware validation; reject empty, malformed, negative/out-of-range, or zero lookback values with the variable name. Keep the existing lookback-greater-than-safety check. Add focused config tests and update the hardware-backup runbook.
- Host/environment changes actually applied: none for this change. The already prepared Azure VM still has the earlier ARM64 binary; the production Pi was not changed.
- Runtime/exposure state: unchanged. This validation takes effect only after a new reviewed hardware-backup release is built and installed.
- Validation performed and outcome: focused Go tests and formatting checks pending at the time of this record; final result to be recorded in an addendum if different.
- Not performed / deferred: rebuilding and deploying the worker, VM activation, production rollout, and end-to-end backup execution.
- Risks and data handling: an explicitly present but invalid value now prevents worker startup instead of falling back silently; omitted values remain backward compatible. No credential values were read or stored.
- Rollback: revert this parser change and release a reviewed prior binary; no host rollback was needed.
- Follow-up: include the parser in the next reviewed ARM64 release and verify the startup error path on a nonproduction VM before Pi rollout.
- Related ADR/runbook: [hardware-backup runbook](../agents/hardware-backup/README.md).

### 2026-09-28 — Validation addendum for backup window parser

- Status: local validation passed; host deployment still deferred.
- Scope and intent: complete the pending validation recorded in the preceding entry.
- Repository branch and commit/PR: `main` working tree; commit/PR pending.
- Repository changes: none beyond the preceding parser, tests, and runbook change.
- Host/environment changes actually applied: none.
- Runtime/exposure state: unchanged; the Azure VM and production Pi still run earlier binaries.
- Validation performed and outcome: `gofmt` completed, `go test ./...` passed in `agents/hardware-backup`, and `git diff --check` passed.
- Not performed / deferred: VM startup check with the rebuilt binary, Cowrie/Zeek prerequisites, and production deployment.
- Risks and data handling: test credentials were synthetic literals in local unit tests; no private host env was read.
- Rollback: no host rollback required.
- Follow-up: build and review a new release before testing this behavior on the VM.
- Related ADR/runbook: [hardware-backup runbook](../agents/hardware-backup/README.md).

### 2026-09-28 — Exercise resumable Pi installer on a fresh Azure ARM64 VM

- Status: first prepare and blank-configuration gate passed on a disposable VM; full sensor installation remains partial.
- Scope and intent: test the new one-command path against a real Ubuntu 24.04 ARM64 guest before adding Cowrie, Zeek, and decoy installation.
- Repository branch and commit/PR: `main` working tree; commit/PR pending.
- Repository changes: record the VM acceptance result in the validation note, VM target, and Ansible runbook. Installer behavior was not changed by this entry.
- Host/environment changes actually applied: on the Azure test VM, refreshed the Ubuntu apt index, installed the four reviewed package versions and their dependencies, copied the approved five-binary ARM64 release, installed five inactive systemd units, created the dedicated agent account and directories, and staged five `.env.example` files plus five blank actual `.env` files. A read-only Redis checker was also copied under the VM's `/tmp` for an independent check. The developer workstation and existing production Pi were not changed by the playbook.
- Runtime/exposure state: Redis and all five Go units remained inactive and disabled. The VM remained reachable by administrator SSH; no project listener, Cowrie, Zeek, decoy, or Dashboard service was started.
- Validation performed and outcome: verified Ubuntu 24.04/aarch64, 2 vCPU, approximately 4 GiB RAM and a 30 GiB root filesystem; approved manifest and installed binary/package audit passed. First wrapper run paused at missing env values as expected. The second run reused the prepared release, staging reported `changed=0`, all five private-file SHA-256 hashes and root-owned `0600` modes stayed the same, and activation again stopped before starting units. Independent Redis loopback/protected-mode config check and `systemd-analyze verify` for all five units passed without starting them. Local Ansible needed execution outside the tool sandbox because its local RPC server could not start there; SSH bypassed an unrelated unsafe local SSH config include with `-F /dev/null`.
- Not performed / deferred: clean snapshot was not verified; symlink/interrupted-run/rollback cases, completed operator configuration, Cowrie/Zeek dependency installation, Go activation, telemetry, backup restore, and existing-Pi migration remain untested.
- Risks and data handling: no real credential values were placed on the VM or in the repository. The Azure VM has a public SSH management address, unlike the isolated generic VM target; the address and private key are omitted from repository records. The observed root disk is 30 GiB, below the target document's 32 GiB sizing suggestion; this pass exercised only the Go preparation slice.
- Rollback: delete the disposable Azure test VM and its associated disk/network resources after evidence is retained, or restore a verified clean snapshot if one is created. No production rollback is involved.
- Follow-up: qualify the remaining failure and activation cases on this VM or a fresh snapshot, then implement and test Cowrie, Zeek, decoy, and Dashboard installers separately.
- Related ADR/runbook: [Ansible preparation runbook](../deploy/ansible/README.md), [VM target](INSTALLER-VM-TEST-TARGET.md), and [validation evidence](validation/2026-09-28-azure-arm64-installer-first-run.md).

### 2026-09-28 — Create missing private Pi env skeletons during staging

- Status: repository change prepared; not applied to a Pi or VM.
- Scope and intent: let the single Pi installer place both examples and editable actual env files so the operator only has to fill values and rerun.
- Repository branch and commit/PR: `main` working tree; commit/PR pending.
- Repository changes: extend the staging playbook to inspect each actual env path and create the five files from non-secret examples only when absent, with `root:root` ownership and mode `0600`. Reject symlinks and non-regular existing paths; skip existing regular files without reading or replacing content. Update wrapper output, examples, runbook, Thai manual, and ADR-0011; link ADR-0009's amended file-creation clause.
- Host/environment changes actually applied: none. No Pi/VM sudo, file creation, or service activation was performed.
- Runtime/exposure state: existing Pi and Dashboard runtime unchanged. Blank files alone do not pass the value gate, so Go services stay inactive until operator completion and dependency validation.
- Validation performed and outcome: Ansible syntax, installer unit tests, Python compilation, and `git diff --check` passed locally; first-run and retry behavior on a VM remain untested.
- Not performed / deferred: clean ARM64 VM creation, owner/mode and no-clobber acceptance, operator value entry, activation, and existing-Pi migration.
- Risks and data handling: staged actual files contain only blank credential fields and non-secret defaults. The installer never copies live credentials into the repository or logs. Existing operator files are not read or overwritten by staging.
- Rollback: on a disposable VM, restore the snapshot. On any host, remove only untouched blank skeletons after confirming they have no operator values; completed private files remain operator-owned.
- Follow-up: test missing-file creation, blank-value pause, filled-file retry, existing-file preservation, and symlink rejection on the disposable ARM64 VM.
- Related ADR/runbook: [ADR-0011](adr/ADR-0011-installer-private-env-skeletons.md), [ADR-0009](adr/ADR-0009-installer-operator-managed-credentials.md), and [Ansible preparation runbook](../deploy/ansible/README.md).

### 2026-09-28 — Stage blank Pi env examples beside private target paths

- Status: repository change prepared; not run on a Pi or VM.
- Scope and intent: make the single Pi command place its own non-secret examples on the target so the operator can copy, fill, and retry without locating templates in the controller checkout.
- Repository branch and commit/PR: `main` working tree; commit/PR pending.
- Repository changes: add `stage-pi-env-examples.yml` after release audit and before activation; it verifies the approved preparation marker, checks target path safety, and copies five blank examples to `/etc/honeypot-agent.env.example` and `/etc/honeypot/*.env.example` as root-owned mode `0600` without overwriting existing examples. Run all four playbooks in one Ansible invocation so interactive sudo authentication is requested once; provide an explicit passwordless-sudo option. Update the wrapper message, CI syntax check, and operator runbook.
- Host/environment changes actually applied: none for this change. No target playbook or sudo operation was executed.
- Runtime/exposure state: existing Pi and Dashboard runtime unchanged. The actual `.env` paths are not written by this step and the prepared units remain inactive until the separate activation gate passes.
- Validation performed and outcome: Ansible syntax check, installer unit suite, Python compilation, and `git diff --check` passed locally; no live-host staging test was performed.
- Not performed / deferred: VM execution, example-to-private copy/edit, credential and dependency validation, activation, and existing-Pi migration.
- Risks and data handling: blank examples have no private values and are restricted to root. Existing private files are untouched. A user could mistakenly edit an example with real credentials; the runbook directs editing only a private copy.
- Rollback: remove only the staged `.example` files after confirming they contain no operator edits; no host rollback was required during this repository change.
- Follow-up: verify first-run staging, missing-env pause, and unchanged-file retry on a clean ARM64 VM.
- Related ADR/runbook: [ADR-0009](adr/ADR-0009-installer-operator-managed-credentials.md) and [Ansible preparation runbook](../deploy/ansible/README.md).

### 2026-09-28 — Add resumable Pi Go-slice installation entry point

- Status: repository implementation prepared; not run on a Pi or VM.
- Scope and intent: provide one command that builds a missing reviewed Go release, prepares the Pi once, waits for operator env files and prerequisites, and activates only the five Go units and local Redis when gates pass.
- Repository branch and commit/PR: `main` working tree; commit/PR pending.
- Repository changes: add `install_pi_sensor.py`, a Redis loopback config checker, and `activate-pi-go.yml`; make `prepare-pi.yml` exit without mutation for a matching completed marker; allow the read-only audit to inspect an active prepared release; update CI and the Ansible runbook. A first local build pauses for approval of its manifest digest, and retries use the same release ID and digest.
- Host/environment changes actually applied: none for this change. No Pi or VM playbook was executed.
- Runtime/exposure state: existing Pi and Dashboard runtime unchanged. The new activation playbook is not active anywhere.
- Validation performed and outcome: Python compilation, 33 installer unit tests, all three Ansible playbook syntax checks, and `git diff --check` passed locally; no live-host behavior was tested.
- Not performed / deferred: clean ARM64 VM prepare, missing-env retry, Cowrie/Zeek install, Redis binding acceptance, credential/connectivity validation, activation, and existing-Pi migration.
- Risks and data handling: the wrapper accepts one inventory host and reviewed non-secret vars only. It never uploads private env values. Activation validates local file shape and service state but cannot establish Mongo/B2 credential validity, telemetry delivery, or backup restore readiness. Failure after a unit starts triggers rollback of units that were inactive before that attempt.
- Rollback: remove the entry point and activation files. For a VM attempt, restore its snapshot; production rollback remains unqualified.
- Follow-up: run the full pause/upload/rerun path on a disposable ARM64 VM, then add accepted Cowrie/Zeek/decoy installation and deeper connectivity checks before production use.
- Related ADR/runbook: [ADR-0009](adr/ADR-0009-installer-operator-managed-credentials.md) and [Ansible preparation runbook](../deploy/ansible/README.md).

### 2026-09-28 — Prepare operator-uploaded Pi environment examples and checks

- Status: repository change prepared; not uploaded to or activated on a Pi or VM.
- Scope and intent: let the operator fill separate private env files for the five prepared Go services, then check their paths and required names before activation.
- Repository branch and commit/PR: `main` working tree; commit/PR pending.
- Repository changes: add blank env examples for the shared agent, processor, TI worker, hardware agent, and backup worker; add a read-only checker for regular files, root ownership, mode `0600`, syntax, duplicate names, and per-service required nonempty keys; document private upload and checking in the Ansible runbook; include the checker in installer CI. No credential values or existing Pi env files were copied.
- Host/environment changes actually applied: none for this change. No Pi or VM file was uploaded or modified.
- Runtime/exposure state: existing Pi and Dashboard services unchanged; the prepared playbook still leaves new units stopped and disabled.
- Validation performed and outcome: the full installer unit suite passed (28 tests, including three focused checker tests); Python compilation, checker CLI help, and `git diff --check` passed locally. No live host file was inspected.
- Not performed / deferred: operator upload, live Pi permission check, credential/connectivity validation, Cowrie/Zeek/decoy installation, VM activation, and existing-Pi migration.
- Risks and data handling: templates contain blank credential fields and no private values. The checker reads private files but prints only key names and diagnostic categories; passing its checks does not establish service readiness.
- Rollback: remove the templates/checker and documentation changes; no host rollback is needed.
- Follow-up: test the upload and validation flow on the disposable ARM64 VM, then add dependency and connectivity gates plus explicit service activation.
- Related ADR/runbook: [ADR-0009](adr/ADR-0009-installer-operator-managed-credentials.md) and [Ansible preparation runbook](../deploy/ansible/README.md).

### 2026-09-28 — Add online build-host bootstrap for Go agent releases

- Status: repository change prepared; not applied to a Pi, VM, or Dashboard host.
- Scope and intent: let a developer or operator prepare a Linux build host from a fresh checkout and produce the existing five-agent ARM64 bundle with one script.
- Repository branch and commit/PR: `main` working tree; commit/PR pending.
- Repository changes: add `bootstrap_sensor_build.sh` with a read-only `--check`, conditional Ubuntu 24.04 apt installation through `sudo`, an official Go 1.26.3 download pinned by SHA-256 for Linux amd64/arm64, per-module download and verification, and handoff to the offline release builder. Update the build/runbook instructions and CI syntax/check invocation. The script does not install runtime services, Redis diagnostics, or Pi packages.
- Host/environment changes actually applied: on the development build host, the pinned Go archive was downloaded and extracted under `/tmp/pti-bootstrap-e2e-data`, public modules were fetched into the user's Go module cache, and a release was written under `/tmp/pti-bootstrap-e2e-releases`. No apt or sudo action occurred. Nothing was applied to the Pi, VM, or Dashboard host.
- Runtime/exposure state: existing Pi and Dashboard runtime unchanged; no new service or listener was enabled.
- Validation performed and outcome: shell syntax and read-only bootstrap check passed; 25 installer unit tests passed; the online bootstrap fetched and SHA-256-verified official Go 1.26.3, downloaded and verified all five modules, passed their Go tests, and built all five ARM64 binaries without build-time downloads. The independent release verifier accepted the generated bundle and its reviewed manifest SHA-256; `git diff --check` passed. This was a repeatable-path test on an existing development host, not a fresh-OS acceptance run.
- Not performed / deferred: online bootstrap execution on a fresh build host with missing base packages and sudo; clean ARM64 VM preparation, installation, and runtime activation.
- Risks and data handling: the toolchain and module downloads require trusted HTTPS access; the pinned Go archive hash and Go module sum verification detect changed artifacts. The bootstrap does not accept or write runtime credentials. Ubuntu apt package versions depend on the configured apt sources and are separate from the Pi's reviewed package pins.
- Rollback: remove the bootstrap script and docs/CI references. A user who ran it can remove its user-level Go toolchain and release directory; Ubuntu packages must be reviewed before removal.
- Follow-up: exercise the full online bootstrap from a clean Linux build host, then use the resulting approved release for the disposable ARM64 VM acceptance run.
- Related ADR/runbook: [Ansible preparation runbook](../deploy/ansible/README.md), [VM test target](INSTALLER-VM-TEST-TARGET.md), and [ADR-0009](adr/ADR-0009-installer-operator-managed-credentials.md).

### 2026-09-28 — Prepare read-only VM acceptance audit for first Pi installation slice

- Status: repository change prepared; not applied to a VM, Pi, or Dashboard host.
- Scope and intent: give the operator a repeatable post-prepare acceptance check while a clean Ubuntu 24.04 ARM64 VM is being arranged.
- Repository branch and commit/PR: `main` working tree; commit/PR pending.
- Repository changes: add `audit-prepared-pi.yml` to verify the release marker, approved manifest and five binary hashes, exact package versions, and stopped/disabled Redis and Go units without reading private env files. Include the audit and tracked decoy-source syntax checks in installer CI; update the Ansible and Thai VM runbooks.
- Host/environment changes actually applied: none. A temporary five-agent Linux ARM64 release was built under `/tmp` on the development machine; no service was installed or started.
- Runtime/exposure state: existing Pi and Dashboard runtime unchanged. The VM is not yet available.
- Validation performed and outcome: all five Go module tests and ARM64 builds passed; release manifest and binary hashes verified. Twenty-five installer tests, both Ansible playbook syntax checks, Compose config validation, and CI YAML parsing passed locally. A read-only localhost audit execution was attempted but the sandbox's Ansible local RPC server could not start; no target task ran. The Core and Web-corp images built on the x86-64 development host, and each imported inside an isolated container without network or published ports.
- Not performed / deferred: execution of prepare/audit on a clean ARM64 VM, ARM64 container image build, Cowrie/Zeek/decoy installation, private-input validation, and activation.
- Risks and data handling: syntax and local build success do not establish host behavior. The temporary bundle has no runtime configuration; approved release identity must be recorded separately before use. No private values or attacker records entered the test artifact.
- Rollback: revert repository changes; no host rollback is needed. Restore the clean VM snapshot for future apply/retry tests.
- Follow-up: when the VM is ready, run baseline inventory, snapshot, prepare, audit, same-release retry, and audit again; then resolve any observed package, unit, or permission differences before extending the installer.
- Related ADR/runbook: [Ansible preparation runbook](../deploy/ansible/README.md), [VM test target](INSTALLER-VM-TEST-TARGET.md), and [ADR-0009](adr/ADR-0009-installer-operator-managed-credentials.md).

### 2026-09-28 — Track active decoy Compose and Deception Core build source

- Status: repository source prepared; not installed or activated on a host.
- Scope and intent: make the active PostgreSQL, Deception Core, and Web-corp HTTP stack reviewable from one repository checkout for the fresh-Pi installer.
- Repository branch and commit/PR: `main` working tree; commit/PR pending.
- Repository changes: add `deploy/decoy-honeypot/compose.yaml` with repository-local build contexts and a stable project name; import only the active Deception Core Docker build inputs and synthetic schemas; remove its hard-coded PostgreSQL password fallback, replace a copied overlay address in source/schema examples with a documentation address, and correct Dockerfile multi-source `COPY` destinations; add ADR-0010 and update current-state and service runbooks. Odoo, FTP, SMTP, direct Pi HTTPS, private env files, runtime volumes, backups, and event logs were not imported.
- Host/environment changes actually applied: none. The Pi's external Compose file, running containers, volumes, and private configuration were not changed.
- Runtime/exposure state: unchanged; the tracked Compose source is not the active Pi deployment.
- Validation performed and outcome: `docker compose config` with a disposable validation-only password passed; the project name, three service names, and default loopback bindings were checked, and omitting the operator password failed as required. Python compilation/syntax checks, JSON parsing, changed-document links, and `git diff --check` passed. After correcting the Dockerfile, both Core and Web-corp images built on the x86-64 development host and imported in isolated, network-disabled containers; Core was given temporary `/data` storage for its startup import. The imported file list and credential fallback were reviewed; no private config file or runtime data was copied.
- Not performed / deferred: ARM64 Docker image build, clean ARM64 VM acceptance, image digest pinning, existing-Pi migration, operator-input validation, and activation.
- Risks and data handling: the imported Core code and synthetic schemas still need build and behavior acceptance. The PostgreSQL image uses a major-version tag, so a pinned release digest is required before production installation. `POSTGRES_PASSWORD` remains operator-managed outside Git.
- Rollback: remove this repository change; no host rollback is needed because no host was modified.
- Follow-up: build and test the Core image on a disposable ARM64 VM, validate host paths and private inputs, then plan a separate Pi cutover.
- Related ADR/runbook: [ADR-0010](adr/ADR-0010-track-active-decoy-compose.md), [decoy Compose runbook](../deploy/decoy-honeypot/README.md), and [ADR-0009](adr/ADR-0009-installer-operator-managed-credentials.md).
### 2026-09-28 — Show SSH attacker category in the unified session directory

- Status: repository Dashboard change prepared; staging deployment pending verification after push.
- Scope and intent: replace generic SSH command-activity text in the unified session directory with the attacker category already returned by the Dashboard API, while preserving HTTP request activity.
- Repository branch and commit/PR: `staging-release`; Dashboard change commit `f1395dbd`, followed by merge of current `origin/main` at `f824ff575`.
- Repository changes: project the existing SSH `classification` value into the directory row and render APT, Bot, Script Kiddie, or Unclassified as a compact tag on desktop and mobile. Unknown values fail closed to Unclassified. HTTP activity remains unchanged. Update the focused directory test and an outdated advisory-copy assertion; no API, schema, backend, or classification behavior changes.
- Host/environment changes actually applied: none.
- Runtime/exposure state: not deployed at the time of this entry. The category remains an existing classification/projection and must not be interpreted as verified actor attribution.
- Validation performed and outcome: focused Threat Intel/advisory tests passed (27/27); TypeScript, targeted ESLint, and `git diff --check` passed. `npx next build --webpack` passed; default Turbopack build could not bind a port in the sandbox. Full Vitest suite: 827 passed, 5 failed in Filesystem/command-route test files, 2 expected failures, and 14 skipped. Backend targeted suites passed (116 passed, 2 skipped); a separate AI-presentation suite could not be collected because its import does not match the checked-out dirty source tree. One authorized public Cowrie session reached the verified HAProxy-to-Cowrie route. Analysis completed for that session; Model2 identity binding was complete, but T1105 transfer and T1110 repeated-auth gates correctly rejected raw PRESENT outputs, and T1046 was unavailable. No policy-supported canonical threat hypothesis was produced because the attempted fetch did not complete. Response guidance was manual-only. AI advisory returned accepted/valid on one on-demand provider call. The PDF endpoint returned HTTP 200 and a valid PDF. ETI reported `NO_STORED_PROVIDER_RESULT` for its eligible observable although enrichment jobs had completed. The session source was marked public by the system.
- Not performed / deferred: staging deployment and authenticated browser inspection remain pending. The benign fetch did not complete and no transfer observation was produced. No direct/manual MongoDB writes, service changes, or config changes were made; the test session itself was stored through the normal application pipeline.
- Risks and data handling: display reuses the current API field and does not claim verified actor identity. The single test session followed the normal pipeline; its on-demand AI advisory called the configured provider. No credentials, raw commands, payloads, or source IP were added to the UI or this log.
- Rollback: revert the Dashboard UI commit; no backend or data rollback is required.
- Follow-up: push through the existing staging CI/CD route if checks pass, then verify the deployed page and API.
- Related ADR/runbook: unified Threat Intelligence session directory implementation.

### 2026-09-28 — Harden offline Pi preparation before VM acceptance

- Status: repository change prepared; not applied to a VM, Pi, or Dashboard host.
- Scope and intent: make the first Ansible preparation slice resumable, pin its package and release inputs, and verify transferred binaries before units are installed.
- Repository branch and commit/PR: `fix/installer-prepare-hardening`; commit/PR follow this entry.
- Repository changes: require an approved manifest SHA-256 and exact top-level package versions; reject unexpected release content and malformed manifests; verify staged manifest and binary hashes on the target; reject active or enabled services and symlinked installation paths; record a release-bound `preparing`/`prepared` marker so an interrupted preparation can rerun with the same bundle. Add a focused pull-request CI workflow and update the operator runbook and tests.
- Host/environment changes actually applied: none. Only a temporary local ARM64 build and read-only local checks were run.
- Runtime/exposure state: existing Pi and Dashboard services remain unchanged; no VM or production service was installed, enabled, or exposed.
- Validation performed and outcome: 25 focused Python tests, Ansible syntax check, workflow YAML parse, an offline five-agent ARM64 cross-build with pinned-digest verification, a read-only local Ansible expression check, Markdown links, and `git diff --check` passed. Full playbook execution and the new CI workflow have not yet run on GitHub.
- Not performed / deferred: clean ARM64 VM apply/retry test, Pi hardware acceptance, Cowrie/Zeek/Compose/Dashboard installation, private-config validation, activation, and production rollback.
- Risks and data handling: a SHA-256 supplied from the same untrusted bundle is not an authenticity proof; operators must use the reviewed build receipt. Top-level package versions are pinned, while transitive dependencies still depend on approved Ubuntu package sources. No credentials or private env contents entered this change.
- Rollback: revert this repository change if needed; no host rollback is required because no host was modified.
- Follow-up: exercise first run, interrupted rerun, wrong digest, active-service rejection, and rollback on a disposable ARM64 VM before declaring the preparation phase qualified.
- Related ADR/runbook: [ADR-0009](adr/ADR-0009-installer-operator-managed-credentials.md), [Ansible preparation runbook](../deploy/ansible/README.md), and [VM test target](INSTALLER-VM-TEST-TARGET.md).

### 2026-09-28 — Prepare first Ansible slice for fresh ARM64 Pi installation

- Status: repository implementation prepared; not applied to a host or activated.
- Scope and intent: begin the accepted fresh-Pi installer with an idempotent, non-secret Ansible preparation step, reusing the prior read-only planner and ARM64 release builder.
- Repository branch and commit/PR: `feat/ansible-pi-prepare`; commit/PR follow this entry.
- Repository changes: import the plan-only profiles, builder, tests, and draft manuals from the unmerged installer branch; add a release verifier, Ansible playbook, inactive Go service templates, inventory example, and operator runbook. The playbook installs base packages and Redis, stops/disables Redis, stages a verified release, and leaves application units disabled. It does not touch `.env` files.
- Host/environment changes actually applied: none. No Pi, Dashboard, or VM was changed.
- Runtime/exposure state: existing Pi and Dashboard runtime are unchanged; no new trap port or service is active.
- Validation performed and outcome: 22 focused Python tests, Ansible syntax check, local Markdown links, and `git diff --check` passed. The five Go modules passed tests and cross-built to a static Linux ARM64 bundle with network downloads disabled; the bundle verifier passed, and rendered systemd units passed `systemd-analyze verify` against those binaries. No clean ARM64 VM execution or hardware acceptance was performed.
- Not performed / deferred: Cowrie/Zeek/Compose/Dashboard installation, Redis private-binding verification on a clean VM, collector log ACLs, value-redacting activation, existing-Pi migration, and production rollback tests.
- Risks and data handling: source units contain old checkout paths, so the new templates point to the versioned bundle; their runtime permissions remain unqualified until VM tests. The bundle contains binaries and hashes only. No private env values, credentials, or attacker content were copied into the repo.
- Rollback: restore the disposable VM snapshot for first validation; production rollback is deferred until acceptance. Revert the branch commit for repository rollback.
- Follow-up: qualify this prepare phase on a clean ARM64 VM, pin and package remaining service artifacts, then implement separate operator-input validation and activation.
- Related ADR/runbook: [ADR-0009](adr/ADR-0009-installer-operator-managed-credentials.md), [Ansible preparation runbook](../deploy/ansible/README.md), [VM test target](INSTALLER-VM-TEST-TARGET.md), and [readiness audit](INSTALLATION-READINESS-2026-09-28.md).

### 2026-09-28 — Set installer boundary for operator-managed private configuration

- Status: design and documentation prepared; no installer apply mode or host deployment performed.
- Scope and intent: define the first fresh-Pi installer as a preparatory installation of services, dependencies, and non-secret configuration, with operator-managed `.env` and credentials.
- Repository branch and commit/PR: `docs/installer-operator-credentials`; commit/PR follow this entry.
- Repository changes: add ADR-0009 and align the installer blueprint, readiness audit, roadmap, and documentation index with a separate validation/activation phase.
- Host/environment changes actually applied: none in this change; no private file was created, read, changed, or copied.
- Runtime/exposure state: the existing Pi and Dashboard services remain as previously audited. No new service was installed or enabled.
- Validation performed and outcome: reviewed the current plan-only profile, readiness findings, and installer blueprint; checked changed Markdown links and `git diff --check` locally.
- Not performed / deferred: apply/activate implementation, ARM64 VM and Pi installation tests, Dashboard staging env correction, and existing-Pi migration.
- Risks and data handling: a prepared installation is deliberately not operational; activation must fail if required operator inputs are absent. No credential values or raw attacker material enter this record.
- Rollback: revert the documentation change with a dated ADR supersession if the accepted boundary changes; no host rollback is needed.
- Follow-up: implement versioned, non-secret preparation artifacts and a value-redacting activation preflight on the installer branch; then qualify them on a disposable ARM64 VM.
- Related ADR/runbook: [ADR-0009](adr/ADR-0009-installer-operator-managed-credentials.md), [installation readiness audit](INSTALLATION-READINESS-2026-09-28.md), and [installer blueprint](HONEYPOT-PORTAL-INSTALLER-GUIDE.md).

### 2026-09-28 — Addendum: identify unmerged installer planning branch

- Status: documentation corrected; no host change or installation performed.
- Scope and intent: supplement the installation-readiness audit after finding existing installer work outside `main`.
- Repository branch and commit/PR: `docs/installation-audit-addendum`; commit/PR follow this entry.
- Repository changes: document `feat/appliance-installer` at `ddf4f3c` and its plan-only CLI, profiles, tests, and draft manuals. Clarify that no runnable full-system installer is present on `main`.
- Host/environment changes actually applied: none in this addendum.
- Runtime/exposure state: unchanged from the preceding audit; no service or release was touched.
- Validation performed and outcome: inspected the branch commit, file list, CLI execution-mode guard, draft manuals, and PR status. The branch is unmerged and has no PR.
- Not performed / deferred: merge or rebase of the installer branch, fresh-OS installation, and VM or Pi acceptance tests.
- Risks and data handling: the branch is based on an older `main` revision; the plan-only tool must not be presented as an installation command. No secrets were recorded.
- Rollback: revert this documentation addendum with a new dated correction if the branch state changes.
- Follow-up: rebase and review installer work against current `main` and the readiness blockers before developing apply mode.
- Related ADR/runbook: [installation readiness audit](INSTALLATION-READINESS-2026-09-28.md) and [installer blueprint](HONEYPOT-PORTAL-INSTALLER-GUIDE.md).

### 2026-09-28 — Audit fresh-Pi installation readiness and tighten an exposed env file

- Status: repository readiness document prepared; one Pi file-permission correction applied; no installation or deployment performed.
- Scope and intent: compare current repository and Dashboard environment contracts with the running `pi-t` host before drafting a clean-OS Raspberry Pi installation manual.
- Repository branch and commit/PR: `docs/installation-readiness-audit`; commit/PR follow this entry.
- Repository changes: add a sanitized installation-readiness audit and link it from the documentation index and roadmap. The target is a fresh ARM64 Pi; migration of the existing Pi remains separate.
- Host/environment changes actually applied: changed only the Pi checkout's `dashboard-v2/.env.local` mode from `0664` to `0600` and verified the result. No env value, service, binary, database, firewall rule, or active release pointer was changed.
- Runtime/exposure state: Cowrie, Redis, Zeek, collector, processor, hardware, TI, backup control, and legacy forwarder remained active during the read-only inventory. Dashboard services were not installed on that Pi. The Dashboard production host was not accessed.
- Validation performed and outcome: inspected source and Pi branch status, OS/architecture, service and Compose inventory, env key names and modes without printing values, and current Dashboard runtime key references. Local Markdown links resolved and `git diff --check` passed.
- Not performed / deferred: fresh-OS installation test, Dashboard production env audit, backup restore rehearsal, existing-Pi migration, and changes to the stale staging Dashboard env bootstrap/template.
- Risks and data handling: the Pi checkout is dirty and divergent; current Dashboard staging env names do not match current application auth settings. No credential values or raw attacker content were copied to the repo. The permission correction limits local read access to a file containing `MONGODB_URI`.
- Rollback: restore the prior mode only if an owner-approved operational dependency requires it; otherwise retain `0600`. Revert the documentation commit separately if the audit record is superseded, using a dated correction rather than rewriting historical facts.
- Follow-up: define a pinned fresh-Pi release and reconcile Dashboard env/bootstrap and external Compose ownership before publishing runnable installation steps.
- Related ADR/runbook: [installation readiness audit](INSTALLATION-READINESS-2026-09-28.md), [installer blueprint](HONEYPOT-PORTAL-INSTALLER-GUIDE.md), [current architecture](CURRENT-ARCHITECTURE.md), and [security policy](SECURITY-AND-MALWARE-POLICY.md).

### 2026-09-28 — Close the current Filesystem Activity round and hand off installation documentation

- Status: repository documentation prepared; no host deployment in this change.
- Scope and intent: reconcile the live working state with merged PR #96 and the operator's authenticated local Evidence review, then make the installation manual the next distinct documentation focus.
- Repository branch and commit/PR: `docs/filesystem-activity-closure-handoff`; commit/PR follow this entry. PR #96 previously merged at `8cffe85`.
- Repository changes: mark the accepted local `FS-025` Evidence slice `DONE`; move unaccepted `FS-020` through `FS-024` to `DEFERRED`; update the Filesystem working state, architecture snapshot, roadmap, documentation index, and installer blueprint handoff. Earlier implementation-log entries remain unchanged; this entry corrects their now-stale pending-PR and unreviewed-local-browser status.
- Host/environment changes actually applied: none. No Pi service, Dashboard process, database, secret, or installer was changed.
- Runtime/exposure state: the operator's localhost Dashboard displayed command rows and one canonical file-download event for the selected session after PR #96 merged. The production Dashboard deployment remains unverified. The customer installer is still proposed, not runnable.
- Validation performed and outcome: reviewed PR #96 merge and passing CI, the operator-provided browser screenshot, and tracked FS statuses. A documentation consistency check confirmed `FS-020` through `FS-024` are `DEFERRED`, `FS-025` is `DONE`, no FS item remains `IN PROGRESS`, and local Markdown links resolve. `git diff --check` passed.
- Not performed / deferred: production Dashboard deployment, opening the Artifact Intelligence hash link, authenticated Live radar acceptance, CWD-hop/file-operation correlation, forensic export, and installation-manual implementation.
- Risks and data handling: closure applies only to the accepted current Filesystem scope. No real attacker content, private configuration, or credentials were copied into documentation. Historical installer control-plane examples remain marked as superseded by ADR-0007.
- Rollback: revert this documentation commit; no host rollback is needed.
- Follow-up: write and verify the installation manual against current deployment facts, with a declared target path and runnable versus proposed steps separated.
- Related ADR/runbook: [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md), [current architecture](CURRENT-ARCHITECTURE.md), [roadmap](ROADMAP.md), [installer blueprint](HONEYPOT-PORTAL-INSTALLER-GUIDE.md), and [ADR-0007](adr/ADR-0007-retire-dashboard-session-termination.md).

### 2026-09-27 — Add session download evidence and exact artifact hash lookup

- Status: repository change prepared; not deployed.
- Scope and intent: show retained Cowrie file-download events alongside command submissions in Filesystem Activity Evidence and link their SHA-256 to Artifact Intelligence.
- Repository branch and commit/PR: `feat/filesystem-session-download-evidence`; commit/PR pending.
- Repository changes: add an Admin-only, no-store exact-session canonical download endpoint with bounded event ID, timestamp, and hash metadata; add a separate Evidence section while retaining command rows; make exact SHA-256 search fall back to observed events if no enrichment record matches; read the hash from the Artifact Intelligence URL; update API and working-state documentation.
- Host/environment changes actually applied: read-only Pi inspection of canonical and normalized event metadata. No service, database document, configuration, or Pi binary was changed.
- Runtime/exposure state: the active Dashboard and Pi remain unchanged. The new Evidence section becomes available when this Dashboard revision is deployed.
- Validation performed and outcome: Pi metadata showed 725 canonical file-download events across 496 canonical sessions; a sampled canonical row carried a valid SHA-256. The normalized collection held 804 file-download events. Eleven focused tests, targeted ESLint, TypeScript, and webpack production build passed. Default Turbopack build could not bind an internal port in this execution environment.
- Not performed / deferred: authenticated browser review and Dashboard deployment; CWD-hop correlation, file read/write inference, and artifact byte retrieval.
- Risks and data handling: response is Admin-only and exposes hash metadata, never raw Cowrie payloads, URLs, paths, or bytes. Canonical and normalized collections have different event counts; the view deliberately uses only canonical rows with verified session identity. Exact hash fallback remains bounded by the existing event scan limit.
- Rollback: revert this Dashboard change; no host rollback is required until separately deployed.
- Follow-up: verify a known session with a canonical download event in an authenticated browser after deployment.
- Related ADR/runbook: [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md), [Dashboard API contract](../dashboard-v2/docs/API.md), and [ADR-0002](adr/ADR-0002-hash-only-malware-handling.md).

### 2026-09-27 — Restore local Filesystem Evidence access and align command rows

- Status: repository correction prepared; private local development source enabled; production Dashboard deployment not performed.
- Scope and intent: investigate the Evidence Retry/error state in Session audit & replay and make local command review match the production monitor's submission-only list.
- Repository branch and commit/PR: `fix/filesystem-command-evidence-dev`; commit and PR follow this entry.
- Repository changes: limit the local Admin command query to `cowrie.command.input` so outcome events do not duplicate submissions; isolate the route's missing-alias test from live Mongo; document the explicit development gate and current Evidence source. No authentication, canonical binding, or production monitor contract was relaxed.
- Host/environment changes actually applied: set `PTI_LOCAL_ADMIN_COMMANDS_FROM_MONGO=true` in the ignored, owner-only `dashboard-v2/.env.local` for this development workspace. No Pi service, production Dashboard configuration, or canonical record was changed. The existing Dashboard process was not restarted from this environment.
- Runtime/exposure state: the flag is available to a development-mode Next server on loopback after it reloads the local environment. The route still requires an authenticated Admin and exact verified session binding. Production remains on the separate protected monitor path.
- Validation performed and outcome: read-only Mongo metadata showed 5,341 stored command-input events and a valid alias for a sampled command session. A temporary live route smoke test returned commands for that sensor-local session with submission-only rows; 9 focused tests passed. The committed 12-test command suite, targeted ESLint, TypeScript, and `git diff --check` passed locally. No raw inputs were printed or added to fixtures.
- Not performed / deferred: authenticated browser review in the operator's running localhost process and production Dashboard deployment were not performed; that process may need a restart to load the changed environment.
- Risks and data handling: the local route can return sensitive retained command input to an Admin on loopback. The flag and credentials remain outside Git; responses are private/no-store. Redacted-before-persistence originals remain unrecoverable.
- Rollback: remove the local development flag and restart that dev server; revert the repository correction if the submission-only query must be restored.
- Follow-up: verify the Evidence tab after the operator's dev server reloads, then continue FS-025 acceptance with an authenticated browser review.
- Related ADR/runbook: [Filesystem Activity working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md) and [Dashboard API contract](../dashboard-v2/docs/API.md).

### 2026-09-27 — Balance backup schedule form layout

- Status: repository Dashboard UI correction prepared; Dashboard deployment not performed.
- Scope and intent: remove the uneven nested cards and excess space in the schedule editor reported after the preceding alignment change.
- Repository branch and commit/PR: `fix/backup-schedule-form-layout`; commit and PR follow this entry.
- Repository changes: place the time and scope controls in one shared surface with aligned columns, move quick times and the scheduling explanation into a full-width footer, and align Preview change to the right. The existing fixed-height scope transition remains for stable Permanent and Temporary switching.
- Host/environment changes actually applied: none. No schedule revision, Pi service, manifest, or B2 object was changed.
- Runtime/exposure state: the active daily backup schedule remains unchanged; the layout appears only where the updated Dashboard revision is loaded.
- Validation performed and outcome: targeted Dashboard ESLint, TypeScript compilation, and `git diff --check` passed locally.
- Not performed / deferred: authenticated browser visual review and production Dashboard deployment were not performed.
- Risks and data handling: layout-only change; no new data flow or credential exposure.
- Rollback: revert this UI commit.
- Follow-up: inspect Permanent and Temporary layouts after Dashboard deployment.
- Related ADR/runbook: [ADR-0008](adr/ADR-0008-dashboard-backup-daily-schedule.md).

### 2026-09-27 — Align backup schedule scope with time inputs

- Status: repository Dashboard UI correction prepared; Dashboard deployment not performed.
- Scope and intent: align the schedule scope field with the Hour and Minute controls for easier scanning.
- Repository branch and commit/PR: `fix/backup-schedule-scope-alignment`; commit and PR follow this entry.
- Repository changes: add a small "Schedule scope" heading above the existing Permanent, Temporary, and return-to-permanent scope field. The shared spacing places its label and value on the same rows as the time controls without changing form behavior.
- Host/environment changes actually applied: none. No Pi worker, schedule revision, manifest, or B2 object was changed.
- Runtime/exposure state: the active backup schedule remains unchanged; the alignment appears only where the updated Dashboard revision is loaded.
- Validation performed and outcome: targeted Dashboard ESLint and `git diff --check` passed locally.
- Not performed / deferred: authenticated browser visual review and production Dashboard deployment were not performed.
- Risks and data handling: layout-only change; no new data flow or credential exposure.
- Rollback: revert this UI commit.
- Follow-up: inspect Permanent and Temporary modes after Dashboard deployment.
- Related ADR/runbook: [ADR-0008](adr/ADR-0008-dashboard-backup-daily-schedule.md).

### 2026-09-27 — Clarify backup coverage and add bounded hardware history

- Status: repository Dashboard change prepared; Dashboard deployment not performed.
- Scope and intent: distinguish completed manifest checks from actual archive objects, explain empty days, allow bounded historical review, and remove unused space in the hardware card.
- Repository branch and commit/PR: `feat/backup-coverage-history`; commit and PR follow this entry.
- Repository changes: add an authenticated, read-only hardware history endpoint with non-overlapping 29-day windows and a 36-period bound; add Older/Newer/Latest controls, separate checked/archived/empty/review counts, clearer empty-day text, and a full-width card layout with live Pi controls below the calendar. Clarify the source summary's eligible-day wording and document the endpoint contract.
- Host/environment changes actually applied: none. No Pi worker, MongoDB manifest, schedule, or B2 object was changed.
- Runtime/exposure state: the existing Pi schedule remains 01:00 Asia/Bangkok. The new history view becomes active only where this Dashboard revision is deployed; manual actions continue to use the latest live window.
- Validation performed and outcome: targeted hardware backup tests, Dashboard production build, TypeScript compilation, targeted ESLint, and `git diff --check` passed locally.
- Not performed / deferred: authenticated browser visual review, production Dashboard deployment, Pi worker changes, and restore rehearsal were not performed.
- Risks and data handling: historical gaps before target activation can appear as missing, so the UI labels history read-only and leaves actions on the live window. The endpoint reads only bounded manifest metadata and does not expose archive contents or credentials.
- Rollback: revert this Dashboard change; no host rollback is needed unless separately deployed.
- Follow-up: verify layout and historical paging in an authenticated browser after deployment.
- Related ADR/runbook: [Dashboard API contract](../dashboard-v2/docs/API.md) and [ADR-0008](adr/ADR-0008-dashboard-backup-daily-schedule.md).

### 2026-09-27 — Remove stale fixed-time label from hardware backup card

- Status: repository Dashboard UI correction prepared; production Dashboard deployment not performed.
- Scope and intent: stop showing the obsolete fixed 03:30 time beside hardware backup controls after the daily schedule became configurable.
- Repository branch and commit/PR: `fix/backup-sidebar-schedule-label`; commit and PR follow this entry.
- Repository changes: replace the hardcoded time with `Daily · Asia/Bangkok`; the schedule card above remains the source for the actual current time. No API, Pi worker, or stored schedule change.
- Host/environment changes actually applied: none. The Pi worker rollout and audited request recorded in the next entry remain active.
- Runtime/exposure state: the currently running Pi schedule is 01:00 Asia/Bangkok; this wording appears wherever the updated Dashboard code is loaded.
- Validation performed and outcome: targeted Dashboard ESLint and `git diff --check` passed locally; the change is a static label correction.
- Not performed / deferred: production Dashboard deployment and authenticated browser visual review were not performed for this label correction.
- Risks and data handling: no new data flow or credentials. The sidebar now names the timezone but leaves exact time to the schedule card.
- Rollback: revert this UI commit.
- Follow-up: inspect the label after Dashboard deployment.
- Related ADR/runbook: [ADR-0008](adr/ADR-0008-dashboard-backup-daily-schedule.md).

### 2026-09-27 — Deploy and verify manual backup window correction on Pi

- Status: Pi control worker correction installed and active; Dashboard UI correction is merged into `main` but no production Dashboard deployment was performed.
- Scope and intent: apply the tested manual-window fix from [PR #89](https://github.com/siridet-su/proactive-threat-intelligence-honeypot/pull/89) and verify the previously skipped 2026-08-27 hardware day.
- Repository branch and commit/PR: deployment used merge commit `8527d31` from PR #89; this dated deployment record was added on `docs/backup-manual-window-rollout`.
- Repository changes: no worker source change beyond PR #89. This entry records host application and read-only validation after that merge.
- Host/environment changes actually applied: built the Linux ARM64 worker from clean merge commit `8527d31`, verified its SHA-256 on the Pi, saved the previous root-owned binary at `/var/backups/hardware-backup-control-20260927-1c06e18c.bin`, installed the new binary atomically, and restarted only `honeypot-hardware-backup-control.service`. The Pi repository branch and its unrelated modified file were not changed. An operator-approved `run_missing` request was inserted directly into the audited control collection for this maintenance verification, without using the Dashboard API.
- Runtime/exposure state: the Pi control service is active with the new binary and a fresh heartbeat. The approved request completed successfully for 1/1 selected day, 2026-08-27. Its active-bucket manifest is successful but empty: 0 records, 0 archive bytes, and no B2 object. The stored daily schedule remains 01:00 Asia/Bangkok.
- Validation performed and outcome: `go test ./...`, Dashboard TypeScript and targeted ESLint checks, Linux ARM64 cross-build, GitHub Dashboard staging CI, local/Pi binary hash comparison, service status, Pi journal, request progress, and manifest metadata all passed. Read-only counts found zero `hardware_metrics_1m` records for that UTC day with either BSON Date or ISO string timestamps, confirming the empty result is not caused by an old timestamp field.
- Not performed / deferred: production Dashboard deployment, read-only restore rehearsal, and the next scheduled Pi run were not tested in this deployment.
- Risks and data handling: the worker now follows the displayed scheduled-run window for manual actions; a later eligible day with records may create a B2 object. This verified day was empty and created none. No credentials, source records, archive contents, or protected configuration contents were copied into the repository.
- Rollback: restore the protected previous binary atomically and restart the control service if needed; PR #89 can be reverted separately for repository rollback.
- Follow-up: verify the next scheduled run and inspect the Dashboard after its UI code is deployed; the other two 2026-08-27 target exceptions remain separate from the hardware request.
- Related ADR/runbook: [ADR-0008](adr/ADR-0008-dashboard-backup-daily-schedule.md) and [hardware backup worker runbook](../agents/hardware-backup/README.md).

### 2026-09-27 — Align manual backup actions with displayed coverage

- Status: repository Pi worker correction prepared; not deployed to the Pi.
- Scope and intent: make Run missing days and Retry failed days use the same UTC coverage window that the Dashboard displays under the current Bangkok schedule.
- Repository branch and commit/PR: `fix/backup-manual-window-anchor`; commit and PR follow this entry.
- Repository changes: anchor manual request day selection to the latest scheduled occurrence, including temporary times, instead of the current UTC date. Show an explicit no-eligible-days result in the Dashboard for a completed `0/0` request, instead of a misleading 100% progress bar. Add boundary tests and update the worker runbook. Scheduled runs, manifest schema, bucket matching, and retention policy remain unchanged.
- Host/environment changes actually applied: none. No Pi binary, service, stored schedule, manifest, or B2 object was changed by this repository edit.
- Runtime/exposure state: the running Pi worker still uses its previous manual window calculation until deployed. At 2026-09-27 21:09 Bangkok time, its log recorded a `run_missing` request for hardware rollups with `days=0` while the Dashboard showed 2026-08-27 missing; the request completed without an upload.
- Validation performed and outcome: `go test ./...` passed for the Pi worker, including UTC/Bangkok boundary and temporary schedule cases; Linux ARM64 cross-build produced a static executable. Dashboard TypeScript and targeted ESLint checks plus `git diff --check` passed locally. Read-only Pi journal inspection confirmed the 2026-09-27 21:09 request selected zero days.
- Not performed / deferred: Pi deployment, live retry of the missing day, and restore verification were not performed.
- Risks and data handling: manual actions may archive an eligible day that was previously skipped because the worker window had moved one day ahead of the Dashboard; B2 storage use may increase by that archive. No secrets or archive contents enter this change.
- Rollback: restore the previous worker binary and restart the Pi control service if runtime behavior regresses; repository rollback is a revert of this commit.
- Follow-up: deploy the tested worker, rerun the missing-day action, and verify its manifest and Dashboard coverage.
- Related ADR/runbook: [ADR-0008](adr/ADR-0008-dashboard-backup-daily-schedule.md) and [hardware backup worker runbook](../agents/hardware-backup/README.md).

### 2026-09-27 — Align backup schedule time and scope controls

- Status: repository Dashboard UI correction prepared; local development Dashboard uses it when reloaded.
- Scope and intent: align the Daily time and Applies for controls shown side by side on wide screens.
- Repository branch and commit/PR: `fix/backup-schedule-field-alignment`; commit and PR follow this entry.
- Repository changes: move the Permanent, Temporary, and Return to permanent mode choices above both editor columns so their control panels start at the same vertical position. Schedule behavior and API remain unchanged.
- Host/environment changes actually applied: none. No Pi service, stored schedule, or production Dashboard deployment was changed.
- Runtime/exposure state: the Pi scheduler is unaffected; this layout appears where the updated Dashboard code is loaded.
- Validation performed and outcome: Dashboard production build including TypeScript check, targeted ESLint, and `git diff --check` passed locally. The two control panels now share the same CSS grid row below the mode selector.
- Not performed / deferred: authenticated browser visual review, live Admin schedule edit, production Dashboard deployment, and next Pi run verification were not performed for this visual correction.
- Risks and data handling: no new data flow or permission change. No secrets or archive contents enter this change.
- Rollback: revert this UI commit; no Pi or data rollback is required.
- Follow-up: inspect the aligned fields with live Admin data after Dashboard deployment.
- Related ADR/runbook: [ADR-0008](adr/ADR-0008-dashboard-backup-daily-schedule.md).

### 2026-09-27 — Reorganize the backup schedule overview

- Status: repository Dashboard UI change prepared; local development Dashboard uses it when reloaded.
- Scope and intent: remove the tall, mostly empty schedule summary panel and give the current schedule, temporary change, and today's run balanced space above the editor.
- Repository branch and commit/PR: `feat/backup-schedule-overview-layout`; commit and PR follow this entry.
- Repository changes: replace the stretched left/right card layout with three compact status tiles, place the editor below in responsive time and scope columns, move the one-run guidance beside the scope control, and present the preview as a horizontal confirmation row. Preserve the mode transitions, temporary range picker, preview, three-second Undo, and backend no-op check. No schedule/API behavior changes.
- Host/environment changes actually applied: none. No Pi service, systemd timer, MongoDB revision, B2 object, or production Dashboard deployment was changed.
- Runtime/exposure state: the Pi and stored schedule are unaffected; the local Dashboard displays this layout when the new UI code is loaded.
- Validation performed and outcome: Dashboard TypeScript check, targeted schedule picker and Undo tests (4/4), targeted ESLint, production build, and `git diff --check` passed. Chromium mock-data visual review covered wide and narrow layouts, both schedule modes, and the range calendar.
- Not performed / deferred: live Admin edit, production Dashboard deployment, and next scheduled Pi run verification were not performed for this UI change.
- Risks and data handling: responsive columns leave calendar popovers free to overlay neighboring space; schedule authorization and server validation remain unchanged. No secrets or archive contents enter this change.
- Rollback: revert this UI commit; no Pi or data rollback is required.
- Follow-up: inspect the overview with live Admin data after Dashboard deployment.
- Related ADR/runbook: [ADR-0008](adr/ADR-0008-dashboard-backup-daily-schedule.md) and [Dashboard API contract](../dashboard-v2/docs/API.md#backup-daily-schedule-endpoints).

### 2026-09-27 — Prevent identical backup schedule revisions

- Status: repository Dashboard and API change prepared; local development Dashboard uses it when reloaded.
- Scope and intent: prevent repeated saves of the same permanent time and temporary override from creating redundant schedule revisions. Read-only verification before this change found two consecutive `01:00` revisions; the latest active revision was `02:00`.
- Repository branch and commit/PR: `fix/backup-schedule-noop-guard`; commit and PR follow this entry.
- Repository changes: compare the complete schedule settings in both the Admin preview and every save request at the backend. Preview reports `unchanged`; the Dashboard disables Save and explains why. An identical direct POST returns `unchanged:true` without inserting a revision, while an applied edit returns `unchanged:false`. Keep stale-revision conflict checks and the existing three-second Undo window. Add backend and component regression tests and update the Dashboard API contract.
- Host/environment changes actually applied: none. No Pi service, systemd timer, MongoDB schedule revision, B2 object, or production Dashboard deployment was changed by this implementation.
- Runtime/exposure state: the Pi scheduler remains on the previously verified `02:00` Asia/Bangkok permanent revision until an Admin changes it; this repository change does not alter the stored schedule or Pi worker. The local Dashboard and API pick up this code when reloaded.
- Validation performed and outcome: targeted Dashboard schedule and Undo tests passed (9/9), TypeScript check, targeted lint, production Dashboard build, and `git diff --check` passed locally.
- Not performed / deferred: live Admin no-op save, authenticated browser review, production Dashboard deployment, and the next scheduled Pi run were not performed for this change.
- Risks and data handling: comparison includes permanent time and the complete temporary override. Concurrent edits still return `409` for stale revisions; no-op requests do not need a live worker because they do not write. No secrets or archive contents enter the change.
- Rollback: revert this Dashboard/API commit; no Pi or data rollback is required.
- Follow-up: confirm an authenticated same-setting preview disables Save and monitor the next 02:00 scheduled run.
- Related ADR/runbook: [ADR-0008](adr/ADR-0008-dashboard-backup-daily-schedule.md) and [Dashboard API contract](../dashboard-v2/docs/API.md#backup-daily-schedule-endpoints).

### 2026-09-27 — Keep backup schedule toast movement horizontal

- Status: repository Dashboard UI correction prepared; local development Dashboard uses it when reloaded.
- Scope and intent: correct the diagonal toast motion reported after PR #83 so it enters and exits only from the right.
- Repository branch and commit/PR: `fix/backup-toast-horizontal-motion`; commit and PR follow this entry.
- Repository changes: remove the 24-pixel vertical offset from the shared toast's initial and exit animation while keeping its bottom-right position, horizontal motion, fade, and reduced-motion behavior. No schedule or API logic changes.
- Host/environment changes actually applied: none. No Pi service, systemd timer, MongoDB schedule revision, B2 object, or production Dashboard deployment was changed.
- Runtime/exposure state: the Pi scheduler and stored schedule are unaffected. The visual correction appears where the new Dashboard UI is loaded.
- Validation performed and outcome: Dashboard TypeScript check, targeted toast lint, and `git diff --check` passed locally. No new component test was added for this animation-only coordinate correction.
- Not performed / deferred: authenticated browser visual review, live Admin schedule edit, production Dashboard deployment, and next scheduled Pi run verification were not performed for this correction.
- Risks and data handling: animation coordinates are presentation only; reduced-motion users still receive no movement. No secrets or archive contents enter this change.
- Rollback: revert this UI commit; no Pi or data rollback is required.
- Follow-up: check horizontal entry and exit in an authenticated browser at desktop and narrow widths.
- Related ADR/runbook: [ADR-0008](adr/ADR-0008-dashboard-backup-daily-schedule.md) and [Dashboard API contract](../dashboard-v2/docs/API.md#backup-daily-schedule-endpoints).

### 2026-09-27 — Refine backup schedule toast motion and controls

- Status: repository Dashboard UI fix prepared; local development Dashboard uses it when reloaded.
- Scope and intent: make schedule notices enter from the lower-right edge of the viewport and keep the close or Undo control readable without squeezing its label.
- Repository branch and commit/PR: `fix/backup-toast-layout-motion`; commit and PR follow this entry.
- Repository changes: animate the shared toast from the lower right with reduced-motion support, give the close button a fixed square size, place Undo in the same right-side action area, and close the toast directly after Undo. Keep the three-second cancellation timer and schedule API unchanged. Extend the Undo component test to check that no canceled notice remains.
- Host/environment changes actually applied: none. No Pi service, systemd timer, MongoDB schedule revision, B2 object, or production Dashboard deployment was changed.
- Runtime/exposure state: the Pi scheduling configuration is unaffected by this UI fix; its last verified permanent time was 01:00 Asia/Bangkok. The Dashboard toast changes only where this repository UI code is loaded.
- Validation performed and outcome: targeted Undo component test, TypeScript check, targeted lint, production Dashboard build, and `git diff --check` passed locally.
- Not performed / deferred: authenticated browser visual review, live Admin schedule edit, production Dashboard deployment, and next scheduled Pi run verification were not performed for this UI fix.
- Risks and data handling: Undo still cancels only before the schedule POST starts. The toast layout is responsive, and reduced-motion users receive no movement. No secrets or archive contents enter this change.
- Rollback: revert this UI commit; no Pi or data rollback is required.
- Follow-up: inspect the toast in authenticated light and dark browser sessions at desktop and narrow widths.
- Related ADR/runbook: [ADR-0008](adr/ADR-0008-dashboard-backup-daily-schedule.md) and [Dashboard API contract](../dashboard-v2/docs/API.md#backup-daily-schedule-endpoints).

### 2026-09-27 — Add a three-second Undo window for backup schedule saves

- Status: repository Dashboard UI change prepared; local development Dashboard uses it when reloaded.
- Scope and intent: give an Admin a brief chance to cancel a previewed schedule change and make save status visible.
- Repository branch and commit/PR: `feat/backup-schedule-undo-toast`; commit and PR follow this entry.
- Repository changes: show a themed pending toast with Undo for three seconds after Save, send the existing schedule POST only when that interval ends, and show separate saving, success, cancellation, and error notices. Add a component test for cancellation and delayed write, and document the browser-side grace period in the Dashboard API guide. Server and Pi scheduling logic are unchanged.
- Host/environment changes actually applied: none. No Pi service, systemd timer, MongoDB schedule revision, B2 object, or production Dashboard deployment was changed.
- Runtime/exposure state: the Pi control scheduler remains active with the Admin's permanent 01:00 Asia/Bangkok revision observed earlier on 2026-09-27; the former fixed timer remains disabled. This change affects only the Dashboard page when its new code is loaded.
- Validation performed and outcome: the targeted Dashboard Undo and range-picker tests passed (3/3), TypeScript check, targeted lint, production Dashboard build, and `git diff --check` passed locally.
- Not performed / deferred: authenticated browser interaction, live Admin save or Undo, production Dashboard deployment, next scheduled Pi run, and restore rehearsal were not performed for this UI change.
- Risks and data handling: Undo is available only before the POST begins and while this page remains mounted. A request already sent or saved is not reversed; a stale revision still returns the server's conflict response. No secrets or archive contents enter the UI change.
- Rollback: revert this UI commit; no Pi or data rollback is required.
- Follow-up: verify the pending, canceled, and saved notices in an authenticated browser and monitor the next scheduled Pi run.
- Related ADR/runbook: [ADR-0008](adr/ADR-0008-dashboard-backup-daily-schedule.md) and [Dashboard API contract](../dashboard-v2/docs/API.md#backup-daily-schedule-endpoints).

### 2026-09-27 — Keep backup schedule card height stable across modes

- Status: repository Dashboard UI fix prepared; local development Dashboard uses it when reloaded.
- Scope and intent: prevent the Backup & Retention schedule card and Preview button from shifting vertically when an Admin switches Permanent and Temporary modes.
- Repository branch and commit/PR: `fix/backup-schedule-card-height`; commit and PR follow this entry.
- Repository changes: keep the daily time controls mounted, reserve one equal-height row below them, and show either the temporary date range or permanent-duration explanation in that row with an opacity transition. The clear-override option uses the same layout and shows the permanent base time read-only. No API payload or schedule calculation changes.
- Host/environment changes actually applied: none. No Pi binary, systemd timer, MongoDB schedule revision, B2 object, or production Dashboard deployment was changed.
- Runtime/exposure state: the Pi scheduler remains active at its permanent 03:30 Asia/Bangkok default; the former fixed timer remains disabled. This change affects only local Dashboard presentation until a production Dashboard deployment.
- Validation performed and outcome: local TypeScript check, lint, production build, and `git diff --check` passed. CI and authenticated visual review remain pending at the time of this entry.
- Not performed / deferred: authenticated browser visual review, live Admin schedule edit, production Dashboard deployment, next-day scheduled run, and restore rehearsal were not performed.
- Risks and data handling: the fixed row still allows the temporary date-range popup to overlay the card. The Admin preview/save gate and server validation remain unchanged; no secrets or archive data enter this change.
- Rollback: revert this UI commit; no Pi or data rollback is required.
- Follow-up: verify stable card height in authenticated light/dark browser sessions and monitor the next Pi run.
- Related ADR/runbook: [ADR-0008](adr/ADR-0008-dashboard-backup-daily-schedule.md) and [Dashboard API contract](../dashboard-v2/docs/API.md#backup-daily-schedule-endpoints).

### 2026-09-27 — Choose temporary backup dates as an inclusive range

- Status: repository Dashboard UI change prepared; local development Dashboard uses it when reloaded.
- Scope and intent: make temporary schedule dates easier to understand by selecting the first and last backup day rather than entering a start date and counting days manually.
- Repository branch and commit/PR: `feat/backup-schedule-range-picker`; commit and PR follow this entry.
- Repository changes: turn the rolling calendar into an inclusive range picker with start/end highlights, a 90-day end bound, and 1/7/30-day shortcuts. Show the selected range and computed duration in the form and current schedule summary. Prefill an existing temporary override with its remaining dates. Keep the existing `start_date` plus `days` API payload and document the UI conversion.
- Host/environment changes actually applied: none. No Pi binary, systemd timer, MongoDB schedule revision, B2 object, or production Dashboard deployment was changed.
- Runtime/exposure state: the Pi scheduler remains active at the permanent 03:30 Asia/Bangkok default; the former fixed timer remains disabled. The new range controls are available in the local development Dashboard when reloaded.
- Validation performed and outcome: two targeted Dashboard component tests passed for an inclusive seven-day range crossing September into October and the 90-day maximum. TypeScript check, lint, production build, and `git diff --check` passed locally. CI remains pending at the time of this entry.
- Not performed / deferred: authenticated browser visual review, live Admin schedule edit, production Dashboard deployment, next-day scheduled run, and restore rehearsal were not performed.
- Risks and data handling: the picker limits the start to today through the next 365 Bangkok days and the inclusive duration to 1–90 days; the server still validates both. No secrets or archive contents enter this change.
- Rollback: revert this UI commit; no Pi or data rollback is required.
- Follow-up: inspect range selection in an authenticated light/dark browser session and monitor the next Pi run.
- Related ADR/runbook: [ADR-0008](adr/ADR-0008-dashboard-backup-daily-schedule.md) and [Dashboard API contract](../dashboard-v2/docs/API.md#backup-daily-schedule-endpoints).

### 2026-09-27 — Show upcoming dates in the backup schedule calendar

- Status: repository Dashboard UI fix prepared; local development Dashboard uses it when reloaded.
- Scope and intent: make the temporary schedule start-date picker useful late in a month, when a conventional current-month calendar shows mostly unavailable past dates.
- Repository branch and commit/PR: `fix/backup-schedule-calendar-range`; commit and PR follow this entry.
- Repository changes: replace the month grid with a rolling five-week view from the current week, readable disabled dates, bounded forward navigation, and Today/Tomorrow shortcuts. Keep the existing `YYYY-MM-DD` API value, one-year selection limit, themed colors, and reduced-motion behavior.
- Host/environment changes actually applied: none. No Pi binary, timer, MongoDB schedule revision, B2 object, or production Dashboard deployment was changed.
- Runtime/exposure state: the Pi scheduler remains active at the permanent 03:30 Asia/Bangkok default; the former fixed timer remains disabled. The local development Dashboard reflects this presentation change when reloaded.
- Validation performed and outcome: local TypeScript check, lint, production build, and `git diff --check` passed. The unauthenticated local Backup & Retention route returned its expected login redirect. CI and authenticated visual review remain pending at the time of this entry.
- Not performed / deferred: authenticated browser visual review, live Admin schedule edit, production Dashboard deployment, next-day scheduled run, and restore rehearsal were not performed.
- Risks and data handling: the picker still restricts start dates to today through the next 365 Bangkok calendar days, with the API enforcing the same range. No secret or archive data enters the UI.
- Rollback: revert this UI commit; no Pi or data rollback is required.
- Follow-up: inspect the picker in authenticated light/dark browser sessions and monitor the next Pi run.
- Related ADR/runbook: [ADR-0008](adr/ADR-0008-dashboard-backup-daily-schedule.md) and [Dashboard API contract](../dashboard-v2/docs/API.md#backup-daily-schedule-endpoints).

### 2026-09-27 — Theme the backup schedule pickers and transitions

- Status: repository Dashboard UI change prepared; local development Dashboard uses the working tree when reloaded.
- Scope and intent: replace browser-native schedule dropdowns and date popup with theme-aware controls and add short open/close and mode-change transitions.
- Repository branch and commit/PR: `fix/backup-schedule-themed-pickers`; commit and PR follow this entry.
- Repository changes: add bounded, theme-aware hour/minute menus and a one-year start-date calendar using the existing Dashboard calendar; animate menu, calendar, and Permanent/Temporary form transitions while respecting reduced-motion preference. Preserve the `HH:mm` and local `YYYY-MM-DD` API values.
- Host/environment changes actually applied: none. No Pi binary, systemd timer, MongoDB schedule revision, B2 object, or production Dashboard deployment was changed.
- Runtime/exposure state: the Pi scheduler remains active at its permanent 03:30 Asia/Bangkok default; the former fixed timer remains disabled. This change affects only Dashboard presentation.
- Validation performed and outcome: local TypeScript check, lint, and production build passed. The initial build exposed a browser import of the server-backed schedule module; date arithmetic was moved into the client picker and the build then passed. CI and authenticated visual review remain pending at the time of this entry.
- Not performed / deferred: authenticated browser visual review, live Admin schedule edit, production Dashboard deployment, next-day scheduled run, and restore rehearsal were not performed.
- Risks and data handling: the date picker limits selection to today through the next 365 Bangkok calendar days, matching server validation; schedule writes still require preview and Admin authorization. No secrets or archive contents enter this change.
- Rollback: revert this UI commit; no host or data rollback is required.
- Follow-up: inspect the new menus in authenticated light/dark sessions and monitor the next Pi backup run.
- Related ADR/runbook: [ADR-0008](adr/ADR-0008-dashboard-backup-daily-schedule.md) and [Dashboard API contract](../dashboard-v2/docs/API.md#backup-daily-schedule-endpoints).

### 2026-09-27 — Improve Dashboard backup schedule time controls

- Status: repository UI change prepared; local development Dashboard picks it up through the running dev server.
- Scope and intent: make the daily backup time easy to change without relying on the browser's clock icon or native time popup.
- Repository branch and commit/PR: `fix/backup-schedule-time-picker`; commit and PR follow this entry.
- Repository changes: replace the native time input with two full-width themed hour/minute selects in 24-hour Bangkok time, add 01:00/02:00/03:30 quick choices, and place schedule summary and form in theme-aware panels. The stored `HH:mm` API contract and preview/save workflow are unchanged.
- Host/environment changes actually applied: none. No Pi binary, timer, environment file, MongoDB schedule revision, B2 object, or production Dashboard deployment was changed.
- Runtime/exposure state: the Pi control scheduler remains active at the permanent 03:30 Bangkok default; the former fixed timer remains disabled. Only the local development Dashboard UI changes when the dev server reloads.
- Validation performed and outcome: Dashboard lint, TypeScript check, production build, and `git diff --check` passed locally. CI and authenticated visual interaction remain pending at the time of this entry.
- Not performed / deferred: authenticated browser interaction review, live Admin schedule change, production Dashboard deployment, next-day scheduled run, and restore rehearsal were not performed.
- Risks and data handling: hour and minute controls still produce the same validated 24-hour `HH:mm` value; no secret or archive data enters the UI change.
- Rollback: revert this UI commit; no Pi or data rollback is required.
- Follow-up: verify the controls in an authenticated light and dark browser session and monitor the next Pi run.
- Related ADR/runbook: [ADR-0008](adr/ADR-0008-dashboard-backup-daily-schedule.md) and [Dashboard API contract](../dashboard-v2/docs/API.md#backup-daily-schedule-endpoints).

### 2026-09-27 — Preserve complete response guidance in compact session detail

- Status: installed and active on the GCP monitor API.
- Scope and intent: keep complete policy-authored finding and action text in the compact session detail projection so the dashboard does not cut an artifact SHA-256 or the final qualification from an advisory sentence.
- Repository branch and commit/PR: `fix/session-display-operational-closeout-20260927`, based on `origin/release/model2-54f-rrf-closeout-20260926` at `9d9cf7fb0`; this entry ships with the fix commit.
- Repository changes: set a separate 2,048-character limit for response-guidance finding/action text and list entries; retain the 160-character limit for unrelated compact metadata. Raise the Model2 bridge client timeout from 0.25 to 3.0 seconds after measuring 215–250 ms normal spool lookup time. Add full-hash, full-sentence, upper-bound and delayed-bridge regression assertions.
- Host/environment changes actually applied: installed checksum-verified `security.py` and `evidence.py` at their respective paths under `/opt/honeypot/production/`; restarted only `honeypot-monitor-web` after each installation. Owner-only backups are at `/home/siridet_s_dev/security.py.pre-guidance-projection-20260927` and `/home/siridet_s_dev/evidence.py.pre-bridge-timeout-20260927` on the GCP host. No dashboard or model service was restarted.
- Runtime/exposure state: monitor API is active; its `/health` endpoint returned HTTP 200 after warm-up. The public dashboard tunnel remains on its existing address and `/login` returned HTTP 200. The active release directory is named for `9d9cf7fb0`, while its copied manifest and `DEPLOYED_COMMIT` marker still identify an older `00d3fde...` backend package. A read-only manifest verification fails at release-path matching. This provenance drift predates the two-file patch, which was installed into the active directory in place; the functional checks below do not constitute an immutable-release verification.
- Validation performed and outcome: targeted regression suites passed 128 tests with 3 skips; `py_compile` and `git diff --check` passed. A known session's compact detail returned HTTP 200 with two findings and two actions; the first finding and action include a complete 64-character SHA-256 and terminal sentence punctuation (lengths 200 and 170). Guidance still requires manual approval and cannot auto-execute. After the timeout fix, the same session's HTTP API returned a bound V3 Model2 result and `EXPERIMENTAL_RRF`, moving T1105 to the first recommendation. Two additional current V3 sessions returned bound Model2 results; their RRF review order remained Model1-only because no gated support changed the order. PDF returned HTTP 200; dashboard login returned HTTP 200 and protected session route HTTP 307 without authentication.
- Not performed / deferred: authenticated browser visual review. A historical V2 session still has one valid hypothesis but currently falls back to Model1-only because the active V3 identity gate does not accept that older artifact; historical report wording describes its original V2 runtime, not current live fusion.
- Risks and data handling: the larger limit applies only to policy-authored guidance projection. The protected session API response used for validation was owner-only on the GCP host, then removed with the two upload staging files after validation. No response payload was committed; the two rollback backups remain owner-only.
- Rollback: restore both protected backups to their exact backend paths with root ownership and their original modes (`security.py` 0664, `evidence.py` 0644), compile and restart `honeypot-monitor-web`; verify `/health` and the original checksums `c9f2f53a28ff148515340c21f7257e28faa5df776a9d31c9ebee571987e3e3b6` and `e3c5986ac9c3bdfa144d7fa2bc3842b4768de58d5a261c69c7850821055ae959`.
- Follow-up: rebuild and promote a clean manifest-bound backend release from the committed revision, then verify the complete guidance in an authenticated browser session. See [validation note](validation/2026-09-27-session-guidance-projection-closeout.md).

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

### 2026-09-25 — Activate sensitive threat-event archive on the Pi

- Status: active for all three configured targets: `hardware_metrics_1m`,
  `filesystem_audit`, and `threat_events`.
- Scope and intent: enable the final retained-data target after the private
  bucket, upload-key capability boundary, and sensitive-data handling policy
  were explicitly reviewed.
- Repository branch and commit/PR: `feat/artifact-intelligence`; this entry
  and the current-state updates are committed with the host activation record.
- Repository changes: updated the current architecture, service catalog, data
  ownership contract, and hardware-backup runbook to record that the sensitive
  target is now active while preserving the no-read/no-delete upload boundary.
- Host/environment changes actually applied: preserved the prior environment at
  `/var/lib/honeypot/hardware-backups/deploy-backups/backup.env.pre-threat-events-20260925`,
  set `BACKUP_TARGETS=hardware_metrics_1m,filesystem_audit,threat_events`, set
  `BACKUP_ALLOW_SENSITIVE=true` in the protected `/etc/honeypot/backup.env`,
  and restarted `honeypot-hardware-backup-control.service`. No credential
  value or protected configuration content was copied into the repository.
- Runtime/exposure state: the control service is active and reports all three
  targets; the daily timer remains enabled. The upload worker still has only
  `listFiles` and `writeFiles` for the private B2 bucket. The dashboard target
  status is therefore eligible to show all three cards as Active.
- Validation performed and outcome: a manual scheduled run completed without
  error for all three targets and refreshed the B2 storage snapshot. Hardware
  and filesystem archives were uploaded for the newly eligible day. The
  `threat_events` target produced successful zero-document manifests for the
  current lookback window because its event records have not yet passed the
  two-day late-write safety hold; no threat-event upload failure was observed.
  The oneshot service exited successfully while the control loop remained
  active.
- Not performed / deferred: no restore/read operation was run; no sensitive
  event payload was read back from B2; and no direct local B2 listing was
  possible because the workstation could not resolve the regional Backblaze
  API hostname. Pi-side authorization, target activation, and upload logs were
  verified.
- Risks and data handling: the `events` archive can contain credential-bearing
  web-login fields. Keep the bucket private, restrict restore access to the
  separate read-only operator key, and do not place raw event values in logs,
  docs, or fixtures.
- Rollback: restore the protected environment copy above to
  `/etc/honeypot/backup.env`, remove `threat_events` and
  `BACKUP_ALLOW_SENSITIVE` from the active environment, and restart the
  control service. Existing B2 objects remain unless an operator separately
  applies the cloud lifecycle policy.
- Follow-up: monitor the first non-empty `threat_events` archive after the
  safety hold and validate the read-only restore procedure under the approved
  operator path.
- Related material: [retained-data backup runbook](../agents/hardware-backup/README.md),
  [ADR-0006](adr/ADR-0006-retained-data-backup-boundaries.md),
  [current architecture](CURRENT-ARCHITECTURE.md), and
  [data ownership](DATA-OWNERSHIP.md).

### 2026-09-25 — Add per-target backup coverage to the dashboard

- Status: repository implementation complete; local dashboard worktree is ready
  for review. No production web deployment was performed by this change.
- Scope and intent: distinguish a target being enabled on the Pi from the
  amount of data actually archived for that target.
- Repository branch and commit/PR: `feat/artifact-intelligence`; dashboard and
  test changes are included with this entry.
- Repository changes: extended the backup target overview API to aggregate the
  `hardware_backup_manifests` window by target, including successful, archived,
  empty, failed, running, and missing days plus document and compressed-byte
  totals. Updated the source cards to show independent coverage, records,
  archive size, and latest checked day for hardware, filesystem, and threat
  archives. Empty successful manifests are presented as `No eligible records`
  rather than falsely implying a B2 object exists.
- Host/environment changes actually applied: none. The Pi backup worker and
  MongoDB data were not changed; the UI reads the existing
  `backup_target_status` and `hardware_backup_manifests` records.
- Runtime/exposure state: the existing local development server can hot-reload
  the worktree; no production dashboard process or external endpoint was
  restarted.
- Validation performed and outcome: the targeted backup dashboard test suite
  passed 5 tests, ESLint passed, TypeScript `--noEmit` passed, and the new
  manifest aggregation test covers archived, empty, failed, and missing days.
- Not performed / deferred: no authenticated browser screenshot validation and
  no production dashboard deployment; the API still requires the existing
  operator session.
- Risks and data handling: the dashboard exposes counts, sizes, dates, and
  statuses only. It does not return archive payloads or credential-bearing
  event contents.
- Rollback: revert the dashboard/API commit; the Pi worker and existing
  manifests remain unchanged.
- Follow-up: deploy the dashboard branch through the normal web release path
  and verify the three active target cards against the authenticated API.
- Related material: [retained-data backup runbook](../agents/hardware-backup/README.md),
  [current architecture](CURRENT-ARCHITECTURE.md), and
  [data ownership](DATA-OWNERSHIP.md).
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

### 2026-09-25 — Rebuild collector and processor binaries from a clean Pi checkout

- Status: active; deployed and verified on the Pi.
- Scope and intent: replace the collector and processor binaries that were
  stamped `vcs.modified=true` with clean builds while preserving the existing
  service configuration and runtime data path.
- Repository branch and commit/PR: `feat/artifact-intelligence` at merge
  commit `275314a`; the Pi source checkout was at `6e46abf` and its tracked
  collector/processor source files matched the branch before build.
- Repository changes: appended this deployment record; no agent source,
  schema, or service-unit change was introduced.
- Host/environment changes actually applied: ran `go test ./...` for both
  agent modules; built Linux ARM64 binaries with `-trimpath` and
  `CGO_ENABLED=1`; preserved the previous binaries under the protected
  rollback directory `/home/cpe27/agent-deploy-backups/collector-processor-20260925-clean-vcs`; installed the new binaries atomically.
- Runtime/exposure state: restarted `honeypot-collector.service` and
  `honeypot-processor.service`. Both are active with zero restart failures;
  the hardware and hardware-backup services were not restarted.
- Validation performed and outcome: both Go test suites passed; deployed
  collector SHA-256 is
  `0126a24de591096390cee11476ad352e414a7285d5adec9bfb501265351c6fde` and
  processor SHA-256 is
  `d11451eb02e0c89669bb4950b1d532fa12ec716834ec6589c66d8960fd0abc38`.
  Both binaries report `vcs.modified=false`; post-restart service checks were
  active with no error-priority journal entries.
- Not performed / deferred: no synthetic login event, MongoDB write, Redis
  throughput test, or dashboard regression test was generated by this
  restart.
- Risks and data handling: binary-only replacement; no credentials, event
  payloads, MongoDB records, or retention policy were changed.
- Rollback: atomically restore the preserved binaries from the rollback
  directory and restart the two services.
- Follow-up: keep the clean-build hashes with the deployment record and use a
  clean checkout for future Pi agent releases.
- Related ADR/runbook: [web-login pipeline deployment validation](validation/2026-09-24-web-login-pipeline.md)
  and [current architecture](CURRENT-ARCHITECTURE.md).

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

### 2026-09-25 — Add backup posture and archive operations overview

- Status: prepared; dashboard and heartbeat source changes are not deployed.
- Scope and intent: make the Backup & Retention page report operational state
  across all enabled archive targets instead of presenting only hardware
  coverage and a hardcoded Pi connection badge.
- Repository branch and commit/PR: `feat/artifact-intelligence`; commit/PR
  pending at the time of this entry.
- Repository changes: extended `/api/backup/targets` with control-worker
  heartbeat state, B2 snapshot freshness, per-target lag and coverage
  exceptions, recent audited request activity, policy metadata, and
  evidence-based restore readiness. The dashboard now renders a backup
  posture strip, explicit per-target archived/empty/attention/lag values,
  exception and activity panels, destination freshness, restore readiness, and
  policy safeguards. The control worker now refreshes `backup_target_status`
  on each control poll so `last_seen_at` is a real heartbeat. Error text shown
  by the overview is normalized and bounded; raw event documents and secrets
  are not returned.
- Host/environment changes actually applied: none. No Pi binary, systemd
  unit, MongoDB data, B2 object, or credential was changed by this work.
- Runtime/exposure state: the new dashboard contract and control-worker
  heartbeat are prepared in the worktree only. The currently running Pi
  worker and deployed dashboard remain on their previous code until a reviewed
  deployment.
- Validation performed and outcome: the targeted backup Vitest suite passed;
  TypeScript `tsc --noEmit` passed; targeted ESLint for changed dashboard
  files passed; `gofmt`, `go test ./...` in `agents/hardware-backup`, and
  `git diff --check` passed. Full dashboard lint remains blocked by the
  pre-existing `react-hooks/set-state-in-effect` error at
  `dashboard-v2/src/components/filesystem/TopologyToolbar.tsx:111`. The full
  Vitest suite was also run; 69 files passed, while three filesystem component
  tests failed in untouched topology code (`TopologyCanvas` empty state/path
  annotations).
- Not performed / deferred: no live MongoDB/API smoke test, authenticated
  browser review, B2 query, Pi deployment, worker restart, or restore
  rehearsal was performed. `backup_restore_verifications` has no assumed
  success record; the UI intentionally reports `Not tested` when absent.
- Risks and data handling: threat-event archives remain sensitive and are
  still governed by the existing private-bucket and explicit opt-in policy.
  The dashboard exposes only bounded operational metadata, not event payloads,
  credentials, access tokens, or private keys.
- Rollback: do not deploy this worktree; or revert the dashboard/API and
  heartbeat source changes from the implementation commit. No host rollback
  is required because no host was changed.
- Follow-up: deploy the rebuilt hardware-backup control binary and dashboard
  separately, then verify heartbeat freshness, activity/exception rendering,
  and an approved read-only restore rehearsal before recording any restore
  verification result.
- Related ADR/runbook: [retained-data backup boundaries](adr/ADR-0006-retained-data-backup-boundaries.md), [hardware backup worker runbook](../agents/hardware-backup/README.md), and [data ownership](DATA-OWNERSHIP.md).

### 2026-09-25 — Compact backup data visualization

- Status: prepared; dashboard UI refinement is not deployed.
- Scope and intent: reduce visual density and make archive data readable at a
  glance without removing the operational fields added in the backup overview.
- Repository branch and commit/PR: `feat/artifact-intelligence`; commit/PR
  pending at the time of this entry.
- Repository changes: condensed the source tiles around a large coverage
  percentage, segmented status rail, and larger archived/empty/failed/missing/
  lag values. Removed repeated descriptions and worker text, reduced padding
  and row height in exception/activity panels, and kept audit actor, status,
  date, progress, and duration in compact rows. Restore readiness and policy
  safeguards were also tightened into smaller data blocks.
- Host/environment changes actually applied: none. No Pi binary, systemd
  unit, MongoDB data, B2 object, or credential was changed.
- Runtime/exposure state: the compact layout is prepared in the worktree only;
  the running dashboard remains unchanged until deployment.
- Validation performed and outcome: targeted backup Vitest tests passed;
  TypeScript `tsc --noEmit`, targeted ESLint for `BackupSourceMap.tsx`,
  production build, and `git diff --check` passed.
- Not performed / deferred: no authenticated browser screenshot review, Pi
  deployment, or full-suite rerun was performed for this presentation-only
  refinement.
- Risks and data handling: presentation-only change; backup API contracts,
  sensitive-target boundaries, and operational metadata ownership are
  unchanged. No event payloads or secrets were added.
- Rollback: revert the `BackupSourceMap.tsx` presentation changes; no host
  rollback is required.
- Follow-up: review the page at the active dashboard viewport and adjust only
  breakpoint-specific spacing if the compact tiles still wrap poorly.
- Related ADR/runbook: [hardware backup worker runbook](../agents/hardware-backup/README.md) and [retained-data backup boundaries](adr/ADR-0006-retained-data-backup-boundaries.md).

### 2026-09-25 — Remove duplicate backup coverage rail

- Status: prepared; dashboard UI refinement is not deployed.
- Scope and intent: remove the duplicate archive bars shown in each backup
  source tile while retaining the status breakdown.
- Repository branch and commit/PR: `feat/artifact-intelligence`; commit/PR
  pending at the time of this entry.
- Repository changes: removed the standalone archived-percentage progress bar
  and kept one segmented coverage rail for archived, empty, failed, running,
  and missing days. Added an accessible summary label for the single rail.
- Host/environment changes actually applied: none. No Pi binary, systemd
  unit, MongoDB data, B2 object, or credential was changed.
- Runtime/exposure state: the UI refinement is prepared in the worktree only;
  no dashboard or Pi deployment was performed.
- Validation performed and outcome: targeted backup Vitest tests passed (5/5);
  TypeScript `tsc --noEmit`, targeted ESLint for `BackupSourceMap.tsx`, the
  production build, and `git diff --check` also passed.
- Not performed / deferred: no authenticated browser screenshot review, Pi
  deployment, or restore rehearsal was performed.
- Risks and data handling: presentation-only change; no API/data/secret
  changes.
- Rollback: restore the removed standalone progress-bar block; no host
  rollback is required.
- Follow-up: review the source tiles at the active dashboard viewport.
- Related ADR/runbook: [hardware backup worker runbook](../agents/hardware-backup/README.md) and [retained-data backup boundaries](adr/ADR-0006-retained-data-backup-boundaries.md).

### 2026-09-25 — Rework Backup & Retention information layout

- Status: prepared for review; not deployed to production.
- Scope and intent: improve the hierarchy and readability of the backup
  dashboard while retaining the page header style used by other dashboard
  tabs.
- Repository branch and commit/PR: `feat/artifact-intelligence`; changes are
  uncommitted.
- Repository changes: moved the hardware archive view to the primary position;
  replaced the nested source cards with a single comparison table; consolidated
  the worker, attention, and active-target summary into one status strip; and
  grouped attention, recent actions, restore readiness, and policy details into
  fewer sections. Simplified the hardware archive panel, clarified the daily
  manifest calendar and legend, and kept Pi actions, progress, cloud storage,
  and retention settings available.
- Host/environment changes actually applied: none. No Pi worker, systemd unit,
  MongoDB data, B2 object, or production dashboard was changed.
- Runtime/exposure state: local development server at port `3100` is running
  from this worktree and receives the edits through HMR.
- Validation performed and outcome: `npx tsc --noEmit`, targeted ESLint for the
  three changed dashboard files, and `git diff --check` passed. Automated tests
  and a production build were not run.
- Not performed / deferred: no authenticated browser visual review, Pi
  deployment, or production dashboard deployment was performed.
- Risks and data handling: presentation-only changes; API behavior, backup
  scope, retention policy, and sensitive-data handling are unchanged.
- Rollback: restore the previous page layout in `BackupSourceMap.tsx`,
  `HardwareBackupStatus.tsx`, and the page section order; no host rollback is
  required.
- Follow-up: review `http://localhost:3100/backup-retention` at desktop and
  narrow widths.
- Related ADR/runbook: none; this change affects presentation only.
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

### 2026-09-27 — Merge current main into artifact intelligence

- Status: repository merge prepared; no deployment performed.
- Scope and intent: bring `feat/artifact-intelligence` up to the current `origin/main` while retaining its pending backup overview work and all newer mainline changes.
- Repository branch and commit/PR: `feat/artifact-intelligence`; merge commit pending at the time of this entry; PR #69 remains open.
- Repository changes: merged `origin/main` into the branch. Resolved the sole content conflict in this append-only log by retaining both the backup overview entries and the Filesystem Evidence and response-control entries. Code and other documentation merged automatically.
- Host/environment changes actually applied: none. No service, dashboard deployment, database, backup target, or host configuration was changed.
- Runtime/exposure state: this merge changes repository source only; deployed services retain their previously recorded state. The backup overview remains prepared in the branch and is not active on production hosts.
- Validation performed and outcome: merge conflict markers were removed and the resolved log passed `git diff --check`. The targeted dashboard backup Vitest suite passed (5/5), and `go test ./...` passed in `agents/hardware-backup`. `npx tsc --noEmit` reported only two stale generated `.next` validator imports for the removed session-terminate route; it reported no source diagnostics. The full staged `git diff --check` reports whitespace already present in incoming mainline research files, including intentional Markdown line breaks.
- Not performed / deferred: no production deployment, authenticated browser review, live backup restore rehearsal, or host-level validation was performed. A clean TypeScript check after regenerating `.next` types was not performed.
- Risks and data handling: the merge preserves both histories and adds no secrets or attacker content to the log. Runtime interactions across the merged branches require the targeted checks noted above.
- Rollback: revert the merge commit if needed; no host rollback is required for this repository-only change.
- Follow-up: review PR #69 against the refreshed main branch and deploy the backup changes separately after approval.
- Related ADR/runbook: no architectural decision or operating step changed as part of this merge; existing current-state documents and runbooks from both branches are retained.

### 2026-09-27 — Clear the Dashboard lint gate for artifact intelligence PR

- Status: repository fix prepared for PR #69; not deployed.
- Scope and intent: clear the staging CI lint failure introduced by the inherited Filesystem Activity toolbar while preserving View menu behavior when live topology becomes empty.
- Repository branch and commit/PR: `feat/artifact-intelligence`; fix commit pending at the time of this entry; PR #69.
- Repository changes: replace the toolbar effect that synchronously closes the View menu with a guarded state adjustment when the empty-live prop changes. Extend the existing toolbar test to verify the menu closes on empty state and stays closed when live data returns.
- Host/environment changes actually applied: none. No dashboard, Pi service, database, backup target, or host configuration was changed.
- Runtime/exposure state: the source fix is only in the PR branch; production dashboard behavior is unchanged until a separate deployment.
- Validation performed and outcome: full Dashboard `npm run lint`, the targeted Filesystem density/minimap suite (6/6), and `git diff --check` passed after the regression assertion was added. PR CI was pending when this entry was written.
- Not performed / deferred: no production deployment, authenticated browser review, or host-level validation was performed. The prior TypeScript check remains blocked by stale generated `.next` route imports.
- Risks and data handling: the change affects only local toolbar state and adds no telemetry, credentials, or attacker content.
- Rollback: revert the toolbar state adjustment and related test; no host rollback is needed.
- Follow-up: wait for PR CI, then merge PR #69 after the required checks pass.
- Related ADR/runbook: no architecture decision or operating procedure changed.

### 2026-09-27 — Prepare bucket-scoped retained backup rollover

- Status: repository implementation prepared for review; not deployed.
- Scope and intent: consolidate overlapping backup branches on current `main` and prevent old-bucket manifests from satisfying coverage for a new B2 bucket.
- Repository branch and commit/PR: `feat/backup-bucket-rollover`; commit and PR pending at the time of this entry.
- Repository changes: give new manifests and storage snapshots bucket-scoped identities; constrain scheduled skip, control-request selection, Dashboard coverage, destination status, and restore-verification display to the active bucket; permit legacy bucket-less records only when their historical bucket is explicitly configured. Update the worker runbook, Dashboard environment example, current architecture, and ADR-0006 amendment. The old branch's B2 v4 change was already present on `main`, and its older UI was superseded by PR #69, so neither was copied.
- Host/environment changes actually applied: none. No Pi worker, systemd unit, MongoDB document, B2 object, bucket policy, key, or Dashboard deployment was changed.
- Runtime/exposure state: the deployed worker and Dashboard retain their previous behavior. Bucket-scoped rollover is active only in this repository branch until a separate reviewed deployment.
- Validation performed and outcome: `go test ./...` in `agents/hardware-backup`, the targeted Dashboard backup Vitest suite (6/6), `npx tsc --noEmit`, full Dashboard `npm run lint`, and `git diff --check` passed. No live service or B2 behavior was exercised.
- Not performed / deferred: no live MongoDB/B2 query, bucket move, deployment, authenticated browser review, or restore rehearsal was performed. Legacy-manifest bucket attribution and the new bucket's key scope must be verified before rollout.
- Risks and data handling: a bucket change may re-archive eligible days and incur storage cost. Legacy manifests without an explicitly configured historical bucket are excluded from new-bucket coverage rather than assumed successful. No credentials or attacker data were added to repository files.
- Rollback: revert this repository change before deployment. Once deployed, restore the previous worker and Dashboard versions and keep all old manifests and B2 objects for audit; do not delete archives as part of rollback.
- Follow-up: review the new PR, deploy worker and Dashboard separately, verify current-bucket manifests and storage snapshots, and perform an approved read-only restore check before retiring an old bucket.
- Related ADR/runbook: [ADR-0006](adr/ADR-0006-retained-data-backup-boundaries.md) and [retained backup worker runbook](../agents/hardware-backup/README.md).

### 2026-09-27 — Preserve backup branch audit history before branch cleanup

- Status: historical addendum to records from 2026-09-24 and 2026-09-25; documentation only.
- Scope and intent: retain the host and validation facts recorded only on the overlapping backup branches before their refs and worktrees are cleaned up. This entry does not revise those earlier records or claim a new deployment.
- Repository branch and commit/PR: `docs/backup-branch-history-closeout`; historical source commits `894486e`, `67aaa95`, `82ef4e3` on `feat/hardware-backup-bucket-transition`, `52761c9` on `feat/dashboard-backup-status`, and `6f5d038` on `feat/backup-data`.
- Repository changes: append this provenance summary and clarify the current architecture's distinction between the earlier hardware-only Pi validation and the new multi-target rollover source in PR #72. The old backup UI is superseded by PR #69; its local review history is retained here, not reintroduced into the current UI.
- Host/environment changes actually applied: none by this addendum. The 2026-09-25 hardware-branch records state that an operator prepared protected Pi backup environment settings, retained the previous environment file at a protected rollback path, installed an updated ARM64 backup worker, and restarted only `honeypot-hardware-backup-control.service`. The scheduled service remained inactive at that time. No secret values or backup contents are copied here.
- Runtime/exposure state: the 2026-09-25 record reported an active control worker using the new bucket and key; the first controlled retry produced 29 successful daily manifests, of which 14 had source data and B2 objects. It reported a storage snapshot with 14 file versions. These are historical observations, not a fresh assertion about the currently installed Pi binary, active bucket, or Dashboard deployment. The dashboard-status branch recorded only a local Dashboard runtime on port `3001`; the older backup UI branch likewise recorded local review, not production Dashboard deployment.
- Validation performed and outcome: compared the five cited commit records with the current mainline log and confirmed their host validation facts were not previously preserved there. The historical hardware record reported successful Go tests, B2 v4 authorization and prefix listing, and an active control service; the local Dashboard records reported type-check, lint, tests, and build at their respective times. This addendum itself passed `git diff --check`.
- Not performed / deferred: no host status check, B2 query, current binary inspection, archive download, restore rehearsal, or Dashboard deployment was performed for this addendum. The old record explicitly deferred restore verification and production Dashboard deployment.
- Risks and data handling: old branch names and commit IDs remain as provenance after branch deletion. Protected Pi environment and rollback files remain host-held; this repository stores no credential or archive contents.
- Rollback: revert this addendum only if a factual correction is needed, and then replace it with a dated correction so the audit trail remains append-only; no host rollback is involved.
- Follow-up: verify current Pi worker revision, bucket scope, scheduled/control service state, and read-only restore evidence before any further bucket retirement or deployment claim.
- Related ADR/runbook: [ADR-0006](adr/ADR-0006-retained-data-backup-boundaries.md) and [retained backup worker runbook](../agents/hardware-backup/README.md).

### 2026-09-27 — Deploy bucket-scoped backup worker and refresh current-bucket coverage

- Status: applied on the Pi; documentation prepared on `ops/backup-bucket-scope-pi-rollout`.
- Scope and intent: correct the local Backup & Retention page showing all eligible days as missing because its bucket-scoped query excluded manifests written by the older Pi binary without a `bucket` field. Historical hardware manifests include both old-bucket rows and newer rows with a bucket encoded only in their ID, so attributing every bucket-less row to the active bucket would have been inaccurate.
- Repository branch and commit/PR: `ops/backup-bucket-scope-pi-rollout`; deployed worker source is clean `main` revision `8302f9e` from PR #72; documentation commit pending at the time of this entry.
- Repository changes: update the current architecture and worker runbook to reflect the verified Pi deployment and append this audit entry. No worker or Dashboard source code was changed in this branch.
- Host/environment changes actually applied: cross-built the ARM64 worker from `8302f9e`, copied it to the Pi, preserved the previous binary in a protected host rollback location, atomically installed the new binary, restarted `honeypot-hardware-backup-control.service`, and manually started `honeypot-hardware-backup.service` once. No environment file, systemd unit, Pi Git checkout, old MongoDB manifest, or old B2 object was edited or deleted. The host Git checkout retains its pre-existing unrelated working-tree change.
- Runtime/exposure state: the control service is active and the scheduled service completed successfully as a oneshot; its timer remains enabled. The installed binary reports revision `8302f9e`. All three previously enabled targets remain active in the same private bucket. The local development Dashboard uses the bucket-scoped read path; no production Dashboard deployment was performed.
- Validation performed and outcome: local `go test ./...` passed, the staged Pi binary hash matched the local build, and the protected rollback copy matched the previous Pi binary. The manual scheduled run exited `0/SUCCESS` for all three targets. MongoDB read-only checks found 29 successful bucket-tagged manifests in the current 29-day Dashboard window for each target: 17 hardware days and 17 filesystem days contained archive objects; threat-event days contained zero source documents. The new B2 snapshot recorded 35 hardware and 33 filesystem file versions, up from 18 and 16 before the run; threat events remained at zero. Target heartbeats updated after the run.
- Not performed / deferred: no authenticated browser refresh, independent archive download, read-only restore rehearsal, production Dashboard deployment, bucket retirement, or old-version deletion was performed. Restore readiness remains unverified.
- Risks and data handling: re-archiving eligible days created additional B2 file versions and storage use. Old bucket-less manifests remain for audit but do not satisfy the active bucket's Dashboard coverage. No credentials, attacker payloads, archive contents, or protected configuration values were copied into the repository.
- Rollback: restore the protected previous Pi binary atomically and restart the control service if runtime behavior regresses; keep new MongoDB manifests and B2 versions for audit. A rollback to the old binary would again leave future manifests without bucket fields and may make the bucket-scoped Dashboard show later days as missing.
- Follow-up: confirm the authenticated local Backup & Retention page reports 29/29 archived days, monitor the next timer run, and perform a separately reviewed read-only restore rehearsal before claiming recovery readiness.
- Related ADR/runbook: [ADR-0006](adr/ADR-0006-retained-data-backup-boundaries.md) and [retained backup worker runbook](../agents/hardware-backup/README.md).

### 2026-09-27 — Prepare canonical threat-event timestamp backup fix

- Status: repository fix prepared on `fix/threat-event-backup-timestamps`; host rollout not yet applied at the time of this entry.
- Scope and intent: correct the `threat_events` archive query, which compared BSON Date bounds against ISO 8601 UTC strings in the canonical `events.timestamp` field and therefore recorded eligible days as successful but empty.
- Repository branch and commit/PR: `fix/threat-event-backup-timestamps`; source commit and PR pending at the time of this entry.
- Repository changes: include indexed UTC string day bounds alongside BSON Date bounds for the event source; recheck successful zero-document manifests for source records during scheduled runs so a corrected worker can fill those days without forcing unrelated targets; add a regression test for midnight and fractional-second boundaries.
- Host/environment changes actually applied: none for this prepared fix. The Pi still runs worker source `8302f9e`; no service, database document, B2 object, environment file, or systemd unit was changed by this repository change.
- Runtime/exposure state: the active Pi worker still treats the event window as empty until this fix is deployed and a scheduled run completes. The private B2 sensitive-target opt-in remains enabled; other target schedules and bucket scope are unchanged.
- Validation performed and outcome: `go test ./...` passed. Read-only MongoDB metadata checks found all 87,992 then-current event timestamps were ISO 8601 UTC strings, with 53,496 in the eligible 29-day window, while the old BSON Date query matched none. The `events.timestamp` index is present. These counts may change as live ingest continues.
- Not performed / deferred: no live archive upload, host deployment, authenticated Dashboard check, archive download, or restore rehearsal was performed for this prepared change.
- Risks and data handling: deploying the fix will archive existing eligible sensitive events into the already reviewed private B2 target and increase storage use. No raw event contents, credentials, or protected configuration were copied into repository files or audit output.
- Rollback: revert this source change before deployment; if deployed, restore the previous protected Pi binary and retain any created manifests and B2 versions for audit.
- Follow-up: deploy a clean ARM64 build, run the scheduled worker once, verify event manifest and B2 counts, and record host actions in a dated addendum.
- Related ADR/runbook: [ADR-0006](adr/ADR-0006-retained-data-backup-boundaries.md) and [retained backup worker runbook](../agents/hardware-backup/README.md).

### 2026-09-27 — Apply threat-event timestamp fix and correct empty-source interpretation

- Status: applied on the Pi; dated addendum to the earlier 2026-09-27 bucket-scoped rollout entry.
- Scope and intent: finish the approved `threat_events` backup rollout and correct the earlier interpretation of zero archived event records. The earlier worker returned zero because it queried BSON Dates against UTC string timestamps; source events were present. The earlier log remains unchanged as a record of what that run reported.
- Repository branch and commit/PR: `fix/threat-event-backup-timestamps`; clean ARM64 worker source commit `de9304e`; documentation completion commit and PR pending at the time of this entry.
- Repository changes: add UTC string timestamp query support and empty-success rechecks to the backup worker, add a regression test, correct the worker schedule and event-source description in the runbook, update the current architecture, and append this audit addendum. No Dashboard source code or accepted architecture decision changed.
- Host/environment changes actually applied: copied the ARM64 binary to the Pi, preserved the prior `8302f9e` binary in a protected rollback location, atomically installed the new binary, restarted only the backup control service, and manually started the scheduled backup service once. No host environment file, timer, systemd unit, Pi Git checkout, old manifest, or B2 object was edited or deleted.
- Runtime/exposure state: the Pi control service is active with source `de9304e`; the scheduled oneshot completed successfully and its daily timer remains enabled. The existing private B2 target and sensitive-event opt-in are unchanged. The local Dashboard reads the new manifests from MongoDB; no production Dashboard deployment occurred.
- Validation performed and outcome: local `go test ./...` and `git diff --check` passed; the staged binary hash and VCS revision matched the clean local build, and the protected rollback copy matched the previously active binary. The manual run exited `0/SUCCESS`. MongoDB showed 29 successful, bucket-tagged threat-event manifests in the current 29-day window, with 21 archived days, eight empty days, and 53,496 archived records. The B2 snapshot reported 21 threat-event file versions totaling 9,365,344 bytes; hardware and filesystem file-version counts stayed at 35 and 33. The worker did not force a re-upload of those other targets.
- Not performed / deferred: no authenticated browser review, archive download, independent content/hash comparison, read-only restore rehearsal, production Dashboard deployment, bucket retirement, or old-version deletion was performed. Upload success does not establish restore readiness.
- Risks and data handling: this run wrote eligible sensitive events to the already reviewed private B2 target. No raw event contents, attacker credentials, archive contents, access tokens, or protected configuration values were copied into repository files or audit output. Previously empty manifests were updated in place by the normal worker operation and retain their bucket-scoped identity.
- Rollback: atomically restore the protected previous binary and restart the control service if the new worker regresses. Keep created manifests and B2 versions for audit; the older worker would again fail to archive UTC string event timestamps.
- Follow-up: refresh the authenticated Backup & Retention page and expect 21/29 archived threat-event days with eight empty days; monitor the next 03:30 Asia/Bangkok timer run; perform a separately reviewed read-only restore rehearsal before claiming recovery readiness.
- Related ADR/runbook: [ADR-0006](adr/ADR-0006-retained-data-backup-boundaries.md) and [retained backup worker runbook](../agents/hardware-backup/README.md).

### 2026-09-27 — Prepare Dashboard-controlled daily backup schedule

- Status: repository implementation prepared on `feat/backup-daily-schedule`; not active on the Pi at the time of this entry.
- Scope and intent: allow an Admin to set the permanent daily Bangkok backup time or one bounded temporary override in a single Dashboard form, with a preview of catch-up, next run, and automatic return to the permanent time.
- Repository branch and commit/PR: `feat/backup-daily-schedule`; source commit and PR pending at the time of this entry.
- Repository changes: add ADR-0008, append-only schedule revisions and Admin-only preview/write APIs, a Dashboard schedule card, Pi control-worker daily claims and bounded retry, and schedule-aware Dashboard UTC coverage anchoring. Add Go and Dashboard schedule tests and update the API contract and worker runbook. The default time remains 03:30 Asia/Bangkok until an Admin changes it.
- Host/environment changes actually applied: none for this prepared implementation. No Pi binary, systemd timer, environment file, MongoDB schedule document, B2 object, or production Dashboard deployment was changed.
- Runtime/exposure state: the Pi still runs the fixed 03:30 systemd timer and the prior control binary. The local Dashboard shows schedule status but disables edits until it sees a fresh scheduler-capable Pi heartbeat. Backup targets, the UTC two-day safety hold, and private B2 policy remain unchanged.
- Validation performed and outcome: `go test ./...` passed; the targeted Dashboard schedule and backup suites passed (9 tests); full Dashboard lint, TypeScript check after removing a stale generated route type, and `git diff --check` passed. No live schedule change was made.
- Not performed / deferred: no Pi deployment, timer cutover, authenticated browser review, production Dashboard deployment, live schedule edit, archive restore, or B2 upload was performed for this prepared entry.
- Risks and data handling: a schedule change may move a run into the current day and trigger one prompt catch-up. The worker records one claimed scheduled run per Bangkok date and keeps B2 credentials on the Pi. Revision records contain only schedule metadata and operator identity, never secrets or attacker data.
- Rollback: revert the repository branch before deployment. After deployment, restore the previous protected Pi binary and re-enable the 03:30 timer if the control scheduler fails; retain append-only schedule revisions and run records for audit.
- Follow-up: build and install a clean ARM64 binary, verify its heartbeat and default-time run claim, disable the old timer only after the control scheduler is healthy, then record actual host state in a dated addendum.
- Related ADR/runbook: [ADR-0008](adr/ADR-0008-dashboard-backup-daily-schedule.md), [worker runbook](../agents/hardware-backup/README.md), and [Dashboard API contract](../dashboard-v2/docs/API.md#backup-daily-schedule-endpoints).


### 2026-09-27 — Activate Pi daily backup scheduler

- Status: installed and active on the Pi; Dashboard production deployment remains pending.
- Scope and intent: activate the Dashboard-controlled daily schedule while retaining the permanent 03:30 Asia/Bangkok default and the three existing archive targets.
- Repository branch and commit/PR: `feat/backup-daily-schedule`, source commit `b75749e`; this addendum and PR follow that commit.
- Repository changes: update the current architecture and worker runbook after the verified host cutover. No schedule policy or archive source code changed in this addendum.
- Host/environment changes actually applied: built a clean ARM64 worker from `b75749e`, preserved the previous binary in a protected rollback location under `/var/lib/honeypot/hardware-backups/`, atomically installed the new binary, restarted the control service, then disabled and stopped `honeypot-hardware-backup.timer` after its first successful scheduler run. No host environment file, Pi Git checkout, or existing B2 object was edited or deleted.
- Runtime/exposure state: `honeypot-hardware-backup-control.service` is enabled and active with zero restarts; its installed binary SHA-256 is `1c06e18cff683b55891ddf8e7574b3e302ebd9344a7df3df70ea78bed53795b0`. The former timer is disabled and inactive. The default schedule remains 03:30 Asia/Bangkok; no Admin revision has been saved. The three archive targets and private B2 policy remain active. The local development Dashboard includes the schedule UI; production Dashboard has not been deployed.
- Validation performed and outcome: `go test ./...`, targeted Dashboard tests (9/9), lint, TypeScript check, and Dashboard build passed before installation. The Pi service journal shows one scheduler claim for local day 2026-09-27 at 17:36 Bangkok and successful completion of all three targets by 17:36:11; MongoDB recorded that day's `backup_schedule_runs` status as `success`. A later SSH check confirmed the control service enabled/active with zero restarts, timer disabled/inactive, and installed binary checksum matching the clean build.
- Not performed / deferred: no live Admin schedule edit, next-day 03:30 run, authenticated browser review, production Dashboard deployment, archive download, or read-only restore rehearsal was performed. The successful run alone does not prove future scheduling or recovery readiness.
- Risks and data handling: the control service now owns the daily trigger; if it stops and systemd cannot restart it, backup is delayed until recovery. Schedule and run records contain only operational metadata. No secrets, attacker data, or protected backup contents were copied into repository files.
- Rollback: restore the protected previous binary and restart the control service, and re-enable the fixed 03:30 timer as a pair. Preserve schedule revisions, run claims, manifests, and B2 versions for audit.
- Follow-up: monitor the next scheduled run and authenticated schedule UI; perform a read-only restore rehearsal before claiming recovery readiness.
- Related ADR/runbook: [ADR-0008](adr/ADR-0008-dashboard-backup-daily-schedule.md), [worker runbook](../agents/hardware-backup/README.md), and [Dashboard API contract](../dashboard-v2/docs/API.md#backup-daily-schedule-endpoints).

### 2026-09-27 — Align Activity Evidence timeline and compact technical details

- Status: repository Dashboard UI change prepared on an isolated branch; staging deployment pending.
- Scope and intent: keep event timestamps aligned when only the latest event has a state label, and make technical/provenance fields secondary to analyst-facing summaries.
- Repository branch and commit/PR: `codex/fix-activity-evidence-timeline-20260927`; commit and staging push follow this entry.
- Repository changes: render Activity Evidence rows with a consistent information, timestamp, and reserved state-label grid; retain the connected navy timeline, use orange only for LATEST, and slightly reduce event spacing. Keep expandable technical details collapsed by default, avoid duplicated fields and unnecessary nested disclosures, and compact mostly unavailable or zero-valued field sets. Add presentation regression assertions.
- Host/environment changes actually applied: none. No GCP service, application, backend, MongoDB data, or production configuration was changed manually.
- Runtime/exposure state: not yet deployed. Pushing the change to staging is intended to trigger the configured CI/CD workflow; workflow completion and live visibility are not verified by this entry.
- Validation performed and outcome: focused session-analysis and classification-detail tests passed (21/21); full Dashboard lint and `npx tsc --noEmit` passed; the staging workflow's external-TI tests passed (8/8) and BFF/staging contract tests passed (10/10); the production build passed with `npm run build -- --webpack`. The full Dashboard suite reported 815 passed, 5 failed, 2 expected failures, and 14 skipped (74 files). The five failures are in filesystem-topology empty states, filesystem CWD/path-interest presentation, and a session-command route status assertion; they are outside the changed files and were not investigated as part of this UI fix. The default Turbopack build could not run in this local linked-dependency setup because Turbopack rejects the external `node_modules` symlink; this is not a clean CI checkout.
- Not performed / deferred: authenticated browser visual review, default-Turbopack build in a clean dependency installation, resolution of the unrelated full-suite failures, and confirmation of the staging CI/CD result.
- Risks and data handling: presentation-only; event data, server behavior, policies, and response authority are unchanged. No session payloads or secrets were added.
- Rollback: revert the UI commit on the staging branch; no host or data rollback is required.
- Follow-up: inspect the staging workflow result and review the event alignment and collapsed technical-detail sections in an authenticated browser.
- Related ADR/runbook: N/A; no operating procedure or architecture decision changed.

### 2026-09-27 — Restore session classification filtering and structure provider intelligence

- Status: repository Dashboard UI correction prepared in an isolated worktree; not pushed or deployed.
- Scope and intent: restore the existing SSH attacker-type filter after unifying protocol browsing, tighten approximate-origin map framing, and make external provider evidence scannable without changing its source contract.
- Repository branch and commit/PR: detached worktree based on staging commit `b30a7e49`; follow-up commit and PR pending.
- Repository changes: expose the existing server-side attacker types (`APT`, `Bot`, `ScriptKiddie`) only in the SSH view and pass the selected value through the directory and export APIs; do not invent a Telnet protocol distinction absent from the current directory projection. Set single-origin and clustered multi-origin map zoom caps to regional scale. Replace paragraph-heavy external-TI cards with provider-specific metadata panels, keep the provider summary outside a 620px-bounded results viewport, retain allowlisted provider fields and collapsed provenance details, and distinguish provider errors from lookups that were not executed. Add/adjust focused regression tests.
- Host/environment changes actually applied: none. No backend, API/schema, MongoDB, provider request, GCP service, or production configuration was changed. A temporary dependency symlink used for local checks was removed automatically after validation.
- Runtime/exposure state: these changes exist only in the isolated repository worktree. They are not active on staging or production; the configured CI/CD behavior has not been triggered for this follow-up.
- Validation performed and outcome: focused map, session-directory, and session-analysis presentation tests passed (26/26); Dashboard `tsc --noEmit`, ESLint on changed source/tests, and `git diff --check` passed. No production build or authenticated browser review was performed.
- Not performed / deferred: no push, CI/CD run, staging/production deployment, map screenshot review, live session/API check, or full Dashboard test suite was performed.
- Risks and data handling: the map's automatic view now starts closer (8x) while retaining approximate-geolocation semantics and a manual reset; provider records remain contextual and non-authoritative. Attacker-type values continue to use the backend's existing server-side filter and pagination. No secrets or raw request payloads were added.
- Rollback: revert the follow-up UI commit; no service, data, or backend rollback is needed.
- Follow-up: after an authorized staging push, inspect the Brazil/Korea regional maps, confirm the SSH filter returns the existing server-side results, and review AbuseIPDB/OTX/Shodan panels with fresh, stale, error, and unqueried data.
- Related ADR/runbook: N/A; presentation and existing filter wiring only; no operating procedure or architecture decision changed.

### 2026-09-28 — Clarify TTP counts and show one recommendation

- Status: staging UI change prepared in an isolated temporary checkout based on exact remote staging commit `f3af6609b84c3efe2e91bf8bcf25507995bc9dbc`; CI/CD deployment follows a push and is not claimed by this entry.
- Scope and intent: distinguish distinct trusted ATT&CK techniques from classified command events and replace the visible ranked TTP list with one advisory recommendation.
- Repository changes: add the count explanation beside Trusted observations; change the section and navigation to TTP recommendation; highlight only the leading server-owned weighted-voting candidate while listing other Model1 TTPs without priority labels or scores. Preserve the collapsed formula comparison and technical evidence. Add regression tests.
- Host/environment changes actually applied: none by this UI change. Pi/GCP Model2 V2 shadow-path activation is recorded separately in ADR-0008 and the Model2 worktree implementation log; this UI change does not alter backend logic, model, policy, MongoDB or service configuration.
- Runtime/exposure state: frontend still follows the existing staging CI/CD path; until the workflow completes, the live dashboard may retain the old TTP review order.
- Validation performed and outcome: two focused Vitest files passed 7/7, TypeScript `tsc --noEmit`, scoped ESLint and `git diff --check` passed in a clean npm dependency install.
- Not performed / deferred: full dashboard suite, authenticated browser review and confirmation of the staging CI/CD run. The screenshot's 2 trusted TTPs and 3 classified events are counts of different entities, not evidence of a counting defect.
- Risks and data handling: recommendation remains advisory, not trusted ATT&CK evidence, probability, confidence or response authorization. No secrets or raw payloads were added.
- Rollback: revert only this staging UI commit; no Pi/GCP or database rollback is involved.
- Follow-up: verify the staging build and check the live session page shows one Recommend badge, other Model1 techniques without rank labels, and the explicit 2-versus-3 count explanation.
- Related ADR/runbook: N/A; presentation-only.

### 2026-09-28 — Support dark mode in Session Analysis detail page

- Status: repository styling update completed on `edit-dashboard`; host/production deployment pending.
- Scope and intent: eliminate remaining white sections in the Session Analysis page (`/threat-intel/[id]`) during dark mode by replacing hardcoded Tailwind light classes with semantic theme tokens.
- Repository branch and commit/PR: `edit-dashboard`.
- Repository changes: update `dashboard-v2/src/app/(main)/threat-intel/[id]/page.tsx` to replace fixed `bg-[#F9FAFB]`, `bg-white`, `bg-slate-50`, `bg-slate-100`, `border-slate-200`, and `text-slate-800` classes with semantic theme tokens (`bg-surface`, `bg-surface-subtle`, `border-border`, `text-text`, `text-text-muted`, `text-text-subtle`, `var(--map-land)`).
- Host/environment changes actually applied: none. No host, systemd service, database, or production deployment was altered.
- Runtime/exposure state: local development update only; production Dashboard has not been deployed.
- Validation performed and outcome: `npx tsc --noEmit` passed with zero errors; targeted session and threat intelligence test suites (11 files, 62 passed tests) passed cleanly.
- Not performed / deferred: production Docker/staging rollout was deferred.
- Risks and data handling: purely presentational CSS class adjustments; no API contracts, data models, credentials, or telemetry boundaries are affected.
- Rollback: git checkout of `dashboard-v2/src/app/(main)/threat-intel/[id]/page.tsx`.
- Follow-up: verify visual presentation across both light and dark mode themes in the browser.
- Related ADR/runbook: `dashboard-v2/docs/PRODUCTION_THEME_DESIGN_SPEC.md`.

### 2026-09-28 — Guard fresh-Pi administrator SSH migration before Cowrie

- Status: repository implementation prepared; bounded dual-port rollback tested on the disposable Azure VM; no full cutover or Pi deployment.
- Scope and intent: let the fresh Wi-Fi installer choose an available administrator SSH port without relying on an operator remembering a manual migration, while keeping TCP 22 recoverable until the new route has been authenticated.
- Repository changes: add a target-side Ubuntu 24.04 `ssh.socket` helper and controller orchestration, port suggestion and collision checks, local access receipt, dual-port verification, timed cutover rollback, and installer routing through the confirmed new port. Update the fresh-install runbook and ADR-0015; add focused tests and validation record.
- Host/environment changes actually applied: on the disposable Azure ARM64 VM only, copied the helper and briefly opened SSH on 22 and 2222. Controller access to 2222 timed out; the helper and then the new controller orchestration each rolled back through 22 during bounded tests. A final probe showed the VM back in fresh SSH state with 22 active. No firewall or cloud security rule was changed.
- Runtime/exposure state: no active Pi or production service was changed. The VM remains accessible on administrator SSH 22. No Cowrie service was started by this test.
- Validation performed and outcome: the installer suite passed with `PYTHONPATH=.` (42 tests and five subtests), as did Python compilation and whitespace checks. The VM's blocked new-port case demonstrated safe rollback before Cowrie activation. An initial `pytest` invocation without repository `PYTHONPATH` failed collection for three existing imports; the corrected run passed.
- Not performed / deferred: successful port cutover, actual timed rollback expiry, Wi-Fi Pi activation, end-to-end installation, and console recovery drill remain untested.
- Risks and data handling: external firewall or router policy can block an apparently free local port, so controller authentication is mandatory before cutover. The receipt stores only inventory path and port, with owner-only file permissions; it stores no SSH key or credential.
- Rollback: before cutover, the target helper removes its managed SSH drop-in and restores port 22. During cutover, a 150-second systemd timer is armed and cancelled only after the new route is confirmed. Console recovery remains the last resort if host or controller fails during a network change.
- Follow-up: validate a successful cutover and timeout rollback on a console-accessible clean host with its management port allowed, then test the full installer and Cowrie bind to 22.
- Related ADR/runbook: [ADR-0015](adr/ADR-0015-fresh-pi-local-decoys.md), [fresh Pi installation](../deploy/ansible/README.md), and [bounded validation](validation/2026-09-28-admin-ssh-cutover.md).

### 2026-09-28 — Withdraw automatic administrator SSH migration

- Status: automatic migration removed from the working tree before commit at the operator's request; the earlier entry remains as an audit record of the bounded experiment.
- Scope and intent: avoid changing the administrator's SSH route automatically during fresh-Pi installation.
- Repository changes: remove the proposed controller and target migration helpers and their focused tests; restore the existing fresh installer, runbook, and ADR-0015 contract. Cowrie remains configured for TCP 22/23 on a real Wi-Fi Pi; the installer still requires a separately established administrator SSH route and refuses a port collision.
- Host/environment changes actually applied: removed the copied migration helper from the disposable Azure VM and the controller's local test receipt. The VM had no managed SSH drop-in or migration marker, and `ssh.socket` was active with effective TCP port 22. No Pi service was changed.
- Runtime/exposure state: the Azure VM remains on administrator SSH 22. The active Pi and its Cowrie configuration were not changed by this withdrawal.
- Validation performed and outcome: read-only VM checks confirmed active `ssh.socket`, effective port 22, and absence of the managed drop-in and marker before removing the dormant helper. The remaining installer suite passed (38 tests and five subtests), and `git diff --check` passed.
- Not performed / deferred: no Cowrie port change or full clean-Pi installation was performed. Whether the fresh Pi should use Cowrie's upstream high ports instead of the project's 22/23 policy remains a separate decision.
- Risks and data handling: a fresh Pi with real SSH occupying 22 will stop at the existing Cowrie collision gate until its operator establishes a separate route or changes the decoy port policy. No credential or private config contents were copied into the repository.
- Rollback: not applicable to the withdrawn code. The earlier VM dual-port experiment was already rolled back before this addendum.
- Follow-up: decide whether to keep the existing 22/23 decoy exposure contract or explicitly move Cowrie and Zeek to high ports for the fresh-Pi profile.
- Related ADR/runbook: [ADR-0015](adr/ADR-0015-fresh-pi-local-decoys.md), [fresh Pi installation](../deploy/ansible/README.md), and [historical validation](validation/2026-09-28-admin-ssh-cutover.md).

### 2026-09-28 — Default fresh-Pi Cowrie and Zeek to high ports

- Status: repository change prepared; no host deployment.
- Scope and intent: let a developer install the fresh Wi-Fi profile while administrator SSH stays on TCP 22, and leave well-known decoy exposure as a separate reviewed change.
- Repository changes: set the reviewed Wi-Fi example and Ansible defaults to Cowrie SSH/Telnet TCP 2222/2223 and matching Zeek capture ports; continue deriving `ALLOW_RESP_PORTS` from those vars. Remove the wrapper's hard-coded Wi-Fi 22/23 requirement while keeping distinct valid TCP ports and exact Cowrie/Zeek agreement. Update the installer runbook, current architecture, ADR-0015, and focused validation tests.
- Host/environment changes actually applied: none. No Pi, disposable VM, firewall, SSH daemon, Cowrie listener, or Zeek process was changed for this port-default update.
- Runtime/exposure state: the active Pi still uses its existing Cowrie and Zeek 22/23 configuration and separate administrator SSH route. The revised 2222/2223 defaults apply only to a future fresh installation using the updated reviewed vars.
- Validation performed and outcome: validation commands and results are recorded after this entry once complete.
- Not performed / deferred: no full fresh-Pi installation, live 2222/2223 listener check, Wi-Fi capture check, or public 22/23 exposure migration was performed.
- Risks and data handling: the high-port profile will not receive scans aimed only at 22/23. A reviewed vars change to 22/23 still requires an alternate administrator route and listener checks before first activation; the same-release retry refuses an active Cowrie port change. No private values were added to the repository.
- Rollback: restore the prior reviewed vars and matching Cowrie/Zeek defaults before deploying a fresh host; existing Pi services are unaffected.
- Follow-up: test the high-port profile end to end on a clean Pi and write a separate, console-backed exposure procedure if the developer elects to move Cowrie to 22/23.
- Related ADR/runbook: [ADR-0015](adr/ADR-0015-fresh-pi-local-decoys.md), [fresh Pi installation](../deploy/ansible/README.md), and [current architecture](CURRENT-ARCHITECTURE.md).

### 2026-09-28 — Validate fresh-Pi high-port defaults

- Status: validation addendum to the repository-only port-default change above; no host deployment.
- Repository changes: add a reproducible validation record; no further runtime code change in this addendum.
- Host/environment changes actually applied: none. The active Pi and disposable VM were not modified for these checks.
- Runtime/exposure state: repository defaults for future fresh installs are Cowrie and Zeek TCP 2222/2223; the active Pi retains its previously deployed 22/23 listeners and capture policy.
- Validation performed and outcome: `PYTHONPATH=. pytest -q tests/installer` passed (39 tests, five subtests); syntax checks passed for the three affected Ansible playbooks; Python compilation, example JSON parsing, and `git diff --check` passed. The Ansible syntax check used a localhost inventory with no `pi_sensors` host, so it produced a non-fatal host-pattern warning and ran no tasks.
- Not performed / deferred: no fresh-Pi activation, live listener/capture verification, or migration of the active Pi.
- Risks and data handling: high-port decoys do not attract scans addressed only to well-known 22/23. The tested override accepts reviewed matching ports before first install but does not prove an in-place migration. No private configuration or credentials were inspected or recorded.
- Rollback: revert the repository port-default change before a fresh deployment if needed; no host rollback applies.
- Follow-up: run a clean Wi-Fi Pi end-to-end test with the approved release and confirm Cowrie listeners, Zeek filter, and SSH administrator access.
- Related ADR/runbook: [ADR-0015](adr/ADR-0015-fresh-pi-local-decoys.md), [fresh Pi installation](../deploy/ansible/README.md), and [validation record](validation/2026-09-28-fresh-high-port-defaults.md).

Additional validation on 2026-09-28: a local Zeek policy render with ports 2222/2223 produced source and destination filter terms for both ports. The temporary file was removed; no service was started or changed.

### 2026-09-29 — Recheck manifest bytes in fresh installer preparation

- Status: repository fix prepared during a clean Azure ARM64 VM installation rehearsal; full installation remains in progress.
- Scope and intent: make the second manifest integrity check operate on the exact file bytes rather than a Jinja-loaded text value.
- Repository changes: use delegated `stat` with SHA-256 on the controller's `manifest.json`, require a regular non-symlink file and the approved digest, then load the JSON metadata. The prior Python release verification and target-side installed-file audit remain in place.
- Host/environment changes actually applied: on the newly reimaged disposable VM, cloned repository commit `1086c6d`, refreshed apt indexes, installed Ubuntu `ansible-core`, and built a reviewed ARM64 Go release plus Cowrie and decoy source bundles outside Git. The first full installer attempt stopped at the manifest assertion before any Ansible host mutation. No Pi or production host was changed.
- Runtime/exposure state: VM administrator SSH remains on TCP 22; no Cowrie, Zeek, Docker decoy, Redis, Go agent, or B2 backup service was activated by the failed attempt.
- Validation performed and outcome: the approved release passed the Python verifier, but Ansible 2.16's Jinja text hash assertion rejected the same manifest. Syntax and repeated installation checks follow in a dated addendum.
- Not performed / deferred: full prepared-state audit, blank-env pause, service activation, and end-to-end telemetry remain untested at this point.
- Risks and data handling: the manifest contains release metadata but no runtime secrets. Build artifacts and reviewed non-secret vars are outside the repository; no credential value was copied into logs or documentation.
- Rollback: revert the repository assertion change if necessary; no host rollback applies to the failed preparation attempt.
- Follow-up: pull the fix into the VM checkout and rerun the same approved release and vars.
- Related ADR/runbook: [fresh installation runbook](../deploy/ansible/README.md) and [ADR-0009](adr/ADR-0009-installer-operator-managed-credentials.md).

### 2026-09-29 — Accept Ansible-native manifest metadata during preparation

- Status: repository compatibility fix prepared during the same clean VM rehearsal; service activation remains pending.
- Repository changes: accept the approved manifest metadata as a mapping when Ansible already converts the JSON lookup result, while still parsing it when it remains a string.
- Host/environment changes actually applied: none from the second installer attempt. The VM passed file-byte SHA-256 verification and stopped at the manifest parsing task before package or service mutation.
- Runtime/exposure state: administrator SSH remains on TCP 22; no project service was activated.
- Validation performed and outcome: a minimal Ansible 2.16 playbook showed the file lookup stored through `set_fact` had type `dict`, and `from_json` on that value raised a type error. Rerun validation follows in a dated addendum.
- Not performed / deferred: the preparation and audit playbooks, env pause, and activation had not completed when this entry was written.
- Risks and data handling: the manifest is non-secret release metadata. No private env value was read or recorded.
- Rollback: revert this mapping-aware expression if it causes a compatibility regression; the failed VM attempt made no project host change.
- Follow-up: pull the fix to the VM and rerun the same approved release and vars.
- Related ADR/runbook: [fresh installation runbook](../deploy/ansible/README.md).

### 2026-09-29 — Rehearse fresh installer on reimaged Azure ARM64 VM

- Status: full-stack preparation installed on a disposable VM; activation paused for operator credentials.
- Scope and intent: follow the documented clone, artifact build, reviewed vars, and one-command installation flow on a newly reimaged host.
- Repository branch and commit/PR: `main`; this validation and runbook addendum follows compatibility fixes `bb7cf7e` and `a6bba68`.
- Repository changes: add same-host VM controller prerequisites and private credential pause instructions to the fresh-install runbook; add a bounded validation record and index links. No runtime behavior changed in this addendum.
- Host/environment changes actually applied: cloned the repository, refreshed apt indexes, installed `ansible-core` and the installer-approved packages, built reviewed ARM64 Go/Cowrie/sanitizer/decoy artifacts outside Git, staged release files and blank private env files, and staged Cowrie, Zeek, and Docker/Compose on the disposable VM. The existing Pi, Droplet, Dashboard, Atlas, and B2 were untouched.
- Runtime/exposure state: VM administrator SSH remained on TCP 22. Cowrie had no listener; Redis, Zeek, Docker, and all five Go units were inactive. The B2 backup unit remained disabled. The installer stopped before any fresh service activation.
- Validation performed and outcome: read-only host preflight/package audit/plan passed; approved release and source bundle checks passed. The full wrapper passed preparation/audit and exited with pause code 2 because `MONGO_URI` was absent. A same-command retry reported `FRESH_ENV_UNCHANGED` and paused at the same gate. Six actual private env files were root-owned and mode `0600`; a socket check showed no new project listener. The installer suite passed 39 tests and five subtests before this VM run.
- Not performed / deferred: filling private credentials, activation, synthetic event delivery, Atlas write/read, Dashboard login, Wi-Fi capture, and B2 upload/restore. The decoy password gate was not reached after the first env failure.
- Risks and data handling: the VM used isolated loopback capture in place of Wi-Fi and does not prove external decoy reachability. No private env content or credential value was printed, stored in Git, or included in the validation record.
- Rollback: stop the disposable VM or reimage it; no production rollback is involved. The staged project units are inactive and disabled.
- Follow-up: operator supplies test-scoped write-capable Mongo and PostgreSQL credentials in the VM's private env files, then rerun the same command and verify end-to-end telemetry. Keep B2 disabled until a new write-capable destination is provisioned.
- Related ADR/runbook: [ADR-0009](adr/ADR-0009-installer-operator-managed-credentials.md), [fresh installation runbook](../deploy/ansible/README.md), and [VM evidence](validation/2026-09-29-azure-arm64-fresh-installer.md).

### 2026-09-29 — Require hardware sample interval before fresh activation

- Status: repository fix prepared after the first credentialed activation attempt on the disposable Azure VM; host retest pending.
- Scope and intent: prevent the fresh installer from passing its env gate while the hardware agent lacks its mandatory sample interval.
- Repository changes: add `NETWORK_SAMPLE_SECONDS` to the hardware env example, fill a blank value with the documented one-second default, require a positive integer in the redacting env check, and add a regression test and runbook note.
- Host/environment changes actually applied: the credentialed VM run activated Zeek, Cowrie, and the localhost PostgreSQL/Core/Web-corp Compose stack. Go activation reached the hardware agent, which exited because `NETWORK_SAMPLE_SECONDS` was missing; the playbook stopped and disabled all newly started Go units and Redis. No Pi or production service was changed.
- Runtime/exposure state: on the disposable VM, SSH remains on TCP 22; Cowrie listens only on loopback TCP 2222/2223, Web-corp/Core/PostgreSQL bind only to loopback, and Zeek and Docker are active. The Go and Redis units remain inactive after rollback; B2 backup remains disabled.
- Validation performed and outcome: the value-redacted private env checks initially passed, exposing the missing-key gap. The hardware journal named the missing key without a credential value. Focused installer tests passed 10/10; Python compilation and whitespace checks passed.
- Not performed / deferred: the fixed script has not yet been pulled into the VM, full Go activation, MongoDB connectivity and writes, telemetry end to end, Wi-Fi capture, Dashboard, and B2 were not tested at this entry.
- Risks and data handling: the fix preserves nonblank operator values. Runtime env contents and credentials were not copied into Git or the implementation record. The VM test decoys are bound only to loopback.
- Rollback: revert the repository fix if necessary; stop the disposable VM's active Cowrie, Zeek, and Compose stack to return it to an inactive state. No production rollback applies.
- Follow-up: pull the fix on the VM and rerun the same installer with the same reviewed release and vars, then verify service state and a synthetic event.
- Related ADR/runbook: [fresh installation runbook](../deploy/ansible/README.md), [hardware agent](../agents/hardware-agent/README.md), and [VM validation](validation/2026-09-29-azure-arm64-fresh-installer.md).

### 2026-09-29 — Share fresh Web-corp spool with the collector identity

- Status: repository activation fix prepared after a credentialed disposable-VM run; host retest pending.
- Scope and intent: let the fresh collector drain Web-corp's private pending login files while retaining mode-`0600` files and mode-`0700` spool directories.
- Repository changes: resolve the prepared `pti-agent` UID/GID, assign only the fresh Web-corp spool tree to that identity, and apply a generated Compose user override to every activation/rollback Compose command. Update the fresh installer and decoy runbooks and ADR-0015. The reviewed decoy source bundle and existing Pi Compose files remain unchanged.
- Host/environment changes actually applied: the previous VM retry filled the hardware sample interval and activated Cowrie, Zeek, Redis, all four core Go units, and the localhost PostgreSQL/Core/Web-corp stack. A post-start collector log reported permission denied while scanning the root-only Web-corp spool. The new override had not been applied at this entry.
- Runtime/exposure state: the disposable VM's core units and localhost decoys were active after the retry; B2 backup remained inactive and disabled. Administrator SSH stayed on TCP 22; Cowrie SSH/Telnet and all decoy HTTP/database listeners bound only to loopback.
- Validation performed and outcome: the fresh installer returned `ACTIVE`, all four core Go units plus Redis/Cowrie/Zeek/Docker were active and enabled, Web-corp returned HTTP 200, and socket checks showed only loopback project listeners. The collector spool denial means Web-corp login telemetry was not yet qualified end to end. Ansible syntax and VM retest of the new override follow separately.
- Not performed / deferred: non-root Web-corp startup, spool drain, Redis/Mongo event persistence, Dashboard login, Pi Wi-Fi behavior, and B2 transfer were not tested for this fix at this entry.
- Risks and data handling: fresh Web-corp and collector share only the pending-login spool identity. The override contains numeric IDs, not credentials. Pending login payloads were not read or copied into Git. The existing Pi's external Compose is untouched.
- Rollback: on the disposable VM, stop its fresh Compose stack and Go collector before removing the generated override or changing spool ownership. No production host rollback applies.
- Follow-up: pull the activation fix to the VM, run the same installer, verify the Web-corp container identity and collector spool access, then send one synthetic login and confirm a single canonical event.
- Related ADR/runbook: [ADR-0015](adr/ADR-0015-fresh-pi-local-decoys.md), [fresh installation runbook](../deploy/ansible/README.md), and [Web-corp data access](../integrations/web-corp/DATA-ACCESS.md).

### 2026-09-29 — Align fresh Cowrie and Zeek logs with the collector

- Status: repository fix prepared after synthetic loopback checks on the disposable VM; host retest pending.
- Scope and intent: make the fresh collector able to read Cowrie's sanitized JSON log and parse Zeek's connection events.
- Repository changes: permit the `cowrie` group to traverse only Cowrie's log directory while retaining owner-only private state and group-readable `cowrie.json`; load Zeek's packaged JSON logging policy and restart Zeek when the policy is first added. Update the fresh runbook and ADR-0015.
- Host/environment changes actually applied: before this fix, one synthetic Web-corp login was accepted, drained from the private spool into Redis, and found as one matching canonical MongoDB event. A synthetic loopback SSH banner exchange reached Cowrie; its log grew and Zeek wrote `conn.log`, but Redis had no Cowrie or Zeek connection entry. No Pi or production host was changed by the proposed log fix.
- Runtime/exposure state: the disposable VM's core services and localhost decoys remained active; B2 was inactive. Cowrie's existing log directory was mode `0700`, blocking the collector despite its `cowrie` group membership. Zeek's `conn.log` was in default ASCII form and the collector rejected it as invalid JSON.
- Validation performed and outcome: a host permission probe showed `pti-agent` could not read Cowrie's JSON log; `namei` identified the blocking directory. The collector journal reported invalid JSON for Zeek `conn.log`. The Web-corp canonical-event probe returned one matching record without reading or printing payloads.
- Not performed / deferred: retest of group-readable Cowrie logs, JSON Zeek output, their Redis/Mongo ingestion, physical Wi-Fi capture, Dashboard, and B2 transfer.
- Risks and data handling: the log contains sanitized Cowrie output but may still include attacker activity; it remains readable only to owner and the explicit group. No raw log lines, attacker payloads, private env contents, or credentials were copied into Git.
- Rollback: restore the prior Cowrie log-directory mode and remove the Zeek JSON policy load on the disposable VM if needed; no production rollback applies.
- Follow-up: pull the fix to the VM, rerun the same installer, and verify one bounded Cowrie/Zeek event traverses the collector and processor.
- Related ADR/runbook: [ADR-0015](adr/ADR-0015-fresh-pi-local-decoys.md), [fresh installation runbook](../deploy/ansible/README.md), and [VM validation](validation/2026-09-29-azure-arm64-fresh-installer.md).

### 2026-09-29 — Complete bounded fresh-stack VM acceptance

- Status: the full fresh installer and bounded telemetry paths are active on the disposable Azure ARM64 VM; physical Pi and B2 acceptance remain open.
- Scope and intent: retest the credentialed fresh installer after hardware interval, Web-corp spool, Cowrie log, and Zeek JSON fixes.
- Repository branch and commit/PR: `main` at `2341488` for the tested installer; this addendum records its observed VM result.
- Repository changes: add the final VM activation evidence and update the fresh runbook's qualification status. No new runtime code change in this addendum.
- Host/environment changes actually applied: pulled `2341488` to the reimaged VM, reran the same installer with the same reviewed release and private values already entered by the operator, and sent bounded localhost Web-corp and Cowrie test traffic. Synthetic canonical records were written to the operator-configured MongoDB destination. Existing Pi and Droplet services were not changed.
- Runtime/exposure state: Cowrie, Zeek, Redis, four core Go units, Docker, PostgreSQL, Deception Core, and Web-corp were active on the VM. Web-corp/Core/PostgreSQL/Redis and Cowrie's test ports were loopback-bound. Administrator SSH stayed on TCP 22. B2 backup control remained inactive and disabled.
- Validation performed and outcome: installer returned `ACTIVE`; Web-corp HTTP returned 200; a synthetic login drained from the private spool through Redis and had one matching canonical MongoDB event. A bounded Cowrie SSH banner exchange produced collector/Zeek JSON events; Redis held Cowrie and Zeek connection records, and count-only MongoDB queries found VM-sensor canonical events from both sources. The last five-minute Go journal check had no permission-denied, invalid-JSON, or MongoDB error messages.
- Not performed / deferred: reboot persistence, physical `wlan0` traffic capture, public exposure, Dashboard authentication, non-synthetic traffic, B2 upload/restore, and a broad data-retention audit.
- Risks and data handling: the synthetic records remain in the operator-configured MongoDB destination. The host is a loopback-capture VM and does not prove physical Pi behavior. Neither credentials nor event payloads were printed or copied into Git.
- Rollback: stop the disposable VM or its fresh project services if the rehearsal is no longer needed; no production service rollback applies. Synthetic records in MongoDB require a separate reviewed cleanup if desired.
- Follow-up: accept the same release on physical Pi `wlan0`, verify reboot/capture/listener behavior, and separately provision and test a new B2 write destination before backup opt-in.
- Related ADR/runbook: [ADR-0015](adr/ADR-0015-fresh-pi-local-decoys.md), [fresh installation runbook](../deploy/ansible/README.md), and [activation evidence](validation/2026-09-29-azure-arm64-fresh-activation.md).

### 2026-09-29 — Stop the disposable VM after fresh-stack acceptance

- Status: stopped and disabled on the disposable Azure ARM64 VM.
- Scope and intent: prevent the test VM from continuing to send events to the same configured MongoDB destination as the existing Pi.
- Repository branch and commit/PR: `main`; documentation addendum, commit pending at entry time.
- Repository changes: append this shutdown record and a post-test addendum to the VM activation evidence; no runtime code or configuration changed in the repository.
- Host/environment changes actually applied: stopped and disabled the VM's five honeypot Go units, Cowrie, Zeek, Redis, Docker service/socket, and containerd. Set the three fresh-stack containers' restart policies to `no` and stopped them. The existing Pi was not changed.
- Runtime/exposure state: all eleven checked VM systemd units are `inactive` and `disabled`. The fresh-stack containers were stopped. The checked project TCP listeners are closed; administrator SSH remains available on TCP 22. B2 backup control is among the disabled units.
- Validation performed and outcome: checked systemd active and enabled states for all eleven units and checked listening TCP sockets for the project's service ports. Only TCP 22 remained in that port check.
- Not performed / deferred: VM reboot persistence and a later MongoDB count query were not tested. Existing synthetic records in the configured MongoDB destination were not removed.
- Risks and data handling: private credentials remain on the VM for a future operator-controlled retest; disabled units must be deliberately restarted before they can write again. No credential or event payload was copied into this record.
- Rollback: explicitly re-enable and start the reviewed VM services only for a new isolated test after confirming the destination and sensor identity; do not start this VM alongside the existing Pi against a shared write destination.
- Follow-up: use a separate test MongoDB destination for any future VM acceptance or keep the VM stack stopped.
- Related ADR/runbook: [fresh installation runbook](../deploy/ansible/README.md) and [VM activation evidence](validation/2026-09-29-azure-arm64-fresh-activation.md).

### 2026-09-29 — Compare daily backup coverage across all archive sources

- Status: repository change prepared; no host deployment.
- Scope and intent: make daily archive health comparable for hardware, threat events, and filesystem audit in one overview before the hardware-specific controls and longer history.
- Repository branch and commit/PR: `main` working tree; commit pending at entry time.
- Repository changes: include each target's current eligible-day manifest states in the backup targets API, show an aligned daily status strip in every active source row, count completed manifest checks separately from archived B2 days, and place the cross-source overview before the hardware detail card. Update the Dashboard API contract and targeted coverage test. No worker or schedule logic changed.
- Host/environment changes actually applied: none. No Dashboard deployment, Pi service, MongoDB data, schedule revision, or B2 object was changed.
- Runtime/exposure state: the existing Pi backup worker and stored schedule are unchanged. The new comparison appears only where this Dashboard code is run.
- Validation performed and outcome: TypeScript check and targeted hardware-backup tests passed locally; no authenticated browser review was performed.
- Not performed / deferred: production Dashboard deployment, browser visual review, and live Pi or B2 verification.
- Risks and data handling: only bounded manifest metadata already used by the overview is returned; no archive contents or credentials are added. The detailed older-history pager remains hardware-specific.
- Rollback: revert this Dashboard/API presentation change; no host rollback applies.
- Follow-up: review the three aligned strips with live data in a browser and decide whether older-history navigation should be offered for the other targets.
- Related ADR/runbook: [Dashboard API contract](../dashboard-v2/docs/API.md) and [backup schedule decision](adr/ADR-0008-dashboard-backup-daily-schedule.md).

### 2026-09-29 — Activate daily archive comparison on Dashboard staging

- Status: active on Dashboard staging; production Dashboard was not deployed.
- Scope and intent: publish the three-source daily manifest comparison after its staging CI gate.
- Repository branch and commit/PR: main change `24ebbc8`; staging release commit `21bf51f`; GitHub Actions run `36519955587`.
- Repository changes: this dated deployment addendum only. The UI and API changes remain in the preceding implementation entry.
- Host/environment changes actually applied: the staging workflow transferred the immutable tested artifact, switched `/opt/honeypot-dashboard-v2-staging/current`, and restarted only `honeypot-dashboard-v2-staging.service`. The Pi worker, MongoDB records, B2 objects, and production Dashboard were not changed.
- Runtime/exposure state: the staging deploy wrapper reported success for release `21bf51f` with `rollback:false`; its post-switch health checks passed. The previous staging release was `d690c6f`.
- Validation performed and outcome: staging CI passed full Dashboard lint, TypeScript, external TI test, focused Python contracts, server build, artifact packaging, and artifact identity verification. The deploy job completed successfully and reported the exact commit and healthy staging service.
- Not performed / deferred: authenticated visual inspection of the three source strips, live-data comparison, and production Dashboard deployment.
- Risks and data handling: only bounded manifest metadata is added to the authenticated target overview. No archive content, private configuration, or credentials were copied into this record.
- Rollback: use the staging deployment wrapper's reviewed rollback procedure to restore the previous immutable release if a browser regression is found.
- Follow-up: inspect Backup & Retention in an authenticated staging browser and compare the three per-source day strips with manifest counts.
- Related ADR/runbook: [Dashboard staging runbook](../honeypot-analysis/deployment/dashboard-v2-staging/README.md) and [Dashboard API contract](../dashboard-v2/docs/API.md).

### 2026-09-29 — Consolidate Backup & Retention details under the source overview

- Status: repository UI change prepared; no host deployment in this entry.
- Scope and intent: reduce repeated hardware data and page length while keeping backup actions, older history, and operational evidence available on demand.
- Repository branch and commit/PR: `main` working tree; commit pending at entry time.
- Repository changes: render only schedule and three-source overview by default. Move the existing Hardware actions/history component into an expandable section under Archive sources, and put activity, recovery, and policy behind a second control. Preserve both existing APIs and the hardware exception path to its controls. Document the new page behavior in the Dashboard API guide.
- Host/environment changes actually applied: none. No staging or production Dashboard, Pi worker, MongoDB schedule, manifest, or B2 object was changed by this repository edit.
- Runtime/exposure state: the deployed staging Dashboard remains on the previous layout until its next release. Backup scheduling and archive execution remain unchanged.
- Validation performed and outcome: local TypeScript, targeted ESLint, and 10 focused Dashboard tests passed. Staging CI and browser review follow separately.
- Not performed / deferred: authenticated browser layout review, staging deployment, production Dashboard deployment, and live Pi/B2 interaction.
- Risks and data handling: controls and history now load only when opened; operators must expand that section to queue hardware actions. The overview still exposes attention count and per-target daily status. No protected data or credentials entered the repository.
- Rollback: revert this UI change and redeploy the prior Dashboard artifact; no Pi rollback applies.
- Follow-up: deploy to staging, verify controls and detail transitions in a browser, then assess whether production should receive this layout.
- Related ADR/runbook: [Dashboard API guide](../dashboard-v2/docs/API.md) and [staging runbook](../honeypot-analysis/deployment/dashboard-v2-staging/README.md).

### 2026-09-29 — Activate consolidated Backup & Retention layout on staging

- Status: active on Dashboard staging; production Dashboard unchanged.
- Scope and intent: publish the compact three-source overview with hardware and operational details available on demand.
- Repository branch and commit/PR: main UI commit `9a6ce76`; staging release `1c7fad6`; GitHub Actions run `36521414728`.
- Repository changes: append this deployment record only. The UI change and its test are in the preceding entry.
- Host/environment changes actually applied: staging CI/CD switched the immutable staging release and restarted `honeypot-dashboard-v2-staging.service`. The Pi worker, MongoDB state, B2 objects, and production Dashboard were not changed.
- Runtime/exposure state: the deploy wrapper reported service success for release `1c7fad6`, with `rollback:false`; its post-switch health check passed. The previous staging release was `21bf51f`.
- Validation performed and outcome: full staging CI passed lint, TypeScript, external TI test, focused Python contracts, Next.js build, artifact packaging, and artifact identity verification. The deployment job completed successfully.
- Not performed / deferred: authenticated browser visual inspection and production Dashboard deployment.
- Risks and data handling: actions require expanding Hardware details; the source overview retains attention count and daily status. No archive contents or credentials were copied into this record.
- Rollback: restore the prior immutable staging release through the reviewed staging deployment procedure if a browser regression is found.
- Follow-up: inspect the collapsed page, reopen Hardware actions/history, and confirm the operational detail panel in an authenticated staging browser.
- Related ADR/runbook: [Dashboard staging runbook](../honeypot-analysis/deployment/dashboard-v2-staging/README.md) and [Dashboard API guide](../dashboard-v2/docs/API.md).

### 2026-10-07 — Prepare public-safe runtime source curation

- Status: isolated source curation prepared; not yet pushed or deployed.
- Scope and intent: build a fast-forward candidate from the fetched upstream
  `main`, carrying reviewed runtime code and tests without publishing the
  local research/evaluation evidence corpus or host-state records.
- Repository branch and commit/PR: `codex/public-main-curation-20261007`;
  commit pending.
- Repository changes: include selected Dashboard, Model2, Next-Distinct,
  hypothesis/guidance, AI projection, storage, and backend bundle source;
  related policy/configuration and regression tests; and a minimal public-safe
  bundle README. GCP project/network values in examples are placeholders.
  The AI projection recognizes the reviewed V3 manual-guidance rule IDs while
  retaining manual-approval and no-auto-execution checks. Research/evaluation
  corpora, receipts, databases, PDFs/screenshots, detailed host-state logs, and
  network-specific Zeek configuration are excluded from this publication set.
- Host/environment changes actually applied: none. No VM, Pi, database,
  service, firewall, credential, or external endpoint was changed.
- Runtime/exposure state: unchanged; this is repository content only. No
  deployment or AI-provider activation is claimed.
- Validation performed and outcome: 30 selected Python test modules passed
  (618 passed, 11 expected failures); response-guidance and classification
  policy validators passed. The focused AI/guidance integration set passed
  (48 tests). Dashboard TypeScript and changed-file lint passed; the two
  Node-runner checks passed (3 tests). The complete Dashboard Vitest suite
  reported 853 passed, 4 failed, 1 expected failure, and 14 skipped; the four
  failures are in existing filesystem UI tests outside this curation scope.
- Not performed / deferred: live GCP/Pi validation, authenticated browser or
  staging/production checks, deployment, and a complete repository-wide or
  history-wide secret scan. GitHub publication is still pending.
- Risks and data handling: dedicated secret-scanner binaries were unavailable;
  heuristic checks are not proof of absence. This curation does not rewrite
  remote history or audit every file already present on upstream `main`.
  The complete previous local `main` remains preserved by a local archive ref.
- Rollback: revert the eventual curation commit; no host rollback applies.
- Follow-up: resolve the four unrelated Dashboard filesystem UI failures and
  re-check the remote `main` SHA immediately before any fast-forward push.

### 2026-09-29 — Unify archive calendar across three backup sources

- Status: repository change prepared; no host deployment in this entry.
- Scope and intent: show hardware rollups, threat events, and filesystem audit on the same UTC date grid instead of leaving the full calendar and older-history navigation tied to hardware only.
- Repository branch and commit/PR: `main` working tree; commit pending at entry time.
- Repository changes: add authenticated, bounded all-target backup history; move daily archive calendar and older/newer navigation into Archive sources; remove the duplicate hardware-only calendar and summary from the expandable hardware controls. Update the Dashboard API guide and focused tests.
- Host/environment changes actually applied: none. No Dashboard service, Pi worker, MongoDB records, schedule, or B2 object was changed by this repository edit.
- Runtime/exposure state: existing Dashboard deployments retain their previous UI until a release includes this change. Backup execution and stored manifests remain unchanged.
- Validation performed and outcome: TypeScript and targeted ESLint passed; focused test outcome is recorded with the commit.
- Not performed / deferred: authenticated browser visual inspection, live Pi/B2 checks, and production Dashboard deployment.
- Risks and data handling: historical gaps before source activation remain labeled missing; navigation is read-only and does not queue work. The API returns bounded manifest metadata and no archive contents or credentials.
- Rollback: revert the shared calendar UI and history endpoint, then redeploy the previous Dashboard artifact; no Pi rollback applies.
- Follow-up: inspect the three aligned rows with live staging data and verify older/newer navigation in an authenticated browser.
- Related ADR/runbook: [Dashboard API guide](../dashboard-v2/docs/API.md) and [Dashboard staging runbook](../honeypot-analysis/deployment/dashboard-v2-staging/README.md).

### 2026-09-29 — Activate shared three-source archive calendar on staging

- Status: active on Dashboard staging; production Dashboard unchanged.
- Scope and intent: publish a single date-aligned archive calendar and shared older-history navigation for hardware, threat events, and filesystem audit.
- Repository branch and commit/PR: main UI commit `ffead62`; staging release `0491ff3`; GitHub Actions run `36522587608`.
- Repository changes: append this deployment record only. The UI, API, and test changes are in the preceding entry.
- Host/environment changes actually applied: staging CI/CD switched the immutable staging release and restarted `honeypot-dashboard-v2-staging.service`. The Pi worker, MongoDB data, B2 objects, and production Dashboard were not changed.
- Runtime/exposure state: the deploy wrapper reported service success for release `0491ff3`, with `rollback:false`; its post-switch health check passed. The previous staging release was `1c7fad6`.
- Validation performed and outcome: 11 focused local tests, TypeScript, targeted ESLint, full staging CI, artifact identity verification, and deploy job passed.
- Not performed / deferred: authenticated browser visual inspection and production Dashboard deployment.
- Risks and data handling: calendar history is read-only and bounded to 36 earlier periods; target activation may leave earlier gaps. No archive contents or credentials were copied into this record.
- Rollback: restore the prior immutable staging release through the reviewed staging deployment procedure if a browser regression is found.
- Follow-up: inspect the aligned calendar and older/newer behavior in an authenticated staging browser.
- Related ADR/runbook: [Dashboard staging runbook](../honeypot-analysis/deployment/dashboard-v2-staging/README.md) and [Dashboard API guide](../dashboard-v2/docs/API.md).

### 2026-09-29 — Restore stronger archive calendar status colors

- Status: repository UI change prepared; host deployment recorded separately if performed.
- Scope and intent: make each daily status distinguishable at a glance in the shared three-source archive calendar.
- Repository branch and commit/PR: `main` working tree; commit pending at entry time.
- Repository changes: use stronger theme status tints and borders for calendar cells, add a matching status dot inside each populated cell, and replace the text-only calendar key with the existing five-color dot legend. Update the Dashboard API description.
- Host/environment changes actually applied: none in this repository change. No Pi worker, MongoDB manifest, B2 object, or backup schedule was changed.
- Runtime/exposure state: deployed Dashboards keep the prior colors until their next release; archive status data and classification are unchanged.
- Validation performed and outcome: targeted Dashboard test, TypeScript, and lint outcomes are recorded with the commit.
- Not performed / deferred: authenticated browser visual inspection and production Dashboard deployment.
- Risks and data handling: theme variables keep light/dark colors aligned; planned targets remain neutral without a status dot. No credentials or archive contents were added.
- Rollback: revert this presentation change and redeploy the previous Dashboard artifact; no worker rollback applies.
- Follow-up: inspect status contrast in both Dashboard themes with live data.
- Related ADR/runbook: [Dashboard API guide](../dashboard-v2/docs/API.md) and [Dashboard staging runbook](../honeypot-analysis/deployment/dashboard-v2-staging/README.md).

### 2026-09-29 — Activate stronger archive calendar colors on staging

- Status: active on Dashboard staging; Railway production revision not verified.
- Scope and intent: publish clearer status fills and matching dots in the shared three-source calendar.
- Repository branch and commit/PR: main UI commit `fb63409`; staging release `a6f63b3`; GitHub Actions run `36523409674`.
- Repository changes: append this deployment record only. The UI and API-guide edits are in the preceding entry.
- Host/environment changes actually applied: staging CI/CD switched the immutable staging release and restarted `honeypot-dashboard-v2-staging.service`. No Pi worker, MongoDB record, or B2 object was changed by this deployment.
- Runtime/exposure state: the staging deploy wrapper reported service success for release `a6f63b3`, with `rollback:false`; its post-switch health check passed. The previous staging release was `0491ff3`. Railway production deployment state was not observed.
- Validation performed and outcome: focused local Dashboard tests, TypeScript, targeted ESLint, full staging CI, artifact identity verification, and staging deploy job passed.
- Not performed / deferred: authenticated browser review in light/dark themes and verification of the Railway production revision.
- Risks and data handling: this changes only UI color and status markers. No archive contents, credentials, or private configuration were copied into this record.
- Rollback: restore the previous immutable staging release through the reviewed staging deployment procedure if a visual regression is found.
- Follow-up: inspect calendar status contrast in an authenticated browser and verify the production revision independently.
- Related ADR/runbook: [Dashboard staging runbook](../honeypot-analysis/deployment/dashboard-v2-staging/README.md) and [Dashboard API guide](../dashboard-v2/docs/API.md).

### 2026-10-07 — Publication and log-order addendum

- Status: source curation is published to GitHub `main`; this addendum is
  repository-only and does not describe a host deployment.
- Scope and intent: record the actual publication outcome and correct the
  placement of the preceding curation record.
- Repository branch and commit/PR: source curation commit
  `3a3b2f8ace48ba732f1f508b81fce76f22489dc7` was pushed to
  `origin/main` as a fast-forward from `8ff7c99c7ea2614a3ec1325274a6ba36545707f1`.
  No force-push or history rewrite was used.
- Repository changes: this addendum only. The earlier 2026-10-07 curation
  entry remains unchanged but was inserted before EOF because its patch matched
  a repeated line; this entry is the chronological EOF correction and records
  the completed push.
- Host/environment changes actually applied: none. No GCP VM, Pi, database,
  service, firewall, credential, or external endpoint was changed.
- Runtime/exposure state: unchanged; publication did not deploy or activate
  the code.
- Validation performed and outcome: post-commit backend/policy integration
  tests passed (149); the selected Python suite passed (618, with 11 expected
  failures); the complete Dashboard suite retained four failures in existing
  filesystem UI tests. TypeScript, targeted lint, policy validators, and the
  new Node checks passed.
- Not performed / deferred: live host, browser, staging, or production
  validation; full-history secret scanning; deployment.
- Risks and data handling: publication was limited to the curated commit and
  did not rewrite already-published history. Heuristic checks are not proof
  that every pre-existing upstream file is free of sensitive content.
- Rollback: revert the source curation commit and this addendum; no host
  rollback applies.
- Follow-up: resolve the four existing Dashboard filesystem UI failures and
  complete live qualification before any deployment.

### 2026-10-07 — Remote branch content review

- Status: branch-by-branch source review complete; no runtime code or host
  deployment in this entry.
- Scope and intent: inspect remote branches after curated `main` publication,
  decide which unique changes remain necessary, and explain why the GitHub
  branch list does not change when only `main` advances.
- Repository branch and commit/PR: review baseline `origin/main`
  `89eb8cd141f556bc044ae16e64143283c5eb5ea8`; audit note added on the current
  `main` line.
- Repository changes: add
  [the remote branch review](validation/2026-10-07-remote-branch-review.md)
  and link it from the validation index. Of 43 actual remote refs including
  `main`, 11 non-main heads had unique commits and were individually reviewed;
  31 other non-main heads were already ancestors of `main`. Useful code from
  selected old branches had already been ported to the published source
  curation commit. No branch pointer was moved and no branch or commit was
  deleted.
- Host/environment changes actually applied: none. No GCP VM, Pi, Dashboard,
  database, network, credential, or external service was changed.
- Runtime/exposure state: unchanged. The review did not deploy or activate
  code. GitHub continues to display the branch refs and their ahead/behind
  counts because selectively publishing code to `main` does not merge or
  repoint those refs.
- Validation performed and outcome: fetched remote refs without pruning;
  compared reachability and reviewed unique patches, source, and tests; checked
  that the 31 non-main contained heads are ancestors of the recorded `main`
  snapshot. Documentation links and whitespace are checked with this commit.
- Not performed / deferred: no code test suite was rerun for this
  documentation-only audit; prior curation test results remain recorded in
  the preceding publication entry. No live staging/production test, full
  history secret scan, branch deletion, or branch repointing was performed.
- Risks and data handling: the very large PoC branch was not merged because it
  includes databases, logs, and historical artifacts. No secret values,
  raw sessions, or database contents were copied into this report.
- Rollback: revert this documentation/index/log commit; no host rollback
  applies. The append-only log must be corrected with a dated addendum rather
  than silently rewritten.
- Follow-up: keep branch refs for traceability. Consider archival/deletion
  only as a separately authorized action after checking pull requests and
  retention needs; port any future required code as a focused change against
  current `main`.

### 2026-10-07 — Reconcile dashboard freshness on the public-main candidate

- Status: prepared on an isolated candidate branch; not deployed to a host.
- Scope and intent: keep Filesystem Activity and Threat Feed snapshots current
  when SSE remains open but quiet, show late session-analysis/advisory results,
  and disclose when the bounded hypothesis projection omits additional sets.
- Repository branch and commit/PR: `codex/public-main-20261007`, based on the
  fetched `origin/main` snapshot `47e0913f89cc0a11a63eb7f9b7a21cd238b4cfc1`;
  the focused source commit is created with this entry.
- Repository changes: update the dashboard stream reconciliation and
  session-detail refresh, bound the public hypothesis projection at 50 with a
  truncation flag, add regression tests and current-state documentation, and
  link those dashboard documents from this index. The fetched main already
  contained the reviewed hypothesis-family policy; that policy was preserved.
  The separate local research corpus, old VM migration/AI-provider work, and
  unrelated local-only history were not copied into this candidate.
- Host/environment changes actually applied: none. Dependencies were installed
  from the lockfile in isolated local checkouts; no VM, Pi, database, service,
  firewall, credential, or external endpoint was changed.
- Runtime/exposure state: no host runtime changed. This candidate is not active
  until a separately performed deployment.
- Validation performed and outcome: focused dashboard tests passed (59); the
  relevant backend contract/guidance tests passed (50); the three dedicated
  Node test scripts passed (11); ESLint, `npx tsc --noEmit`, and the webpack
  production build passed. The complete Vitest run had 861 passes, 4 existing
  filesystem UI assertion failures, 1 expected failure, and 14 skipped tests.
- Not performed / deferred: authenticated browser, staging/production,
  live-session, and host deployment verification. The four existing UI test
  failures remain open and must be resolved before claiming the complete suite
  passes.
- Risks and data handling: polling is bounded and limited to exact session
  detail; truncation is disclosed instead of silently implying completeness.
  No credentials, raw attacker data, or research database artifacts were
  added.
- Rollback: revert the focused source commit; no host rollback applies because
  no host was changed.
- Follow-up: resolve the four existing filesystem UI test failures and perform
  authenticated staging/browser verification before deployment.
- Related ADR/runbook: [Dashboard data semantics](../dashboard-v2/docs/DATA_SEMANTICS.md),
  [real-time CWD tracking](../dashboard-v2/docs/REALTIME_CWD_TRACKING.md), and
  [Dashboard staging runbook](../honeypot-analysis/deployment/dashboard-v2-staging/README.md).
