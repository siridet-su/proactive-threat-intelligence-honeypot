# Current production state (repository-recorded)

This is a bounded snapshot, not a substitute for the private resource inventory,
release manifests, storage receipts, or live health checks. Exact public and
private addresses, overlay identities, SSH principals/keys, firewall sources,
and secret locations belong only in the owner-controlled inventory.

## Active production target

Read-only SSH verification on 2026-10-08 confirmed the active VM hostname is
`capstone`. Its current release and the repository candidate are different:

| Boundary | Verified state |
| --- | --- |
| Active release | `dcaa63b606da637a41b78e6c123a2df62d63de56` |
| Runtime-code candidate on `main` | `d391ccb503520c6a4d9259f4e9e8626b818004fb`; not installed on the VM |
| Private ingest route | Bound to the private overlay; exact endpoint is in the owner-only inventory |
| Canonical storage | MongoDB epoch selected by the reviewed 8.0.34 receipt |
| Report authority | `session_assessment.v4` and `response_guidance.v3`; guidance remains manual-only |
| Dashboard staging | Active on VM loopback `127.0.0.1:3001`; workstation SSH forward is available; production Dashboard remains disabled |

Do not use historical addresses or SSH examples from old receipts as current
selectors. The prior VM was reported by the owner as shut down to avoid cost;
that state was not independently queried through the GCP control plane, and it
is not a verified rollback target.

## Live checks and release boundary

The 2026-10-08 bounded host follow-up found all eight core backend services,
both Next-Distinct shadow services, and the observed Model2 v7 services active,
with zero failed systemd units. Ingest health returned 200 on its private
overlay binding; Dashboard API and monitor health returned 200 on their local
bindings. The AI advisory worker was inactive. The production GCP Dashboard
service remains stopped/disabled; after that earlier stop, the staging service
was enabled for operator access and is active only on VM loopback
`127.0.0.1:3001`. Workstation access uses an SSH local forward bound to
`127.0.0.1`; no public listener or firewall rule was added. Staging's
HTTP-cookie opt-in is limited to that loopback-forwarded path, and its prior
environment file is retained in the root-only backup area. The recovery
watchdog timer remains stopped/disabled because its protected targets include
the Dashboard services; its program/configuration were not changed.

The repository managed-unit policy was revised to make the already-required
Next-Distinct shadow and feeder units explicitly required-enabled. The revised
`gcp_backend` policy passed a read-only inventory validation against the VM.
That validator scopes unknown enabled units to the `honeypot-` prefix; it does
not inventory the separate `model2-v7-*` services. Their presence and
configuration remain outside that policy's proof and still require an
independent reviewed runtime receipt. No backend release cutover, Model2
configuration change, or public network change was made.

The active release verifier rejects the preserved Model2 runtime-configuration
hash, and neither the active nor retained alternate release currently verifies
as a manifest-bound rollback target. The Model2 configuration was not changed.
The active release must remain in place until a successor release and rollback
release both verify, canonical MongoDB backup/restore is qualified, and the
independent Model2 runtime boundary is reviewed. The policy validation does not
qualify a release or substitute for those gates.

A new root-only backup and isolated restore of the epoch-bound SQLite rollback
mirror passed SHA-256, schema, table-count, `quick_check`, and full integrity
checks. This is not a backup of the canonical MongoDB data. A separate
provider-supported MongoDB backup and restore qualification remains required
before any cutover or database migration.

## Dashboard and stored-session smoke result — 2026-10-08

The workstation SSH forward to the staging UI was verified as loopback-only;
`GET /login` returned HTTP 200. An authenticated session/detail smoke returned
HTTP 200 and included Model1 classification evidence, trusted observations,
threat hypotheses, a Model1-led TTP recommendation, and a session-bound
Next-Distinct `PREDICTED/FINAL` result. Model2 was partial. This is a bounded
inspection of an existing record, not a fresh Cowrie end-to-end session.

The same report's Response Guidance was rejected as `invalid_stored_guidance`:
the stored record references policy 3.8.0, while the active runtime does not
resolve the exact policy needed to validate it. A read-only scan of local Git
refs found top-level policy revisions 3.7.0 and 4.0.0, but no exact 3.8.0
policy file. Its PDF route returned HTTP
503 (`pdf_render_failed`) because the assessment validator rejects that stored
guidance; this was not a missing ReportLab dependency. The repository contains
the current v4.0 policy, but it is not a substitute for the exact historical
policy/hash and must not be used to silently reinterpret the immutable report.
External TI remained pending with zero provider calls because the observable
was not eligible for lookup. The AI advisory worker was inactive; a stored
advisory selection is not evidence of a live AI API request. No fresh-session,
current-policy guidance, new-report PDF, public-IP TI provider, or live AI
acceptance test has passed.

## Authority and operating invariants

Cowrie evidence and the canonical evidence snapshot remain authoritative.
Predictions and external enrichment are context only. Model2 and Next-Distinct
remain shadow/non-authoritative; no model output or response guidance executes
an action. Exact resource identities, credentials, addresses, database
receipts, and protected backup paths remain outside Git.

See [GCP VM architecture](GCP_VM_CURRENT_ARCHITECTURE.md), [deployment and
recovery](DEPLOYMENT_AND_RECOVERY.md), and the [GCP replacement
runbook](GCP_VM_REBUILD_RUNBOOK.md) for current constraints and gates.
