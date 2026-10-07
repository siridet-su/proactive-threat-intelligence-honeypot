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

Do not use historical addresses or SSH examples from old receipts as current
selectors. The prior VM was reported by the owner as shut down to avoid cost;
that state was not independently queried through the GCP control plane, and it
is not a verified rollback target.

## Live checks and release boundary

The 2026-10-08 bounded host follow-up found all eight core backend services,
both Next-Distinct shadow services, and the observed Model2 v7 services active,
with zero failed systemd units. Ingest health returned 200 on its private
overlay binding; Dashboard API and monitor health returned 200 on their local
bindings. The AI advisory worker was inactive. The two GCP Dashboard v2
services were stopped and disabled to match the requested local-dashboard
direction. Their unit definitions and the watchdog service/timer definitions
were archived under the host's root-only backup area; the watchdog timer was
also stopped and disabled because its protected target list includes those
Dashboard services. The watchdog program and protected configuration were not
changed.

The repository managed-unit policy was revised to make the already-required
Next-Distinct shadow and feeder units explicitly required-enabled. The revised
`gcp_backend` policy passed a read-only inventory validation against the VM.
That validator scopes unknown enabled units to the `honeypot-` prefix; it does
not inventory the separate `model2-v7-*` services. Their presence and
configuration remain outside that policy's proof and still require an
independent reviewed runtime receipt. No synthetic session, model-inference,
external-provider, authenticated UI, or report/PDF acceptance test was run.

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

## Authority and operating invariants

Cowrie evidence and the canonical evidence snapshot remain authoritative.
Predictions and external enrichment are context only. Model2 and Next-Distinct
remain shadow/non-authoritative; no model output or response guidance executes
an action. Exact resource identities, credentials, addresses, database
receipts, and protected backup paths remain outside Git.

See [GCP VM architecture](GCP_VM_CURRENT_ARCHITECTURE.md), [deployment and
recovery](DEPLOYMENT_AND_RECOVERY.md), and the [GCP replacement
runbook](GCP_VM_REBUILD_RUNBOOK.md) for current constraints and gates.
