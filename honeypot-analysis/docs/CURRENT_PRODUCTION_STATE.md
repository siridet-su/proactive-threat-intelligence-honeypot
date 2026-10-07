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

The 2026-10-08 read-only check found all eight core backend services, both
Next-Distinct shadow services, and both Model2 shadow services active, with no
failed systemd units. The ingest health endpoint returned 200 on its private
overlay binding; Dashboard API and monitor health returned 200 locally. This
was a health check only, not a synthetic session, model-inference, provider, or
report/PDF acceptance test. AI advisory was inactive. Two Dashboard v2 services
and the service-watchdog timer were also active outside the current `main`
managed-unit allowlist, so the host does not yet match that policy's unit
inventory.

The active release verifier rejects the preserved Model2 runtime-configuration
hash, and neither the active nor retained alternate release currently verifies
as a manifest-bound rollback target. The Model2 configuration was not changed.
The active release must remain in place until a successor release and rollback
release both verify and the unit inventory is reconciled.

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
