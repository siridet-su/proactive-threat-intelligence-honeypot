# Canonical backup and retention implementation plan

## Status

**Planning only. No implementation, scheduler, purge, TTL index, or host
configuration has been activated.**

- Last verified: 2026-09-24
- Current phase: Phase 0 — inventory and contract preparation
- Target database: `honeypot_canonical_v1`
- Long-term archive: private Backblaze B2
- Current backup implementation: `honeypot_db.hardware_metrics_1m` only
- Purge authority: manual approval after verified backup and restore evidence
- Approved deployment posture: portable worker code only; no GCP activation in
  the capstone project at this stage
- Approved B2 permissions: upload worker has `writeFiles` + `listFiles`; restore
  operator has `readFiles`; upload worker has no `deleteFiles`
- Approved control-plane direction: generic backup request/manifest records in a
  separate operational control database, not in canonical evidence collections

This is a living implementation plan. Every implementation change must update
the live state, phase checklist, validation evidence, and deployment status in
this document. This document is not evidence that a worker is installed or
active.

## 1. Problem and intended outcome

`honeypot_canonical_v1` is the canonical analysis store, not a disposable
cache. It intentionally does not use authoritative MongoDB TTL indexes. If no
controlled archive lifecycle is added, the database will grow without bound.

The target design is:

```text
canonical MongoDB
  → policy-aware archive worker
  → compressed B2 object
  → count/hash/restore verification
  → backup manifest
  → manually authorized purge when eligible
```

The design must preserve reproducible evidence while keeping MongoDB as a
bounded hot/operational store. B2 is the long-term archive; MongoDB is not the
only copy of retained history.

## 2. Current verified state

### 2.1 Storage authority

- The canonical schema manifest names `honeypot_canonical_v1` as the database
  and prohibits authoritative TTL indexes.
- The canonical manifest defines 31 collections.
- The live database currently contains 33 non-system collections. The two
  additional runtime collections are:
  - `external_ti_source_ip_cache`
  - `external_ti_provider_proof_guard`
- The backup implementation in `agents/hardware-backup/` is hard-coded to
  `honeypot_db.hardware_metrics_1m`; it is not a canonical backup worker.
- The existing dashboard request/progress pattern is Pi-oriented and must not
  make the browser connect directly to MongoDB or B2.
- The implementation must remain cloud-neutral. GCP is a documented activation
  target, not a build-time or runtime dependency; another cloud runner may be
  used after the academic project environment or credits expire.

### 2.2 Point-in-time live inventory

The following values are read-only diagnostics from 2026-09-24. They are not
retention limits or contractual counts.

| Database / collection | Approximate records | Role in this plan |
| --- | ---: | --- |
| `honeypot_canonical_v1.events` | 31,880 | Canonical evidence; must retain/archive |
| `honeypot_canonical_v1.sessions` | 5,186 | Canonical session state; must retain/archive |
| `honeypot_canonical_v1.canonical_assessments` | 2,546 | Canonical analysis output |
| `honeypot_canonical_v1.reports` | 2,546 | Canonical user-visible output |
| `honeypot_canonical_v1.prediction_snapshots` | 53,408 | Recomputable model history; separate tier |
| `honeypot_canonical_v1.session_links` | 331,494 | Long-term correlation context; potentially large |
| `honeypot_canonical_v1.enrichment_records` | 1,759 | Long-term TI context |
| `honeypot_db.events` | 103,230 | Separate legacy operational event source |
| `honeypot_db.threat_intel` | 147 | Short-lived provider cache |
| `honeypot_db.normalized_events` | 342 | Legacy derived copy |
| `honeypot_db.enriched_events` | 342 | Legacy enriched copy; overlaps normalized copy |

Identity checks found zero exact `event_id` overlap between canonical
`events` and `honeypot_db.events`. The two stores must therefore remain
separate in the archive namespace. Observable values can overlap because they
represent the same indicator, not the same event document.

## 3. Design principles and non-goals

### Principles

1. Do not add TTL to canonical evidence merely to control storage size.
2. Archive before purge; never purge an unverified or partially uploaded range.
3. Select records by policy and dependency state, not age alone.
4. Keep stable identity, schema version, policy hash, counts, and hashes with
   every archive.
5. Make archive operations idempotent and safe to retry.
6. Keep the dashboard as a request/status surface; credentials and data movement
   remain on a protected worker host.
7. Treat `honeypot_canonical_v1` and `honeypot_db` as different authorities,
   even when collection names or observable values overlap.

### Non-goals for the first implementation

- No automatic deletion of canonical records.
- No migration or merging of `honeypot_db` into `honeypot_canonical_v1`.
- No browser-side MongoDB or B2 access.
- No raw attacker payload, password, private key, malware binary, or provider
  secret in the archive manifest or dashboard.
- No change to the active event pipeline or canonical analysis semantics.

## 4. Retention classes

The policy must classify every canonical collection before implementation.
`archive_after_days` is a selection policy, not an `expires_at` field and not a
MongoDB TTL.

| Class | Collections | Archive rule | Purge rule |
| --- | --- | --- | --- |
| Canonical evidence | `events`, `sessions` | Only finalized/terminal records with dependency checks | Manual approval only |
| Canonical analysis | `canonical_assessments`, `reports` | Archive after finalized state | Manual approval only |
| Long-term context | `observables`, `observable_sightings`, `enrichment_records`, `session_links`, `campaigns`, `campaign_sessions` | Archive after finalized state | Manual approval; keep if investigation references remain |
| Human/audit evidence | `alerts`, `analyst_feedback`, `classification_review_labels` | Archive all finalized records | Never automatic |
| Recomputable research | `prediction_snapshots`, `ai_advisories`, backtest/calibration runs | Archive selected history or latest-per-session policy | Explicit research decision |
| Runtime coordination | `event_processing`, `session_dispatch`, `worker_leases`, `analysis_jobs`, `enrichment_jobs`, `threat_hunt_jobs`, outboxes, `webhook_deliveries`, `reconciliation_cursors`, `feed_status` | Keep hot; archive only for recovery/audit need | Rebuild or expire only after operational safety review |
| Provenance | `schema_manifests`, `lifecycle_ledger`, `migration_receipts` | Always retain | Never automatic |
| Runtime external TI | `external_ti_source_ip_cache`, `external_ti_provider_proof_guard` | Separate policy; retain when provider audit/replay requires it | Never infer from the 31-collection manifest |

Initial policy candidates are 30–90 days for evidence hot storage, 365 days
for assessment/report hot storage, 180 days for prediction snapshots, and
730 days for long-term correlation context. These are proposals only and must
be approved before they are encoded in a worker.

## 5. Archive package contract

### 5.1 Object layout

Use separate prefixes so the two databases cannot be mistaken for one source:

```text
canonical-v1/<backup-id>/<collection>/YYYY/MM/DD/part-000.jsonl.gz
honeypot-db/<backup-id>/<collection>/YYYY/MM/DD/part-000.jsonl.gz
```

The first phase should use collection-scoped Extended JSON Lines with gzip,
matching the existing hardware archive's streaming and hashing model. A later
full-disaster-recovery profile may add `mongodump --archive --gzip` when index
and restore fidelity require it.

### 5.2 Required manifest fields

Each collection/range archive must record:

- `backup_id` and request ID
- source database and collection
- schema version and schema-manifest hash
- lifecycle-policy hash
- selection query/cutoff digest
- primary time field and inclusive/exclusive bounds
- document count, first/last identity, compressed byte count
- SHA-256 of the local archive and uploaded object
- B2 bucket/prefix/object name
- status, worker identity, start/end time, verification time
- restore-rehearsal result
- purge eligibility and approval receipt, if any

No record values or secrets belong in the manifest.

### 5.3 Request and state model

Requests should support at least:

- `dry_run`: estimate candidates and dependencies without writing
- `archive_missing`: upload eligible ranges not already verified
- `verify`: recheck object metadata/hash and optionally restore to isolation
- `purge_review`: produce a deletion candidate set; never delete
- `purge_apply`: delete only an explicitly approved manifest/range
- `retry_failed`

State transitions:

```text
planned → queued → scanning → exporting → uploading → verifying
                                      ↓                  ↓
                                   failed            verified
                                                         ↓
                                                  purge_eligible
                                                         ↓
                                                  purge_approved
                                                         ↓
                                                       purged
```

`blocked_dependency`, `cancelled`, and `failed` are terminal request states
until a new request retries them. A worker crash must leave enough heartbeat
state for safe reclaim without duplicating an already verified object.

### 5.4 Operational control database

The control database is the audit/control plane for backup actions. It does not
contain a second copy of canonical events and does not replace the B2 archive.
It records what an operator requested, what the worker did, and which verified
object represents which source range.

The approved target is a separate operational database, provisionally named
`honeypot_backup_control`, so the canonical schema and the live legacy data
store remain independent. The exact database name can be made configurable;
the worker must not hard-code a GCP hostname.

Initial generic collections:

- `backup_requests`: dashboard actions, requester, scope, target collections,
  status, progress, heartbeat, worker ID, timestamps, and safe error metadata;
- `backup_manifests`: immutable archive facts including source database,
  collection/range, policy/schema hashes, document count, B2 object name, and
  verification result.

Example request shape (illustrative; no secrets or document payloads):

```json
{
  "schema_version": "pti.backup_request.v1",
  "scope": "canonical-v1",
  "action": "archive_missing",
  "requested_by": "operator-id",
  "status": "queued",
  "target": {"database": "honeypot_canonical_v1", "collections": ["events"]},
  "progress": {"completed_units": 0, "total_units": 0, "percent": 0}
}
```

Example manifest shape:

```json
{
  "schema_version": "pti.backup_manifest.v1",
  "scope": "canonical-v1",
  "database": "honeypot_canonical_v1",
  "collection": "events",
  "object_name": "canonical-v1/2026-09-24/events/part-000.jsonl.gz",
  "document_count": 0,
  "archive_sha256": "...",
  "status": "verified",
  "request_id": "..."
}
```

These records support dashboard progress and audit questions such as “who
requested this archive?”, “which collection/range was uploaded?”, “did hash
verification pass?”, and “is this range eligible for a later approved purge?”.
The control records themselves are small and should be retained as provenance;
the actual event data remains in the B2 object.

## 6. Dependency safety rules

### Events

An event range is archive-eligible only when:

- `processed=true`;
- processing/analysis work is terminal or explicitly marked not applicable;
- dependent session, assessment, and report state has been finalized or its
  absence is recorded;
- no open review, feedback, campaign, or investigation reference blocks the
  range;
- the archive manifest has been verified.

Events must not be deleted solely because `received_at` is old.

### Sessions and derived records

Sessions, assessments, reports, predictions, links, and campaign relations
must be archived in an order that preserves their references. The worker must
either archive a complete dependency set or leave the source records in
MongoDB.

### Operational records

Queues, leases, retry state, and outboxes are not part of the default research
archive. A recovery snapshot may include them, but it must be labeled as an
operational restore artifact and must not be treated as analytical evidence.

## 7. Worker and host integration

### Recommended placement

The canonical archive worker should run on the canonical service host or a
protected runner with managed-Mongo access. It should not depend on the Pi
being online if the canonical database is hosted elsewhere.

The dashboard may create an authenticated request, but the worker owns:

- Mongo reads;
- local temporary archive files;
- B2 credentials;
- upload and verification;
- progress/heartbeat updates.

### Proposed service boundary

```text
Backup & Retention UI
  → canonical_backup_requests
  → canonical-backup-control.service
  → canonical-backup worker
  → canonical MongoDB + B2
  → canonical_backup_manifests
  → dashboard status polling/SSE
```

The existing hardware worker may later be generalized behind a `scope`
interface, but the first canonical implementation must not silently reuse
hardware-specific collection names, manifest schema, or systemd assumptions.

## 8. Implementation phases

### Phase 0 — Inventory and contract preparation (current)

- [x] Compare canonical and `honeypot_db` collection names and authorities.
- [x] Check live collection counts, sizes, and top-level field shapes without
  exposing document values.
- [x] Verify exact `event_id` overlap before proposing deduplication.
- [x] Identify the two runtime canonical collections absent from the 31-entry
  schema manifest.
- [x] Decide the canonical backup runner posture: portable code, GCP or another
  cloud only when explicitly activated.
- [x] Approve initial retention windows and the default archive scope.
- [x] Approve B2 permissions: upload worker cannot delete; restore is a
  separate read-only role.
- [x] Choose a separate operational control database direction for generic
  requests and manifests.

### Phase 1 — Policy and schema contract

- [ ] Add a versioned canonical backup policy file.
- [ ] Define collection classes, primary time fields, dependency checks, and
  archive windows.
- [ ] Reconcile `external_ti_*` collections with the canonical schema manifest.
- [ ] Define request, manifest, and restore-rehearsal schemas.
- [x] Use a separate operational control database direction; do not mix generic
  canonical manifests into the canonical evidence schema.
- [ ] Confirm the final control database name and Mongo role grants.

### Phase 2 — Dry-run selector

- [ ] Implement read-only candidate selection.
- [ ] Report document count, logical size estimate, time bounds, blocked
  dependencies, and expected archive size.
- [ ] Add tests for late events, missing timestamps, non-terminal jobs, and
  repeated runs.
- [ ] Prove dry-run never creates TTL indexes or modifies source documents.

### Phase 3 — Archive worker

- [ ] Implement streaming collection export and gzip compression.
- [ ] Add idempotent object naming and local temporary-file cleanup.
- [ ] Upload to a private B2 prefix with server-side encryption settings already
  approved for the bucket.
- [ ] Write/update manifest only after upload and hash verification.
- [ ] Add retry, heartbeat, stale-request reclaim, and concurrency locking.

### Phase 4 — Verification and restore rehearsal

- [ ] Verify B2 object metadata and SHA-256.
- [ ] Restore a sample archive into an isolated Mongo database.
- [ ] Compare counts, identity ranges, schema versions, and representative
  hashes without exposing sensitive values.
- [ ] Record restore evidence and mark the archive `verified`.

### Phase 5 — Dashboard integration

- [ ] Add a separate canonical archive card to Backup & Retention.
- [ ] Show scope, last successful archive, pending/blocked ranges, progress,
  verification status, and B2 usage.
- [ ] Add `dry run`, `archive missing`, `verify`, and `retry failed` actions.
- [ ] Keep purge behind a separate confirmation and approval flow.
- [ ] Display that canonical and hardware retention policies are different.

### Phase 6 — Controlled purge (later, explicitly approved)

- [ ] Generate a purge candidate report from verified manifests.
- [ ] Require operator approval tied to exact collection/range/manifest hashes.
- [ ] Take a final count/hash checkpoint.
- [ ] Delete only the approved range with dependency-safe filters.
- [ ] Record a purge receipt and verify Mongo counts after deletion.
- [ ] Rehearse restore before enabling recurring purge.

### Phase 7 — Recurring operation

- [ ] Add a protected scheduler on the selected runner host.
- [ ] Run daily archive discovery with a safety window for late writes.
- [ ] Run monthly retention review and storage report.
- [ ] Alert on failed, blocked, stale, or unverified archives.
- [ ] Review B2 file versions and lifecycle separately from Mongo retention.

## 9. Validation and security gates

Before any production activation:

- unit tests for policy selection, dependency blocking, idempotency, hashing,
  retry, and state transitions;
- Mongo integration tests with late/duplicate/unfinished records;
- B2 integration test against a non-production prefix;
- isolated restore rehearsal;
- `git diff --check`, lint, type-check, and Go tests for changed components;
- systemd unit validation and least-privilege filesystem checks;
- verify no B2/Mongo credentials reach browser responses or logs;
- verify no password, raw payload, private key, or provider secret is exported;
- verify purge is disabled until the approval gate is explicitly enabled.

## 10. Rollback

Before Phase 6, rollback is operationally simple: stop/disable the canonical
worker and leave MongoDB unchanged. Failed uploads and unverified temporary
files must be cleaned without changing source records.

After purge is enabled, rollback requires the verified B2 manifest, restore
rehearsal procedure, purge receipt, and an isolated restore before any source
database repair. No destructive command or automatic purge may be introduced
without this evidence.

## 11. Open decisions before implementation

1. Which exact cloud runner will be used when the project is activated?
2. Confirm whether the existing B2 bucket remains available at activation time;
   the approved default is the same bucket with a separate `canonical-v1/`
   prefix.
3. Should `prediction_snapshots` keep all history or latest-per-session only?
4. Should external TI cache/proof records be part of the default research
   archive or a separate audit profile?
5. Should the first archive format be JSONL.gz only, or include a full
   `mongodump --archive --gzip` recovery profile?
6. What approval role is required before canonical purge?

## 12. Live state update format

Every future change to this plan should update this block:

```text
Status: planning decisions approved; implementation not started
Phase: 0 — inventory and contract preparation
Implementation active: no
Canonical archive worker active: no
Canonical purge active: no
Last verified: 2026-09-24
Next gate: implement the policy/control contracts in a separate branch, then
run a read-only dry run
```

Related source of truth:

- [MongoDB canonical schema manifest](../../honeypot-analysis/configs/mongodb_canonical_schema.v1.json)
- [Canonical lifecycle configuration](../../honeypot-analysis/configs/mongo_pi_retention.final.json)
- [Hardware backup worker](../../agents/hardware-backup/README.md)
- [Implementation log](../IMPLEMENTATION-LOG.md)
