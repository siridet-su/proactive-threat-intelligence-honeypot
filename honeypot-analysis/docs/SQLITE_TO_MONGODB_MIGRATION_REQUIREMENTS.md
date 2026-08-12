# Future SQLite to MongoDB migration requirements

Status: offline backend implementation complete; Atlas staging remains an
external gate and SQLite remains the sole production backend. The repository
contains a backend-neutral canonical event record, the complete formal runtime
storage contract, a content-addressed MongoDB schema/index/validator manifest,
a validated least-privilege identity manifest, shadow and rollback-mirror state
machines, and bounded migration/reconciliation tooling. The implementation is
exercised against a disposable local MongoDB 8.0 replica set but is deliberately
not selectable through `open_storage`. This document does not authorize an
Atlas purchase, data copy, shadow activation, cutover, credential use, or
service deployment.

## Verified Atlas control-plane gate (2026-08-12)

The observed legacy Atlas environment is organization
`6a549939366a569efa96227b`, project `6a549939366a569efa96236e` (`Project 0`),
and cluster `Honeypot-DB`. The project has three human Project Owners and an
Atlas Charts identity. It also has three broad, unscoped database users:
`atlasAdmin` and two `readWriteAnyDatabase` identities. The project has no API
keys, project service accounts, custom database roles, private endpoints, or
peering.

The legacy cluster is an AWS Hong Kong `AP_EAST_1` M0 replica set running
MongoDB 8.0.29. It has 0.5 GB configured storage and reported 538,739,600 bytes
of logical data. It has no Cloud Backup, PITR, snapshots, or backup schedule.
Its IP access list includes three `/32` entries and `0.0.0.0/0`. The Pi legacy
processor has live Atlas connections from public egress `110.77.157.101`, which
is not one of the explicit `/32` entries. The open rule cannot be removed until
that live legacy dependency and other Project Owners' consumers have approved
narrow replacements.

This proves that the existing M0 is a shared legacy environment, not a safe
canonical destination. Existing `honeypot_db` collections remain noncanonical
legacy/archive data and must not be modified or copied wholesale.

## Selected future canonical environment

Use a separate, dedicated Atlas project and cluster named
`Honeypot-Canonical`; do not upgrade or repurpose `Honeypot-DB`. Prefer GCP
Singapore to colocate with capstone's GCP `asia-southeast1` runtime. The last
observed SQLite source size was approximately 6.3 GB. A 10 GB default volume is
therefore not a defensible migration target after BSON, indexes, receipts,
working space, and growth are included. The first paid staging review should
quote the smallest dedicated tier that supports replica-set transactions,
Cloud Backup, continuous backup/PITR, and at least 20 GB configured storage in
that region. M10 with 20 GB is the technical starting candidate if the Atlas
quote confirms those features; M20 is recommended headroom, not a proven
minimum. No tier should be purchased until a consistent production SQLite
backup is measured by the migration tool and the exact Atlas quote is approved.

The canonical project access list must never include `0.0.0.0/0`. Prefer a
private endpoint from capstone. If that is not approved, allow only capstone's
stable egress `34.142.229.209/32` as a documented interim limitation. The Pi
does not receive canonical MongoDB credentials or direct canonical database
access.

The runtime database user is exactly `10k`, SCRAM-SHA-256, cluster-scoped to
`Honeypot-Canonical`, and assigned only the custom role described in
`configs/mongodb_runtime_identity.v1.json`. That role grants CRUD and bounded
inspection only on `honeypot_canonical_v1`; it excludes collection/index/user,
backup, network, project, bypass-validation, and database administration. A
separate deployment identity installs validators/indexes and the manifest,
then is removed from the runtime credential path.

## Non-negotiable migration boundary

The future MongoDB implementation must replace storage mechanics without
changing analytical authority or event meaning. In particular it must preserve:

- sanitization before the first persistent or forwarded Cowrie JSON boundary;
- authenticated, sensor-aware session identity and stable event deduplication;
- per-session head-of-line processing with leases and fencing;
- exact durable event-prefix manifests and deterministic v4 analysis;
- atomic report/job/session completion and reference-only AI enqueue;
- Transformer-only production prediction with no automatic VOMM fallback;
- manual-only response guidance and prohibited automatic alerts/execution; and
- prediction, enrichment, correlation, and AI as non-authoritative context.

SQLite must remain the only accepted `database_backend` until a MongoDB adapter,
contract tests, migration validator, backup/restore procedure, and rollback plan
have all passed review. There must never be two independently authoritative
primary stores.

## Current Pi MongoDB environment is not a migration target yet

The Pi currently has legacy Redis-backed collector, processor, and hardware
agents in addition to the canonical sanitized forwarder. Their Go processor
uses a different event model and can reconstruct fields that the canonical
privacy boundary removes. Its collections, Redis stream, credentials, and
operational purpose must therefore be treated as a separate legacy system—not
as a compatible destination for SQLite rows.

Before reuse is considered, a future task must establish:

1. whether MongoDB is local, Atlas, or another remote deployment;
2. replica-set/transaction support, TLS, authentication, network allowlists,
   backups, retention, ownership, and university data-governance approval;
3. a new least-privilege application identity, separate from legacy agents;
4. an isolated database/collection namespace for sanitized canonical records;
5. that no legacy raw Cowrie/credential collection is read by the new backend;
6. credential rotation and provisioning through owner-only files; and
7. capacity, latency, availability, and egress behavior from capstone.

No current MongoDB credential should be copied into repository configuration or
made available to the Pi forwarder.

## Components affected

| Area | Required migration work |
| --- | --- |
| `production.storage.contract` | Freeze and expand backend-neutral behavioral contracts before adapter work. |
| `production.storage.backend` | Split SQLite implementation from backend-independent IDs, validation, and queue semantics. |
| Configuration | Add an explicitly gated MongoDB backend and owner-only URI/credential files; retain fail-closed SQLite defaults. |
| Ingest | Prove acknowledged events are durably committed with the same stable IDs and canonical sensor/session provenance. |
| Session worker | Reproduce leader lease, per-session ordering, event fencing, retry, dead-letter, and watermark behavior. |
| Analysis worker | Reproduce exact-prefix snapshot reads and atomic report/job/session/AI-outbox completion. |
| Prediction outbox | Preserve deterministic task/snapshot identities, cutoff ordering, leases, and replay behavior. |
| Enrichment/threat hunt | Preserve UPSERT, caching, claim fencing, retries, and terminal states. |
| Webhooks | Preserve delivery identity, signing input, claim fencing, and receiver-idempotency assumptions. |
| Dashboard/monitor | Replace SQLite-specific queries without widening projections or raw-command access. |
| Backup/recovery | Add consistent MongoDB snapshot, restore, integrity, and rollback receipts. |
| Release/deployment | Pin the MongoDB driver and CA/runtime dependencies; add egress and secret policy. |
| Tests/tools | Run the full storage contract against both adapters and add cross-backend equivalence fixtures. |

Pi Cowrie output and the sensor forwarder should not require a database driver.
They must continue sending sanitized authenticated batches to capstone ingest.

## Required collection and index semantics

The initial collection model should retain current table boundaries unless an
explicit equivalence proof justifies combining them. At minimum it needs
collections corresponding to events, sessions, worker leases, analysis jobs,
reports, prediction snapshots/outbox, enrichment jobs/records, threat-hunt
jobs, observables/sightings, session links, campaigns, feedback/review labels,
webhook deliveries, lifecycle ledgers, and additive AI advisory records.

Required unique identities include stable event ID, session-aware session ID,
job/report/snapshot/outbox/advisory IDs, observable identity, delivery identity,
and campaign membership. Required compound indexes must reproduce current
claimability, session ordering, cutoff, latest-record, and retry queries.

MongoDB-specific risks that require executable tests include:

- multi-document transactions require a replica set or supported sharded setup;
- write concern must provide durable acknowledged writes (`majority` plus
  journaling where supported);
- `findOneAndUpdate` filters must include owner/token/lease fencing predicates;
- retryable writes must not duplicate side effects;
- BSON date ordering must match current UTC timestamp/event-ID ordering;
- missing versus `null` fields must not change queue eligibility;
- the 16 MiB BSON document limit may conflict with bounded session/report
  payloads and must fail closed before writes;
- unique-index creation on imported data must detect rather than silently merge
  collisions; and
- transaction size/time limits must accommodate analysis completion or require
  a reviewed transactional redesign with equivalent recovery semantics.

## Implemented offline migration controls

- `MongoDBStorageBackend` implements all formal runtime operations using
  deterministic application IDs, primary majority reads, majority+j writes,
  fenced claims, and transactions for multi-document publication.
- `SQLiteMongoShadowOutbox` writes the authoritative SQLite event and its
  deterministic shadow intent in one SQLite transaction. MongoDB remains
  non-authoritative and discrepancies are durable promotion blockers.
- `MongoSQLiteRollbackMirror` implements the future acknowledgement states
  neither, Mongo-only, SQLite-only, both-exact, and either-side conflict. It is
  not connected to ingest.
- `mongodb_canonical_migration` reads only a consistent immutable SQLite backup,
  streams documents with bounded memory, preserves IDs and JSON bytes, and
  emits content-addressed count/cutoff/whole-document aggregate evidence.
- reconciliation compares every migrated domain and reports missing,
  unexpected, or changed state without repairing either side.
- `mongodb_schema_admin` separates install authority from read-only runtime
  verification and accepts its URI only through an owner-only file reference.

The local exact-version gate remains explicit: MongoDB 8.0.4 was the closest
usable 8.0 container on this host. MongoDB 8.0.29 could not run because that
server build rejects the host's newer kernel. Exact Atlas 8.0.29 behavior,
authentication, backup/PITR, regional latency, capacity, and restore must be
validated in the isolated staging environment before promotion review.

## Compatibility and verification gates

Before any production write, a future adapter must pass:

1. every backend-neutral storage and queue lifecycle test;
2. cross-backend golden tests for IDs, ordering, payload JSON/BSON projection,
   event-prefix hashes, reports, predictions, retries, and failure states;
3. crash tests at every acknowledgement/transaction boundary;
4. privacy scans proving no credential/raw-field regression;
5. load tests covering Pi outage replay and concurrent worker claims;
6. backup/restore plus point-in-time recovery drills;
7. index/collection-manifest validation on an empty and restored database; and
8. release/runtime receipts that bind the exact driver, CA trust, and config.

The adapter should first run against synthetic fixtures, then a non-authoritative
shadow copy whose records are compared by canonical hashes. Shadow results must
not drive APIs, workers, reports, alerts, or retention.

## Future cutover and rollback outline

A later, separately approved cutover should:

1. take and verify an online SQLite backup;
2. stop new ingest acknowledgements or durably spool them on the Pi;
3. drain and fence workers at a recorded event/job boundary;
4. copy sanitized canonical records with deterministic source-to-target counts
   and hashes;
5. verify unique indexes, queue states, exact-prefix manifests, and report IDs;
6. activate exactly one MongoDB-backed release/configuration;
7. run bounded health and controlled replay tests;
8. retain SQLite read-only as the rollback source for an approved window; and
9. roll back by restoring the recorded release/configuration and replaying only
   durably unacknowledged events.

No SQLite file, table, or historical row should be deleted during migration.
Retirement requires a separate retention and evidence-governance decision.
