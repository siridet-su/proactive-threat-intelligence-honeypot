# SQLite to MongoDB canonical-epoch requirements

Status: the reviewed backend is selectable only through an exact
`canonical_storage_epoch.v2` receipt, owner-only Atlas URI credential, and a
separate synchronous SQLite rollback mirror bound through
`rollback_mirror_identity.v1`. SQLite remains the production
authority until the documented Atlas M0 parity, backup, capacity, and cutover
gates pass. The repository
contains a backend-neutral canonical event record, the complete formal runtime
storage contract, a content-addressed MongoDB schema/index/validator manifest,
a validated least-privilege identity manifest, shadow and rollback-mirror state
machines, and bounded migration/reconciliation tooling. The implementation is
exercised against MongoDB 8.0. Historical SQLite data is never copied into the
new M0 epoch. This document does not authorize a paid Atlas resource or any
reuse of the legacy Atlas environment.

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

## Selected free canonical environment

The isolated project uses the free M0 cluster `Honeypot-Canonical` on GCP
Singapore. Its 0.5 GB constraint is accepted only for a new, empty canonical
epoch: the approximately 6.3 GB historical SQLite authority remains an
immutable read-only archive. Canonical storage and index bytes are monitored
separately with warnings at 60% and 75% and a fail-safe write gate at 85%.
Canonical evidence is never silently deleted, assigned a TTL, or moved to a
paid tier.

The canonical project access list must never include `0.0.0.0/0`. Prefer a
private endpoint from capstone. If that is not approved, allow only capstone's
stable egress `34.142.229.209/32` as a documented interim limitation. The Pi
does not receive canonical MongoDB credentials or direct canonical database
access.

The runtime database user is exactly `10k`, SCRAM-SHA-256, scoped by the exact
epoch receipt to its reviewed cluster, and assigned only the custom role described in
`configs/mongodb_runtime_identity.v2.json`. That role grants CRUD and bounded
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

`database_backend=mongodb` is accepted only when the protected URI, exact Atlas
schema, storage-epoch receipt, capacity policy, and separate rollback-mirror
identity all validate. Otherwise startup fails closed. There must never be two
independently authoritative primary stores: the historical SQLite cutoff owns
the prefix, and MongoDB owns only the explicitly recorded later epoch.

For each post-cutover event the application fixes `event_id` and `received_at`
once, majority-writes and verifies MongoDB, writes and verifies the SQLite
rollback mirror with `synchronous=FULL`, and only then permits the ingest ACK.
An exact retry repairs either missing copy; conflicting content fails closed.

M0 has no reviewed managed PITR/Cloud Backup guarantee. Before cutover retain a
verified immutable SQLite archive, test backup/restore of the new rollback
mirror, and test a manual `mongodump`/`mongorestore` round trip using synthetic
staging data. Do not describe that procedure as managed backup.

The v2 epoch receipt records the exact Atlas organization/project/cluster,
provider, region, SRV hostname, replica-set name, observed server version,
release commit/tree/manifest, failed predecessor, and historical SQLite
policy/environment hashes. Runtime verifies the protected URI hostname and
connected replica-set/version before authority can activate. Atlas deployment
IDs are receipt values, never application-source constants.

The receipt also embeds a content-addressed `rollback_mirror_identity.v1`.
Preparation creates the schema and immutable lineage row, verifies WAL plus
`synchronous=FULL`, commits, truncates/checkpoints the WAL, closes writers, and
hashes the resulting main database with zero canonical events. Empty sidecars
are not identity artifacts; any non-empty sidecar blocks preparation. Before
activation, runtime requires the exact initial SHA-256 and zero-event state.
After the first canonical write the file hash is expected to change: restarts
instead verify the embedded mirror/epoch/release lineage, immutable-lineage
triggers, schema, durability PRAGMAs, integrity, and the normal exact
MongoDB-to-SQLite event contract. The initial hash is immutable creation
lineage, not a post-write file invariant.

The epoch receipt records historical SQLite policy/environment hashes and new
MongoDB-epoch policy/environment hashes independently. Both lineages are
validated, but they are not forced equal: a reviewed release boundary may
update policy provenance without reinterpreting or rewriting historical
assessments.

## Manual M0 export and restore

Use a GPG-verified MongoDB Database Tools release on the capstone host. Keep
archives outside the application release, owner-only, encrypted at rest when
retained, and record the tool version and archive SHA-256. Never place the URI
on the Pi or in a repository script. The reviewed operational sequence is:

1. pause canonical writes and drain workers so the export has a declared
   cutoff; record collection counts and the current epoch receipt;
2. run `mongodump` with the protected capstone runtime credential, database
   `honeypot_canonical_v1`, `--archive`, and `--gzip`;
3. hash the archive and store it with the epoch/cutoff/count receipt;
4. restore only into an isolated empty schema-qualified test environment using
   `mongorestore --archive --gzip`; never overwrite the live epoch as a test;
5. verify schema, indexes, validators, collection counts, canonical IDs, payload
   hashes, and a sample of durable-prefix manifests before accepting restore;
6. delete synthetic restore data and retain the production archive according
   to the owner-approved research retention policy.

The staging qualification used Database Tools 100.17.0 and a synthetic event
round trip without retaining any attacker data. Production cutover still
requires a new consistent export after forwarding is paused and queues drain.

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
- `mongodb_epoch_receipt --prepare-mirror` exclusively creates a fresh mirror
  and its non-secret content-addressed identity. Operators do not manually
  calculate the initial database hash.
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
