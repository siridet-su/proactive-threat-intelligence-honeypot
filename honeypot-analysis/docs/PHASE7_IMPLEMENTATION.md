# Phase 7 targeted implementation

Phase 7 implements the accepted and modified decisions in
`PHASE7_DECISION_RECORD.md`. It does not deploy or contact a sensor, cloud
service, feed, model registry, or enrichment provider.

## Runtime changes

- Cowrie login credential fields are deterministically redacted before a
  forwarder spool write. Ingest applies the same sanitizer before SQLite as
  defense in depth. Presence metadata is retained, but new records do not HMAC a
  redaction marker. Historical hashes and records remain unchanged.
- External enrichment requires `EXTERNAL_ENRICHMENT_PROFILE`. The default is
  `disabled`; `non_ip_observables` permits only configured URL/domain/hash
  providers. The exact lifecycle policy is loaded and hashed by the enrichment
  worker, and its prohibition on source-IP sharing always wins.
- `ENRICHMENT_DB_PATH`, when non-empty, must name a regular non-symlink
  `local_enrichment_snapshot.v1` file. The file has configured byte/record
  bounds and requires dataset/version/timestamps plus the SHA-256 of its
  canonical `records` object. It remains non-authoritative context.
- Closed-session analysis jobs bind to an ordered durable SQLite event prefix.
  Analysis reloads and verifies that exact prefix rather than trusting the
  monitor's bounded in-memory history. Missing, changed or oversized evidence
  fails to observation-only abstention through the existing analysis failure
  path.
- The durable worker's only active command classifier is the configured
  `NotebookParityClassifier`; the active monitor has no in-memory campaign
  tracker. The legacy helper classes remain importable for historical and
  notebook compatibility.
- New alert IDs bind to the observed alert key and triggering event; v4 report
  IDs bind to the assessment/job; v4 artifact versions bind to assessment and
  evidence hashes. Historical identity behavior is retained for legacy
  payloads.
- Configuration rejects unknown JSON keys, invalid boolean text, noncanonical
  production classification strategy, invalid enrichment profiles, and unsafe
  evidence/local-data bounds.
- SQLite uses a 30-second bounded busy timeout, explicit full synchronous mode,
  WAL/foreign keys, and owner-only database permissions. All systemd service
  templates use `UMask=0077` and the common sandbox baseline.
- The monitor labels prediction data as non-authoritative model context and its
  CSP no longer permits arbitrary HTTPS `connect-src`. CDN assets remain a
  documented deferred gap.

## Optional local snapshot contract

An operator may create a reviewed snapshot offline:

```json
{
  "schema_version": "local_enrichment_snapshot.v1",
  "dataset_id": "reviewed-local-context",
  "version": "2026-07-29",
  "generated_at": "2026-07-29T00:00:00+00:00",
  "expires_at": "2026-08-05T00:00:00+00:00",
  "records_sha256": "<sha256 of stable canonical JSON for records>",
  "records": {
    "203.0.113.10": {"country": "ZZ", "asn": "AS64500"}
  }
}
```

No updater is installed. Stage and validate a new immutable file, retain the
previous file as the rollback copy, change only the explicit path, and restart
the existing consumers. Rollback restores the prior path/file. Expiry fails
closed unless `ENRICHMENT_ALLOW_STALE=true` is explicitly selected; stale data
is still marked stale and remains contextual.

Phase 7 deliberately ships no GeoIP, ASN, prefix, Tor, or threat-feed dataset.
Selecting one requires a separate source/license/accuracy/privacy review and a
pinned rollback artifact.

## Preserved authority

`session_assessment.v4` and `response_guidance.v3` validation is unchanged.
Observed Cowrie evidence remains authoritative. Prediction, enrichment,
cross-session correlation and optional prose remain context only.
`requires_manual_approval=true`, `safe_to_auto_execute=false`, no predictive
alert authority, and no automatic response execution remain mandatory.

## Deferred items

- CDN UI dependencies are not self-hosted. There is no reviewed vendored asset
  set, integrity manifest, license bundle, local build, or offline rendering test
  in the repository. A separate UI-assets change should establish those before
  switching CSP to self-only.
- No external accuracy validation, real production load test, long-duration
  observation, privacy-law review, or deployed backup/restore rehearsal was
  performed locally.
