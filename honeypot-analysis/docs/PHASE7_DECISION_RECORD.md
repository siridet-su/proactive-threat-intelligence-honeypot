# Phase 7 targeted remediation decision record

Status: accepted for implementation  
Baseline revision: `19aac5722d3f808014ba86992f126e86f4aa6ee6`  
Baseline verification: `727 passed, 7 skipped` (the same suite produced eight
local-HTTP failures under the restricted socket sandbox; all passed when local
loopback socket creation was permitted).

## Scope and invariants

This record was written before changing runtime behavior. The decisions below
were re-evaluated against the current code rather than inherited from an earlier
review.

Phase 7 keeps:

- the SQLite modular monolith and its durable queues;
- `session_assessment.v4` as the only authority for new reports;
- `response_guidance.v3` as manual, advisory-only guidance;
- Transformer production authority with explicit VOMM rollback support;
- read-only historical v1/v2/v3 compatibility;
- Cowrie observations as the only authoritative evidence;
- no predictive alert authority and no automatic response execution.

## Decisions

| Proposal | Decision | Current evidence and implementation boundary |
|---|---|---|
| Sanitize credentials before spool and SQLite persistence | **ACCEPT** | `production/workers/sensor_forwarder.py:DiskSpool.append_many` currently serializes Cowrie events verbatim. `production/api/ingest_api.py:IngestHandler.do_POST` passes each event directly to `SQLiteStorage.store_event`, which stores the complete payload. Later sanitization in `SessionMonitor` cannot satisfy `configs/data_lifecycle_policy.v1.json`, which prohibits credential plaintext storage. A shared, deterministic Cowrie credential sanitizer will run before spool append and again before ingest persistence. It will preserve only presence metadata and canonical redaction markers. New events will not HMAC a redaction marker; historical credential hashes remain readable and unchanged. |
| Enforce lifecycle policy for external source-IP sharing | **ACCEPT** | `EnrichmentWorker` currently selects any configured provider by observable type, while OTX, AbuseIPDB, Shodan, Censys and VirusTotal support IP lookups. The lifecycle policy explicitly sets `source_ip_external_sharing_allowed=false`, but the worker does not load or enforce it. The worker will load the exact policy and fail closed before provider selection. |
| Prefer selected local GeoIP/ASN/prefix/Tor/small feeds | **REJECT** as a dataset addition; **MODIFY** the existing local-file contract | No licensed, reviewed GeoIP/ASN/prefix/Tor dataset, pin, evaluation, or update source exists in the repository. Adding one would create storage, licensing and supply-chain obligations with no evidence that it improves thesis findings. The existing explicit `ENRICHMENT_DB_PATH` hook will remain, but a new file must use a bounded, hash-verified, expiring local snapshot envelope. No automatic downloader or refresh service will be added. |
| Local-data limits, TTL, provenance, hashes, rollback and updates | **ACCEPT** for operator-provided snapshots | The legacy loader accepts an unbounded raw JSON mapping with no digest or expiry. The replacement envelope will cap bytes and records, verify the exact records SHA-256, require dataset/version/generated/expiry provenance, and expose that provenance as non-authoritative context. Updates are offline/operator-controlled: validate a new immutable file, retain the prior file, change the explicit path, restart only consumers, and roll back the path. Expired or invalid snapshots fail closed unless the existing explicit stale-context setting is enabled. |
| Retain external enrichment as an optional fail-closed profile | **MODIFY** | External context can be useful for hashes, URLs and domains, but API-key presence must not silently authorize disclosure. Add an explicit profile: `disabled` (default) or `non_ip_observables`. IP sharing remains prohibited by the current lifecycle contract in every profile. Provider errors remain contextual and retryable; they cannot affect v4 findings, v3 action selection, alerts or authority. |
| Reconstruct complete canonical evidence from durable events | **ACCEPT** | `SessionMonitor` bounds `raw_events` using `session_event_history_limit` (default 10,000), and the analysis job currently embeds that bounded state. SQLite retains the complete session event stream. At session close, the worker will bind the analysis job to a durable event manifest (ordered event IDs and payload hashes through the close event). The analysis worker will reconstruct and verify that exact stream. A separate configured maximum prevents unbounded report memory use; missing, changed or oversized evidence yields observation-only abstention rather than a partial authoritative assessment. |
| Consolidate trusted classification | **ACCEPT** | `SessionWorker` already constructs `NotebookParityClassifier` from the configured rules file, and its output carries rule-policy SHA-256. `SessionMonitor` also contains `_KEYWORD_TTP_RULES` and several rule/model strategies. The active durable path will require the injected canonical classifier and `notebook_merge`; absent/failed classification becomes audit-only unclassified output. The old helper surface may remain only for test/historical import compatibility, but it will not be a new-record authority. |
| Consolidate campaign tracking | **ACCEPT** | `SessionMonitor.CampaignTracker` is an in-memory, restart-sensitive correlator that can emit “returning actor” alerts. `SessionWorker._apply_campaign_clustering` already uses durable campaign storage and explicit policy. The in-memory tracker will be retained only as an import-compatible legacy utility and removed from the active monitor path. Durable campaign clustering remains contextual and cannot create v4 findings or guidance. |
| Deterministic alert/report/artifact identities | **ACCEPT** | Alert IDs currently hash timestamp-bearing payloads; report IDs hash the whole generated report; artifact versions hash report/session timestamps. IDs will instead bind to stable triggering evidence/alert key, v4 assessment ID/job ID, and v4 evidence/assessment plus renderer contract. Historical stored IDs are not rewritten. Artifact file hashes remain recorded and verified independently. |
| Strict configuration validation | **MODIFY** | `_env_bool` silently converts every unknown value to false, and file keys not present in the dataclass are silently dropped. Reject unknown file keys and invalid booleans, validate the new enrichment profile and durable-evidence bounds, and keep the existing effective prediction-policy overlay for historical environment compatibility. A wholesale configuration-schema rewrite is not justified in this phase. |
| API/UI consistency and prediction wording | **MODIFY** | The current `/api/session` monitor contract and client fields match (`overview`, `events_table_rows`, `prediction_snapshots`). No duplicate contract rewrite is needed. However, the UI says “Predictive Alert” and “Authoritative Next-Tactic Forecast”, contradicting the advisory boundary. Replace those labels with explicit non-authoritative forecast context and add contract tests. |
| Self-hosted UI dependencies and CSP hardening | **REJECT** in this phase | Tailwind, Lucide, Leaflet and ECharts are loaded from CDNs, but no reviewed vendored copies, integrity pins, licenses or local build pipeline exist. Removing them breaks the single-file monitor; copying unknown versions is not demonstrably safer. CSP cannot honestly become self-only while those dependencies remain. Phase 7 will document the gap and preserve the current functional UI. A later isolated UI-assets phase should vendor exact reviewed versions, record hashes/licenses, test offline rendering, then tighten CSP to self-only. |
| SQLite hardening | **ACCEPT** (targeted) | Connections set WAL and foreign keys but no busy timeout, and file mode depends partly on process umask. Add a bounded connection/busy timeout and force the database file to owner-only mode. Do not change schema/backend or introduce a pool. |
| systemd hardening | **ACCEPT** (targeted) | Several units lack `UMask=0077`; monitor and threat-hunt units also omit the common group/hardening baseline. Align the existing modular-monolith units without changing networking, users, service topology or secrets. |
| Migration, backup, retry, privacy and large-session tests | **MODIFY** | Phase 5 already added migration, transactional outbox, backup/restore and retry mechanisms; replacing them is unjustified. Add regression tests for schema ledger continuity, SQLite contention/permissions, backup privacy, retry identity stability, lifecycle-gated enrichment, spool/ingest sanitization, and a session whose durable event count exceeds the in-memory history limit. |

## Explicitly excluded

- No GCP, Raspberry Pi, network feed, package registry or third-party API access.
- No model training, recalibration, authority change or automatic response.
- No bundled GeoIP/Tor/threat dataset without a separately reviewed source,
  license, evaluation, pin and rollback artifact.
- No database replacement, microservice split or schema rewrite.
- No historical payload, ID or artifact rewrite.

## Reviewable implementation boundaries

1. **Privacy/config/enrichment:** shared pre-persistence sanitizer, strict config,
   lifecycle-gated optional external profile, verified local snapshot envelope.
2. **Canonical runtime paths:** durable evidence manifest/reconstruction,
   canonical classifier-only active path, durable campaign-only active path,
   deterministic new identities.
3. **Operational contracts:** SQLite/systemd hardening, monitor wording,
   documentation and focused privacy/large-session/backup/retry tests.

Each boundary is a separate commit. A boundary advances only after its focused
tests pass. The full suite must pass before Phase 7 is complete.

## Acceptance criteria

- No new Cowrie login username/password plaintext reaches the spool or SQLite
  payload, including direct ingest clients.
- An external provider is never called for an IP under the current lifecycle
  policy. Non-IP calls require the explicit `non_ip_observables` profile.
- Invalid/expired/oversized local snapshots and invalid configuration fail
  closed with stable, non-secret errors.
- A closed session report reconstructs the exact durable event manifest even
  when the in-memory event history truncated; a mismatch or configured size
  excess abstains.
- New classification events originate from the configured canonical classifier
  and carry its exact policy provenance.
- The active monitor cannot emit an in-memory campaign/returning-actor alert.
- Retried alerts, reports and artifact generations retain the same identity for
  the same authoritative evidence.
- v4/v3 validation and authority invariants remain unchanged; prediction and
  enrichment context cannot change findings, hypotheses, guidance IDs/actions,
  alerts or response authority.
- Focused tests and the full feasible suite pass, and the worktree is clean.
