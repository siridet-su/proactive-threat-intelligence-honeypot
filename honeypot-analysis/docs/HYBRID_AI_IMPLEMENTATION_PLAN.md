# Hybrid AI Advisory Implementation Plan

Status: original implementation plan plus Vertex/ADC addendum, 2026-08-10

Baseline: branch `professor-approved-poc-evaluation`, revision
`f1b9dabe4c98cac3363bf04b877437d770f90c39`.

## Verified current architecture and insertion point

`production/workers/analysis_worker.py` reconstructs a session from durable
SQLite events, builds `session_assessment.v4`, calls
`validate_session_assessment_v4`, attaches artifacts, validates again, and
passes the report to `SQLiteStorage.complete_analysis_job`. That storage method
persists the report and completes the analysis job in one `BEGIN IMMEDIATE`
  transaction. AI enqueue is deliberately outside that transaction: after commit,
  a cutoff-gated, best-effort idempotent enqueue records only stable report
  references, and the AI worker reconciles any missing jobs. Optional schema or
  enqueue failure can therefore neither delay nor roll back canonical analysis.

The following remain authoritative and unchanged:

- classification trust decisions and `configs/classification_rules.trusted.json`;
- canonical evidence, typed facts, findings, and hypotheses in
  `production/reporting/session_assessment_v4.py`;
- deterministic guidance in `production/reporting/response_guidance_v3.py` and
  `configs/response_guidance_policy.v3.json`;
- SecureBERT trust gates and the Transformer-only production prediction path;
- report/artifact identities, alerts, webhooks, and response safety policy.

At the original baseline, repository search found no hosted generative-AI client, provider/model
configuration, API credential, or provider SDK. `llm_context` in
`session_assessment_v4.py` is only an optional non-authoritative compatibility
field and is not a provider integration. Therefore this change will add a
provider interface plus a deterministic offline fixture provider. It will not
invent a provider, model, endpoint, or secret. A real hosted adapter remains a
separate, explicitly configured implementation task. That follow-on task is now
implemented as the reviewed, still-disabled `google_vertex_gemini` adapter using
`google-genai`, Vertex AI, and standard ADC. The original safety insertion point
and authority model below are unchanged.

## Reuse and new components

Reuse:

- `stable_json` and `stable_id` from `production/utils/serialization.py`;
- strict SQLite migrations, leases, retries, and queue metrics in
  `production/storage/backend.py`;
- `ProductionConfig.from_env` strict configuration handling;
- v4/v3 whole-contract validators and their recorded policy hashes;
- monitor loopback boundary, no-store responses, and safe DOM `textContent`;
- sensitive-data utilities as a defence-in-depth check, not as the allowlist.

Add:

- `production/ai_advisory/contracts.py`: exact-key schemas, closed-vocabulary
  validation, reference resolution, and normalized accepted output;
- `production/ai_advisory/projection.py`: positive allowlist projection from a
  valid persisted v4 report;
- `production/ai_advisory/provider.py`: provider protocol, disabled provider,
  and test-only fixture provider;
- `production/ai_advisory/rendering.py`: deterministic template renderer;
- `production/workers/ai_advisory_worker.py`: asynchronous leased outbox worker;
- `configs/ai_advisory_policy.v1.json`: immutable vocabularies, template IDs,
  limits, and prompt contract;
- a checksummed, rollback-compatible SQLite schema extension for
  `ai_advisory_outbox` and `ai_advisories`;
- an additive monitor API and separately labelled non-authoritative panels;
- focused tests and an offline research-evaluation interface.

No AI field will be added to `session_assessment.v4`, `response_guidance.v3`,
prediction snapshots, report artifacts, alerts, or webhooks.

## Storage and transaction design

The rollback-compatible extension adds:

1. `ai_advisory_outbox`, using the repository's standard `job_id`, queued /
   retry / running / succeeded / failed lifecycle, lease token, bounded
   attempts, stable error codes, and a payload containing only `report_id`,
   `session_id`, and `assessment_id`.
2. `ai_advisories`, keyed by a content-addressed `advisory_id` and a unique
   cache key. It records accepted/rejected/unavailable status, normalized
   advisory and shadow data (accepted data only), request/response hashes,
   provider/model/prompt/schema/policy provenance, validation reason codes,
   and evaluation counters. Rejected raw provider text is never persisted.

`complete_analysis_job(..., enqueue_ai_advisory=False)` remains backward
compatible. The analysis worker passes the feature flag. Canonical commit is
atomic and independent; post-commit enqueue plus worker reconciliation is
recoverable and bounded. The default is disabled, so canonical storage startup
does not create or validate the optional extension and existing runtime
behaviour is unchanged.

Identical request projections, policy, provider, model, adapter revision,
endpoint identity, API version, request options, prompt, schema, and explicit
byte/token budgets produce one cache key. A completed row is replayed without
another provider call. Timestamps and latency never enter content identities.

## Configuration and secrets

New strict settings are disabled by default:

- `enable_ai_advisory=false` / `ENABLE_AI_ADVISORY`;
- `ai_advisory_provider=disabled` / `AI_ADVISORY_PROVIDER`;
- `ai_advisory_model` / `AI_ADVISORY_MODEL`;
- `ai_advisory_project` / `AI_ADVISORY_PROJECT` and
  `ai_advisory_location` / `AI_ADVISORY_LOCATION`;
- `ai_advisory_policy_path` / `AI_ADVISORY_POLICY_PATH`;
- `ai_advisory_api_key_file` / `AI_ADVISORY_API_KEY_FILE` for future adapters
  only; the reviewed Vertex adapter rejects it and uses ADC;
- provider-scoped alias-key and short-lived activation-receipt files;
- a required canonical `prediction_evidence_cutoff.v1` event-prefix boundary,
  exactly duplicated in the activation receipt under `new_sessions_only`;
- an exact HTTPS endpoint host allowlist for every reviewed hosted adapter;
- bounded batch, poll, lease, timeout, retry, request/response-size, token-budget,
  queue, global record/byte, and advisory-retention settings;
- `ai_advisory_fixture_response_path`, accepted only by the offline fixture
  adapter used in tests/evaluation.

Secure file loading uses absolute component-wise no-follow descriptor opens,
then verifies exact owner, regular-file type, mode, and size on the opened
descriptor. A hosted adapter must resolve its reviewed credential mechanism at
call time and never log credential material. The Vertex adapter uses ADC and
accepts no key value. A managed static worker unit is present but disabled by default; no
production secret, provider, or activation is included.

The new-session-only boundary is the canonical tuple `(received_at, event_id)`.
`received_at` is normalized to UTC with microsecond precision; tuple equality is
historical/excluded. A report is eligible only if the session's earliest
persisted event is strictly after the tuple. Missing/malformed values and
receipt mismatches fail closed, while the config/receipt persistence survives
worker restart, interruption, and VM reboot without a database schema change.

## Allowlisted request projection

`ai_advisory_projection.v1` has `additionalProperties=false` semantics and the
following exact top-level fields:

- `schema_version`, provider-scoped assessment/evidence aliases, and
  `projection_sha256`;
- `provenance`: evaluator revision plus exact behavior, classification, MITRE,
  model-artifact-set, typed fact/vocabulary, guidance policy/profile, and AI
  policy hashes;
- `authority`: fixed false values for AI authority, execution, and alerts;
- `evidence_index`: opaque evidence ID, allowlisted event type, ordinal, and
  categorical observation status only;
- `findings`: existing IDs, policy rule/type, categorical status/severity,
  evidence and relationship references, and limitation codes;
- `relationships`: existing opaque IDs, categorical relationship type/status,
  opaque evidence/entity/chain references, and limitation codes;
- `hypotheses`: existing hypothesis IDs, status, evidence/relationship
  references, limitations, and falsifier codes only;
- `guidance`: existing guidance ID/state and existing action IDs, rule IDs,
  order, evidence/finding references, and fixed safety booleans;
- `abstention`: categorical status and allowlisted reason code;
- `allowed_output`: the policy's template, reason, limitation, candidate,
  missing-evidence, and falsifier codes.

Canonical IDs and stable local hashes are never provider-visible; keyed-HMAC
aliases are scoped to the selected provider identity and mapped back only in
worker memory after reference validation. It deliberately excludes raw commands, command fragments, usernames, source
IPs, credentials, payloads, URLs, hashes of downloaded payloads, raw event
documents, timestamps precise enough to identify a subject, enrichment text,
prediction prose, entity values, canonical statements/action prose, and all
untrusted strings. A recursive prohibited-key scan plus closed-vocabulary and
reference validation runs after construction. This is not a general value
redactor: the positive allowlist and categorical IDs are the primary privacy
boundary. Telemetry is data only; no telemetry text is included in provider
instructions.

## Provider output contracts

The provider envelope is `ai_provider_output.v1`, with exactly
`schema_version`, `projection_sha256`, `policy_sha256`,
`validated_advisory`, and `shadow_candidates`.

`ai_validated_advisory_selection.v1` contains only:

- `schema_version`, `abstained`, `abstention_reason_code`;
- ordered, unique `selected_finding_ids`, `selected_relationship_ids`, and
  `ranked_action_ids`;
- `template_selections`, each containing one approved template ID and lists of
  existing finding, relationship, action, limitation, and reason codes.

It contains no prose, confidence, severity, ATT&CK mapping, new action, alert,
or execution field.

`ai_shadow_candidate_set.v1` contains only:

- `schema_version` and a bounded `candidates` list;
- each candidate has fixed status `unverified_ai_candidate`, an allowlisted
  candidate type, existing premise finding/relationship/evidence IDs,
  allowlisted reason/missing-evidence/falsifier codes, and no free text;
- candidate IDs are computed by the server after validation.

All objects reject extra properties. Lists have policy-defined count and string
limits. Numeric model confidence is not accepted.

## Deterministic validation and rendering

Before a call, the worker revalidates the persisted v4 record, its v3 guidance,
policy hashes, and projection hash. After a call it:

- requires exact schema and policy/projection hash echoes;
- rejects unknown/duplicate/invented IDs or codes;
- resolves every evidence, entity, chain, relationship, finding, hypothesis,
  action, policy, and template reference against the immutable projection;
- permits only supported relationships and canonical existing items;
- verifies every selected action still has `requires_manual_approval=true`,
  `safe_to_auto_execute=false`, and no execution integration;
- applies template-specific cardinality and reference requirements;
- rejects prohibited keys, prose, ATT&CK creation, severity changes, alerts,
  actions, instructions, URLs, or confidence fields;
- treats structural validation of a shadow candidate as permission to retain an
  explicitly unverified candidate, never as confirmation of its claim;
- abstains and stores only error codes/hashes on any mismatch.

The renderer is deterministic. Approved templates from the hash-bound policy
combine accepted IDs, semantic family names, relationship counts, manual-only
action IDs, and limitation codes. Canonical statements, relationship labels,
and other evidence values are never substituted. A final central privacy scan is still
performed before persistence. Provider text is never rendered. Identical
normalized selections and policies produce identical visible text.

## Worker failure behaviour

The worker uses bounded durable claims, queue growth limits, global retention
bounds, and heartbeat renewal. Provider timeout,
rate limit, and transient outage schedule bounded exponential retry. Schema,
reference, policy, safety, or prohibited-content failure is terminal rejection.
After attempts are exhausted the row becomes unavailable. Every path emits only
safe hashes, reason codes, and latency counters to logs. Canonical reports are
already committed and are never modified. Running the worker while disabled
performs no calls.

## API, UI, privacy, and injection boundary

An additive loopback-monitor endpoint returns a separate advisory only when it
matches the exact current canonical report and assessment. Older data is marked
superseded rather than displayed; pending, failed, unavailable, and superseded
states are explicit. Existing public session/report APIs remain unchanged. The
monitor loads it asynchronously and labels sections “AI-generated advisory —
non-authoritative” and “Unverified AI candidates.” Responses use
`Cache-Control: no-store`; rendering uses `textContent`. No AI content is placed
in initial HTML, exports, reports, PDF, STIX, logs, alerts, webhooks, or
prediction snapshots.

The positive projection, rather than a blacklist redactor, is the primary
privacy boundary. Recursive prohibited-field scans, length limits, absence of
telemetry text, a fixed provider instruction contract, strict JSON-only output,
and rejection of extra fields provide defence in depth against prompt
injection. AI output cannot call tools or select any operation outside existing
manual-only guidance.

## Migration and compatibility

The SQLite extension is additive and non-destructive. Historical v1/v2/v3/v4
records are not rewritten. It uses a separate checksummed extension ledger and
leaves `PRAGMA user_version` at the existing version, so the previous release
can open the database and ignore the new tables during rollback. Existing
storage calls retain default arguments. AI-disabled reports, IDs, artifacts,
APIs, and service results must remain byte and semantically unchanged.

## Tests and research metrics

Unit and integration tests cover:

- disabled, success, timeout/outage, malformed JSON, and retry exhaustion;
- canonical report equality before/after success or failure;
- strict additional-property rejection and invented IDs/references/hashes;
- unsafe actions, execution/alert requests, confidence, and prohibited fields;
- recursive absence of commands, credentials, IPs, URLs, secrets, payloads,
  usernames, raw events, and injected telemetry from the projection;
- deterministic cache replay and renderer output;
- shadow/canonical separation;
- atomic outbox enqueue, leases, cache, schema extension, and backward compatibility;
- additive monitor endpoint, labels, no-store, and safe DOM rendering;
- full existing authority, privacy, v4/v3, prediction, artifact, and storage
  regressions.

Persisted evaluation counters include schema-valid, accepted/rejected,
unsupported/invented-reference, evidence-reference completeness, abstention,
cache hit, latency, and validation reason codes. An offline harness can compare
deterministic-only, an explicitly isolated unrestricted fixture baseline,
validated advisory, and validated advisory plus shadow candidates. Repeated-run
agreement, selected-ID/rank agreement, prompt-injection success, leakage,
coverage, and analyst ratings remain evaluation results rather than product
authority. The implementation must allow the conclusion that AI adds no value.

## Staged implementation and acceptance

1. **Contracts and policy.** Add the immutable policy, projection, exact schemas,
   validators, provider abstraction, and renderer. Acceptance: all prohibited
   data is absent; invented fields/IDs fail; rendering is repeatable.
2. **Durability.** Add the rollback-compatible extension, post-commit
   idempotent enqueue, advisory storage, cache, and bounded queue/reconciliation
   operations. Acceptance: extension/integrity tests
   pass and disabled analysis produces no row or report difference.
3. **Worker and configuration.** Add strict disabled/fixture configuration and
   asynchronous worker. Acceptance: success, rejection, retry, cache, outage,
   and canonical-isolation tests pass without network access.
4. **Additive monitor view.** Add the separate endpoint and labelled DOM panel.
   Acceptance: canonical APIs/artifacts are byte-identical; no-store and safe
   rendering tests pass.
5. **Evaluation and documentation.** Add metrics export/offline fixtures and
   operator documentation. Acceptance: focused suites and the full feasible
   repository suite pass; worktree contains no secrets or provider choice.

The follow-on implementation adds one reviewed Vertex/ADC adapter and a gated
one-request integration test. Production activation/manifest changes, permanent
credentials, an analyst study, and production deployment still do not exist.
They require a separately verified readiness receipt and deployment approval
after the offline safety gates pass.
