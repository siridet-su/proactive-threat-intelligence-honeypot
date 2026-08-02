# System architecture

This is the canonical architecture and analytical-authority contract.

## End-to-end flow

```text
Pi Cowrie (sanitized JSON)
  -> sensor_forwarder (bounded durable batches, sensor authentication)
  -> HAProxy/PROXY protocol and ingest_api
  -> SQLite (transactions, deduplication, leases, outbox)
  -> session_worker/session_monitor
  -> reviewed classification and canonical evidence reconstruction
  -> session_assessment.v4 + advisory Transformer snapshot
  -> response_guidance.v3 (manual-only)
  -> JSON/Markdown/PDF/STIX reports, dashboard API, monitor UI
```

The last repository-recorded public Cowrie route is TCP/2222. The application
ingest route is private (Tailscale); dashboard and monitor health routes are
loopback services. The exact final connectivity evidence is
`evaluation/cowrie_public_connectivity_root_cause_20260802.json`: HAProxy was
already bound correctly and its Pi backend was healthy; the existing scoped
GCP firewall rule was disabled and was re-enabled without adding a listener or
widening its declared source range. Live state is not inferred from that
receipt.

## Component and trust boundaries

- `production.workers.sensor_forwarder` reads only the authorized sanitized
  Cowrie feed and sends authenticated, bounded batches.
- `production.api.ingest_api` validates authentication, limits, event shape,
  and sensitive-data policy before a transaction reaches SQLite.
- `production.storage.backend` is authoritative. SQLite is the only active
  backend; historical adapters are read-only.
- Session workers reconstruct complete sessions, apply reviewed deterministic
  classification, and build occurrence-preserving evidence relationships.
- Reports and APIs revalidate the same v4/v3 contracts at their boundaries.
  STIX is an export, not an authority escalation.

| Data | Authority |
| --- | --- |
| Observed Cowrie events | Canonical evidence, subject to ingest provenance |
| Reviewed rule classifications | Trusted candidate evidence only when policy permits |
| SecureBERT candidates, enrichment, correlations | Audit/context only |
| Transformer/VOMM predictions | Advisory prediction context only |
| Findings and hypotheses | v4 whole-contract evaluator |
| Guidance | v3 policy over immutable canonical evidence |
| Response execution | Outside this application and requires a human |

## Session assessment v4

`session_assessment.v4` is the sole assessment authority for newly generated
reports. Its evaluator normalizes one Cowrie session, rebuilds evidence
relationships rather than accepting a caller cache, and creates exactly one
content-addressed `canonical_evidence_snapshot.v1`. That snapshot contains
sensor evidence, observations, direct Cowrie transfer events, entities,
relationships, connected chains, and trusted ATT&CK candidates. Model-only or
audit-only classifications are excluded.

The classification policy is read once, validated as a whole, hashed from
those exact bytes, and compiled from that document. An explicitly configured
missing or invalid behavior, classification, or MITRE source is never replaced
with a bundled source: the result fails closed to
`observation_only_abstention`, retains the evidence snapshot, and emits no
findings or hypothesis sets.

The canonical output contains:

- `behavioral_findings`: bounded observations with content-addressed IDs and
  exact evidence references; and
- `hypothesis_sets`: bounded, non-exhaustive alternatives with falsification
  conditions, never attacker-intent or exact-next-action claims.

An incomplete-chain hypothesis requires a resolved artifact identity and no
completion observation for that identity anywhere in the canonical session.
Ambiguous identity or contradictory completion evidence deterministically
abstains. Predictions, enrichment, cross-session correlation, and optional LLM
prose stay under `non_authoritative_context` and cannot change canonical
content, status, or identity.

Each assessment records exact evidence, policy, model-artifact, MITRE-cache,
evaluator-revision, and cache-rebuild provenance. Actual and expected hashes
remain distinct; metadata cannot turn a mismatch into verification. New
records contain no intent, objective, predicted-next-action, global-score,
mitigation, response-action, or alert authority. Historical v2/v3 payloads
remain immutable behind read-only adapters.

Whole-contract validation checks evidence/policy/typed-semantic provenance,
authority flags, meaningful selected-content IDs and traces, resolvable
evidence references, and prohibited fields. Monitor summaries, API payloads,
and JSON/Markdown/PDF/STIX exports consume those same validated values; STIX
cannot promote a hypothesis into an indicator, alert, actor, or action.

## Typed semantic facts

`typed_semantic_fact_set.v2` is a deterministic, lossless interpretation of
the same redacted observed behavior. It binds canonical/source evidence,
every extractor-read input field, exact behavior/classification/vocabulary
policy bytes and hashes, extractor/vocabulary versions, and evaluator Git
revision. A missing, invalid, or substituted vocabulary makes affected family
input unavailable; no vocabulary or legacy matcher is substituted.

The complete fact set is validated and content-addressed but is not persisted,
served by an API, or rendered. V4 and v3 independently retain only bounded
selection traces. Facts preserve ordered operation facets, Cowrie-scoped
outcomes, proof scope, structured and redacted entity identity, shell and
working-directory context, resolved paths, evidence references, typed
relationships/chains, and ATT&CK mapping scope. ATT&CK candidates have
`may_define_operations=false` and cannot create a literal operation.

The extractor supports a deliberately bounded shell subset: POSIX words and
quoting, the canonical pipe/`&&`/`||`/sequence split, simple redirection,
reviewed command options, and explicit wrapper forms. Variables, globs,
substitution, heredocs, file-descriptor manipulation, unsupported options, and
malformed quoting abstain. Failed or compound outcomes never become completed
fragment effects. Limits are 2,048 facts, 8,192 entities, 8,192 relationships,
2,048 chains, 8,192 UTF-8 bytes per command, and 1 MiB aggregate command
input; exceeding a limit closes affected selection.

Relationships require resolved shared identity and an applicable observed
outcome. A conditional path may produce a partial diagnostic relation with no
authoritative entity reference, but it cannot become a supported relation or
chain. Transfer attempts connect to direct transfer observations only through
matching resolved identity.

Only these family slices are activated:

- `sensitive_read` requires exactly a parsed successful `file_read` plus
  `credential_path_read` on the same resolved, linkable entity. Matching is
  against the complete quote-normalized path with segment-exact reviewed
  names. Mentions, failures, extra operations, ambiguous/conditional outcomes,
  unsupported syntax, and unresolved identity abstain.
- `transfer` requires one direct `cowrie.session.file_download` or
  `cowrie.session.file_upload` observation, one exact linkable SHA-256, a direct
  event outcome/reference, and no unresolved entity. Downloader commands and
  ATT&CK T1105 remain attempts/context; linkage does not prove causality or
  execution.
- `inspection` requires exactly one reviewed, successful inspection operation
  in a parsed non-abstained fragment. Required entities and paths must resolve;
  valid entity-free operations need no invented target. It creates only a
  bounded observation finding and makes no reconnaissance, intent, compromise,
  result-content, or real-host claim.
- `transfer_attempt` records a bounded command transfer attempt without
  promoting it to a direct transfer observation or a completed effect.
- `filesystem` requires a reviewed, successful filesystem-change operation
  with resolved mutation identity; it does not establish resulting state,
  persistence, cleanup, compromise, or real-host effect.
- `execution` requires a reviewed, successful execution-attempt operation with
  resolved script or inline-program identity; it does not establish program
  existence, completed execution, or any effect.

All other operation families remain contained or shadow-only. Sensitive-read
and direct-transfer may select specialized v3 guidance; inspection adds no
specialized guidance or hypothesis. A typed-evaluation error fails activated
selection closed without promoting legacy matching.

Cowrie-reported command success is not proof of credential acquisition or a
real-host effect. Direct-transfer guidance asks only for manual correlation of
the exact observed hash and does not claim download execution or host impact.

## Response guidance v3

`response_guidance.v3` is the sole guidance authority for new reports, APIs,
monitor views, and artifacts. Only the immutable evidence snapshot embedded in
the sibling v4 assessment may select findings, triage, or advisory tasks.
Policy validation rejects prediction, enrichment/reputation, regex,
default-guidance, and automatic-execution conditions. Each selected task has a
complete predicate trace and at least one canonical Cowrie evidence reference.

`guidance_id` binds the evidence digest, exact policy SHA-256, any explicitly
configured non-example asset-profile SHA-256, complete selected content, and
activated typed-semantic vocabulary/selection hashes. Timestamps, predictions,
enrichment, scores, and source locations do not affect identity. Asset context
cannot select tasks.

Every task permanently requires manual approval, is unsafe to auto-execute,
and records execution integration as not implemented. Guidance produces no
alerts or response actions and is never written into prediction snapshots.
Historical guidance remains unchanged and readable only through a
non-authorizing legacy adapter.

The guidance-policy path defaults to
`configs/response_guidance_policy.v3.json`. An optional asset profile must be
explicitly configured, must not be the example profile, and contributes its
byte hash to provenance without influencing selection.

## Deliberate simplifications

MongoDB, PostgreSQL, SMB, Vertex, legacy report generators, duplicate monitor
renderers, prediction-only recommendations, and automatic response paths are
removed or archived. The application is a modular monolith with separately
managed systemd processes, not a microservice or SOAR platform.
