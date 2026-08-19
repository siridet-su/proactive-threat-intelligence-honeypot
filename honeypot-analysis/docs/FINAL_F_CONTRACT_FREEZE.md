# Final F Contract Freeze

Status: Phase 0 contract specification. It is not an active runtime contract.

Final F is the external-AI role named **chronological graph-grounded analyst
synthesis and prioritization**. Deterministic analysis remains the sole
authority for evidence, typed semantics, ATT&CK mappings, graph objects,
findings, hypotheses, limitations, evidence gaps, and manual guidance.

The machine-readable freeze is
`evaluation/final_f_contract_bundle.v1.json`. The proposed reviewed policy is
`evaluation/final_f_ai_advisory_policy.v2.proposed.json`. Neither file is read
by production configuration or runtime code in Phase 0.

## Frozen authority boundary

The provider may select and order only identifiers and codes present in its
current projection. It may not create evidence, facts, ATT&CK mappings,
relationships, chains, findings, hypotheses, actions, alerts, execution
instructions, severity, confidence, or factual prose. Visible prose is
rendered locally from reviewed templates after strict validation.

AI output is separately persisted and has no canonical, finding, hypothesis,
guidance, alert, response, or prediction authority. Provider failure,
abstention, rejection, timeout, retry exhaustion, or unavailability cannot
change the canonical assessment.

## Frozen chronology rule

The existing `canonical_semantic_graph.v1` remains the only semantic graph.
The future projection must derive ordering from durable evidence
`sequence_index` values and directed `source_fact_ref -> target_fact_ref`
relationships. It must not trust the current lexicographically sorted chain
fact list as chronology.

Facts are mapped to their ordered observed evidence. Directed edges must not
contradict durable order. A stable topological order is resolved with durable
sequence and stable IDs as tie breakers. Only after validation is that order
converted into a dense provider ordinal.

Classification-only evidence with no durable sequence may support an already
ordered fact, but cannot create a new chronological step. Cycles,
contradictions, or unresolved placement make the affected chain ineligible.
If no eligible synthesis context remains, the advisory abstains locally and
the provider is not invoked.

## Frozen privacy rule

The projection is a positive allowlist of categorical fields and
assessment-scoped aliases. It excludes raw commands and fragments, durable
event references, addresses, usernames, credentials, URLs, payloads,
filenames, raw entity values, arbitrary descriptions, canonical statements,
and previous AI prose.

Aliases are derived as:

`HMAC-SHA256(alias_key, provider_id || assessment_id || object_kind || local_id)`

and encoded as `a_` followed by 32 lowercase hexadecimal characters. The
full digest is retained locally for collision detection; only the truncated
alias is projected. Alias resolution is local and a collision fails closed.
Assessment scoping prevents cross-session correlation.

## Frozen invocation rule

Every new v6 report may create a durable v2 advisory task, but the external
provider is called only when all of these conditions hold:

1. the v6 report, graph, guidance, and complete identities validate;
2. the chronological projection is internally consistent;
3. at least one AI-eligible chain or at least two trusted findings exist; and
4. at least one approved manual action, existing bounded hypothesis,
   additional trusted finding/chain, limitation, or evidence gap exists.

Failure of this rule creates a local, non-provider abstention with an
allowlisted reason. Unknown deterministic cases remain unsupported and are
not sent to the provider for open-ended reasoning.

## Frozen synthesis semantics

A non-abstaining response chooses primary existing chains/findings, ranks
existing trusted findings and approved manual actions, selects existing
bounded hypotheses, surfaces existing limitations and gaps, and returns an
ordered review plan. Every plan step has exactly one selected anchor and only
references already selected projected objects.

Partial chains are eligible only when the future deterministic graph-view
policy explicitly marks them eligible and they are linked to an existing
validated hypothesis or evidence gap. Audit-only candidates are never
eligible.

## Version and compatibility boundary

The successor names frozen by this phase are:

- `session_assessment.v6`
- `response_guidance.v4`
- `ai_advisory_projection.v2`
- `ai_provider_output.v2`
- `ai_advisory_validated_output.v2`
- `ai_advisory_rendered.v2`
- `ai_advisory_record.v2`
- `ai_advisory_task.v2`
- `ai_vertex_request.v2`
- `ai_advisory_policy.v2`

Historical v4/v5 assessments, guidance v3, and AI advisory v1 records remain
immutable and use version-specific readers and renderers. Shadow candidates
remain readable only in historical v1 records. They do not exist in the v2
provider or persisted advisory contracts. No historical report is requeued or
rewritten merely to obtain v2 output.

Existing SQLite tables and MongoDB collections are reused. Phase 0 performs no
database or schema migration.

## Evaluation freeze

The later thesis evaluation compares deterministic default ordering, the
historical flat v1 selector, and Final F. The frozen design uses 40 cases: 30
approved nonsealed development sessions and 10 synthetic contract edge cases,
with four ten-case strata. Human prioritization claims require two independent
reviewers. A single reviewer permits descriptive results only.

The evaluation measures structural grounding, prioritization agreement,
omission, review time, abstention, repeat stability, containment, invocation
rate, latency, tokens, and cost. It does not measure ATT&CK accuracy,
novel-threat discovery, attacker intent, hypothesis truth, SOC efficacy, or
autonomous response.

## Phase 0 exclusions

This freeze does not change canonical producers, guidance, AI runtime,
provider calls, worker/outbox behavior, storage, API/UI, production
configuration, or Transformer prediction. Subsequent phases require separate
authorization.
