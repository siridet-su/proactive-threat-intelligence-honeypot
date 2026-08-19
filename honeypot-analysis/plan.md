## 1. CURRENT IMPLEMENTATION SUMMARY

The current system already has most of the required safety infrastructure, but its active contracts are inconsistent:

- The normal canonical coordinator still produces `session_assessment.v4` through [canonical_pipeline.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/reporting/canonical_pipeline.py:15).
- The analysis-worker fallback aliases the v5 builder under a v4 name in [analysis_worker.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/workers/analysis_worker.py:36). Normal and fallback paths can therefore produce different assessment versions.
- V4 appends audit-only findings back into `behavioral_findings` in [session_assessment_v4.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/reporting/session_assessment_v4.py:870).
- V5 already fixes that authority boundary and strengthens hypotheses in [session_assessment_v5.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/reporting/session_assessment_v5.py:172), but is not the sole producer.
- `canonical_semantic_graph.v1` already contains evidence, facts, entities, directed relationships, chains, authority decisions, and audit-only candidates in [canonical_semantic_graph.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/reporting/canonical_semantic_graph.py:13). It is sufficient as the one canonical graph.
- Guidance v3 is manual-only and prediction-independent, but its validator is not a complete content-integrity boundary. Dashboard “current” reevaluation rebuilds from denormalized session data rather than the exact durable graph.
- The current AI system is a constrained flat selector:

  - `ai_advisory_projection.v1`;
  - `ai_provider_output.v1`;
  - existing finding/relationship/action selection;
  - template selection;
  - historical `shadow_candidates`.

- The provider receives structured JSON and returns schema-constrained JSON. Server-side templates produce visible prose.
- The AI worker already has a durable outbox, leases, retries, cache identity, provider deadlines, retention, and failure isolation.
- SQLite and MongoDB AI storage are generic JSON-backed records and do not require a new database layout for a v2 advisory.
- The UI already separates deterministic, AI, and prediction lanes, although v4 findings and historical shadow candidates can still be presented too strongly.
- Transformer prediction is operationally separate in [session_worker.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/workers/session_worker.py:678) and does not require modification for Final F.

Repository inspection was read-only. Tracked files remain unchanged at `feabca5c27fcb09f02271dad792bfd96d20b6d90`.

## 2. FINAL F TARGET SUMMARY

Final F is a deterministic-first architecture in which the external AI:

- receives a privacy-minimized chronological view of the existing canonical graph;
- selects and orders existing chains, trusted findings, bounded hypotheses, manual actions, limitations, gaps, questions, and explanation templates;
- returns a structured whole-session review plan;
- cannot introduce factual prose or new analytical objects;
- is validated locally and rendered with server-owned templates;
- remains separately persisted and non-authoritative;
- abstains without affecting the canonical report.

The final canonical production record should be a proposed `session_assessment.v6`, based on v5 authority semantics and embedding a new graph-bound `response_guidance.v4`.

The existing semantic graph remains the only graph.

## 3. CURRENT → FINAL GAP TABLE

| Component | Current | Final | Action | Main ownership | Dependency |
|---|---|---|---|---|---|
| Canonical assessment | Normal path v4; fallback v5 | One v6 producer; v4/v5 read-only | MODIFY/ADD | `canonical_pipeline.py`, `analysis_worker.py`, `session_assessment_v5.py`, new `session_assessment_v6.py` | Phases 1–2 |
| Finding authority | V4 republishes audit-only findings | Trusted findings only; audit candidates separate | MODIFY | `session_assessment_v5.py`, consumers | Phase 1 |
| Semantic graph | One content-addressed v1 graph | Same graph plus validated query/view helper | KEEP/ADD | `canonical_semantic_graph.py`, new `canonical_graph_queries.py` | Phase 2 |
| Chronology | Evidence has `sequence_index`; chains list sorted references | Directed, chronology-checked projection derived from evidence and edges | MODIFY | New graph-query and projection code | Phases 2–3 |
| Hypotheses | V4 and stricter v5 formats coexist | V5/v6 `threat_hypothesis_set.v2` only for new AI input | KEEP/MODIFY | `session_assessment_v5.py` | Phase 1 |
| Guidance builder | V3 selects from snapshot arrays and separately supplied facts | V4 queries the validated graph only | REPLACE active path | `response_guidance_v3.py`, new `response_guidance_v4.py` | Phase 2 |
| Guidance validator | Open/incomplete content and policy binding | Closed shape, policy-content binding, exact graph/reference binding | REPLACE active path | New v4 validator | Phase 2 |
| Current reevaluation | Rebuilds from denormalized session fields | Uses current validated report/graph or fails closed | MODIFY | `dashboard_api.py`, `monitor_web.py` | Phase 2 |
| AI projection | Flat lists and synthetic ordinal | Chronological graph view with chains, facts, edges, gaps | REPLACE active path | `ai_advisory/projection.py` | Phase 3 |
| AI output contract | Flat selection plus shadow candidates | Structured synthesis selection and ordered review plan | ADD/DEPRECATE | `ai_advisory/contracts.py`, policy v2 | Phase 4 |
| Provider request | `ai_vertex_request.v1` | Versioned v2 request using projection/output v2 | MODIFY | `google_vertex_provider.py` | Phases 3–4 |
| Local validator | Strict v1 structure, including shadow candidates | Strict v2 grounding and cross-reference validation | ADD | `contracts.py` or `contracts_v2.py` | Phase 4 |
| Renderer | V1 policy-authored paragraphs | Version-dispatched v1/v2 renderer; structured plan text | EXTEND | `rendering.py` | Phase 5 |
| Worker/outbox | Robust v1 asynchronous workflow | Version dispatch and deterministic no-call abstention | EXTEND | `ai_advisory_worker.py` | Phase 5 |
| Persistence | Generic JSON records in existing tables/collections | Same storage, v1/v2 payloads | KEEP/MODIFY validation | `backend.py`, `mongodb_operations.py` | Phase 5 |
| API | Returns v1 fields including shadow candidates | Versioned common view plus v2 synthesis | EXTEND | `monitor_web.py` | Phase 6 |
| UI | Separate lane, but active shadow section and authority drift | Structured AI plan; v1 shadows historical-only | MODIFY | `static/monitor.html`, `monitor_web.py` | Phase 6 |
| Artifacts | Consume top-level findings | Validate authority/version before export | MODIFY | `artifacts.py` | Phase 1 |
| Historical records | V4/v5 reports and AI v1 records | Immutable and version-rendered | KEEP | Readers and renderers | All |
| Transformer | Separate trusted-history predictor | Unchanged and isolated | KEEP | `production/prediction/*`, `session_worker.py` | Noninterference tests only |

## 4. CONFIRMED PREREQUISITE BUG FIXES

All five previously reported issues remain confirmed.

1. **A — Audit-only finding leakage**

   V4 runs authority decisions, then appends `audit_findings` back into `behavioral_findings`. Monitor and artifact consumers subsequently treat the resulting collection as canonical.

   Classification: **PREREQUISITE BUG FIX**.

2. **B — Current-guidance durable-prefix bypass**

   [dashboard_api.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/api/dashboard_api.py:190) loads a denormalized session and calls `build_response_guidance_v3_from_session`. It does not require the current report’s exact durable prefix or semantic graph.

   Classification: **PREREQUISITE BUG FIX**.

3. **C — Guidance integrity boundary incomplete**

   V3 does not fully bind output content to the referenced policy bytes, exact graph facts, or exact predicate evidence. Its schema is not fully closed against all unexpected nested or authority-bearing content.

   Classification: **PREREQUISITE BUG FIX**.

4. **D — V4/V5 producer drift**

   The normal coordinator imports v4 while the fallback worker aliases v5 as v4.

   Classification: **PREREQUISITE BUG FIX**.

5. **E — UI/export authority enforcement**

   Monitor, Markdown/PDF, and STIX consumers iterate top-level findings without consistently resolving each finding against graph authority.

   Classification: **PREREQUISITE BUG FIX**.

No Final F provider call should be permitted until these defects are closed.

## 5. COMPONENTS TO KEEP UNCHANGED

Keep the following architecture and semantics:

- durable Cowrie evidence ordering and session reconstruction;
- typed semantic parsing and abstention;
- reviewed ATT&CK classification and authority policy;
- `canonical_semantic_graph.v1` as the single graph;
- v5 bounded hypothesis construction;
- existing manual action catalog and all manual-only safety flags;
- HMAC/provider aliasing infrastructure;
- provider credentials through reviewed ADC handling;
- outbox lease, retry, cache, deadline, heartbeat, reconciliation, and retention mechanisms;
- generic SQLite/MongoDB advisory storage layout;
- canonical report completion when AI fails;
- existing non-authoritative AI authority declarations;
- Transformer target, inputs, history, model artifacts, receipts, UI semantics, and runtime;
- historical v1/v4/v5 readers.

## 6. COMPONENTS TO MODIFY

- Make the canonical coordinator and fallback use one explicit assessment builder.
- Require authority-aware finding rendering in all consumers.
- Replace session-only guidance reevaluation with graph-bound reevaluation.
- Introduce guidance v4 validation and content identity.
- Extend assessment identity with a complete report-content hash.
- Replace the flat AI projection with a chronological graph projection.
- Add an AI contract version dispatcher.
- Add deterministic invocation eligibility and local no-call abstention.
- Extend worker, renderer, API, and UI for advisory v2.
- Extend storage completion codes to represent deterministic abstention accurately.

## 7. COMPONENTS TO ADD

Recommended additions:

- `production/reporting/canonical_graph_queries.py`
- `production/reporting/response_guidance_v4.py`
- `production/reporting/session_assessment_v6.py`
- `configs/ai_advisory_policy.v2.json`
- versioned projection/output/record validators, either alongside v1 in `contracts.py` or in `contracts_v2.py`;
- v2 deterministic renderer;
- frozen known-answer projection and synthesis fixtures;
- offline Final F evaluation harness;
- release/contract receipt binding all relevant hashes.

`canonical_graph_queries.py` must be a pure view/query layer. It must not construct or persist a second graph.

## 8. COMPONENTS TO DEPRECATE / REMOVE FROM ACTIVE PATH

Deprecate only from new records:

- `session_assessment.v4` production;
- session-payload-only guidance reevaluation;
- `response_guidance.v3` for new v6 reports;
- `ai_advisory_projection.v1`;
- `ai_provider_output.v1`;
- `ai_shadow_candidate_set.v1`;
- provider-selected candidate hypotheses or relationships;
- the active UI heading “Unverified AI candidates.”

Keep all v1/v3/v4/v5 validators and renderers needed for immutable historical data.

## 9. FINAL AI INPUT PROJECTION DESIGN

Proposed schema: `ai_advisory_projection.v2`.

### Identity and provenance

The projection must bind:

- `assessment_id`;
- `report_content_sha256`;
- canonical evidence SHA-256;
- graph SHA-256;
- typed fact-set SHA-256;
- guidance v4 content SHA-256;
- deterministic policy hashes;
- AI policy SHA-256;
- projection SHA-256;
- projection-contract version.

### Projected object sets

1. `timeline_steps`

   Each item contains only:

   - dense causal ordinal;
   - aliased evidence IDs;
   - aliased fact IDs;
   - typed semantic family;
   - allowlisted operation types;
   - categorical outcome;
   - aliased entity IDs;
   - related relationship and chain aliases.

2. `chains`

   - chain alias;
   - deterministic status;
   - fact aliases;
   - directed relationship aliases;
   - evidence aliases;
   - entity aliases;
   - limitation/gap codes;
   - explicit AI-eligibility status.

3. `relationships`

   - relationship alias;
   - relationship type;
   - source and target fact aliases;
   - entity alias;
   - categorical status;
   - limitation codes.

4. `findings`

   Only findings with a matching trusted graph authority decision:

   - finding alias;
   - finding type/family;
   - status;
   - chain, relationship, and evidence aliases;
   - allowlisted deterministic priority band, if one exists;
   - limitation codes.

5. `hypotheses`

   Only validated `threat_hypothesis_set.v2` alternatives:

   - hypothesis and set aliases;
   - chain/fact/relationship/evidence aliases;
   - status;
   - gaps, limitations, and falsifier codes.

6. `actions`

   - action alias;
   - action category/rule alias;
   - supporting finding/evidence aliases;
   - policy order;
   - mandatory manual-only safety fields.

7. `limitations`, `evidence_gaps`, and the exact allowed question/explanation template catalog.

### Chronology construction

The existing graph is adequate:

- evidence nodes provide `sequence_index`;
- fact nodes resolve to evidence;
- relationships provide directed `source_fact_ref → target_fact_ref`;
- chains bind the relevant facts and edges.

The view should:

1. map each fact to its ordered observed evidence;
2. verify directed edges do not contradict durable sequence order;
3. topologically order chain facts using directed edges and evidence sequence;
4. assign a dense provider ordinal after validation;
5. reject cycles, contradictory order, or unresolved causal placement.

Classification-only evidence nodes with `sequence_index=None` must not be assigned fabricated positions. They may remain supporting provenance for an already ordered fact, but cannot independently create a chronological step.

### Privacy

Never project:

- raw commands or fragments;
- durable event references;
- entity values;
- filenames or URLs;
- addresses or usernames;
- policy descriptions containing deployment values;
- statements or arbitrary prose;
- previous AI output.

Aliases should be HMAC-derived in an assessment-specific namespace so identical entities cannot be correlated across unrelated sessions.

## 10. FINAL AI OUTPUT CONTRACT DESIGN

Proposed external schema: `ai_provider_output.v2`.

```text
schema_version
projection_sha256
policy_sha256
synthesis:
  schema_version
  abstained
  abstention_reason_code
  selected_chain_ids
  selected_relationship_ids
  ranked_finding_ids
  selected_hypothesis_ids
  ranked_action_ids
  selected_limitation_codes
  selected_evidence_gap_codes
  analyst_question_selections
  explanation_template_selections
  review_plan
```

Each `review_plan` item should be exact and closed:

```text
order
step_type
anchor_type
anchor_id
related_chain_ids
related_finding_ids
related_hypothesis_ids
related_action_ids
limitation_codes
evidence_gap_codes
analyst_question_template_ids
explanation_template_id
```

Allowlisted `step_type` examples:

- `review_chain`;
- `review_finding`;
- `test_existing_hypothesis`;
- `perform_manual_check`;
- `resolve_evidence_gap`.

The provider cannot return descriptions, rationales, factual statements, ATT&CK fields, confidence, severity, alerts, or executable instructions.

The normalized local record should be `ai_advisory_validated_output.v2`; the persisted envelope should be `ai_advisory_record.v2`.

## 11. WHOLE-SESSION SYNTHESIS SEMANTICS

A valid non-abstaining synthesis must:

1. identify one or more primary existing chains or trusted findings;
2. rank the existing trusted findings relevant to those chains;
3. select existing hypotheses only where their chain/reference domains overlap;
4. rank approved manual checks grounded in the selected findings;
5. surface applicable limitations and evidence gaps;
6. order the review into an explicit bounded plan;
7. select analyst questions that test an existing hypothesis or close an existing gap;
8. select explanation templates for server rendering.

It is more than severity sorting because it joins multiple object categories and orders the investigation. It still cannot infer an absent conclusion.

Partial chains may be eligible only when deterministic policy explicitly marks them eligible and they are tied to a validated existing hypothesis or gap. Audit-only candidates never qualify.

## 12. AI INVOCATION / ABSTENTION RULE

Run the durable AI job for each new v6 report, but call the provider only when this deterministic eligibility rule passes:

```text
valid current v6 report
AND valid complete graph/guidance identities
AND chronological projection is internally consistent
AND (
      at least one AI-eligible chain
      OR at least two trusted findings
    )
AND at least one of:
      approved manual action
      existing bounded hypothesis
      additional trusted finding/chain
      existing limitation or evidence gap
```

This is a simple rule, not a learned router.

If it fails, the worker should persist a local `ai_advisory_record.v2` with:

- `status=abstained`;
- an allowlisted reason such as `insufficient_synthesis_context` or `chronology_unavailable`;
- no provider request;
- no selected objects.

Provider abstention remains separately valid.

Unknown or unsupported deterministic cases do not become AI reasoning tasks.

## 13. VALIDATION DESIGN

The v2 validator must:

- enforce exact keys recursively;
- validate projection and policy hashes;
- resolve every alias against the exact current projection;
- reject duplicate IDs and invalid ranking positions;
- require selected chains to be AI-eligible;
- verify every selected relationship belongs to the graph;
- verify finding authority is trusted;
- verify hypothesis set, chain, relationship, fact, entity, and evidence references;
- verify actions belong to guidance v4 and are manual-only;
- require action evidence/finding references to match the selected deterministic grounding;
- validate limitation and gap codes against the selected objects and policy;
- validate every question/template against the policy catalog and its permitted anchor type;
- require contiguous plan ordering;
- require each plan item to reference already selected objects;
- prohibit all free-text and authority/action keys;
- validate current `assessment_id`, report hash, graph hash, and projection hash;
- reject responses for superseded report revisions;
- ensure abstention has no non-empty selections;
- ensure non-abstention has a primary anchor and at least one plan item.

Failure result:

- provider output rejected or unavailable;
- canonical report remains complete;
- no partial provider content is rendered;
- retry only for transport/provider failures, not deterministic schema rejection.

## 14. DETERMINISTIC RENDERING DESIGN

Extend [rendering.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/production/ai_advisory/rendering.py:36), retaining the v1 renderer.

The v2 renderer should:

- load only the validated local-ID form of the synthesis;
- resolve IDs against the current validated v6 report;
- render section headings and sentences from policy-owned templates;
- render stable object labels/categories, never statements or entity values;
- show the ordered review plan;
- link each item to its deterministic finding/chain/hypothesis/action in the UI;
- run the existing privacy redactor over the complete rendered object;
- content-address the result as `ai_advisory_rendered.v2`.

Suggested UI sections:

1. Primary deterministic chain(s)
2. Prioritized canonical findings
3. Existing hypotheses to test
4. Manual analyst checks
5. Limitations and evidence gaps
6. Suggested analyst questions

Every heading should say that AI selected existing deterministic objects.

## 15. VERSIONING / HISTORICAL COMPATIBILITY

Recommended append-only versions:

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

Compatibility rules:

- V4/v5 reports remain immutable and use their original validators.
- Guidance v3 remains readable through its original validator.
- AI v1 records retain the v1 renderer and historical shadow-candidate UI.
- New AI v2 records contain no shadow-candidate field.
- No v1 record is rewritten or reinterpreted as v2.
- No historical report is requeued merely to obtain v2 AI output.
- New v2 tasks bind `report_content_sha256` in addition to report/assessment IDs.
- API responses expose an explicit contract version while preserving common status fields.
- Existing SQLite tables and MongoDB collections remain unchanged.
- Add the `deterministic_abstention` completion code consistently to SQLite and Mongo operations; this is a code-contract change, not a schema migration.
- At cutover, existing v1 jobs should either drain under the v1 worker or remain handled by version dispatch.

## 16. TRANSFORMER NONINTERFERENCE PLAN

No Transformer file, target, policy, checkpoint, receipt, or support corpus belongs in the Final F change set.

Enforcement tests must prove:

- adding or removing an advisory leaves trusted tactic history byte-identical;
- prediction model inputs and snapshot IDs remain identical before and after AI processing;
- no advisory/projection fields occur recursively in trusted-history manifests;
- AI modules do not import prediction preprocessing, training, or target builders;
- prediction modules do not import AI contracts or advisory records;
- prediction output is absent from the AI premise projection;
- AI output is absent from assessment identity, graph authority, findings, hypotheses, and guidance selection;
- failed AI jobs do not enqueue or alter prediction work.

UI aggregation may display the lanes on one page, but it must not merge their payloads.

## 17. TEST MATRIX

| Area | Required tests |
|---|---|
| Canonical authority | V5/v6 new reports contain only trusted findings; audit candidates remain separate; normal and fallback paths produce the same schema and identity |
| Durable boundary | Current guidance refuses session-only/denormalized input; missing or mismatched graph/prefix fails closed |
| Guidance integrity | Unknown keys, policy-byte mismatch, altered prose/action content, unrelated evidence refs, graph/fact hash mismatch, unsafe actions all fail |
| Export/UI authority | Audit-only finding never appears as canonical in monitor, Markdown, PDF, or STIX |
| Graph chronology | A→B→C preserves sequence; cycles, reversed edges, missing positions, conflicting evidence order fail |
| Projection privacy | No raw commands, fragments, IPs, usernames, paths, URLs, durable refs, entity values, arbitrary descriptions, or prior AI prose |
| Aliasing | Valid aliases resolve; cross-assessment aliases differ; unknown aliases fail |
| Contract | Valid synthesis accepted; invented chain/finding/hypothesis/action/template rejected; duplicates and unknown keys rejected |
| Grounding | Selected action matches guidance finding/evidence; hypothesis matches its chain; plan anchors are selected and current |
| Abstention | Deterministic no-call and provider abstention accepted only with empty selection |
| Staleness | Old projection response cannot attach after report revision |
| Failure isolation | Timeout, 429, unavailable provider, malformed JSON, oversized response, hash mismatch, duplicate retry, claim loss, worker restart |
| Persistence | SQLite/Mongo parity; v1/v2 read compatibility; idempotent cache replay; deterministic abstention completion |
| Renderer | Only policy templates; privacy scan; stable render hash |
| UI/API | Deterministic, AI, and prediction lanes distinct; historical shadows explicitly historical; unavailable/abstained/rejected states |
| Transformer | Trusted history, model input, and prediction identity unchanged by every AI success/failure variant |

Build on existing tests such as [test_phase3_session_assessment_v5.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/tests/test_phase3_session_assessment_v5.py), [test_response_guidance_v3.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/tests/test_response_guidance_v3.py), [test_semantic_graph_authority_v2.py](/home/rubchek/Desktop/teammate-repo/honeypot-analysis/tests/test_semantic_graph_authority_v2.py), and the existing AI advisory test family. Add version-specific tests rather than changing historical expected fixtures.

## 18. THESIS EVALUATION PLAN

### Data

Use approximately 40 frozen, privacy-safe development cases:

- 10 simple/insufficient cases expected to abstain;
- 10 one-chain multi-finding cases;
- 10 multi-chain or multi-finding/action cases;
- 10 cases with existing hypotheses, limitations, or gaps.

Prefer 30 nonsealed, approved historical development sessions plus 10 frozen synthetic edge cases. Synthetic cases support contract testing, not external-validity claims.

Do not use Transformer sealed-test material.

### Conditions

- A: deterministic policy/default ordering;
- B: current flat AI selector v1;
- C: Final F chronological graph-grounded synthesis v2.

### Human review

Use two independent reviewers if making analyst-prioritization claims.

Each reviewer should:

- select primary chains/findings;
- rank relevant manual actions;
- select relevant hypotheses/gaps;
- judge whether AI invocation or abstention was appropriate;
- record review time and bounded usefulness.

Use a randomized Latin-square presentation so reviewers do not always see the same condition first. Adjudicate disagreements only after independent scoring.

If only one reviewer is available, report results as descriptive developer evaluation, not independent analyst validation.

### Metrics

| Metric | Source | Sample | Interpretation/limit |
|---|---|---:|---|
| Valid-reference rate | Automated validator | All cases/calls | Contract correctness only |
| Prohibited-output rate | Automated security scan | All | Safety boundary only |
| Grounding consistency | Automated reference checks | All | Structural, not factual correctness |
| Top-k finding recall/NDCG | Blinded reviewers | ≥30 real cases | Agreement with reviewer prioritization |
| Action rank agreement | Kendall/Spearman | ≥30 | Ranking agreement, not response efficacy |
| Analyst omission rate | Reviewer-selected items absent | ≥30 | Prioritization coverage |
| Review time | Timed reviewer task | ≥30 | Workflow effect; not SOC efficacy |
| Abstention appropriateness | Frozen rule plus reviewer judgment | All | Scope discipline |
| Repeated-call stability | Three calls on 12 cases | 36 calls | Provider nondeterminism |
| Invocation rate | Offline eligibility scan | Larger nonsealed corpus | Expected API utilization |
| Latency/tokens/cost | Provider metadata | All provider calls | Operational feasibility |
| Failure containment | Injected fixtures | Automated | Canonical isolation |

Do not claim:

- ATT&CK accuracy;
- novel-threat discovery;
- attacker-intent inference;
- hypothesis correctness;
- operational incident-response improvement;
- autonomous analytical authority.

## 19. IMPLEMENTATION PHASES

### Phase 0 — Freeze Final F contracts and authority model

- **Scope:** Freeze schema names, exact fields, enums, eligibility, chronology, alias namespace, compatibility, and evaluation protocol.
- **Files:** New architecture specification, proposed policy/schema fixtures, known-answer JSON fixtures.
- **Not touched:** Runtime, storage, provider, UI, prediction.
- **Prerequisite:** None.
- **Tests:** Static schema/fixture validation and deterministic hashes.
- **Acceptance:** No ambiguous field, authority, chronology, or versioning decision remains.
- **Rollback:** Remove the additive specification commit.
- **Freeze artifact:** Final F contract receipt with commit/tree/file hashes.
- **Production change:** None.
- **Effort:** SMALL.

### Phase 1 — Repair assessment authority and consumer drift

- **Scope:** Make v5 the sole current producer; remove misleading builder aliases; enforce authority in monitor/artifacts.
- **Files:** `canonical_pipeline.py`, `analysis_worker.py`, `session_assessment_v5.py`, `monitor_web.py`, `artifacts.py`, authority tests.
- **Not touched:** Guidance policy, AI, provider, storage, Transformer.
- **Prerequisite:** Phase 0.
- **Tests:** Producer parity, audit-only containment, monitor/PDF/STIX authority.
- **Acceptance:** Every new path produces the same v5 identity; no audit-only candidate is presented as canonical.
- **Rollback:** Restore prior application version; v5 records remain readable.
- **Freeze artifact:** Canonical-authority remediation receipt.
- **Production change:** New reports change from v4 to v5 only when separately deployed.
- **Effort:** MEDIUM.

### Phase 2 — Establish graph-bound guidance and final assessment v6

- **Scope:** Add graph query helper, response guidance v4, closed validator, exact current reevaluation, and assessment v6.
- **Files:** New `canonical_graph_queries.py`, `response_guidance_v4.py`, `session_assessment_v6.py`; `canonical_pipeline.py`, `analysis_worker.py`, `dashboard_api.py`, `monitor_web.py`, `artifacts.py`.
- **Not touched:** AI provider/worker and Transformer.
- **Prerequisite:** Phase 1.
- **Tests:** Graph-only selection, policy-content binding, exact evidence refs, stale/missing graph, session-only bypass, v3 historical compatibility.
- **Acceptance:** Guidance cannot be selected from a separate fact set or denormalized session; v6 complete content is hash-bound.
- **Rollback:** Switch current producer back to v5; retain v6 reader.
- **Freeze artifact:** Guidance v4 and assessment v6 contract receipt.
- **Production change:** New reports/guidance change only after separate deployment.
- **Effort:** LARGE.

### Phase 3 — Add chronological privacy-safe projection v2

- **Scope:** Build and validate the graph view and projection; no provider calls.
- **Files:** `ai_advisory/projection.py`, `security.py`, graph query helper, new projection tests/fixtures.
- **Not touched:** Worker, storage, UI, prediction.
- **Prerequisite:** Phase 2.
- **Tests:** Chronology, cycles, missing order, aliases, raw-field exclusion, graph/hash mismatch.
- **Acceptance:** Known-answer A→B→C projection is deterministic and contains no prohibited/private value.
- **Rollback:** V1 remains the only runtime projection.
- **Freeze artifact:** Projection schema and known-answer receipt.
- **Production change:** None.
- **Effort:** MEDIUM.

### Phase 4 — Add AI contract and policy v2

- **Scope:** Add exact output schema, allowed review-plan semantics, strict validator, and remove shadows from the active contract.
- **Files:** `contracts.py` or new `contracts_v2.py`, `configs/ai_advisory_policy.v2.json`, policy validator, fixtures.
- **Not touched:** Provider network code, worker, storage, UI, prediction.
- **Prerequisite:** Phases 0 and 2; may proceed alongside Phase 3 against the frozen interface.
- **Tests:** Valid synthesis, invented IDs, free text, unknown fields, cross-reference errors, abstention.
- **Acceptance:** Provider can express only selection/order of existing objects.
- **Rollback:** Runtime continues using v1.
- **Freeze artifact:** Policy/contract SHA receipt.
- **Production change:** None.
- **Effort:** MEDIUM.

### Phase 5 — Integrate provider, renderer, worker, and persistence

- **Scope:** V2 request, version dispatch, deterministic eligibility/no-call abstention, v2 renderer, v1/v2 storage handling.
- **Files:** `google_vertex_provider.py`, `rendering.py`, `ai_advisory_worker.py`, `provider.py` if needed, `backend.py`, `mongodb_operations.py`, storage contract.
- **Not touched:** Canonical analysis logic, guidance selection, prediction.
- **Prerequisite:** Phases 3 and 4.
- **Tests:** Worker success/rejection/abstention, timeout/retry/cache, SQLite/Mongo parity, v1 queue compatibility.
- **Acceptance:** V2 records persist atomically; provider failure cannot alter canonical data; no DB migration required.
- **Rollback:** Disable AI worker or select v1 advisory policy; canonical processing continues.
- **Freeze artifact:** Worker/provider/storage integration receipt.
- **Production change:** AI behavior changes only when v2 configuration is activated.
- **Effort:** MEDIUM.

### Phase 6 — Update API and UI

- **Scope:** Versioned advisory API and v2 synthesis panel; historical shadow candidates labeled historical.
- **Files:** `monitor_web.py`, `static/monitor.html`, monitor tests.
- **Not touched:** Canonical algorithms, provider, prediction runtime.
- **Prerequisite:** Phase 5.
- **Tests:** V1/v2 rendering, pending/unavailable/abstained/rejected/superseded states, lane separation.
- **Acceptance:** No AI selection is labeled as canonical; prediction remains separately labeled.
- **Rollback:** UI falls back to the existing v1 panel; stored records remain intact.
- **Freeze artifact:** API/UI compatibility receipt and screenshots/DOM fixtures.
- **Production change:** Presentation only after deployment.
- **Effort:** MEDIUM.

### Phase 7 — Integrated security and noninterference qualification

- **Scope:** Complete privacy, failure, retry, stale-response, authority, and Transformer isolation suite.
- **Files:** Tests and qualification tools; source changes only for demonstrated defects.
- **Not touched:** Model training or policies except reviewed defect corrections.
- **Prerequisite:** Phases 1–6.
- **Tests:** Full matrix in section 17, full test suite, validators, compileall, pip check, secret scan.
- **Acceptance:** All gates pass with a clean worktree and exact release identities.
- **Rollback:** Do not promote the release candidate.
- **Freeze artifact:** Final F qualification receipt.
- **Production change:** None.
- **Effort:** LARGE.

### Phase 8 — Thesis evaluation

- **Scope:** Run the frozen A/B/C comparison in an isolated, privacy-approved harness.
- **Files:** Evaluation harness and immutable results only.
- **Not touched:** Production, canonical policies, Transformer, sealed prediction evidence.
- **Prerequisite:** Phase 7 and reviewer protocol approval.
- **Tests:** Evaluation receipt validation and reproducibility.
- **Acceptance:** Complete sample, no protocol changes after results, all provider usage/cost recorded.
- **Rollback:** Preserve incomplete run as evidence; restart only under a new receipt if protocol permits.
- **Freeze artifact:** Dataset manifest, reviewer protocol, raw judgments, metrics, provider identities.
- **Production change:** None.
- **Effort:** LARGE.

### Phase 9 — Release-readiness gate

- **Scope:** Build a reviewed release candidate and operational rollback plan. Do not deploy automatically.
- **Files:** Release manifest, architecture documentation, runbook, current-state documentation.
- **Not touched:** Historical records and prediction artifacts.
- **Prerequisite:** Phases 7–8.
- **Tests:** Exact release-manifest validation and dry-run enable/disable checks.
- **Acceptance:** Separate deployment authorization can be requested with exact commit/tree/config identities.
- **Rollback:** Keep AI v2 disabled.
- **Freeze artifact:** Release-readiness receipt.
- **Production change:** None until separately authorized.
- **Effort:** SMALL.

## 20. DEPENDENCY GRAPH

```text
Phase 0
   |
Phase 1
   |
Phase 2
   |\
   | +------ Phase 4
   |
Phase 3 -----+
   |         |
   +----+----+
        |
      Phase 5
        |
      Phase 6
        |
      Phase 7
        |
      Phase 8
        |
      Phase 9
```

- Phases 1 and 2 cannot safely run in parallel.
- Phases 3 and 4 may run in parallel only after Phase 0 has frozen their shared field catalogs and Phase 2 has frozen graph/guidance domains.
- Phase 5 requires both 3 and 4.
- UI integration should follow the worker/persistence contract.
- Evaluation cannot begin before integrated qualification.

## 21. ESTIMATED COMPLEXITY

| Phase | Complexity |
|---|---|
| 0 | SMALL |
| 1 | MEDIUM |
| 2 | LARGE |
| 3 | MEDIUM |
| 4 | MEDIUM |
| 5 | MEDIUM |
| 6 | MEDIUM |
| 7 | LARGE |
| 8 | LARGE |
| 9 | SMALL |

Overall implementation: **LARGE**, primarily because canonical/guidance integrity must be fixed before the comparatively bounded AI changes.

## 22. RISKS AND CONTROLS

| Risk | Preventive control | Detection | Fail behavior |
|---|---|---|---|
| Prompt injection | No raw/attacker prose; closed categorical projection | Recursive prohibited-field scan | Reject projection; no provider call |
| Privacy leakage | Positive allowlist, per-assessment aliases, server privacy scan | Known-answer and redaction tests | Reject projection/render |
| Alias correlation | Assessment-specific HMAC namespace | Cross-session alias test | Projection unavailable |
| Stale attachment | Bind report content, graph, guidance, and projection hashes | Completion-time identity check | Reject response as stale |
| Hallucinated selection | Exact ID catalogs and cross-reference validation | Local validator | Rejected advisory |
| Automation bias | Strong non-authoritative UI and manual-only actions | UI regression/reviewer study | No operational execution |
| Provider nondeterminism | Temperature/options bound; structured output; stability measurement | Repeated-call metrics | Display accepted structured result without authority claim |
| Retry/cost duplication | Existing cache/lease identity; bounded retry | Cache-hit and provider-call metrics | Stop retries at policy limit |
| UI authority confusion | Separate lanes, version labels, object links | DOM/screenshot tests | Show unavailable rather than merged content |
| Historical drift | Version-specific validators/renderers | Historical fixture suite | Keep record readable; never reinterpret |
| Deterministic/AI drift | Projection binds all source hashes | Contract receipt validation | No provider invocation |
| Prediction contamination | Import/data-flow tests and hash parity | Trusted-history/snapshot comparisons | Qualification failure |
| Incomplete chronology | Edge/sequence consistency checks | Projection validator | Exclude affected chain or abstain |
| Unsafe action ranking | Only guidance-v4 manual actions projected | Safety invariant checks | Reject advisory |

## 23. THINGS EXPLICITLY NOT NEEDED

Final F does not require:

- a second semantic graph;
- RAG or a vector database;
- conversational memory;
- autonomous agents or multi-agent orchestration;
- raw-command LLM analysis;
- LLM ATT&CK classification;
- AI-created findings, relationships, hypotheses, or actions;
- embeddings or an additional ML model;
- a learned invocation router;
- candidate-to-policy learning;
- automated alerts or response;
- database collection/table migration;
- historical record rewriting;
- Transformer retraining, retargeting, or data changes;
- production deployment during implementation;
- AI ingestion into canonical reports or prediction inputs.

## 24. FIRST IMPLEMENTATION TASK

The first future implementation prompt should authorize **Phase 0 only**:

> Freeze the Final F chronological graph-grounded synthesis contracts without changing runtime behavior. Add the reviewed architecture specification, exact proposed v2 projection/provider/validated/rendered/record/task field catalogs, whole-session review-plan semantics, deterministic invocation rule, chronology rules, privacy allowlist/prohibited fields, alias namespace, version compatibility matrix, and known-answer JSON fixtures. Add validators/tests only for these frozen specifications. Do not change canonical builders, guidance, AI worker/provider execution, storage, UI, production configuration, or Transformer. Record exact commit/tree/file hashes and stop after the contract-freeze acceptance gate.

Do not combine Phase 0 with the authority fixes. The contract freeze should be independently reviewable before runtime changes begin.

## 25. FINAL READINESS VERDICT

The architecture is implementation-ready. The existing graph, provider isolation, manual-action catalog, renderer pattern, outbox, persistence, and UI separation can be reused. The main prerequisite is repairing canonical assessment/guidance authority before enabling the successor AI path.

No code, schema, policy, database, production state, or Transformer component was changed during this planning audit.

FINAL F IMPLEMENTATION PLAN READY — NO CODE CHANGED