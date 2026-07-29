# Response Guidance v3

`response_guidance.v3` is the only response-guidance authority for newly
generated reports, APIs, monitor views, and report artifacts.

It is deterministic: `guidance_id` derives from the canonical evidence digest,
the exact policy SHA-256, the optional explicitly configured asset-profile
SHA-256, the complete selected findings/actions/triage/safety content, and the
activated typed-semantic fact, vocabulary, and selection hashes.
`generated_at`, predictions, enrichment, scores, and source-file locations are
not identity inputs.

## Selection boundary

Only the exact immutable `canonical_evidence_snapshot.v1` embedded in the
sibling `session_assessment.v4` can select a finding, triage value, or advisory
action. Current API reevaluations and the read-only legacy report adapter call
the same snapshot builder instead of constructing a parallel evidence shape.
The policy validator rejects prediction,
enrichment/reputation, regex, default-guidance, and automatic-execution action
conditions. Every selected task records its complete predicate trace and at
least one canonical Cowrie evidence reference.

Broad ATT&CK tactics cannot be the sole semantic support for specialized
guidance. Credential guidance is the first family migrated to
`typed_semantic_fact_set.v2`: it requires exact same-entity
`credential_path_read` and `file_read` operations, resolved identity, no
abstention, and a Cowrie-reported successful fragment. Cowrie success is not
proof of credential acquisition or real-host effect. The guidance evaluator
selects from the immutable facts independently of threat findings or
hypotheses.

Direct Cowrie transfer observation is the second migrated family. Transfer
guidance requires `transfer_observed`, direct-event outcome and proof, one
exact linkable SHA-256, no unresolved entity, and a direct transfer evidence
reference. T1105, downloader commands, Cowrie command success, predictions,
enrichment, and hypotheses cannot select it. The action asks only for manual
correlation of the exact observed hash and does not claim execution or
real-host impact.

Execution and every other operation family remain on the contained behavior
or shadow-only path. The combined persistence/evasion task is intentionally
absent until those operations can be distinguished without relying on a broad
tactic or command-family label.

Every v3 task permanently has:

- `requires_manual_approval: true`
- `safe_to_auto_execute: false`
- `execution_integration: "not_implemented"`

Guidance creates neither alerts nor response actions. The session worker does
not write guidance into prediction snapshots.

## Configuration

`RESPONSE_GUIDANCE_POLICY_PATH` defaults to
`configs/response_guidance_policy.v3.json`. Validate it with:

```bash
python -m production.policies.validate_response_guidance_policy \
  --policy configs/response_guidance_policy.v3.json
```

`RESPONSE_GUIDANCE_ASSET_PROFILE_PATH` is optional. If configured, it must be
an explicit non-example asset profile and its byte SHA-256 is recorded in
provenance. Asset context is not used to select v3 tasks.

Legacy `SMB_*` runtime fields and generators are removed. Historical v1/v2
documents are decoded by the read-only adapter from their stored payloads;
they do not require an active legacy policy or generator.

## Migration and historical data

No historical report or prediction snapshot is rewritten. Stored v1/v2 records
are exposed only through `response_guidance_legacy_adapter.v1`, which has no
advisory actions. New `session_assessment.v4` reports contain
`response_guidance_v3` as a separate advisory-only sibling contract.
Historical `session_assessment_v3.response_guidance_ref` fields remain
read-only.
