# Response Guidance v3

`response_guidance.v3` is the only response-guidance authority for newly
generated reports, APIs, monitor views, and report artifacts.

It is deterministic: `guidance_id` derives from the canonical evidence digest,
the exact policy SHA-256, the optional explicitly configured asset-profile
SHA-256, and the selected finding/action rule identities. `generated_at`,
predictions, enrichment, scores, and source-file locations are not identity
inputs.

## Selection boundary

Only the exact immutable `canonical_evidence_snapshot.v1` embedded in the
sibling `session_assessment.v4` can select a finding, triage value, or advisory
action. Current API reevaluations and the read-only legacy report adapter call
the same snapshot builder instead of constructing a parallel evidence shape.
The policy validator rejects prediction,
enrichment/reputation, regex, default-guidance, and automatic-execution action
conditions. Every selected task records its complete predicate trace and at
least one canonical Cowrie evidence reference.

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
