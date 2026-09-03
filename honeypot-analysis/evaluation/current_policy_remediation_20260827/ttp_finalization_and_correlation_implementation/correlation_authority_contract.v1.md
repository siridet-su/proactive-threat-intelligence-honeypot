# Correlation authority contract

## Namespaces

`observed_trusted_ttps` contains only command/event mappings accepted by the
current classification authority and trust contract. It is deterministic,
deduplicated by normalized technique identity while retaining original source
TTP/subtechnique values, classification-event references, command references,
authority references, and sequence indices.

`correlated_ttp_hypotheses` contains session-rule matches and is report/context
only. The serialized `session_ttp_correlations` field remains a compatibility
alias for consumers that have not migrated; it is never the trusted observed
namespace. A correlation match may name an ATT&CK technique as a contextual
hypothesis even when no trusted mapping exists, but that label cannot enter
`observed_trusted_ttps`.

## Non-authority invariants

Every contextual result carries an explicit authority object with all of the
following values set to false:

```json
{
  "status": "non_authoritative",
  "can_override_trusted": false,
  "can_remove_trusted": false,
  "can_promote_trusted": false,
  "may_drive_prediction": false,
  "may_authorize_response": false,
  "canonical_write_allowed": false
}
```

The policy-level `correlation_output_contract` is validated fail-closed. A
missing contract, a widened flag, or malformed score semantics is not accepted
as the current policy. Reporting may display contextual matches; prediction,
campaign, threat-hunt, alert, response, and canonical-write consumers cannot
gain authority from a match under the current policy.

## Evidence and score semantics

Matched conditions, rule identity, policy identity, chronology category, and
evidence references remain visible. `strength` is a bounded deterministic
policy value. The compatibility `confidence` field may remain, but it carries
the same explicit semantics:
`developer_defined_heuristic_policy_strength_not_probability`.
All evidence-affecting local values are marked
`PROJECT_LOCAL_HEURISTIC` unless the completed review classified them as a
deterministic safety/representation bound. No external reference is claimed
to validate a local score, threshold, chain, path join, or campaign weight.

## Temporal and rule-shape semantics

An `ordered_sequence` result proves only that the declared ordered subsequence
was observed within one session's available evidence. It does not prove an
elapsed-time bound. The current policy is
`session_scoped_no_elapsed_window`; `time_bounded_correlation` is emitted only
if a future policy explicitly supplies a window field. Rule metadata labels
direct event/command reconfirmation separately from genuine multi-event and
single-session threshold rules.

## Fail-closed behavior

Unknown/malformed mappings, missing authority, disagreement, model-only
evidence, unsupported/ambiguous path or entity joins, conditional execution,
invalid chronology, incomplete predicates, and invalid output contracts remain
unknown, audit-only, contextual, or unmatched. No fallback aggregate or
correlation result manufactures trusted ATT&CK truth. A future stronger
consumer requires a new reviewed policy, empirical validation, and a versioned
schema.
