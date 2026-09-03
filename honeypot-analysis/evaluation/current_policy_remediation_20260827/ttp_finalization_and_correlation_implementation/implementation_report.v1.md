# TTP finalization and session-correlation implementation report

Date: 2026-08-28 (Asia/Bangkok)
Status: **IMPLEMENTATION COMPLETE — READY FOR FRESH OFFLINE REVALIDATION**

## Result

The completed review decision was implemented without redesigning ATT&CK
classification or creating a new authoritative final-TTP engine. Trusted
command/event mappings now form a deterministic, traceable
`observed_trusted_ttps` session representation. Session-rule and similarity
outputs are represented as separate contextual namespaces with explicit
non-authority and non-probability metadata. Compatibility aliases remain for
existing consumers.

## Contract outcomes

- `MergedResult.final_ttps` remains a backward-compatible internal alias for
  `selected_command_ttps`; it is not attacker ground truth, session-final
  truth, or correlation-confirmed truth.
- Correlation cannot override, remove, or promote trusted mappings; it cannot
  drive prediction, authorize response, create canonical TTP truth, or write
  canonical state.
- `strength` is a project-local deterministic heuristic. The compatibility
  `confidence` name is explicitly marked
  `developer_defined_heuristic_policy_strength_not_probability`.
- Ordered rules are `ordered_sequence` and remain session-scoped. No elapsed
  time window was invented; current policy declares
  `session_scoped_no_elapsed_window`.
- Direct event/command reconfirmation is distinguished from genuine multi-event
  and single-session threshold rules.
- Unknown/malformed TTP markers, invalid output contracts, insufficient
  predicates, and untrusted/model-only candidates fail closed or remain
  contextual.

## Validation

The focused implementation test contains 10 nodes and passes 10/10. The
combined implementation/Phase 4 semantic, authority, typed, API, monitor, and
classifier-binding suite passes 164/164. Policy validation, targeted Python
compilation, and whitespace checks pass. A broader worker/reporting suite has
45 passes and one previously known out-of-scope response-guidance lifecycle
fixture failure; it is preserved and carried forward, not misclassified as a
TTP defect.

## Operational boundary

No release was built, no selector or active deployment changed, no service or
database was touched, no GCP/production operation occurred, no model or
checkpoint changed, no historical receipt was rewritten, and no Git stage,
commit, push, reset, checkout, or clean operation occurred. A future candidate
build is required before deploying these source/policy changes.

The exact file-level delta, review identities, unresolved findings, and
machine-readable closure receipt are in the sibling artifacts in this
namespace.
