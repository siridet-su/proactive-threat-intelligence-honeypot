# Prediction trusted-history contract

The live Transformer input is deliberately separate from the realtime monitor
tail.  `production/workers/session_monitor.py` maintains a ring of the last
eight trusted behavior phases, while audit-only classifier output is ignored
for eviction.  `production/prediction/trusted_history.py` serializes that ring
as `prediction_trusted_history_manifest.v2` and binds it to the evidence
cutoff and classifier environment.

Each phase carries explicit `labels` records containing one tactic and one
technique. The parallel `tactics`/`techniques` arrays remain compatibility
projections; v2 never infers a Cartesian product or assigns one tactic to
multiple techniques. The manifest records complete and selected phase counts,
the omitted prefix count, and a `truncated` flag. Each phase carries a
content-addressed `phase_sha256`; the ordered phase list and complete manifest
also have independent hashes. Every v2 consumer recomputes all three layers,
including cutoff, ordering, counts, and exact label pairs, and rejects any
mismatch. Closed-session replay
rebuilds the complete durable prefix before selecting the final eight phases.

The value eight is not introduced by this remediation.  It is the frozen
Transformer maximum sequence length in
`configs/next_behavior_preprocessing.v1.json` and the model specification
used by `production/prediction/next_behavior_tensor.py`.  This repository
records the architectural value and experiment contracts, but does not contain
an independently adjudicated command-level study that justifies a different
history length.  The remediation therefore preserves eight and makes no claim
of empirical command-level accuracy.

Closed-session canonical reports reclassify the complete verified durable event
prefix.  The monitor's bounded classification tail remains a live projection
only; it is never substituted for the durable-prefix classification manifest.

The classifier environment receipt binds the v2 builder and runtime hashes.
Current v3 receipts additionally bind a content-addressed classifier source
identity (including parser, authority, trusted-history, policy, trust, and
MITRE assets). The release manifest separately binds that receipt to the final
Git revision/tree, avoiding a receipt-to-commit self-reference. Changing the
reviewed classifier policy or receipt creates a new provenance identity;
historical manifests remain readable and are not reinterpreted.
