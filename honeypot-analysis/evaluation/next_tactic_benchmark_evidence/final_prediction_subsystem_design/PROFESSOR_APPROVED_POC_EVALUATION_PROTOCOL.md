# Professor-approved corrected-target PoC evaluation

Status: `PROFESSOR_APPROVED_POC_EVALUATION`

This is a separate, additive protocol. It does not amend or reinterpret the
original corrected-target experiment closed by
`3d3fca68a814ce6dd5b206bc008f9f79216ffea7` as `BLOCKED_AT_SELECTION`.
Every original seed remains ineligible under that frozen policy because its
Selection defense-evasion recall is zero while the same-target VOMM recall is
nonzero.

The supervising professor and project team have instead authorised one narrow
offline PoC evaluation. It ranks the already complete seeds using Selection
only: highest macro-F1, then balanced accuracy, terminal F1, lower p95 latency,
then lower seed. It preserves, reports, and accepts the original
defense-evasion limitation; it does not make the old candidate eligible.

Calibration uses the independent Calibration role only. The predeclared PoC
decision is temperature-scaled sigmoid probabilities with a fixed 0.5 tactic
and terminal threshold (equivalent to the already frozen raw-logit threshold
of zero for a positive temperature), terminal precedence, highest-ranked tactic
only when a non-terminal prediction set would otherwise be empty, and no
score-based abstention. Asset/hash/schema failures remain fail-closed and do
not invoke a VOMM fallback.

Before final access, the new manifest must bind the approval record, selected
checkpoint, model/vocabulary/preprocessing contracts, calibration mapping,
threshold policy, baselines, environment, provenance receipts, and authority
restriction. Final Test may then be opened exactly once by the dedicated
ledger. No model weight, threshold, checkpoint, or configuration change is
permitted afterwards.

Predictions remain advisory experimental forecasts. They cannot establish
observed behavior or independently authorize alerts, hypotheses, guidance,
recommendations, blocking, or response actions. The final claim is limited to
the within-Zenodo chronological holdout with classifier-derived weak labels;
it is not external validation.
