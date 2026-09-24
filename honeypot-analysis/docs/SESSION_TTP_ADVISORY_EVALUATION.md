# Session-level TTP advisory evaluation plan

## Current read model

Model1 predicts one selected technique per command event. The session advisory
counts distinct command identities per selected technique and orders techniques
by that count, breaking ties by technique ID. Repeated classification rows for
one compound command and technique count once. Top-k alternatives, decision
margins, command text, and Model2 outputs do not affect this order. The number
is a support count, **not** a confidence estimate, trusted mapping, canonical
finding, or response authorization. Rows without a stable command identity are
excluded and counted as such.

Model2 may be displayed alongside a technique only when artifact and feature
hashes, status, and exact session/run/measurement/episode bindings validate.
Its independent binary heads are not a cross-technique ranking. `ABSENT` is a
reported head result, not proof that a technique did not occur; unavailable
heads are not negative votes. Techniques outside the Model2 head set have no
Model2 comparison.

The API full and compact projections and the PDF use the same command-count
summarizer. The PDF is generated at its own snapshot time; an older immutable
PDF must not be described as a live reflection of later events.

## Evaluation before any RRF claim

1. Freeze a labeled set of sessions with analyst-reviewed technique labels and
   direct evidence references. Separate training/development from final test
   sessions; group near-duplicate scripts or campaigns into the same split.
2. Evaluate the current command-count order against Model1-only alternatives
   using precision@k, recall@k, and nDCG@k. Report results by session length,
   repeated-command rate, and whether Model2 is bound and available.
3. If Model2 eventually produces a validated ranking over the *same candidate
   TTP universe*, evaluate RRF as an experimental method against the
   Model1-only baseline. Document the candidate universe, ranks, tie handling,
   missing-head handling, choice of k, and statistical uncertainty. Never
   convert independent binary PRESENT/ABSENT heads into fabricated ranks.
4. Do not call RRF output probability or confidence without separate
   calibration against labeled sessions. Do not let any advisory promote
   trusted mappings, canonical findings, policy actions, or automatic response.

Until steps 1-3 are met, RRF stays disabled. An unavailable Model2 is a normal
read-model state, not a reason to synthesize a score.
