# Corrected-target experiment: frozen Selection result

Status: **BLOCKED_AT_FROZEN_SELECTION_GATE**

The corrected-target experiment completed canonical role preparation,
partitioning, the Train-only vocabulary, four independently fitted same-target
baselines, and all five declared Transformer seed runs. It did not select a
Transformer checkpoint.

Every Transformer seed collapsed the reportable `defense-evasion` class to
zero recall on Selection. The independently trained hard-backoff VOMM recalled
6 of the 44 targets (recall `0.1363636364`, precision `1.0`). The design-frozen
rule rejects any reportable class with zero Transformer recall when the
baseline recall is nonzero. All five candidates therefore have the blocker
`reportable_zero_recall:defense-evasion`.

This is not an Execution veto. The hard-backoff VOMM's Selection Execution
recall is `0.9995916701`; the five Transformer recall regressions range from
`0.0026541445` to `0.0075541037`, below the predeclared `0.10` limit.

The best aggregate Transformer seed on Selection is 20260721 (macro-F1
`0.6670593527`, balanced accuracy `0.8170294338`), but it is ineligible under
the predeclared rule. Selecting it after observing this result would weaken a
frozen policy post hoc.

Consequently:

- no checkpoint was selected;
- Calibration was not used;
- the pre-test experiment manifest was not merged;
- Final Test remains sealed and its access ledger was never created;
- final Transformer/VOMM metrics, calibration diagnostics, final error
  analysis, and selected-checkpoint runtime measurements are
  `NOT_DETERMINABLE`;
- no model or production behavior changed.

The complete private pre-test evidence is preserved atomically under the
experiment cache as `training.selection_blocked/`. Its receipt SHA-256 is
`1845249166196898fd2f50a15bcc2e828b584b61189a526ef97c56e7bf12b379`
(the receipt file SHA-256 is
`fea344c71e9757a8f6794f7e7e0290f24ac80d9ccefebd0dbded917a5ae75da8`),
and all 51 referenced artifacts verify. The compact machine-readable summary
is `corrected_target_selection_blocked.json`.

## Scientifically valid next step

Do not open Final Test and do not choose a seed from these Selection results.
A future experiment requires a new, prospectively amended design decision
before training—for example, a justified class-support/loss treatment or an
explicitly different zero-recall policy—followed by a new experiment
generation, retraining, Selection, and Calibration. The current sealed Final
cohort may be eligible only if the amendment process can prove it was never
accessed and explicitly authorizes reuse; otherwise a new untouched final
cohort is required.
