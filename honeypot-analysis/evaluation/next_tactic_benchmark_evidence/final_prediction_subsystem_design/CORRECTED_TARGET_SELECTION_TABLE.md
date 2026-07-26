# Corrected-target Transformer experiment: Selection table

Status: **BLOCKED_AT_SELECTION**. These are frozen, pre-test Selection values,
not Final Test claims. Source: the atomic private
`training.selection_blocked/SELECTION_BLOCKED.json` receipt, whose semantic
SHA-256 is `1845249166196898fd2f50a15bcc2e828b584b61189a526ef97c56e7bf12b379`
and whose file SHA-256 is
`fea344c71e9757a8f6794f7e7e0290f24ac80d9ccefebd0dbded917a5ae75da8`.

| Candidate | Selection macro-F1 | Balanced accuracy | Terminal F1 | Execution recall regression vs VOMM | Defense-evasion recall | Eligible? |
|---|---:|---:|---:|---:|---:|---|
| Hard-backoff VOMM | 0.463510 | 0.724736 | 0.705760 | 0.000000 | 0.136364 (6/44) | Baseline |
| Transformer, seed 20260721 | 0.667059 | 0.817029 | 0.705651 | 0.002654 | 0.000000 (0/44) | No |
| Transformer, seed 20260722 | 0.666209 | 0.816445 | 0.705419 | 0.007554 | 0.000000 (0/44) | No |
| Transformer, seed 20260723 | 0.666149 | 0.816785 | 0.705784 | 0.005308 | 0.000000 (0/44) | No |
| Transformer, seed 20260724 | 0.666855 | 0.816924 | 0.705902 | 0.003675 | 0.000000 (0/44) | No |
| Transformer, seed 20260725 | 0.667009 | 0.816603 | 0.705912 | 0.007554 | 0.000000 (0/44) | No |

The frozen policy rejects a complete candidate when a reportable class has zero
Transformer recall and the independently fitted baseline has nonzero recall.
All five seeds therefore have the identical blocker
`reportable_zero_recall:defense-evasion`. Aggregate Transformer superiority is
real on Selection but is insufficient for selection under that policy.

Final Test metrics, final confidence intervals, calibration, model selection,
and selected-checkpoint runtime are **NOT_DETERMINABLE**. No Final Test labels,
predictions, or evaluation ledger were accessed.
