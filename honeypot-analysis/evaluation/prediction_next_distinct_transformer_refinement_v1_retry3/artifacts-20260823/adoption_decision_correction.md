# Adoption decision correction

Status: `COMPLETE_VALID`.

The original refinement study artifacts and base receipt remain frozen. An audit
of the first adoption addendum found one reporting-level aggregation mismatch:
its internal grouped-CV Macro-F1 used the 3-seed/5-fold baseline aggregate, but
its baseline Balanced Accuracy and Top-1 used the seed-20260822 single-seed
five-fold values. The underlying training, fold assignments, predictions,
checkpoints, and post-selection evaluations were not changed.

This correction recomputes every internal comparison field from matching
3-seed/5-fold artifacts:

| Metric | Original Transformer | Refined Transformer | Delta |
|---|---:|---:|---:|
| grouped-CV Macro-F1 | 0.8171449002 | 0.8756102579 | +0.0584653578 |
| grouped-CV Balanced Accuracy | 0.7947710166 | 0.9327515284 | +0.1379805119 |
| grouped-CV Top-1 | 0.9847188447 | 0.9774522863 | -0.0072665585 |
| grouped-CV Top-3 | 0.9987897253 | 0.9926370561 | -0.0061526693 |
| grouped-CV Weighted-F1 | 0.9807112007 | 0.9822600090 | +0.0015488083 |
| grouped-CV MRR | 0.9908635981 | 0.9851784829 | -0.0056851153 |

The absolute Top-1 regression is 0.00727, below the preregistered 0.03 guard.
Common-class collapse is not observed; the large Macro-F1 and Balanced Accuracy
gains are driven primarily by recovery of the rare credential-access class,
while common-class F1 changes are small. The corrected adoption decision is
therefore unchanged:

**REFINED TRANSFORMER ADOPTION SUPPORTED**

This means supported as a prediction-only POC/shadow candidate, not as a
canonical, causal, production, or attacker-population claim. The decision does
not authorize deployment or change any frozen prediction semantics.

The correction supersedes only the inconsistent metric fields in the prior
addendum. It does not rewrite that historical addendum or the frozen base
receipt.
