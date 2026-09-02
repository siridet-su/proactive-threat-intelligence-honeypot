# Thesis claim boundary

| Claim | Disposition | Safe wording |
|---|---|---|
| “SecureBERT classifies attacker commands into ATT&CK techniques.” | SUPPORTED_WITH_LIMITATION | A private ModernBERT-based classifier historically named SecureBERT proposes one top-ranked ATT&CK technique candidate per stripped command fragment. |
| “SecureBERT improves detection accuracy.” | NOT_CURRENTLY_SUPPORTED | No independent labeled, checkpoint-bound comparison establishes an accuracy improvement. |
| “SecureBERT provides calibrated confidence.” | NOT_CURRENTLY_SUPPORTED | The adapter exposes the largest raw softmax score; it is not calibrated correctness probability. |
| “The system combines rules and SecureBERT.” | SUPPORTED_WITH_LIMITATION | Reviewed rules provide authority; the model supplies candidate/corroborating evidence and can cause disagreement abstention. |
| “SecureBERT is used as an advisory classifier.” | SUPPORTED | Model-only output is audit-only and cannot independently establish trusted ATT&CK evidence. |
| “SecureBERT output is authoritative.” | NOT_CURRENTLY_SUPPORTED / FALSE | Model-only output is explicitly non-authoritative. |
| “SecureBERT generalizes to unseen attacker commands.” | NOT_CURRENTLY_SUPPORTED | No independent unseen-command evaluation with leakage controls is retained. |
| “The model is the published SecureBERT.” | NOT_CURRENTLY_SUPPORTED | Executable metadata identifies ModernBERT, not the published RoBERTa-based SecureBERT. |
| “One command produces multiple model TTPs.” | NOT CURRENT IMPLEMENTATION | Canonical softmax/argmax produces one model TTP; multiple rule/fragments can produce multiple events. |

The thesis's authoritative contribution does not depend on model-only output. It rests
on deterministic reviewed rules, explicit authority decisions, durable evidence, and
fail-closed trust. SecureBERT is optional corroboration/disagreement evidence. When it
is unavailable, rule-only processing continues.

Do not claim checkpoint accuracy, robustness, independent reproducibility, calibration,
published SecureBERT lineage, optimal thresholds, or coverage of truncated tails until
new evidence directly supports those claims.

