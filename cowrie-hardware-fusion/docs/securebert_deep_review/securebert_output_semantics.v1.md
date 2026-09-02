# SecureBERT output semantics

The executable task is **single-label multiclass classification** over 196 ATT&CK
top-level technique IDs. For logits `z`:

```text
p_i = exp(z_i) / sum(exp(z_j))
selected_index = argmax(p)
selected_ttp = config.id2label[selected_index]
score = p[selected_index]
```

No temperature, sigmoid, margin, rejection class, or multiple-label threshold is
applied. Scores sum to one and the classes compete. One fragment therefore produces
at most one model-originated TTP. Multiple classification events can arise only from
multiple deterministic rule matches or compound-command fragments.

The field called `confidence` is the top raw softmax value, rounded to four decimals
when materialized by `NotebookParityClassifier`. It is not proven calibrated, not an
empirical correctness probability, and not comparable to deterministic rule
`confidence=1.0`. Current events correctly use `model_score_not_calibrated_probability`.

At `score >= 0.55`, a model candidate is eligible for comparison but is still forced
audit-only when model-only. Exact rule/model technique agreement leaves the reviewed
rule as authority. Disagreement demotes the rule event to audit-only. Thus SecureBERT
cannot promote truth, but it can veto/suppress a would-be trusted rule observation.

The separate next-distinct prediction model uses temperature `0.699067...`; importing
that value here would be mathematically and architecturally wrong.

