# ATT&CK mapping boundary

SecureBERT's classifier head directly indexes 196 `Txxxx` strings in
`config.id2label`; there is no intermediate behavior label and no post-model mapping
table. ATT&CK names and tactics are resolved later from the frozen MITRE cache.

Deterministic rules independently emit ATT&CK IDs from the reviewed classification
policy. One command may therefore have several rule-originated technique candidates
while the model contributes only one top-1 technique candidate.

```text
model logits -> argmax index -> checkpoint id2label -> Txxxx -> audit/rule-comparison
rule/parser -> reviewed rule metadata -> Txxxx -> authority decision
```

Exact model/rule agreement is evidence of agreement, not independent ATT&CK truth;
the reviewed rule remains the authority. A model-only TTP is audit-only. A model/rule
disagreement is audit-only and cannot replace the rule with the model label. Downstream
trusted histories and observed session TTPs exclude these model-only/disagreement
candidates.

No external SecureBERT publication validates this project's ATT&CK head, its label
order, its Cowrie semantics, its 0.55 threshold, or its accuracy.

