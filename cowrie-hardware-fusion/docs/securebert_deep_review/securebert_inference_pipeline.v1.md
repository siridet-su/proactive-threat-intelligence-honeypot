# Executable inference pipeline

```text
Cowrie command event
  -> NotebookParityClassifier.classify(command)
     [strip; split on newline, ;, &&, ||; preserve pipes]
  -> _classify_single(fragment)
     -> deterministic operation parser + reviewed rule policy
     -> SecureBertCommandClassifier.classify(fragment)
        -> strip
        -> NFC + byte-level BPE
        -> [CLS] tokens [SEP], right truncate to 128, right-pad batch
        -> input_ids + attention_mask on selected device
        -> ModernBertForSequenceClassification.eval(), torch.no_grad()
        -> logits z in R^196
        -> p_i = exp(z_i) / sum_j exp(z_j)
        -> argmax_i p_i -> config.id2label[i] -> Txxxx
     -> compare one model candidate with zero-or-more rule candidates
     -> classification_event.v2 + authority_decision
  -> classification_evidence_tier
     -> trusted rule or exact rule/model agreement (rule remains authority)
     -> model-only, low score, disagreement, conditional fragment: audit-only
  -> trusted observed session TTPs / bounded trusted history
  -> reports, correlation, and next-behavior prediction consume trusted evidence
```

The path is deterministic on the tested CPU for fixed bytes and input. Model output is
learned; thresholding and authority are project policy; only the trust gate may promote
an event. SecureBERT never writes canonical truth directly.

There is no SecureBERT temperature step. The known `0.699067...` temperature is used
by another model after its own logits. `MergedResult.final_ttps` is an offline/legacy
compatibility alias for a command-level high-confidence selection and is not in the
canonical event authority path.

For `&&`/`||`, right-hand fragments are classified but tagged
`conditional_unproven` and forced audit-only because execution is not proven. Semicolon
and newline fragments are independently classified. Pipes remain inside one model text.

