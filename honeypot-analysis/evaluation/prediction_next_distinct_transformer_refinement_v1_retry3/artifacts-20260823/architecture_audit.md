# Frozen Transformer architecture audit

Source: `honeypot-analysis/evaluation/prediction_next_distinct_model_comparison_v2/run_v2.py`
Source SHA-256: `e7ee9f599d1d156a3bb891d7696ad86045e4834fdb6174ade64d9f5d70fcb488`

## Verified findings

- The model has a trainable learned absolute positional parameter initialized to zeros.
- It uses a causal TransformerEncoder mask but no padding key mask.
- Inputs are left padded and the final fixed-window slot is classified.
- The stored history-length scalar is not passed to the Transformer.
- Padding-position probe: FAIL — padding changes probabilities

## Parameter breakdown

```json
{"architecture":{"d_model":16,"dropout":0.1,"ffn":32,"heads":4,"label_smoothing":0.0,"layers":1,"loss":"ce","lr":0.001,"mask_current":false,"max_epochs":20,"max_history":8,"name":"baseline_p0","padding_mask":false,"padding_side":"left","patience":4,"pooling":"current","pos":"learned","weight_decay":0.0},"by_component":{"attention":1088,"classifier":119,"embeddings":128,"feed_forward":1072,"normalization":64,"other":0,"position_representation":128},"total":2599}
```

Attention-weight inspection is NOT_AVAILABLE without changing inference behavior.
