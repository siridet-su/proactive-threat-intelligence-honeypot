# SecureBERT model and inference deep review

Date: 2026-08-29 (Asia/Bangkok)  
Status: **COMPLETE — READY FOR IMPLEMENTATION DECISION**

## Executive result

The component called SecureBERT is a private 149,755,588-parameter
`ModernBertForSequenceClassification` checkpoint, not the published RoBERTa-based
SecureBERT architecture. It takes one stripped Cowrie command fragment, applies NFC
and byte-level BPE, silently right-truncates to 128 tokens, and produces exactly one
top-ranked ATT&CK technique from a 196-class softmax.

The returned `confidence` is an uncalibrated top softmax score. The known temperature
`0.6990670591704266` belongs to the separate next-distinct prediction Transformer and
is never applied here. Model-only output is audit-only. Reviewed rules are the only
classification authority; exact agreement corroborates a rule, while disagreement
fails closed by demoting that command's rule event to audit-only.

The checkpoint and bundle have strong byte identity, but training and evaluation
provenance is incomplete. The most important runtime gap is that ordinary worker
startup does not re-hash the installed model/tokenizer/label assets even though build
tooling does. No model-only authority bypass was found.

## End-to-end flow

```text
Cowrie event -> command text -> strip/split -> reviewed rules + raw fragment to model
 -> NFC/ByteLevel BPE -> [CLS]... [SEP] -> right truncate 128 -> tensors
 -> ModernBERT forward -> 196 logits -> raw softmax -> argmax -> Txxxx
 -> 0.55 candidate gate -> rule comparison -> authority_decision
 -> trusted rule evidence OR audit-only model/disagreement
 -> session/report; trusted-only history feeds correlation/prediction
```

## Required answers

1. **Project role:** learned command-to-ATT&CK candidate/corroboration and disagreement signal.
2. **Architecture:** ModernBERT sequence classifier; 22 layers, hidden 768, 12 heads, intermediate 1152, mean pooling, GELU head, 196 outputs, 8,192 positions, zero configured dropout.
3. **Identity:** checkpoint `dc3a...a759b`, 599,036,536 bytes, frozen bundle `62a8...e156c96`; active environment bytes `612f...74c6`.
4. **Fine-tuning:** task-specific 196-way head proves project specialization; base initialization and trained layers are unknown.
5. **Tokenizer:** `TokenizersBackend`, NFC, case-sensitive byte-level BPE, 50,368 model vocabulary, CLS/SEP, right padding/truncation, attention mask.
6. **Preprocessing:** strip and split on newline/`;`/`&&`/`||`; no lowercasing, redaction, argument/path/IP/URL replacement, decoding, or prompts. Pipes remain.
7. **Exact input:** a raw stripped fragment string, not a description, semantic fact, parsed operation, or event serialization.
8. **Labels:** exact ordered 196 top-level `Txxxx` IDs in `id2label`; full order is in the label artifact.
9. **Task semantics:** single-label multiclass; one model TTP maximum per fragment.
10. **Formula:** `p=softmax(z)`, `i=argmax(p)`, label=`id2label[i]`; no SecureBERT calibration.
11. **Temperature:** `0.699067...` is valid evidence for another predictor, not this classifier; SecureBERT calibration provenance is absent.
12. **Thresholds:** canonical candidate 0.55, metadata-only model threshold 0.90, max length 128, noncanonical top-k 3/512, historical legacy 0.45, minimum three characters.
13. **Confidence:** top raw normalized softmax value; ranking strength, not calibrated correctness probability.
14. **`final_ttps`:** legacy/offline alias for internal high-confidence command selection, preferring rules when present.
15. **Naming:** yes, misleading if read as final/authoritative/session truth.
16. **ATT&CK generation:** model index maps directly to `Txxxx`; rules emit `Txxxx` independently; names/tactics resolve from frozen cache.
17. **Authority:** exact matrix is in `securebert_rule_model_authority_matrix.v1.json`.
18. **Model-only authority:** impossible under current `classification_event.v2`/trust gate.
19. **Training provenance:** checkpoint bytes available; dataset, split, label lineage, initialization, optimization, seed, and licensing are missing.
20. **Metrics:** no independent checkpoint-bound quality metrics are safe to claim; 45 focused implementation tests passed.
21. **Calibration:** no SecureBERT calibration dataset/artifact/metrics; score is uncalibrated.
22. **Determinism:** three CPU repetitions were bit-identical for fixed input and bytes; cross-hardware equivalence is unproven.
23. **Truncation:** right tail beyond 128 tokens disappears silently and is not recorded in classification evidence.
24. **Fail-closed:** authority is fail-closed; installed asset identity and truncation observability are incomplete. Rules continue on load/model errors.
25. **Sensitivity:** case, quoting, separators, long payloads, and tail placement materially changed distributions; no robustness/accuracy claim follows.
26. **Production:** session and analysis workers run as `honeypot`; synchronous eager CPU-configured model; analysis path can load per job; no forward timeout.
27. **Performance:** local short inference ~29.6–36.9 ms, 128-token ~142–145 ms, batch-4 ~82.38 ms; peak process RSS ~845,584 KiB; not an SLA.
28. **Beyond rules:** model supplies learned candidate/corroboration and a conservative disagreement veto for text not necessarily covered by rules.
29. **Failure:** loader returns unavailable, rules and ingest continue, model-derived corroboration/veto is absent.
30. **Critical/high:** zero critical; four high—architecture-name mismatch, runtime asset hash gap, absent independent evaluation/calibration, and cross-model temperature conflation.
31. **Unsupported:** published SecureBERT lineage, classifier accuracy improvement, calibration, unseen generalization, robustness, optimal threshold, complete training reproducibility, and multi-label model output.
32. **Safe thesis:** a private ModernBERT-based advisory classifier proposes one ATT&CK candidate; reviewed rules remain authority; model-only/disagreement are audit-only.
33. **Later considerations:** startup asset hashing before load, explicit finite/shape checks, truncation telemetry, scoped identity names, independent leakage-controlled evaluation, operational singleton/timeout profiling.
34. **Do not change without evidence:** weights, tokenizer, labels/order, threshold, temperature, max length, rules, or authority policy.
35. **Manifest:** recorded in `securebert_review_artifact_manifest.v1.json`; the external manifest-file SHA is reported at closure.
36. **Recommendation:** retain the conservative non-authoritative architecture, correct thesis/model naming now, and require the listed identity/provenance validation before any model/threshold change.

## Source-state boundary

Active d5f contains adapter SHA `72c7...22be`, pipeline SHA `3b0c...733b`, and
environment file SHA `612f...74c6`. The adapter is still byte-identical in the current
worktree; later TTP work changed the pipeline and environment hashes. This review did
not force the worktree to match d5f and did not modify either state.

## Validation

- Exact checkpoint SHA replay: PASS.
- Model/config/tokenizer/label bundle identity: PASS.
- Local model load and bounded CPU inference: PASS.
- Repeat determinism: PASS on tested CPU.
- JSON parse of review evidence: PASS.
- Focused environment/authority/cross-layer/final-TTP tests: **45 passed**.
- Production/Git/model/source mutation: none.

