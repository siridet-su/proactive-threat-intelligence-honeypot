# Unified Model2 — ablation and non-regression results

**Data warning:** every result in this document is `CONTROLLED_SYNTHETIC_POC_NOT_REAL_WORLD_ACCURACY`.  
**Baseline:** frozen 32F and Model1 were not changed. Neither has paired rows in this corpus.

## 1. Evaluation plan

One deterministic corpus has 324 synthetic rows across 81 procedure families: FIT/SELECTION/SEALED_FINAL = 108/108/108. Whole family IDs are split-isolated. The final partition's labels are included in the generated corpus, so this is not an external blind holdout. Candidate standardizer and weights use FIT only; per-mode thresholds use SELECTION only; the three modes are frozen before the evaluation scoring run.

`command_presence_only` uses command event count, unique/unknown command-family counts, and transfer-tool count. `without_sequence` excludes the defined sequence feature block. These are research ablations, not production models.

## 2. Final confusion results by mode

| Mode | TTP | TP | FP | TN | FN | Precision | Recall | F1 | Specificity | FPR | FNR | Balanced accuracy |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Command presence only | T1105 | 44 | 4 | 60 | 0 | 0.9167 | 1.0000 | 0.9565 | 0.9375 | 0.0625 | 0.0000 | 0.9688 |
| Full 54F | T1105 | 44 | 4 | 60 | 0 | 0.9167 | 1.0000 | 0.9565 | 0.9375 | 0.0625 | 0.0000 | 0.9688 |
| Without sequence | T1105 | 44 | 4 | 60 | 0 | 0.9167 | 1.0000 | 0.9565 | 0.9375 | 0.0625 | 0.0000 | 0.9688 |
| Command presence only | T1046 | 12 | 16 | 76 | 4 | 0.4286 | 0.7500 | 0.5455 | 0.8261 | 0.1739 | 0.2500 | 0.7880 |
| Full 54F | T1046 | 16 | 0 | 92 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 |
| Without sequence | T1046 | 16 | 0 | 92 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 |
| Command presence only | T1110 | 8 | 20 | 72 | 8 | 0.2857 | 0.5000 | 0.3636 | 0.7826 | 0.2174 | 0.5000 | 0.6413 |
| Full 54F | T1110 | 16 | 0 | 92 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 |
| Without sequence | T1110 | 16 | 0 | 92 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 |

Support is 108 per head (T1105: 44 positive/64 negative; T1046/T1110: 16 positive/92 negative).

## 3. Interpretation by head

- **T1105:** full 54F does not improve over command presence or without-sequence. It has 4 false positives among 64 no-session-bound-transfer controls (FPR 6.25%). Controlled T1105 gate remains blocked. The benign-content positive slice is predicted positive, but is only four synthetic final cases and does not rescue the hard-negative failure.
- **T1046:** full 54F and without-sequence outperform the very small command-presence feature set on authored controls. Removing sequence did not change results, so this corpus does not show sequence incremental value for T1046.
- **T1110:** full 54F and without-sequence outperform command-presence-only on authored controls; sequence removal again changes no result. These deterministic cases directly encode large auth-count differences and do not establish real operational quality.

## 4. T1105 confusion slices

| Slice | Support | TP / FP / TN / FN |
|---|---:|---:|
| Basic transfer | 4 positive | 4 / 0 / 0 / 0 |
| Benign-content transfer | 4 positive | 4 / 0 / 0 / 0 |
| Transfer then execute | 8 positive | 8 / 0 / 0 / 0 |
| Mixed TTP | 12 positive + 4 negative | 12 / 0 / 4 / 0 |
| Malformed/help/embedded/quoted text | 20 negative | 0 / 0 / 20 / 0 |
| URL without transfer tool | 4 negative | 0 / 0 / 4 / 0 |
| Local file operation | 4 negative | 0 / 0 / 4 / 0 |
| No session-bound transfer | 64 negative | 0 / 4 / 60 / 0 |

The 4 false positives are reported only at aggregate no-transfer-slice level. Do not infer family-level causes or tune on this inspected partition.

## 5. Baseline/RRF gates

No same-session frozen-32F/Model1 outputs were paired with these synthetic rows. Consequently, 32F non-regression, Model1-vs-candidate gain, and RRF ranking metrics are `NOT_COMPUTABLE`. The production 32F artifact and Model1 package remain unchanged. T1105 remains disabled in RRF; T1046/T1110 are not promoted by this synthetic study.

The result validates deterministic dataset/extractor/training/runtime mechanics only. A real evaluation needs new controlled and real episode families, independent blinded human adjudication, external holdout custody, exact baseline/model identities, and pre-registered support/acceptance gates.
