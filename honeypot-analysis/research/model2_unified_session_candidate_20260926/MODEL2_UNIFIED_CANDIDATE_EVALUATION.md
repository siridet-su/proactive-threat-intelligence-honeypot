# Unified Model2 candidate evaluation — corrected controlled PoC

**Candidate:** one unified 54F standardized OVR logistic artifact, outputs T1105/T1046/T1110.  
**Data:** deterministic synthetic episodes only.  
**Decision:** training/research mechanics verified; T1105 gate BLOCK; production not ready.

## 1. Label correction

T1105 is `SESSION_BOUND_TRANSFER_ACTIVITY`, not content-maliciousness, successful-transfer, attacker-intent, or compromise. A valid in-session retrieval of a benign document is still a positive under this honeypot threat model when its network activity is bound to the exact same episode. Artifact/outcome receipts are not candidate inputs. The exact semantics and controls are in [MODEL2_UNIFIED_DATASET_DESIGN.md](MODEL2_UNIFIED_DATASET_DESIGN.md).

The corpus now nuisance-matches transfer-basic and benign-content transfer. Their feature vectors and three-label vectors are identical. T1105 false cases are no-transfer/parser controls and a complete transfer-command/no-flow control; an unbound or missing source yields `UNAVAILABLE` instead of a negative vector.

## 2. Training and holdout procedure

The generator creates 324 synthetic rows across 81 split-specific procedure families: FIT 108, SELECTION 108, SEALED_FINAL 108. Standardizer and weights are FIT-only; each mode's thresholds are chosen only from SELECTION. Full 54F, command-presence-only, and without-sequence candidates are all fit/frozen and assigned canonical identities before the evaluation scoring run. One unified full artifact is serialized; the ablations remain evaluation-only.

This is not an independently adjudicated dataset. Labels are preregistered synthetic scenario semantics (never model outputs), and the `SEALED_FINAL` labels are present in the same synthetic corpus file. Therefore metrics are strictly `CONTROLLED_SYNTHETIC_POC_NOT_REAL_WORLD_ACCURACY`; the split is not an externally escrowed blind test.

## 3. Full candidate final confusion results

| TTP | Support (+ / -) | TP / FP / TN / FN | Precision | Recall | F1 | Specificity | FPR | FNR | Balanced accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| T1105 | 44 / 64 | 44 / 4 / 60 / 0 | 0.9167 | 1.0000 | 0.9565 | 0.9375 | 0.0625 | 0.0000 | 0.9688 |
| T1046 | 16 / 92 | 16 / 0 / 92 / 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 |
| T1110 | 16 / 92 | 16 / 0 / 92 / 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 |

These are synthetic-generator results. T1046/T1110 perfect scores are not real-traffic claims.

## 4. T1105 final slices

| Slice | Support (+ / -) | TP / FP / TN / FN | Result |
|---|---:|---:|---|
| Basic transfer | 4 / 0 | 4 / 0 / 0 / 0 | All positive. |
| Benign-content transfer | 4 / 0 | 4 / 0 / 0 / 0 | All positive; matched feature/label vectors equal basic. |
| Transfer then execute | 8 / 0 | 8 / 0 / 0 / 0 | Positive for transfer behavior, not proof of execution success. |
| Mixed TTP | 12 / 4 | 12 / 0 / 4 / 0 | All four T1105-negative mixed controls correct. |
| Malformed/help/embedded/quoted text | 0 / 20 | 0 / 0 / 20 / 0 | No false positives in these generated cases. |
| URL without retrieval tool | 0 / 4 | 0 / 0 / 4 / 0 | Correct in these generated cases. |
| Local file operation | 0 / 4 | 0 / 0 / 4 / 0 | Correct in these generated cases. |
| No session-bound transfer | 0 / 64 | 0 / 4 / 60 / 0 | Four false positives; gate fails. |

The model's four false positives prevent even the controlled T1105 gate from opening. Do not infer which specific negative procedure family caused them from the aggregate slice; per-family final metrics are not emitted.

## 5. Ablation results

| Mode | T1105 TP/FP/TN/FN; F1 | T1046 TP/FP/TN/FN; F1 | T1110 TP/FP/TN/FN; F1 |
|---|---|---|---|
| Command presence only | 44/4/60/0; 0.9565 | 12/16/76/4; 0.5455 | 8/20/72/8; 0.3636 |
| Full 54F | 44/4/60/0; 0.9565 | 16/0/92/0; 1.0000 | 16/0/92/0; 1.0000 |
| Without sequence | 44/4/60/0; 0.9565 | 16/0/92/0; 1.0000 | 16/0/92/0; 1.0000 |

Full 54F beats the minimal command-count baseline for T1046/T1110 in these authored cases, but sequence removal changes neither result. For T1105, full 54F exactly matches command-presence metrics, including four false positives; no incremental T1105 value is demonstrated. This comparison is not against Model1 or the frozen 32F artifact.

## 6. Artifact identity and runtime

| Identity | SHA-256 |
|---|---|
| Feature schema | `28cc1a43e59259c5939dacdb889cdbe4e13fbdaa71b197264e27907a071d13c1` |
| Canonical model identity | `b015de3a5f65eddcba710949604845db5aa6a599d921de8f85336b541133641c` |
| Serialized artifact | `adff0e76507edfc4f5deadb02922917ff66962c6c2824eb25970ebf40a06b424` |
| Serialized dataset | `550e0dfd5f67f785c75f6c8fcc41c5b0298e902d63b39fd21f71eb8fc31dbcc7` |
| Full dataset content | `1e0dc84860784fef597621abe167de30566f974eeefdbf0aa6303397ab67a917` |
| FIT+SELECTION content | `9a754c3ed0867623beceb0b3849cece9513781250cc7db7af7011f28a71431a9` |
| Split manifest | `2f954d44c2072762f3f016808a3562d65c93d31a5344e1a6363d49cec9115a39` |

Runtime loading verifies exact schema/artifact/manifest identity, three heads, unified architecture, non-calibrated score semantics, and blocked production/ensemble gates. Tampered bytes and a manifest pinned to the previous canonical identity are rejected. Synthetic runtime smoke covers all-three, no-TTP, basic and benign-content transfer, malformed transfer, discovery-only, and brute-force-only; all use the same artifact and no vote/write/response authority.

## 7. Comparison limits and decision

- Exact paired real-session evaluation: `NOT_COMPUTABLE` (zero paired real rows).
- Frozen 32F comparison/non-regression: `NOT_COMPUTABLE`; the baseline was not changed.
- Model1-only / RRF ranking: `NOT_COMPUTABLE`; no paired real Model1 rankings or independently labeled ranking target.
- Production T1105 and RRF vote: `BLOCK`.
- Controlled T1105 research gate: `BLOCK` because 4/64 complete no-transfer controls are false positives.

The artifact proves the unified training/loading/testing path can run on this controlled corpus. It does not show that Model2 is accurate on honeypot traffic or that T1105 should vote in a fusion system.
