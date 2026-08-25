# Genuine XGBoost Next-Distinct-Tactic Comparator

Status: COMPLETE_VALID; prediction-only and non-authoritative.

## Frozen inputs

V2 manifest SHA-256: `5b88e7410e4f2ba96ff578cb5e9da025b3028c2e12c6017f08e6bee0a177458d`; cases: Train 10,186, Selection 1,983, Calibration 2,104; directed pairs 16.
V1 and V2 artifacts were read-only. No neural model was retrained. No sealed/final-test data was accessed.

## XGBoost environment and selected model

Genuine XGBoost `3.1.1` in `/tmp/finalf-xgboost-venv`; objective `multi:softprob`; class order is the frozen seven-tactic order; features are only fixed tactic-history positions and history length.
Selected configuration: `train_class_balanced-00`; weighting `train_class_balanced`; model SHA-256 `798345f349d2ccceb6ce1611bb31c5ba27156fe7753921039d8e00bbdc17d759`; 700 trees (100 boosting rounds); 477727 bytes.

## Five-way Selection comparison

| Metric | Markov | Tree surrogate | XGBoost | GRU | Transformer |
|---|---:|---:|---:|---:|---:|
| Top-1 | 0.966213 | 0.991931 | 0.971760 | 0.991931 | 0.991931 |
| Top-3 | 1.000000 | 0.994957 | 0.999496 | 0.994957 | 0.995461 |
| Macro-F1 | 0.447096 | 0.828775 | 0.851828 | 0.828775 | 0.828775 |
| Balanced Accuracy | 0.441142 | 0.830281 | 0.966735 | 0.830281 | 0.830281 |
| Weighted-F1 | 0.955033 | 0.990836 | 0.980944 | 0.990836 | 0.990836 |
| MRR | 0.981678 | 0.994680 | 0.981834 | 0.994285 | 0.994747 |

Tree surrogate is not XGBoost; it remains historical V1/V2 evidence only.

## XGBoost Calibration

Top-1 `0.826046`, Top-3 `0.998574`, Macro-F1 `0.402253`, Balanced Accuracy `0.458620`, Weighted-F1 `0.862344`, MRR `0.907641`. Unsupported classes: `['credential-access']`. This is the previously observed calibration cohort, not blind validation.

## History ablation

Full-vs-last-only Macro-F1 delta: `0.597761`; full-vs-true-shuffle mean delta: `0.159359`; full-vs-reverse delta: `0.349672`. The frozen XGBoost model was not retrained. Ten true prefix shuffles and history >=3 results are in `xgboost_ablation_results.json`.

## Decision

Final classification: **C** — XGBoost matches the neural models within the preregistered margin with lower practical complexity.

The V2 conclusion remains unchanged: additional context helps, but Transformer full history equals true prefix shuffle, so ordered history is not demonstrated. XGBoost is evaluated as a genuine classical comparator, not as a substitute tree surrogate.

## Preservation

Prior V1/V2 experiments, checkpoints, manifests, policies, canonical artifacts, and sealed boundaries were preserved. Existing files modified: none. Existing files overwritten: none.
