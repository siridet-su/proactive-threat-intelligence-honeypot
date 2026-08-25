# Final POC runtime-binding resolution study

Status: **COMPLETE_VALID / LOCAL ONLY / NOT DEPLOYED**

The scientifically retained prediction-only checkpoint remains `16506...d283`. The later padding-study checkpoint `96f17...e54b` and its temperature `0.6191339280332447` were not used. A new scalar temperature was fit from held-out TRAIN OOF logits for the retained configuration and bound to the retained full-TRAIN refit by configuration-level calibration.

## Results

- Checkpoint load, architecture, parameter count, and seven-label order: PASS.
- Proper OOF logits: PASS; 10,186 TRAIN cases, each once in the aggregated OOF view, three seed-specific held-out predictions averaged per case, frozen group folds, no NaN/Inf.
- Temperature acceptance: PASS; NLL and at least one of ECE/Brier improved, ranking unchanged, deterministic repeat matched.
- Actual adapter inference and canonical isolation: PASS.
- Hash-bound runtime binding and independent bundle replay: PASS.
- GCP was not contacted or changed. Gates A (inventory), B (ownership), and C (capacity) remain external blockers.

## Required questions

1. Torch/inference environment established? **Yes**, offline cached CPU torch 2.13.0+cpu under Python 3.12.3.
2. Retained checkpoint hash verified? **Yes**, `16506...d283`.
3. Successfully loaded? **Yes**, strict state-dict load, 2,599 parameters.
4. Proper TRAIN OOF logits available? **Yes**, reconstructed because retained OOF logits were not persisted.
5. Truly out-of-fold? **Yes**, every seed/fold model excluded its held-out fold; aggregate contains every TRAIN case once.
6. New temperature fit for retained model/configuration? **Yes**, one scalar from TRAIN OOF NLL.
7. Exact T? See `config/final_retained_model_temperature.json` (full precision).
8. NLL improved? **Yes**.
9. ECE improved? See raw/calibrated metrics; acceptance required ECE or Brier improvement.
10. Brier improved? See raw/calibrated metrics.
11. Top-1 unchanged? **Yes**.
12. Top-3 unchanged? **Yes**.
13. Old `0.6191339280332447` still used? **No**.
14. Why not? It is content-bound to `96f17...e54b`, not the retained checkpoint.
15. What replaced it? The new retained-model TRAIN-OOF scalar artifact.
16. Adapter real checkpoint inference? **Yes**; model forward logits were passed through the adapter.
17. Actual inference tests pass? **Yes**.
18. Canonical isolation with real inference? **Yes**; production tree unchanged and no prohibited imports/writes.
19. Exact label order verified? **Yes**, independent frozen artifacts and source vocabularies agree.
20. Final checkpoint unambiguously 16506? **Yes**.
21. 96f17 excluded from bundle? **Yes**.
22. Runtime binding hash-bound? **Yes**.
23. Minimal bundle prepared? **Yes**, offline bundle only.
24. Bundle independently self-verifying? **Yes**, hashes, model load, adapter, and golden fixtures replayed.
25. Shadow deployment only? **Yes**, localhost-only proposal and `deployment_authorized=false`.
26. Production replacement prohibited? **Yes**.
27. Gates now pass? **D–J pass** locally; A–C remain external failures.
28. Remaining blockers? Read-only Compute inventory/ownership proof and VM capacity.
29. Operator actions? Obtain project-scoped read-only Compute visibility and ownership allowlist, then provide an owner-approved capacity resolution; rerun A–J before any upload/deployment.
30. Further model tuning required? **No**.

## Preservation

`SELECTED MODEL CHANGED = FALSE`  
`MODEL WEIGHTS RETRAINED = FALSE`  
`TEMPERATURE FIT = TRUE`  
`TEMPERATURE FIT SOURCE = TRAIN OOF ONLY`  
`SELECTION/CALIBRATION/SYNTHETIC/OOD USED FOR FITTING = FALSE`  
`SEALED DATA ACCESSED = FALSE`  
`GCP RESOURCES MODIFIED = NONE`  
`GCP RESOURCES DELETED = NONE`  
`IAM MODIFIED = FALSE`  
`VM DISK MODIFIED = FALSE`  
`PRODUCTION MODIFIED = FALSE`  
`FINAL RUNTIME BINDING CREATED = TRUE`  
`FINAL BUNDLE CREATED = TRUE`
