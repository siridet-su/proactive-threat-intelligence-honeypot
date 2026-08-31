# FINAL_S1 model card

Selected model: `S1_BASE`. Package SHA-256: `3bad72d688add1064aa236f3a24e9f031aa9e97a8fb449ad730e64389487c5d7`.

Architecture is frozen character TF-IDF n-grams 2–5 plus word TF-IDF n-grams 1–1 and balanced LinearSVC (C=1.0, min_df=1, sublinear TF, lowercase disabled). Decision margins are uncalibrated scores, not probabilities. The model is advisory-only; deterministic reviewed rules remain authoritative and historical production records are not reclassified.

Replay labels are controlled task-intent labels from observed Cowrie events, not public ground truth or model-generated labels. Results support only the disclosed corpus/replay protocol; they do not establish universal ATT&CK accuracy, causal intent, or cross-environment generalization.
