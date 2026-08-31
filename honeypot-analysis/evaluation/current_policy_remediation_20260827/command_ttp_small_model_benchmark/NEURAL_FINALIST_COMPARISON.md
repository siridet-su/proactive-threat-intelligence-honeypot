# Neural finalist comparison

All three compact neural finalists were fine-tuned on the frozen 38-label
training partition with seed 42. Epoch selection used validation Macro-F1
only; command/source/historical/demo sets were opened only after each recipe
was frozen. Scores below are deterministic benchmark metrics, not probability
calibration or evidence of ATT&CK ground truth.

| Model | Val Macro-F1 | Command-heldout | Source-heldout | Historical Top-1 / Top-3 | Best epoch |
|---|---:|---:|---:|---:|---:|
| S2_MINILM_L6_H384 | 0.047168 | 0.072608 | 0.006357 | 0.263393 / 0.436012 | 3 |
| S3_MOBILEBERT | 0.235818 | 0.222712 | 0.034649 | 0.595238 / 0.726190 | 4 |
| S4_DISTILBERT_BASE | 0.406187 | 0.338035 | 0.015550 | 0.601190 / 0.702381 | 3 |

The locked S1 LinearSVC reference is validation 0.702514, command 0.615624, source 0.176065, and historical 0.741071 / 0.918155. S1 therefore remains the scientific and deployment champion for this task.

No UniXcoder optimization or new model training was performed in this local phase; its Stage-C values remain an existing frozen reference.
