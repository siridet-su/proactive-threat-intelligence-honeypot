# Genuine XGBoost comparator

This namespace compares a genuine, separately installed XGBoost multiclass
model with the frozen V2 Markov, tree-surrogate, GRU, and Transformer outputs.
It reads the V2 dataset and predictions only; it never retrains or modifies
those experiments.  The XGBoost environment is experiment-local and is not a
project or production dependency.
