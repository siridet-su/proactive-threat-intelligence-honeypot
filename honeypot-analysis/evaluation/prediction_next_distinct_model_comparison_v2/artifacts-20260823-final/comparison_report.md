# Prediction-Only Next-Distinct-Tactic Model Comparison V2

Status: COMPLETE_VALID; this is an isolated reproduction, not an authoritative predictor.

## Frozen task and dataset

Task: `prediction_next_distinct_model_comparison_v2_20260823` — P(next observed distinct trusted tactic | previous observed distinct trusted tactics).
V1 manifest SHA-256: `5b88e7410e4f2ba96ff578cb5e9da025b3028c2e12c6017f08e6bee0a177458d`; pooled cases: `14273`; directed pairs: `16`.
Train/Selection/Calibration cases: `10186` / `1983` / `2104`.
Calibration is explicitly a previously observed cohort used only for reproduction, not a blind final test.

## Model status

Markov is first-order with Laplace alpha=1 and deterministic global-target backoff. The tree is `tree_surrogate_xgboost_unavailable`; genuine XGBoost was not available and no package/network was used.
Selected GRU seed: `20260822`; selected Transformer seed: `20260822`.

## V1 reproducibility

```json
{
  "gru": {
    "20260822": {
      "actual": {
        "balanced_accuracy": 0.8302808302808302,
        "macro_f1": 0.8287745288824188,
        "top1": 0.9919314170448815
      },
      "deltas": {
        "balanced_accuracy": 0.0,
        "macro_f1": 0.0,
        "top1": 0.0
      },
      "exact": true,
      "expected_v1": {
        "balanced_accuracy": 0.8302808302808302,
        "macro_f1": 0.8287745288824188,
        "top1": 0.9919314170448815
      },
      "within_1e-12": true
    },
    "20260823": {
      "actual": {
        "balanced_accuracy": 0.8302808302808302,
        "macro_f1": 0.8287745288824188,
        "top1": 0.9919314170448815
      },
      "deltas": {
        "balanced_accuracy": 0.0,
        "macro_f1": 0.0,
        "top1": 0.0
      },
      "exact": true,
      "expected_v1": {
        "balanced_accuracy": 0.8302808302808302,
        "macro_f1": 0.8287745288824188,
        "top1": 0.9919314170448815
      },
      "within_1e-12": true
    },
    "20260824": {
      "actual": {
        "balanced_accuracy": 0.8302808302808302,
        "macro_f1": 0.8287745288824188,
        "top1": 0.9919314170448815
      },
      "deltas": {
        "balanced_accuracy": 0.0,
        "macro_f1": 0.0,
        "top1": 0.0
      },
      "exact": true,
      "expected_v1": {
        "balanced_accuracy": 0.8302808302808302,
        "macro_f1": 0.8287745288824188,
        "top1": 0.9919314170448815
      },
      "within_1e-12": true
    },
    "20260825": {
      "actual": {
        "balanced_accuracy": 0.8302808302808302,
        "macro_f1": 0.8287745288824188,
        "top1": 0.9919314170448815
      },
      "deltas": {
        "balanced_accuracy": 0.0,
        "macro_f1": 0.0,
        "top1": 0.0
      },
      "exact": true,
      "expected_v1": {
        "balanced_accuracy": 0.8302808302808302,
        "macro_f1": 0.8287745288824188,
        "top1": 0.9919314170448815
      },
      "within_1e-12": true
    },
    "20260826": {
      "actual": {
        "balanced_accuracy": 0.8302808302808302,
        "macro_f1": 0.8287745288824188,
        "top1": 0.9919314170448815
      },
      "deltas": {
        "balanced_accuracy": 0.0,
        "macro_f1": 0.0,
        "top1": 0.0
      },
      "exact": true,
      "expected_v1": {
        "balanced_accuracy": 0.8302808302808302,
        "macro_f1": 0.8287745288824188,
        "top1": 0.9919314170448815
      },
      "within_1e-12": true
    }
  },
  "transformer": {
    "20260822": {
      "actual": {
        "balanced_accuracy": 0.8302808302808302,
        "macro_f1": 0.8287745288824188,
        "top1": 0.9919314170448815
      },
      "deltas": {
        "balanced_accuracy": 0.0,
        "macro_f1": 0.0,
        "top1": 0.0
      },
      "exact": true,
      "expected_v1": {
        "balanced_accuracy": 0.8302808302808302,
        "macro_f1": 0.8287745288824188,
        "top1": 0.9919314170448815
      },
      "within_1e-12": true
    },
    "20260823": {
      "actual": {
        "balanced_accuracy": 0.8302808302808302,
        "macro_f1": 0.8287745288824188,
        "top1": 0.9919314170448815
      },
      "deltas": {
        "balanced_accuracy": 0.0,
        "macro_f1": 0.0,
        "top1": 0.0
      },
      "exact": true,
      "expected_v1": {
        "balanced_accuracy": 0.8302808302808302,
        "macro_f1": 0.8287745288824188,
        "top1": 0.9919314170448815
      },
      "within_1e-12": true
    },
    "20260824": {
      "actual": {
        "balanced_accuracy": 0.8302808302808302,
        "macro_f1": 0.8287745288824188,
        "top1": 0.9919314170448815
      },
      "deltas": {
        "balanced_accuracy": 0.0,
        "macro_f1": 0.0,
        "top1": 0.0
      },
      "exact": true,
      "expected_v1": {
        "balanced_accuracy": 0.8302808302808302,
        "macro_f1": 0.8287745288824188,
        "top1": 0.9919314170448815
      },
      "within_1e-12": true
    },
    "20260825": {
      "actual": {
        "balanced_accuracy": 0.8302808302808302,
        "macro_f1": 0.8287745288824188,
        "top1": 0.9919314170448815
      },
      "deltas": {
        "balanced_accuracy": 0.0,
        "macro_f1": 0.0,
        "top1": 0.0
      },
      "exact": true,
      "expected_v1": {
        "balanced_accuracy": 0.8302808302808302,
        "macro_f1": 0.8287745288824188,
        "top1": 0.9919314170448815
      },
      "within_1e-12": true
    },
    "20260826": {
      "actual": {
        "balanced_accuracy": 0.8302808302808302,
        "macro_f1": 0.8287745288824188,
        "top1": 0.9919314170448815
      },
      "deltas": {
        "balanced_accuracy": 0.0,
        "macro_f1": 0.0,
        "top1": 0.0
      },
      "exact": true,
      "expected_v1": {
        "balanced_accuracy": 0.8302808302808302,
        "macro_f1": 0.8287745288824188,
        "top1": 0.9919314170448815
      },
      "within_1e-12": true
    }
  },
  "tree": {
    "actual": {
      "balanced_accuracy": 0.8302808302808302,
      "macro_f1": 0.8287745288824188,
      "top1": 0.9919314170448815
    },
    "deltas": {
      "balanced_accuracy": 0.0,
      "macro_f1": 0.0,
      "top1": 0.0
    },
    "exact": true,
    "expected_v1": {
      "balanced_accuracy": 0.8302808302808302,
      "macro_f1": 0.8287745288824188,
      "top1": 0.9919314170448815
    },
    "within_1e-12": true
  }
}
```

## Exact persisted prediction comparisons

See `paired_case_comparisons.json` for identical/different labels, both-correct/both-wrong, model-only correctness, and probability differences. Per-case outputs are in the two privacy-safe JSONL files.

## Checkpoint provenance

```json
{
  "candidate_a_hash_match": false,
  "historical_transformer_hash_match": false,
  "identity_note": "Exact V1 hash identity is expected from deterministic fresh training with the same seed, architecture, data, and serialization; V2 paths, logs, and reload checks independently establish provenance.",
  "v1_checkpoint_hashes_read_only": {
    "gru-seed-20260822.pt": "a2204f409d4e8e5c34d1e63de20550c73a87a2154cb1e5e5ab28b131eb991842",
    "gru-seed-20260823.pt": "3bce1b9cc14bcb2ba9f348c80ba1fdaf1f502bd2046bc79c0c1e2d26284b7065",
    "gru-seed-20260824.pt": "402bccda2202182549b57c15cdcc8350187c37814326cbf7a3ad89abe6d3c140",
    "gru-seed-20260825.pt": "e5f89a82be6f39bb70c330df7cc73397156edb9033ffe384cb848be4bb39324c",
    "gru-seed-20260826.pt": "09e341dbd809aab8c217ccce2ea77cba101ea7da686a24c032eef594c2ae7852",
    "transformer-seed-20260822.pt": "362f3903fa508d6034f9e92098d33a9b15711d0d8cf4d8b0b4df4c12e74fdd85",
    "transformer-seed-20260823.pt": "60aa9d191438280e35284ff17643622cb0c61e91fcfd20be36d7a8f172109c32",
    "transformer-seed-20260824.pt": "873d6590715dbdde1dbcb33be26f989bf4db716afeffbbb1f6d9532382cba443",
    "transformer-seed-20260825.pt": "ce03368f81aa8480929544fac9355f8d9af1fbfa7daa398a51787b1dc407c37b",
    "transformer-seed-20260826.pt": "f496a29d82d4372e0895aaf93c5077253d1172536c55c439f33f65132169a0b0"
  },
  "v2_checkpoints_distinct_across_families": true,
  "v2_checkpoints_distinct_within_family": true,
  "v2_hash_matches_v1_deterministic_reproduction": {
    "gru": {
      "20260822": true,
      "20260823": true,
      "20260824": true,
      "20260825": true,
      "20260826": true
    },
    "transformer": {
      "20260822": true,
      "20260823": true,
      "20260824": true,
      "20260825": true,
      "20260826": true
    }
  },
  "v2_paths_are_new_namespace": true,
  "weights_loaded_from_prior_experiment": false
}
```
V2 checkpoint files are in a separate namespace and were saved after fresh seeded training. Their byte hashes match the deterministic V1 checkpoints; this is reproducibility, not loading or copying V1 weights. Historical Transformer and Candidate A hashes do not match.

## History ablation

Ablations reload the selected checkpoint and set `ablation_retrained=false`. `true_prefix_shuffle` permutes only earlier tokens, retains the final/current token, uses ten deterministic seeds, and reports cases actually changed; histories of length <=2 are not treated as order tests.
```json
{
  "artifact": "/home/rubchek/Desktop/teammate-repo/honeypot-analysis/evaluation/prediction_next_distinct_model_comparison_v2/artifacts-20260823-final/ablation_results.json",
  "models": {
    "gru": {
      "full_vs_last_only_macro_f1_delta": 0.4111819794780114,
      "full_vs_reverse_macro_f1_delta": 0.5364884732718571,
      "full_vs_true_shuffle_macro_f1_delta": 0.04036527033613713,
      "selected_seed": 20260822
    },
    "transformer": {
      "full_vs_last_only_macro_f1_delta": 0.3816782051372833,
      "full_vs_reverse_macro_f1_delta": 0.5473628717889727,
      "full_vs_true_shuffle_macro_f1_delta": 0.0,
      "selected_seed": 20260822
    }
  }
}
```

## Support and transition concentration

```json
{
  "top1": [
    [
      "command-and-control -> execution",
      5919
    ]
  ],
  "top3": [
    [
      "command-and-control -> execution",
      5919
    ],
    [
      "execution -> persistence",
      3544
    ],
    [
      "persistence -> discovery",
      3544
    ]
  ],
  "top5": [
    [
      "command-and-control -> execution",
      5919
    ],
    [
      "execution -> persistence",
      3544
    ],
    [
      "persistence -> discovery",
      3544
    ],
    [
      "execution -> discovery",
      239
    ],
    [
      "discovery -> execution",
      206
    ]
  ],
  "train_shares": {
    "command-and-control -> defense-evasion": 0.007068525427056745,
    "command-and-control -> discovery": 0.0007853917141174161,
    "command-and-control -> execution": 0.4038876889848812,
    "credential-access -> discovery": 0.006774003534262714,
    "defense-evasion -> execution": 0.008933830748085608,
    "discovery -> command-and-control": 0.006577655605733359,
    "discovery -> credential-access": 0.0068721774985273905,
    "discovery -> defense-evasion": 0.00019634792852935403,
    "discovery -> execution": 0.01246809346161398,
    "discovery -> privilege-escalation": 0.007068525427056745,
    "execution -> command-and-control": 0.005890437855880621,
    "execution -> discovery": 0.0033379147849990185,
    "execution -> persistence": 0.26163361476536423,
    "persistence -> discovery": 0.26163361476536423,
    "privilege-escalation -> command-and-control": 0.006774003534262714,
    "privilege-escalation -> discovery": 9.817396426467701e-05
  }
}
```

## Required interpretation

Final V2 classification: **C** — Additional context helps over last-only, but true prefix shuffling is equivalent within tolerance; order is not demonstrated.

The final classification is based on the V2 evidence and is not inherited from V1. If full history is approximately last-only, multi-step history is not materially useful; if full exceeds last-only but matches true shuffle, context helps but order is not demonstrated. Transformer equality with GRU does not establish architectural superiority. Genuine XGBoost conclusions are unavailable.

### Required answers

1. V1 training genuineness is addressed by the independent V2 checkpoint, epoch-log, and per-case-output evidence; V2 does not infer missing V1 logs.
2. V2 reports exact/within-tolerance/material Selection reproducibility for every seed in `comparison_results.json`.
3. Case-by-case GRU/Transformer identity is in `paired_case_comparisons.json`, not inferred from aggregate scores.
4. Tree/GRU/Transformer/Markov identity and probability differences are persisted in the same paired artifact.
5. Full-versus-last-only is reported for selected GRU and Transformer, including history >=3.
6. Full-versus-true-prefix-shuffle uses ten deterministic shuffles and reports changed cases and mean/std.
7. History >=3 is the order-sensitive stratum; short histories are not treated as ordering evidence.
8. Transformer-vs-GRU superiority is evaluated by Selection Macro-F1, balanced accuracy, rare-class and stability evidence.
9. Transformer-vs-Markov/tree is evaluated, with the tree explicitly marked as a surrogate because XGBoost is unavailable.
10. Scientific justification follows the V2 classification above, not a prespecified Transformer preference.
11. No genuine XGBoost-vs-Transformer conclusion is permitted in this offline reproduction.

## Preservation and safety

V1, historical Transformer, Candidate A, V2.1, Balanced D2, frozen sidecars/manifests/policies, production, and sealed artifacts were read-only and preserved. No prior weights were loaded; no external AI was called; no sealed data was accessed; no existing file was modified or overwritten.

## Reproducibility artifacts

`training_history.json`, `seed_summary.json`, per-case prediction JSONL, `ablation_results.json`, `paired_case_comparisons.json`, `runtime_breakdown.json`, `comparison_results.json`, model checkpoints, and `comparison_receipt.v2.json` are all content-addressed in the V2 receipt.
