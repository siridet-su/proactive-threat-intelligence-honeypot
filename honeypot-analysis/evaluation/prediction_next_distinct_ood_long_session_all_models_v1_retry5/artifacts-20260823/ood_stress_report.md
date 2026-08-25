# OOD long-session all-model stress test

Status: COMPLETE_VALID synthetic stress evidence only; not blind validation, real-world generalization, causal forecasting, or production accuracy.

Accepted sessions: 40; teacher-forced cases: 671; all authored expected tactics are synthetic.

## Frozen-model identity

Markov was reconstructed from frozen TRAIN; the deterministic tree retained the exact name `tree_surrogate_xgboost_unavailable`; XGBoost, GRU, and Transformer were loaded from hash-verified frozen artifacts. No model was retrained or tuned.

## OOD-level Top-1 / Top-3

| Level | Model | Cases | Top-1 | Top-3 | Macro-F1 | Mean expected probability | Wrong >0.80 |
|---|---|---:|---:|---:|---:|---:|---:|
| OOD-L1 | markov | 155 | 0.4903 | 0.8839 | 0.3117 | 0.4940 | 41 |
| OOD-L1 | tree_surrogate_xgboost_unavailable | 155 | 0.3161 | 0.5548 | 0.2084 | 0.2518 | 33 |
| OOD-L1 | xgboost | 155 | 0.2452 | 0.6194 | 0.2021 | 0.2306 | 9 |
| OOD-L1 | gru | 155 | 0.3871 | 0.7032 | 0.3079 | 0.3360 | 5 |
| OOD-L1 | transformer | 155 | 0.4645 | 0.7742 | 0.3164 | 0.4571 | 19 |
| OOD-L2 | markov | 155 | 0.5226 | 0.8774 | 0.3093 | 0.5021 | 36 |
| OOD-L2 | tree_surrogate_xgboost_unavailable | 155 | 0.3226 | 0.5871 | 0.1680 | 0.2577 | 33 |
| OOD-L2 | xgboost | 155 | 0.2194 | 0.5677 | 0.1917 | 0.1770 | 9 |
| OOD-L2 | gru | 155 | 0.4258 | 0.6903 | 0.3570 | 0.3169 | 3 |
| OOD-L2 | transformer | 155 | 0.5226 | 0.8452 | 0.3551 | 0.4787 | 18 |
| OOD-L3 | markov | 155 | 0.1806 | 0.4774 | 0.1210 | 0.1875 | 109 |
| OOD-L3 | tree_surrogate_xgboost_unavailable | 155 | 0.1290 | 0.4387 | 0.0751 | 0.1410 | 47 |
| OOD-L3 | xgboost | 155 | 0.1548 | 0.4903 | 0.1133 | 0.1525 | 21 |
| OOD-L3 | gru | 155 | 0.1871 | 0.5290 | 0.1527 | 0.1876 | 30 |
| OOD-L3 | transformer | 155 | 0.1419 | 0.5097 | 0.1075 | 0.1559 | 74 |
| OOD-L4 | markov | 206 | 0.1845 | 0.4612 | 0.1301 | 0.1861 | 147 |
| OOD-L4 | tree_surrogate_xgboost_unavailable | 206 | 0.1408 | 0.4223 | 0.0967 | 0.1590 | 68 |
| OOD-L4 | xgboost | 206 | 0.1359 | 0.4272 | 0.1261 | 0.1507 | 17 |
| OOD-L4 | gru | 206 | 0.1553 | 0.4563 | 0.1284 | 0.1598 | 40 |
| OOD-L4 | transformer | 206 | 0.1456 | 0.4660 | 0.1193 | 0.1520 | 101 |

## Interpretation boundaries

OOD-L1/L2 are known-pair interpolation or novel higher-order composition stress. OOD-L3/L4 include unseen TRAIN transitions and therefore are severe extrapolation. Manually authored sequences are not attacker ground truth. Strong or weak performance here does not establish real-world generalization.

## Order counterfactual

{'markov': {'pairs': 20, 'top1_changed_count': 0, 'top1_changed_rate': 0.0, 'mean_probability_l1_change': 0.0, 'max_probability_l1_change': 0.0}, 'tree_surrogate_xgboost_unavailable': {'pairs': 20, 'top1_changed_count': 3, 'top1_changed_rate': 0.15, 'mean_probability_l1_change': 0.28076063446286953, 'max_probability_l1_change': 1.8717375630857969}, 'xgboost': {'pairs': 20, 'top1_changed_count': 10, 'top1_changed_rate': 0.5, 'mean_probability_l1_change': 0.7029139079667648, 'max_probability_l1_change': 1.4584129059443935}, 'gru': {'pairs': 20, 'top1_changed_count': 6, 'top1_changed_rate': 0.3, 'mean_probability_l1_change': 0.32254498939944487, 'max_probability_l1_change': 0.6790917857419071}, 'transformer': {'pairs': 20, 'top1_changed_count': 6, 'top1_changed_rate': 0.3, 'mean_probability_l1_change': 0.3325311326430074, 'max_probability_l1_change': 1.6820819515728744}}

## Detailed authored examples

### ood_l1_01 (OOD-L1)

`execution -> persistence -> discovery -> command-and-control -> execution -> discovery -> execution -> discovery -> privilege-escalation -> discovery -> privilege-escalation -> discovery`

| Expected | Markov | Tree | XGB | GRU | Transformer |
|---|---|---|---|---|---|
| persistence | persistence ✓ | persistence ✓ | persistence ✓ | persistence ✓ | persistence ✓ |
| discovery | discovery ✓ | discovery ✓ | discovery ✓ | discovery ✓ | discovery ✓ |
| command-and-control | execution ✗ | execution ✗ | privilege-escalation ✗ | privilege-escalation ✗ | execution ✗ |
| execution | execution ✓ | execution ✓ | privilege-escalation ✗ | defense-evasion ✗ | execution ✓ |
| discovery | persistence ✗ | discovery ✓ | defense-evasion ✗ | command-and-control ✗ | command-and-control ✗ |
| execution | execution ✓ | execution ✓ | defense-evasion ✗ | privilege-escalation ✗ | execution ✓ |
| discovery | persistence ✗ | discovery ✓ | defense-evasion ✗ | command-and-control ✗ | command-and-control ✗ |
| privilege-escalation | execution ✗ | execution ✗ | privilege-escalation ✓ | privilege-escalation ✓ | execution ✗ |
| discovery | command-and-control ✗ | command-and-control ✗ | command-and-control ✗ | command-and-control ✗ | command-and-control ✗ |
| privilege-escalation | execution ✗ | execution ✗ | defense-evasion ✗ | command-and-control ✗ | execution ✗ |
| discovery | command-and-control ✗ | command-and-control ✗ | command-and-control ✗ | command-and-control ✗ | command-and-control ✗ |

### ood_l1_02 (OOD-L1)

`persistence -> discovery -> defense-evasion -> execution -> command-and-control -> defense-evasion -> execution -> discovery -> privilege-escalation -> discovery -> privilege-escalation -> discovery -> defense-evasion -> execution -> persistence`

| Expected | Markov | Tree | XGB | GRU | Transformer |
|---|---|---|---|---|---|
| discovery | discovery ✓ | execution ✗ | persistence ✗ | discovery ✓ | discovery ✓ |
| defense-evasion | execution ✗ | discovery ✗ | discovery ✗ | command-and-control ✗ | execution ✗ |
| execution | execution ✓ | execution ✓ | privilege-escalation ✗ | execution ✓ | execution ✓ |
| command-and-control | persistence ✗ | discovery ✗ | privilege-escalation ✗ | persistence ✗ | discovery ✗ |
| defense-evasion | execution ✗ | defense-evasion ✓ | defense-evasion ✓ | execution ✗ | execution ✗ |
| execution | execution ✓ | execution ✓ | execution ✓ | execution ✓ | execution ✓ |
| discovery | persistence ✗ | discovery ✓ | execution ✗ | persistence ✗ | command-and-control ✗ |
| privilege-escalation | execution ✗ | execution ✗ | defense-evasion ✗ | discovery ✗ | execution ✗ |
| discovery | command-and-control ✗ | command-and-control ✗ | privilege-escalation ✗ | command-and-control ✗ | command-and-control ✗ |
| privilege-escalation | execution ✗ | execution ✗ | execution ✗ | command-and-control ✗ | execution ✗ |
| discovery | command-and-control ✗ | command-and-control ✗ | command-and-control ✗ | command-and-control ✗ | command-and-control ✗ |
| defense-evasion | execution ✗ | execution ✗ | defense-evasion ✓ | command-and-control ✗ | execution ✗ |

### ood_l1_03 (OOD-L1)

`defense-evasion -> execution -> persistence -> discovery -> defense-evasion -> execution -> discovery -> privilege-escalation -> command-and-control -> defense-evasion -> execution -> discovery -> defense-evasion -> execution -> persistence -> discovery -> defense-evasion -> execution`

| Expected | Markov | Tree | XGB | GRU | Transformer |
|---|---|---|---|---|---|
| execution | execution ✓ | execution ✓ | execution ✓ | execution ✓ | execution ✓ |
| persistence | persistence ✓ | discovery ✗ | command-and-control ✗ | persistence ✓ | persistence ✓ |
| discovery | discovery ✓ | execution ✗ | discovery ✓ | discovery ✓ | discovery ✓ |
| defense-evasion | execution ✗ | execution ✗ | privilege-escalation ✗ | privilege-escalation ✗ | execution ✗ |
| execution | execution ✓ | execution ✓ | execution ✓ | privilege-escalation ✗ | execution ✓ |
| discovery | persistence ✗ | discovery ✓ | defense-evasion ✗ | command-and-control ✗ | discovery ✓ |
| privilege-escalation | execution ✗ | execution ✗ | defense-evasion ✗ | privilege-escalation ✓ | command-and-control ✗ |
| command-and-control | command-and-control ✓ | command-and-control ✓ | command-and-control ✓ | command-and-control ✓ | command-and-control ✓ |
| defense-evasion | execution ✗ | execution ✗ | defense-evasion ✓ | execution ✗ | execution ✗ |
| execution | execution ✓ | execution ✓ | defense-evasion ✗ | execution ✓ | execution ✓ |
| discovery | persistence ✗ | discovery ✓ | defense-evasion ✗ | persistence ✗ | command-and-control ✗ |
| defense-evasion | execution ✗ | execution ✗ | defense-evasion ✓ | discovery ✗ | execution ✗ |

### ood_l2_01 (OOD-L2)

`credential-access -> discovery -> defense-evasion -> execution -> discovery -> privilege-escalation -> command-and-control -> execution -> persistence -> discovery -> command-and-control -> discovery`

| Expected | Markov | Tree | XGB | GRU | Transformer |
|---|---|---|---|---|---|
| discovery | discovery ✓ | execution ✗ | execution ✗ | discovery ✓ | discovery ✓ |
| defense-evasion | execution ✗ | discovery ✗ | command-and-control ✗ | command-and-control ✗ | privilege-escalation ✗ |
| execution | execution ✓ | execution ✓ | execution ✓ | execution ✓ | execution ✓ |
| discovery | persistence ✗ | discovery ✓ | privilege-escalation ✗ | persistence ✗ | discovery ✓ |
| privilege-escalation | execution ✗ | execution ✗ | command-and-control ✗ | privilege-escalation ✓ | privilege-escalation ✓ |
| command-and-control | command-and-control ✓ | command-and-control ✓ | command-and-control ✓ | command-and-control ✓ | command-and-control ✓ |
| execution | execution ✓ | execution ✓ | defense-evasion ✗ | execution ✓ | defense-evasion ✗ |
| persistence | persistence ✓ | discovery ✗ | defense-evasion ✗ | persistence ✓ | discovery ✗ |
| discovery | discovery ✓ | execution ✗ | defense-evasion ✗ | discovery ✓ | discovery ✓ |
| command-and-control | execution ✗ | execution ✗ | defense-evasion ✗ | privilege-escalation ✗ | execution ✗ |
| discovery | execution ✗ | execution ✗ | execution ✗ | defense-evasion ✗ | execution ✗ |

### ood_l2_02 (OOD-L2)

`credential-access -> discovery -> privilege-escalation -> command-and-control -> discovery -> execution -> persistence -> discovery -> defense-evasion -> execution -> command-and-control -> execution -> persistence -> discovery -> credential-access`

| Expected | Markov | Tree | XGB | GRU | Transformer |
|---|---|---|---|---|---|
| discovery | discovery ✓ | execution ✗ | execution ✗ | discovery ✓ | discovery ✓ |
| privilege-escalation | execution ✗ | discovery ✗ | command-and-control ✗ | command-and-control ✗ | privilege-escalation ✓ |
| command-and-control | command-and-control ✓ | command-and-control ✓ | command-and-control ✓ | discovery ✗ | command-and-control ✓ |
| discovery | execution ✗ | execution ✗ | privilege-escalation ✗ | execution ✗ | defense-evasion ✗ |
| execution | execution ✓ | execution ✓ | command-and-control ✗ | command-and-control ✗ | privilege-escalation ✗ |
| persistence | persistence ✓ | discovery ✗ | defense-evasion ✗ | discovery ✗ | discovery ✗ |
| discovery | discovery ✓ | execution ✗ | defense-evasion ✗ | discovery ✓ | discovery ✓ |
| defense-evasion | execution ✗ | execution ✗ | privilege-escalation ✗ | privilege-escalation ✗ | privilege-escalation ✗ |
| execution | execution ✓ | execution ✓ | defense-evasion ✗ | privilege-escalation ✗ | execution ✓ |
| command-and-control | persistence ✗ | discovery ✗ | defense-evasion ✗ | command-and-control ✓ | command-and-control ✓ |
| execution | execution ✓ | execution ✓ | defense-evasion ✗ | defense-evasion ✗ | execution ✓ |
| persistence | persistence ✓ | discovery ✗ | defense-evasion ✗ | persistence ✓ | command-and-control ✗ |

### ood_l2_03 (OOD-L2)

`credential-access -> discovery -> credential-access -> discovery -> credential-access -> discovery -> defense-evasion -> execution -> persistence -> discovery -> privilege-escalation -> command-and-control -> discovery -> execution -> command-and-control -> discovery -> credential-access -> discovery`

| Expected | Markov | Tree | XGB | GRU | Transformer |
|---|---|---|---|---|---|
| discovery | discovery ✓ | execution ✗ | execution ✗ | discovery ✓ | discovery ✓ |
| credential-access | execution ✗ | discovery ✗ | command-and-control ✗ | command-and-control ✗ | privilege-escalation ✗ |
| discovery | discovery ✓ | execution ✗ | execution ✗ | discovery ✓ | discovery ✓ |
| credential-access | execution ✗ | privilege-escalation ✗ | privilege-escalation ✗ | privilege-escalation ✗ | privilege-escalation ✗ |
| discovery | discovery ✓ | execution ✗ | execution ✗ | privilege-escalation ✗ | discovery ✓ |
| defense-evasion | execution ✗ | privilege-escalation ✗ | defense-evasion ✓ | privilege-escalation ✗ | privilege-escalation ✗ |
| execution | execution ✓ | execution ✓ | execution ✓ | privilege-escalation ✗ | execution ✓ |
| persistence | persistence ✓ | discovery ✗ | defense-evasion ✗ | command-and-control ✗ | discovery ✗ |
| discovery | discovery ✓ | execution ✗ | execution ✗ | discovery ✓ | discovery ✓ |
| privilege-escalation | execution ✗ | execution ✗ | defense-evasion ✗ | privilege-escalation ✓ | privilege-escalation ✓ |
| command-and-control | command-and-control ✓ | command-and-control ✓ | command-and-control ✓ | command-and-control ✓ | command-and-control ✓ |
| discovery | execution ✗ | execution ✗ | defense-evasion ✗ | defense-evasion ✗ | defense-evasion ✗ |

### ood_l3_01 (OOD-L3)

`discovery -> command-and-control -> execution -> discovery -> persistence -> command-and-control -> execution -> discovery -> defense-evasion -> discovery -> privilege-escalation -> credential-access`

| Expected | Markov | Tree | XGB | GRU | Transformer |
|---|---|---|---|---|---|
| command-and-control | execution ✗ | execution ✗ | credential-access ✗ | execution ✗ | execution ✗ |
| execution | execution ✓ | execution ✓ | execution ✓ | execution ✓ | execution ✓ |
| discovery | persistence ✗ | discovery ✓ | privilege-escalation ✗ | persistence ✗ | command-and-control ✗ |
| persistence | execution ✗ | execution ✗ | command-and-control ✗ | privilege-escalation ✗ | execution ✗ |
| command-and-control | discovery ✗ | execution ✗ | defense-evasion ✗ | discovery ✗ | discovery ✗ |
| execution | execution ✓ | execution ✓ | execution ✓ | defense-evasion ✗ | execution ✓ |
| discovery | persistence ✗ | discovery ✓ | defense-evasion ✗ | persistence ✗ | command-and-control ✗ |
| defense-evasion | execution ✗ | execution ✗ | defense-evasion ✓ | privilege-escalation ✗ | execution ✗ |
| discovery | execution ✗ | execution ✗ | execution ✗ | execution ✗ | execution ✗ |
| privilege-escalation | execution ✗ | execution ✗ | privilege-escalation ✓ | privilege-escalation ✓ | execution ✗ |
| credential-access | command-and-control ✗ | command-and-control ✗ | command-and-control ✗ | command-and-control ✗ | command-and-control ✗ |

### ood_l3_02 (OOD-L3)

`command-and-control -> persistence -> command-and-control -> defense-evasion -> credential-access -> privilege-escalation -> command-and-control -> credential-access -> privilege-escalation -> execution -> persistence -> discovery -> privilege-escalation -> persistence -> discovery`

| Expected | Markov | Tree | XGB | GRU | Transformer |
|---|---|---|---|---|---|
| persistence | execution ✗ | execution ✗ | execution ✗ | execution ✗ | execution ✗ |
| command-and-control | discovery ✗ | command-and-control ✓ | discovery ✗ | execution ✗ | discovery ✗ |
| defense-evasion | execution ✗ | execution ✗ | execution ✗ | execution ✗ | execution ✗ |
| credential-access | execution ✗ | execution ✗ | privilege-escalation ✗ | execution ✗ | execution ✗ |
| privilege-escalation | discovery ✗ | execution ✗ | execution ✗ | execution ✗ | discovery ✗ |
| command-and-control | command-and-control ✓ | privilege-escalation ✗ | command-and-control ✓ | execution ✗ | command-and-control ✓ |
| credential-access | execution ✗ | execution ✗ | execution ✗ | execution ✗ | defense-evasion ✗ |
| privilege-escalation | discovery ✗ | execution ✗ | execution ✗ | execution ✗ | discovery ✗ |
| execution | command-and-control ✗ | privilege-escalation ✗ | command-and-control ✗ | execution ✓ | command-and-control ✗ |
| persistence | persistence ✓ | discovery ✗ | defense-evasion ✗ | persistence ✓ | discovery ✗ |
| discovery | discovery ✓ | execution ✗ | privilege-escalation ✗ | discovery ✓ | discovery ✓ |
| privilege-escalation | execution ✗ | execution ✗ | execution ✗ | privilege-escalation ✓ | privilege-escalation ✓ |

### ood_l4_01 (OOD-L4)

`defense-evasion -> persistence -> discovery -> execution -> privilege-escalation -> discovery -> privilege-escalation -> execution -> defense-evasion -> privilege-escalation -> execution -> defense-evasion -> credential-access -> discovery -> defense-evasion -> persistence -> credential-access -> privilege-escalation -> persistence -> execution`

| Expected | Markov | Tree | XGB | GRU | Transformer |
|---|---|---|---|---|---|
| persistence | execution ✗ | execution ✗ | execution ✗ | execution ✗ | execution ✗ |
| discovery | discovery ✓ | discovery ✓ | discovery ✓ | discovery ✓ | discovery ✓ |
| execution | execution ✓ | execution ✓ | command-and-control ✗ | command-and-control ✗ | execution ✓ |
| privilege-escalation | persistence ✗ | discovery ✗ | privilege-escalation ✓ | discovery ✗ | discovery ✗ |
| discovery | command-and-control ✗ | command-and-control ✗ | command-and-control ✗ | command-and-control ✗ | command-and-control ✗ |
| privilege-escalation | execution ✗ | execution ✗ | defense-evasion ✗ | command-and-control ✗ | command-and-control ✗ |
| execution | command-and-control ✗ | command-and-control ✗ | command-and-control ✗ | command-and-control ✗ | command-and-control ✗ |
| defense-evasion | persistence ✗ | discovery ✗ | defense-evasion ✓ | persistence ✗ | discovery ✗ |
| privilege-escalation | execution ✗ | execution ✗ | execution ✗ | command-and-control ✗ | execution ✗ |
| execution | command-and-control ✗ | command-and-control ✗ | command-and-control ✗ | command-and-control ✗ | command-and-control ✗ |
| defense-evasion | persistence ✗ | discovery ✗ | defense-evasion ✓ | persistence ✗ | discovery ✗ |
| credential-access | execution ✗ | execution ✗ | execution ✗ | execution ✗ | execution ✗ |

### ood_l4_02 (OOD-L4)

`discovery -> privilege-escalation -> persistence -> command-and-control -> defense-evasion -> command-and-control -> execution -> persistence -> credential-access -> privilege-escalation -> discovery -> command-and-control -> privilege-escalation -> persistence -> defense-evasion -> command-and-control -> privilege-escalation -> defense-evasion -> privilege-escalation -> persistence -> credential-access -> persistence -> defense-evasion -> privilege-escalation -> credential-access`

| Expected | Markov | Tree | XGB | GRU | Transformer |
|---|---|---|---|---|---|
| privilege-escalation | execution ✗ | execution ✗ | credential-access ✗ | execution ✗ | execution ✗ |
| persistence | command-and-control ✗ | discovery ✗ | discovery ✗ | discovery ✗ | command-and-control ✗ |
| command-and-control | discovery ✗ | execution ✗ | privilege-escalation ✗ | discovery ✗ | discovery ✗ |
| defense-evasion | execution ✗ | execution ✗ | privilege-escalation ✗ | execution ✗ | execution ✗ |
| command-and-control | execution ✗ | execution ✗ | defense-evasion ✗ | execution ✗ | execution ✗ |
| execution | execution ✓ | execution ✓ | defense-evasion ✗ | execution ✓ | execution ✓ |
| persistence | persistence ✓ | discovery ✗ | defense-evasion ✗ | command-and-control ✗ | command-and-control ✗ |
| credential-access | discovery ✗ | execution ✗ | execution ✗ | discovery ✗ | discovery ✗ |
| privilege-escalation | discovery ✗ | execution ✗ | execution ✗ | discovery ✗ | discovery ✗ |
| discovery | command-and-control ✗ | privilege-escalation ✗ | command-and-control ✗ | command-and-control ✗ | command-and-control ✗ |
| command-and-control | execution ✗ | execution ✗ | defense-evasion ✗ | command-and-control ✓ | execution ✗ |
| privilege-escalation | execution ✗ | execution ✗ | defense-evasion ✗ | execution ✗ | defense-evasion ✗ |

## Preservation

No prior artifact was modified or overwritten. No sealed/final-test data was accessed. Models were not retrained.
