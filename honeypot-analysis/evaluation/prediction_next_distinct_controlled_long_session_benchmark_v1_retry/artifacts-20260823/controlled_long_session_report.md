# Controlled synthetic long-session benchmark

Status: COMPLETE_VALID controlled synthetic stress evidence only; not real attacker ground truth, blind validation, real-world generalization accuracy, or production performance.

The real honeypot development corpus has insufficient long multi-tactic progression support. This controlled benchmark therefore examines frozen model behavior and failure modes beyond commonly observed progression lengths. Synthetic expected tactics are authored expectations, not observed attacker ground truth.

Benchmark sessions: 80; teacher-forced cases: 1320; model weights retrained: false.

## Overall metrics

| Model | Top-1 | Top-3 | Macro-F1 | Balanced accuracy | Weighted-F1 | MRR |
|---|---:|---:|---:|---:|---:|---:|
| markov | 0.4371 | 0.7803 | 0.2666 | 0.3202 | 0.3776 | 0.6258 |
| tree_surrogate_xgboost_unavailable | 0.2833 | 0.5538 | 0.1785 | 0.2210 | 0.2191 | 0.4845 |
| xgboost | 0.2121 | 0.5674 | 0.1687 | 0.2101 | 0.1848 | 0.4483 |
| gru | 0.3538 | 0.6318 | 0.2925 | 0.3192 | 0.3585 | 0.5441 |
| transformer | 0.4508 | 0.7258 | 0.3116 | 0.3450 | 0.4077 | 0.6191 |

## Difficulty × length Top-1 / Top-3

| Model | Difficulty | 10 | 15 | 20 | 25 |
|---|---|---:|---:|---:|---:|
| markov | D1 Top-1 | 0.511 | 0.529 | 0.484 | 0.458 |
| markov | D1 Top-3 | 0.844 | 0.900 | 0.895 | 0.925 |
| markov | D2 Top-1 | 0.489 | 0.514 | 0.526 | 0.408 |
| markov | D2 Top-3 | 0.867 | 0.914 | 0.905 | 0.883 |
| markov | D3 Top-1 | 0.600 | 0.371 | 0.442 | 0.450 |
| markov | D3 Top-3 | 0.778 | 0.757 | 0.800 | 0.783 |
| markov | D4 Top-1 | 0.378 | 0.386 | 0.337 | 0.283 |
| markov | D4 Top-3 | 0.578 | 0.514 | 0.547 | 0.550 |
| tree_surrogate_xgboost_unavailable | D1 Top-1 | 0.222 | 0.343 | 0.253 | 0.383 |
| tree_surrogate_xgboost_unavailable | D1 Top-3 | 0.511 | 0.614 | 0.558 | 0.733 |
| tree_surrogate_xgboost_unavailable | D2 Top-1 | 0.378 | 0.400 | 0.442 | 0.350 |
| tree_surrogate_xgboost_unavailable | D2 Top-3 | 0.689 | 0.700 | 0.663 | 0.708 |
| tree_surrogate_xgboost_unavailable | D3 Top-1 | 0.244 | 0.329 | 0.189 | 0.183 |
| tree_surrogate_xgboost_unavailable | D3 Top-3 | 0.422 | 0.629 | 0.442 | 0.450 |
| tree_surrogate_xgboost_unavailable | D4 Top-1 | 0.133 | 0.229 | 0.242 | 0.183 |
| tree_surrogate_xgboost_unavailable | D4 Top-3 | 0.356 | 0.414 | 0.453 | 0.408 |
| xgboost | D1 Top-1 | 0.200 | 0.357 | 0.147 | 0.225 |
| xgboost | D1 Top-3 | 0.622 | 0.643 | 0.600 | 0.667 |
| xgboost | D2 Top-1 | 0.244 | 0.329 | 0.211 | 0.225 |
| xgboost | D2 Top-3 | 0.667 | 0.729 | 0.611 | 0.733 |
| xgboost | D3 Top-1 | 0.244 | 0.186 | 0.116 | 0.192 |
| xgboost | D3 Top-3 | 0.533 | 0.557 | 0.453 | 0.517 |
| xgboost | D4 Top-1 | 0.156 | 0.186 | 0.242 | 0.192 |
| xgboost | D4 Top-3 | 0.444 | 0.471 | 0.453 | 0.400 |
| gru | D1 Top-1 | 0.422 | 0.529 | 0.284 | 0.467 |
| gru | D1 Top-3 | 0.689 | 0.800 | 0.547 | 0.775 |
| gru | D2 Top-1 | 0.356 | 0.471 | 0.358 | 0.350 |
| gru | D2 Top-3 | 0.711 | 0.700 | 0.674 | 0.700 |
| gru | D3 Top-1 | 0.489 | 0.371 | 0.295 | 0.350 |
| gru | D3 Top-3 | 0.667 | 0.671 | 0.558 | 0.625 |
| gru | D4 Top-1 | 0.311 | 0.271 | 0.274 | 0.217 |
| gru | D4 Top-3 | 0.533 | 0.500 | 0.526 | 0.492 |
| transformer | D1 Top-1 | 0.511 | 0.557 | 0.442 | 0.525 |
| transformer | D1 Top-3 | 0.867 | 0.814 | 0.789 | 0.817 |
| transformer | D2 Top-1 | 0.422 | 0.557 | 0.537 | 0.433 |
| transformer | D2 Top-3 | 0.800 | 0.829 | 0.832 | 0.808 |
| transformer | D3 Top-1 | 0.556 | 0.429 | 0.474 | 0.458 |
| transformer | D3 Top-3 | 0.756 | 0.771 | 0.695 | 0.725 |
| transformer | D4 Top-1 | 0.422 | 0.386 | 0.337 | 0.283 |
| transformer | D4 Top-3 | 0.644 | 0.543 | 0.537 | 0.500 |

## Truncation

{'before_truncation_1_8': {'markov': {'cases': 640, 'top1': 0.4328125, 'top3': 0.765625, 'macro_f1': 0.26728544790567293, 'balanced_accuracy': 0.3212816745263277, 'weighted_f1': 0.37395180735450906, 'mrr': 0.6187202380952381, 'top3_only': 0.3328125, 'top3_only_count': 213}, 'tree_surrogate_xgboost_unavailable': {'cases': 640, 'top1': 0.2890625, 'top3': 0.5453125, 'macro_f1': 0.1921404216149902, 'balanced_accuracy': 0.22548807795729292, 'weighted_f1': 0.23799774680989166, 'mrr': 0.48609002976190474, 'top3_only': 0.25625, 'top3_only_count': 164}, 'xgboost': {'cases': 640, 'top1': 0.2109375, 'top3': 0.58125, 'macro_f1': 0.18782876514146313, 'balanced_accuracy': 0.21212411957597727, 'weighted_f1': 0.20526245439594862, 'mrr': 0.4495386904761905, 'top3_only': 0.3703125, 'top3_only_count': 237}, 'gru': {'cases': 640, 'top1': 0.3640625, 'top3': 0.6390625, 'macro_f1': 0.28046679053764423, 'balanced_accuracy': 0.30619004205381656, 'weighted_f1': 0.3562091817103562, 'mrr': 0.5545572916666667, 'top3_only': 0.275, 'top3_only_count': 176}, 'transformer': {'cases': 640, 'top1': 0.4515625, 'top3': 0.7265625, 'macro_f1': 0.3162441589500171, 'balanced_accuracy': 0.351654794575762, 'weighted_f1': 0.4088812161823555, 'mrr': 0.6220684523809524, 'top3_only': 0.275, 'top3_only_count': 176}}, 'after_truncation_9_plus': {'markov': {'cases': 680, 'top1': 0.4411764705882353, 'top3': 0.7941176470588235, 'macro_f1': 0.2661745458002717, 'balanced_accuracy': 0.3195378392325847, 'weighted_f1': 0.3807406314848508, 'mrr': 0.6323949579831932, 'top3_only': 0.35294117647058826, 'top3_only_count': 240}, 'tree_surrogate_xgboost_unavailable': {'cases': 680, 'top1': 0.27794117647058825, 'top3': 0.5617647058823529, 'macro_f1': 0.1618085377308551, 'balanced_accuracy': 0.2159170068932169, 'weighted_f1': 0.19856550233303213, 'mrr': 0.48299369747899157, 'top3_only': 0.2838235294117647, 'top3_only_count': 193}, 'xgboost': {'cases': 680, 'top1': 0.21323529411764705, 'top3': 0.5544117647058824, 'macro_f1': 0.13716312627447413, 'balanced_accuracy': 0.20809564985118717, 'weighted_f1': 0.1560655832566792, 'mrr': 0.4471953781512605, 'top3_only': 0.3411764705882353, 'top3_only_count': 232}, 'gru': {'cases': 680, 'top1': 0.34411764705882353, 'top3': 0.625, 'macro_f1': 0.2974714769496987, 'balanced_accuracy': 0.329916781399878, 'weighted_f1': 0.3542413609481444, 'mrr': 0.5342401960784313, 'top3_only': 0.28088235294117647, 'top3_only_count': 191}, 'transformer': {'cases': 680, 'top1': 0.45, 'top3': 0.725, 'macro_f1': 0.30108160899670994, 'balanced_accuracy': 0.33869091170157617, 'weighted_f1': 0.4020598440483627, 'mrr': 0.6163235294117647, 'top3_only': 0.275, 'top3_only_count': 187}}, 'history_1_2': {'markov': {'cases': 160, 'top1': 0.5, 'top3': 0.8375, 'macro_f1': 0.30685597471311754, 'balanced_accuracy': 0.3593155091493962, 'weighted_f1': 0.4391511093073593, 'mrr': 0.6763392857142857, 'top3_only': 0.3375, 'top3_only_count': 54}, 'tree_surrogate_xgboost_unavailable': {'cases': 160, 'top1': 0.31875, 'top3': 0.60625, 'macro_f1': 0.19410007931522716, 'balanced_accuracy': 0.22223452688568968, 'weighted_f1': 0.27033233351179764, 'mrr': 0.5263541666666667, 'top3_only': 0.2875, 'top3_only_count': 46}, 'xgboost': {'cases': 160, 'top1': 0.30625, 'top3': 0.7, 'macro_f1': 0.21798531056958023, 'balanced_accuracy': 0.24258468245179207, 'weighted_f1': 0.27727485529451823, 'mrr': 0.5248809523809523, 'top3_only': 0.39375, 'top3_only_count': 63}, 'gru': {'cases': 160, 'top1': 0.44375, 'top3': 0.7125, 'macro_f1': 0.2552868973676427, 'balanced_accuracy': 0.3080648279983828, 'weighted_f1': 0.3757019927536232, 'mrr': 0.6228422619047619, 'top3_only': 0.26875, 'top3_only_count': 43}, 'transformer': {'cases': 160, 'top1': 0.50625, 'top3': 0.7625, 'macro_f1': 0.33946773603364394, 'balanced_accuracy': 0.38171966461003004, 'weighted_f1': 0.45463423615580717, 'mrr': 0.665625, 'top3_only': 0.25625, 'top3_only_count': 41}}, 'history_3_4': {'markov': {'cases': 160, 'top1': 0.425, 'top3': 0.75, 'macro_f1': 0.2690863024296817, 'balanced_accuracy': 0.3282862035451474, 'weighted_f1': 0.36191682192206176, 'mrr': 0.6150744047619048, 'top3_only': 0.325, 'top3_only_count': 52}, 'tree_surrogate_xgboost_unavailable': {'cases': 160, 'top1': 0.3, 'top3': 0.5375, 'macro_f1': 0.18448924509074885, 'balanced_accuracy': 0.2333637341640039, 'weighted_f1': 0.23196322537112013, 'mrr': 0.4902827380952381, 'top3_only': 0.2375, 'top3_only_count': 38}, 'xgboost': {'cases': 160, 'top1': 0.1625, 'top3': 0.58125, 'macro_f1': 0.118305888141133, 'balanced_accuracy': 0.16559803465052425, 'weighted_f1': 0.151057868636194, 'mrr': 0.4306696428571429, 'top3_only': 0.41875, 'top3_only_count': 67}, 'gru': {'cases': 160, 'top1': 0.35625, 'top3': 0.66875, 'macro_f1': 0.27515475292594627, 'balanced_accuracy': 0.2943789611307413, 'weighted_f1': 0.3383159492829234, 'mrr': 0.5566369047619047, 'top3_only': 0.3125, 'top3_only_count': 50}, 'transformer': {'cases': 160, 'top1': 0.475, 'top3': 0.73125, 'macro_f1': 0.3428868289003762, 'balanced_accuracy': 0.3737340685028273, 'weighted_f1': 0.4251663096668198, 'mrr': 0.641264880952381, 'top3_only': 0.25625, 'top3_only_count': 41}}, 'history_5_8': {'markov': {'cases': 320, 'top1': 0.403125, 'top3': 0.7375, 'macro_f1': 0.2444713041337861, 'balanced_accuracy': 0.2984841167152616, 'weighted_f1': 0.3489383883380758, 'mrr': 0.591733630952381, 'top3_only': 0.334375, 'top3_only_count': 107}, 'tree_surrogate_xgboost_unavailable': {'cases': 320, 'top1': 0.26875, 'top3': 0.51875, 'macro_f1': 0.1714506810734796, 'balanced_accuracy': 0.22191491814389264, 'weighted_f1': 0.20947205004969266, 'mrr': 0.4638616071428571, 'top3_only': 0.25, 'top3_only_count': 80}, 'xgboost': {'cases': 320, 'top1': 0.1875, 'top3': 0.521875, 'macro_f1': 0.1370810827600558, 'balanced_accuracy': 0.20476190476190476, 'weighted_f1': 0.13151299988971368, 'mrr': 0.42130208333333335, 'top3_only': 0.334375, 'top3_only_count': 107}, 'gru': {'cases': 320, 'top1': 0.328125, 'top3': 0.5875, 'macro_f1': 0.27638906152997, 'balanced_accuracy': 0.30863141199549227, 'weighted_f1': 0.34193375283375593, 'mrr': 0.519375, 'top3_only': 0.259375, 'top3_only_count': 83}, 'transformer': {'cases': 320, 'top1': 0.4125, 'top3': 0.70625, 'macro_f1': 0.26934499903262066, 'balanced_accuracy': 0.32479285048465734, 'weighted_f1': 0.36342367567568157, 'mrr': 0.5906919642857142, 'top3_only': 0.29375, 'top3_only_count': 94}}, 'history_9_12': {'markov': {'cases': 260, 'top1': 0.46923076923076923, 'top3': 0.7807692307692308, 'macro_f1': 0.27929576919199295, 'balanced_accuracy': 0.3312319864044002, 'weighted_f1': 0.411373922672051, 'mrr': 0.6413644688644689, 'top3_only': 0.31153846153846154, 'top3_only_count': 81}, 'tree_surrogate_xgboost_unavailable': {'cases': 260, 'top1': 0.27307692307692305, 'top3': 0.5192307692307693, 'macro_f1': 0.15876602564102563, 'balanced_accuracy': 0.2111999111999112, 'weighted_f1': 0.19507334812623275, 'mrr': 0.46503663003663004, 'top3_only': 0.24615384615384617, 'top3_only_count': 64}, 'xgboost': {'cases': 260, 'top1': 0.21923076923076923, 'top3': 0.5307692307692308, 'macro_f1': 0.1422582308275279, 'balanced_accuracy': 0.2291042291042291, 'weighted_f1': 0.1524342927463783, 'mrr': 0.4472161172161172, 'top3_only': 0.31153846153846154, 'top3_only_count': 81}, 'gru': {'cases': 260, 'top1': 0.3346153846153846, 'top3': 0.6230769230769231, 'macro_f1': 0.2902838792350011, 'balanced_accuracy': 0.3319385595247664, 'weighted_f1': 0.34598281530222885, 'mrr': 0.525467032967033, 'top3_only': 0.28846153846153844, 'top3_only_count': 75}, 'transformer': {'cases': 260, 'top1': 0.4307692307692308, 'top3': 0.7230769230769231, 'macro_f1': 0.27386501667030577, 'balanced_accuracy': 0.31320901320901323, 'weighted_f1': 0.39100420148514525, 'mrr': 0.6079029304029304, 'top3_only': 0.2923076923076923, 'top3_only_count': 76}}, 'history_13_20': {'markov': {'cases': 340, 'top1': 0.4323529411764706, 'top3': 0.8088235294117647, 'macro_f1': 0.26066263950616114, 'balanced_accuracy': 0.31303335926788023, 'weighted_f1': 0.37111730931669124, 'mrr': 0.6314635854341737, 'top3_only': 0.3764705882352941, 'top3_only_count': 128}, 'tree_surrogate_xgboost_unavailable': {'cases': 340, 'top1': 0.3058823529411765, 'top3': 0.5911764705882353, 'macro_f1': 0.174484126984127, 'balanced_accuracy': 0.22452937279627974, 'weighted_f1': 0.22276225490196078, 'mrr': 0.5099439775910364, 'top3_only': 0.2852941176470588, 'top3_only_count': 97}, 'xgboost': {'cases': 340, 'top1': 0.21176470588235294, 'top3': 0.5588235294117647, 'macro_f1': 0.13453717731634138, 'balanced_accuracy': 0.1983202524414044, 'weighted_f1': 0.1599299261189192, 'mrr': 0.4478641456582633, 'top3_only': 0.34705882352941175, 'top3_only_count': 118}, 'gru': {'cases': 340, 'top1': 0.34705882352941175, 'top3': 0.611764705882353, 'macro_f1': 0.29205282990957754, 'balanced_accuracy': 0.33172643112408773, 'weighted_f1': 0.34934921750978853, 'mrr': 0.5342156862745098, 'top3_only': 0.2647058823529412, 'top3_only_count': 90}, 'transformer': {'cases': 340, 'top1': 0.46176470588235297, 'top3': 0.7176470588235294, 'macro_f1': 0.3067746160702107, 'balanced_accuracy': 0.3429820483115954, 'weighted_f1': 0.4091495230986569, 'mrr': 0.6205812324929972, 'top3_only': 0.25588235294117645, 'top3_only_count': 87}}, 'history_gt20': {'markov': {'cases': 80, 'top1': 0.3875, 'top3': 0.775, 'macro_f1': 0.2445120489948076, 'balanced_accuracy': 0.33034188034188033, 'weighted_f1': 0.32930475302889095, 'mrr': 0.607202380952381, 'top3_only': 0.3875, 'top3_only_count': 31}, 'tree_surrogate_xgboost_unavailable': {'cases': 80, 'top1': 0.175, 'top3': 0.575, 'macro_f1': 0.1193923723335488, 'balanced_accuracy': 0.20793650793650795, 'weighted_f1': 0.11938914027149321, 'mrr': 0.42681547619047616, 'top3_only': 0.4, 'top3_only_count': 32}, 'xgboost': {'cases': 80, 'top1': 0.2, 'top3': 0.6125, 'macro_f1': 0.12984716432992294, 'balanced_accuracy': 0.2007936507936508, 'weighted_f1': 0.15255305039787798, 'mrr': 0.4442857142857143, 'top3_only': 0.4125, 'top3_only_count': 33}, 'gru': {'cases': 80, 'top1': 0.3625, 'top3': 0.6875, 'macro_f1': 0.3221354560096954, 'balanced_accuracy': 0.3637973137973138, 'weighted_f1': 0.36519203319406157, 'mrr': 0.5628571428571428, 'top3_only': 0.325, 'top3_only_count': 26}, 'transformer': {'cases': 80, 'top1': 0.4625, 'top3': 0.7625, 'macro_f1': 0.3418546365914787, 'balanced_accuracy': 0.41825396825396827, 'weighted_f1': 0.404718045112782, 'mrr': 0.6255952380952381, 'top3_only': 0.3, 'top3_only_count': 24}}}

Performance after history length 8 uses only the last eight visible tactics; it must not be interpreted as complete-session memory.

## Order counterfactual

{'markov': {'pairs': 40, 'top1_changed_count': 0, 'top1_changed_rate': 0.0, 'top3_set_changed_count': 0, 'top3_set_changed_rate': 0.0, 'mean_probability_l1_change': 0.0, 'max_probability_l1_change': 0.0}, 'tree_surrogate_xgboost_unavailable': {'pairs': 40, 'top1_changed_count': 6, 'top1_changed_rate': 0.15, 'top3_set_changed_count': 6, 'top3_set_changed_rate': 0.15, 'mean_probability_l1_change': 0.28076063446286953, 'max_probability_l1_change': 1.8717375630857969}, 'xgboost': {'pairs': 40, 'top1_changed_count': 19, 'top1_changed_rate': 0.475, 'top3_set_changed_count': 20, 'top3_set_changed_rate': 0.5, 'mean_probability_l1_change': 0.5687057649876737, 'max_probability_l1_change': 1.431132656882046}, 'gru': {'pairs': 40, 'top1_changed_count': 10, 'top1_changed_rate': 0.25, 'top3_set_changed_count': 20, 'top3_set_changed_rate': 0.5, 'mean_probability_l1_change': 0.37821050624011165, 'max_probability_l1_change': 1.5840149356526707}, 'transformer': {'pairs': 40, 'top1_changed_count': 6, 'top1_changed_rate': 0.15, 'top3_set_changed_count': 12, 'top3_set_changed_rate': 0.3, 'mean_probability_l1_change': 0.2747163620586262, 'max_probability_l1_change': 1.7638710762021448}}

## Detailed sessions

### D1-L10-01 (D1)

`persistence -> discovery -> command-and-control -> execution -> persistence -> discovery -> command-and-control -> discovery -> command-and-control -> defense-evasion`

| Expected | Markov | Tree | XGB | GRU | Transformer |
|---|---|---|---|---|---|
| discovery | discovery ✓ | execution ✗ | persistence ✗ | discovery ✓ | discovery ✓ |
| command-and-control | execution ✗ | discovery ✗ | discovery ✗ | command-and-control ✓ | execution ✗ |
| execution | execution ✓ | execution ✓ | privilege-escalation ✗ | execution ✓ | execution ✓ |
| persistence | persistence ✓ | discovery ✗ | privilege-escalation ✗ | persistence ✓ | command-and-control ✗ |
| discovery | discovery ✓ | execution ✗ | defense-evasion ✗ | discovery ✓ | discovery ✓ |
| command-and-control | execution ✗ | execution ✗ | defense-evasion ✗ | privilege-escalation ✗ | execution ✗ |
| discovery | execution ✗ | execution ✗ | execution ✗ | defense-evasion ✗ | execution ✗ |
| command-and-control | execution ✗ | execution ✗ | defense-evasion ✗ | privilege-escalation ✗ | execution ✗ |
| defense-evasion [TRUNCATED] | execution ✗ | execution ✗ | defense-evasion ✓ | execution ✗ | execution ✗ |

### D1-L10-02 (D1)

`discovery -> execution -> discovery -> command-and-control -> execution -> persistence -> discovery -> credential-access -> discovery -> credential-access`

| Expected | Markov | Tree | XGB | GRU | Transformer |
|---|---|---|---|---|---|
| execution | execution ✓ | execution ✓ | credential-access ✗ | execution ✓ | execution ✓ |
| discovery | persistence ✗ | discovery ✓ | discovery ✓ | discovery ✓ | discovery ✓ |
| command-and-control | execution ✗ | execution ✗ | privilege-escalation ✗ | privilege-escalation ✗ | command-and-control ✓ |
| execution | execution ✓ | execution ✓ | privilege-escalation ✗ | defense-evasion ✗ | execution ✓ |
| persistence | persistence ✓ | discovery ✗ | defense-evasion ✗ | command-and-control ✗ | command-and-control ✗ |
| discovery | discovery ✓ | execution ✗ | defense-evasion ✗ | discovery ✓ | discovery ✓ |
| credential-access | execution ✗ | execution ✗ | defense-evasion ✗ | privilege-escalation ✗ | execution ✗ |
| discovery | discovery ✓ | execution ✗ | privilege-escalation ✗ | privilege-escalation ✗ | discovery ✓ |
| credential-access [TRUNCATED] | execution ✗ | privilege-escalation ✗ | defense-evasion ✗ | privilege-escalation ✗ | privilege-escalation ✗ |

### D1-L10-03 (D1)

`execution -> discovery -> execution -> persistence -> discovery -> defense-evasion -> execution -> discovery -> execution -> command-and-control`

| Expected | Markov | Tree | XGB | GRU | Transformer |
|---|---|---|---|---|---|
| discovery | persistence ✗ | persistence ✗ | persistence ✗ | persistence ✗ | persistence ✗ |
| execution | execution ✓ | discovery ✗ | discovery ✗ | discovery ✗ | execution ✓ |
| persistence | persistence ✓ | discovery ✗ | privilege-escalation ✗ | discovery ✗ | discovery ✗ |
| discovery | discovery ✓ | execution ✗ | privilege-escalation ✗ | discovery ✓ | discovery ✓ |
| defense-evasion | execution ✗ | execution ✗ | defense-evasion ✓ | privilege-escalation ✗ | command-and-control ✗ |
| execution | execution ✓ | execution ✓ | execution ✓ | privilege-escalation ✗ | execution ✓ |
| discovery | persistence ✗ | discovery ✓ | defense-evasion ✗ | command-and-control ✗ | discovery ✓ |
| execution | execution ✓ | execution ✓ | defense-evasion ✗ | privilege-escalation ✗ | command-and-control ✗ |
| command-and-control [TRUNCATED] | persistence ✗ | discovery ✗ | defense-evasion ✗ | command-and-control ✓ | discovery ✗ |

### D2-L10-01 (D2)

`credential-access -> discovery -> credential-access -> discovery -> privilege-escalation -> discovery -> credential-access -> discovery -> defense-evasion -> execution`

| Expected | Markov | Tree | XGB | GRU | Transformer |
|---|---|---|---|---|---|
| discovery | discovery ✓ | execution ✗ | execution ✗ | discovery ✓ | discovery ✓ |
| credential-access | execution ✗ | discovery ✗ | command-and-control ✗ | command-and-control ✗ | privilege-escalation ✗ |
| discovery | discovery ✓ | execution ✗ | execution ✗ | discovery ✓ | discovery ✓ |
| privilege-escalation | execution ✗ | privilege-escalation ✓ | privilege-escalation ✓ | privilege-escalation ✓ | privilege-escalation ✓ |
| discovery | command-and-control ✗ | command-and-control ✗ | command-and-control ✗ | command-and-control ✗ | command-and-control ✗ |
| credential-access | execution ✗ | execution ✗ | defense-evasion ✗ | command-and-control ✗ | privilege-escalation ✗ |
| discovery | discovery ✓ | execution ✗ | execution ✗ | privilege-escalation ✗ | discovery ✓ |
| defense-evasion | execution ✗ | privilege-escalation ✗ | defense-evasion ✓ | privilege-escalation ✗ | privilege-escalation ✗ |
| execution [TRUNCATED] | execution ✓ | execution ✓ | execution ✓ | privilege-escalation ✗ | execution ✓ |

### D2-L10-02 (D2)

`execution -> persistence -> discovery -> command-and-control -> execution -> discovery -> credential-access -> discovery -> credential-access -> discovery`

| Expected | Markov | Tree | XGB | GRU | Transformer |
|---|---|---|---|---|---|
| persistence | persistence ✓ | persistence ✓ | persistence ✓ | persistence ✓ | persistence ✓ |
| discovery | discovery ✓ | discovery ✓ | discovery ✓ | discovery ✓ | discovery ✓ |
| command-and-control | execution ✗ | execution ✗ | privilege-escalation ✗ | privilege-escalation ✗ | execution ✗ |
| execution | execution ✓ | execution ✓ | privilege-escalation ✗ | defense-evasion ✗ | execution ✓ |
| discovery | persistence ✗ | discovery ✓ | defense-evasion ✗ | command-and-control ✗ | command-and-control ✗ |
| credential-access | execution ✗ | execution ✗ | defense-evasion ✗ | privilege-escalation ✗ | execution ✗ |
| discovery | discovery ✓ | execution ✗ | execution ✗ | privilege-escalation ✗ | discovery ✓ |
| credential-access | execution ✗ | privilege-escalation ✗ | privilege-escalation ✗ | privilege-escalation ✗ | privilege-escalation ✗ |
| discovery [TRUNCATED] | discovery ✓ | execution ✗ | defense-evasion ✗ | privilege-escalation ✗ | discovery ✓ |

### D2-L10-03 (D2)

`discovery -> execution -> command-and-control -> defense-evasion -> execution -> discovery -> credential-access -> discovery -> defense-evasion -> execution`

| Expected | Markov | Tree | XGB | GRU | Transformer |
|---|---|---|---|---|---|
| execution | execution ✓ | execution ✓ | credential-access ✗ | execution ✓ | execution ✓ |
| command-and-control | persistence ✗ | discovery ✗ | discovery ✗ | discovery ✗ | discovery ✗ |
| defense-evasion | execution ✗ | execution ✗ | privilege-escalation ✗ | discovery ✗ | execution ✗ |
| execution | execution ✓ | execution ✓ | privilege-escalation ✗ | execution ✓ | execution ✓ |
| discovery | persistence ✗ | discovery ✓ | defense-evasion ✗ | persistence ✗ | command-and-control ✗ |
| credential-access | execution ✗ | execution ✗ | defense-evasion ✗ | privilege-escalation ✗ | execution ✗ |
| discovery | discovery ✓ | execution ✗ | privilege-escalation ✗ | discovery ✓ | discovery ✓ |
| defense-evasion | execution ✗ | privilege-escalation ✗ | command-and-control ✗ | privilege-escalation ✗ | privilege-escalation ✗ |
| execution [TRUNCATED] | execution ✓ | execution ✓ | defense-evasion ✗ | privilege-escalation ✗ | execution ✓ |

### D3-L10-01 (D3)

`credential-access -> discovery -> command-and-control -> credential-access -> discovery -> defense-evasion -> execution -> persistence -> discovery -> credential-access`

| Expected | Markov | Tree | XGB | GRU | Transformer |
|---|---|---|---|---|---|
| discovery | discovery ✓ | execution ✗ | execution ✗ | discovery ✓ | discovery ✓ |
| command-and-control | execution ✗ | discovery ✗ | command-and-control ✓ | command-and-control ✓ | privilege-escalation ✗ |
| credential-access | execution ✗ | execution ✗ | execution ✗ | execution ✗ | defense-evasion ✗ |
| discovery | discovery ✓ | execution ✗ | privilege-escalation ✗ | discovery ✓ | discovery ✓ |
| defense-evasion | execution ✗ | privilege-escalation ✗ | command-and-control ✗ | privilege-escalation ✗ | privilege-escalation ✗ |
| execution | execution ✓ | execution ✓ | defense-evasion ✗ | privilege-escalation ✗ | execution ✓ |
| persistence | persistence ✓ | discovery ✗ | privilege-escalation ✗ | command-and-control ✗ | discovery ✗ |
| discovery | discovery ✓ | execution ✗ | command-and-control ✗ | discovery ✓ | discovery ✓ |
| credential-access [TRUNCATED] | execution ✗ | execution ✗ | defense-evasion ✗ | privilege-escalation ✗ | privilege-escalation ✗ |

### D3-L10-02 (D3)

`defense-evasion -> execution -> command-and-control -> execution -> persistence -> credential-access -> discovery -> privilege-escalation -> command-and-control -> discovery`

| Expected | Markov | Tree | XGB | GRU | Transformer |
|---|---|---|---|---|---|
| execution | execution ✓ | execution ✓ | execution ✓ | execution ✓ | execution ✓ |
| command-and-control | persistence ✗ | discovery ✗ | command-and-control ✓ | persistence ✗ | persistence ✗ |
| execution | execution ✓ | execution ✓ | execution ✓ | execution ✓ | execution ✓ |
| persistence | persistence ✓ | discovery ✗ | privilege-escalation ✗ | persistence ✓ | command-and-control ✗ |
| credential-access | discovery ✗ | execution ✗ | command-and-control ✗ | discovery ✗ | discovery ✗ |
| discovery | discovery ✓ | execution ✗ | defense-evasion ✗ | discovery ✓ | discovery ✓ |
| privilege-escalation | execution ✗ | privilege-escalation ✓ | privilege-escalation ✓ | privilege-escalation ✓ | privilege-escalation ✓ |
| command-and-control | command-and-control ✓ | command-and-control ✓ | command-and-control ✓ | command-and-control ✓ | command-and-control ✓ |
| discovery [TRUNCATED] | execution ✗ | execution ✗ | defense-evasion ✗ | defense-evasion ✗ | defense-evasion ✗ |

### D3-L10-03 (D3)

`persistence -> discovery -> credential-access -> discovery -> privilege-escalation -> command-and-control -> persistence -> execution -> persistence -> discovery`

| Expected | Markov | Tree | XGB | GRU | Transformer |
|---|---|---|---|---|---|
| discovery | discovery ✓ | execution ✗ | persistence ✗ | discovery ✓ | discovery ✓ |
| credential-access | execution ✗ | discovery ✗ | discovery ✗ | command-and-control ✗ | execution ✗ |
| discovery | discovery ✓ | execution ✗ | privilege-escalation ✗ | discovery ✓ | discovery ✓ |
| privilege-escalation | execution ✗ | privilege-escalation ✓ | privilege-escalation ✓ | privilege-escalation ✓ | privilege-escalation ✓ |
| command-and-control | command-and-control ✓ | command-and-control ✓ | command-and-control ✓ | command-and-control ✓ | command-and-control ✓ |
| persistence | execution ✗ | execution ✗ | defense-evasion ✗ | defense-evasion ✗ | defense-evasion ✗ |
| execution | discovery ✗ | execution ✓ | execution ✓ | discovery ✗ | discovery ✗ |
| persistence | persistence ✓ | discovery ✗ | defense-evasion ✗ | persistence ✓ | discovery ✗ |
| discovery [TRUNCATED] | discovery ✓ | execution ✗ | defense-evasion ✗ | discovery ✓ | discovery ✓ |

### D4-L10-01 (D4)

`persistence -> defense-evasion -> execution -> persistence -> credential-access -> discovery -> command-and-control -> defense-evasion -> command-and-control -> credential-access`

| Expected | Markov | Tree | XGB | GRU | Transformer |
|---|---|---|---|---|---|
| defense-evasion | discovery ✗ | execution ✗ | persistence ✗ | discovery ✗ | discovery ✗ |
| execution | execution ✓ | discovery ✗ | discovery ✗ | execution ✓ | execution ✓ |
| persistence | persistence ✓ | discovery ✗ | privilege-escalation ✗ | persistence ✓ | persistence ✓ |
| credential-access | discovery ✗ | execution ✗ | command-and-control ✗ | discovery ✗ | discovery ✗ |
| discovery | discovery ✓ | execution ✗ | defense-evasion ✗ | discovery ✓ | discovery ✓ |
| command-and-control | execution ✗ | privilege-escalation ✗ | execution ✗ | privilege-escalation ✗ | privilege-escalation ✗ |
| defense-evasion | execution ✗ | execution ✗ | defense-evasion ✓ | defense-evasion ✓ | defense-evasion ✓ |
| command-and-control | execution ✗ | execution ✗ | execution ✗ | execution ✗ | execution ✗ |
| credential-access [TRUNCATED] | execution ✗ | execution ✗ | execution ✗ | execution ✗ | defense-evasion ✗ |

### D4-L10-02 (D4)

`defense-evasion -> command-and-control -> defense-evasion -> execution -> credential-access -> discovery -> execution -> discovery -> persistence -> discovery`

| Expected | Markov | Tree | XGB | GRU | Transformer |
|---|---|---|---|---|---|
| command-and-control | execution ✗ | execution ✗ | execution ✗ | execution ✗ | execution ✗ |
| defense-evasion | execution ✗ | execution ✗ | execution ✗ | execution ✗ | execution ✗ |
| execution | execution ✓ | execution ✓ | execution ✓ | execution ✓ | execution ✓ |
| credential-access | persistence ✗ | discovery ✗ | command-and-control ✗ | persistence ✗ | command-and-control ✗ |
| discovery | discovery ✓ | execution ✗ | execution ✗ | discovery ✓ | discovery ✓ |
| execution | execution ✓ | privilege-escalation ✗ | privilege-escalation ✗ | privilege-escalation ✗ | privilege-escalation ✗ |
| discovery | persistence ✗ | discovery ✓ | command-and-control ✗ | command-and-control ✗ | discovery ✓ |
| persistence | execution ✗ | execution ✗ | defense-evasion ✗ | privilege-escalation ✗ | privilege-escalation ✗ |
| discovery [TRUNCATED] | discovery ✓ | execution ✗ | execution ✗ | privilege-escalation ✗ | discovery ✓ |

### D4-L10-03 (D4)

`defense-evasion -> execution -> persistence -> discovery -> command-and-control -> credential-access -> defense-evasion -> discovery -> persistence -> discovery`

| Expected | Markov | Tree | XGB | GRU | Transformer |
|---|---|---|---|---|---|
| execution | execution ✓ | execution ✓ | execution ✓ | execution ✓ | execution ✓ |
| persistence | persistence ✓ | discovery ✗ | command-and-control ✗ | persistence ✓ | persistence ✓ |
| discovery | discovery ✓ | execution ✗ | discovery ✓ | discovery ✓ | discovery ✓ |
| command-and-control | execution ✗ | execution ✗ | privilege-escalation ✗ | privilege-escalation ✗ | execution ✗ |
| credential-access | execution ✗ | defense-evasion ✗ | execution ✗ | defense-evasion ✗ | execution ✗ |
| defense-evasion | discovery ✗ | execution ✗ | defense-evasion ✓ | privilege-escalation ✗ | discovery ✗ |
| discovery | execution ✗ | privilege-escalation ✗ | execution ✗ | execution ✗ | execution ✗ |
| persistence | execution ✗ | execution ✗ | defense-evasion ✗ | command-and-control ✗ | privilege-escalation ✗ |
| discovery [TRUNCATED] | discovery ✓ | execution ✗ | command-and-control ✗ | privilege-escalation ✗ | discovery ✓ |

## Limits

This benchmark characterizes controlled synthetic robustness and failure behavior only. It cannot establish attacker-population accuracy, causal forecasting, production performance, or real-world generalization. The sessions are benchmark-only and are not eligible for training, calibration, model selection, or policy changes.
