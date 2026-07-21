# Final next-tactic model-selection figure summary

This package uses only compact accepted repository evidence. Aggregate GRU and Transformer results appear only in the initial all-model predictive comparison; focused conclusions use the frozen seed-20260723 checkpoint. Raw neural scores are not calibrated probabilities.

## 01_all_model_predictive_overview.png / 01_all_model_predictive_overview.pdf

- **Purpose:** Compare all six models on five compatible predictive metrics.
- **Source:** overall_metrics.json
- **Metrics:** Top-1, Top-3, Macro-F1, balanced accuracy, MRR
- **Interpretation:** Aggregate Transformer leads four metrics; hard-backoff VOMM leads Top-3.
- **Limitation:** Neural values are five-seed aggregates in this section.
- **Decision relevance:** Establishes the broad benchmark context.

## 02_all_model_metric_heatmap.png / 02_all_model_metric_heatmap.pdf

- **Purpose:** Display the complete compatible all-model metric table.
- **Source:** overall_metrics.json
- **Metrics:** Top-1, Top-3, Macro-F1, weighted-F1, balanced accuracy, MRR, coverage, abstention
- **Interpretation:** Neural aggregates lead most discrimination metrics; coverage is identical.
- **Limitation:** Abstention is zero for every evaluated model.
- **Decision relevance:** Prevents a Top-1-only ranking.

## 03_all_model_ranking.png / 03_all_model_ranking.pdf

- **Purpose:** Rank models by mean rank over five predictive metrics and label model roles.
- **Source:** overall_metrics.json; current prediction policy
- **Metrics:** Equal-weight rank of Top-1, Top-3, Macro-F1, balanced accuracy, MRR
- **Interpretation:** Transformer aggregate is strongest overall; VOMM remains deployed/interpretable.
- **Limitation:** Rank aggregation is descriptive, not a selection test.
- **Decision relevance:** Separates empirical rank from operational role.

## 04_predictive_radar.png / 04_predictive_radar.pdf

- **Purpose:** Compare four major models using only compatible predictive dimensions.
- **Source:** overall_metrics.json
- **Metrics:** Top-1, Top-3, Macro-F1, balanced accuracy, MRR
- **Interpretation:** Neural models dominate aggregate quality; VOMMs retain near-ceiling Top-3.
- **Limitation:** Radar geometry can visually amplify small differences.
- **Decision relevance:** Shows multi-metric profiles without mixing runtime units.

## 05_sequence_length.png / 05_sequence_length.pdf

- **Purpose:** Show preserved performance by sequence length.
- **Source:** single_checkpoint_evaluation.json
- **Metrics:** Top-1, Macro-F1, support
- **Interpretation:** Transformer gains concentrate at short sequences; long-sequence evidence is sparse.
- **Limitation:** Only selected Transformer and VOMM have preserved compatible breakdowns.
- **Decision relevance:** Qualifies aggregate conclusions by context length.

## 06_latency.png / 06_latency.pdf

- **Purpose:** Compare measured p50, p95, and p99 single-case latency.
- **Source:** efficiency.json; single_checkpoint_evaluation.json
- **Metrics:** Latency milliseconds
- **Interpretation:** All measured models meet PoC needs; selected Transformer is faster than production VOMM.
- **Limitation:** Aggregate neural lookup timings are excluded as non-inference measurements.
- **Decision relevance:** Demonstrates CPU feasibility without false comparisons.

## 07_throughput.png / 07_throughput.pdf

- **Purpose:** Separate real-time single-case throughput from batch throughput.
- **Source:** efficiency.json; single_checkpoint_evaluation.json
- **Metrics:** Cases per second
- **Interpretation:** Transformer batch throughput is high but not equivalent to session-by-session inference.
- **Limitation:** GRU inference and non-neural batch throughput were not measured.
- **Decision relevance:** Avoids conflating offline batches with operational latency.

## 08_memory_storage_complexity.png / 08_memory_storage_complexity.pdf

- **Purpose:** Compare measured memory, stored model size, parameters, and dependency complexity.
- **Source:** efficiency.json; dataset_split_manifest.json; selected_transformer_metadata.json
- **Metrics:** Peak Python allocation, bytes, parameters, qualitative dependency class
- **Interpretation:** Both artifacts are tiny; PyTorch dominates Transformer dependency cost.
- **Limitation:** Steady-state RSS and installed dependency bytes were not measured.
- **Decision relevance:** Makes operational trade-offs explicit.

## 09_accuracy_latency_tradeoff.png / 09_accuracy_latency_tradeoff.pdf

- **Purpose:** Show Top-1 against measured p95 latency and Pareto status.
- **Source:** overall_metrics.json; efficiency.json; single_checkpoint_evaluation.json
- **Metrics:** Top-1, p95 latency, peak Python allocation
- **Interpretation:** Selected Transformer dominates VOMM empirically and in measured latency.
- **Limitation:** Hardware-specific offline measurements; aggregate neural points excluded.
- **Decision relevance:** Shows that the Transformer cost is dependency complexity, not measured speed.

## 10_macro_f1_memory_tradeoff.png / 10_macro_f1_memory_tradeoff.pdf

- **Purpose:** Show Macro-F1 against measured peak Python allocation.
- **Source:** overall_metrics.json; efficiency.json; single_checkpoint_evaluation.json
- **Metrics:** Macro-F1, peak Python allocation, p95 latency
- **Interpretation:** Transformer improves Macro-F1 without a large measured allocation penalty.
- **Limitation:** Python allocation is not full process steady-state memory.
- **Decision relevance:** Provides a bounded memory-performance view.

## 11_performance_efficiency_summary.png / 11_performance_efficiency_summary.pdf

- **Purpose:** Present descriptive performance-efficiency ratios.
- **Source:** overall_metrics.json; efficiency.json; single_checkpoint_evaluation.json
- **Metrics:** Top-1/ms, Macro-F1/ms, throughput/MiB, deltas versus VOMM
- **Interpretation:** Simple baselines have large ratios because they do less; ratios are not selection criteria.
- **Limitation:** Unavailable storage values remain N/A.
- **Decision relevance:** Prevents cherry-picking an efficiency quotient.

## 12_focused_overall.png / 12_focused_overall.pdf

- **Purpose:** Compare the frozen Transformer with VOMM on the identical test set.
- **Source:** single_checkpoint_evaluation.json
- **Metrics:** Top-1, Top-3, Macro-F1, weighted-F1, balanced accuracy, MRR, coverage, abstention
- **Interpretation:** Transformer leads most aggregate metrics; VOMM leads Top-3 slightly.
- **Limitation:** Raw neural scores are not calibrated probabilities.
- **Decision relevance:** Defines the final single-checkpoint empirical comparison.

## 13_paired_outcomes.png / 13_paired_outcomes.pdf

- **Purpose:** Show mutually exclusive paired case outcomes.
- **Source:** single_checkpoint_evaluation.json
- **Metrics:** Transformer wins, VOMM wins, both correct, both wrong
- **Interpretation:** Transformer has 1,887 wins versus 838 VOMM wins.
- **Limitation:** Counts do not encode tactic-specific costs.
- **Decision relevance:** Shows case-level rather than aggregate-only superiority.

## 14_paired_confidence_intervals.png / 14_paired_confidence_intervals.pdf

- **Purpose:** Show paired whole-session improvement intervals.
- **Source:** single_checkpoint_evaluation.json
- **Metrics:** Transformer-minus-VOMM Top-1, Macro-F1, balanced accuracy
- **Interpretation:** All interval lower bounds exceed zero.
- **Limitation:** Bootstrap uncertainty does not address label validity.
- **Decision relevance:** Confirms that aggregate gains are not sampling noise within this corpus.

## 15_tactic_precision.png / 15_tactic_precision.pdf

- **Purpose:** Compare tactic precision with support.
- **Source:** single_checkpoint_evaluation.json
- **Metrics:** Precision and support
- **Interpretation:** Transformer increases Persistence and Execution precision.
- **Limitation:** Impact has zero support; credential access has two cases.
- **Decision relevance:** Exposes class-level behavior.

## 16_tactic_recall.png / 16_tactic_recall.pdf

- **Purpose:** Compare tactic recall with support.
- **Source:** single_checkpoint_evaluation.json
- **Metrics:** Recall and support
- **Interpretation:** Transformer gains Persistence recall but loses Execution and privilege escalation.
- **Limitation:** Rare-class estimates are unstable or unavailable.
- **Decision relevance:** Displays the central selection trade-off.

## 17_tactic_f1.png / 17_tactic_f1.pdf

- **Purpose:** Compare tactic F1 with support.
- **Source:** single_checkpoint_evaluation.json
- **Metrics:** F1 and support
- **Interpretation:** Transformer improves major supported class F1 except command/control and privilege escalation.
- **Limitation:** Macro summaries include highly unequal supports.
- **Decision relevance:** Balances class precision and recall.

## 18_persistence_execution_tradeoff.png / 18_persistence_execution_tradeoff.pdf

- **Purpose:** Compare precision, recall, and F1 for Persistence and Execution.
- **Source:** single_checkpoint_evaluation.json
- **Metrics:** Six tactic metrics per model
- **Interpretation:** Persistence recall rises to 1.0 while Execution recall falls to 0.7118.
- **Limitation:** No empirical tactic-cost matrix exists.
- **Decision relevance:** Explains why aggregate superiority is not the whole decision.

## 19_opposing_confusions.png / 19_opposing_confusions.pdf

- **Purpose:** Present both models' opposing major confusions neutrally.
- **Source:** single_checkpoint_evaluation.json
- **Metrics:** VOMM Persistence→Execution; Transformer Execution→Persistence
- **Interpretation:** VOMM misses 1,718 Persistence cases; Transformer misses 819 Execution cases.
- **Limitation:** Only the focal cross-confusions are shown.
- **Decision relevance:** Prevents one-sided presentation of model error.

## 20_transformer_win_sources.png / 20_transformer_win_sources.pdf

- **Purpose:** Decompose Transformer paired wins by tactic.
- **Source:** single_checkpoint_evaluation.json
- **Metrics:** 1,718 Persistence wins, 169 other wins, 1,887 total
- **Interpretation:** 91.0% of wins are Persistence, but aggregate Macro-F1 and balance still improve.
- **Limitation:** Win concentration may reflect corpus patterns.
- **Decision relevance:** States the strongest limitation on the aggregate result.

## 21_chronological_stability.png / 21_chronological_stability.pdf

- **Purpose:** Compare four ordered test windows.
- **Source:** single_checkpoint_evaluation.json
- **Metrics:** Top-1, Macro-F1, Execution recall, Persistence recall
- **Interpretation:** Aggregate gain and Execution regression both persist.
- **Limitation:** Privacy minimization omits per-session timestamps.
- **Decision relevance:** Tests internal temporal stability without claiming future generalization.

## 22_repeated_pattern_caveat.png / 22_repeated_pattern_caveat.pdf

- **Purpose:** Visualize repeated-pattern and weak-label caveats.
- **Source:** single_checkpoint_evaluation.json
- **Metrics:** 12,235 cases, 45 sequences, 99.47% repeated-win exposure, 100% Persistence exposure
- **Interpretation:** The corpus is highly repetitive.
- **Limitation:** This is not proof of leakage or template causality.
- **Decision relevance:** Bounds generalization claims.

## 23_reliability_failure_handling.png / 23_reliability_failure_handling.pdf

- **Purpose:** Summarize verified and unavailable reliability evidence.
- **Source:** single_checkpoint_evaluation.json; selected_transformer_metadata.json; focused tests
- **Metrics:** Replay runs, failures, score delta, hash/reload/state checks, failure semantics
- **Interpretation:** Offline checkpoint replay is deterministic; runtime invalid-input handling is not implemented for Transformer.
- **Limitation:** No deployed Transformer adapter exists.
- **Decision relevance:** Separates checkpoint reliability from production readiness.

## 24_weighted_decision_matrix.png / 24_weighted_decision_matrix.pdf

- **Purpose:** Display the accepted retrospective multi-factor matrix.
- **Source:** latest accepted multi-factor decision analysis
- **Metrics:** Seven criteria, weights, five alternatives, weighted totals
- **Interpretation:** Transformer-primary dual reporting ranks first.
- **Limitation:** The matrix is retrospective and not a preregistered statistical test.
- **Decision relevance:** Connects evidence to the PoC objective transparently.

## 25_model_roles.png / 25_model_roles.pdf

- **Purpose:** Separate empirical, operational, and thesis roles.
- **Source:** single_checkpoint_evaluation.json; current policy; accepted decision analysis
- **Metrics:** Role assignments
- **Interpretation:** Transformer is primary experimental; VOMM remains baseline and rollback.
- **Limitation:** This task does not change deployed authority.
- **Decision relevance:** Avoids using one label for several different decisions.

## 26_why_transformer_selected.png / 26_why_transformer_selected.pdf

- **Purpose:** Balance reasons for selecting Transformer against remaining limitations.
- **Source:** single_checkpoint_evaluation.json
- **Metrics:** Aggregate gains, intervals, runtime, integrity, class limitations
- **Interpretation:** Evidence supports corpus-level experimental selection, not production superiority.
- **Limitation:** Weak labels and no prospective independent holdout remain.
- **Decision relevance:** Provides an examiner-ready balanced rationale.

## 27_why_vomm_retained.png / 27_why_vomm_retained.pdf

- **Purpose:** Explain VOMM's continuing baseline and rollback value.
- **Source:** artifact manifest; single_checkpoint_evaluation.json; current policy
- **Metrics:** Execution recall, explainability, dependencies, integration, rollback
- **Interpretation:** VOMM remains operationally and analytically important despite lower aggregate metrics.
- **Limitation:** Its Persistence recall is only 0.0402.
- **Decision relevance:** Justifies dual reporting rather than removal.

## 28_final_decision_dashboard.png / 28_final_decision_dashboard.pdf

- **Purpose:** Summarize metric winners, operational winners, selected roles, and the central trade-off.
- **Source:** all accepted compact evidence
- **Metrics:** Top-1, Macro-F1, balance, Top-3, latency, complexity, roles
- **Interpretation:** Different objectives produce different winners.
- **Limitation:** Operational simplicity is qualitative where dependency footprint is unmeasured.
- **Decision relevance:** Supports thesis defense at a glance.

## 29_executive_summary.png / 29_executive_summary.pdf

- **Purpose:** Answer the final seven model-selection questions.
- **Source:** all accepted compact evidence and accepted decision analysis
- **Metrics:** Decision and claim boundaries
- **Interpretation:** Transformer is primary experimental; VOMM remains concurrent baseline/rollback.
- **Limitation:** No general production-superiority claim is justified.
- **Decision relevance:** States the final conclusion without score fusion or routing.

## Claim boundary

The accepted evidence supports the Transformer as the strongest aggregate model on this external held-out corpus and as the primary experimental PoC predictor. It does not establish general production superiority. VOMM remains the concurrent interpretable baseline and rollback model. No score fusion or tactic-dependent routing is used.
