# Next-tactic model-decision figure summary

All figures use the accepted single-checkpoint evidence in `evaluation/next_tactic_benchmark_evidence/single_checkpoint_evaluation.json`. The
Transformer checkpoint is the validation-only-selected seed 20260723 with
SHA-256 `d9b316d76e63b15b175668aa0bf69cfe4172bbd812d6b19743a628cd0ec8073d`. Raw Transformer scores are not treated
as calibrated probabilities. Conclusions are limited to the external,
classifier-derived weak-label held-out corpus.

1. **Overall metric comparison.** Shows higher Transformer Top-1, Macro-F1,
   balanced accuracy, and MRR, while VOMM retains higher Top-3.
2. **Paired outcomes.** Reports the exact 1,887 Transformer wins, 838 VOMM
   wins, 8,960 both-correct cases, and 550 both-wrong cases.
3. **Promotion gate.** Six criteria pass and tactic safety fails; this is the
   direct reason the Transformer was not promoted.
4. **Per-tactic metrics.** Compares precision, recall, and F1 for all requested
   supported tactics without suppressing regressions or weak classes.
5. **Persistence versus Execution.** Contrasts the Persistence recall increase
   with the Execution recall decline.
6. **Focused confusion matrix.** Shows the exact 819 Execution cases predicted
   as Persistence by the Transformer.
7. **Non-promotion explanation.** Summarizes that 1,718 of 1,887 Transformer
   wins were Persistence, alongside Execution and privilege-escalation losses.
8. **Chronological stability.** Shows higher Transformer Top-1 in all four
   windows and lower Transformer Execution recall in every window.
9. **Repeated-pattern warning.** Records 45 distinct tactic-sequence patterns
   across 12,235 cases, 99.47% of Transformer wins in patterns repeated at
   least ten times, and all Persistence cases in such patterns. This is a
   caveat, not a causal claim about templates.
10. **Executive summary.** Distinguishes the best aggregate held-out model
    from the selected authoritative PoC model and states the failed gate.

The previously accepted aggregate benchmark files remain unchanged. This
package neither recomputes metrics nor modifies production behavior.
