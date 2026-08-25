# Padding-fix completion addendum

This addendum is content-addressed to the COMPLETE_VALID base receipt and adds the required final tables and explicit answers. It does not modify the base receipt or any prior artifact.

## Required internal TRAIN table

| Variant | Macro-F1 | Balanced Accuracy | Top-1 | Top-3 | Credential F1 | Credential precision (OOF) | Credential recall (OOF) | Credential FP (OOF) | Defense Evasion F1 | Privilege Escalation F1 | Wrong >0.80 mean/fold | Seed std Macro-F1 | Parameters |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| M0 | 0.817145 | 0.794771 | 0.984719 | 0.998790 | 0.000000 | 0.000000 | 0.000000 | 0 | 0.965977 | 0.984358 | 2.60 | 0.006714 | 2599 |
| M1 | 0.875610 | 0.932752 | 0.977452 | 0.992637 | 0.417788 | 0.261194 | 1.000000 | 198 | 0.965977 | 0.984358 | 6.00 | 0.014384 | 2599 |
| M2 | 0.817441 | 0.794845 | 0.984883 | 0.998823 | 0.000000 | 0.000000 | 0.000000 | 0 | 0.965977 | 0.984358 | 2.40 | 0.006425 | 2599 |
| M3 | 0.871780 | 0.932066 | 0.977713 | 0.994926 | 0.420239 | 0.265152 | 1.000000 | 194 | 0.965977 | 0.982064 | 2.73 | 0.008716 | 2599 |

## Final model comparison

The selected padding-final is M1/refined-v1 because the corrected M3 variant did not improve the primary grouped-CV Macro-F1. See `final_model_comparison` in the JSON.

## Required questions

1. No. The prior probe changed absolute valid-token positions together with padding.
2. Yes; it is classified POSITION_AND_PADDING_CONFOUNDED.
3. Yes. M1 exposes 53.4227% valid-query attention mass on PAD keys in the diagnostic.
4. Yes. M3 passes a bool key-padding mask with zero measured PAD-key mass.
5. Yes; all lengths 1,2,3,4,5,6,8 pass at atol 1e-6 (fresh M3 delta 0.0).
6. atol=1e-6, rtol=0.0.
7. Yes; invalid_final_slot_count is 0 across 10,186 TRAIN cases.
8. M2 improves Macro-F1 only negligibly over M0; M3 is 0.00383 below M1, so masking alone does not improve the selected inverse-sqrt primary metric.
9. M2 is negligibly higher than M0; M3 is negligibly lower than M1.
10. M2 is negligibly higher than M0; M3 is slightly higher than M1.
11. M2 is negligibly higher than M0; M3 is higher than M1.
12. M3 rare-class F1 is mixed: credential +0.00245, defense unchanged, privilege slightly lower than M1.
13. Yes, credential FP falls from 198 to 194 in the TRAIN OOF seed-20260822 comparison.
14. Yes; credential recall is 1.0 for both M1 and M3 in that OOF comparison.
15. Mixed: execution/persistence improve slightly under M3 while command-and-control and privilege trade off; no common-class collapse.
16. Yes. Inverse-sqrt reweighting is the dominant gain after masking (M3 vs M2 Macro-F1 +0.05434).
17. Loss reweighting matters substantially more than the padding correction on Macro-F1.
18. The interaction is structurally valid and improves calibration/Top-3, but not primary Macro-F1 over M1.
19. Yes. M3 five-seed Macro-F1 mean 0.87368, std 0.00872; no single-seed selection was used.
20. Yes; full selected M1 Macro-F1 0.87368 versus last-only 0.54468 on held-out TRAIN folds.
21. No. Full and true-prefix-shuffle correctness are exactly equal in this study.
22. No; context is useful, but chronological order is not demonstrated.
23. Yes descriptively; learned position norms are nonzero and pairwise distances diverge (see positional_embedding_diagnostics.json).
24. Yes; the original diagnostic measured substantial PAD-key mass.
25. Yes; M3 PAD-key mass is exactly zero in the available attention diagnostic.
26. No; all four variants have 2,599 parameters.
27. Not materially established as a decisive difference; the architecture and parameter count are unchanged and no latency regression gate failed.
28. Yes on TRAIN OOF for the selected M1: temperature scaling improves NLL/ECE/Brier.
29. Yes; NLL improvement is 0.04685.
30. Yes; ECE improvement is 0.04926.
31. Yes; Brier improvement is 0.00568.
32. Yes; top-1 labels, top-3 rankings, and full ranking are exact unchanged.
33. Raw scores alone are not preferred for display.
34. Yes; temperature-scaled scores are preferred.
35. No; ranks-only is not required because the TRAIN-OOF temperature study supports the scaled display, with post-selection limits retained.
36. Yes slightly: padding-final M1 Selection Macro-F1 0.85183 versus refined-v1 0.85120, descriptive only.
37. No material difference: observed Calibration Macro-F1 is 0.41527 for both refined-v1 and padding-final.
38. No: padding-final is below refined-v1 on controlled Top-3 and slightly below on Top-1.
39. D3 is not an adoption basis; controlled results remain synthetic descriptive evidence.
40. D4 is not an adoption basis; controlled results remain synthetic descriptive evidence.
41. Length-25 behavior does not provide evidence for generalization; it remains descriptive stress behavior.
42. Yes; unseen-pair behavior remains weak by design and was not used for tuning.
43. No reduction is demonstrated: both refined-v1 and padding-final report 12 two-cycle detections in the exact-start free-run regression.
44. Yes structurally, because M3 masks PAD keys correctly; predictive replacement is not justified.
45. No for replacement: M3 is competitive but does not improve the primary Macro-F1 over refined-v1.
46. Yes; TRAIN support remains sparse (history counts and target support are frozen in the summary).
47. Yes; label ambiguity remains a documented bottleneck from the prior frozen support audit.
48. No evidence justifies increasing model size; this targeted study did not reopen capacity search.
49. For the prediction-only POC, retain the compact original-architecture inverse-sqrt Transformer (M1/refined-v1) with TRAIN-OOF temperature scalar 0.61913 for display; keep M3 as the structurally corrected alternative, not the adopted replacement.
50. Allowed claims are bounded to TRAIN group-aware development evidence, structural padding correctness, and controlled descriptive stress results; no attacker-intent, unknown-attack, production-readiness, or real-world-generalization claims.

## Preservation

PRIOR ARTIFACTS PRESERVED = YES
EXISTING FILES MODIFIED = NONE
EXISTING FILES OVERWRITTEN = NONE
SEALED DATA ACCESSED = FALSE
SYNTHETIC DATA USED FOR TRAINING = FALSE
SELECTION USED FOR TUNING = FALSE
CALIBRATION USED FOR TUNING = FALSE
CONTROLLED BENCHMARK USED FOR TUNING = FALSE
TEMPERATURE FIT DATA SOURCE = TRAIN OOF ONLY
