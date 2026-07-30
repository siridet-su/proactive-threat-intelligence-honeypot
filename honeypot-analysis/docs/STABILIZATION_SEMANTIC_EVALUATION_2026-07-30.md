# Independent stabilization semantic evaluation

## Scope and freeze boundary

The 40-case specification was authored and frozen before execution in commit
`1648c68bbacf178e83756e04aaef1bcacefc65e0`. Its SHA-256 is
`5fa0bdb5d6fcebf021a1b122e04f52c873e1f17f494c18d07dc26d9a449f3ac7`.
The expected labels were not changed after observing runtime output.

Independence is partial, not organizationally independent: the evaluator was
authored in a Codex session that had already inspected runtime contracts. No
cases or labels were copied from repository tests, existing frozen
evaluations, rule examples, policy examples, or documentation examples.

The final execution used evaluator revision
`2d42fd092f19bbf5bd283b3eba3937e5f076acb3`. The complete result is
`evaluation/stabilization_semantic_evaluation_results_2026-07-30.json`, with
SHA-256
`3ab19759ba6d0facc5c683a6e1db03197290cd0454302c0c0bee60c5165c1639`.

## Results

| Layer | Micro precision | Micro recall | Micro F1 | Macro F1 |
| --- | ---: | ---: | ---: | ---: |
| Reviewed classification | 0.461538 | 0.342857 | 0.393443 | 0.234848 |
| Typed operations | 0.803571 | 0.818182 | 0.810811 | 0.784375 |
| Eligible family selection | 1.000000 | 0.875000 | 0.933333 | 0.945074 |
| Specialized findings | 1.000000 | 0.875000 | 0.933333 | 0.945074 |
| Specialized guidance actions | 1.000000 | 0.166667 | 0.285714 | 0.500000 |

Seven cases matched all frozen labels (`SE11`, `SE12`, `SE20`, `SE24`,
`SE27`, `SE32`, and `SE36`); 33 retained one or more differences. The result
document records the expected and actual sets, false positives, and false
negatives for every case.

Classification differences are dominated by the deployed reviewed policy
using parent techniques where the independent labels expected sub-techniques
(`T1059`/`T1059.004`, `T1552`/`T1552.004`, `T1222`/`T1222.002`, and
`T1053`/`T1053.003`), plus genuine coverage disagreements for inspection,
archive, service, and removal variants. These are evaluation findings, not
silently normalized matches.

Typed-operation misses occurred for the unseen `ps -eo`, `truncate -s 0`,
`systemctl try-restart`, one `wget --timeout` variant, one piped transfer, and
expansion-dependent read. The copy lookalike produced read/write facets while
remaining ineligible for every specialized family. Family selection and
finding evaluation had no false-positive selections, but abstained on one
inspection, one filesystem-modification, and one transfer-attempt case.

Specialized guidance had no false-positive action families. Its lower recall
reflects that the current v3 policy emits specialized actions for only a
subset of independently expected inspection, filesystem, and transfer-attempt
findings. The frozen result preserves this difference; no policy or expected
label was changed.

## Safety, integrity, and reproducibility

- Unsupported specialized output rate: `0.0` (zero unsupported selections,
  findings, guidance actions, or hypothesis sets).
- Contradicted hypotheses: `0`; unfalsifiable hypotheses: `0`.
- Required abstention correctness: `40/40`.
- Typed-fact, selection, v4, and v3 reference/integrity validation: `40/40`.
- SQLite report persistence equality: `40/40`.
- JSON/Markdown/PDF-or-fallback/STIX manifest validation: `40/40`.
- Integrity-bound semantic repeatability: `40/40`.
- Automatic execution remained false, manual approval remained required, and
  automatic-alert authority remained false in every case.
- Prediction, enrichment, correlation, LLM-style prose, and an audit-only
  ATT&CK candidate did not create specialized output in `SE36`.

## Interpretation and boundary

The evaluation confirms strong precision and fail-safe abstention at the
activated family/finding boundary, but it does not support a claim of complete
classification, typed-operation, or specialized-guidance coverage. The exact
classification disagreements and 33 case-level differences require
independent adjudication before any runtime correction. They were deliberately
not used to tune this stabilization run.

This task made no runtime policy, classifier, typed-semantic extractor,
hypothesis, guidance, production data, service, deployment, or infrastructure
change.
