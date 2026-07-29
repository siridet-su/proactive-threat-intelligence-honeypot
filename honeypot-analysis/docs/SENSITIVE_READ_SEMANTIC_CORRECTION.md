# Sensitive-read semantic correction

The correction starts from
`70671d18930c1a866eb7dd48fdc0301ea0b27618` and changes only the activated
`sensitive_read` input. It does not activate another operation family or
change historical readers.

## Verified root causes

- `stat` shared the content-reader branch and was promoted to `file_read`.
- credential sensitivity came from raw-command regex substrings rather than
  complete parsed operands, splitting AWS and gcloud paths and missing quoted
  or complete SSH paths;
- generic string cleaning removed meaningful leading or trailing path
  whitespace;
- CWD-resolved reads and raw credential substrings produced different entity
  identities;
- input redirects were appended after sensitive-read derivation;
- a numeric command argument immediately before a redirect was mistaken for a
  file descriptor; and
- unsupported nested syntax could retain a resolved raw credential entity.

## Correction boundary

The hash-bound typed vocabulary now contains a closed sensitive-path policy.
The parser rebuilds authority-bearing credential entities from complete parsed
path operands, preserves exact path whitespace, distinguishes adjacent
IO-number redirects from separately spaced numeric arguments, and derives the
sensitive operation only after redirect facets exist. Metadata inspection
remains unknown. Failures, uncertainty, compound outcomes, additional
operations, unsupported syntax, and unresolved identity continue to abstain.

The finding remains a Cowrie-reported command observation, not proof of
credential acquisition or a real-host effect. Guidance remains manually
approved, unsafe to auto-execute, independent of hypotheses, and unable to
create alerts or actions.

## Frozen evaluations

The unchanged 50-case replay is recorded in
`evaluation/sensitive_read_frozen_50_replay.v1.json`. It references the
external frozen specification SHA-256
`4a9d5826253109f93c05f82fc671d0be57979d8e717458d3553ea387dbae78a9`.
The repository replay file SHA-256 is
`0a838aa30016e985202c0ca0327861bb7b5cd6b788a24b38dadb3ae35f0598f1`.

The separately authored holdout was frozen before its first execution at
`evaluation/sensitive_read_holdout.v1.json`, SHA-256
`be7aed354c18e8174e419e47bccbd8c84a8e2a4a1a37129beec73c9501d805d5`.
Its commands are not copied from the implementation tests or the 50-case
replay.

The corrected results are:

| Evaluation | Literal operation TP/FP/FN/TN | Eligible selection TP/FP/FN/TN | Precision / recall / F1 |
| --- | --- | --- | --- |
| Frozen 50 cases | 28 / 0 / 0 / 22 | 18 / 0 / 0 / 32 | 1.0 / 1.0 / 1.0 |
| Independent 24-case holdout | 15 / 0 / 0 / 9 | 12 / 0 / 0 / 12 | 1.0 / 1.0 / 1.0 |

Both evaluations rebuild each case twice and require byte-equivalent fact sets
and selections plus stable assessment and guidance IDs. Every fact set,
selection, v4 assessment, v3 guidance, evidence reference, entity reference,
path identity, and artifact contract validates. The focused correction suite
passes with `125 passed, 1 skipped`; the complete local suite passes with
`863 passed, 7 skipped`.
