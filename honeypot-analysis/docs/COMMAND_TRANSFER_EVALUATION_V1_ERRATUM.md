# Command-transfer evaluation v1 erratum

The frozen file
`evaluation/command_transfer_attempt_independent_frozen.v1.json` was not
modified after execution.

Its expected entity labels were wrong for `CTA-013`, `CTA-014`, `CTA-018`,
and `CTA-022`. Each command contains a literal HTTP(S) URL but is
hard-abstained because of an unsupported option, unresolved expansion, or
malformed quoting. The lossless typed-fact contract correctly retains the
literal URL entity while emitting an `unknown` operation. It produces zero
eligible family matches, findings, hypotheses, or guidance.

Removing those literal entities to make the fixture pass would be a lossy,
case-tailored implementation change. The replay test therefore preserves and
classifies the four frozen expectation discrepancies explicitly while still
requiring exact operations and zero authority. The independently authored
post-implementation holdout is the acceptance set for both lossless entity
retention and family selection.

