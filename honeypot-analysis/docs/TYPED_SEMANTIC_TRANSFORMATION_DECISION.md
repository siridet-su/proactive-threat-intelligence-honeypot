# Typed transformation family decision

Decision date: 2026-07-30

Baseline: `574df6c`

Disposition: **retain as shadow-only**

## Frozen contract

The typed layer may describe a literal, supported `base64` decode operation as
`decode_transform`. An input redirect is an independent `file_read` facet and
an output redirect is an independent `file_write` or `file_append` facet.
A pipe into a shell is an execution-attempt observation in a different
fragment; it is not proof that decoding produced valid bytes or that the shell
executed them.

Malformed syntax, missing operands, encoding rather than decoding, unsupported
transform utilities, unresolved expansions, failed commands, unknown outcomes,
and compound outcomes are ineligible for transformation findings or guidance.
Cowrie command success cannot prove decoded content, output bytes, or a
real-host effect.

## Evidence and decision

No retained raw command in the privacy-preserving demonstration telemetry
exercises decoding. The only large-corpus evidence is aggregate and cannot
validate a literal transform. Activating a transformation finding would add a
new authority surface without an observed thesis example, while decode-to-file
and decode-to-shell require exact cross-fragment outcome and relationship
semantics. This is outside the minimum convincing PoC target.

The frozen evaluation therefore checks that the shadow representation keeps
decode-only, decode-to-file, and decode-to-shell distinct and fails closed. It
does not authorize a v4 finding, hypothesis, v3 finding, or advisory action.
Activation remains blocked until independent retained telemetry and a
family-specific evaluation justify the additional authority.

## Acceptance

- expected literal operations and redirect facets are losslessly retained;
- malformed, unsupported, missing, and expansion-dependent inputs stay
  unknown;
- no transformation-specific v4/v3 output is emitted;
- no hypothesis or action derives from shadow facts;
- fact and report validation and repeated construction are deterministic.

