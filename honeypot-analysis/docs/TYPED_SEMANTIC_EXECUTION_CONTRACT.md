# Typed execution-attempt contract

Decision date: 2026-07-30

Baseline: `0fbe1d4`

Disposition: **activate only the bounded contract below if the frozen
evaluation and later holdout pass**

## Authority contract frozen before implementation

An eligible execution observation requires exactly one
`execution_attempt` operation in a parsed, successful, single-fragment Cowrie
command fact. The supported shell subset is limited to a reviewed interpreter
(`sh`, `bash`, `dash`, `python`, `python2`, `python3`, or `perl`, including the
already supported `env`/`sudo` wrappers) with either:

- one literal, linkable, resolved script-path entity; or
- an explicit `-c` option with a non-empty literal inline-program entity.

`shell_pipe_execution_attempt` remains a typed observation but is not eligible
because Cowrie supplies only a compound-event outcome for a pipeline. Direct
arbitrary executables, relative `./` invocations, command substitutions,
expansions, wildcards, aliases, unsupported interpreters or options, missing
operands, failed/unknown outcomes, and compound or conditional commands
abstain.

The output states only that Cowrie reported success for an explicit supported
execution-attempt command in its simulated shell. It does not establish that
the program existed, that interpreter evaluation completed, what it did,
attacker intent, compromise, persistence, or any real-host effect.

## Hypothesis and guidance behavior

The exact typed facts independently select:

- one bounded v4 behavioral finding;
- one matching v3 finding; and
- a manual-only corroboration action that asks an authorized analyst to check
  independent process/audit telemetry.

The action is selected directly from the immutable execution fact selection,
not from threat-hypothesis output. No execution hypothesis is emitted because
the literal attempt is an observed finding, not a falsifiable explanation for
unknown behavior. ATT&CK, prediction, enrichment, correlation, and optional
prose cannot create or alter eligibility.

## Acceptance

- zero false-positive eligible selections;
- zero unsupported specialized findings or guidance;
- zero execution hypotheses;
- exact operation, entity, outcome, proof scope, and evidence references;
- all trace fields and IDs integrity-bound;
- deterministic persistence and JSON/Markdown/PDF/STIX rendering;
- existing families and historical readers unchanged.

