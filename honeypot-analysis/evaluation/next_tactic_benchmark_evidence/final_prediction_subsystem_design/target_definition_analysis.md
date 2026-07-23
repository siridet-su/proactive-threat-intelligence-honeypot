# Prediction-target design analysis

## Decision

The final primary task should be:

> Given all trusted Cowrie observations up to a command-derived behavior phase, forecast the next observable outcome before that session ends: either the unordered set of trusted ATT&CK tactics attached to the next distinct behavior phase, or `session_end_no_further_trusted_behavior`.

“Distinct behavior phase” means that consecutive observations with the same tactic set are one phase, while their count and elapsed duration remain input features. The output is a ranked tactic list plus a separate terminal-outcome score. It is not a forecast of the exact next command, attacker intent, compromise of a real asset, or chronological ATT&CK doctrine.

This is a recommendation for the regenerated final experiment. The accepted historical benchmark remains valid evidence for its narrower next-distinct-single-tactic task.

## Compared formulations

| Formulation | Operational meaning and data fit | Advantages | Defects and evaluation burden | Decision |
|---|---|---|---|---|
| Immediately following raw event tactic | Tactic assigned to the next Cowrie event | Closest to event stream | Most Cowrie events have no tactic; timing and event types dominate; weak labels are command-derived; not represented in current corpus | Reject |
| Next command-derived single tactic | One label for the next labeled command | Clear time order across commands | A command can legitimately have multiple labels; choosing or ordering one is arbitrary | Reject as primary |
| Current next distinct flattened tactic | Next item after adjacent duplicate collapse, conditional on a transition | Simple categorical task; directly matches accepted benchmark | Flattens simultaneous labels, hides repetition, excludes terminal outcomes, conditions on continuation, and can overstate live utility | Preserve as historical benchmark only |
| Next tactic transition in a fixed time horizon | Next tactic within a predefined duration | Operationally bounded; supports abstention/negative outcome | Current public corpus lacks timestamps; horizon choice requires new data and predefinition | Future secondary task after timestamped regeneration |
| Next tactic before session termination | Next tactic or end | Addresses live continuation bias | Still ambiguous if next command has multiple simultaneous tactics | Incorporate as terminal branch of the recommended task |
| Multi-label next command behavior | Set of tactics on next labeled command | Does not fabricate within-command order | Same tactic set can repeat many times; no terminal target unless added | Core of the recommended target |
| Ranked candidate tactics only | Marginal rank of possible next tactics | Analyst-friendly, compatible with multi-label outcomes | Without terminal state, coverage and continuation are misleading | Retain as one output of the recommended target |
| Calibrated probabilities | Claimed probabilities per tactic/end | Enables risk/coverage decisions | Requires independent calibration and validation under multilabel semantics; current scores are not calibrated | Optional only after valid calibration |

## Why the current conditional task is incomplete

The accepted payload has 219,336 sessions, but only 49,713 sessions produce at least one transition. Current case generation emits 178,922 cases and discards every terminal prefix. A live predictor does not know in advance that another distinct tactic will occur. Reported accuracy therefore answers:

> If another distinct labeled tactic will eventually occur in this already-selected closed session, which tactic is it?

It does not answer:

> What observable behavior will occur next in the active session, including the possibility that no further trusted behavior occurs?

The final target must include terminal outcomes to remove this survivorship condition.

## Simultaneous-label ordering

The preparation pipeline appends every accepted label from one command to a flat list. Source order within that list is deterministic but is not an observed temporal order. A rule and a model, or multiple deterministic rules, can attach several tactics to the same command. Treating those labels as sequential transitions can manufacture both inputs and targets.

The final example builder must:

1. group labels by original command/event identity;
2. represent the group's tactic values as an unordered set;
3. retain deterministic technique and provenance collections;
4. collapse only consecutive identical sets into phases;
5. record phase run length and elapsed duration;
6. emit the next phase set or terminal outcome.

## Adjacent duplicates

### What current removal does

It retains the order in which tactic names change and removes:

- repeated observations within a tactic;
- phase duration;
- number of contributing commands;
- whether a tactic persisted for one or many events;
- same-tactic continuation as a possible target.

This makes the corpus compact but creates an artificial next-distinct-tactic task.

### Alternatives

| Representation | Scientific effect | Recommendation |
|---|---|---|
| No deduplication | Preserves every label but lets frequent repeated commands dominate and still fabricates within-command order | Do not use on flattened labels |
| Current adjacent string deduplication | Removes repetition entirely | Preserve only for historical compatibility |
| Run-length encoding | Preserves phase order and repetition count with little complexity | Required |
| Tactic set plus repetition count | Avoids within-command order and retains phase persistence | Required |
| Add elapsed time | Separates burst repetition from long persistence | Required when timestamps are available; use predeclared buckets |
| Phase segmentation learned from data | Potentially richer but creates another learned, hard-to-audit preprocessing stage | Out of thesis scope |
| Dual event/phase models | Could answer both immediate and strategic questions | Future research, not minimal final PoC |

Adjacent compression should therefore remain as a phase-construction operation, not as information deletion.

## Final output semantics

- `status`: `predicted`, `abstained`, `insufficient_history`, or `model_unavailable`.
- `terminal_outcome`: a separate raw score for `session_end_no_further_trusted_behavior`.
- `ranked_tactics`: marginal raw scores for tactic candidates in the next phase.
- `prediction_set`: optional thresholded set only if thresholds were fixed on a separate calibration partition.
- `abstention`: used for invalid model, unsupported/OOD input, missing required feature contract, or predeclared uncertainty rule.
- `raw_score`: a model ordering value, never called a probability.
- `calibrated_probability`: absent unless an independently fitted and tested mapping exists.

## Secondary outputs

- Time-to-next-outcome bucket may be added after timestamps are preserved and a horizon is predeclared.
- VOMM disagreement should be a diagnostic, not a fallback, ensemble, or routing signal.
- A score-free generic ATT&CK progression prior may remain documentation-only and must not be presented as an empirical prediction.

## Claims enabled by this target

The primary defensible claim would be:

> On the frozen, provenance-preserving Cowrie corpus, the model ranks tactics associated with the next distinct command-derived behavior phase and distinguishes sessions with no later trusted behavior.

General attacker intent, exact next command, compromise likelihood, future attack outcome, and response necessity remain outside the target.
