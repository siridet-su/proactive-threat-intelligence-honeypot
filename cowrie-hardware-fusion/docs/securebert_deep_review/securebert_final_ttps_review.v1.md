# `final_ttps` review

`MergedResult.final_ttps` is a backward-compatible alias for
`selected_command_ttps`. It is used by offline/legacy merge helpers, not by the
canonical `classification_event.v2` trust decision.

The executable selection is:

1. If any rule predictions exist, return every rule prediction whose `high_conf` is
   true.
2. Otherwise return every model prediction whose `high_conf` is true.

It can be empty. It can contain multiple rule labels. Given the canonical model
adapter it can contain at most one model label. There is no ranking, new ATT&CK
mapping, or cross-source deduplication in the property itself. Model-only values can
enter this compatibility list when no rule exists.

It is therefore **not final truth**. It means an internal high-confidence
command-level compatibility selection before current authority resolution. The name is
misleading outside its documented compatibility boundary. It is not session-final,
attacker ground truth, correlation-confirmed, or equivalent to the trusted observed
session TTP set.

Current worktree documentation/docstrings already clarify this boundary; active d5f
predates part of the later wording, so thesis/report wording must not rely on the field
name alone.

