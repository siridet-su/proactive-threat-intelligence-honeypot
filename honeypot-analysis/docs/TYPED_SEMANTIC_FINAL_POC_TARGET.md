# Minimum final typed-semantic PoC target

Baseline: `c78f52bcf48e5b21773a0e566dfe51f5d737d792`

## Evidence-based target

The retained 14-command Cowrie demonstration contains four inspection
commands, three sensitive reads, two downloader attempts, two permission
changes, one deletion, and one compound scheduled-task sequence. The large
privacy-minimized corpus contains no raw commands; its aggregate execution
and discovery labels establish thesis relevance but cannot validate literal
operations.

The smallest convincing final controlled-PoC target is therefore:

1. common Cowrie inspection — already activated;
2. resolved sensitive-path reads — already activated;
3. direct Cowrie transfer observations — already activated;
4. bounded filesystem-change observations — justified by retained literal
   permission and deletion commands;
5. explicit execution attempts — the high-value evidence story identified as
   missing by the existing roadmap; and
6. command transfer attempts — separately named and explicitly unable to prove
   transfer completion.

All new outputs remain behavioral observations. They do not claim attacker
intent, compromise, command result contents, persistence, or real-host effect.
Only a separately reviewed policy may add manual guidance; no action is
automatic or executable.

## Remaining-family disposition

| Family | Evidence in checkout | Demonstration value | Authority risk | Initial disposition |
| --- | --- | --- | --- | --- |
| Filesystem create/truncate, append, modify, permission change, directory create, move, delete | Permission changes and deletion occur in retained demo | High | Medium if Cowrie success is described as real effect | Activate as bounded Cowrie command observations after independent evaluation |
| Decode/transformation | No retained raw example | Moderate for staged payload narratives | High across decode-only, file-output, and shell-consumer boundaries | Evaluate; retain shadow-only unless exact output/consumer relationships pass |
| Execution attempt | Aggregate execution labels; no retained raw demo execution | High and explicitly missing from prior target | High if attempt or Cowrie outcome becomes execution proof | Activate only exact script/inline forms; suppress legacy overbroad path |
| Scheduled task | One compound demo sequence without fragment outcome proof | Moderate persistence demonstration | High intent/completion risk and weak retained evidence | Evaluate; keep shadow-only unless exact non-compound cases independently justify it |
| Service inspect/modify | No retained raw example | Low incremental value | Medium-to-high modification/effect risk | Evaluate and normally defer |
| Collection/archive | No retained raw example | Moderate chained-demo value | High source/output/completion and intent risk | Evaluate and normally defer |
| Command transfer attempt | Two retained downloader commands | High contrast with direct transfer | High if called a completed transfer | Split from direct transfer and activate as attempt-only observation |
| Transfer → transform → execute; search → archive → transfer | Typed relationships can be reconstructed | High visual demonstration value | Very high causal, identity, outcome, and attacker-intent risk | Keep contextual until every participating family and exact relationship independently pass |

Unknown, malformed, unsupported, incomplete, expansion-dependent, wildcard,
ambiguous, unresolved, failed, conditional, and compound-outcome inputs never
become eligible merely to improve coverage.

## Filesystem-change contract

The family covers:

- `file_write` (`create_or_truncate`);
- `file_append` (`append_or_create`);
- `file_modify`;
- `permission_modify`;
- `directory_create`;
- `file_move`; and
- `file_delete`.

One and only one of these mutation operations must appear in a parsed,
successful Cowrie fragment. Exact non-authoritative companion facets are
allowed only when required by the literal syntax: `literal_data_emission` for
redirection, and `file_read` for copy or in-place modification. Every mutation
target must resolve to a linkable entity and every path target must have a
resolved path identity. Additional mutations, failed/unknown/compound
outcomes, unsupported syntax, unresolved operands, or any abstention cause
family abstention.

The v4 and v3 outputs state only that Cowrie reported success for the parsed
filesystem-change command inside its simulated shell. They do not establish
the resulting filesystem state, malicious intent, persistence, cleanup,
compromise, or real-host effect. No filesystem-specific action or hypothesis
is authorized.

## Rollback

The complete pre-batch boundary is
`c78f52bcf48e5b21773a0e566dfe51f5d737d792`. Each accepted family receives a
separate implementation commit so it can be reverted without rewriting
historical records.
