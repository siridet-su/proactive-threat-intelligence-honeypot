# Typed-semantic coverage roadmap

This decision record was authored from the repository at
`4dc0f08da2395b07998d79683266814734ca578c`. It reviews the evidence available
in the checkout rather than treating operation count as a coverage goal.

## Evidence available for the decision

- `data/samples/demo_cowrie_realistic.json` contains 14 Cowrie
  `command.success` events. The typed parser produces four inspection
  observations (`whoami` twice, `id`, and `uname -a`), three sensitive reads,
  two transfer attempts, two permission changes, one schedule inspection, one
  literal emission, one delete, and two unknown fragments. Inspection is the
  most common defensible non-activated family in this retained command sample.
- `evaluation/next_tactic_zenodo_7day_model_comparison.json` records 387,720
  sessions with commands and 580,174 aggregate `discovery` labels. These
  aggregate labels support demonstration relevance, but they are not raw
  commands and cannot validate a literal inspection operation.
- The privacy-minimized 219,336-session payload explicitly has
  `contains_raw_commands=false`. It can evaluate tactic transitions, not typed
  command semantics.
- The canonical event path retains command input/success/failure and direct
  Cowrie file download/upload observations. Login, connection, and client
  metadata remain observed evidence but are not shell operations.
- `session_assessment.v4` and `response_guidance.v3` currently activate only a
  resolved sensitive-path read and a direct Cowrie transfer observation.
  Downloader commands remain attempts. All other typed operation families are
  shadow-only.

The aggregate classification corpus is therefore evidence of project
relevance, not proof that any new parser rule is correct. Activation must be
justified by the literal Cowrie evidence and the closed typed contract.

## Coverage matrix

| Behavior or family | Current recognition | Thesis / guidance / hypothesis value | Ambiguity and overclaim risk | Minimum authoritative evidence | Decision |
| --- | --- | --- | --- | --- | --- |
| Resolved sensitive credential-path content read | Activated `sensitive_read` | High-value credential-access demonstration; bounded manual exposure review; behavioral finding only | Medium path and outcome risk, already independently corrected | Exact `file_read` plus `credential_path_read`, same resolved path identity, parsed fragment, Cowrie-reported success, exact evidence ref | **Retain activated** |
| Direct Cowrie file transfer | Activated `transfer` | High-value sensor-native transfer demonstration and exact-hash correlation review | Low when restricted to direct event; high if command attempts are promoted | Direct download/upload event, exact valid SHA-256, event-observed outcome, exact event ref | **Retain activated** |
| Host, account, route, process, socket, account-database, capacity, and filesystem-search inspection | Typed, shadow-only | High demonstration value for common discovery-like behavior; useful bounded observed finding; no specialized response action needed | Low to medium. Risk comes from unsupported options, unresolved paths, compound outcomes, and describing observation as intent or real-host discovery | Exactly one reviewed inspection operation in a parsed fragment; Cowrie-reported success; no additional operation or abstention; every referenced entity/path resolved | **Activate next, observation-only** |
| General file content read | Typed, shadow-only except sensitive reads | Moderate behavioral value, little response value for arbitrary paths | Medium: stdin, pipes, aliases, and target identity | Exact reader operation and resolved operand/redirect | **Defer**; broad reads add little beyond the generic command finding |
| Create, overwrite, append, in-place modify, permission change, move, and delete | Typed, shadow-only | Useful filesystem-change-attempt demonstration | Medium to high: Cowrie success is not real-host effect; option and multi-target semantics matter | Exact operation and target, supported option subset, parsed fragment, bounded Cowrie outcome | **Defer** pending family-specific effect wording and independent evaluation |
| Decode and transformation | Typed, shadow-only | Useful for payload-preparation chains | High when decode-only, decode-to-file, and decode-to-shell are conflated | Exact source/destination/consumer facets and supported chain relationships | **Defer** |
| Execution attempt | Typed, shadow-only; contained legacy finding remains | High PoC value | High: attempts, shell consumers, script identity, failures, and real-host effect are easy to overstate | Exact executable or inline-program facet, resolved target where applicable, fragment outcome, no ambiguity | **Defer as the next likely evaluation target**; do not activate with inspection |
| Scheduled-task inspect | Typed, shadow-only | Moderate observation value | Low for exact list operations, but low incremental value this stage | Exact supported inspect subcommand and fragment outcome | **Retain observation-only in shadow** |
| Scheduled-task create/modify/delete | Typed, shadow-only | High persistence-demo value | High attacker-intent and completion risk; stdin task content is unresolved | Exact operation, target/content relationship, outcome, and no ambiguous stdin | **Defer** |
| Service inspect | Typed, shadow-only | Moderate observation value | Low to medium, but separate command grammar and weak incremental value | Exact read-only subcommand and service entity where required | **Retain observation-only in shadow** |
| Service modify | Typed, shadow-only | Moderate operational-change demonstration | High effect and intent risk | Exact modifying subcommand, service entity, outcome | **Defer** |
| Filesystem search | Included in selected inspection family | High discovery-like demonstration value | Medium path and `find` expression risk | Resolved starting path, no mutating predicate, supported expression subset, successful fragment | **Activate only under the inspection contract** |
| Collection and archive creation | Typed, shadow-only | High value for staged collection chains | High without source, destination, and completion relationships | Exact archive output and source refs, supported syntax, fragment outcome | **Defer** |
| Command transfer attempt | Typed, shadow-only | Useful context for a transfer chain | High if called a completed transfer | Exact URL/destination attempt; direct transfer event needed for completion | **Retain shadow-only** |
| Transfer → transform → execution | Relationships can be represented, authority inactive | Potentially compelling chained demonstration | Very high causal, identity, and outcome overclaim risk | Resolved same-entity relationships across all operations and direct evidence where completion is claimed | **Defer** until each family passes independently |
| Working-directory change | Typed context, shadow-only | Important for resolving later relative paths, not a report claim itself | Medium when change outcome is failed/compound/unknown | Exact `cd`, resolved target, Cowrie-reported successful fragment | **Retain as context-only** |
| Account modification | Typed broad family, shadow-only | Potential account-change demonstration | High because account creation, key writing, and generic modification are not equivalent | Split operation contracts and exact account/path relationships | **Reject current broad activation** |
| Login/connect/client metadata | Canonical observed events, not typed operations | Useful session context | High if promoted to shell behavior | Direct Cowrie event only | **Retain as observed context** |
| Unknown, malformed, unsupported, expansion-dependent, or incomplete input | Typed `unknown` or abstention | Important safe-failure demonstration | Overclaim risk is the reason to abstain | No defensible complete literal operation | **Never activate** |

## Smallest convincing controlled-PoC target

A representative PoC does not require every Linux command or every mutation.
The smallest justified target has four distinct evidence stories:

1. common read-only inspection inside Cowrie;
2. a resolved sensitive credential-path read;
3. a direct sensor-observed file transfer; and
4. a narrowly evaluated execution-attempt family in a later change.

The current change adds only item 1. Items 2 and 3 are already activated.
Item 4 remains deferred because its overclaim risk and path/consumer semantics
are materially different. Filesystem mutation, persistence, collection, and
multi-family chains remain shadow-only until independently justified.

## Selected contract: `inspection`

The selected family is an observation-only interpretation of these closed
operation types:

- `host_uptime_inspection`
- `filesystem_capacity_inspection`
- `system_identity_inspection`
- `account_identity_inspection`
- `network_route_inspection`
- `process_inspection`
- `network_socket_inspection`
- `account_database_inspection`
- `filesystem_search`

Eligibility requires:

- a parsed command fragment with no abstention reason;
- exactly one of the allowed inspection operations and no other operation;
- `reported_success`, fragment scope, and `reported_completed`;
- `general_command_semantics` proof;
- complete resolution of every referenced entity;
- a resolved path identity for every referenced path; and
- exact source-observation and supporting-evidence references.

An eligible fact produces a low-severity behavioral finding that Cowrie
reported a supported inspection command in its simulated shell. It does not
claim reconnaissance, malicious intent, successful compromise, result
contents, or any effect on a real system. The threat-hypothesis path records
the same bounded behavioral finding independently and emits no inspection
hypothesis. `response_guidance.v3` independently records the finding and adds
no inspection-specific action. Existing generic manual corroboration guidance
may remain because it is grounded in the canonical command observation, not
in a hypothesis or prediction.

Failed, unknown, compound, conditional, contradictory, malformed, unsupported,
unresolved, wildcard, expansion-dependent, multi-operation, or incomplete
facts abstain. ATT&CK mappings, predictions, enrichment, correlations, and
optional prose cannot create or alter eligibility.

## Expected examples frozen with the contract

| Cowrie evidence | Expected typed result | Authoritative output |
| --- | --- | --- |
| successful `uname -srv` fragment | `system_identity_inspection` | bounded inspection finding; no inspection action or hypothesis |
| failed `ip route list` fragment | operation retained with failed effect | family abstention |
| successful `find reports -type f` with observed CWD `/srv/cowrie` | resolved `filesystem_search` | bounded inspection finding |
| the same relative search without a known CWD | unresolved path | family abstention |
| successful `uname -m > /tmp/profile` | inspection plus write facet | family abstention because this activation is not a pure inspection |
| ATT&CK discovery label attached to `printf survey` | literal emission plus contextual ATT&CK candidate | no inspection finding |

## Rollback boundary

The pre-activation boundary is
`4dc0f08da2395b07998d79683266814734ca578c`. Reverting the activation commit
must restore the two-family policy and runtime behavior without rewriting
historical v4/v3 records. The frozen evaluation specification is an evidence
artifact and can remain across a runtime rollback.
