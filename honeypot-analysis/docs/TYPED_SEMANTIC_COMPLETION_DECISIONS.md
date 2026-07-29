# Typed semantic completion decisions

This record was written before implementation changes, from commit
`ec5cfdc1fa5dcf870192958dd4d33cedf576d0b1`.

The retained 12-scenario evaluation generated 33 facts, including 24 unknown
operations, five relationships, and four chains. All current fact sets passed
the existing validator. Independent probes nevertheless reproduced these
readiness-review findings:

- recomputed hashes and IDs allowed invented operation, operation-class,
  resolution, and status values to validate;
- `sed -i` was represented as read-only;
- malformed quoting was promoted through whitespace-token fallback;
- output redirection had no write operation or path entity;
- `base64 -d` remained unknown in a decode-to-shell pipeline;
- an explicitly failed `cd` retained a conditional path candidate; and
- relationships copied the source graph instead of using typed path
  resolutions across the complete session.

These are contract and semantic defects, not reasons to grant the shadow layer
authority. The layer remains non-authoritative and discarded.

## Supplemental proposal decisions

### Document the supported shell-language subset

Decision: `ACCEPT`

Evidence: the current implementation uses `shlex` plus a compound-command
splitter, not a shell interpreter. Treating aliases, substitutions, expansions,
heredocs, process substitution, shell functions, or malformed syntax as though
they were fully evaluated would create unsupported effects. The supported
subset will be explicit, and syntax outside it will abstain.

### Store vocabulary in a separate immutable, hash-bound policy

Decision: `ACCEPT`

Evidence: operation strings and proof semantics are currently embedded in
Python and are only partially validated. A reviewed JSON policy provides one
closed vocabulary, extractor version, relationship rules, and bounded resource
limits. The exact file bytes will be SHA-256 bound into every fact set. Missing
or invalid policy will make shadow evaluation unavailable; it will never fall
back to a different policy.

The policy remains semantic configuration for a shadow evaluator. It does not
become a hypothesis, guidance, alert, or response policy.

### Use categorical proof scopes instead of numeric confidence

Decision: `ACCEPT`

Evidence: the available evidence distinguishes literal syntax, direct Cowrie
events, fragment outcomes, compound outcomes, conditional candidates, and
unresolved identity. No calibrated data supports a numeric probability.
Closed categorical proof scopes preserve those distinctions without implying
statistical confidence.

### Produce readable shadow-diff reports

Decision: `MODIFY`

Evidence: readable comparisons are needed to review blocked matches and
abstentions, but persisting or exposing them through production consumers would
change the v4/v3 contract. The implementation will provide deterministic,
direct-caller diagnostic data and a human-readable renderer. The v4 invocation
will continue to discard all shadow results.

The report may show source literal action types, typed operations, relationship
changes, blocked candidate matches, abstention reasons, and hypothetical policy
impact. It must not execute either policy or claim that hypothetical impact is
an authoritative result.

### Add property-based or bounded fuzz testing

Decision: `MODIFY`

Evidence: whitespace, quoting, option ordering, redirection, and shell-operator
combinations are high-risk parser boundaries. Adding an unpinned property-test
dependency is unnecessary for this repository. Tests will use deterministic,
bounded combinations with fixed seeds and explicit invariants. Malformed or
unsupported forms must remain unknown.

### Prepare later activation by operation family

Decision: `ACCEPT`

Evidence: inspection, filesystem mutation, transformation, transfer, execution,
and context operations have different semantic and operational risks. The
vocabulary will identify stable operation families so a later, separately
approved migration can activate only independently validated families.
Activation metadata grants no authority in this work.

### Define resource and incomplete-session limits

Decision: `ACCEPT`

Evidence: the current builder has no fact, relationship, entity, command-length,
or aggregate-input bounds. Deterministic limits protect a SQLite-backed
controlled PoC from pathological sessions and relationship growth. Exceeding a
limit will make the shadow evaluation unavailable and will not affect v4/v3.
Empty or incomplete sessions remain valid observation-only inputs with no
invented facts.

## Implementation boundary

The implementation may:

- replace the shadow fact schema because no fact set is persisted or consumed;
- add a mandatory, immutable semantic-vocabulary policy;
- add general, argument-aware extraction for provable syntax;
- rebuild typed relationships separately from the authoritative source graph;
- add diagnostic rendering and tests; and
- pass canonical evidence and exact provenance into the discarded shadow call.

It must not:

- change canonical evidence, current findings, hypotheses, guidance, IDs,
  persistence, APIs, reports, artifacts, alerts, or response authority;
- treat ATT&CK candidates as literal operations;
- interpret unsupported shell language;
- promote missing operands or targets; or
- begin hypothesis or response-guidance migration.

## Readiness-review dispositions verified during implementation

The 24 reviewed unknowns were re-evaluated by semantic family, not by matching
the exact fixture strings. The complete forms below are supported by general
argument-aware extractors:

| Reviewed form | Disposition | Typed operation or facets |
|---|---|---|
| `uptime` | `ADD_GENERAL_EXTRACTOR` | host uptime inspection |
| `df -h /var` | `ADD_GENERAL_EXTRACTOR` | filesystem-capacity inspection |
| `uname -a` | `ADD_GENERAL_EXTRACTOR` | system-identity inspection |
| `id` | `ADD_GENERAL_EXTRACTOR` | account-identity inspection |
| `ip route show` | `ADD_GENERAL_EXTRACTOR` | network-route inspection |
| `ps aux` | `ADD_GENERAL_EXTRACTOR` | process inspection |
| `ss -tulpn` | `ADD_GENERAL_EXTRACTOR` | network-socket inspection |
| `getent passwd` | `ADD_GENERAL_EXTRACTOR` | account-database inspection |
| `find /tmp -type f` | `ADD_GENERAL_EXTRACTOR` | filesystem search |
| `cat /etc/passwd` | `ADD_GENERAL_EXTRACTOR` | file and credential-path read |
| `sed -i s/a/b/ ./target` | `ADD_GENERAL_EXTRACTOR` | file read and in-place modify |
| `echo value > ./target` | `ADD_GENERAL_EXTRACTOR` | literal emission and overwrite |
| `echo value >> ./target` | `ADD_GENERAL_EXTRACTOR` | literal emission and append |
| `base64 --decode /tmp/blob` | `ADD_GENERAL_EXTRACTOR` | decode transform |
| `tar -czf /tmp/logs.tgz /var/log` | `ADD_GENERAL_EXTRACTOR` | file read and archive create |
| `crontab -l` | `ADD_GENERAL_EXTRACTOR` | schedule inspection |
| `crontab -r` | `ADD_GENERAL_EXTRACTOR` | schedule deletion |
| `crontab /tmp/jobs` | `ADD_GENERAL_EXTRACTOR` | schedule modification |
| `systemctl status sshd` | `ADD_GENERAL_EXTRACTOR` | service inspection |
| `systemctl restart sshd` | `ADD_GENERAL_EXTRACTOR` | service modification |
| `rm -f /tmp/item` | `ADD_GENERAL_EXTRACTOR` | file deletion |
| `chmod 700 /tmp/item` | `ADD_GENERAL_EXTRACTOR` | permission modification |
| `chmod 700` | `KEEP_UNKNOWN` | target is missing |
| `rm` | `KEEP_UNKNOWN` | target is missing |

The readiness findings were also reproduced and corrected generically:
`sed -i` no longer treats its program as a path, malformed quoting cannot use a
whitespace fallback, redirection creates distinct write or append facets,
decode-to-file and decode-to-shell retain all facets, failed `cd` cannot update
effective context, and relationships are rebuilt from typed facts over the
complete session.

No implementation special-cases the reviewed literal command strings.
