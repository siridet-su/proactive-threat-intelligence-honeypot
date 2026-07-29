# First typed-semantic policy family decision

Date: 2026-07-29

Starting revision:
`3f2de84b42178b215087b2fabd5059d5fd597d87`

## Decision

Activate only the `sensitive_read` operation family as an input to new
`session_assessment.v4` behavioral findings and `response_guidance.v3`
advisory guidance.

This is a family-scoped migration, not activation of the complete
`typed_semantic_fact_set.v2` contract. Every other operation family remains
on the existing contained evaluator or shadow-comparison path. Historical
records and readers are unchanged.

## Selection evidence

`sensitive_read` is the smallest family that exercises both target policy
boundaries:

- it contains one typed operation, `credential_path_read`;
- the current threat policy has one independent credential-path claim;
- the current guidance policy has one credential-path finding and one
  manual-only playbook;
- a defensible match is local to one command fact and one resolved path, so it
  does not depend on inferred chains, cross-event relationships, enrichment,
  predictions, correlations, or ATT&CK labels; and
- the only permitted effect is a bounded observation that Cowrie reported a
  parsed read command as successful. It is never proof that credentials were
  acquired, exposed, used, or affected on a real host.

`inspection` is operationally low risk but is not the smallest useful policy
migration. It contains nine operations and currently has no specialized
hypothesis or guidance rule. Activating it first would exercise plumbing
without testing the requested independent hypothesis/guidance authority
boundary.

## Required containment before activation

The starting extractor translates the canonical
`credential_path_access` literal action to `credential_path_read` without
checking the parsed operation. Independent probes demonstrated false read
facts for:

- `echo /etc/shadow`;
- `rm /etc/shadow`; and
- `chmod 600 /etc/shadow`.

Activation is blocked until `credential_path_read` is emitted only when a
general `file_read` operation references the same exact credential-path
entity.

A selected fact must also satisfy every one of these closed, hash-bound
requirements:

- the whole typed fact set validates;
- parsing completed with no abstention reason;
- both `file_read` and `credential_path_read` are present on the same entity;
- the entity is a linkable, non-uncertain `path` in the
  `credential_paths` role;
- the matching path identity is resolved from literal or confirmed context;
- the Cowrie outcome is `reported_success` for that fragment;
- both operation effects are `reported_completed`;
- all canonical evidence and policy references resolve; and
- the vocabulary, canonical evidence, behavior policy, classification policy,
  semantic input, and evaluator revision hashes verify.

Unknown, failed, compound, conditional, malformed, unsupported, ambiguous, or
unresolved facts abstain. Cowrie-reported success remains explicitly limited
to the simulated shell and does not establish a real-host effect.

## Independent consumers

The v4 and v3 evaluators receive the same immutable validated fact set but
evaluate eligibility separately. Guidance does not read a threat finding or
hypothesis as an action-selection input.

The threat path replaces only the legacy credential-pattern claim. Its
family-scoped result is an observed behavioral finding, not an attacker-intent
claim or a speculative hypothesis. The guidance path replaces only the two
credential action-type rules. Generic and all other non-migrated rules retain
their current contained behavior.

ATT&CK candidates can remain display context. They are neither required nor
accepted as proof of the literal read operation.

## Families not selected

| Family | Disposition and blocker |
| --- | --- |
| `unknown` | Permanently ineligible. |
| `inspection` | No specialized target output; nine operations need separate semantic review. |
| `filesystem` | Multiple read/write/append/modify/delete/move effects and path-transition relationships require narrower activation units. |
| `transformation` | Decode-only, decode-to-file, and decode-to-shell distinctions require relationship-aware policy evaluation. |
| `collection` | Archive input/output identities and the difference between attempted and observed collection require independent evaluation. |
| `scheduled_task` | Read, modify, and delete operations have materially different persistence semantics. |
| `service` | Inspect and modify operations must not be conflated; Cowrie success is not a real service change. |
| `context` | Conditional working-directory transitions and unresolved relative paths require cross-fragment evaluation. |
| `transfer` | Attempt versus direct Cowrie transfer observation and exact artifact relationships remain required blockers. |
| `execution` | Pipeline identity, failure/compound outcomes, and real-host-effect wording require separate review. |
| `identity` | Account modification is higher impact and needs entity/outcome-specific policy review. |

## Acceptance boundary

The family is acceptable for independent evaluation only if generalized
positive, negative, failure, malformed, ambiguous, contradiction, and unseen
command tests pass; the whole v4/v3 contracts and reference integrity pass;
shadow comparisons explain every changed credential output; all other family
outputs remain unchanged; the full feasible suite passes; and the worktree is
clean.
