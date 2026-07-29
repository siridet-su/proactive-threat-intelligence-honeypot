# Typed-semantic transfer-family migration decision

Date: 2026-07-30

Starting revision:
`50de9c25d15f3a8ea642e41108b22d2caefa8240`

## Decision

Activate the `transfer` family as the next family-scoped policy input, but make
only a direct Cowrie `transfer_observed` fact eligible for specialized output.
The command-derived `remote_content_access`, `remote_content_pipe_source`, and
`transfer_attempt` operations remain ineligible and abstain.

The selected operation is valuable because the current guidance policy selects
`hunt-observed-transfer-indicators` from a T1105 candidate mapping. A probe at
the starting revision demonstrated that an ATT&CK-only `echo ready` observation
could therefore select the action with both indicator fields rendered as
`not observed`, while a standalone `cowrie.session.file_download` event selected
no transfer guidance. The typed layer already represents the important
boundary:

- a downloader command produces an attempted transfer operation even when
  Cowrie reports command success;
- a Cowrie file-transfer event produces `transfer_observed` with
  `event_observed` outcome and `direct_cowrie_event` proof;
- a valid `shasum` is a linkable artifact-hash entity;
- a shared resolved destination may create a
  `transfer_observation_confirmation` relationship, without making that
  relationship causal or proof of execution.

This migration replaces ATT&CK-only transfer authority with direct observed
event authority. It does not claim that a transfer affected a real host, that
an artifact executed, or that an attacker had a particular intent.

## Comparison of remaining families

| Family | Semantic clarity | Policy value | Relationship/outcome/path risk | Decision |
| --- | --- | --- | --- | --- |
| `transfer` | High only for `transfer_observed`; attempt operations are explicitly distinct | High: removes existing T1105-only guidance authority and grounds an existing direct-event finding | Direct event has categorical outcome and proof. A valid hash is required; unresolved entities abstain. Command-to-event relationships remain contextual. | **Selected**, direct-event slice only |
| `collection` | Moderate: one archive operation, but one operation currently mixes output and source refs | Moderate | Needs a reviewed input/output relationship contract and attempted-versus-observed collection semantics | Deferred |
| `context` | High for a successful, resolved `cd` | Low: no defensible specialized threat or response output | Subsequent path effects depend on cross-fragment CWD state | Deferred |
| `identity` | Low to moderate: current typed operation originates from a broad legacy literal action | High | Account creation, key-file mutation, failure, and Cowrie-versus-real-host effect are not yet separated | Deferred |
| `inspection` | Varies across nine operations | Low for specialized response | Broad family; most observations warrant no action | Deferred |
| `filesystem` | Varies across read/create/append/modify/delete/move | High | Role, path, transition, and effect distinctions are too broad for one activation | Deferred |
| `transformation` | Moderate | Moderate | Decode-only, decode-to-file, and decode-to-shell require relationship-aware evaluation | Deferred |
| `scheduled_task` | Varies across inspect/modify/delete | High | Read and deletion must not inherit persistence semantics from modification | Deferred |
| `service` | Varies across inspect/modify | Moderate | Cowrie-reported success cannot establish a real service change | Deferred |
| `execution` | Moderate for attempts | High | Highest overclaim risk; reported command success is not execution-effect proof | Deferred |
| `unknown` | Intentionally unknown | None | Permanently ineligible | Not eligible |

## Intended authority contract

A `transfer` match is eligible only when every condition below is true:

1. The complete `typed_semantic_fact_set.v2` validates against its exact
   hash-bound vocabulary.
2. The source fact is a `direct_cowrie_transfer_event`, parses without an
   abstention reason, and contains exactly one `transfer_observed` operation.
3. The outcome is `event_observed` at `direct_cowrie_event` scope; the operation
   effect is `event_observed` and its proof scope is
   `direct_cowrie_event`.
4. The operation references a linkable, non-uncertain `artifact_hashes` entity
   containing exactly 64 lowercase hexadecimal characters.
5. Every other entity in the same fact is linkable and non-uncertain. A
   relative path without observed/confirmed CWD, a wildcard, expansion, or
   otherwise unresolved identity makes the complete fact ineligible.
6. The source observation has a resolvable direct-Cowrie-event evidence
   reference. ATT&CK candidates are excluded from the supporting references.
7. Any relationship or chain retained by the fact set must pass whole-contract
   reference validation. A confirmation relationship may corroborate shared
   path identity, but its absence cannot convert a command attempt into an
   observed transfer and its presence cannot prove causality or execution.

Selection produces one match per eligible artifact hash. A direct event with
multiple otherwise valid hashes is not expected from the current Cowrie
contract and must abstain rather than multiply authority.

## Threat and guidance outputs

The threat evaluator and the guidance evaluator invoke the family selector
independently over the same immutable fact set.

An eligible match may produce:

- v4 behavioral finding type `observed_cowrie_transfer_event`, stating only
  that Cowrie recorded a transfer event for the exact artifact hash;
- v3 advisory action `hunt-observed-transfer-indicators`, asking a human to
  correlate the observed hash in authorized telemetry.

Both outputs bind the exact fact-set hash, vocabulary hash, family-selection
hash, direct evidence reference, operation, entity, outcome, proof scope,
limitations, and safety fields into their content-addressed identities.

The selected family emits no threat-hypothesis alternative. Transfer-related
follow-on hypotheses abstain while execution and cross-family relationship
semantics remain non-activated. This prevents a direct Cowrie transfer event
from becoming a prediction of later execution.

All guidance remains:

- `requires_manual_approval=true`;
- `safe_to_auto_execute=false`;
- without alerting or response side effects.

## Expected examples fixed before implementation

| Input | Typed result | Specialized v4 finding | Threat hypothesis | Specialized v3 guidance |
| --- | --- | --- | --- | --- |
| Direct `cowrie.session.file_download`, absolute destination, URL, valid SHA-256 | eligible `transfer_observed` | emitted for the hash | suppressed | manual hash-correlation review |
| `curl`/`wget` command only, including Cowrie-reported success and T1105 | `transfer_attempt`; abstain | none | none from transfer | none from transfer |
| Benign command with injected T1105 | no literal transfer observation; abstain | none | none | none |
| Direct event with relative destination and no observed CWD | unresolved fact; abstain | none | none | none |
| Direct event with wildcard/expansion-dependent destination | unresolved fact; abstain | none | none | none |
| Failed, malformed, wrapped, piped, or compound transfer command without a direct event | attempt/unknown/partial; abstain | none | none | none |
| Exact command attempt followed by a matching direct event | eligible direct event; optional supported confirmation relationship | emitted for direct event | suppressed | manual hash-correlation review |
| Direct event plus later execution-like command | direct event remains observed; execution family remains non-activated | transfer finding only | transfer follow-on abstains | transfer guidance remains limited to hash correlation |
| Prediction, enrichment, or injected hypothesis changes | no selector change | unchanged | unchanged | unchanged |

## Compatibility and rollback boundary

`sensitive_read` remains activated with unchanged selection semantics.
Historical pre-typed and one-family v4/v3 records remain read-only and
validatable without rewriting. Every other family remains non-activated.

The rollback boundary is this starting revision. Reverting the later
implementation commit restores one-family activation and the previous transfer
policy behavior; it does not alter historical records or production state.
