# Cowrie inspection-family evaluation

Date: 2026-07-30

Starting revision:
`4dc0f08da2395b07998d79683266814734ca578c`

This record covers only the observation-only `inspection` family selected in
`docs/TYPED_SEMANTIC_COVERAGE_ROADMAP.md`. The already activated
`sensitive_read` and direct Cowrie `transfer` families remain active. Every
other operation family remains contained or shadow-only.

## Decision and implementation commits

| Commit | Purpose |
| --- | --- |
| `02a96243733381015795e018f57e2cd8ff3d62cd` | Evidence-based coverage matrix, selected contract, and pre-execution evaluation freeze |
| `92900870d036fb34157043fd129571a8c3c0f430` | Observation-only inspection selection, v4/v3 findings, policy provenance, historical compatibility, and focused tests |
| `4111168a025682398e580cc5e5af4dc016e71f58` | Separately authored post-implementation holdout freeze |
| `23592e26c94cb4864fbc73bf7fa0f5b916436abe` | General parser corrections exposed by the frozen holdout and complete replay tests |

## Frozen evidence

| Artifact | SHA-256 | Cases | Freeze point |
| --- | --- | ---: | --- |
| `evaluation/inspection_family_independent_frozen.v1.json` | `ef6254418ba8971eb591f424e9cbd9dd1a123b90692d65bd9da1b8424dcf9cf9` | 45 | Commit `02a96243733381015795e018f57e2cd8ff3d62cd`, before activation and first execution |
| `evaluation/inspection_family_holdout_frozen.v1.json` | `f14acf430b8449d985895d59fd494a2ad1f8deac4380f6bce67fae24592518ec` | 34 | Commit `4111168a025682398e580cc5e5af4dc016e71f58`, after implementation tests and before first holdout execution |

Neither file’s expected labels or cases changed after execution.

The holdout’s ancillary `implementation_revision_before_authoring` value
contains a transcription error (`929008797...`). The actual commit is
`92900870d036fb34157043fd129571a8c3c0f430`. The frozen file was not rewritten.
The correction is recorded in
`evaluation/inspection_family_holdout_provenance_correction.v1.json`, SHA-256
`8c98c07686f70bf394e12399d43efdbdef5060d9664ec2e3b9eb114000ac001f`.
The receipt binds the original holdout hash and states that cases, expected
labels, and measured results are unchanged.

## Result definitions

- **Typed operation** is a case-level classification of whether one or more
  reviewed inspection operations should be present. A failed or unknown
  outcome can retain the literal operation while remaining ineligible.
- **Eligible family** means the strict selector matched. It requires exactly
  one inspection operation, a parsed successful fragment, no abstention or
  extra operation, and complete referenced identity resolution.
- **Specialized finding** is the v4
  `observed_cowrie_inspection_command` behavioral finding.
- **Guidance** in the metrics is the corresponding v3
  `observed-cowrie-inspection-command` evidence finding. Inspection has no
  specialized action, so an action-level positive class would be empty and
  action precision/recall would be undefined rather than `1.0`.

## Results

| Measure | Independent set | Holdout | Combined |
| --- | ---: | ---: | ---: |
| Typed-operation TP / FP / FN / TN | 27 / 0 / 0 / 18 | 19 / 0 / 0 / 15 | 46 / 0 / 0 / 33 |
| Typed-operation precision / recall / F1 | 1.000 / 1.000 / 1.000 | 1.000 / 1.000 / 1.000 | 1.000 / 1.000 / 1.000 |
| Eligible-family TP / FP / FN / TN | 19 / 0 / 0 / 26 | 15 / 0 / 0 / 19 | 34 / 0 / 0 / 45 |
| Eligible-family precision / recall / F1 | 1.000 / 1.000 / 1.000 | 1.000 / 1.000 / 1.000 | 1.000 / 1.000 / 1.000 |
| Specialized-finding precision / recall / F1 | 1.000 / 1.000 / 1.000 | 1.000 / 1.000 / 1.000 | 1.000 / 1.000 / 1.000 |
| v3 guidance-finding precision / recall / F1 | 1.000 / 1.000 / 1.000 | 1.000 / 1.000 / 1.000 | 1.000 / 1.000 / 1.000 |
| Unsupported specialized outputs | 0 | 0 | 0 |
| Inspection-specific actions emitted | 0 | 0 | 0 |
| Emitted inspection hypotheses | 0 | 0 | 0 |
| Contradicted or unfalsifiable hypotheses | 0 | 0 | 0 |
| Reference and integrity validation | 45/45 | 34/34 | 79/79 |
| Deterministic repeated semantic results | 45/45 | 34/34 | 79/79 |
| SQLite and artifact validation | 45/45 | 34/34 | 79/79 |

The unsupported-output rate, contradicted-hypothesis rate, unsafe-action rate,
prediction-only authority rate, enrichment-only authority rate, and
ATT&CK-only authority rate were all `0/79`.

Every action that remained in a report was either the pre-existing generic
observed-command corroboration action or an independently selected
`sensitive_read`/direct-transfer action. Every one required manual approval,
set `safe_to_auto_execute=false`, had no execution integration, and produced
no alert or response side effect.

The artifact run validated SQLite report persistence, canonical JSON,
Markdown, STIX, and each integrity manifest for all 79 cases. ReportLab was
not installed, so the configured deterministic `pdf_fallback_markdown` path
ran instead of native PDF rendering. The combined evaluation took 9.08
seconds with 51,096 KiB maximum resident memory on the local test host,
including 79 persistence cycles and 79 artifact sets.

## Holdout discrepancies and general corrections

The first holdout execution found eight failing cases from five general root
causes. Expected labels were not changed.

1. Absolute paths to reviewed inspection utilities inherited the legacy
   generic `execution_attempt` facet. A reviewed `uname`, `hostname`, or
   `ip route` query now retains its exact inspection operation without the
   redundant artifact-execution facet. Unreviewed absolute executables still
   retain execution-attempt semantics.
2. `id USER` discarded the queried account. The supported one-account form
   now binds the exact account entity; multiple operands abstain.
3. `uname` and `hostname` accepted arbitrary options, including help or setter
   forms. Both now have closed reviewed read-only option subsets.
4. `whoami` accepted an extra operand. Any operand now abstains.
5. `find` file-output predicates (`-fprint`, `-fprint0`, `-fprintf`, and
   `-fls`) were treated as pure search. They now abstain alongside delete and
   execution predicates.

These changes apply by syntax family, not by frozen command string. Nearby
unseen variants are covered in the focused tests. Malformed, unsupported,
incomplete, expansion-dependent, wildcard, compound, failed, unknown, and
multi-operation cases remain unknown or abstain.

## Representative actual outputs

### Successful system inspection

Input: Cowrie `command.success` for `uname -srv`.

- Typed operation: `system_identity_inspection`,
  `reported_completed`, fragment scope, with
  `general_command_semantics` proof.
- Selector: one match, citing the exact command-action observation and its
  direct Cowrie event reference.
- v4: emitted `observed_cowrie_inspection_command`.
- Threat hypothesis: suppressed; none emitted.
- v3: emitted the bounded inspection evidence finding.
- Inspection-specific action: none. The existing generic manual
  `review-observed-source-in-real-auth-logs` action remained grounded in the
  observed command.
- Limitations deny malicious reconnaissance or attacker intent, command result
  contents, compromise, and real-host effect.

### Failed inspection

Input: Cowrie `command.failed` for `uptime -p`.

- Typed operation: `host_uptime_inspection` with `reported_failed`.
- Selector: abstained with `outcome_not_eligible` and
  `effect_status_not_eligible`.
- v4 inspection finding, v3 inspection finding, inspection hypothesis, and
  inspection action: all suppressed.
- The generic manual observed-command action remained; it does not claim the
  inspection succeeded.

### Unresolved path

Input: Cowrie `command.success` for `find evidence -type f`, with no observed
or confirmed CWD.

- Typed operation: `filesystem_search`; target retained as
  `relative:evidence`.
- Selector: abstained because the referenced path identity was unresolved.
- No inspection finding, hypothesis, or specialized guidance was emitted.

### File-writing `find` predicate

Input: Cowrie `command.success` for
`find /var -fprint /tmp/search-results`.

- Typed operation: `unknown` with an unsupported-option abstention.
- Selector and all specialized outputs: abstained/suppressed.
- The output path is not misrepresented as read-only search.

### Three activated families in one session

Input: successful `id -Gn`, successful
`head -n 2 /etc/shadow`, and a direct
`cowrie.session.file_upload` with an exact SHA-256.

- Typed operations: `account_identity_inspection`, `file_read`,
  `credential_path_read`, and `transfer_observed`.
- Each family selected independently from the same immutable fact set.
- v4 emitted the three bounded behavioral findings.
- v3 emitted the inspection evidence finding plus the existing manually
  approved credential-review and exact-hash correlation actions.
- No inspection action and no hypothesis were emitted.
- No family derived authority from another finding, hypothesis, ATT&CK label,
  prediction, enrichment value, or prose field.

## Old-versus-new behavior

At `4dc0f08...`, inspection operations were shadow-only. An eligible command
could produce the generic observed-command finding and manual corroboration
action, but no typed inspection finding. The new behavior adds only:

- a v4 bounded Cowrie inspection observation;
- a v3 bounded inspection evidence finding; and
- content-addressed inspection selection hashes and policy traces.

It adds no inspection action or hypothesis. The existing generic finding and
manual action remain unchanged. Non-eligible cases add no authoritative
output. Policy and activation hashes necessarily change, so new assessment
and guidance identities differ deterministically from the old two-family
record; historical records are not recomputed.

The five parser corrections above also improve the shadow fact representation
for those exact grammar classes. They do not activate execution, filesystem
mutation, or any other family.

## Policy integrity and tests

- Typed semantic vocabulary SHA-256:
  `ee141671ac207c4e69a09dd0c96c1fadf21a06e150c82e1bcb067181a060e3e0`
- Behavior policy SHA-256:
  `b2a5423ac98ec11c6bdb950d6dfd25f539076afa766a2444ebf586ccda7b775d`
- Response-guidance policy SHA-256:
  `10da305149653fb0f05f1fa038bab63cb356e9da0b2bc12f4f3adc04848aa84f`

All three policy validators passed. Focused activation and combined-family
tests passed `195 passed`. The final complete local suite passed
`931 passed, 7 skipped`.

## Remaining families and blockers

| Family | Status | Primary blocker |
| --- | --- | --- |
| General filesystem read/mutation | Shadow-only | Separate read/write/append/delete effect wording and multi-target/path evaluation |
| Transformation/decode | Shadow-only | Decode-only, decode-to-file, and decode-to-shell relationships must remain distinct |
| Execution | Shadow-only | Exact script/consumer identity and attempt/outcome language carry higher overclaim risk |
| Scheduled task | Shadow-only | Inspection has low incremental value; modification needs target/content and persistence-safe wording |
| Service | Shadow-only | Separate read-versus-modify grammar and weak incremental PoC value |
| Collection/archive | Shadow-only | Source/output relationships and completion semantics require independent evaluation |
| Transfer attempts | Shadow-only | Only direct Cowrie events currently prove an observed transfer |
| Cross-family chains | Shadow-only | Every participating family and exact relationship identity must pass independently first |
| Context (`cd`) | Context-only | Useful for resolution, not an independent report claim |
| Broad identity modification | Not activated | Current operation must be split before it can safely represent account/key changes |

## Readiness and limitations

The observation-only inspection family is **ready to retain for independent
evaluation and controlled-PoC demonstration**. Together with resolved
sensitive reads and direct Cowrie transfer events, it gives the project three
semantically distinct, evidence-bounded demonstrations without activating a
high-risk execution or persistence claim.

This conclusion is limited to the reviewed shell subset and the 79
developer-authored frozen cases. The large privacy-minimized corpus has no raw
commands, so it cannot independently validate literal operation prevalence or
accuracy. The retained 14-command demo is small. No external expert
adjudication, native-PDF dependency run, production load, GCP/Pi deployment,
or long-term telemetry observation was performed. Unknown count is not a
failure metric; unseen or ambiguous commands should continue to abstain.

Rollback boundaries are the starting revision `4dc0f08...`, the decision and
freeze commit `02a9624...`, the activation commit `9290087...`, and the
holdout-correction commit `23592e2...`. Reverting the activation and correction
commits restores the two-family runtime without changing historical records.
No production service, database, GCP host, or Raspberry Pi was accessed or
modified.
