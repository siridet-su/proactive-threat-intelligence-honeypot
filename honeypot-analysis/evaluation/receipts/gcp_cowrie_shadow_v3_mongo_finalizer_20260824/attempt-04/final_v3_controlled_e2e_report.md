# Final V3 / MongoDB controlled E2E finalizer

Date: 2026-08-24 (Asia/Bangkok)  
Status: COMPLETE_VALID / DEPLOYED / ONE POST-REPAIR CONTROLLED E2E VERIFIED  
Namespace: evaluation/receipts/gcp_cowrie_shadow_v3_mongo_finalizer_20260824/attempt-04/

## Executive result

The active deployment is the new immutable candidate 403c989d9cfe7e7726610018345352e76bfd5d7f. It is the reviewed a5 V3/Mongo candidate plus one narrow compatibility repair in the controlled-provenance wrapper. The complete path passed:

approved Pi Cowrie :22 -> new production_live canonical Mongo session -> terminal V3 trusted-history manifest and cutoff -> active read-only Mongo/V3 feeder -> localhost non-authoritative predictor -> exactly one isolated shadow record.

The first session in this finalizer window exposed the blocker and is preserved as evidence; it was not replayed or backfilled. After the immutable repair and guarded activation, exactly one additional benign authenticated session was sent. That post-repair session produced the one validated shadow prediction. No further Cowrie traffic was sent.

## Deployment identity and baseline

| Binding | Value |
|---|---|
| Active release | 403c989d9cfe7e7726610018345352e76bfd5d7f |
| Release SHA-256 | 403c989d9cfe7e7726610018345352e76bfd5d7fc75cc3952d3217a00e0c6669 |
| Immutable tree SHA-1 | 71428a1735a9802f878931153d242cd1d2cf23ee |
| Release manifest SHA-256 | 7a43ed039db5521c357c681dba5ca3e640b6c35dc544d669f77bc3481a3399ec |
| Storage epoch | mongodb-m0-canonical-retry-20260813-49f9b74 |
| Active epoch file SHA-256 | f155419ffbd43f6910223f0c9a3cd347d0385d475771d37e79174b51b60ad017 |
| Active epoch receipt | 7e3e415dd0de85a2645b16b8c2789cceb8859e65946f5ade1cc292ccbdc697c5 |
| Classifier source identity | 9493daa3ccc10ac8fbd17f3596bc9a0c5811a81d22beadee9ffa9c73053f3a93 |
| Checkpoint | 16506e962432f9921d18a514c3a31686a20f9734385ec49439ad2651e4cdd283 |
| Temperature | 0.6990670591704266 |
| Authority | non_authoritative |
| Canonical writes | false |

Worker, Mongo/V3 feeder, and predictor were active/running with status 0.
Predictor health was READY with 2,599 parameters, max history 8, the frozen
label binding, and the frozen runtime binding.

## Repaired blocker

The a5 session worker had the V3 terminal-persistence repair, but the
controlled-provenance wrapper still monkey-patched SessionWorker._on_session_end
with the old signature (self, state). The V3 worker calls it with
evidence_cutoff=.... The first fresh session therefore dead-lettered only its
close event as event_processing_invalid/ValidationError; its canonical row
remains historical evidence and was not replayed.

The new candidate changes only production/controlled_provenance_runtime.py:

- before hash: c8771d3a4cefa990629402d4096ca2ec8834328752694a2b9a2af11b7dbaaaf5
- after hash: a88eff72b3f46431622b03e307bc084fcd6707a90074fc344bc12eeacaf2ad48
- patched_close(self, state, evidence_cutoff=None)
- both calls to the original close method forward the keyword

The session-worker V3 source remains
ef9e1c281fd88380a8c91d68129affab5f10b5c9ba42b288c10bb248276b7665. Controlled
session exclusion remains intact. No model, policy, classifier identity,
lifecycle semantics, or storage lineage changed.

## Controlled session

The approved operator source was fedora (identity hash
7386530c730433e396f54a469ef60677ec4df2bfc3fc0359502def0e74f07a9d). The
verified target was the Pi Cowrie listener on TCP/22. Management TCP/2222 and
relay TCP/2224 were not used.

The successful post-repair session was authenticated and production_live. Its
privacy-safe session-ID hash is
76c113a3e3cd47fe2ab5053ec0d218f8a75ec69e6d413c832e0110a967b9d295. It
persisted 16 events, all processed successfully; cowrie.session.closed was
processed with outcome succeeded; it ended at revision 19; and it has no
dead-letter events. Harmless commands were id, uname -a, pwd, whoami, echo
controlled-e2e-finalizer, date -u, and exit. Raw command text is absent from
this evidence namespace.

The terminal cutoff was received at 2026-08-24T14:48:42.596035+00:00 and the
canonical terminal row was updated at 2026-08-24T14:48:56.137896+00:00.

## V3 manifest

The canonical payload contains schema prediction_trusted_history_manifest.v3
and target contract next_distinct_trusted_behavior_phase_or_session_end.v2.
It contains one ordered trusted discovery phase, four trusted labels, three
audit-only labels, and these hashes:

- history manifest: 9609d89a44e2052a04aeac61c7058a46ef68b7c059a181233bd3a66e0826d809
- ordered phases: a1f1e123b54db68957c953df241b59259af4af79eacf9104f547407742221302
- phase: 7513b66b3367ec431674faaff23650c9cee2a336489e22012d49f19186085908
- cutoff event ID: e6a376af6963151b2a873ab8fa8017fe3927ae4a24877e22161a7d854ebbf66f

The cutoff schema is prediction_evidence_cutoff.v1, selected/original distinct
phase count is 1, and truncated/upstream_truncated are both false.

## Feeder and predictor

The active feeder source hash is
d179a253e6ef8877845649b16f517d3e10fa705ffedd0332f7399cefbe71d448; config
hash is 2af49f6b1a967515de9e8b8e6c826fbff956a9e97409c540ddd2dad62caec1ef;
unit hash is f4b89e130ff3cab2dcb63dcedd3e81a2b713fe81088008089c096b933268932e.
It reads Mongo honeypot_canonical_v1, accepts production_live plus valid V3
manifests, and has no Mongo insert/update/replace/delete method.

The seeded activation watermark was revision 15 at
2026-08-24T14:22:19.523502+00:00, session hash
4aa3a7c3db77b583b4a69d6c6dd10e32b19c6eb8023437f6610072ba026f41cd. It was
seeded once, so the failed session and all earlier rows were not replayed.

Final feeder metrics were rows_seen=7, rows_eligible=1, rejected_rows=5,
duplicate_rows=1, predictions_emitted=1, predictor_failures=0,
transient_cursor_holds=0. One privacy-safe record remained in the isolated
shadow root. Its file hash is
f1da1548b30ec35ea14cbc5a3d3bfa5aa54451dbc7d4c71c4f6635bc1b4ad99; its
session hash is 76c113a3e3cd47fe2ab5053ec0d218f8a75ec69e6d413c832e0110a967b9d295;
revision is 18; progression index is 1; and history length is 1. No raw
commands are stored.

The feeder called http://127.0.0.1:18082/predict successfully. The predictor
used checkpoint 16506e...d283 and temperature 0.6990670591704266, returned
authority non_authoritative and canonical_write_allowed=false, and returned
Top-1 credential-access and Top-3 credential-access, command-and-control,
execution. The normalized seven-class vector is persisted only by hash
d062e4f25bdee9c6938a9f090ea70dda028e4e03b761c9a4ff7273b1a7d77e80.

A later read-only poll left metrics and record hash unchanged: one record
remained and no second prediction was emitted. Duplicate suppression passed.

## Before/after canonical state

| Collection/role | Before | After | Delta |
|---|---:|---:|---:|
| sessions | 76 | 77 | +1 |
| events | 1,121 | 1,137 | +16 |
| prediction snapshots | 686 | 696 | +10 |
| prediction outbox | 686 | 696 | +10 |
| analysis jobs | 68 | 69 | +1 |
| reports | 67 | 67 | 0 |
| alerts | 0 | 0 | 0 |
| lifecycle ledger | 1 | 1 | 0 |
| production_live sessions | 71 | 72 | +1 |
| e2e_test sessions | 5 | 5 | 0 |

These are exactly the expected worker effects of one new authenticated session.
The feeder made no Mongo writes. The failed session hash 4aa3...41cd remained
unended and was not replayed or backfilled. No controlled/e2e row was promoted.

## Required answers

1. Candidate required: wrapper signature drift was exposed; active release in-place modification was prohibited.
2. Exact source change: controlled_provenance_runtime.py patched_close now forwards evidence_cutoff.
3. Prior a5/ebe69 work overwritten: no.
4. Active release: 403c989d9cfe7e7726610018345352e76bfd5d7f.
5. Classifier identity changed: no, 9493daa3....
6. Storage lineage changed: no.
7. New empty mirror: no.
8. Local preactivation: compile, lifecycle, V3 environment, classifier, monitor, and zero-event probes passed.
9. Worker stable: yes, active/running/status 0.
10. Mongo healthy: yes.
11. Lifecycle idempotency: passed under canonical_storage_epoch.v2.
12. Terminal V3 manifest persisted: yes.
13. Evidence cutoff persisted: yes.
14. Manifestless row eligibility: rejected closed; five intermediate rows were rejected.
15. Feeder race validation: passed.
16. Fresh watermark: yes.
17. Old rows replayed: no.
18. New sessions: two total bounded sessions in this finalizer activity; one pre-repair diagnostic failure and one post-repair successful session. Only the latter supports the final claim.
19. Successful session reached Mongo: yes.
20. Trusted tactic history: yes, one discovery phase and four trusted labels.
21. V3 manifest/cutoff: yes.
22. Feeder accepted it: exactly one eligible row.
23. Predictor called: one successful call.
24. Model: frozen 2,599-parameter checkpoint 16506...d283.
25. Temperature: 0.6990670591704266.
26. Exactly one shadow result: yes.
27. Duplicate suppression: yes; duplicate counter 1, emitted count remained 1.
28. Feeder canonical mutation: no.
29. Historical sessions unchanged: yes.
30. Controlled/e2e source promoted: no.
31. Production non-interference: passed with expected one-session delta.
32. Guard bypass: none.
33. Retrain/refit: none.
34. Firewall/public endpoint: unchanged; predictor remained localhost-only.
35. Further model work: no.

## Preservation accounting

PRIOR REVIEWED RELEASES MODIFIED IN PLACE = FALSE
FAILED LIVE TEST SESSION BACKFILLED = FALSE
FAILED LIVE TEST SESSION REPLAYED = FALSE
HISTORICAL MONGO ROWS DELETED = FALSE
HISTORICAL MONGO ROWS REWRITTEN = FALSE
STORAGE LINEAGE RESET = FALSE
ROLLBACK MIRROR DESTRUCTIVELY REWRITTEN = FALSE
LIFECYCLE POLICY MUTATED = FALSE
SOURCE IDENTITY GUARD BYPASSED = FALSE
STORAGE GUARD BYPASSED = FALSE
MIRROR GUARD BYPASSED = FALSE
CONTROLLED/E2E HISTORICAL SOURCE PROMOTED = FALSE
MODEL RETRAINED = FALSE
TEMPERATURE REFIT = FALSE
CHECKPOINT CHANGED = FALSE
FIREWALL MODIFIED = FALSE
PUBLIC PREDICTOR ENDPOINT CREATED = FALSE

All prior V1/V2, model-comparison, refinement, padding, deployment, promotion,
controlled-traversal, and finalizer artifacts remain available. New a6 release,
receipts, feeder evidence, session evidence, and hash manifest are confined
to attempt-04. No existing receipt was overwritten.

## Final verdict

FINAL CONTROLLED E2E VALIDATION COMPLETE —
COWRIE → CANONICAL MONGO → V3 SESSION MANIFEST →
MONGO LIVE SHADOW FEEDER → PREDICTOR VERIFIED /
EXACTLY ONE SHADOW PREDICTION VERIFIED /
HISTORICAL REPLAY ZERO /
CANONICAL NON-INTERFERENCE VERIFIED

