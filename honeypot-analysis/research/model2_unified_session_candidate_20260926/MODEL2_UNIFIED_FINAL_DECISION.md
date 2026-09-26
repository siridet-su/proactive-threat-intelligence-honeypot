# Unified Model2 — corrected T1105 semantics and controlled PoC decision

> เอกสารนี้เป็นผล V2 เดิม ผล retrain T1110 hard-negative และการเปรียบเทียบ ensemble 5 วิธีล่าสุดอยู่ที่ `../model2_formula_comparison_20260927/FIVE_METHOD_COMPARISON_REPORT_TH.md` ห้ามนำตัวเลข V2 ด้านล่างไปอ้างว่าเป็น candidate ปัจจุบัน

**Run date:** 26 Sep 2026  
**Decision:** `CONTROLLED_SYNTHETIC_POC_RETRAINED; T1105_GATE_BLOCKED`  
**Scope:** isolated research candidate only. No production deployment or change to the frozen 32F baseline.

## Decision in brief

The old `benign-large` label was inconsistent with this honeypot's threat model: it used a valid retrieval command and an episode-bound network flow but was labeled T1105-negative only because its content was benign. The corrected target is `SESSION_BOUND_TRANSFER_ACTIVITY`; content benignness/maliciousness and transfer completion are separate dimensions. Every matched basic/benign-content pair now has identical features and the same positive label.

The unified 54-feature model was retrained as one artifact with three OVR logistic heads (T1105/T1046/T1110). There is no T1105-only model. The corrected corpus has zero conflicting exact-feature/different-label collisions. However, the final synthetic T1105 negative slice still has 4 false positives in 64 negatives. Therefore both the controlled-research T1105 gate and production/RRF T1105 gate remain `BLOCK`.

> Within this honeypot threat model, a valid session-bound file retrieval remains T1105 transfer behavior regardless of whether the retrieved content is benign or malicious. Content maliciousness and transfer completion are separate evidence dimensions.

This run reports controlled-generator separability only. It does not estimate field accuracy, establish deployment readiness, or prove non-regression against Model1 or the frozen 32F baseline.

## Semantics and evidence boundaries

The output target is session-level support for transfer activity, not malware detection, attacker intent, successful download, file persistence, compromise, or a trusted ATT&CK finding.

1. `TRANSFER_COMMAND_ATTEMPT`: valid supported transfer client + target is observed in Cowrie command input.
2. `SESSION_BOUND_TRANSFER_ACTIVITY`: the controlled case also has complete network evidence bound to the exact same session/run/measurement/episode. This is the T1105 label target in this PoC.
3. `ARTIFACT_RECEIVED_OR_VERIFIED`: outcome/receiver evidence is label-side only and is not a feature.
4. `POST_TRANSFER_ACTIVITY`: later execution/permission/archive/cleanup remains separate sequence evidence.
5. `MALICIOUS_ARTIFACT`: requires separate artifact analysis; the T1105 head does not classify maliciousness.

The synthetic episode envelope contains only exact-episode Zeek `conn.log`-style flows. No Zeek `http.log`, HTTP status, response body length, headers, cookie, or payload is used. A complete episode with no bound flow is a negative control for this session-bound target; a missing, partial, or misbound source is `UNAVAILABLE`, never a negative row. An unrelated/background large HTTP flow is not inserted into the Cowrie episode.

## Corpus, training, and evaluation protocol

| Item | Result |
|---|---:|
| Dataset type | `CONTROLLED_SYNTHETIC_POC` |
| Rows / procedure families | 324 / 81 |
| FIT / SELECTION / SEALED_FINAL | 108 / 108 / 108 rows; 27 families per split |
| T1105 positives / negatives | 132 / 192 |
| Non-transfer T1105 controls | 192 total; 128 FIT+SELECTION and 64 SEALED_FINAL |
| Benign-content transfer positives | 12 total; 8 FIT+SELECTION and 4 SEALED_FINAL |
| Human adjudication | No; labels are scenario-defined before fit, not model-generated |

Whole procedure-family IDs remain in one split; repetitions are deterministic. Standardization and weights use FIT only; thresholds use SELECTION only. The candidate modes and their hashes are frozen before the final scoring run. Important limitation: this synthetic dataset stores all split labels in the same generated corpus JSON; `SEALED_FINAL` is a held-out partition in the deterministic evaluation procedure, **not** a separately escrowed blind human holdout. There are no real-session or paired-baseline rows.

The fitted object is a single standardized OVR logistic artifact with shared 54-feature input/standardizer and three output heads. Its sigmoid outputs are `SIGMOID_DECISION_SCORE_NOT_CALIBRATED_PROBABILITY`; they must not be presented as calibrated probability or confidence.

### Final controlled results

All rows below are from the same 108-row synthetic SEALED_FINAL partition. TP/FP/TN/FN are reported in that order.

| Head | Support (+ / -) | TP / FP / TN / FN | Precision | Recall | F1 | Specificity | FPR | FNR | Balanced accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| T1105 | 44 / 64 | 44 / 4 / 60 / 0 | 0.9167 | 1.0000 | 0.9565 | 0.9375 | 0.0625 | 0.0000 | 0.9688 |
| T1046 | 16 / 92 | 16 / 0 / 92 / 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 |
| T1110 | 16 / 92 | 16 / 0 / 92 / 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 |

The perfect T1046/T1110 scores reflect simple, intentionally separated synthetic controls. They are not evidence of real traffic accuracy or baseline non-regression.

### T1105 slices (full 54F candidate)

| Slice | Support (+ / -) | TP / FP / TN / FN | Interpretation |
|---|---:|---:|---|
| Basic transfer | 4 / 0 | 4 / 0 / 0 / 0 | All four synthetic positives predicted present. No negative support in this slice. |
| Benign-content transfer | 4 / 0 | 4 / 0 / 0 / 0 | Same feature vectors and T1105 labels as matched basic transfer. |
| Transfer then execute | 8 / 0 | 8 / 0 / 0 / 0 | Sequence/outcome wording is not proof execution succeeded. |
| Mixed TTP | 12 / 4 | 12 / 0 / 4 / 0 | Four mixed discovery+auth controls are T1105-negative. |
| Malformed/help/embedded/quoted text | 0 / 20 | 0 / 0 / 20 / 0 | No false positives in these 20 synthetic negatives. |
| URL without retrieval tool | 0 / 4 | 0 / 0 / 4 / 0 | Correctly negative in this generated case. |
| Local file operation | 0 / 4 | 0 / 0 / 4 / 0 | Correctly negative in this generated case. |
| No session-bound transfer | 0 / 64 | 0 / 4 / 60 / 0 | Four false positives; hard-negative gate fails. |

Slice supports are small and generated. Do not extrapolate their rates to live honeypot traffic.

## Collision audit and matched case

- Unique feature vectors: 312.
- Conflicting groups with identical feature vector but different three-head labels: **0**.
- Matched basic/benign-content pairs: 12; identical features 12/12; identical full label vectors 12/12.
- Both matched labels are T1105-positive; content benignness did not affect the target.

## Ablations

`command_presence_only` uses only command event/family counts and transfer-tool command count. `without_sequence` removes the defined sequence features. All thresholds were selected on SELECTION independently for each mode.

| Mode | T1105 TP/FP/TN/FN; F1 | T1046 TP/FP/TN/FN; F1 | T1110 TP/FP/TN/FN; F1 |
|---|---|---|---|
| Command presence only | 44/4/60/0; 0.9565 | 12/16/76/4; 0.5455 | 8/20/72/8; 0.3636 |
| Full 54F | 44/4/60/0; 0.9565 | 16/0/92/0; 1.0000 | 16/0/92/0; 1.0000 |
| Without sequence | 44/4/60/0; 0.9565 | 16/0/92/0; 1.0000 | 16/0/92/0; 1.0000 |

On this synthetic set, full 54F improves the command-count ablation for T1046/T1110, but adding session sequence does not change those scores. For T1105, full 54F does **not** improve over command presence and retains the same four false positives. No incremental T1105 value is demonstrated.

## Artifact identities

| Identity | SHA-256 |
|---|---|
| Feature schema | `28cc1a43e59259c5939dacdb889cdbe4e13fbdaa71b197264e27907a071d13c1` |
| Canonical model identity | `b015de3a5f65eddcba710949604845db5aa6a599d921de8f85336b541133641c` |
| Serialized artifact file | `adff0e76507edfc4f5deadb02922917ff66962c6c2824eb25970ebf40a06b424` |
| Serialized dataset file | `550e0dfd5f67f785c75f6c8fcc41c5b0298e902d63b39fd21f71eb8fc31dbcc7` |
| Full dataset content | `1e0dc84860784fef597621abe167de30566f974eeefdbf0aa6303397ab67a917` |
| FIT+SELECTION content | `9a754c3ed0867623beceb0b3849cece9513781250cc7db7af7011f28a71431a9` |
| Split manifest | `2f954d44c2072762f3f016808a3562d65c93d31a5344e1a6363d49cec9115a39` |

The candidate manifest pins the canonical model identity, serialized artifact bytes, schema, dataset, and split identities. The shadow runtime loads the exact artifact/hash and rejects a manifest bound to the previous model identity or altered artifact bytes.

## Gates and next work

| Gate | Result |
|---|---|
| Synthetic label semantics and matched pair | PASS |
| Conflicting feature/label collisions | PASS, zero |
| T1105 non-transfer hard-negative check | **FAIL**, 4 FP / 64 negatives |
| T1105 controlled-research gate | **BLOCK** |
| Production T1105 / RRF gate | **BLOCK** |
| T1046/T1110 controlled synthetic separability | PASS in this synthetic corpus only |
| Paired 32F / Model1 comparison | NOT COMPUTABLE; no paired real rows/outputs |
| RRF performance | NOT COMPUTABLE |
| Production readiness | NO |

Do not tune thresholds/features against these already inspected synthetic evaluation results and call them independent validation. Any future change needs a newly generated, preregistered held-out controlled set plus real-session/independent labels and same-session baseline predictions. First investigate why the unified T1105 head emits four positives among complete no-transfer sessions; do not patch a post-hoc rule to make the metrics pass. Keep Model2 shadow-only, all votes disabled, trusted finding and response authority unchanged.

## Smoke/runtime and scope

The runtime smoke produced: all-three → all three `PRESENT`; no-TTP → all `ABSENT`; basic and benign-content transfer → T1105 `PRESENT` with identical score/decision; malformed → all `ABSENT`; discovery-only → T1046 `PRESENT`; brute-force-only → T1110 `PRESENT`. All cases loaded the same exact artifact, all remained `rrf_vote_eligible=false`, and all output scores remain uncalibrated. Missing/misbound evidence returns `UNAVAILABLE`, with canonical-write and response authority false. This verifies loading/materialization mechanics, not predictive validity.

Production deployment/restarts: **none**. 32F artifact/schema, production policy, MongoDB, provider behavior, session observer, and RRF vote behavior were not changed. The candidate remains research-only.
