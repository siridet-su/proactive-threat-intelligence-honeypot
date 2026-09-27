# Unified Model2 controlled dataset and label design

**Current dataset:** deterministic `CONTROLLED_SYNTHETIC_POC`, not collected honeypot traffic.  
**Model unit:** one complete synthetic Cowrie session episode with exact session/run/measurement/episode identity and an episode-bound conn.log-style flow set.  
**Candidate labels:** T1105, T1046, and T1110, all in the same row and one unified model.

## 1. Target labels and corrected T1105 semantics

T1105 means `SESSION_BOUND_TRANSFER_ACTIVITY` in this research PoC. A valid transfer-tool invocation and target plus network activity bound to the exact same session episode are required by the controlled scenario definition. It is not a malware, intent, completion, compromise, or trusted-finding label.

> Within this honeypot threat model, a valid session-bound file retrieval remains T1105 transfer behavior regardless of whether the retrieved content is benign or malicious. Content maliciousness and transfer completion are separate evidence dimensions.

The prior `benign-large` case used the same valid wget/curl operation and session-bound flow as `transfer-basic`, yet had a false T1105 label because the retrieved content was benign. That label has been corrected: `benign_content_transfer_positive` is T1105-positive. Basic and benign-content samples are nuisance-matched so their observed 54F vectors are identical and their three labels are identical.

| Evidence dimension | Use in this candidate |
|---|---|
| Transfer command attempt | Parsed in memory from allowlisted Cowrie command events; emits aggregate tool/intent features only. |
| Session-bound activity | Requires the complete episode evidence contract and a flow bound to that exact episode. This is the T1105 label target. |
| Artifact received/verified | Label-side/outcome evidence only; never a predictor feature. The controlled synthetic generator does not claim real retrieval completion. |
| Post-transfer behavior | Later command-family sequence features; not proof that execution or extraction succeeded. |
| Artifact maliciousness | Separate artifact-analysis/ETI concern, not predicted by T1105. |

The flow provenance contract verifies episode identity, finalized PCAP identity, Zeek-to-PCAP binding, complete tuple, unique UID, and flow binding. It does not claim to infer content, validate HTTP result, or prove transfer completion. An unrelated/background HTTP flow must never be inserted into the session's flow list. A failed/missing/misbound source yields `UNAVAILABLE`; a complete episode with no flow is an explicit negative control for this target.

## 2. Controlled procedure matrix

There are 27 deterministic procedure families per split, each repeated four times, for 81 families and 324 generated rows total. Labels are set in the preregistered procedure catalogue before fitting and are never generated from Model1/Model2 output.

| T1105 positives | T1105 negatives / controls |
|---|---|
| Basic retrieval; benign-content retrieval; output-file variant; redirect variant; transfer then execute; transfer then chmod; transfer then extract; transfer then cleanup; transfer+T1046; transfer+T1110; all three TTPs. | No-transfer baseline; transfer command with no session flow; embedded/quoted command text; wget help; curl version; malformed/bare transfer command; URL without retrieval tool; local file operation; execution of existing local file; ordinary auth-only; discovery-only; single-service access; benign auth retry. |

Every positive T1105 procedure has the scenario-defined session transfer operation and an exact episode-bound network flow. The matched basic/benign-content procedure pair has the same command, flow, and nuisance stream; the content description is not feature input. `transfer_attempt_no_session_flow` is negative for the narrower session-bound-activity target. An unbound background flow is not a negative sample; it invalidates required evidence and causes abstention.

The corpus also represents `none`, each TTP separately, T1105+T1046, T1105+T1110, T1046+T1110, and all three. Multiple TTP labels are allowed; heads are not mutually exclusive.

## 3. Split, provenance, and honest synthetic labeling

| Split | Rows | Procedure families | Role |
|---|---:|---:|---|
| FIT | 108 | 27 | Fit the shared standardizer and three head weights. |
| SELECTION | 108 | 27 | Select per-head thresholds; no FIT transform refitting. |
| SEALED_FINAL | 108 | 27 | Score only after all feature modes, weights, and thresholds are frozen. |

Procedure-family IDs are split-specific; repetitions stay in their procedure family. The `SEALED_FINAL` rows are in the same generated JSON as the other rows. This means the partition is algorithmically held out but **not** an externally blinded/escrowed independent holdout. No human adjudication occurred. Manifest provenance explicitly states: scenario-defined before fitting, not human-adjudicated, and not model-generated.

Each row contains identity and evidence hashes as metadata, availability states, ordered feature values, predeclared Boolean labels, provenance class, and allowlisted control tags. The feature vector contains none of the IDs/hashes/labels/model outputs. The validator rejects prediction columns, wrong order/schema, incomplete sources, source-evidence duplicates, group leakage, and contradictory T1105 semantic tags. It distinguishes human blinded lab labels from preregistered synthetic scenario labels; it does not misrepresent the latter as human adjudication.

## 4. Runtime feature contract and exclusions

The artifact consumes a shared 54-dimensional vector from Cowrie event aggregates, normalized command/sequence signals, complete exact-episode Zeek conn.log aggregates, and authentication aggregates. It does **not** consume `http.log`, status_code, response_body_len, headers, cookie, payload, HTTP transaction metadata, `file_download` outcome events, fixture host/URI, artifact hash, or model predictions. HTTP response metadata was not added to this contract.

Feature/materialization gates are fail-closed: incomplete Cowrie/auth telemetry, partial PCAP, parser failure, missing/stale or mismatched identity, PCAP/Zeek hash mismatch, invalid tuple/UID, or unbound flow means no vector and all three outputs unavailable. Complete zero-flow telemetry may represent an observed empty network set; it is not the same as a missing Zeek source.

The synthetic cases use conn.log-like flow aggregates and do not prove that production acquisition can supply this 54F episode contract. The active Pi/V7 outcome-conditioned observer was not changed or connected to this research artifact.

## 5. Current counts and interpretation

| Count | Current value |
|---|---:|
| Total synthetic rows / families | 324 / 81 |
| T1105 positive / negative | 132 / 192 |
| Non-transfer T1105 controls | 192 overall; 128 FIT+SELECTION and 64 final |
| Benign-content transfer positive | 12 overall; 4 final |
| Conflicting exact-feature/different-label groups | 0 |
| Matched basic vs benign-content pairs | 12; features equal 12/12, labels equal 12/12 |
| Real paired production/baseline sessions | 0 |

The corpus is constructed by code and deliberately compact. Perfect T1046/T1110 results and the zero collision count establish only mechanics/separability under these authored scenarios. No empirical field-rate or real-world accuracy is claimed.

## 6. Future data required before a real claim

Collect fresh episode-wide observations with fixed capture windows, exact Cowrie/PCAP/Zeek binding, independent human adjudication blinded to model outputs, and real benign/non-transfer controls. Include valid benign-content retrieval as positive T1105, and separately adjudicate actual transfer outcome and artifact maliciousness without passing either into model features. Freeze family-level FIT/SELECTION/final assignments and support minima before evaluation. Pair the same sessions with exact frozen 32F and Model1 outputs. Keep current synthetic final results out of any claim of independent validation.
