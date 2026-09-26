# Unified session Model2 — feature contract

**Disposition:** research-only 54F contract, fitted controlled-synthetic candidate, and extractor mechanics; not production-integrated.  
**Question:** can session sequence and bound network/auth context provide useful evidence for T1105/T1046/T1110 after removing HTTP response metadata?  
**Feature schema:** model2_unified_session_research.v1; ordered names are frozen in FEATURE_SCHEMA.v1.json.

## 1. Existing baseline verified from current local source/artifact

The checked-in V5-style result bridge pins Model2 artifact SHA-256 104d4c77a3e1536b847561abb19fc7c0d6d7dc0111cd98d1ff2d9c9d74a2ed1a and feature-contract SHA-256 cf985643ce89c3d1f86f6c45943c3ba3af6cf13c60c4b41e215c7c7bc8990a20. Rehashing the local artifact at evaluation/model2_v5_style_unified_production_native_20260915_v1/production_artifact_pnvunified20260915a/MODEL2_V5_STYLE_UNIFIED_PRODUCTION_NATIVE_SHADOW_ARTIFACT.json and the V7 32F schema reproduced those hashes.

The local artifact contract is one torch.nn.Linear(32,3) model, one inference call, multi-label outputs ordered T1105/T1046/T1110, threshold zero, no argmax, and no partial-vector inference. The 32 inputs are 17 Cowrie aggregate features plus 15 Zeek connection features. The active loaded production process was **not independently verified in this task**; a repository pin is not proof of process memory or an API result. Do not interpret this local artifact identity as a new production attestation.

The 32F contract excludes raw command text and explicit file-download outcome counts. It has no HTTP status/body fields. Do not append the new features to it or alter it in place.

The frozen source schema is V7_32_FEATURE_SCHEMA.json. All 32 features are shared by all three output heads; “available” below means required by the selected local full-vector inference contract, not independently attested in a currently loaded remote process.

| # | Frozen feature | Actual source / level | Outputs; inference contract | Main leakage or interpretation risk |
|---:|---|---|---|---|
| 1 | v7_c_auth_attempt_count_episode | Sanitized Cowrie login events / session | All three; required | Event count is not a label. |
| 2 | v7_c_auth_failure_count_episode | Cowrie failed-login events / session | All three; required | Strong T1110 target proxy; require benign-retry controls. |
| 3 | v7_c_auth_success_count_episode | Cowrie successful-login events / session | All three; required | Success is not proof of compromise. |
| 4 | v7_c_auth_attempt_rate_episode | Cowrie auth events and episode duration / session | All three; required | Reuses count and duration. |
| 5 | v7_c_auth_failure_rate_episode | Cowrie failure events / session | All three; required | T1110 proxy and count overlap. |
| 6 | v7_c_auth_failure_fraction_episode | Cowrie auth outcomes / session | All three; required | Strong T1110 proxy; benign retry confounding. |
| 7 | v7_c_auth_max_failure_streak_episode | Ordered Cowrie auth events / sequence | All three; required | Requires complete event order. |
| 8 | v7_c_auth_event_span_s_episode | Cowrie auth timestamps / session | All three; required | May identify test procedure or schedule. |
| 9 | v7_c_auth_interarrival_median_s_episode | Cowrie auth timestamps / session | All three; required | Timing/procedure leakage risk. |
| 10 | v7_c_auth_interarrival_iqr_s_episode | Cowrie auth timestamps / session | All three; required | Timing/procedure leakage risk. |
| 11 | v7_c_auth_interarrival_cv_episode | Cowrie auth timestamps / session | All three; required | Timing/procedure leakage risk. |
| 12 | v7_c_burst_window_count_episode | Cowrie auth timestamps / session | All three; required | Depends on fixed window formula; procedure shortcut risk. |
| 13 | v7_c_preauth_session_count_episode | Cowrie lifecycle/auth events / session | All three; required | Depends on lifecycle-event completeness. |
| 14 | v7_c_authenticated_session_count_episode | Cowrie successful-auth lifecycle / session | All three; required | Success count is not compromise evidence. |
| 15 | v7_c_session_duration_median_s_episode | Cowrie connect/close events / session aggregate | All three; required | Can encode test duration. |
| 16 | v7_c_failed_to_success_transition_count_episode | Ordered Cowrie login events / sequence | All three; required | Outcome-adjacent; requires independent controls. |
| 17 | v7_cowrie_event_count_episode | Sanitized Cowrie event stream / session | All three; required | Can encode duration or sensor coverage. |
| 18 | v7_z_connection_count_episode | Exact bound Zeek conn rows / network-session | All three; required | Requires complete PCAP and flow binding. |
| 19 | v7_z_distinct_destination_port_count_episode | Zeek destination ports / network-session | All three; required | T1046-related proxy, not scan intent alone. |
| 20 | v7_z_port_fanout_ratio_episode | Zeek connection rows / network-session | All three; required | Unstable at low count. |
| 21 | v7_z_connection_rate_per_s_episode | Zeek rows and episode duration / network-session | All three; required | Timing/procedure shortcut risk. |
| 22 | v7_z_destination_port_entropy_episode | Zeek destination ports / network-session | All three; required | Requires stable formula and adequate support. |
| 23 | v7_z_protocol_diversity_episode | Zeek protocol values / network-session | All three; required | Sensor configuration can change it. |
| 24 | v7_z_flow_count_episode | Bound Zeek flow rows / network-session | All three; required | Potentially redundant with connection count. |
| 25 | v7_z_orig_bytes_sum_episode | Zeek originator byte aggregates / network-session | All three; required | Large benign transfer confounder. |
| 26 | v7_z_resp_bytes_sum_episode | Zeek responder byte aggregates / network-session | All three; required | Large benign HTTP confounder; not transfer success. |
| 27 | v7_z_orig_packets_sum_episode | Zeek originator packet aggregates / network-session | All three; required | Traffic-volume proxy, not transfer semantics. |
| 28 | v7_z_resp_packets_sum_episode | Zeek responder packet aggregates / network-session | All three; required | Traffic-volume proxy, not transfer semantics. |
| 29 | v7_z_duration_sum_s_episode | Zeek flow durations / network-session | All three; required | May encode capture/procedure duration. |
| 30 | v7_z_duration_median_s_episode | Zeek flow durations / network-session | All three; required | Requires complete flow population. |
| 31 | v7_z_failed_connection_fraction_episode | Zeek connection states / network-session | All three; required | State-to-failure mapping needs review. |
| 32 | v7_z_interarrival_cv_episode | Zeek connection timestamps / network-session | All three; required | Timing can encode scripted procedure. |

These names/source descriptions were checked against the frozen schema at honeypot-analysis/evaluation/model2_v7_32_feature_generation_20260913_v1/V7_32_FEATURE_SCHEMA.json. Missing, partial, stale, or misbound input is UNAVAILABLE under the full-vector contract, never a fabricated zero.

## 2. Proposed target semantics and authority

One row is one complete, exact, closed Cowrie session episode. The single future candidate must return three independent multi-label decisions in one result:

| Output | What a positive means | What it does not mean |
|---|---|---|
| T1105 | A valid transfer operation and exact session/episode-bound network activity support `SESSION_BOUND_TRANSFER_ACTIVITY`; benign-content retrieval remains positive. | It does not prove successful retrieval, artifact persistence, malicious content, attacker intent, compromise, execution, or trusted ATT&CK truth. |
| T1046 | Session behavior supports service-discovery/scanning activity, with exact episode-bound network evidence available. | A Cowrie command string alone is not proof that packets reached a target. |
| T1110 | Session behavior supports repeated authentication-guessing behavior from exact-session authentication events. | It does not identify a real-world actor or establish account compromise. |

Model2 remains experimental/non-authoritative. It must not create trusted findings, alter ATT&CK authority, select/execute response actions, or enable Model1 fusion. Model1 remains the candidate generator for the proposed RRF step.

## 3. Data path

1. An episode controller assigns source-session, run, measurement, and episode identities before the test begins.
2. It captures the complete Cowrie event stream and a fixed episode-wide PCAP window independently of event outcome or model result.
3. Offline Zeek creates conn.log from that exact finalized PCAP. Each admitted flow carries a validated episode-binding receipt, Zeek UID, and complete directional tuple. No join is repaired by IP or time alone.
4. The adapter supplies stable source_event_key and source_sequence values. Exact duplicated source events collapse by key; separate keys for repeated commands remain separate observations.
5. The extractor normalizes allowlisted command families and computes the ordered feature vector. Raw command, destination, username, IP, port, source IDs, receipts, and hashes do not enter the vector.
6. The controlled research candidate verifies the schema/hash/order, fits shared preprocessing on FIT only, selects thresholds on SELECTION only, and returns T1105/T1046/T1110 from one artifact. Its generated final metrics are synthetic-only; it is not connected to production.

This extractor consumes a research episode envelope, not an asserted active Pi/production observer feed. Production acquisition was not inspected or modified in this task. Any future candidate data path must be fixed-window/episode-wide and must not use `cowrie.session.file_download` or other outcome-conditioned selection to create model input or choose included rows.

## 4. Predictor feature groups

The JSON schema contains 54 numeric features in a deterministic order:

| Group | Count | Examples and source |
|---|---:|---|
| Session aggregates | 11 | Closed duration, safe event/command counts, finite command-family diversity/repeats, explicit command failures, density and inter-command gaps. Cowrie session events. |
| Sequence | 9 | Adjacent family transitions; auth-before-command; discovery-before-transfer; transfer-before-execution/permission/archive/cleanup; longest repeated-family run. Exact timestamps plus source sequence determine order. |
| Transfer intent | 16 | Allowlisted wget/curl/other-known tool counts; scheme and normalized port-class counts; output/redirect/pipe-to-shell intent; ephemeral distinct-destination count. Parsed in memory from command input. These are attempt/intention signals, not outcome evidence. |
| Network | 11 | Bound connection/protocol counts, distinct destination-port count, finite service classes, established vs S0/REJ counts, aggregate bytes and duration. Exact-episode Zeek conn.log. |
| Authentication | 7 | Attempt/failure/success counts, failure fraction, ephemeral distinct-username count, max failure streak, interarrival CV. Cowrie login events. |
| Availability | Gate only | Completeness, freshness, exact identity, capture and parser state are required metadata gates, not learned predictors. |

The implementation exports exactly the contract order and only finite nonnegative numbers. Counts and ratios use structural zero only when complete source coverage proves the denominator/event set is empty. A missing source is never converted to an observed zero.

### HTTP response metadata is deliberately absent

The new contract does not read http.log, status_code, response_body_len, transaction depth, URI, headers, cookies, or payload. HTTPS without decryption, absent http.log, incomplete response, and redirect response therefore do not become synthetic status values. The model can use command intent and exact episode-bound connection aggregates, but those do not prove a file was successfully fetched. An independent artifact/receiver receipt may adjudicate a label but is never an input feature.

## 5. Binding, missingness, and privacy rules

The extractor requires exact equality for source_session_id, run_id, measurement_id, and episode_id across expected identity, Cowrie envelope, Zeek envelope, and every admitted flow. The Zeek receipt must name the same finalized PCAP hash used to derive conn.log; the capture must have zero disqualifying drops; each UID is unique; each flow tuple is complete. Cowrie must be complete, closed, auth-observable, and carry unique stable event keys/order. Any failure returns UNAVAILABLE with no vector and all three outputs unset.

cowrie.session.file_download and cowrie.session.file_download.failed are excluded before feature counting. Their event presence, artifact hash, bytes, filename, fixture receipt, and outcome-selected flow subset cannot influence a candidate vector. The code does not return raw command text, URL/host/path, username, password, cookie, token, literal IP/port, or payload.

## 6. Model1 overlap and incremental context

Current Model1 is a command-level LinearSVC over character/word TF-IDF (package SHA-256 3bad72d688add1064aa236f3a24e9f031aa9e97a8fb449ad730e64389487c5d7; manifest SHA-256 188ecec7361b0606d9e2fb8eb012e09f533695d34c334e6aced3af5ca385818e). It ranks 38 top-level labels for one non-empty command and emits an uncalibrated decision margin.

Overlap exists: Model1 sees command wording, while candidate Model2 would reduce commands to finite families and aggregate auth activity. Do not describe those as independent evidence merely because the models differ. The incremental hypothesis is the session-level chronology, repeated behavior across distinct events, event timing/density, and exact-episode Zeek connection fan-out/bytes/state. The old 32F Model2 already uses aggregate Cowrie auth and Zeek flows, so some new session/auth/network fields also overlap with that baseline. The paired ablation is required to establish whether sequence/command context adds information beyond frozen 32F and Model1.

## 7. Implementation boundary

`pipeline.py`, `controlled_poc.py`, `shadow_runtime.py`, and their candidate artifact/tests are isolated research code. They are not imported by production. A single 54F artifact with three OVR heads was newly trained from the deterministic synthetic corpus; it is not the frozen 32F baseline and is not a T1105-only model. Candidate metrics are controlled synthetic results, not field performance. No BFF, receiver, policy, Mongo, service, production model, or active runtime was changed.
