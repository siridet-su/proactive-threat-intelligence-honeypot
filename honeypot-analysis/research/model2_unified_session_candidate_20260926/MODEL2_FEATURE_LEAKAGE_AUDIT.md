# Unified Model2 — feature, label, and privacy audit

**Scope:** isolated 54F research extractor, controlled synthetic data generator, generated candidate artifact, and mechanics/runtime tests.  
**Result:** the candidate schema excludes listed outcome/identity/secret sources; dataset labels are explicitly scenario-defined and not human-adjudicated. This is not an audit of deployed acquisition or production runtime.

## 1. Prohibited model inputs

The predictor must not receive:

- TTP labels/ATT&CK IDs, adjudication outcomes, Model1/Model2 outputs, score/threshold fields, or procedure/family/split IDs.
- `cowrie.session.file_download` or `.failed`, receiver/object success, artifact hashes/path/name/bytes, or outcome-selected packet subsets.
- Fixture host/URI/path/query/marker, synthetic family name, source session/run/measurement/episode IDs, exact procedure timestamps, receipts, or hashes.
- HTTP status/body length/transaction metadata/headers/cookies/authorization/user-agent/payload, raw requests/responses, or model outputs.
- Literal endpoints/ports, username, password, credential/token/secret.

HTTP `http.log` is not read. This candidate uses episode-bound conn.log-style aggregates only; it makes no statement that conn.log proves transfer success.

## 2. Transformation and provenance controls

Raw Cowrie command input and username are used transiently in memory and are not returned or persisted. The extractor emits finite aggregate tool/family/sequence/auth/network values; URL/host/path and usernames are omitted. Transfer-result events are excluded before counting. Flow endpoint/UID/tuple details are validated but not copied into feature values; only counts/classes/aggregate bytes and durations are returned. Password/cookie/payload fields are not read by the event fingerprint.

Each row stores source IDs/hashes and label provenance outside the feature vector. Dataset validation enforces the exact 54-name vector order, source identity/hash formats, complete Cowrie/auth/PCAP/Zeek states, stable event keys, exact episode-bound flow evidence, family/duplicate split isolation, unique episode/evidence hashes, allowlisted metadata, and no model-prediction fields.

The generator's labels come from preregistered synthetic procedure definitions before fitting; `model_outputs_used=false`, `labels_defined_before_fit=true`, and `human_adjudication=false`. They must not be described as independently human-adjudicated or real ground truth. The validator separately supports actual blinded lab adjudication provenance for future research rows.

## 3. T1105-specific leakage and semantic controls

T1105 targets session-bound transfer activity. A valid retrieval inside the honeypot session remains positive if the downloaded content is benign; it is not a malware/content classifier. A file-download outcome is not an input. Matched basic and benign-content procedures have identical features and same T1105-positive label. A complete no-flow transfer-attempt control is T1105-negative for this narrower session-bound target. If a flow is missing, partial, stale, unbound, or identity-mismatched, extraction fails closed as `UNAVAILABLE` rather than using it as a negative. Unrelated/background traffic is not added to an episode.

The corrected full candidate has zero exact feature-vector groups with conflicting label vectors. It nevertheless has 4 false positives in 64 no-session-bound-transfer final controls, so T1105 remains blocked even for controlled research use. Zero collisions does not imply adequate classifier performance.

## 4. Remaining scope limitation

The 54F extractor consumes a research episode envelope; this task did not inspect or modify the production collector, Cowrie, PCAP capture service, Zeek invocation, API, BFF, policy, Mongo, or active model processes. Therefore the test proof establishes the research envelope contract only. A real source adapter must independently prove exact Cowrie↔PCAP↔Zeek flow/session binding and completeness. No production capability or behavior is claimed here.

## 5. Test evidence

The complete package suite passes 51 tests: pipeline/extractor 16; dataset/provenance 13; controlled synthetic generator/training 6; runtime load/inference 6; RRF mechanics 10. These test ordering, deduplication, strict schemas, identity/hash rejection, privacy exclusions, label semantics, synthetic splits, collision accounting, fail-closed missingness, unified runtime loading, and RRF safety gates. They are mechanics and controlled-case checks, not real-world performance validation or independent privacy certification.
