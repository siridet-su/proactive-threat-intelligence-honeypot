# Authoritative external VOMM evaluation

- Evaluation schema: `authoritative_external_vomm_evaluation.v1`
- Exact artifact: `externaltransition_1ec330113086868b5d6ab05eef9602f5`
- Artifact SHA-256: `f6f4650f9b6c8bdda39998eed039afc0aa3f948ddb3b0e5582f5145bc5530b51`
- Dataset SHA-256: `c36b2519fcb859910a9e6b95c16662e13ed8b2c974e7a5be1b4e301ea6654cdb`
- Dataset sessions / held-out transition cases: `219336` / `12235`
- Split: `preassigned_whole_session_split`
- Windows / bootstrap resamples / seed: `3` / `100` / `20260721`
- Classifier provenance: `not_recorded_in_external_artifact`
- External training overlap proof: `not_available`
- Promotion gate: **not_supported_for_production_change**

| Model | Coverage | All-case Top-1 | Selective Top-1 | Balanced Top-1 | Normalized Brier |
|---|---:|---:|---:|---:|---:|
| current_local_first_cascade | 1.0000 | 0.8069 | 0.8069 | 0.3954 | 0.1072 |
| external_authoritative_abstain | 0.9962 | 0.7954 | 0.7985 | 0.3880 | 0.1085 |
| external_then_heuristic | 1.0000 | 0.7981 | 0.7981 | 0.4081 | 0.1078 |
| heuristic_only | 1.0000 | 0.2081 | 0.2081 | 0.2153 | 0.5936 |
| local_shadow_only | 0.9937 | 0.8019 | 0.8070 | 0.3583 | 0.1089 |

## Gate reasons

- external_artifact_training_data_manifest_missing_no_overlap_proof
- no_clean_local_production_chronological_evidence

## Interpretation boundary

- This is an offline external-corpus comparison. It does not change the production policy, artifact, service, alerting, or response-guidance authority.
- The local scorer is a chronology-limited proxy trained on this external corpus; it is not evidence about the deployment-local model.
- An absent training-member manifest prevents proof that the frozen artifact and the held-out corpus do not overlap. The recorded result therefore cannot authorize a production architecture change.
