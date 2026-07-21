# Authoritative external VOMM evaluation

- Evaluation schema: `authoritative_external_vomm_evaluation.v1`
- Exact artifact: `externalvomm_8dabca1f770b06e73fb051766539435a`
- Artifact SHA-256: `b5a60951764648ed242d7b9acfe1df6f5f314f96e341badb7f4bd55107614e3e`
- Manifest ID / SHA-256: `externalvommmanifest_f97d2d3770c6ac44f9eb7e7905c7736b` / `01c0665566467693e3dbb408f0383900f7d09e769d27c93161937b27d7d6d429`
- Dataset SHA-256: `c36b2519fcb859910a9e6b95c16662e13ed8b2c974e7a5be1b4e301ea6654cdb`
- Dataset sessions / held-out transition cases: `219336` / `12235`
- Split: `preassigned_whole_session_split`
- Windows / bootstrap resamples / seed: `3` / `500` / `20260721`
- Classifier provenance: `recorded_in_external_artifact`
- External training overlap proof: `available`
- Promotion gate: **supported_for_production_change**

| Model | Coverage | All-case Top-1 | Top-3 | Macro-F1 | Balanced Top-1 | Brier | Log loss |
|---|---:|---:|---:|---:|---:|---:|---:|
| current_local_first_cascade | 1.0000 | 0.8082 | 0.9886 | 0.5206 | 0.3992 | 0.1059 | 0.6713 |
| external_authoritative_abstain | 1.0000 | 0.8008 | 0.9959 | 0.4630 | 0.3996 | 0.1255 | 0.5540 |
| external_then_heuristic | 1.0000 | 0.8008 | 0.9959 | 0.4630 | 0.3996 | 0.1255 | 0.5540 |
| heuristic_only | 1.0000 | 0.2081 | 0.2087 | 0.1355 | 0.2153 | 0.5936 | 27.4569 |
| local_shadow_only | 0.9937 | 0.8019 | 0.9823 | 0.5919 | 0.3583 | 0.1089 | 0.8878 |

## Gate reasons

- none

## Interpretation boundary

- This is an offline external-corpus comparison. It does not change the production policy, artifact, service, alerting, or response-guidance authority.
- The local scorer is a chronology-limited proxy trained on this external corpus; it is not evidence about the deployment-local model.
- A manifest-bound run cryptographically verifies the exact evaluation memberships and artifact byte hash. A legacy stand-alone run cannot authorize an external-only production change.
