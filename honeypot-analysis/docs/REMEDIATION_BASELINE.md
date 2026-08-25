# Behavioral remediation baseline

This document freezes the source and release evidence from which the behavioral-intelligence remediation is implemented. It is evidence only: it does not activate a new runtime contract, reinterpret historical records, or change production state.

## Source identity

- Baseline commit: `49f9b74fbe31c938d37767675d51ff863ce6902d`
- Baseline Git tree: `d66aa7859c0262024a55a2bae16cf950d4c72463`
- `git ls-tree -r --full-tree HEAD` SHA-256: `f99e3044d94e5bc981df74ade3ffa948cf60a325dd48ee61f917b79e019f4db4`
- Approved remediation-plan SHA-256: `a5dabdb5f36c479a7dbdaedfe247b43b858b8f3af7ae5dcaa420e43a9f394624`
- Initially empty completion-ledger SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- Deterministic baseline fingerprint: `9c0e870f464f355f90f0b856f1441ceeef34ba263d59d31bc40aedf6b26ca801`

The deterministic baseline fingerprint is the SHA-256 of stable compact JSON containing the five fields above: `base_commit`, `base_tree`, `tracked_inventory_sha256`, `reviewed_plan_sha256`, and `completion_log_sha256`.

## Bound configuration and release evidence

| Evidence | SHA-256 |
|---|---|
| `configs/classification_rules.trusted.json` | `32744defdf1746d23764772ad20cf8fd4c2630c04f63ed85cbb4bbfc28f7d7fc` |
| `configs/next_behavior_classifier_environment.v1.json` | `3b241b86b12fea45efe658939f25a5f11d3ce81859c8e85fa9f9bd4c6f64b90a` |
| `configs/prediction_policy.transformer_poc.trusted.json` | `d6cc0197f80a0533b5395a39a4de55193dc415b1d05f6051ed5c034303763317` |
| `configs/next_behavior_checkpoint_compatibility_evaluation.v1.json` | `01dcb38f9f43b1a1f5c140eb85a9e54a78f853dfad8a4acf328a1fe35b3844eb` |
| `configs/production_config.example.json` | `2c677f0220950a2c887d6a701898262ce435a3b1217a5cb03a1b77a2d1280247` |
| Baseline `honeypot_release_manifest.v7.json` | `adc093db423cf2ac92683ac60088d0de7676b30c8c40137c5e089e439272cfdb` |
| Baseline frozen-model bundle manifest | `ec27d2a4b3c75a36d343fac86d0f9c9fb29f380c2827c4aa39593cc408d749f7` |

The baseline release evidence is historical evidence only. It must not be regenerated or relabeled as compatible with remediation contracts until the approved Phase 7 deterministic-semantics freeze and subsequent Transformer compatibility gate.

## Compatibility rule

Historical contract versions remain immutable and readable under their original policy, environment, and model identities. They are never silently upgraded, rehashed, backfilled, or made inference-eligible under a newer contract. New-version records are written alongside historical records and receive new identities.

The machine-readable ownership and disposition map is `configs/remediation_contract_lineage.v1.json`.
