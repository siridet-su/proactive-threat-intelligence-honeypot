# Historical contract tests, preserved 2026-09-28

These 13 modules were moved unchanged except for an archival comment from the active `tests/` directory. They exercise experimental Final-F V6 assessment, AI projection/contract V2, and next-behavior preparation/selection APIs that are not provided by the current production source. In the prior location they caused 13 collection errors before the active runtime tests could run.

This is **not** a claim that the historical experiments passed or that their behavior was replaced one-for-one. The modules remain source-controlled here for research audit. To replay them, restore their original `tests/` paths in an isolated historical checkout with the exact historical source and artifact identity that supplies the missing APIs; do not import them into the current runtime or use them as current release evidence.

Current release coverage is provided by the live-path assessment v4, response guidance v3, AI advisory projection/contract, Model2 bridge, and Next-Distinct PoC tests under `tests/`. Before removing a current API, its active-path tests and this mapping must be reviewed together.

Missing legacy symbols include `CONTROLLED_SYNTHETIC_PROVENANCE_MARKER`, `validate_ai_advisory_projection_v2`, `build_model_input_from_trusted_history_manifest`, `_CANONICAL_LABEL_ADAPTER_RELATIVE_PATH`, and `_rebuild_sessions_reference`. Their absence must not be masked by no-op shims.
