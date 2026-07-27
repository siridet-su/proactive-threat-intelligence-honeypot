# Handoff to the next cohort

## Complete and deployed

- Evidence-bounded Cowrie ingest, SQLite storage, durable workers, reporting,
  dashboard, monitoring, redaction, provenance, and manual-approval guidance.
- Frozen Transformer seed `20260721` as the sole experimental PoC predictor.
- Explicit VOMM rollback/reference model.
- GCP deployment, backup, rollback rehearsal, restoration, controlled event,
  report, API/UI, queue, port, log, and database validation.

Exact deployment evidence: [GCP_TRANSFORMER_POC_DEPLOYMENT_20260727.md](GCP_TRANSFORMER_POC_DEPLOYMENT_20260727.md).

## Experimental truth

The original corrected-target experiment is permanently
`BLOCKED_AT_SELECTION`: every Transformer seed failed the predeclared
defense-evasion recall gate. A separate professor-approved PoC protocol
accepted that limitation and evaluated one frozen checkpoint. Do not erase,
weaken, or merge these two decisions.

The Final data is a within-Zenodo temporal holdout with classifier-derived weak
labels, not external validation. Do not reopen Final, retune thresholds,
replace the checkpoint based on Final results, or claim organic production
validation.

## Important paths

- Runtime: `production/`
- Trusted policies: `configs/*.trusted.json`
- Units: `deployment/systemd/`
- Rollback model: `data/models/external_cowrie_vomm_zenodo_7day_20260721.*`
- Current architecture: `docs/ARCHITECTURE_CURRENT.md`
- Corrected-target evidence/design:
  `evaluation/next_tactic_benchmark_evidence/final_prediction_subsystem_design/`
- Repository cleanup recovery tag:
  `pre-handoff-repository-cleanup-20260727`

Private checkpoints, databases, keys, raw members, and deployment backups are
intentionally outside Git. Verify hashes from receipts before use.

## Remaining work

1. Collect genuinely future, production-local labeled observations without
   changing the frozen checkpoint; reassess domain shift and weak-label bias.
2. Improve defense-evasion support through a new, separately preregistered
   experiment—not by retuning the completed Final evaluation.
3. Decide whether MongoDB remains worthwhile. Promotion requires live parity,
   indexing, migration, backup/restore, rollback, and operational ownership.
4. Reduce historical evaluation tooling only after extracting shared parsing
   and metric functions used by current VOMM/corrected-target reproduction.

## Do not repeat

- Do not rerun or reinterpret the immutable Final evaluation.
- Do not re-download verified Zenodo members when receipts match.
- Do not rebuild the selected checkpoint from Final data.
- Do not enable model-driven response authority.
- Do not add fallback/cascade semantics to hide artifact failure.
- Do not modify networking or exposure while changing analysis code.

## Safe first tasks

- Run the focused and full local suites in a socket-capable environment.
- Review documentation links and configuration examples.
- Add read-only dashboards for forecast disagreement/domain shift.
- Improve operator-facing limitations and evidence navigation without changing
  analytical authority.
