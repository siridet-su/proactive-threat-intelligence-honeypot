# Phase 6 archive boundary

Phase 6 removes inactive implementations without migrating or rewriting data.
The recovery boundary for every removed path is handoff commit
`d2e047c31fa4ba524ca4bb7b89660d8ae6a87d22`; Git history is the archive.

## Active canonical paths

- `production/reporting/canonical_pipeline.py` is the only coordinator for new
  reports.
- `production/reporting/session_assessment_v4.py` is the only new assessment
  contract and whole-contract validator.
- `production/reporting/response_guidance_v3.py` is the only new guidance
  evaluator. All actions require manual approval and prohibit automatic
  execution.
- `production/reporting/threat_hypothesis.py` retains only the deterministic
  evidence-relationship functions consumed by v4.
- `production/storage/backend.py` and `contract.py` expose SQLite only.
- `production/api/static/monitor.html` is the sole monitor document.

Historical `session_assessment.v2/v3`, `response_guidance.v1/v2`, and
`smb_decision.v1` payloads are not regenerated. The v4/v3 read adapters return
the stored record without recomputation or authorization.

## Archived source

- legacy report, session-assessment, response-guidance, and SMB-decision
  generators and their active-generation tests;
- legacy SMB policies and validator;
- Vertex narrative client/configuration/dependency;
- MongoDB and PostgreSQL adapters, schema, migration tool, dependencies, and
  backend-specific tests;
- superseded threat-hypothesis evaluators whose retained results remain under
  `evaluation/`;
- the console script pointing to the absent prediction-retention module;
- the shared stale systemd environment template;
- the server-rendered monitor and `/legacy` page.

No evaluation artifacts, historical fixtures, SQLite data, model artifacts,
deployment manifests, or rollback packages are changed by this phase.

## Acceptance boundary

Phase 6 passes only when:

1. all packaged console entrypoints import;
2. non-SQLite backend selection fails closed;
3. new analysis emits validated `session_assessment.v4` with
   `response_guidance.v3`;
4. prediction/enrichment context cannot change findings, hypotheses, guidance,
   statuses, or IDs;
5. historical adapters are read-only and preserve their input;
6. the monitor has one static UI and no fallback renderer;
7. focused and full feasible tests pass.
