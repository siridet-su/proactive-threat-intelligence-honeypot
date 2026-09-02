---
title: Post-session and cloud-analysis contract
status: target
last_verified: 2026-08-25
---

# Post-session and cloud-analysis contract

## Role

Post-session/cloud analysis is a production workstream. It consumes canonical
Atlas telemetry after or near session completion and produces evidence-linked
analysis for dashboard and reports. It does not control live Cowrie shell
output, execute artifacts, or remediate external systems.

## Input contract

An analysis request contains:

- session identity and start/end timestamps;
- ordered canonical-event references;
- normalized command/activity facts;
- Zeek/network evidence references;
- decoy-service observations where available;
- provider-neutral threat-intelligence summaries;
- schema version and data-quality indicators.

The request excludes raw secrets, payload bytes, provider API keys, and host
administration data.

## Output contract

```json
{
  "analysis_id": "stable-id",
  "session_id": "correlated-session",
  "model": {"name": "model-or-rule-set", "version": "version"},
  "observed_facts": [],
  "evidence_linked_inferences": [],
  "hypotheses": [],
  "limitations": [],
  "confidence": "qualified-not-authoritative",
  "created_at": "RFC3339 timestamp",
  "schema_version": 1
}
```

Every factual claim must cite source event IDs. Inferences and hypotheses must
be visibly labelled and include falsification conditions where practical.

## Quality and reporting rules

- No actor attribution from weak evidence alone.
- A provider verdict or model classification is supporting evidence, not proof
  of compromise or execution.
- Report templates use only versioned aggregate evidence and identify the
  environment, evaluation method, limitations, and date.
- Model output must remain available alongside deterministic fallback analysis.

## Handoff test

Use synthetic fixtures to prove the cloud workstream can read a completed
session, preserve evidence references, distinguish unknown from benign, and
render a report without exposing sensitive raw fields.
