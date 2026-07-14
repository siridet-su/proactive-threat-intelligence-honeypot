# Honeypot Threat Intelligence

An educational and research prototype for analyzing **Cowrie
honeypot-observable SSH behavior only**. It ingests synthetic or authorized
Cowrie telemetry, maps observed commands to candidate MITRE ATT&CK techniques
and tactics, correlates session behavior, ranks an advisory next-tactic
hypothesis, and produces an evidence-grounded post-session threat hypothesis.

This README is the canonical public documentation. The public package contains
no real credentials, private keys, databases, Cowrie logs, forwarder spools,
captured payloads, raw production sessions, cloud identifiers, or private
network configuration.

> **Security warning:** This repository is not a guide for exposing a honeypot
> to the Internet. Do not expose Cowrie or any related service without explicit
> authorization, network isolation, egress controls, monitoring, and a tested
> recovery procedure. Public-exposure and private-infrastructure deployment
> material is intentionally excluded.

## Scope And Claim Boundary

The empirical scope is limited to telemetry directly observable by Cowrie:

- SSH connection and login events
- interactive `cowrie.command.input` events
- Cowrie file download/upload events when present
- command-level candidate ATT&CK mappings
- session-level correlation from observable command and transfer evidence
- advisory next-tactic hypotheses from trusted tactic sequences
- post-session threat hypotheses grounded in recorded honeypot evidence

The project does **not** predict arbitrary cyberattacks, exact next commands, or
an enterprise attack lifecycle. It does not establish named attacker
attribution or intent, prove compromise or victim impact, confirm malware
execution without direct evidence, infer unobserved lateral movement, or
perform autonomous blocking or response.

## Architecture

```text
authorized Cowrie event or synthetic fixture
  -> authenticated ingest API
  -> SQLite/Postgres storage adapter
  -> session worker and SessionMonitor
  -> command splitting and candidate ATT&CK classification
  -> report-only session behavior correlation
  -> advisory next-tactic hypothesis
  -> enrichment and cross-session analysis
  -> evidence-grounded post-session report
  -> dashboard API and local read-only monitor
```

The public package covers the analysis pipeline. Sensor exposure, cloud
firewall rules, SSH administration, HAProxy relays, overlay-network policy,
systemd units, and emergency rollback tooling are private operational concerns
and are not included.

## Methodology

### Command Classification

`production.classification.classification_pipeline` splits compound shell input
where possible and applies deterministic reviewed rules. SecureBERT can be
enabled as an optional NLP-assisted classifier for ambiguous commands.
Classifications contain a candidate technique, tactic, confidence, source, and
provenance; they are observable-based evidence rather than confirmation of
attacker intent.

`production.classification.trust` enforces the evidence boundary. Shell noise,
low-confidence SecureBERT output, and known semantically unsupported opaque
probes remain audit-only. They cannot enter trusted tactic/TTP sequences,
correlation facts, prediction evidence, kill-chain facts, actor-profile facts,
or threat-hypothesis evidence.

### Session Correlation

Trusted command evidence is accumulated by session. The correlation layer can
identify conservative multi-command patterns such as discovery activity or a
download command followed by an execution attempt. Current correlation rules
are report-only: they enrich the explanation but do not alter the production
prediction sequence. A downloader command supports attempted transfer or
possible payload staging; a successful download is not claimed without a
corresponding Cowrie transfer event.

### Next-Tactic Prediction

The active `primary_transition_with_fallback` design is a source-selecting
transition model, not a weighted vote across all contextual scorers:

1. Use trusted local tactic transitions when the observed prefix has support.
2. Otherwise use the selected external Cowrie transition model as a cold-start
   prior when it supports that prefix.
3. Otherwise emit a conservative, policy-defined fallback hypothesis.

The input is the trusted, adjacent-deduplicated tactic sequence, not raw command
text. SecureBERT classifies already-observed commands; it is not the next-tactic
predictor. The historical weighted ensemble remains comparison-only and does
not produce the active final ranking.

The checked-in external model contains aggregate counts and provenance rather
than raw sessions. Its labels are automatically generated weak labels, not
independently adjudicated ground truth.

### Threat Hypothesis

After a session closes, the reporting pipeline separates:

- directly observed facts
- supported, evidence-linked inferences
- advisory follow-on hypotheses
- explicit falsification conditions and limitations

Weak evidence cannot enter the factual sections. Actor-profile wording remains
conservative when evidence is insufficient, and no attribution is claimed.
Successful payload transfer, execution, persistence, or compromise is reported
only when the relevant Cowrie evidence exists. Optional AI text generation is
post-session only; deterministic reporting remains available, and generated
text cannot authorize remediation actions.

## Repository Structure

```text
configs/       Trusted policies and local-safe example configuration
data/feeds/    Reproducible public threat-reference caches
data/models/   Selected aggregate external transition model
data/samples/  Synthetic Cowrie and enrichment fixtures
demo/          Local synthetic event replay tool
evaluation/    Compact, non-sensitive evaluation summaries
production/    Runtime package, workers, APIs, analysis, and offline tools
tests/         Unit, service, provenance, regression, and local E2E tests
```

## Local Setup

Python 3.10 or newer is required.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
cp configs/production_config.example.json /tmp/honeypot-config.json
export HONEYPOT_CONFIG_FILE=/tmp/honeypot-config.json
```

The default example binds APIs to loopback, uses SQLite, disables SecureBERT,
and uses only repository-local fixtures/caches. Replace `<TOKEN>` locally before
sending events. Do not commit the edited copy.

Run the local components in separate terminals:

```bash
python -m production.api.ingest_api --config /tmp/honeypot-config.json
python -m production.workers.session_worker --config /tmp/honeypot-config.json
python -m production.workers.analysis_worker --config /tmp/honeypot-config.json
python -m production.api.dashboard_api --config /tmp/honeypot-config.json
python -m production.api.monitor_web --config /tmp/honeypot-config.json
```

Print a synthetic Cowrie session without sending it:

```bash
python demo/realtime_pipeline_demo.py --print-only
```

Optional capabilities require additional packages:

```bash
# PDF reports, Gemini, Postgres, and SecureBERT/training support
pip install reportlab google-genai 'psycopg[binary]' torch transformers pandas scikit-learn numpy
```

## Tests And Policy Validation

```bash
pytest tests/test_production_services.py
pytest tests/test_system_regressions.py
pytest tests/test_production_e2e.py

python -m production.policies.validate_prediction_policy \
  --policy configs/prediction_policy.trusted.json
python -m production.policies.validate_classification_rules \
  --policy configs/classification_rules.trusted.json
python -m production.policies.validate_session_ttp_correlation_policy \
  --policy configs/session_ttp_correlation.trusted.json
python -m production.policies.validate_smb_policy \
  --action-policy configs/smb_action_playbooks.trusted.json \
  --asset-profile configs/smb_asset_profile.example.json
```

## Evaluation Summary

| Component | Current evidence | Safe interpretation |
|---|---|---|
| Command classification | 130-command researcher/AI-assisted consistency benchmark; trusted hybrid precision 0.9560, recall 0.8969, F1 0.9255, exact-set 0.9174 over 121 evaluable cases | Diagnostic consistency, not independent expert validation or production accuracy |
| Session correlations | 15 enabled rules reviewed; all report-only | Policy consistency review, not empirical precision |
| Current next-tactic predictor | One clean held-out transition in the scoped chronological evaluation | Insufficient data for a defensible accuracy estimate |
| Threat hypotheses | 45/45 controlled factuality scenarios passed | Controlled implementation correctness, not field accuracy |
| Historical weighted comparison | Held-out Top-1 0.8488, Top-3 0.9966, MRR 0.9201, Brier 0.216126 over 291 external weak-label examples | Proposal-only comparison; not current production architecture accuracy |

Public summary artifacts:

- `evaluation/classification_benchmark.json`
- `evaluation/session_correlation_review.json`
- `evaluation/threat_hypothesis_factuality.json`
- `evaluation/external_seed_weight_fit.json`
- `evaluation/external_seed_weight_sweep.json`

The historical weight-fitting experiment minimized Brier score on a calibration
split and evaluated on a held-out external Cowrie split. Its code-level
`local_transition` scorer was trained from that external train split; the fitted
weight does not demonstrate strength of local production data. These artifacts
are comparison evidence only and do not change the active prediction mode or
weights.

## Limitations

- ATT&CK mappings are candidate mappings, not definitive TTPs.
- SecureBERT and deterministic rules can misclassify ambiguous commands.
- Benchmark labels are researcher/AI-assisted and not independent expert ground
  truth or a prevalence-weighted production sample.
- Current local transition evidence is sparse; current-mode accuracy is not yet
  statistically estimable.
- The external transition model may not represent another deployment's traffic.
- Correlation strengths and fallback progression are policy choices, not fitted
  probabilities.
- Similar-session clusters are behavioral similarity, not actor attribution.
- Reports are advisory and post-session; the system does not block traffic.
- STIX-style output is not a complete interoperable CTI exchange package.

## Public Package Boundary

Intentionally excluded from the public package:

- cloud, VM, Raspberry Pi, systemd, firewall, SSH, HAProxy, Tailscale, and
  Internet-exposure deployment material
- real environment files, machine addresses, usernames, and absolute user paths
- raw Cowrie logs, session exports, databases, spools, reports, and payloads
- private shutdown/rollback bundles and historical task reports
- case-level evaluation data and session identifiers
- review queues, scratch validation output, notebooks, archives, and superseded
  models

The sample events use IANA documentation address ranges and fake credentials.
They are synthetic fixtures, not captured attacker sessions.

## Team Integration

For public release, copy the cleaned public package into a **fresh repository or
fresh branch without this private repository's history**. Review namespace and
configuration conflicts with the teammate's code before merging. Keep generated
evaluation output under `evaluation/generated/`, which is ignored, and promote
only deliberately reviewed aggregate summaries.

Before publishing:

1. Run all tests and policy validators.
2. Run `git diff --check` and a secret scanner over the public repository.
3. Confirm no deployment directory, environment file, key, database, log,
   session export, or generated report is staged.
4. Add the license selected by the project team.

**License decision required by project team.**
The team may choose a license such as MIT later if every project contributor agrees.
