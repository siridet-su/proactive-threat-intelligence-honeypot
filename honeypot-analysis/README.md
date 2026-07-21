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
> state is intentionally excluded. The repository includes generic hardened
> deployment templates, but they are not evidence of any live host's state.

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
  -> SQLite or MongoDB storage adapter
  -> session worker and SessionMonitor
  -> command splitting and candidate ATT&CK classification
  -> report-only session behavior correlation
  -> advisory next-tactic hypothesis
  -> enrichment and cross-session analysis
  -> evidence-grounded post-session report
  -> dashboard API and local read-only monitor
```

The public package covers the analysis pipeline and generic systemd templates.
Sensor exposure, cloud firewall rules, SSH administration, HAProxy relays,
overlay-network policy, populated service configuration, host manifests,
backups, and emergency rollback bundles are private operational concerns and
are not included.

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

Exact rule/SecureBERT technique agreement is retained as trusted `both`
evidence. Same-tactic/different-technique and different-tactic disagreements
remain audit-only, while a reviewed rule remains usable when the SecureBERT
candidate is below threshold. Classification events preserve the Cowrie event
type and timestamp, command outcome when Cowrie reports one, compound-fragment
position, stable evidence reference, confidence semantics, and available rule
policy provenance.

### Session Correlation

Trusted command evidence is accumulated by session. The correlation layer can
identify conservative multi-command patterns such as discovery activity or a
download command followed by an execution attempt. Current correlation rules
are report-only: they enrich the explanation but do not alter the production
prediction sequence. A downloader command supports attempted transfer or
possible payload staging; a successful download is not claimed without a
corresponding Cowrie transfer event.

### Next-Tactic Prediction

The active `external_hard_backoff_vomm` design uses one immutable,
manifest-bound external Cowrie VOMM as the sole authoritative ranker:

1. Verify the artifact byte hash, model ID, manifest ID, split membership, and
   provenance before it is eligible at runtime.
2. Use its longest empirically supported prefix, then technique, then tactic
   context in hard-backoff order.
3. Explicitly abstain when no supported external context exists, or report
   `model_unavailable` when verification fails. It never falls back to a local
   model or heuristic ranking.

The input is the trusted, adjacent-deduplicated tactic sequence, not raw command
text. SecureBERT classifies already-observed commands; it is not the next-tactic
predictor. The local VOMM remains a separately stored shadow/offline comparison.
The human-curated progression list is exposed only as `generic_progression_prior`:
non-empirical planning context with no prediction confidence and no authority
for alerts, hypotheses, guidance, or actions. The historical local-first cascade
and weighted ensemble remain offline comparison baselines and do not produce the
active final ranking. Historical snapshots are not rewritten or reinterpreted
after policy changes.

The checked-in external model contains aggregate counts and provenance rather
than raw sessions. Its labels are automatically generated weak labels, not
independently adjudicated ground truth.

### Threat Hypothesis

After a session closes, the deterministic reporting core emits the additive
`threat_hypothesis.v2` JSON contract. It separates:

- `observed_behavior`: the temporally ordered trusted command/evidence chain,
  candidate ATT&CK mappings, audit-only candidates, and Cowrie transfer/outcome
  events
- `supported_assessment`: a conservative behavior summary and possible
  objectives
- `follow_on_hypothesis`: bounded post-session claims, explicit abstention,
  Cowrie-evaluable disconfirming observations, evidence gaps, and separately
  labeled external validation suggestions
- `model_prediction`: the latest realtime next-tactic ranking, support,
  coverage, and abstention state, kept separate from observed evidence
- `contextual_intelligence`: reputation, enrichment, correlation, Sigma/KEV,
  infrastructure, and optional TTP-similarity context
- `recommendations`, `limitations`, and presentation-only wording

Each analytical claim has a stable claim ID, claim type, text,
`supported|partially_supported|insufficient_evidence` status, evidence
references, and limitations. There is no global analytical probability.
Legacy confidence fields remain readable as deprecated `Unscored` aliases with
claim-status counts and `calibrated_probability=false`.

Weak evidence cannot enter the factual sections. Actor-profile wording remains
conservative when evidence is insufficient, and no attribution is claimed.
Successful payload transfer, execution, persistence, or compromise is reported
only to the extent supported by the relevant Cowrie event and command outcome.
Downloader syntax alone means attempted transfer or possible staging; a Cowrie
file event proves transfer into Cowrie but not execution; generic T1059 mapping
does not prove downloaded-payload execution.

Relationship-aware analysis preserves full command arguments and quoted shell
fragments, records the operators between fragments (`&&`, `||`, `;`, newline,
and pipelines), and normalizes observable paths, redacted URLs, accounts, and
hashes. It can therefore link evidence such as an explicit downloader output
path followed by `chmod`, execution, and removal of that same path. Connected
behavior chains are emitted additively alongside the legacy ordered ATT&CK
sequence. Literal command actions may support a bounded behavioral claim, but
only trusted classifier mappings can populate ATT&CK evidence; audit-only
mappings remain excluded. A chain records command outcomes and matching Cowrie
transfer events when available, but unknown or compound-command outcomes are
not treated as proof for every fragment. Entity and shell-operator links mean
"observed in a related evidence chain," not proven causality, successful
execution, malware behavior, or real-host impact. Ambiguous relative paths,
environment-variable expansion, and timing-only transfer matches remain
explicit evidence gaps rather than being resolved speculatively.

Policy-approved operator recommendations use the same canonical ordered
evidence builder as `threat_hypothesis.v2`. Each action records stable evidence
references, evidence scope, trusted policy provenance, cited guidance, and
Cowrie visibility limitations, and always requires manual approval. Transfer
commands, Cowrie-confirmed file transfers, and execution commands are handled
as distinct evidence states; none establishes execution or real-host impact.
Reputation and prediction may prioritize defensive review but remain labeled
context or forecast evidence and cannot strengthen behavioral claims.

The recommendation policy is schema-validated on both file and in-memory
runtime paths before it can influence risk, goals, or actions. Rule and action
provenance must be explicitly reviewed; rule/action IDs and supported condition
fields are validated; configured asset selectors do not match missing session
fields. Strong operator actions, low-evidence default guidance, and rejected
audit-only candidates use separate tiers. A missing, malformed, contradictory,
unreviewed, or duplicate-ID policy fails closed and cannot emit a trusted
operator action. Report, monitor, and artifact consumers recheck the same
trusted-action contract rather than trusting an authority label alone.

`enable_vertex_narrative` and `enable_actor_attribution` both default to
`false`. When explicitly enabled, Vertex can only rewrite presentation text
from cited canonical claim IDs; ungrounded output is rejected as a whole and
cannot alter claims, objectives, recommendations, evidence status, prediction,
or falsification fields. Optional actor matching appears only as
`contextual_intelligence.ttp_similarity` with explicit `not_attribution`
semantics. Existing legacy aliases are generated from v2 fields, so stored JSON
reports, APIs, artifacts, and the monitor remain readable without a database
migration.

## Repository Structure

```text
configs/       Trusted policies and local-safe example configuration
data/feeds/    Reproducible public threat-reference caches
data/models/   Selected aggregate external transition model
data/samples/  Synthetic Cowrie and enrichment fixtures
demo/          Local synthetic event replay tool
evaluation/    Reviewed summaries and privacy-minimized research payloads
production/    Runtime package, workers, APIs, analysis, and offline tools
tests/         Unit, service, provenance, regression, and local E2E tests
```

## Local Setup

Python 3.11 or newer is required.

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

Database selection is explicit:

- `DATABASE_BACKEND=sqlite` uses `SQLITE_DATABASE_PATH`.
- `DATABASE_BACKEND=mongodb` requires both `MONGODB_URI` and
  `MONGODB_DATABASE`.
- `DATABASE_URL` remains a legacy compatibility input for SQLite, MongoDB, and
  PostgreSQL deployments. It must agree with an explicit backend or startup
  fails.

SQLite is the local-development and emergency fallback default. MongoDB is the
intended production backend once it is privately provisioned, indexed, tested,
and migrated. PostgreSQL is retained only as a legacy compatibility path.
Startup descriptions omit database usernames, passwords, and URI query
parameters.

### Optional MongoDB Backend

Install the MongoDB runtime dependency separately so SQLite-only development
does not require it:

```bash
pip install -r requirements-mongodb.txt
```

MongoDB must remain on a private management network and must not be exposed
directly to the public Internet. Adapter initialization creates the reviewed
unique and queue/query indexes before readiness succeeds.

The repository's MongoDB evidence uses mocked adapter tests unless the opt-in
test is explicitly pointed at an authorized private disposable server. A green
default suite is not proof of a live MongoDB deployment, migration, or rollback.

The migration tool opens SQLite read-only, never deletes it, uses stable
idempotency keys, checkpoints each completed batch, and verifies collection
counts plus deterministic sample hashes:

```bash
# Conversion and SQLite integrity check; no MongoDB connection or write.
python -m production.tools.migrate_sqlite_to_mongodb \
  --sqlite sqlite:////path/to/production.db \
  --dry-run

# Private cutover after MONGODB_URI and MONGODB_DATABASE are set.
python -m production.tools.migrate_sqlite_to_mongodb \
  --sqlite sqlite:////path/to/production.db \
  --migration-id production-cutover-v1
```

Rerun the same command to resume an interrupted migration. If SQLite changes
after a checkpoint, the tool refuses resume; rerun with `--restart` to clear
only migration checkpoints and reconcile every source row. Keep the original
SQLite database and a verified backup until MongoDB validation and rollback
testing are complete. The tool never removes the SQLite rollback source.

An opt-in real-driver test uses a unique disposable database when
`MONGODB_TEST_URI` is set; otherwise pytest reports it as explicitly skipped.

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

Optional capabilities use separate, bounded dependency groups:

```bash
pip install -r requirements-mongodb.txt
pip install -r requirements-postgresql.txt  # legacy compatibility only
pip install -r requirements-securebert.txt  # inference
pip install -r requirements-training.txt    # offline training
pip install -r requirements-vertex.txt
pip install -r requirements-artifacts.txt   # PDF + external STIX validation
pip install -r requirements-evaluation.txt  # offline comparisons
pip install -r requirements-dev.txt         # tests
```

Equivalent `pyproject.toml` extras are `mongodb`, `postgresql`, `securebert`,
`training`, `vertex`, `artifacts`, `evaluation`, and `test`. Core/test direct
and transitive versions verified in this workspace are pinned in
`constraints-core-test.txt`; optional compiled groups are bounded and require a
platform-specific resolved lock before production deployment. See
`docs/SUPPORT_STATUS.md` for the authoritative support boundary.

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
| Threat hypotheses | 45/45 broad factuality scenarios and 48/48 relationship-aware controlled scenarios passed; 41 expected relationships recovered with no synthetic false link | Developer-authored controlled implementation correctness, not expert validation or field accuracy |
| Historical weighted comparison | Held-out Top-1 0.8488, Top-3 0.9966, MRR 0.9201, Brier 0.216126 over 291 external weak-label examples | Proposal-only comparison; not current production architecture accuracy |
| External transition-model comparison | Hard-backoff Top-1 0.8076, MRR 0.8920, Brier 0.227558 over the same 291 held-out weak-label transitions; Dirichlet/Empirical-Bayes ranking metrics were identical and Brier was 0.227593 | Comparative SSH/Telnet mixed weak-label evidence; no Bayesian improvement or local accuracy claim |
| Zenodo COW160x4 one-member validation | Hard-backoff pooled Top-1 0.9820, balanced accuracy 0.7078, and normalized Brier 0.009580 over 9,788 held-out weak-label transitions | Additional SSH-only external validation, not replacement evidence; pooled accuracy is inflated by imbalance and regular transitions |
| Zenodo COW160x4 500 MB validation | Hard backoff and Dirichlet VOMM both reach pooled Top-1 0.5477; VOMM reaches MRR 0.7444, balanced accuracy 0.3375, and normalized Brier 0.232554 over 3,969 held-out weak-label transitions | Independent two-day SSH-only validation; materially less regular than the one-day sample, still imbalanced, and not replacement evidence |

Public summary artifacts:

- `evaluation/classification_benchmark.json`
- `evaluation/session_correlation_review.json`
- `evaluation/threat_hypothesis_factuality.json`
- `evaluation/threat_hypothesis_relationship_evaluation.json`
- `evaluation/threat_hypothesis_relationship_evaluation.csv`
- `evaluation/external_seed_weight_fit.json`
- `evaluation/external_seed_weight_sweep.json`
- `evaluation/next_tactic_external_session_payload.jsonl`
- `evaluation/next_tactic_model_comparison.json`
- `evaluation/next_tactic_model_comparison.csv`
- `evaluation/next_tactic_zenodo_session_payload.jsonl`
- `evaluation/next_tactic_zenodo_model_comparison.json`
- `evaluation/next_tactic_zenodo_model_comparison.csv`
- `evaluation/next_tactic_zenodo_500mb_session_payload.jsonl`
- `evaluation/next_tactic_zenodo_500mb_model_comparison.json`
- `evaluation/next_tactic_zenodo_500mb_model_comparison.csv`
- `evaluation/next_tactic_zenodo_500mb_tuned_comparison.json`
- `evaluation/next_tactic_zenodo_500mb_tuned_comparison.csv`

### Threat-hypothesis evaluation protocol

Run the controlled relationship benchmark with:

```bash
python -m production.tools.evaluate_threat_hypothesis_relationships
```

The 48 synthetic cases cover connected artifacts, non-matching paths, curl
semantics, pipelines, conditionals, Cowrie transfer linkage, duplicate and
unrelated commands, accounts and credential paths, outcomes, abstention, and
audit-only evidence. All 48 currently pass. Across the represented patterns,
the evaluator records 41 expected relationships, zero false links, and zero
missed links; controlled relationship precision, recall, evidence-reference
correctness, overclaim-free case rate, and abstention appropriateness are all
1.0. These values describe deterministic behavior on developer-authored cases.
They are not expert-reviewed field accuracy, attacker-intent accuracy, or proof
that unsupported shell patterns are handled correctly.

When private real-session reports are available, a structured single-reviewer
audit can supplement, but not replace, the controlled benchmark. Generate two
30-case templates outside Git:

```bash
python -m production.tools.score_threat_hypothesis_single_reviewer \
  --write-template-directory /tmp/threat-hypothesis-review \
  --case-count 30
```

Assign privately selected anonymized sessions to the generated pseudonymous
case IDs. Review round 1, wait one to two weeks, then review round 2 without
consulting round-1 labels. The second template reverses case order. Each round
records only `yes`, `no`, `uncertain`, or `not_applicable` for relationship
correctness, claim grounding, evidence-reference correctness, abstention, and
overclaim presence. The scorer rejects commands, notes, addresses, credentials,
and other extra fields. Score completed rounds into a private aggregate with:

```bash
python -m production.tools.score_threat_hypothesis_single_reviewer \
  --input /private/review_round_1.jsonl \
  --input /private/review_round_2.jsonl \
  --output /tmp/threat_hypothesis_single_reviewer_aggregate.json
```

The aggregate reports quality rates, repeat percentage agreement, and Cohen's
kappa when estimable, but no case identifiers. Report each round separately
alongside repeat agreement; the pooled descriptive rates do not make the two
reviews independent or double the effective sample size. It must be described
as a structured single-reviewer repeat assessment, not independent or expert
validation. No such result is claimed in this repository until genuine review
rounds have been completed.

Run the deterministic next-tactic comparison workflow against the checked-in,
privacy-minimized external tactic-sequence payload:

```bash
python -m production.tools.evaluate_next_tactic_model_comparison
```

The JSONL payload contains 52,018 completed usable anonymized sessions, of which
854 contain 1,840 adjacent-deduplicated tactic transitions. Its safe split has
51,758 train sessions, 126 calibration sessions, and 134 test sessions; the
held-out test sessions yield 291 transitions. It retains only
classifier-derived weak-label tactic/technique sequences and the original
whole-session split; it contains no commands, credentials, addresses,
timestamps, URLs, or original session identifiers. The source artifact did not
retain protocol metadata, and the upstream dataset covers SSH and Telnet, so
these results are explicitly SSH/Telnet mixed or protocol-unknown rather than
SSH-only performance.

The split is the original deterministic 70/15/15 stratification by first tactic
transition (seed `20260707`). It is not described as chronological because the
sessionized source artifact contains no timestamps. All transitions from a
session remain in one partition.

The proposed Bayesian row is external-prior-only in this run because no clean
local calibration corpus is included. It ties hard backoff on Top-1 and MRR and
is marginally worse on Brier score, so the available evidence does not justify
changing the runtime model.

### Zenodo COW160x4 one-member validation

The separate Zenodo evaluation processes one complete SSH daily member, not the
full 52-member corpus. Its privacy-minimized payload contains 32,157 labeled
sessions and 58,984 adjacent-deduplicated transitions. Whole sessions use a
chronological 70/15/15 split, producing 9,788 held-out transitions.

Pooled Top-1 must not be reported alone. Hard backoff reaches 0.9820 pooled
Top-1 but only 0.7078 balanced accuracy; first-order Markov reaches 0.9781
pooled Top-1 and 0.7805 balanced accuracy. For hard backoff, persistence Top-1
is 0.0417 over 120 examples. Privilege escalation has only nine held-out
examples and is descriptive-only, while credential access and lateral movement
have no held-out targets. Per-tactic Top-1, MRR, and Brier are considered
reportable only at support of at least 30; this threshold is a reporting guard,
not proof of statistical reliability.

The independent 500 MB extension uses two different daily members, June 29 and
August 17, separated by 49 days. Their ZIP-compressed data total 494,485,538
bytes. Private streaming ingestion observed 5,442,989 events; the public-safe
payload retains 47,027 closed sessions with explicit SSH protocol and trusted
tactic labels, yielding 28,991 transitions. Whole-session chronological splits
contain 32,918 train, 7,054 calibration, and 7,055 test sessions; the held-out
sessions yield 3,969 transitions. Three labeled sessions lacking explicit SSH
protocol were excluded rather than inferred to be SSH.

The larger raw byte volume does not provide more transition cases: this sample
has 28,991 trusted transitions versus 58,984 in the earlier one-day member.
Compressed size is therefore not a proxy for useful sequential evidence; the
main value of this extension is temporal diversity and changed per-tactic
support.

| Model | Pooled Top-1 | Top-3 | MRR | Normalized Brier | Balanced Top-1 | Coverage |
|---|---:|---:|---:|---:|---:|---:|
| Majority class | 0.5024 | 0.7105 | 0.6604 | 0.362567 | 0.1429 | 1.0000 |
| First-order Markov | 0.3356 | 0.9627 | 0.6471 | 0.363976 | 0.2238 | 1.0000 |
| Current hard-backoff VOMM | 0.5477 | 0.9025 | 0.7244 | 0.237167 | 0.3375 | 1.0000 |
| Dirichlet-smoothed VOMM | 0.5477 | 0.9116 | 0.7444 | 0.232554 | 0.3375 | 1.0000 |
| Fixed progression fallback | 0.2101 | 0.2101 | 0.2101 | 0.593141 | 0.2509 | 1.0000 |

The larger sample only partly reduces missing tactic support. Credential access
appears in the test set but has only five targets, while lateral movement is
still absent. Privilege escalation rises from 9 to 151 held-out targets and is
reportable at the configured threshold, but hard-backoff Top-1 remains low at
0.0993. Persistence has 491 targets and hard-backoff Top-1 of 0.0346, slightly
below the one-day value of 0.0417. Unlike the one-day result, first-order
Markov does not beat VOMM on balanced Top-1 (0.2238 versus 0.3375). Dirichlet
VOMM ties hard backoff on pooled Top-1 rather than uniquely winning, but
improves MRR and Brier. Discovery accounts for 1,994 of 3,969 held-out targets,
so pooled metrics remain class-imbalance-sensitive. The lower pooled accuracy
relative to the one-day sample is consistent with the earlier sample being
unusually regular; it is not evidence of a production-model regression.

### Zenodo 500 MB calibration-only model investigation

A separate evaluation-only investigation tests whether defensible calibration
can improve the 500 MB result without changing runtime policy. Run it with:

```bash
python -m production.tools.evaluate_zenodo_tuned_next_tactic
```

The tool uses the existing whole-session chronological split. Hyperparameters
are selected from the 21,147 training transitions and 3,875 calibration
transitions by deterministic two-pass coordinate search. The primary selection
objective is balanced Top-1 accuracy; pooled Top-1, MRR, normalized Brier,
coverage, and lower complexity are tie-breakers. Selected models are then refit
on train plus calibration and evaluated once on the unchanged 3,969-transition
test partition. Abstentions count as incorrect in pooled and balanced accuracy,
and no target tactic is removed.

| Model | Pooled Top-1 | Balanced Top-1 | MRR | Normalized Brier | Coverage |
|---|---:|---:|---:|---:|---:|
| First-order Markov | 0.3356 | 0.2238 | 0.6471 | 0.363976 | 1.0000 |
| Current hard-backoff VOMM | 0.5477 | **0.3375** | 0.7244 | 0.237167 | 1.0000 |
| External-only VOMM | 0.5477 | **0.3375** | 0.7244 | 0.237167 | 1.0000 |
| Tuned Dirichlet VOMM | 0.5437 | 0.3364 | 0.7397 | 0.239510 | 1.0000 |
| Tuned interpolated n-gram Markov | 0.5437 | 0.3364 | 0.7508 | 0.224062 | 1.0000 |
| Tuned configuration-aware VOMM | **0.6936** | 0.3208 | **0.8301** | **0.205796** | 1.0000 |

The configuration-aware model selects context length 4, minimum support 1,
alpha 0.01, kappa 20, no confidence abstention threshold, and no heuristic
fallback. It approaches but does not reach 70% pooled Top-1. More importantly,
its balanced Top-1 is lower than the incumbent, so the higher pooled score is
evidence of better modeling of dominant configuration-specific regularities,
not a uniform per-tactic improvement. It is therefore an evaluation result,
not a basis for replacing the runtime model.

The one-day result dropped from 98.20% because that member was unusually
regular: 9,371 of its 9,788 test targets (95.74%) were Command and Control,
Defense Evasion, or Execution. The 500 MB test instead contains 1,994 Discovery,
980 Execution, 491 Persistence, 335 Defense Evasion, and 151 Privilege
Escalation targets. Of those Privilege Escalation targets, 150 occur under
configuration 1, while calibration contains none and training contains only 12
across all configurations. This is temporal and configuration shift, not a
runtime regression that smoothing alone can repair.

Persistence improves under the configuration-aware model from 0.0346 to 0.1568
Top-1, but Privilege Escalation falls from 0.0993 to 0.0000. Credential Access
has only five test targets and remains descriptive-only at 0.0000 Top-1;
Lateral Movement has no held-out target, so its performance is not estimable.
No tested, calibration-selected model reaches 70% pooled Top-1, and none
improves both pooled and balanced accuracy over the incumbent.

These are repeated-holdout comparative results because the same test partition
was reported previously. Although test labels were not used for hyperparameter
selection, a fresh set of later daily members is required before treating any
future improvement as confirmatory evidence. Targets remain classifier-derived
weak labels rather than independent expert ground truth.

Zenodo therefore remains an additional external validation dataset, not a
replacement. Only two of 52 daily members have been processed in the 500 MB
extension. Full processing requires:

1. A private, non-Git, disk-backed session store for all 52 daily members.
2. Streaming only the event fields required for session ordering and sequence construction.
3. Frozen hybrid classification and trust filtering in bounded batches.
4. Complete cross-member session assembly and timestamp ordering before splitting.
5. A whole-session chronological 70/15/15 train/calibration/test split.
6. Pooled and per-configuration evaluation with macro, balanced, and per-tactic metrics.
7. Privacy validation of minimized outputs followed by removal of private staging data when no longer required.

The public package still excludes raw external telemetry and all local session
corpora. An optional local input must carry `session_source=production_live`
and `is_external_source=true` or it is excluded from local evaluation.

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

- host-specific cloud, VM, Raspberry Pi, firewall, SSH, HAProxy, Tailscale, and
  Internet-exposure deployment material (generic hardened systemd templates are
  included for review)
- real environment files, machine addresses, usernames, and absolute user paths
- raw Cowrie logs, session exports, databases, spools, reports, and payloads
- private shutdown/rollback bundles and historical task reports
- raw case-level telemetry and original session identifiers; the retained
  next-tactic JSONL contains only hashed IDs and privacy-minimized tactic labels
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
3. Confirm no host-specific deployment state, populated environment file, key,
   database, log, session export, or unreviewed generated report is staged.
4. Add the license selected by the project team.

**License decision required by project team.**
The team may choose a license such as MIT later if every project contributor agrees.
