# Development

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

Optional dependencies are installed only for their scoped work. Core imports
and `--help` must work without Torch/Transformers, ReportLab, or STIX
validation libraries.

## Validation

```bash
python -m compileall -q production
pytest -q
```

Use focused suites first for storage, ingest security, prediction runtime,
reports/guidance, and authority boundaries. Socket-dependent tests may require
an environment that permits loopback sockets; distinguish sandbox blocking
from assertion failures.

Validate policies explicitly:

```bash
python -m production.policies.validate_prediction_policy \
  --policy configs/prediction_policy.transformer_poc.trusted.json
python -m production.policies.validate_classification_rules \
  --policy configs/classification_rules.trusted.json
python -m production.policies.validate_response_guidance_policy \
  --policy configs/response_guidance_policy.v3.json
```

The only supported prediction runtimes are the frozen Transformer policy and
the explicitly configured, hash-validated VOMM rollback policy. The only
supported experiment CLI is:

```bash
python -m production.tools.reproduce_next_behavior_experiment --help
```

Internal modules under `production.reproduction.next_behavior` are libraries
for that CLI, not independently supported command-line programs.

## Safe changes

### Classifier rule

Add reviewed provenance and bounded conditions, validate the whole policy, then
add positive, negative, compound-command, audit-only, and secret-containment
tests. A label is not proof of command success or impact.

### Model or prediction change

Create a new immutable artifact and manifest. Freeze preprocessing,
vocabulary, classifier/trust policy, memberships, selection rule, calibration,
metrics, authority restrictions, and environment before opening any untouched
test. Never tune after Final access or silently reinterpret stored snapshots.

### Guidance change

Use `response_guidance.v3` and immutable canonical observed evidence. Add
adversarial tests for prediction/enrichment-only input, policy/profile hash
drift, malformed references, automatic-execution attempts, deterministic IDs,
and historical read-only adapter display. Only `sensitive_read` and the
direct-event slice of `transfer` are activated typed-semantic families. A
transfer command remains an attempt and cannot select specialized output; an
eligible transfer requires a direct Cowrie event and exact SHA-256. Do not
activate another family without its own reviewed decision, closed policy
requirements, shadow comparison, and positive/negative/ambiguous acceptance
matrix. Do not write guidance into prediction snapshots or derive alerting
from it.

### Storage change

Maintain SQLite transaction, migration, lease, backup, and restore semantics.
Adding another backend is a new design requiring its own durable contract and
operational evidence; it is not a compatibility toggle.

## Generated artifacts

Caches, databases, checkpoints, logs, benchmark runs, temporary reports, local
keys, and environments are ignored. Commit evidence only after privacy,
provenance, claim, size, and reproducibility review. See
[RETENTION_POLICY.md](RETENTION_POLICY.md).
