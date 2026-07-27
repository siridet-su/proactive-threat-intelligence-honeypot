# Development

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

Optional dependencies are installed only for their scoped work. Core imports
and `--help` must work without MongoDB, Torch/Transformers, Vertex, ReportLab,
or STIX validation libraries.

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
python -m production.policies.validate_smb_policy \
  --action-policy configs/smb_action_playbooks.trusted.json
```

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

Use canonical behavioral evidence references and scope. Add adversarial tests
for prediction-only input, copied provenance, malformed scopes, stale nested
guidance, policy drift, and historical point-in-time display.

### Storage change

Maintain SQLite transaction/lease semantics and backend contract tests.
Migration preflight must validate every record before destination writes and
leave SQLite unchanged. MongoDB changes remain future/offline until separately
authorized.

## Generated artifacts

Caches, databases, checkpoints, logs, benchmark runs, temporary reports, local
keys, and environments are ignored. Commit evidence only after privacy,
provenance, claim, size, and reproducibility review. See
[RETENTION_POLICY.md](RETENTION_POLICY.md).
