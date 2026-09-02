# Documentation index

This directory is the documentation entry point for the active honeypot
project. It separates deployed facts, accepted design, experimental evidence,
and historical material inherited from the previous team.

## Reading order

1. [Current architecture](CURRENT-ARCHITECTURE.md) — deployed components and
   intentional temporary states.
2. [Service catalog](SERVICE-CATALOG.md) — every exposed or supporting service,
   its owner, telemetry, and lifecycle status.
3. [Data ownership](DATA-OWNERSHIP.md) — which system owns each stage of data.
4. [Roadmap](ROADMAP.md) — current work ordered by dependency.
5. [Security and malware policy](SECURITY-AND-MALWARE-POLICY.md) — containment,
   artifact handling, and threat-intelligence boundaries.
6. [Architecture decisions](adr/) — durable decisions and their rationale.

## Document status labels

| Label | Meaning |
| --- | --- |
| **Current** | Verified deployed state or an operating policy. |
| **Target** | Accepted direction that is not yet fully deployed. |
| **Experiment** | POC or test evidence; not approved for production by itself. |
| **Legacy** | Inherited implementation that is not the target architecture. |
| **Archive** | Historical evidence; never use as a current runbook. |

## Rules

- Each concern has one canonical document in this directory.
- `CURRENT-ARCHITECTURE.md` is a snapshot, not a chronological log.
- Record decisions in an ADR before a cross-component change is implemented.
- Put reproducible test results in `validation/evidence/`; promote only their
  conclusion to a design or ADR.
- Do not put secrets, real API keys, raw attacker credentials, raw payloads, or
  private endpoint details in documentation.
- Do not delete inherited documents while consolidating them. Classify and link
  them from [archive/README.md](archive/README.md) first.

## Existing documents awaiting consolidation

- `../adaptive-honeypot/` is the adaptive-shell POC and its test evidence.
- `honeypot-analysis/` is the active post-session/cloud-analysis workstream.
- `old-dashboard-2025/`, `maintenance/`, and `docs/logs/` contain inherited
  history and snapshots, not current operational instructions.
- `../decoy-honeypot/docker-compose.yml` is currently the deployment source of
  truth for the Docker decoy stack. A dedicated design/runbook will be added
  before that configuration is materially changed.
