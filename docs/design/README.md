# Design specifications

Documents in this directory define accepted interfaces and constraints before
implementation begins. A design is not proof of deployment; implementation and
staging evidence belong in `../validation/`.

| Design | Status | Purpose |
| --- | --- | --- |
| [Threat intelligence](threat-intelligence.md) | Target | Asynchronous VirusTotal and AbuseIPDB enrichment. |
| [Decoy-stack telemetry](decoy-stack-telemetry.md) | Target | Bring Docker decoy events into the common event model. |
| [Adaptive Cowrie boundary](adaptive-cowrie-boundary.md) | Target | Production boundary for the raw-command gateway. |
| [Post-session analysis contract](post-session-analysis-contract.md) | Target | Atlas-to-cloud handoff and evidence-safe results. |
| [Honeypot dashboard UX](honeypot-dashboard-ux.md) | Target | Investigation-first dashboard navigation, layouts, and TI presentation. |
