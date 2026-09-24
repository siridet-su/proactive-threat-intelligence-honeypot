# Design specifications

Documents in this directory define accepted interfaces and constraints before
implementation begins. A design is not proof of deployment; implementation and
staging evidence belong in `../validation/`.

| Design | Status | Purpose |
| --- | --- | --- |
| [Threat intelligence](threat-intelligence.md) | Target | Asynchronous VirusTotal and AbuseIPDB enrichment. |
| [Decoy-stack telemetry](decoy-stack-telemetry.md) | Target | Bring Docker decoy events into the common event model. |
| [Web-corp login telemetry](web-login-telemetry.md) | Current | Admin-only event path for fake ERP login attempts, with credential retention in MongoDB, raw Redis input, and SQLi indicators. |
| [Adaptive Cowrie boundary](adaptive-cowrie-boundary.md) | Target | Production boundary for the raw-command gateway. |
| [Returning-attacker continuity](returning-attacker-continuity.md) | Future | Bounded per-actor virtual filesystem overlay after identity, telemetry, retention, and isolation gates. |
| [Post-session analysis contract](post-session-analysis-contract.md) | Target | Atlas-to-cloud handoff and evidence-safe results. |
| [Honeypot dashboard UX](honeypot-dashboard-ux.md) | Target | Investigation-first dashboard navigation, layouts, and TI presentation. |
| [Dashboard v2 UX review](dashboard-v2-ux-review-2026-09-20.md) | Review | Current implementation findings covering data meaning, duplication, hierarchy, and responsive behavior. |
| [Dashboard v2 implementation phases](dashboard-v2-implementation-phases.md) | Plan | Contract-first phased rollout with regression gates and compatibility-safe cutovers. |
| [Atlas Free Tier data lifecycle](atlas-free-tier-data-lifecycle.md) | Target | Retention, TTL, index, and rollup constraints for the 512 MB tier. |
| [Honeypot Portal & Customer Installer](../HONEYPOT-PORTAL-INSTALLER-GUIDE.md) | Target | Outbound WSS gateway, scoped actions, and transactional customer-appliance design. |
