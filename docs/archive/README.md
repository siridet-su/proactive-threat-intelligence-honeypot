# Historical-document register

These documents are retained because the project was inherited. They are
evidence of previous implementations, not instructions for the current system.
Do not delete or follow a document here until its facts are checked against the
current architecture and service catalog.

| Source | Classification | Reason |
| --- | --- | --- |
| `old-dashboard-2025/` | Archive | SQLite, Ngrok, OpenCanary, old dashboards, and earlier LLM setup. |
| `maintenance/pi-cleanup-audit/` | Archive | Point-in-time machine inventory and resource snapshots. |
| `maintenance/maintenance-log-2026-07-22.md` | Archive | Historical migration and firewall narrative; not a current runbook. |
| `docs/logs/` | Archive | Change/optimization history, including superseded network and schema details. |
| `docs/CHANGELOG-2026-07-22.md` | Archive | Useful Go-pipeline migration evidence; not a current service-status source. |
| `docs/HAILO_LLM_TEST_GUIDE.md` | Superseded | Uses an administrative SSH port as a test target and includes prohibited payload-execution steps. |
| `updates/hailo10h_report_20260722_123643.md` | Evidence | Hardware/driver snapshot, not a runtime guarantee. |
| `../adaptive-honeypot/STATUS.md` | Experiment evidence | Valuable POC chronology; split its current state from its test history before migration. |
| `../adaptive_honeypot_concept.md` | Design source | Preserve its deterministic-deception principles; roadmap and storage assumptions need reconciliation with Atlas/cloud architecture. |

## Migration method

1. Preserve the original location and add a link from a canonical document.
2. Extract only still-valid facts into a current design, ADR, runbook, or test
   evidence document.
3. Mark the original as `Archive`, `Experiment`, or `Superseded`.
4. Move files only in a dedicated documentation commit after all links have
   been updated.
