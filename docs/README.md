# Documentation index

This directory is the documentation entry point for the active honeypot
project. It separates deployed facts, accepted design, experimental evidence,
and historical material inherited from the previous team.

## Reading order

1. [Current architecture](CURRENT-ARCHITECTURE.md) — deployed components and
   intentional temporary states.
2. [Implementation log](IMPLEMENTATION-LOG.md) — append-only record of repository
   changes, host application, active state, and deferred verification.
3. [Service catalog](SERVICE-CATALOG.md) — every exposed or supporting service,
   its owner, telemetry, and lifecycle status.
4. [Data ownership](DATA-OWNERSHIP.md) — which system owns each stage of data.
5. [Roadmap](ROADMAP.md) — current work ordered by dependency.
6. [Filesystem Activity live working state](FILESYSTEM-ACTIVITY-WORKING-STATE.md) — active Dashboard Filesystem backlog, current focus, and completion evidence.
7. [Security and malware policy](SECURITY-AND-MALWARE-POLICY.md) — containment,
   artifact handling, and threat-intelligence boundaries.
8. [Architecture decisions](adr/) — durable decisions and their rationale.
9. [Honeypot Portal & Customer Installer Blueprint](HONEYPOT-PORTAL-INSTALLER-GUIDE.md) — proposed outbound gateway, scoped control plane, safe installer contract, and delivery gates.
10. [Validation evidence](validation/README.md) — bounded staging checks and inventory snapshots.
11. [Pi installer VM test target](INSTALLER-VM-TEST-TARGET.md) — clean Ubuntu Server 24.04 ARM64 VM requirements and safe evidence to return before host-dependency work continues.
12. [คู่มือติดตั้งภาษาไทยสำหรับคัดลอกลง Word](INSTALLATION-MANUAL-WORD-TH.md) — ขั้นตอนเตรียม VM และ host foundation สำหรับทดสอบ; ยังไม่รับรองก่อนผ่าน VM
13. [Installation Manual — Word-ready draft](INSTALLATION-MANUAL-WORD.md) — ลำดับโมดูลและรายละเอียดเป้าหมายทั้งระบบ พร้อมระบุ release blockers. โปรไฟล์เริ่มต้นของ installer ครอบคลุมเฉพาะ host foundation; full-system profile แยกต่างหาก. CLI มีเฉพาะ read-only `preflight`, `package-audit`, และ `plan`; `scripts/build_sensor_release.py` สร้าง checksummed ARM64 Go-agent bundle เท่านั้น ไม่ได้ติดตั้ง

The event contract and retrieval steps for fake ERP login attempts are in
[Web-corp login telemetry](design/web-login-telemetry.md), the
[web-corp runbook](../integrations/web-corp/README.md), and its
[data-access guide](../integrations/web-corp/DATA-ACCESS.md).
The optional Web-corp client source-port capture and trusted-proxy boundary are
recorded in [ADR-0006](adr/ADR-0006-web-client-source-port.md).
The status boundary between the active HTTP decoy work and candidate future
work is summarized in [HTTP decoy scope](design/http-decoy-scope.md).
The not-yet-deployed public-IP HTTPS/VPS/WireGuard target procedure is in the
[web-corp public-VPS HTTPS runbook](../integrations/web-corp/PUBLIC-VPS-HTTPS.md).

The tracked decoy source runbooks are [FTP](../integrations/ftp/README.md) and
[SMTP](../integrations/smtp/README.md). Both services are stopped/future work;
their intended behavior and adapter gaps are recorded in the
[service catalog](SERVICE-CATALOG.md).

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
- For every implementation, append a dated entry to
  `IMPLEMENTATION-LOG.md` in the same change. Record repository edits and
  deployed state separately; label changes that are prepared but not active.
- Keep the log factual and append-only. Correct prior entries with a dated
  addendum instead of silently rewriting audit history.
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
- `../decoy-honeypot/docker-compose.yml` remains the deployment source of truth
  for the Docker decoy stack, outside this Git worktree. The corporate web
  application source is tracked in [`integrations/web-corp/`](../integrations/web-corp/README.md);
  its build-context decision is recorded in [ADR-0005](adr/ADR-0005-corporate-web-decoy-source.md).
  Consolidation of the full Compose stack is deferred.
