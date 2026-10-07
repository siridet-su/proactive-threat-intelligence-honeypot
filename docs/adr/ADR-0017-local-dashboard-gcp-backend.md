# ADR-0017: Run the Dashboard UI locally while keeping the backend on GCP

- Status: Accepted; local-to-GCP integration is not yet qualified
- Date: 2026-10-08
- Supersedes: ADR-0016 only for Dashboard deployment placement; its Admin-only
  command-evidence and canonical-session safeguards remain applicable.

## Context

The operator requested that the Dashboard UI run on the local workstation,
while backend services continue running on the replacement GCP VM. Railway and
Cloudflare-hosted Dashboard access are not part of the requested demonstration
path. The VM had separate production and staging Dashboard v2 services, and a
root-run watchdog whose protected target list included both services.

The Dashboard is a server-rendered application with server-side MongoDB-backed
authentication and a backend-for-frontend (BFF). Its current default BFF
origin is a loopback monitor endpoint. Running the app locally therefore does
not by itself establish a safe route to the GCP API; it also must not result in
production database credentials being copied into browser code or an
unreviewed workstation environment. The current end-to-end local-to-GCP flow
has not been tested.

## Decision

- Run the Dashboard UI process on the operator's workstation from an approved
  local checkout. Do not run the GCP production or staging Dashboard v2
  services for the current operating mode.
- Keep the backend, canonical storage, and model/analysis workers on GCP at
  their already-reviewed network bindings. Do not add a public API listener or
  broaden a firewall rule to make the local UI connect.
- Before calling the local UI operational, define and test a server-side,
  authenticated private route from the local Dashboard BFF to the GCP backend.
  The browser must use same-origin Dashboard routes; it must not receive a
  MongoDB URI, API bearer token, or other backend secret.
- Do not copy the production MongoDB URI to the workstation as a shortcut. If
  local server-side database access is later required, first approve a
  least-privilege account and document its credential storage, rotation, and
  revocation.
- Keep the GCP watchdog timer disabled until its protected target list is
  reconciled with the local-UI mode and its source/configuration is reviewed.
  Its current target list includes the intentionally stopped Dashboard
  services. This pause also suspends its periodic checks for other configured
  targets and must be addressed before declaring operations fully ready.
- Preserve ADR-0016's Admin authentication, exact canonical session binding,
  bounded query, no-store response, and sensitive-evidence rules. Its hosted
  production placement is not the current UI deployment mode.

## Consequences

The GCP Dashboard v2 and staging services are stopped and disabled, with their
unit definitions retained in the host's protected backup area. The local UI
remains an implementation target, not a qualified service: authenticated
login, BFF routing, session detail, command evidence, PDFs, and report
generation must pass an end-to-end test before the workflow is described as
ready. Backend health checks alone do not qualify the browser path.

The watchdog timer is also inactive pending target review; no watchdog code or
protected config was edited. The release pointer, backend services, database,
Model2 runtime files, and network/firewall were not changed by this decision.

## Revisit when

The local BFF-to-GCP authentication and private transport have been implemented
and tested, or the operator changes the Dashboard hosting requirement. Any
re-enablement of a hosted UI or watchdog timer must update the reviewed target
inventory and current-state documentation first.

## Operational addendum — 2026-10-08

The intended native-local UI was not established. To let the operator reach
the existing staging build while retaining the backend on GCP, the staging
service was enabled on the replacement VM at loopback `127.0.0.1:3001`; the
operator's workstation reaches it through an SSH local forward bound to its
own `127.0.0.1:3001`. The staging `/login` route returned HTTP 200 through that
forward. No public listener, firewall rule, production Dashboard service, or
backend release pointer was changed. The staging environment explicitly opts
into non-Secure cookies for this HTTP-over-loopback path; the app must not be
exposed on a LAN or public interface. Its env backup remains root-only on the
VM.

This is a temporary operational exception to the decision above, not a change
of target architecture and not evidence that a local Next.js process is
running. In one authenticated session inspection, Model1 evidence, threat
hypotheses, TTP ranking, and a session-bound Next-Distinct prediction were
returned. Response Guidance for the stored report was rejected because its
referenced policy 3.8.0 could not be resolved by the active runtime, and the
PDF endpoint returned HTTP 503 while validating that report. External TI was
pending with no provider call; the AI worker was inactive, so no live AI API
request was tested. A separate SSH test attempt was not accepted as a verified
Cowrie session because the target service identity and resulting canonical
session could not be confirmed. These checks do not qualify the complete
demonstration flow.

The staging UI may be used for limited inspection through the SSH forward, but
do not describe Response Guidance, PDF generation, external TI, AI API, or a
fresh-session end-to-end demonstration as ready until their individual gates
pass. The production UI and recovery-watchdog timer remain disabled. The
active backend release and Model2 configuration remain unchanged; the release
manifest/rollback and canonical MongoDB recovery gates still block backend
cutover.
