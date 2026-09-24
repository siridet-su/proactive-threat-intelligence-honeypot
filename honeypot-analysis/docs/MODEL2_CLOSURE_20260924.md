# Model2 closure decision — 2026-09-24

Scope: close the present Model2 shadow-integration audit without claiming
validated detection accuracy or changing the model, sensor topology, policy,
firewall, MongoDB, or historical sessions.

## Evidence checked

- GCP `model2-v7-receiver.service` was active. The GCP receiver's installed
  capstone and sensor-binding helper hashes matched the tested r4 candidate.
- `session_v1_37d6e920ad42f498109fe3bab26481e3`: two Cowrie login failures;
  session-detail HTTP 200 reports Model2 T1110 `PRESENT / MODEL2_ONLY`, T1105
  `ABSENT`, T1046 unavailable, and zero bounded hypothesis sets. This short
  session has no stored PDF (report endpoint HTTP 404).
- `session_v1_ada027dc2079cfc32a51ccff1e3c957f`: four decoy-port probes
  during a Cowrie session, but no exact session identity in sensor receipts.
  Detail reports T1046 unavailable; Model2-only T1105 and T1110 `PRESENT`
  are unverified shadow false-positive candidates. PDF endpoint returned
  HTTP 200 with `application/pdf`.
- `session_v1_d174981a35ea61887178e6fe196caba6`: after r4 receiver
  hardening, PCAP/Zeek PASS and Model2 `VALID_SHADOW`, but unbound sensor flows
  were excluded. Detail reports T1046 unavailable and T1105/T1110 `ABSENT`.
  PDF endpoint returned HTTP 200 with `application/pdf`.

## Acceptance boundary

T1105 and T1110 may be shown as session-bound *experimental shadow outputs*
when their run/measurement/episode binding is complete. `PRESENT` from Model2
alone is not a canonical finding, observed behavior, or response instruction.
The tests above demonstrate pipeline operation, not model sensitivity,
specificity, or generalization.

T1046 stays unavailable at session level. The GCP decoy sensor sees TCP
connections separate from the Cowrie SSH connection, and its current receipts
carry no independently verifiable Cowrie session identity. IP/time overlap is
source-level context only. The local candidate distinguishes that context from
no nearby receipt, without promoting either to a finding. The source-level
diagnostic, dashboard wording, and PDF comparison table are **candidate-only**
until a coordinated immutable application release is reviewed and installed.
The deployed GCP r4 receiver already excludes unbound flows from Model2 input.

## Verification limits and release status

- The existing PDF endpoints were checked for status and MIME type only; PDF
  content was not exported from production. A full-PDF transfer to local for
  text extraction was rejected because it could exfiltrate sensitive content.
- Local Python assessment/PDF tests passed 40/40 after `reportlab` and `pypdf`
  were installed into an isolated `/tmp` test directory. The PDF fixture
  verifies the bounded T1110 `MODEL2_ONLY` comparison and its experimental
  warning without using production report data. Dashboard component tests
  passed 12/12 and TypeScript type checking passed. `next build --webpack`
  succeeded. The default Turbopack build could not bind its CSS worker's
  ephemeral local port in this environment (`Operation not permitted`); this
  was not treated as a code-level failure or a successful default build.
- The production application still points to the chronology-r8 immutable
  release. No new dashboard/application release or epoch receipt was installed
  in this closure audit. The candidate code must not be described as live UI
  or PDF behavior. Existing unrelated dashboard login edits were untouched.

No further simulated sessions are needed to close this limited shadow audit.
An exact-session T1046 producer would be a separate telemetry/topology project,
not a relaxation of the current gate.
