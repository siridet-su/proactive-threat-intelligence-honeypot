# Model2 V7 public-HTTP transfer binding (2026-09-24)

## Scope

This release changes the Pi Model2 transfer capture/observer/offline verifier and
the GCP Model2 receiver only. It does not change Cowrie, the model artifact,
training, MongoDB schema/data, reviewed policies, firewall, or dashboard source.
The original model/feature/binding contract SHA-256 constants remain unchanged.

## Root cause and fix

The Pi capture, observer, offline verifier, and GCP receiver all required
`1.1.1.1:80`, so a real `file_download` to a different host had no matching
packet tuple. The Pi capture now retains bounded outbound public HTTP traffic
from the existing Pi source IP. The observer selects a tuple only when one
captured HTTP GET has the same host/path fingerprint as the Cowrie download
event within the session window. Pi offline verification checks the selected
tuple, a unique SYN, and the matching HTTP request in the retained PCAP.
The GCP receiver validates tuple boundaries and event counts before inference.

The V6 observer intentionally omitted URLs. V7 therefore stores/transmits only
`download_request_sha256` for HTTP host/path; the raw URL is not added to
Model2 event snapshots. It is a fingerprint, not a confidentiality guarantee
against guessing common URLs. Unsupported HTTPS, ambiguous requests, a reused
TCP connection without a new SYN, or absent packet evidence remain unavailable.
The widened capture filter keeps the existing 8 × 8 MiB PCAP ring and excludes
common non-public destination ranges; the result selector rejects all
non-global IPv4 destinations. Packet data remains on Pi in owner-restricted
ring/retained evidence, and no raw HTTP payload is sent to GCP by this fix.

## Verification

- Unit tests: `python3 -m pytest -q honeypot-analysis/tests/test_model2_v7_transfer_binding.py` — 5 passed.
- Deployed files were compared by SHA-256 to their isolated candidate before installation.
- Pi services: `model2-v7-pi-capture-transfer.service`, `model2-v7-pi-observer.service` active.
- GCP service: `model2-v7-receiver.service` active.
- Fresh public Cowrie session `session_v1_78cba28f4491929f84ca8eb72bd9e42e`
  (sensor session `12f09749dc26`) downloaded `http://example.org/` successfully.
  Model2 spool: `VALID_SHADOW / AVAILABLE`, transfer flow count 1,
  PCAP/Zeek/source binding PASS, artifact/run/measurement/episode present.
  Session-detail API shows the same run binding and `PARTIAL` Model2 coverage:
  T1105 and T1110 heads available, T1046 not observed. Model2 T1105 predicts
  ABSENT for this case; that prediction is not overwritten by the observed
  transfer or promoted to a trusted finding.
- Negative E2E: sensor session `544bb136a9b0` reused an earlier TCP flow to
  `example.com`; offline verifier rejected it as
  `transfer_pcap_tuple_ambiguous` because no new SYN belongs to that session.
- Receiver event snapshot for the successful session has one download
  fingerprint and no raw URL field.

## Rollback

The deploy script retained the previous files under
`/var/backups/model2-transfer-20260924` (initial), `...-r2` (fingerprint),
and `...-r3` (receiver digest). The last deploy only restarted
`model2-v7-receiver.service`; earlier stages restarted the two Pi Model2
services as well. The script automatically restores its immediate predecessor
on install or health-check failure. Cross-session flow reuse remains an
intentional unavailable case, not a reason to relax the evidence gate.
