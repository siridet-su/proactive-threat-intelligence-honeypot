# Final next-tactic production activation

## Result

`PRODUCTION_ACTIVATION_SUCCEEDED`

The previously verified candidate was activated after correcting the disabled
pre-existing GCP TCP/2222 firewall rule. The candidate remained active through
the final restart and 15-minute observation.

## Identity and rollback

- Repository commit: `3c79ae155021ca4cf0ab6d744211d884c4ee039e`
- Active release and marker: `3c79ae155021ca4cf0ab6d744211d884c4ee039e`
- Package SHA-256: `c30c4984a161385210c9fe5559c40c0c4f304351c611f18ec1130ff9d8940068`
- Deployment manifest SHA-256: `c92e4a9e8e837392226c0a633ce067d1de6af718e523ea671567f1fc3314989c`
- Release-tree SHA-256: `de42745d53548390af08315432cdab2d7420dff281708ff22db14b300d47ca31`
- Fresh backup: `/var/backups/honeypot/cowrie-connectivity-20260801T231500Z/production_pilot.db`
- Backup SHA-256: `00ed27d31c32f9b7116514a31d05c77ae91843c4924a866ecfbc973e571ee04b`
- Guard receipt: `/var/backups/honeypot/cowrie-connectivity-20260801T231500Z/activation_guard_receipt.json`
- Final guard state: `ACTIVATION_COMPLETED`
- Recovery release: `19afabd0bb7ed82ac93767301bb0cb1024d0b92e`

The frozen model bundle, policy hashes, and Transformer artifacts were
re-verified before activation. No model, classification, assessment, guidance,
or prediction behavior changed.

## Connectivity and E2E

The public listener accepted a real Cowrie connection after enabling only the
existing correctly scoped firewall rule. HAProxy forwarded with PROXY protocol
to the Pi backend. Fresh sessions produced sanitized JSON, durable events,
prediction snapshots, completed outbox rows, and successful analysis reports.
The exact public source address is intentionally omitted from this committed
report.

For the final sessions, all event processing outcomes were `succeeded`; two
analysis jobs succeeded on their first attempt. Prediction snapshots contained
no `recommendations` field and retained `predictive_alert.status=prohibited`.
Credential-marker count in new event payloads was zero. The benign test marker
was present only as expected observed command evidence. No new alerts or
webhook deliveries were created.

Both final JSON reports passed `session_assessment.v4`, `response_guidance.v3`,
STIX, and artifact-integrity validation. Guidance safety fields remained
manual approval required, automatic execution false, response side effects
false, and alerting side effects false. Dashboard and monitor prediction APIs
returned HTTP 200 and the same current snapshot ID.

## Restart and observation

Exactly the eight approved application services were restarted. All remained
active, with zero failed units and zero restart-counter increments. The three
health endpoints remained live. Queues stayed empty, the worker lease remained
stable, and SQLite quick-check remained `ok` throughout 30 observation samples
over the bounded 15-minute window. TCP/2222 stayed listening and the HAProxy
backend stayed `UP`. Free space remained approximately 4.7 GiB.

The isolated restore rehearsal passed before activation. The temporary restore
and packet captures were removed; production databases, releases, backups,
manifests, and model bundles were retained.

## Final releases

- GCP: candidate `3c79ae155021ca4cf0ab6d744211d884c4ee039e`
- Pi: unchanged accepted release `5bb3b97fbe3b9034c70fc6ca2aba0ad9d159bb02`

The reversible infrastructure rollback is to disable the existing firewall
rule. The application rollback is the guarded pointer rollback to the recovery
release using the retained receipt and fresh backup.
