# Why the legacy sensor forwarder exists

Status: existing Pi runtime only; omitted from the clean-host installer.

`honeypot-sensor-forwarder.service` is inherited from the earlier cloud
analysis path. It tails the Pi's sanitized Cowrie `cowrie.json`, keeps an
owner-only bounded local spool and quarantine so transient delivery failures
do not immediately lose events, and sends authenticated batches to the GCP
ingest API. The receiving API validates and sanitizes again, binds each event
to the authenticated sensor identity, then writes it into its configured
canonical storage. The forwarder needs an ingest token, but it does not hold
MongoDB credentials or enrichment provider keys on the Pi.

This is separate from the current Go collector → Redis → processor → Atlas
`honeypot_db` route. Some Dashboard investigation code still reads the older
`honeypot_canonical_v1` collections, so disabling the existing Pi forwarder
may stop new records on those views even while Go telemetry continues. The
fresh Pi installer intentionally does not install the forwarder. A future
retirement of the existing Pi service requires a per-view read-path inventory,
record parity check, and an explicit cutover to the surviving event source.

The code and operator configuration are in
[`sensor_forwarder.py`](../honeypot-analysis/production/workers/sensor_forwarder.py),
[`ingest_api.py`](../honeypot-analysis/production/api/ingest_api.py), and the
[legacy systemd runbook](../honeypot-analysis/deployment/systemd/README.md).
Never copy the current token, ingest URL, spool contents, or private host
configuration into a developer checkout.
