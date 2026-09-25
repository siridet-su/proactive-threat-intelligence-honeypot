# SMTP sink

> **Lifecycle: future work, stopped.** The SMTP container was stopped on
> 2026-09-25 and is not part of the active web-login collection scope. The
> source/build context is retained for later integration. The deployment
> Compose file is outside this repository and still defines the service; a
> full-stack `docker compose up` may start it again. Do not reactivate it until
> a normalized data adapter and dashboard integration are reviewed.

This directory is the tracked source and Docker build context for the SMTP
decoy. It uses Python 3.11 and aiosmtpd.

The sink accepts recipient and message data with 250 replies, records only
the peer IP, envelope sender/recipients, and message byte count in its
application log, then discards the message. It does not relay mail, persist
the message body or attachments, or send events to Deception Core, Redis, or
MongoDB. It currently has no normalized telemetry adapter.

When enabled, the external Compose service builds from this directory and
publishes host port 127.0.0.1:25 only. The process binds 0.0.0.0:25 inside its
container. The container is currently stopped, so there is no host listener on
port 25. When enabled, that host binding is local-only, not exposed to ZeroTier
or the public network. No TLS or authentication is configured.
The previous sibling SMTP source files are retained unchanged as a rollback
copy; edit this repository path as the canonical source.

No SMTP test suite existed in the sibling source tree at import time. The
image build and Compose configuration are validated separately; no mail was
submitted during this source import.
