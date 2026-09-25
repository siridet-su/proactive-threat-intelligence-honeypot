# FTP decoy

> **Lifecycle: future work, stopped.** The FTP container was stopped on
> 2026-09-25 and is not part of the active web-login collection scope. The
> source/build context is retained for later integration. The deployment
> Compose file is outside this repository and still defines the service; a
> full-stack `docker compose up` may start it again. Do not reactivate it until
> credential handling, a normalized data adapter, and dashboard integration
> are reviewed.

This directory is the tracked source and Docker build context for the
read-only FTP door. The service uses Python 3.11, pyftpdlib, and HTTPX.

## Behavior and data flow

- The FTP account is loaded from static_contents.odoo_conf_content in the
  shared VFS schema at VFS_SCHEMA_PATH. The schema is deployment data shared
  with Deception Core and is intentionally not copied into this repository:
  it contains credential-like decoy configuration and other personas.
- The account has pyftpdlib permissions elr (change directory, list, and
  retrieve); upload, delete, and directory creation are not granted.
- The service creates four bait files under FTP_ROOT: two dated .sql.gz
  backup names, a customer export, and an invoice export. These are synthetic
  lures, not authoritative Odoo or PostgreSQL backups.
- Login attempts and FTP activity are sent to Deception Core (/v1/track).
  Failed login commands currently include the attempted username and
  password, so Core's events.jsonl and session database are
  credential-sensitive. Do not dump those stores into routine logs or reports.
- Retrieving a known lure calls Core /v1/decide; the returned decoy content
  replaces that bait file before FTP sends it. This is separate from the Go
  collector/Redis/MongoDB event pipeline; FTP has no adapter into that
  canonical event path yet.

## Deployment boundary

The active Compose file remains the sibling
/home/cpe27/decoy-honeypot/docker-compose.yml. Its FTP build context now
points to this directory. The shared VFS schema remains a read-only mount from
that deployment tree; do not add it or its credential-like values to Git
without a separate review.
The previous sibling FTP source files are retained unchanged as a rollback
copy; edit this repository path as the canonical source.

At the 2026-09-24 historical runtime check, the container published FTP
control port 21 and passive ports 30000-30009 on ZeroTier 10.58.33.42; its
configured masquerade address was also 10.58.33.42. Deception Core's /health
returned 200 from inside the FTP container. It is now stopped, so those
bindings are not current. A TCP greeting was received in the historical check
without authenticating; a full login/LIST/RETR transfer was not run.

Known follow-up: the current greeting is "220 220 ProFTPD 1.3.8a Server
ready." because the configured banner includes a response code that pyftpdlib
adds itself. The container process runs as root inside the container and no
Docker health check is configured. These remain future work items; the service
is not currently running.
