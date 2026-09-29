# Deception Core build source

Status: **source copied from the active Pi build context on 2026-09-28; built
locally on x86-64 but not deployed from this repository**. This directory contains only the
Python source, Dockerfile, and synthetic decoy schemas required by the active
Core image. It excludes the Pi's `.env`, backups, runtime databases, event
logs, private certificates, stopped-service configuration, and build caches.

The fresh-install [Compose source](../../deploy/decoy-honeypot/README.md)
builds this directory as one Docker context. The imported Core configuration
now requires `PGPASSWORD` from the operator-managed environment; the previous
hard-coded fallback was removed during import. The Dockerfile's multi-source
`COPY` destinations were corrected for the classic Docker builder. Do not use this repository
source as an in-place replacement for the running Pi container until the
image is built, tested, and a rollback is prepared.
