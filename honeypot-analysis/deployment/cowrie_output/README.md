# Cowrie pre-persistence credential output boundary

This bundle replaces only Cowrie's persistent JSON and diagnostic observers.
It does not patch Cowrie source, mutate historical logs, or replace the
downstream forwarder sanitizer.

The design and authority boundary are recorded in
`docs/COWRIE_UPSTREAM_CREDENTIAL_PRIVACY_DECISION.md`.

## Clean package

Build from an extracted `git archive` of an exact full revision, not from a
mutable checkout:

```sh
python -m production.tools.cowrie_output_integration build \
  --source-root /path/to/clean-git-archive \
  --bundle-root /path/to/staging/bundle \
  --revision FULL_GIT_REVISION
tar -C /path/to/staging/bundle -cf \
  cowrie-output-FULL_GIT_REVISION.tar .
```

The builder includes only the closed file inventory required by the
integration. Every file, the policy, and the Git revision are bound by
`COWRIE_OUTPUT_MANIFEST.json`. Directories are mode `0700`, data/code files
are mode `0600`, and executable deployment scripts are mode `0700`.

## Install

Capture the current Cowrie configuration, service state, integration paths,
dirty-checkout status hash, file metadata, and package hash before calling the
installer. The installer performs that capture again in a new non-overwriting
receipt and refuses an existing release or receipt:

```sh
sudo deployment/cowrie_output/install-sanitized-output.sh \
  /path/to/cowrie-output-FULL_GIT_REVISION.tar \
  FULL_GIT_REVISION \
  /var/backups/honeypot/cowrie-output-UTC_TIMESTAMP
```

Only these managed integration points change:

- `/opt/honeypot-cowrie-output/releases/FULL_GIT_REVISION`
- `/opt/honeypot-cowrie-output/current`
- `/home/cowrie/cowrie/etc/cowrie.cfg` output sections
- `/home/cowrie/cowrie/src/cowrie/output/sanitizedjson.py`
- `/etc/systemd/system/cowrie.service.d/20-sanitized-output.conf`
- owner/group/mode metadata for existing credential-bearing Cowrie files

The source checkout is not reset, normalized, or overwritten. The stock
`cowrie.output.jsonlog` remains present but must be disabled.

Validate before and after restart:

```sh
sudo -u cowrie env \
  PYTHONPATH=/opt/honeypot-cowrie-output/current \
  HONEYPOT_COWRIE_OUTPUT_ROOT=/opt/honeypot-cowrie-output/current \
  HONEYPOT_COWRIE_CONFIG=/home/cowrie/cowrie/etc/cowrie.cfg \
  HONEYPOT_COWRIE_ROOT=/home/cowrie/cowrie \
  /home/cowrie/cowrie/cowrie-env/bin/python \
  -m production.tools.cowrie_output_integration validate \
  --config /home/cowrie/cowrie/etc/cowrie.cfg \
  --bundle-root /opt/honeypot-cowrie-output/current \
  --plugin-link /home/cowrie/cowrie/src/cowrie/output/sanitizedjson.py \
  --drop-in /etc/systemd/system/cowrie.service.d/20-sanitized-output.conf \
  --live-permissions
```

## Rollback

Verify the receipt owner, mode, `managed-paths.tsv`, and saved-file hashes
before rollback. Then restore only the managed integration boundary:

```sh
sudo /opt/honeypot-cowrie-output/current/deployment/cowrie_output/rollback-sanitized-output.sh \
  /var/backups/honeypot/cowrie-output-UTC_TIMESTAMP
```

Rollback restores prior configuration, symlinks, drop-in state, and recorded
metadata; it reloads systemd and restarts only Cowrie. It does not delete a
release or rewrite/delete any Cowrie event log. Because the prior observer is
known to persist credentials, rollback is an emergency recovery boundary, not
an acceptable steady state. Reapply the verified bundle before any credential
acceptance replay.
