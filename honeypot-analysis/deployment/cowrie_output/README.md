# Cowrie pre-persistence credential output boundary

This bundle replaces only Cowrie's persistent JSON and diagnostic observers
and binds their external rotation policy.
It does not patch Cowrie source, mutate historical logs, or replace the
downstream forwarder sanitizer.

The v2 bundle manifest also binds the exact reviewed starting sanitizer,
installed Cowrie/Python/Twisted compatibility, receipt schemas, managed
destinations, and service impact. The installer verifies the starting link and
the fully extracted bundle before changing the active link.

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

The immutable bundle and diagnostic/legacy logs are owner-only. The sanitized
`cowrie.json` feed is `cowrie:cowrie` mode `0640` so only Cowrie and the
existing forwarder (via its supplementary `cowrie` group) can use the required
file boundary. Existing historical and rotated files are content-preserved,
hash-receipted, and restricted to `0600`; they are never rewritten.

The diagnostic observer is a closed categorical projection. It never persists
Cowrie's arbitrary preformatted text, because local Cowrie extensions can
embed authentication values before structured credential fields exist. The
service also discards direct stdout/stderr; systemd still retains lifecycle and
exit state without persisting untrusted process text.

Cowrie's daily writer rotates the JSON feed by rename and reopen, allowing the
forwarder to identify and drain the old inode before reading the new feed. The
external logrotate policy deliberately handles only the non-authoritative text
log: applying `copytruncate` to JSON would permit a rapid-regrowth race against
the forwarder's offset checkpoint. Before either rotation mechanism runs, the
active file becomes owner-only; the current JSON feed returns to `0640`, while
every historical or compressed file remains `0600`.

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
- `/etc/logrotate.d/cowrie`
- owner/group/mode metadata for existing credential-bearing Cowrie files

The transaction treats configuration, policy, deployment scripts, and the
current-component symlink as immutable inputs. Pre-stop service information,
the package hash, checkout-status hash, and preliminary managed-file hashes
are diagnostic records only. They are not rollback authority for an active
log. The active JSON feed and forwarder offset/state remain outside the
installer's content-mutation boundary; the running forwarder is never stopped
or restarted. Historical logs retain their content and receive only recorded
owner/mode restoration. Python bytecode and other generated runtime data are
forbidden inside immutable releases.

Before any candidate extraction, the installer follows this order:

1. create a fresh owner-only non-overwriting receipt and record diagnostics;
2. request a bounded Cowrie stop and require inactive state, `MainPID=0`, and
   an empty surviving service cgroup;
3. reject a missing, linked, non-regular, or process-held active text log;
4. atomically move that stable inode into the receipt as
   `cowrie.log.protected.before`, fsync it and both directories, and only then
   calculate its final size and SHA-256;
5. capture the remaining stopped-state metadata, seal the v2 receipt, and
   independently verify its digest, saved hashes, closed paths, types,
   ownership, and modes;
6. extract and verify the candidate only after the receipt is accepted.

The active diagnostic log is never copied, rewritten, truncated, or deleted
by capture. A capture or seal failure moves its exact inode back to the
original destination with its original owner and mode before Cowrie is
restarted. A later installation failure stops Cowrie, rejects a process-held
failed log, applies the verified receipt, removes only the exact incomplete
candidate release, reloads systemd, and restarts only Cowrie. Recovery also
requires the prior component link, a healthy Cowrie, and the original running
forwarder PID. Incomplete seals are renamed as owner-only evidence and cannot
be accepted as rollback receipts.

The source checkout is not reset, normalized, or overwritten. The stock
`cowrie.output.jsonlog` remains present but must be disabled.

Validate before and after restart:

```sh
sudo -u cowrie env \
  PYTHONPATH=/opt/honeypot-cowrie-output/current \
  HONEYPOT_COWRIE_OUTPUT_ROOT=/opt/honeypot-cowrie-output/current \
  HONEYPOT_COWRIE_CONFIG=/home/cowrie/cowrie/etc/cowrie.cfg \
  HONEYPOT_COWRIE_ROOT=/home/cowrie/cowrie \
  PYTHONDONTWRITEBYTECODE=1 \
  /home/cowrie/cowrie/cowrie-env/bin/python \
  -m production.tools.cowrie_output_integration validate \
  --config /home/cowrie/cowrie/etc/cowrie.cfg \
  --bundle-root /opt/honeypot-cowrie-output/current \
  --plugin-link /home/cowrie/cowrie/src/cowrie/output/sanitizedjson.py \
  --drop-in /etc/systemd/system/cowrie.service.d/20-sanitized-output.conf \
  --logrotate /etc/logrotate.d/cowrie \
  --live-permissions
```

## Rollback

New installs write a sealed `cowrie_output_rollback_receipt.v2` JSON Lines
receipt plus an exact SHA-256 sidecar. The rollback program parses and verifies
the complete receipt and every saved-file hash before stopping Cowrie or
touching a managed path. It also accepts the retained legacy actual-tab and
literal-`\\t` receipts, after closed-field, owner/mode, path, and ambiguity
validation.

Verify the receipt owner, mode, receipt digest, and saved-file hashes before
rollback. Then restore only the managed integration boundary:

```sh
sudo /opt/honeypot-cowrie-output/current/deployment/cowrie_output/rollback-sanitized-output.sh \
  /var/backups/honeypot/cowrie-output-UTC_TIMESTAMP
```

Rollback verifies the receipt before touching the service, then requires the
bounded stop, zero main PID, an empty surviving cgroup, and no descriptor on an
active failed text log. It restores prior configuration, symlinks, drop-in
state, the quarantined baseline log, and recorded metadata; it reloads systemd
and restarts only Cowrie. A failed-deployment text log, if present, is retained
owner-only in the receipt. It does not rewrite or delete historical Cowrie
event logs. Because the prior observer is known to persist credentials,
rollback is an emergency recovery boundary, not an acceptable steady state.
Reapply the verified bundle before any credential acceptance replay.
