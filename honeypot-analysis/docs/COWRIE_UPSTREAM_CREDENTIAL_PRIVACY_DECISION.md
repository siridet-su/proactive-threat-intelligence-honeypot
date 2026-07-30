# Cowrie upstream credential-persistence decision

Status: selected for implementation  
Repository baseline:
`4749e7d04e052ff79c911cadcc7f68ac370017bd`  
Installed Cowrie version: `2.6.1`  
Installed Cowrie Git revision:
`575146bc6b24d70082527d66cd805d9bae0e0db4`

## Scope

This decision addresses only the P0 boundary in which attacker-supplied login
credentials can reach durable Pi files before the existing forwarder
sanitizer. It does not change Cowrie protocol behavior, session semantics,
classification, prediction, guidance, response authority, GCP services, or
historical data.

The required path is:

```text
Cowrie event
→ repository-owned sanitizing persistent observers
→ sanitized Cowrie JSON log
→ existing defense-in-depth forwarder sanitizer
→ spool, ingest, SQLite, and artifacts
```

## Verified installed behavior

Cowrie loads output modules from configuration sections named
`output_<engine>`:

```python
engine = section.split("_")[1]
import_module(f"cowrie.output.{engine}").Output()
```

The loader catches ordinary import and initialization exceptions and
continues, so configuration alone cannot prove fail-closed behavior.

The active process is equivalent to:

```text
twistd --umask=0022 --pidfile=var/run/cowrie.pid \
  --logger cowrie.python.logfile.logger -n cowrie
```

Two unsafe persistent observers are active:

1. `[output_jsonlog] enabled=true` writes `cowrie.json` with mode `0664`.
2. `cowrie.python.logfile.logger` formats the original Twisted event into
   `cowrie.log`; it also persisted the synthetic credential used by the prior
   acceptance test.

The customized checkout also contains two direct legacy writers outside the
output-plugin pipeline:

- `/home/cowrie/cowrie/var/log/cowrie/cowrie_custom.json`
- `/home/cowrie/users.txt`

The SSH `users.txt` write is currently below an explicit unreachable return,
but the Telnet path can still write both files. They must therefore be treated
as active unsafe fallbacks, not ignored because one SSH test did not exercise
them.

The checkout has 132 modified/untracked/inaccessible status entries. Its
existing source and historical logs must not be normalized, reset, or folded
into this repository.

## Options

### 1. Repository-owned Cowrie output/observer plugin

Decision: **ACCEPT, with a companion persistent diagnostic observer**.

A separately named `cowrie.output.sanitizedjson` module fits Cowrie's existing
configuration loader and can reuse Cowrie's event/session/timestamp handling
while replacing values immediately before JSON serialization. It is installed
as one managed symlink into the Cowrie output namespace; the symlink target is
an immutable, manifest-bound repository release.

An output plugin alone is insufficient because the main Twisted logger sees
the original event independently.

### 2. Repository-owned event filter before the JSON observer

Decision: **REJECT as the primary design**.

Cowrie 2.6.1 registers the main Twisted logger before output plugins. A filter
inside one output observer cannot prevent another observer from formatting the
original event, nor can it intercept direct `open(..., "a")` writes in the
custom Telnet code. Global monkey-patching of Twisted dispatch would create a
fragile, ordering-dependent runtime overlay.

### 3. Configuration-supported custom output module

Decision: **ACCEPT as the activation mechanism, not as a complete solution**.

`[output_sanitizedjson]` can activate the repository module and
`[output_jsonlog]` can be explicitly disabled. Because Cowrie catches module
load failures, an `ExecStartPre` validator and a sanitizer-backed `--logger`
are also required. Configuration without those gates could appear healthy
while producing no safe JSON log.

### 4. Replace the default JSON writer with a repository-owned sanitized writer

Decision: **ACCEPT through replacement-by-name; REJECT overwriting
`jsonlog.py`**.

The new writer uses a distinct engine name. The stock tracked
`src/cowrie/output/jsonlog.py` remains byte-for-byte unchanged and disabled.
Replacing that tracked file, even with a reproducible copy, would make the
already dirty checkout harder to audit and roll back.

### Rejected post-persistence approaches

The following are rejected:

- tailing and rewriting `cowrie.json`;
- redacting a rotated file after credentials were first written;
- deleting or mutating historical logs;
- relying only on the downstream forwarder;
- dropping whole authentication events when safe fields can be retained;
- disabling SSH or Telnet merely to avoid the privacy boundary.

## Selected design

The selected integration is a small immutable bundle containing:

1. A strict `cowrie_output_privacy_policy.v1` contract.
2. A canonical Cowrie credential-event sanitizer shared with the existing
   persistence sanitizer.
3. `cowrie.output.sanitizedjson`, which sanitizes before `json.dump`.
4. A Twisted logger factory that sanitizes before persistent text formatting.
5. A validator for configuration, policy/code hashes, manifest, symlink
   target, permissions, process command line, and active writer identity.
6. A systemd drop-in that:
   - sets `UMask=0077`;
   - runs the validator before startup;
   - starts `twistd` with the repository logger;
   - makes `users.txt` and `cowrie_custom.json` read-only inside Cowrie's mount
     namespace.
7. Packaging, installation, receipt, and rollback tooling.

Only these managed integration points may change on the Pi:

- one immutable bundle below `/opt/honeypot-cowrie-output/releases/`;
- `/opt/honeypot-cowrie-output/current`;
- one symlink named
  `/home/cowrie/cowrie/src/cowrie/output/sanitizedjson.py`;
- the `[output_jsonlog]` and `[output_sanitizedjson]` configuration sections;
- `/etc/systemd/system/cowrie.service.d/20-sanitized-output.conf`;
- owner/group/mode metadata for Cowrie logs and the two historical direct
  credential files;
- a non-overwriting deployment/rollback receipt.

No tracked Cowrie source file is overwritten.

## Sanitization contract

The contract uses closed, versioned key sets and preserves the event shape.
Credential value keys include reviewed username/password/passphrase/secret
variants. Nested mappings and sequences are traversed with a depth bound.
Credential container keys are traversed when structured and redacted when
scalar. Login summary messages are replaced as a whole because Cowrie's stock
message embeds `username/password`.

The output retains, when present:

- event type;
- timestamp and order;
- session identifier;
- authentication success/failure;
- source/destination address and port fields;
- sensor identity;
- protocol context;
- non-credential evidence fields.

The current lifecycle decision does not permit durable attacker username
plaintext, so username variants remain redacted. Metadata records only the
names of removed fields, sanitizer schema, and
`credential_plaintext_removed=true`.

A bounded process-local registry captures credential values before replacing
them so later diagnostic strings containing the same values can also be
scrubbed. Login/credential-labelled unstructured diagnostics are replaced
whole. Registry and traversal limits fail closed rather than spilling the raw
value.

## Direct legacy writer containment

The customized Telnet code writes credentials directly to
`cowrie_custom.json` and `users.txt`, bypassing Twisted observers. Rewriting
that custom source would exceed the managed integration boundary.

Both files already exist. The systemd drop-in exposes them read-only to the
Cowrie process. Existing content and hashes remain unchanged. The customized
code catches write failures and continues the protocol session; the safe
standard Cowrie authentication event remains available through the sanitized
writer. The files are restricted to mode `0600` on the host.

## Fail-closed behavior

Before Cowrie starts, `ExecStartPre` must prove:

- the manifest and all required file hashes match;
- the stock JSON writer is disabled;
- exactly the reviewed sanitized JSON writer is enabled;
- the plugin symlink resolves into the active immutable bundle;
- the policy is valid and hash-bound;
- the repository logger command is configured;
- the direct legacy files are read-only in the service sandbox;
- file and directory permissions meet the contract.

The repository logger repeats manifest/policy/config validation during Python
initialization. A failure raises before the Twisted application starts.

The JSON plugin repeats the same validation and uses `SystemExit`, which is
not swallowed by Cowrie's `except Exception` output-loader path. Individual
malformed events are rejected with a fixed non-secret diagnostic and are not
serialized.

The stock writer is never used as a fallback.

The sanitized JSON feed is `cowrie:cowrie` mode `0640`, not `0600`, because
the existing dedicated `honeypot-forwarder` service has supplementary group
`cowrie` and must read this feed. The feed contains no credential or username
plaintext. The diagnostic log, direct legacy files, manifest, policy, and
bundle content remain owner-only at mode `0600` (directories and executables
`0700`). This is the narrowest permission compatible with the required
sanitized-JSON-to-forwarder path.

Post-start validation must prove:

- Cowrie is active;
- the process command line names the repository logger;
- the safe engine reports as loaded;
- the unsafe engine does not report as loaded;
- the sanitized JSON feed is mode `0640` and other credential-bearing logs are
  mode `0600`;
- the forwarder remains active.

## Rollback boundary

The deployment receipt stores the exact prior configuration, prior systemd
drop-in state, plugin-link state, hashes, modes, active service state, and
bundle/package hashes. Rollback restores only those managed integration
points, reloads systemd, and restarts Cowrie. It does not restore, rewrite, or
delete any Cowrie event log or `users.txt`.

Rollback is tested at this integration boundary before privacy acceptance is
declared complete.
