# Cowrie live JSON observer divergence

This record contains only privacy-safe structural facts observed during the
read-only production comparison and disposable exact-version reproduction. It
contains no raw events, credentials, commands, addresses, session IDs, logs,
journals, or production data.

## Root-cause decision

The verified classification is:

- `LIVE_EVENT_NOT_ROUTED_TO_PLUGIN`
- `OBSERVABILITY_DEFECT`

The prior acceptance client connected directly to Cowrie's HAProxy endpoint.
That endpoint requires a PROXY-protocol header supplied by the real upstream
proxy. A direct SSH client without the header caused Twisted/Cowrie transport
diagnostics, so the categorical observer advanced, but the custom transport
never established the session identity required by Cowrie's output-base
`emit()` filter. No eligible event was routed to any output plugin. The flat
JSON size and forwarder offset therefore did not prove that the sanitized
plugin had been rejected or had failed to write.

The exact-loader reproduction made two direct, credential-free connections to
the HAProxy endpoint. The categorical descriptor advanced from 3,245 to 4,436
bytes while the sanitized JSON descriptor remained at zero. A control SSH
connection through the ordinary TCP endpoint then produced five valid,
newline-terminated sanitized records, including session-connect, client,
login-success, and session-close categories. The generated credential was
absent from both JSON and categorical output. This proves the observer and
writer worked when Cowrie emitted eligible events and explains the earlier
shape without changing sanitization behavior.

## Effective environment comparison

| Property | Disposable exact-version loader | Effective `cowrie.service` |
|---|---|---|
| Entry point | real `twistd ... -n cowrie` path used by the managed launcher | `/opt/honeypot-cowrie-output/current/deployment/cowrie_output/run-sanitized-cowrie.sh` |
| Python | 3.12.3 exact virtual environment | `/home/cowrie/cowrie/cowrie-env/bin/python`, 3.12.3 |
| `sys.prefix` | disposable Python 3.12.3 virtual environment | `/home/cowrie/cowrie/cowrie-env` |
| Twisted | 25.5.0 | 25.5.0 |
| Cowrie | Git `575146bc6b24d70082527d66cd805d9bae0e0db4` plus reviewed local transport/output-base changes | same Git revision and reviewed dirty checkout |
| Working directory | copied Cowrie root | `/home/cowrie/cowrie` |
| Identity | unprivileged disposable owner with owner-only state | unprivileged `cowrie:cowrie`; one recorded non-privileged supplementary group |
| umask | `0077` | systemd `UMask=0077` |
| configuration order | `etc/cowrie.cfg.dist`, then `etc/cowrie.cfg` | same two-file order |
| enabled output sections | only `output_sanitizedjson` | only `output_sanitizedjson` |
| module search | bundle before Cowrie `src` | active manifest bundle before Cowrie `src` |
| environment | closed service-equivalent names; no secrets | output root, config, Cowrie root, `PYTHONPATH`, and no-bytecode values from the reviewed drop-in; no credential binding |
| output module | source-tree link resolving to manifest regular file | same layout under the active release |
| JSON destination | Cowrie-root-relative canonical `var/log/cowrie/cowrie.json` | `/home/cowrie/cowrie/var/log/cowrie/cowrie.json` |
| lifecycle destination | Cowrie-root-relative owner-only runtime state | `/home/cowrie/cowrie/var/lib/cowrie/cowrie-output-lifecycle.json` |
| process streams | categorical test logger | categorical logger; direct stdout/stderr discarded |
| filesystem boundary | owner-only copied runtime | systemd `ProtectSystem=full`; only reviewed Cowrie runtime paths writable |
| mandatory access control | host controls observed separately | no blocking SELinux/AppArmor rule was observed for the effective paths |

The exact installed output-loader SHA-256 is
`b6fc9e6c90a519404724b1a0d6cbd40281858fdfcd61af9a5fe7411c8d241b37`.
The exact installed output-base SHA-256 is
`0ccf8afde9797efc2a9a94569e37ab68f6727b563f09d09d96449b102868b0e3`.
Cowrie derives `sanitizedjson` from `[output_sanitizedjson]`, imports
`cowrie.output.sanitizedjson`, constructs `Output()` with no arguments, calls
its base constructor (which calls `start()`), then registers `output.emit`.
The class is concrete and inherits Cowrie's exact `Output` base. The loader
catches `ImportError` and ordinary `Exception`, records a failure, and
otherwise continues; service-active state alone is therefore insufficient
evidence.

## Corrective boundary

The correction does not alter event semantics or listeners. It adds:

1. a manifest-bound structural check of effective configuration, import path,
   module hash, concrete class, loader/base hashes, and writable destinations;
2. owner-only, closed, self-hashed lifecycle state for discovery,
   construction, start, registration, invocation, serialization, open, write,
   flush, and stop categories;
3. a post-start check bound to the actual service PID and observer registry;
4. fail-closed reactor shutdown requests for registration, serialization,
   write, short-write, and flush failures;
5. an opt-in acceptance test that launches the real Cowrie loader, performs a
   real SSH authentication/session, validates native JSON rotation, restarts
   Cowrie, and drives the real forwarder parser/state through exactly-once mock
   acknowledgement.

Acceptance must use the ordinary externally routed SSH endpoint or supply a
valid PROXY header to the HAProxy endpoint. Categorical-only activity is never
accepted as proof of an attacker event, sanitized JSON delivery, or forwarding.
