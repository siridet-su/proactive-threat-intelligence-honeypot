# Cowrie pre-persistence credential privacy handoff — 2026-07-30

## Outcome

The P0 source-log credential privacy blocker is resolved.

Cowrie now uses a repository-owned, manifest-bound JSON output plugin and
Twisted diagnostic logger that remove credential plaintext before the first
persistent write. The stock JSON writer is disabled. The two customized
direct credential files are read-only inside the Cowrie service. The
downstream forwarder sanitizer remains as defense in depth.

No GCP application release, database, model, policy authority, semantic
family, prediction behavior, response behavior, networking, or historical
record content was changed.

This handoff deliberately stops before the broader rollback, load, restart,
or recovery stabilization plan.

## Revisions and repository state

- Branch: `professor-approved-poc-evaluation`
- Starting revision:
  `4749e7d04e052ff79c911cadcc7f68ac370017bd`
- Final implementation revision:
  `7f764ab471e8dac555d06277b4613237299aee69`
- GCP application revision, unchanged:
  `325d136a35f4e9b6cf197cc05565a0798f7b3e14`
- Installed Cowrie revision, unchanged:
  `575146bc6b24d70082527d66cd805d9bae0e0db4`
- Cowrie status entries: 133, comprising the prior 132 entries plus the one
  managed `src/cowrie/output/sanitizedjson.py` symlink.
- Stock `cowrie.output.jsonlog` SHA-256, unchanged:
  `b25558820d9e8e45cc3c7cb70e0d8233e0cc30e2c438d7590750f4418cfacf65`

Commits:

1. `7d613a9ad88c5de0d77708e7b1916c0b315dcd89` —
   `Select fail-closed Cowrie credential output boundary`
2. `be67bd425dfb383ea261a815804174f745a64c9e` —
   `Sanitize Cowrie credentials before persistent output`
3. `3c6e354245792db98d4f816c35a5cf48b74464ef` —
   `Keep Cowrie output bundles immutable at runtime`
4. `abe52cdae5b667e93d507bd8be3a8b6ab64c0914` —
   `Record customized Cowrie checkout state reliably`
5. `4d49c1a12bc3006d3a20517df4e15ddc7234d57a` —
   `Preserve executable modes in Cowrie bundle installs`
6. `aa6cbb622c9f9b88d64335a665ef97826a60e83c` —
   `Expose verified Cowrie bundle to startup validation`
7. `3271f610c2b539a9c382bf220a3000d2eb3dbbe2` —
   `Grant the forwarder read-only sanitized log access`
8. `389cd430f672fea3e1eb6da89c267b7795cda780` —
   `Restrict historical Cowrie log permissions`
9. `7f764ab471e8dac555d06277b4613237299aee69` —
   `Exclude active Cowrie logs from historical hash receipts`

This document is committed separately. Its commit cannot be embedded in its
own contents; use `git log -1 --format='%H %s'`.

## Root cause and correction

### Root cause

Four independent paths could persist login credentials before the existing
forwarder sanitizer:

1. enabled stock `cowrie.output.jsonlog`;
2. Cowrie's plaintext Twisted diagnostic logger;
3. customized Telnet `cowrie_custom.json` writes;
4. customized `users.txt` writes.

The stock plugin and diagnostic logger both observed the original event. A
filter inside only one observer could not protect the other. The customized
direct files bypassed both observers.

### Selected boundary

The final path is:

```text
Cowrie event
→ manifest-validated repository sanitizer
→ sanitized Cowrie JSON
→ existing forwarder sanitizer and spool
→ authenticated ingest
→ SQLite, analysis, predictions, report and artifacts
```

The implementation adds:

- `configs/cowrie_output_privacy.v1.json`;
- dependency-free shared sanitizer
  `production/utils/cowrie_privacy.py`;
- `cowrie.output.sanitizedjson`;
- sanitizing Twisted diagnostic logger;
- strict manifest/config/plugin/drop-in/permission validator;
- clean bundle builder and config renderer;
- install/rollback scripts and systemd drop-in;
- focused privacy, fail-closed, manifest, permission, rotation and restart
  tests.

The unsafe `output_jsonlog` is disabled, exactly
`output_sanitizedjson` is enabled, and plugin initialization uses
`SystemExit` so Cowrie's `except Exception` loader cannot silently continue.
The service `ExecStartPre` and both persistent observers independently verify
the bundle and policy.

The systemd boundary keeps `UMask=0077`, uses the reviewed logger command, and
binds these direct legacy files read-only:

```text
/home/cowrie/users.txt
/home/cowrie/cowrie/var/log/cowrie/cowrie_custom.json
```

The sanitized JSON feed is `cowrie:cowrie` mode `0640` because the dedicated
`honeypot-forwarder` process reads it through supplementary group `cowrie`.
It contains no attacker username or credential plaintext. Diagnostic,
legacy, manifest and bundle files are `0600`; bundle directories and scripts
are `0700`. All rotated historical Cowrie logs are `0600`.

Rejected alternatives are documented in
`docs/COWRIE_UPSTREAM_CREDENTIAL_PRIVACY_DECISION.md`: post-write rewriting,
tail-and-redact, forwarder-only sanitization, an in-place patch to the dirty
Cowrie checkout, a global Twisted monkey patch, overwriting stock
`jsonlog.py`, or dropping whole authentication events.

## Final component and deployment receipts

Active Pi release:

```text
/opt/honeypot-cowrie-output/releases/7f764ab471e8dac555d06277b4613237299aee69
```

Active link:

```text
/opt/honeypot-cowrie-output/current
```

Final release identities:

- component ID:
  `cowrie_output_7253a624cef4a9ef96bb6c1cae715002`
- clean package SHA-256:
  `d71f39fd9d57dade7b4a17705e56b81b9c1327493560cfa87b777b289a50b512`
- manifest SHA-256:
  `714d04608d7385490000edef2effddbdad948fd065820e35fdebef29ada0f39d`
- policy SHA-256:
  `439c11f1f88da9873be9ab62ab7f4ae98a7b8a7c73116362a5f4c7a20d47cf76`
- shared sanitizer SHA-256:
  `4e5ad7b4c93b49288cd3e48f0fdae145b62e48abf8ce239c66751775198aeaa8`
- sanitized JSON plugin SHA-256:
  `fd02475916787ed5e38f0102247a7805fb9a3cc9ac9830cfb836708148dd0033`
- sanitizing logger SHA-256:
  `5366ae869aef348bec6bd7a9b238dff78ac22346fc49b188b2a54460c9213013`
- systemd drop-in SHA-256:
  `607c40fdd3e766ce6505b219d5deb5b2889327fd8dd8f5204dc7e10d84935d47`

Final Pi deployment receipt:

```text
/var/backups/honeypot/cowrie-output-20260730T114805Z
```

Receipt identities:

- `historical-log-hashes.before.sha256` SHA-256:
  `30390983ebf3695eab78a63b127e6e911d7f1b8da2547b738f0f7a8a3ab11430`
- all historical hashes verified after the metadata-only restriction;
- historical files with a non-`0600` mode: zero;
- no historical file was rewritten, truncated, deleted, or rotated by the
  deployment.

Before/after Cowrie configuration:

- before SHA-256:
  `0aca806473d7b64106aebe96161d63588d8587333e3a6a798e3be15cfcb0a6a6`
- reviewed post-integration configuration SHA-256:
  `002932230b85f2c7c354caf4c8f9d7b163428500dae14c08641384f610ce5515`
- before: `[output_jsonlog] enabled=true`;
- after: `[output_jsonlog] enabled=false` and
  `[output_sanitizedjson] enabled=true` with bundle, manifest, policy and log
  paths bound to `/opt/honeypot-cowrie-output/current`.

Final observed permissions:

```text
0640 cowrie:cowrie /home/cowrie/cowrie/var/log/cowrie/cowrie.json
0600 cowrie:cowrie /home/cowrie/cowrie/var/log/cowrie/cowrie.log
0600 cowrie:cowrie /home/cowrie/users.txt
0600 cowrie:cowrie /home/cowrie/cowrie/var/log/cowrie/cowrie_custom.json
0600 cowrie:cowrie COWRIE_OUTPUT_MANIFEST.json
0700 root:root     /var/backups/honeypot/cowrie-output-20260730T114805Z
```

The pre-existing direct-file contents remain unchanged. Their final hashes
are:

- `users.txt`:
  `375afcb3a3eef64dd6f85807256156ca8f9bf58167d5de89d0a513886344869d`
- `cowrie_custom.json`:
  `7664add3e6056feca381ab5ce80da1d9e8e85efc0a15606cb9cc5fb9ffbe433a`

## Tests and validators

Final local results:

- focused Cowrie privacy suite: `14 passed`;
- privacy/forwarder focused regression: `38 passed`;
- final full suite: `996 passed, 7 skipped`;
- `python -m compileall -q production`: passed;
- prediction policy validation: passed;
- reviewed classification policy validation: passed;
- response-guidance policy validation: passed;
- threat-hypothesis behavior policy validation: passed;
- typed-semantic vocabulary load/whole-contract validation: passed;
- Cowrie output privacy policy validation: passed;
- shell syntax validation for all integration scripts: passed;
- `git diff --check`: passed.

The first sandboxed full run had the known eight loopback
`PermissionError` failures plus one new optional-import regression. The
optional-import defect was corrected; every subsequent full run with
loopback permitted passed. The final exact revision result is the result
reported above.

Clean, non-persistent Pi Cowrie 2.6.1 smoke testing proved:

- manifest and policy validation passed;
- sanitized JSON mode `0640`;
- diagnostic log mode `0600`;
- successful-login credential did not occur in either output;
- no bundle bytecode or unmanifested runtime file was created.

The installed final validator reports:

```text
schema_version=cowrie_output_boundary_validation.v1
status=valid
git_revision=7f764ab471e8dac555d06277b4613237299aee69
manifest_sha256=714d04608d7385490000edef2effddbdad948fd065820e35fdebef29ada0f39d
policy_sha256=439c11f1f88da9873be9ab62ab7f4ae98a7b8a7c73116362a5f4c7a20d47cf76
```

Cowrie and the forwarder are active with no failed Pi units. The live Cowrie
command uses:

```text
twistd --umask=0077 --logger production.cowrie_output.twisted_logger.logger -n cowrie
```

`cowrie.log` records `Loaded output engine: sanitizedjson`; no unsafe output
engine is enabled.

## Controlled E2E and authority regression

The direct private-listener session:

- session: `fc18cbb983b7`;
- events processed: 13/13;
- analysis job: succeeded;
- report:
  `report_25b55c0e5f5ddaff412a945bba3d09f6`;
- prediction snapshots: six;
- completed prediction outbox rows: six;
- pending prediction outbox rows: zero;
- alerts: zero;
- webhook deliveries: zero.

The report passed complete `session_assessment.v4` validation. Its embedded
`response_guidance.v3` passed validation, all actions require manual approval,
all actions are non-executable, and all prediction snapshots contain no
`recommendations` key. The report authority states observed evidence is
authoritative while predictions, enrichment, correlations and generated
prose are non-authoritative; automatic alerts and automatic response are
false.

Generated JSON, Markdown, native PDF, STIX and integrity-manifest files all
exist at mode `0600` with recorded SHA-256 values. The PDF contained two
ASCII85/Flate streams; both were decoded for the credential scan.

HAProxy remained active at GCP `:2222` with `send-proxy` to Pi `:2224`.
An internal controlled HAProxy session produced Pi/GCP session
`110c24682935`; its tagged event was processed successfully. The public
address timed out from the Codex execution network before authentication, so
public-Internet reachability is
`NOT_DETERMINABLE_FROM_THIS_EXECUTION_NETWORK`. The actual HAProxy PROXY
protocol path was verified through the GCP listener.

GCP remained on revision `325d136…`; six relevant services were active,
SQLite `PRAGMA quick_check` returned `ok`, there were zero controlled-session
alerts, zero pending controlled-session outbox rows, and zero webhook
deliveries. No GCP service was restarted or changed.

## Exact-marker privacy acceptance

The synthetic credential was 59 bytes and never printed, placed in an
argument, committed, or retained. Its one-way SHA-256 receipt is:

```text
8e452e932928eb3521ae8506eadaff941136adc5c6cb1faecc9e58ca18745991
```

Pi scan:

- 418 files;
- 4,846,281,296 bytes;
- Cowrie active/rotated/compressed logs, `users.txt`, forwarder state/spool,
  `/var/log`, `/tmp`, Cowrie and forwarder journals;
- journal bytes: 564,428;
- matching paths: zero;
- journal match: false;
- unreadable paths: zero.

GCP scan:

- 22,216 files;
- 9,638,828,866 bytes;
- active SQLite, WAL/SHM when present, reports, JSON/Markdown/PDF/STIX
  artifacts, `/var/log`, `/tmp`, HAProxy/ingest/session/analysis journals;
- journal bytes: 4,790;
- matching paths: zero;
- journal match: false;
- unreadable paths: zero.

PDF decoded-stream scan:

- PDFs: one;
- streams decoded: two;
- matching paths: zero.

No new database backup was created after correction, so there was no new
backup/isolated restore in the acceptance scope. Existing verified backups
predate this unique marker and were neither modified nor replaced.

The corresponding Pi and GCP login records remain present with event ID,
session, timestamp, source, sensor and success status. Username, password and
login summary are `[REDACTED]`, with
`cowrie_credential_sanitizer.v1` metadata and
`credential_plaintext_removed=true`.

Historical pre-fix logs still contain the earlier, different synthetic
credential. They were not mutated or deleted. All are now restricted to mode
`0600`. This is a retained historical-data limitation, not a failure of the
new marker acceptance.

## Rollback evidence and commands

A full active integration rollback was rehearsed before privacy acceptance:
the managed symlink, configuration and drop-in were removed/restored, the
original configuration hash returned to `0aca8064…`, Cowrie became active,
and the dirty status returned to 132 entries. The corrected release was then
reapplied successfully.

The final rollback release is the previous fully working and credential-safe
integration:

```text
/opt/honeypot-cowrie-output/releases/389cd430f672fea3e1eb6da89c267b7795cda780
```

To restore that release and the exact preceding integration state:

```sh
sudo /opt/honeypot-cowrie-output/current/deployment/cowrie_output/rollback-sanitized-output.sh \
  /var/backups/honeypot/cowrie-output-20260730T114805Z
```

Then verify:

```sh
sudo systemctl is-active cowrie.service honeypot-sensor-forwarder.service
sudo -u cowrie env \
  PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH=/opt/honeypot-cowrie-output/current:/home/cowrie/cowrie/src \
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

Rollback does not rewrite or delete any event log, database, report, model or
historical record.

## Capacity and remaining limitations

- Pi free space: 86,186,631,168 bytes.
- GCP free space: 18,890,776,576 bytes.
- GCP SQLite integrity: `ok`.
- GCP backup from the preceding stabilization remains unchanged:
  `/var/backups/honeypot/stabilization-20260730T083800Z/production_pilot.db`.
- GCP active and rollback application releases remain unchanged.

Remaining limitations:

1. The earlier pre-fix credential remains in preserved historical logs,
   restricted to owner-only access.
2. Public-Internet reachability of GCP `:2222` was not determinable from the
   execution network; internal HAProxy/PROXY behavior passed.
3. The broader application rollback rehearsal and bounded load/restart/
   recovery work were intentionally not started.

The P0 privacy blocker no longer prevents the next stabilization step.
Rollback and bounded recovery stabilization may resume only under a new
explicit instruction, starting by re-reading this handoff and verifying the
local/GCP/Pi revisions, final receipt, service health, capacity and manifests.
