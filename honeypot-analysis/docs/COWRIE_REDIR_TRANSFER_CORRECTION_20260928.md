# Cowrie redirection versus network transfer — correction candidate

Status: tested locally; **not deployed**. Historical reports remain immutable.

## Verified cause

The installed Pi Cowrie emits `cowrie.session.file_download` both when wget/curl
records a fetched URL and when shell redirection content is saved on session
close. The latter has `destfile` and an artifact hash but no `url`; it is not
network-transfer evidence. The real session
`session_v1_b86bd6478dfc73e53a9aa37b763dc158` used local redirection and
nevertheless received a trusted `observed_cowrie_transfer_event` finding and
transfer-specific guidance. This is a false interpretation of the event type,
not evidence of a downloaded file.

## Correction boundary

- A Cowrie download observation now requires a valid remote source URL in the
  event. A missing/malformed/redacted URL, event ID, `destfile`, or hash alone
  cannot establish network transfer. Upload handling is unchanged.
- The raw Cowrie event remains available for forensic inspection; it is not
  promoted to transfer observation, transfer finding, transfer guidance, or a
  transfer flag in the session evidence graph.
- The H2 direct-transfer suppression uses the typed observation, so local
  redirection cannot suppress an otherwise eligible H2 hypothesis.
- The dashboard's file-artifact projection exposes only an enum kind; it does
  not expose the URL, destination path, credentials, or raw payload.
- This does not relax H1/G1 success gates. The real session's
  `cowrie.command.input` records did not carry per-command success, so H1/G1
  remain unavailable for that session. Pi-side outcome instrumentation needs
  a separate contract and tests before activation. The installed Cowrie
  `chmod` implementation calls `fs.chmod` but emits no event on that successful
  operation; the generic command-input event cannot prove success.
- The frozen Next-Distinct runtime and Model2 V7 transfer binding are not
  modified by this correction. Their event-ID-only transfer context remains
  a separate audit item and must not be represented as verified network transfer.

## Verification

- Backend full suite: 2,149 passed, 77 skipped, 15 expected failures.
- Focused redirection/download/H2 tests: 8 passed, including report Markdown
  showing no false trusted transfer claim for a local-redirection fixture.
- Dashboard focused route/projection tests: 5 passed; TypeScript and touched-file
  ESLint passed.
- Dashboard full suite: 846 passed, 14 skipped, 2 expected failures. Four
  pre-existing Filesystem Topology/Evidence assertions described an older UI
  rather than the current live radar and session-scoped Evidence boundary;
  the assertions were updated to test the actual presentation contract.

No production service, Pi sensor, canonical session, MongoDB document, or
historical report was changed by this candidate. A new live session after a
proper staged release is required to validate the corrected finding, API,
dashboard, and PDF together.

## Separate Pi outcome contract needed for H1/G1

The safe next step is not to promote `cowrie.command.input` to success. Add a
versioned, structured Cowrie virtual-filesystem operation result emitted only
after a specific `mkfile`/write or `fs.chmod` returns successfully. Bind each
result to the source Cowrie session and an invocation ID established when the
shell receives the command; carry a normalized path and operation type, and
report partial multi-target `chmod` outcomes per path rather than asserting
whole-command success. Failed/missing-path and zero-byte/no-write cases must
not emit a success result. No credential, command payload, or file contents
belong in this result. The ingest/analysis path must preserve this provenance
and add typed file-write/permission-change observations without fabricating
generic `cowrie.command.success` records.

Before enabling H1/G1 from these events, test exact session/invocation/path
binding, event ordering, different-path negatives, partial chmod, stale or
missing results, and independent API/PDF rendering. This requires a separately
reviewed Pi change and a bounded Cowrie restart.

The backend candidate now implements `cowrie_fs_operation_result.v1` binding
for one simple `echo`/`printf` redirection or one-path `chmod` result. It
requires a unique 32-hex invocation ID on the original `command.input` and
one post-operation result with exact session, path, operation, success, and a
timestamp within five minutes. A write also requires positive bytes written.
Wrong session/path/ID, duplicate results, stale results, compound commands,
or missing result leave the original input outcome unknown. The result adds
provenance to the same command observation; it never becomes an extra command
or a network-transfer event. The derived-evidence projection retains only
the new structural fields and the semantic graph resolves the event reference.

An isolated patch for the current Pi Cowrie files is prepared under
`/tmp/cowrie-fs-outcome.00xitn/` and passes Python compilation. It emits an
invocation ID on interactive `command.input` and a result only after a
non-empty virtual file write or changed virtual permission succeeds. The
running Pi has **not** been changed or restarted. Before activation, the
patch needs exact-source-hash verification, a recoverable backup, a real
Cowrie smoke test, and backend release validation. H1/G1 are not live yet.

After this contract addition, the complete local backend suite passed with
**2,159 passed, 77 skipped, 15 expected failures**, and the Dashboard suite
passed with **846 passed, 14 skipped, 2 expected failures**. The ten new
focused cases cover exact pairing, wrong identity/path/time, duplicate and
missing outcomes, and H1/G1 report projection. These are contract tests,
not proof that the Pi currently emits the event.
