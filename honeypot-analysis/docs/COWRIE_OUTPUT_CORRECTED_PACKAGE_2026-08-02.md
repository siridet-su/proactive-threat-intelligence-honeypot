# Corrected Cowrie output package — 2026-08-02

## Source and identity

- Git revision: `5eb5a19aa7af818566c17b8e79e46d32deb96f6e`
- Component ID: `cowrie_output_59dacd57a23f5c55d64ece4819eb178a`
- Manifest schema: `cowrie_output_bundle_manifest.v4`
- Manifest SHA-256:
  `da58885e6e6c403c89108e12411841125de4413a5125c7f05c4c9d2ad7edd988`
- Package SHA-256:
  `df24688b925ed21a97a2915a68c7feca1a70161ec8c111b05f6121ecd1158db4`
- Package size: `235520` bytes
- Closed archive inventory: 20 regular files plus the manifest and only their
  required owner-only directories
- Proposed Pi temporary destination: `/tmp/cowrie-output-5eb5a19.tar`

The package itself is intentionally not committed.

## Reproducibility and verification

Two independent source trees were extracted with `git archive` from the exact
revision. Each tree produced a fresh v4 bundle and deterministic tar package.
The two package byte streams compared equal and both had the package SHA-256
above. A third owner-only copy at the proposed local transfer name was safely
extracted using the package's own closed-inventory verifier. Its revision,
component, manifest, file count, hashes, modes, and archive safety all passed.

The package contains no logs, events, credentials, addresses, markers,
journals, caches, bytecode, backups, or production data.

## Corrected behavior

- Archive verification and staging occur while the baseline remains active.
- The installer consumes the manifest's per-file owner, group, mode, type,
  executable, immutable, size, hash, source, and destination metadata.
- The installed inventory is verified before the active link can change.
- Every partial staging or release mutation is removed by tested recovery.
- Rollback authority is the sealed receipt and verified saved files.
- Optional JSON status files and stdout cannot block receipt verification or
  application.
- Rollback application is interruption-retryable and idempotent.

## Validation before package construction

- focused Cowrie output/receipt/lifecycle/forwarder suite: `152 passed`;
- full repository suite: `1180 passed, 8 skipped`;
- complete staging and installation fault injection: passed;
- legacy actual-tab and literal-`\\t` receipt compatibility: passed;
- Python syntax: passed;
- shell syntax: passed;
- archive safety and deterministic package comparison: passed;
- `git diff --check`: passed.

The exact Cowrie revision, Python 3.12.3, and Twisted 25.5.0 service-faithful
smoke remains a mandatory isolated Pi pre-activation gate after exact-hash
transfer approval. No Pi or GCP runtime change was made during this package
build.
