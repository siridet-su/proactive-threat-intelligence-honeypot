# Historical implementation record (canonical summary)

Completed work is retained as dated evidence rather than an active second
implementation. This record points to the detailed source documents and keeps
the decision chronology discoverable.

## Major transitions

- The v4 assessment and v3 guidance contracts replaced new-data legacy
  recommendation/hypothesis authority while read-only adapters preserved old
  records (`5fee45a`, `97db7b4`).
- Phase 6 removed confirmed inactive report/generator and backend paths; the
  archive boundary is [`PHASE6_ARCHIVE.md`](PHASE6_ARCHIVE.md).
- Phase 7 separated mutable feed provenance, strict configuration, local data,
  and operational hardening (`1922572`, `bb751ea`).
- Phase 8 bound frozen Transformer artifacts, release manifests, backup/restore,
  and rollback (`1300387`, `d263ead`).
- Typed semantic work activated only reviewed sensitive-read, inspection, and
  direct-transfer slices. Transformation, execution, scheduled-task, service,
  collection, transfer-attempt, and cross-family hypotheses remain contained or
  shadow-only where their contracts say so.
- Stabilization resolved Cowrie credential persistence and forwarder boundary
  defects, then retained failed deployment receipts instead of rewriting them.

## Failed attempts and corrections

The stabilization and next-tactic records preserve the exact stop conditions:
privacy-marker failures, rollback receipt races, bytecode contamination,
canonical-report provenance errors, a disabled pre-existing TCP/2222 firewall
rule, and the subsequent successful bounded correction. These are not current
runtime implementations and must not be deleted merely because a later gate
passed. Start with [`STABILIZATION_HANDOFF_2026-07-30.md`](STABILIZATION_HANDOFF_2026-07-30.md),
[`NEXT_TACTIC_CONTROLLED_PRODUCTION_ACTIVATION_2026-08-01.md`](NEXT_TACTIC_CONTROLLED_PRODUCTION_ACTIVATION_2026-08-01.md),
and [`NEXT_TACTIC_FINAL_PRODUCTION_ACTIVATION_2026-08-02.md`](NEXT_TACTIC_FINAL_PRODUCTION_ACTIVATION_2026-08-02.md).

## Archived alternatives

SQLite remains the only active runtime backend. MongoDB/PostgreSQL adapters,
legacy SMB/Vertex paths, prediction-only authority, automatic response, and
unreviewed semantic families are archived or fail-closed. Frozen VOMM remains a
rollback/reference artifact, not a hidden runtime fallback. Exact removals are
listed in [`LEGACY_REMOVAL_INDEX.md`](LEGACY_REMOVAL_INDEX.md) and prior
cleanup records.
