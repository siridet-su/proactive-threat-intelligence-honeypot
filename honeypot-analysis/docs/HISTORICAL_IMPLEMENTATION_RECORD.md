# Historical implementation record (canonical summary)

Completed work is summarized here rather than retained as an active second
documentation system. Deleted source reports and former machine-readable
cleanup inventories remain byte-for-byte recoverable from Git history.

## Major transitions

- The v4 assessment and v3 guidance contracts replaced new-data legacy
  recommendation/hypothesis authority while read-only adapters preserved old
  records (`5fee45a`, `97db7b4`).
- Phase 6 removed confirmed inactive report/generator and backend paths while
  preserving historical readers.
- Phase 7 separated mutable feed provenance, strict configuration, local data,
  and operational hardening (`1922572`, `bb751ea`).
- Phase 8 bound frozen Transformer artifacts, release manifests, backup/restore,
  and rollback (`1300387`, `d263ead`).
- Typed semantic work activated only reviewed sensitive-read, inspection, and
  direct-transfer slices. Transformation, execution, scheduled-task, service,
  collection, transfer-attempt, and cross-family hypotheses remain contained or
  shadow-only where the current typed-fact contract says so.
- Stabilization resolved Cowrie credential persistence, observer discovery,
  rotation, sealed rollback receipt, immutable-bytecode, and forwarder boundary
  defects. Failed attempts were rolled back before later packages were tested.

## Failed attempts and corrections

The principal stop conditions were privacy-marker failures, incomplete or
racing rollback receipts, bytecode contamination, observer-loader divergence,
canonical-report provenance validation, pre-existing startup-diagnostic
directories, and a disabled pre-existing TCP/2222 firewall rule. Each
production-changing failure returned to its verified baseline before the next
candidate. The final receipt records the successful bounded activation; the
earlier failed and blocked reports are historical context rather than retained
current evidence files.

## Condensed chronology

| Period | Durable outcome |
| --- | --- |
| Phases 0–5 | Canonical v4/v3 authority, deterministic artifacts, SQLite reliability and first manifest-bound deployment |
| Phase 6 | Legacy generators, unsupported backends, stale units/configuration and duplicate UI paths archived or removed |
| Phase 7 | Pre-persistence sanitization, strict configuration, durable reconstruction, local feed provenance and privacy tests |
| Phase 8 | Capacity repair, mutable-feed boundary, frozen model bundle, backup/restore and rollback rehearsal |
| Semantic migration | Typed fact v2 introduced in shadow mode; sensitive-read, direct-transfer and inspection slices activated only after frozen/holdout evaluation |
| Stabilization | Pi privacy boundary and GCP startup/activation defects corrected through rollback-guarded attempts |
| Final activation | GCP revision `3c79ae155021ca4cf0ab6d744211d884c4ee039e`, recovery `19afabd…`, accepted Pi `5bb3b97…`, public Cowrie route restored, E2E and observation passed |

## Archived alternatives

SQLite remains the only active runtime backend. MongoDB/PostgreSQL adapters,
legacy SMB/Vertex paths, prediction-only authority, automatic response, and
unreviewed semantic families are archived or fail-closed. Frozen VOMM remains a
rollback/reference artifact, not a hidden runtime fallback.

## Repository cleanup record

The first cleanup pass at source revision
`48cd3cccf3a38fc38c557614cd999f1cb1f982d9` removed six ignored,
reproducible, incomplete bulk JSONL projections totaling 2,142,707,349 bytes.
Their retained evaluation receipts, policies, inputs, and reproduction tools
remained authoritative; the deleted projections had no exact runtime, test,
schema, manifest, or CI consumer.

The next audited pass used source revision
`f2137ba86aa17c1da914112660ddfe469cc95e1c` and reviewed 264 tracked paths
under documentation and evaluation (98,236,690 bytes). It retained 98 paths,
deleted 166 paths totaling 7,993,592 bytes, merged 53 documents, and recorded
no deletion whose status was `NOT_DETERMINABLE`. The decisions comprised 91
duplicate exports, 11 failed attempts, 31 obsolete designs, and 33 superseded
records; retained paths comprised 18 current contracts, 11 code/test
dependencies, 42 final-evidence records, and 27 schemas/fixtures. Net tracked
reduction was 7,821,626 bytes after growth in the retained summaries.

The current consolidation folds the eleven remaining split authority,
integrity, lifecycle, development, release, model-bundle, and operating
references into the root README and six subject summaries. Together with this
record, `docs/` now has only the seven documents indexed by its README. This is
a documentation-layout change, not a change to runtime authority, evaluation
status, retention approval, or the last repository-recorded production state.

The prior decision tables and every deleted tracked original remain available
at the recorded source revisions. They were intentionally not retained as a
replacement inventory inside the active documentation set.

To inspect a deleted report without restoring it to the worktree, use
`git show f2137ba86aa17c1da914112660ddfe469cc95e1c:honeypot-analysis/<old-path>`.
