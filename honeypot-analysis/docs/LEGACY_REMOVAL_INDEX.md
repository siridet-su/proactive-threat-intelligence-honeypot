# Legacy removal index

Git history is the archive. Do not create a new `legacy/` source tree.

Recovery baseline: annotated local tag
`pre-handoff-repository-cleanup-20260727`, commit
`3fe1482d8047deb9592cf1fb1a52d2cc68df2d18`.

| Removed item | Reason | Replacement | Recovery |
|---|---|---|---|
| `evaluation/generated/` | 2.3 GiB of ignored deterministic duplicate rebuild output | Retained source receipts, canonical cache artifacts, and committed compact evidence | Regenerate with reviewed evaluation tooling; directory was untracked |
| `build/` and `honeypot_analysis.egg-info/` | Local packaging output | `pyproject.toml` | `python -m build` or editable install |
| `.pytest_cache/` and Python bytecode caches | Interpreter/test-generated | Source and tests | Rerun Python/pytest |
| `evaluation/authoritative_external_vomm/` | Pre-provenance evaluation superseded by the exact Zenodo-seven-day evaluation | `evaluation/authoritative_external_vomm_zenodo7_20260721/` | Commit `744dca3` or the recovery tag |

No runtime subsystem was removed merely because it was inactive. Historical
prediction helpers remain where current rollback evaluators, corrected
benchmark reproduction, or stored-snapshot compatibility still import them.
MongoDB remains isolated supported future work, not deployed architecture.

Any later source removal must add its exact paths, replacement, tests, and
recovery commit here.
