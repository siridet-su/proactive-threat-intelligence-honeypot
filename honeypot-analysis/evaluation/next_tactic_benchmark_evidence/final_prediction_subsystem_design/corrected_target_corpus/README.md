# Corrected-target corpus evidence

This compact bundle records the accepted private-to-safe rebuild for
`next_distinct_command_behavior_phase_or_session_end.v1`. Raw Cowrie events,
commands, source identifiers, the private SQLite mapping, and the HMAC key are
not version-controlled.

The build used the seven members pinned in
`configs/next_behavior_zenodo_source.v1.json`, the classifier assets and
environment pinned in `configs/next_behavior_classifier_environment.v1.json`,
and code commit `3ce5f249a21a57a9f041b4770e13d592f2495a21`.

The generated JSONL payload is intentionally ignored:

- local path: `evaluation/generated/next_behavior_corrected_20260723/corpus.jsonl`
- file SHA-256: `81736363154cf485b0fec98fe8ba41e03f1440860564aa843a1de2739aacf375`
- size: 1,231,491,290 bytes
- records: 219,336

An independent rebuild with the same verified inputs and private HMAC key was
byte-identical for the JSONL payload and all three receipt artifacts. Strict
schema validation passed for all 219,336 records and all seven source-member
receipts. A non-content-printing scan found no raw command, raw session,
address, username, password, credential, or private-member fields.

This recovery does **not** establish an independent final experiment. The
private membership mapping proves that every emitted safe session belongs to
the already accepted historical corpus: 153,535 historical-train sessions,
32,900 historical-calibration sessions, and 32,901 historical-test sessions.
The separate `not_present` count is the 168,239 eligible private sessions
dropped because they had no trusted behavior. The recovered corpus may be used
to verify the corrected target and preprocessing, but the frozen redesigned
test must not be opened, trained on, or claimed independent from this source.

The local payload can be reproduced with
`production/tools/build_next_behavior_zenodo_corpus.py` after restoring the
verified public members, private HMAC key, pinned SecureBERT assets, and pinned
environment. The tool refuses a dirty tracked tree, a code-commit mismatch,
changed source/classifier/policy/cache artifacts, incomplete classification,
or output overwrite.
