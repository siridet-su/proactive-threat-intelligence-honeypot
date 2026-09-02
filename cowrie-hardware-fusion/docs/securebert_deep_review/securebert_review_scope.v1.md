# SecureBERT deep-review scope

Date: 2026-08-29 (Asia/Bangkok)  
Mode: read-only model, inference, provenance, authority, and integration review

This review reconstructs executable behavior for the classifier historically named
`SecureBERT` in this repository. It does not retrain, fine-tune, mutate, deploy, or
authorize the model. The reviewed operational baseline is immutable active release
`d5f6dd408df873b5f912f74d96d72f15e1e47da2`; the later unbuilt worktree is reported
separately wherever its hashes differ.

Evidence includes the active release materialization, the retained external frozen
model bundle, current source and tests, prior provenance audits, and bounded local CPU
inference. No MongoDB, GCP, Pi, service, Git index/history, checkpoint, tokenizer,
policy, threshold, calibration value, rule, or application source was modified.

Identity caveat: the supplied `e55289bd...` value is the four-file Phase 4A.2
authority-candidate identity used by the release manifest. The active classifier
environment independently embeds an eleven-file identity `dbcbf30f...`; these are
different scopes and must not be treated as the same digest. The current unbuilt
worktree has further changed hashes.

The supplied temperature `0.6990670591704266` and `label_order_bound=true` belong to
the separate next-observed-distinct-tactic prediction model. They are not part of the
SecureBERT command classifier's logit processing.

