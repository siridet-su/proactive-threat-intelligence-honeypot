# GCP corrected-target Transformer PoC deployment — 2026-07-27

## Decision and immutable evidence

This is a professor-approved experimental PoC deployment. It does **not**
change or pass the original corrected-target experiment status:
`BLOCKED_AT_SELECTION`. The frozen Transformer is preferred here for frequent
behavior aggregate performance; the preserved VOMM remains preferable for
balanced and rare-tactic coverage. Neither is universally superior.

- Previous deployed revision: `ff5cae1` (established from the deployment
  handoff; the installed tree had no Git metadata).
- New deployed revision marker:
  `fd89a826e353928396c4ed3202253073042d3f0b`.
- Deployment code archive SHA-256:
  `2dfbfeee00213903a0ccaa0f2502505356249ef963319d8ab7015b62322441cb`.
- Frozen checkpoint SHA-256:
  `7fbd73c4bd071336fa52a589bf41e39f5a3122a67aee398dfb8e6dd9cfdfb04a`.
- Seed: `20260721`; architecture: one-layer causal Transformer, `d_model=16`,
  four heads, feed-forward dimension 32, dropout 0.1, maximum length 8,
  3,951 parameters, CPU float32 inference.
- Model-spec semantic SHA-256:
  `82b1a15ec96f5165878ee03639daa61e319f06c4376e0a9a8018f3e1a2b3e512`.
- Vocabulary semantic SHA-256:
  `527a65c6d6cee94a3bbb0af6d5df95981a6438cf703e053484c9e7e116f0306f`.
- Preprocessing SHA-256:
  `890569a4597df2f300d7c885a2cf0bd34a9fd9fbdd0ab0938141a8f13f4a25c1`.
- Calibration mapping SHA-256:
  `aa27813af96eaa2674b07d76f41565e71835bfa1a5bba8a3232eaa0a396a4e2d`.
- Immutable Final result SHA-256:
  `3e82ccd46dd1114488e8c7cfc45522ded38ed580969f853687b233e5440c08`.
- Target:
  `next_distinct_command_behavior_phase_or_session_end.v1`.

The live GCP rule file is explicitly bound at SHA-256
`3352f889fe25f88075d53c18d439746653a795045cd3571c46e3364733ad0f39`.
It differs from the later corpus rule file (`33f332…`), so this is recorded as
deployment-domain provenance rather than falsely representing the training
policy as the live policy. The live trust module matches
`1e3518583516a200fc5198ba65cbf10a3f056e4006baa27fc7b5fc6aa835eecd`,
and the SecureBERT checkpoint matches
`dc3a4e2a57a70c4c7cb5f769b6399f32b2b51f0245025653e0b72f6d025a759b`.

## Production semantics

Exactly one model is configured at a time. The active mode is
`professor_approved_corrected_target_transformer_poc`. There is no blending,
cascade, tactic routing, heuristic fallback, or automatic VOMM fallback.
Missing, corrupt, incompatible, or hash-mismatched artifacts produce
`model_unavailable` without breaking canonical evidence processing.

New snapshots use `prediction_snapshot.v3`, retain the historical storage
envelope, and explicitly identify the corrected multi-label target. Historical
VOMM snapshots are unchanged. API and UI output identify the model, artifact,
status, target contract, and advisory authority. Prediction alone cannot create
alerts, establish intent, support factual claims, select guidance or
recommendations, authorize an action, or execute anything.

## Backup and rollback evidence

GCP root-only bundle:
`/var/backups/honeypot/transformer-poc-20260727/`.
Off-host private copy:
`/home/rubchek/Desktop/honeypot-deployment-backups/20260727-transformer-poc/`.

- SQLite backup: 3,924,496,384 bytes, SHA-256
  `67c7c1c07c0032b03f708847122a3c21050d5a333a9c4a0c64d3125d75e54a6c`;
  full `integrity_check=ok`; boundary counts:
  events 49,449, sessions 7,422, reports 6,924, snapshots 21,720; all durable
  queues settled.
- Prior code archive SHA-256:
  `affe7a8e7ef9181c82936e87574cb8474f08d434c1e7ab847b388a3e213a5f47`.
- Protected config/unit archive SHA-256:
  `5d9f3769bdadd74a41c09dc6e65fbc434226588844d2c8e7deea8a271e3c7de1`.
- VOMM rollback archive SHA-256:
  `6c3dd4036e59aceb1acec5c75d0978a2a88f738388dc3decc2bbe21f70b9c484`.
- VOMM artifact SHA-256:
  `b5a60951764648ed242d7b9acfe1df6f5f314f96e341badb7f4bd55107614e3e`.
- VOMM manifest SHA-256:
  `01c0665566467693e3dbb408f0383900f7d09e769d27c93161937b27d7d6d429`.
- VOMM policy SHA-256:
  `0c82941c90d6e36283b638b1554ad700311990df78895b0111131f9658da1c22`.

The off-host hashes matched GCP. All rollback archives extracted successfully
in a fresh root-only scratch directory.

Explicit model rollback:

```text
sudo systemctl stop honeypot-session-worker.service honeypot-dashboard-api.service honeypot-monitor-web.service
sudo install -o root -g root -m 0644 /opt/honeypot/configs/prediction_policy.vomm_rollback.trusted.json /opt/honeypot/configs/prediction_policy.trusted.json
cd /opt/honeypot
sudo /opt/honeypot/.venv/bin/python -m production.policies.validate_prediction_policy --policy configs/prediction_policy.trusted.json --json
sudo systemctl start honeypot-session-worker.service honeypot-dashboard-api.service honeypot-monitor-web.service
```

Restoring the Transformer uses the same procedure with
`prediction_policy.transformer_poc.trusted.json`. No runtime fallback is used.
The rehearsal switched to VOMM, generated a controlled prediction and report,
then restored and revalidated the Transformer.

## Deployment and runtime verification

- Eight honeypot daemons and five existing timers are active; affected
  services have zero restarts.
- Listening ports are unchanged: SSH 22, HAProxy/Cowrie 2222, private ingest
  on the Tailscale address at 8080, and loopback 8081/8090.
- SQLite remains authoritative (`user_version=0`, final `quick_check=ok`);
  MongoDB remains disabled.
- Final counts after three controlled sessions: events 49,463, sessions 7,425,
  reports 6,927, snapshots 21,731. All durable queues are settled.
- Controlled Transformer E2E covered ingest, command classification, evidence
  reconstruction, report generation, Transformer inference, API/UI rendering,
  and guidance checks. The exact checkpoint/vocabulary/preprocessing hashes
  were present; prediction alerts were prohibited; report guidance used
  canonical observed evidence and manual approval. Synthetic passwords were
  absent from derived snapshots and reports.
- The controlled VOMM rollback session produced a prediction and report using
  the exact preserved artifact and manifest. A final controlled session after
  restoration again used the exact Transformer checkpoint.
- GCP Transformer benchmark (200 real inferences): load 4,302.7 ms;
  p50/p95/p99 8.36/10.38/13.57 ms; 115.89 predictions/s; isolated process peak
  RSS 653,660,160 bytes; post-load RSS 643,047,424 bytes; checkpoint 27,400
  bytes; about 192% of one CPU core during the bounded benchmark.
- Preserved non-Final VOMM evidence remains much faster (p50 about 0.023 ms)
  and materially smaller in runtime compute, while its JSON artifact is about
  20.4 MB. The targets and performance trade-offs differ.

## Tests and limitations

- Frozen-model/contract/policy matrix: 60 passed.
- Worker/report/API/guidance affected matrix: 95 passed.
- Full socket-enabled suite before the final provenance tightening:
  1,194 passed, 16 dependency-gated skips. The final tightening was followed
  by 19 focused model/tensor/runtime passes; a final complete rerun is recorded
  in the repository handoff.
- The deployment evidence is a within-Zenodo temporal holdout with
  classifier-derived weak labels, not external validation.
- Transformer Final defense-evasion precision/recall/F1 were 0.0 (support 456);
  this remains a material PoC limitation.
- Cache cleanup inventory before attempted deletion:
  honeypot evidence 28 GB (`REQUIRED` or `AMBIGUOUS_DO_NOT_DELETE`), pip 2.9 GB
  (`SAFE_TO_DELETE`), uv 1.3 GB (`SAFE_TO_DELETE`), Firefox cache 1.1 GB
  (`SAFE_TO_DELETE`), and the unpublished invalid `fc6a83a` preparation 63 MB
  (`SAFE_TO_DELETE`). The managed execution environment rejected the deletion,
  so no cache item was removed and recovered space is zero. This is an
  operational cleanup blocker only; it does not affect deployment correctness.

