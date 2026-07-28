# Deterministic Prediction and Report Artifacts

Current Transformer snapshots and report exports use content-addressed
integrity boundaries.

## Prediction snapshots

`prediction_snapshot.v3` records both `snapshot_id` and `snapshot_sha256`.
They are derived after inference from the canonical prediction content,
including the event, target contract, policy-bound model provenance, model
input hash, status, and output. Wall-clock generation time, model-load time,
and inference latency are diagnostic values and are excluded from identity.
The session worker finalizes the identity again after adding the deterministic
trigger record.

`validate_prediction_snapshot_integrity()` recomputes both values without
running inference. Mutation of a prediction, status, input, authority, or
provenance invalidates the digest and ID. Historical snapshots are not
rewritten and remain readable without this new integrity field.

## Report artifacts

JSON, Markdown, PDF (when ReportLab is installed), and STIX exports use the
same content-addressed `artifact_version`. Renderer-added timestamps come from
the source report/session rather than the wall clock. STIX bundle, report, and
note IDs use deterministic UUIDv5 identifiers. ReportLab is invoked in
invariant mode so identical inputs produce identical PDF bytes.

Every artifact run writes
`report_artifact_manifest.v1`. It records:

- the artifact version
- exact source report and session SHA-256 values
- each emitted filename, media type, byte length, and SHA-256

The manifest filename contains the SHA-256 of the manifest file bytes. Verify
that digest first, then verify every listed artifact. Artifact files remain
private (`0600`) in the validated, owner-only reports directory.

These hashes establish reproducibility and tamper evidence. They do not make a
prediction authoritative, validate model accuracy, or authorize an alert or
response action.
