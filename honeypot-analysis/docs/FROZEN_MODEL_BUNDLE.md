# Immutable frozen-model bundles

Transformer and SecureBERT binaries are private runtime assets. They must not
be added to Git or copied into a mutable release overlay. A production release
instead consumes one separately managed immutable bundle under
`/opt/honeypot-model-bundles/`.

## Boundary

The bundle contains only these receipt-pinned files:

- corrected-target Transformer checkpoint, model specification, vocabulary, and
  calibration mapping;
- the eight SecureBERT runtime files listed by
  `configs/next_behavior_classifier_environment.v1.json`.

Its `FROZEN_MODEL_BUNDLE_MANIFEST.json` records exact byte hashes, sizes,
Transformer policy/final-result identities, vocabulary semantic identity,
calibration identities, and the SecureBERT environment receipt. The bundle
directory is owned by the `honeypot` service account, mode `0700`, with files
mode `0600`. Its archive is mode `0600` and is a recovery artifact, not Git
content.

`production.tools.frozen_model_bundle create` first verifies the candidate
source against the reviewed prediction policy and classifier receipt. It then
copies exact bytes to a new content-addressed bundle. The old source release is
recorded only as provenance; a completed bundle never follows it at runtime.

## Production procedure

Run these commands only after a fresh database backup/restore rehearsal and
after staging a clean release at `$RELEASE`. The source paths below are the
verified recovery source from Phase 8B; they are not runtime dependencies after
the bundle is created.

```sh
REVISION=<full-clean-release-commit>
RELEASE=/opt/honeypot-releases/$REVISION
SOURCE_RELEASE=/opt/honeypot-releases/97db7b495d3f4fb8c14286dff873ef5d07d0fb73
sudo install -d -o honeypot -g honeypot -m 0700 /opt/honeypot-model-bundles /opt/honeypot-model-packages

sudo /opt/honeypot/.venv/bin/python -m production.tools.frozen_model_bundle create \
  --bundle-parent /opt/honeypot-model-bundles \
  --transformer-source-root "$SOURCE_RELEASE" \
  --classifier-source-root "$SOURCE_RELEASE/models/securebert_ttp" \
  --prediction-policy "$RELEASE/configs/prediction_policy.transformer_poc.trusted.json" \
  --classifier-environment "$RELEASE/configs/next_behavior_classifier_environment.v1.json" \
  --repository-root "$RELEASE" \
  --owner honeypot --group honeypot
```

Use the returned bundle ID to set `BUNDLE`. Before writing a release manifest:

```sh
sudo /opt/honeypot/.venv/bin/python -m production.tools.frozen_model_bundle verify \
  --bundle-root "/opt/honeypot-model-bundles/$BUNDLE" \
  --prediction-policy "$RELEASE/configs/prediction_policy.transformer_poc.trusted.json" \
  --classifier-environment "$RELEASE/configs/next_behavior_classifier_environment.v1.json" \
  --repository-root "$RELEASE" --runtime-check --smoke-test

sudo /opt/honeypot/.venv/bin/python -m production.tools.frozen_model_bundle install-release-links \
  --release-root "$RELEASE" --bundle-root "/opt/honeypot-model-bundles/$BUNDLE"

sudo /opt/honeypot/.venv/bin/python -m production.tools.frozen_model_bundle archive \
  --bundle-root "/opt/honeypot-model-bundles/$BUNDLE" \
  --archive "/opt/honeypot-model-packages/$BUNDLE.tar"
```

The link installer is deliberately fail-closed: it refuses a release that
already has any target artifact link or `models` link. It adds the four
Transformer files under `data/models/` and points `models/` at the bundle, so
the reviewed relative policy paths and `SECUREBERT_PATH=/opt/honeypot/models/securebert_ttp`
remain unchanged. The staged release manifest must receive both:

```sh
--frozen-model-bundle-manifest "/opt/honeypot-model-bundles/$BUNDLE/FROZEN_MODEL_BUNDLE_MANIFEST.json" \
--frozen-model-bundle-package "/opt/honeypot-model-packages/$BUNDLE.tar"
```

`release_manifest verify` then verifies release links, every declared model
artifact, the bundle manifest receipt, and the recovery archive receipt.
Runtime feed caches remain separate mutable, non-authoritative provenance.

## Recovery and rollback

Keep the bundle directory and its archive while any release refers to it. To
restore on a replacement host, extract the archive into
`/opt/honeypot-model-bundles/`, restore ownership/modes, then run the `verify`
command above with `--runtime-check --smoke-test` before staging a release.
Verify the archive SHA-256 from the dependent release manifest before extraction.

Release rollback remains a pointer operation. It does not alter the bundle,
database, feeds, model bytes, or model identities. Do not remove the retained
Phase 8B source release until a separately approved retention review confirms
that no live or rollback release still depends on it.
