# Immutable Python runtime and dependency receipt

The GCP application release, frozen model bundle, Python runtime, and offline
dependency bundle are separate immutable components.  Python and wheel
artifacts must not be recorded as model artifacts.

`production.tools.runtime_dependency_receipt` defines three closed contracts:

- `python_runtime_bundle.v1` records the official CPython source, exact build
  environment, installation prefix, runtime file inventory, modes, symlinks,
  and content-addressed runtime identity.
- `python_wheel_bundle.v1` records the frozen lock, target ABI/platforms,
  reviewed indexes, and the filename, package identity, version, tags, size,
  and SHA-256 of every wheel.
- `runtime_dependency_receipt.v1` binds an exact application revision/archive
  to those two manifests and archives.  It is owner-only, portable, and
  contains relative artifact paths rather than host-specific deployment paths.

Verification fails closed on an unexpected file, missing file, symlinked
artifact, unsafe archive member, changed mode, changed hash, non-frozen Python
source/version, non-frozen lock, unreviewed index, missing or extra wheel, or a
wheel whose embedded package metadata differs from the lock or manifest.

The receipt supplements `honeypot_release_manifest.v7`; it does not change the
existing application-release, frozen-model, policy, database, or mutable-feed
boundaries.  A deployment gate must independently verify both manifests before
installing the runtime or dependencies.

Typical creation order:

```bash
python -B -m production.tools.runtime_dependency_receipt \
  create-runtime-manifest \
  --runtime-root /opt/honeypot-python-runtimes/<RUNTIME_ID> \
  --source-archive <ARTIFACT_ROOT>/Python-3.12.13.tar.xz \
  --source-url https://www.python.org/ftp/python/3.12.13/Python-3.12.13.tar.xz \
  --build-environment <ARTIFACT_ROOT>/PYTHON_BUILD_ENVIRONMENT.json \
  --output <ARTIFACT_ROOT>/PYTHON_RUNTIME_MANIFEST.json

python -B -m production.tools.runtime_dependency_receipt \
  create-wheel-manifest \
  --wheel-root <WHEEL_ROOT> \
  --lock requirements-next-behavior-corpus.lock.txt \
  --index https://pypi.org/simple \
  --index https://download.pytorch.org/whl/cpu \
  --resolver-version <EXACT_PIP_VERSION> \
  --download-argument=--only-binary=:all: \
  --download-argument=--implementation=cp \
  --download-argument=--python-version=3.12 \
  --download-argument=--abi=cp312 \
  --download-argument=--platform=manylinux_2_28_x86_64 \
  --download-argument=--platform=manylinux_2_17_x86_64 \
  --output <ARTIFACT_ROOT>/WHEEL_BUNDLE_MANIFEST.json

python -B -m production.tools.runtime_dependency_receipt create-receipt \
  --artifact-root <ARTIFACT_ROOT> \
  --application-revision <40_HEX_COMMIT> \
  --application-archive <ARTIFACT_ROOT>/application.tar.gz \
  --runtime-manifest <ARTIFACT_ROOT>/PYTHON_RUNTIME_MANIFEST.json \
  --runtime-archive <ARTIFACT_ROOT>/python-runtime.tar.gz \
  --wheel-manifest <ARTIFACT_ROOT>/WHEEL_BUNDLE_MANIFEST.json \
  --wheel-archive <ARTIFACT_ROOT>/python-wheels.tar.gz \
  --output <ARTIFACT_ROOT>/RUNTIME_DEPENDENCY_RECEIPT.json

python -B -m production.tools.runtime_dependency_receipt verify \
  --receipt <ARTIFACT_ROOT>/RUNTIME_DEPENDENCY_RECEIPT.json \
  --artifact-root <ARTIFACT_ROOT>
```

The build must retain the reviewed source archive and create deterministic tar
archives with normalized ownership, ordering, and timestamps.  Runtime
installation and dependency verification occur in an isolated environment;
production secrets, databases, mutable feeds, reports, and model files are not
members of these artifacts.
