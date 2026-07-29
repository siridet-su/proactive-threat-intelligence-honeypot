from __future__ import annotations

import json
from pathlib import Path

import pytest

from production.tools.release_manifest import (
    build_manifest,
    verify_manifest,
    write_manifest,
)


REVISION = "a" * 40


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path]:
    release = tmp_path / "release"
    release.mkdir()
    (release / "app.py").write_text("print('release')\n", encoding="utf-8")
    (release / "configs").mkdir()
    policy = release / "configs" / "policy.json"
    policy.write_text('{"advisory_only":true}\n', encoding="utf-8")
    package = tmp_path / "release.tar"
    package.write_bytes(b"immutable-package")
    artifact = tmp_path / "model.bin"
    artifact.write_bytes(b"frozen-model")
    rollback = tmp_path / "rollback"
    rollback.mkdir()
    return release, package, policy, artifact, rollback


def test_release_manifest_binds_package_tree_config_artifact_and_rollback(
    tmp_path: Path,
) -> None:
    release, package, policy, artifact, rollback = _fixture(tmp_path)
    manifest = build_manifest(
        revision=REVISION,
        release_root=release,
        package_path=package,
        rollback_location=rollback,
        configuration_paths={"policy": str(policy)},
        artifact_paths={"model": str(artifact)},
        runtime_feed_provenance_path=str(tmp_path / "runtime-feed-provenance.json"),
        deployed_at="2026-07-28T00:00:00+00:00",
    )
    output = release / "DEPLOYMENT_MANIFEST.json"
    write_manifest(output, manifest)

    result = verify_manifest(output, release)
    assert result["verified"] is True
    assert result["git_revision"] == REVISION
    assert result["release_file_count"] == 2
    recorded = json.loads(output.read_text())
    assert recorded["model_artifacts"]["model"]["sha256"]
    assert recorded["effective_configurations"]["policy"]["sha256"]
    assert recorded["runtime_feed_provenance"]["authority"] == (
        "non_authoritative_context_only"
    )


def test_release_manifest_rejects_overlay_and_artifact_changes(
    tmp_path: Path,
) -> None:
    release, package, policy, artifact, rollback = _fixture(tmp_path)
    manifest = build_manifest(
        revision=REVISION,
        release_root=release,
        package_path=package,
        rollback_location=rollback,
        configuration_paths={"policy": str(policy)},
        artifact_paths={"model": str(artifact)},
    )
    output = release / "DEPLOYMENT_MANIFEST.json"
    write_manifest(output, manifest)
    (release / "overlay.py").write_text("undocumented = True\n", encoding="utf-8")
    with pytest.raises(ValueError, match="release files"):
        verify_manifest(output, release)
    (release / "overlay.py").unlink()
    artifact.write_bytes(b"changed-model")
    with pytest.raises(ValueError, match="artifact"):
        verify_manifest(output, release)


def test_release_manifest_and_marker_are_excluded_from_release_identity(
    tmp_path: Path,
) -> None:
    release, package, policy, artifact, rollback = _fixture(tmp_path)
    manifest = build_manifest(
        revision=REVISION,
        release_root=release,
        package_path=package,
        rollback_location=rollback,
        configuration_paths={"policy": str(policy)},
        artifact_paths={"model": str(artifact)},
    )
    output = release / "DEPLOYMENT_MANIFEST.json"
    write_manifest(output, manifest)
    (release / "DEPLOYED_COMMIT").write_text(REVISION + "\n", encoding="utf-8")
    assert verify_manifest(output, release)["verified"] is True
    with pytest.raises(FileExistsError):
        write_manifest(output, manifest)


def test_release_manifest_excludes_runtime_python_bytecode_only(
    tmp_path: Path,
) -> None:
    release, package, policy, artifact, rollback = _fixture(tmp_path)
    manifest = build_manifest(
        revision=REVISION,
        release_root=release,
        package_path=package,
        rollback_location=rollback,
        configuration_paths={"policy": str(policy)},
        artifact_paths={"model": str(artifact)},
    )
    output = release / "DEPLOYMENT_MANIFEST.json"
    write_manifest(output, manifest)

    bytecode = release / "production" / "__pycache__"
    bytecode.mkdir(parents=True)
    (bytecode / "runtime.cpython-311.pyc").write_bytes(b"runtime-bytecode")
    (release / "generated.pyo").write_bytes(b"runtime-bytecode")

    assert verify_manifest(output, release)["verified"] is True


def test_release_manifest_rejects_mutable_feed_cache_as_immutable_config(
    tmp_path: Path,
) -> None:
    release, package, _policy, artifact, rollback = _fixture(tmp_path)
    feed_cache = tmp_path / "mitre_attack_cache.json"
    feed_cache.write_text('{"_schema":"2"}\n', encoding="utf-8")

    with pytest.raises(ValueError, match="mutable runtime feed caches"):
        build_manifest(
            revision=REVISION,
            release_root=release,
            package_path=package,
            rollback_location=rollback,
            configuration_paths={"mitre_cache": str(feed_cache)},
            artifact_paths={"model": str(artifact)},
        )


def test_release_manifest_keeps_v2_records_readable(tmp_path: Path) -> None:
    release, package, policy, artifact, rollback = _fixture(tmp_path)
    manifest = build_manifest(
        revision=REVISION,
        release_root=release,
        package_path=package,
        rollback_location=rollback,
        configuration_paths={"policy": str(policy)},
        artifact_paths={"model": str(artifact)},
    )
    manifest["schema_version"] = "honeypot_release_manifest.v2"
    manifest.pop("runtime_feed_provenance", None)
    output = release / "DEPLOYMENT_MANIFEST.json"
    write_manifest(output, manifest)

    assert verify_manifest(output, release)["verified"] is True
