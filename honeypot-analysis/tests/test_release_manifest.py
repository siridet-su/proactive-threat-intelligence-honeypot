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
