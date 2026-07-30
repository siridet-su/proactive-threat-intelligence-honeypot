from __future__ import annotations

import json
from pathlib import Path

import pytest

from production.tools.release_manifest import (
    build_manifest,
    inventory_sha256,
    release_file_inventory,
    verify_manifest,
    write_manifest,
)


REVISION = "a" * 40
MANAGED_UNIT_POLICY = (
    Path(__file__).resolve().parents[1]
    / "deployment"
    / "systemd"
    / "managed_units.v1.json"
)


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
        managed_unit_policy_path=str(MANAGED_UNIT_POLICY),
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
    assert recorded["managed_systemd_units"]["sha256"]
    assert recorded["managed_systemd_units"]["policy_id"] == (
        "honeypot-controlled-poc-units"
    )
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
        managed_unit_policy_path=str(MANAGED_UNIT_POLICY),
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


def test_release_manifest_rejects_managed_unit_policy_drift(
    tmp_path: Path,
) -> None:
    release, package, policy, artifact, rollback = _fixture(tmp_path)
    managed = tmp_path / "managed_units.v1.json"
    managed.write_bytes(MANAGED_UNIT_POLICY.read_bytes())
    manifest = build_manifest(
        revision=REVISION,
        release_root=release,
        package_path=package,
        rollback_location=rollback,
        configuration_paths={"policy": str(policy)},
        artifact_paths={"model": str(artifact)},
        managed_unit_policy_path=str(managed),
    )
    output = release / "DEPLOYMENT_MANIFEST.json"
    write_manifest(output, manifest)
    assert verify_manifest(output, release)["verified"] is True

    changed = json.loads(managed.read_text(encoding="utf-8"))
    changed["version"] = "changed-after-manifest"
    managed.write_text(json.dumps(changed), encoding="utf-8")
    with pytest.raises(ValueError, match="managed systemd-unit policy"):
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
        managed_unit_policy_path=str(MANAGED_UNIT_POLICY),
    )
    output = release / "DEPLOYMENT_MANIFEST.json"
    write_manifest(output, manifest)
    (release / "DEPLOYED_COMMIT").write_text(REVISION + "\n", encoding="utf-8")
    assert verify_manifest(output, release)["verified"] is True
    with pytest.raises(FileExistsError):
        write_manifest(output, manifest)


def test_release_manifest_excludes_environment_derived_runtime_state(
    tmp_path: Path,
) -> None:
    release, package, policy, artifact, rollback = _fixture(tmp_path)
    generated_files = [
        release / "production" / "__pycache__" / "runtime.cpython-311.pyc",
        release / "generated.pyo",
        release / ".pytest_cache" / "v" / "cache" / "nodeids",
        release / ".ruff_cache" / "cache",
        release / ".coverage",
        release / "coverage.xml",
        release / "scratch.tmp",
        release / "editor.swp",
        release / "editor.py~",
        release / "runtime_feed_provenance.json",
        release / "production_pilot.db",
        release / "production_pilot.db-wal",
        release / "production_pilot.db-shm",
        release / "runtime.log",
        release / "reports" / "session.json",
        release / "spool" / "batch.jsonl",
        release / "data" / "feeds" / "cisa_kev_cache.json",
        release / "data" / "feeds" / "mitre_attack_cache.json",
        release / "data" / "feeds" / "sigma_rules_cache.json",
        release / "data" / "feeds" / "sigma_rules_cache.json.lock",
    ]
    for generated in generated_files:
        generated.parent.mkdir(parents=True, exist_ok=True)
        generated.write_bytes(b"environment-derived")

    manifest = build_manifest(
        revision=REVISION,
        release_root=release,
        package_path=package,
        rollback_location=rollback,
        configuration_paths={"policy": str(policy)},
        artifact_paths={"model": str(artifact)},
        managed_unit_policy_path=str(MANAGED_UNIT_POLICY),
    )
    output = release / "DEPLOYMENT_MANIFEST.json"
    write_manifest(output, manifest)

    for generated in generated_files:
        assert generated.relative_to(release).as_posix() not in manifest["release_files"]
        generated.write_bytes(b"changed-runtime-state")

    assert verify_manifest(output, release)["verified"] is True


def test_release_manifest_v6_rejects_identity_policy_drift(
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
        managed_unit_policy_path=str(MANAGED_UNIT_POLICY),
    )
    manifest["release_identity"]["policy_id"] = "invented-policy"
    output = release / "DEPLOYMENT_MANIFEST.json"
    write_manifest(output, manifest)

    with pytest.raises(ValueError, match="release identity policy"):
        verify_manifest(output, release)


def test_excluded_classifier_snapshot_can_be_separately_hash_bound(
    tmp_path: Path,
) -> None:
    release, package, policy, artifact, rollback = _fixture(tmp_path)
    frozen_mitre_snapshot = release / "data" / "feeds" / "mitre_attack_cache.json"
    frozen_mitre_snapshot.parent.mkdir(parents=True)
    frozen_mitre_snapshot.write_text('{"_schema":"2"}\n', encoding="utf-8")
    manifest = build_manifest(
        revision=REVISION,
        release_root=release,
        package_path=package,
        rollback_location=rollback,
        configuration_paths={"policy": str(policy)},
        artifact_paths={
            "model": str(artifact),
            "classifier_mitre_snapshot": str(frozen_mitre_snapshot),
        },
        managed_unit_policy_path=str(MANAGED_UNIT_POLICY),
    )
    output = release / "DEPLOYMENT_MANIFEST.json"
    write_manifest(output, manifest)

    assert "data/feeds/mitre_attack_cache.json" not in manifest["release_files"]
    assert verify_manifest(output, release)["verified"] is True

    frozen_mitre_snapshot.write_text('{"_schema":"changed"}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="artifact"):
        verify_manifest(output, release)


def test_release_manifest_keeps_v5_inventory_semantics_readable(
    tmp_path: Path,
) -> None:
    release, package, policy, artifact, rollback = _fixture(tmp_path)
    feed = release / "data" / "feeds" / "mitre_attack_cache.json"
    feed.parent.mkdir(parents=True)
    feed.write_text('{"_schema":"2"}\n', encoding="utf-8")
    manifest = build_manifest(
        revision=REVISION,
        release_root=release,
        package_path=package,
        rollback_location=rollback,
        configuration_paths={"policy": str(policy)},
        artifact_paths={"model": str(artifact)},
        managed_unit_policy_path=str(MANAGED_UNIT_POLICY),
    )
    legacy_inventory = release_file_inventory(
        release,
        schema_version="honeypot_release_manifest.v5",
    )
    manifest["schema_version"] = "honeypot_release_manifest.v5"
    manifest["release_files"] = legacy_inventory
    manifest["release_tree_sha256"] = inventory_sha256(legacy_inventory)
    manifest.pop("release_identity")
    output = release / "DEPLOYMENT_MANIFEST.json"
    write_manifest(output, manifest)

    assert verify_manifest(output, release)["verified"] is True
    assert "data/feeds/mitre_attack_cache.json" in legacy_inventory


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
            managed_unit_policy_path=str(MANAGED_UNIT_POLICY),
        )


def test_release_manifest_binds_separate_frozen_model_bundle(tmp_path: Path) -> None:
    release, package, policy, artifact, rollback = _fixture(tmp_path)
    bundle_root = tmp_path / "frozen-model-bundle"
    bundle_root.mkdir()
    bundle_manifest = bundle_root / "FROZEN_MODEL_BUNDLE_MANIFEST.json"
    bundle_manifest.write_text(
        json.dumps(
            {
                "schema_version": "frozen_model_bundle.v1",
                "bundle_id": "frozen_model_bundle_test",
                "artifact_inventory_sha256": "b" * 64,
            }
        ),
        encoding="utf-8",
    )
    bundle_package = tmp_path / "frozen-model-bundle.tar"
    bundle_package.write_bytes(b"bundle-recovery-package")
    manifest = build_manifest(
        revision=REVISION,
        release_root=release,
        package_path=package,
        rollback_location=rollback,
        configuration_paths={"policy": str(policy)},
        artifact_paths={"model": str(artifact)},
        managed_unit_policy_path=str(MANAGED_UNIT_POLICY),
        frozen_model_bundle_manifest_path=str(bundle_manifest),
        frozen_model_bundle_package_path=str(bundle_package),
    )
    output = release / "DEPLOYMENT_MANIFEST.json"
    write_manifest(output, manifest)

    assert verify_manifest(output, release)["verified"] is True
    assert manifest["frozen_model_bundle"]["bundle_id"] == (
        "frozen_model_bundle_test"
    )
    bundle_package.write_bytes(b"changed")
    with pytest.raises(ValueError, match="frozen model bundle"):
        verify_manifest(output, release)


def test_release_manifest_keeps_v2_records_readable(tmp_path: Path) -> None:
    release, package, policy, artifact, rollback = _fixture(tmp_path)
    manifest = build_manifest(
        revision=REVISION,
        release_root=release,
        package_path=package,
        rollback_location=rollback,
        configuration_paths={"policy": str(policy)},
        artifact_paths={"model": str(artifact)},
        managed_unit_policy_path=str(MANAGED_UNIT_POLICY),
    )
    manifest["schema_version"] = "honeypot_release_manifest.v2"
    manifest.pop("runtime_feed_provenance", None)
    output = release / "DEPLOYMENT_MANIFEST.json"
    write_manifest(output, manifest)

    assert verify_manifest(output, release)["verified"] is True
