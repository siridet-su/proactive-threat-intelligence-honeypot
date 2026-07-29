from __future__ import annotations

import hashlib
import json
import tarfile
from pathlib import Path

import pytest

from production.tools import frozen_model_bundle as bundle


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _policy() -> dict[str, object]:
    return {
        "prediction_mode": bundle.TRANSFORMER_POC_MODE,
        "immutable_final_result_sha256": "f" * 64,
        "transformer_checkpoint_path": "data/models/checkpoint.pt",
        "transformer_checkpoint_sha256": "",
        "transformer_model_spec_path": "data/models/model_spec.json",
        "transformer_model_spec_file_sha256": "",
        "transformer_vocabulary_path": "data/models/vocabulary.json",
        "transformer_vocabulary_file_sha256": "",
        "transformer_calibration_path": "data/models/calibration.json",
        "transformer_calibration_file_sha256": "",
        "transformer_vocabulary_sha256": "e" * 64,
        "transformer_preprocessing_path": "configs/preprocessing.json",
        "runtime_rule_policy_path": "configs/rules.json",
        "runtime_trust_policy_path": "production/trust.py",
        "runtime_classifier_checkpoint_path": "models/securebert_ttp/checkpoint-6765/model.safetensors",
    }


def _fake_classifier_manifest(root: Path) -> dict[str, object]:
    files: dict[str, str] = {}
    for relative in bundle.SECUREBERT_RELATIVE_FILES:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(relative.encode("utf-8"))
        files[relative] = _sha(path)
    return {"classifier": {"files": files}}


def test_create_verify_archive_and_link_bundle_without_release_overlay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transformer_source = tmp_path / "old-release"
    model_source = tmp_path / "old-models" / "securebert_ttp"
    transformer_source.mkdir()
    paths = {
        "transformer_checkpoint": transformer_source / "data/models/checkpoint.pt",
        "transformer_model_spec": transformer_source / "data/models/model_spec.json",
        "transformer_vocabulary": transformer_source / "data/models/vocabulary.json",
        "transformer_calibration": transformer_source / "data/models/calibration.json",
    }
    for role, path in paths.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(role.encode("utf-8"))
    policy = _policy()
    for role, _path_key, hash_key in bundle.TRANSFORMER_SPECS:
        policy[hash_key] = _sha(paths[role])
    classifier_manifest = _fake_classifier_manifest(model_source)
    classifier_environment = tmp_path / "classifier-environment.json"
    classifier_environment.write_text("{}\n", encoding="utf-8")
    prediction_policy = tmp_path / "prediction-policy.json"
    prediction_policy.write_text("{}\n", encoding="utf-8")
    repository_root = tmp_path / "repository"
    repository_root.mkdir()

    def fake_policy(_path: Path) -> tuple[dict[str, object], str]:
        return dict(policy), "a" * 64

    def fake_runtime(_policy: object) -> dict[str, object]:
        return {"runtime": "verified"}

    def fake_classifier_manifest(_path: Path) -> dict[str, object]:
        return classifier_manifest

    def fake_classifier_receipt(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {
            "classifier": {
                "checkpoint_id": "test/checkpoint",
                "checkpoint_sha256": classifier_manifest["classifier"]["files"][
                    "checkpoint-6765/model.safetensors"
                ],
            }
        }

    monkeypatch.setattr(bundle, "_transformer_policy", fake_policy)
    monkeypatch.setattr(bundle, "_validate_transformer_runtime", fake_runtime)
    monkeypatch.setattr(bundle, "load_classifier_manifest", fake_classifier_manifest)
    monkeypatch.setattr(bundle, "verify_classifier_assets", fake_classifier_receipt)

    created = bundle.create_bundle(
        bundle_parent=tmp_path / "bundles",
        transformer_source_root=transformer_source,
        classifier_source_root=model_source,
        prediction_policy_path=prediction_policy,
        classifier_environment_path=classifier_environment,
        repository_root=repository_root,
    )
    root = next((tmp_path / "bundles").iterdir())
    assert created["verified"] is True
    assert root.name.startswith("frozen_model_bundle_")
    assert root.stat().st_mode & 0o077 == 0
    assert not str(root.resolve()).startswith(str(transformer_source.resolve()))
    assert (root / bundle.MANIFEST_NAME).is_file()
    assert (root / "transformer/checkpoint.pt").read_bytes() == b"transformer_checkpoint"

    verified = bundle.verify_bundle(
        bundle_root=root,
        prediction_policy_path=prediction_policy,
        classifier_environment_path=classifier_environment,
        repository_root=repository_root,
        runtime_check=True,
    )
    assert verified["runtime_identity"] == {"runtime": "verified"}

    release = tmp_path / "clean-release"
    (release / "data/models").mkdir(parents=True)
    links = bundle.install_release_links(release_root=release, bundle_root=root)
    assert links["release_links"]["models"] == str(root)
    assert (release / "data/models/checkpoint.pt").resolve() == root / "transformer/checkpoint.pt"
    assert (release / "models/securebert_ttp").resolve() == root / "securebert_ttp"

    archive = tmp_path / "bundle.tar"
    archive_receipt = bundle.archive_bundle(bundle_root=root, archive_path=archive)
    assert archive_receipt["sha256"] == _sha(archive)
    with tarfile.open(archive) as handle:
        assert f"{root.name}/{bundle.MANIFEST_NAME}" in handle.getnames()


def test_release_link_installation_refuses_existing_artifact(tmp_path: Path) -> None:
    release = tmp_path / "release"
    (release / "data/models").mkdir(parents=True)
    (release / "data/models/checkpoint.pt").write_bytes(b"unexpected")
    root = tmp_path / "bundle"
    root.mkdir()
    artifacts = {
        role: {"relative_path": f"transformer/{name}"}
        for role, _path_key, _hash_key in bundle.TRANSFORMER_SPECS
        for name in ["checkpoint.pt" if role == "transformer_checkpoint" else f"{role}.json"]
    }
    (root / bundle.MANIFEST_NAME).write_text(
        json.dumps(
            {
                "schema_version": bundle.SCHEMA_VERSION,
                "transformer": {"artifacts": artifacts},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(bundle.FrozenModelBundleError, match="already exists"):
        bundle.install_release_links(release_root=release, bundle_root=root)
