from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from production.tools.verify_next_behavior_classifier_assets import (
    ClassifierAssetError,
    load_classifier_manifest,
    validate_classifier_manifest,
    verify_classifier_assets,
)


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _fixture_manifest(repository_root: Path, model_root: Path) -> dict:
    paths = {
        "requirements-next-behavior-corpus.lock.txt": b"package==1\n",
        "production/classification/securebert_classifier.py": b"adapter\n",
        "production/classification/classification_pipeline.py": b"pipeline\n",
        "configs/classification_rules.trusted.json": b"rules\n",
        "data/feeds/mitre_attack_cache.json": b"mitre\n",
        "production/classification/trust.py": b"trust\n",
    }
    for relative_path, payload in paths.items():
        path = repository_root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    model_files = {
        "config.json": b"config\n",
        "label_mapping.json": b"labels\n",
        "tokenizer.json": b"tokenizer\n",
        "tokenizer_config.json": b"tokenizer-config\n",
        "checkpoint-6765/config.json": b"config\n",
        "checkpoint-6765/model.safetensors": b"weights\n",
        "checkpoint-6765/tokenizer.json": b"tokenizer\n",
        "checkpoint-6765/tokenizer_config.json": b"tokenizer-config\n",
    }
    for relative_path, payload in model_files.items():
        path = model_root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    return {
        "schema_version": "next_behavior_classifier_environment.v1",
        "python": {"implementation": "CPython", "version": "3.12.13"},
        "dependency_lock": {
            "path": "requirements-next-behavior-corpus.lock.txt",
            "sha256": _sha(paths["requirements-next-behavior-corpus.lock.txt"]),
        },
        "classifier": {
            "adapter": (
                "production.classification.securebert_classifier."
                "SecureBertCommandClassifier"
            ),
            "adapter_sha256": _sha(
                paths["production/classification/securebert_classifier.py"]
            ),
            "pipeline_sha256": _sha(
                paths["production/classification/classification_pipeline.py"]
            ),
            "checkpoint_id": "securebert_ttp_model_v2/checkpoint-6765",
            "checkpoint_sha256": _sha(
                model_files["checkpoint-6765/model.safetensors"]
            ),
            "parameter_count": 10,
            "label_count": 3,
            "device": "cpu",
            "max_length": 128,
            "files": {
                path: _sha(payload) for path, payload in model_files.items()
            },
        },
        "classification_policy": {
            "rule_policy_path": "configs/classification_rules.trusted.json",
            "rule_policy_sha256": _sha(
                paths["configs/classification_rules.trusted.json"]
            ),
            "mitre_cache_path": "data/feeds/mitre_attack_cache.json",
            "mitre_cache_sha256": _sha(
                paths["data/feeds/mitre_attack_cache.json"]
            ),
            "trust_policy_path": "production/classification/trust.py",
            "trust_policy_sha256": _sha(
                paths["production/classification/trust.py"]
            ),
            "securebert_candidate_threshold": 0.55,
            "trusted_model_only_threshold": 0.9,
            "drop_rule_securebert_disagreements": True,
            "compound_command_splitter": (
                "production.classification.classification_pipeline."
                "split_compound_command"
            ),
        },
        "freeze": {
            "basis_commit": "a" * 40,
            "historical_runtime_threshold_distinction_preserved": True,
            "raw_scores_are_probabilities": False,
        },
    }


def test_versioned_classifier_environment_manifest_is_strict() -> None:
    manifest = load_classifier_manifest(
        Path("configs/next_behavior_classifier_environment.v1.json")
    )
    assert validate_classifier_manifest(manifest) == []
    assert manifest["classifier"]["checkpoint_sha256"] == (
        "dc3a4e2a57a70c4c7cb5f769b6399f32b2b51f0245025653e0b72f6d025a759b"
    )
    assert manifest["classifier"]["parameter_count"] == 149755588
    assert manifest["classification_policy"]["trusted_model_only_threshold"] == 0.9


def test_fixture_assets_verify_without_storing_private_paths(
    tmp_path: Path,
) -> None:
    repository_root = tmp_path / "repository"
    model_root = tmp_path / "private-model"
    manifest = _fixture_manifest(repository_root, model_root)

    receipt = verify_classifier_assets(
        manifest,
        repository_root=repository_root,
        model_root=model_root,
    )

    assert receipt["status"] == "assets_verified"
    assert receipt["classifier"]["checkpoint_sha256"] == _sha(b"weights\n")
    assert str(model_root) not in json.dumps(receipt)


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (
            lambda value: value["classification_policy"].__setitem__(
                "trusted_model_only_threshold", 0.4
            ),
            "thresholds are inconsistent",
        ),
        (
            lambda value: value["classification_policy"].__setitem__(
                "drop_rule_securebert_disagreements", False
            ),
            "disagreements must remain audit-only",
        ),
        (
            lambda value: value["classifier"]["files"].update(
                {"../private/model.safetensors": "a" * 64}
            ),
            "exact frozen asset set",
        ),
        (
            lambda value: value["freeze"].__setitem__(
                "raw_scores_are_probabilities", True
            ),
            "must not be called probabilities",
        ),
    ],
)
def test_manifest_rejects_unsafe_or_semantically_inconsistent_values(
    tmp_path: Path,
    mutation,
    expected: str,
) -> None:
    value = _fixture_manifest(tmp_path / "repository", tmp_path / "model")
    mutation(value)
    assert expected in "; ".join(validate_classifier_manifest(value))


def test_asset_hash_mismatch_fails_closed_without_rewriting(
    tmp_path: Path,
) -> None:
    repository_root = tmp_path / "repository"
    model_root = tmp_path / "private-model"
    manifest = _fixture_manifest(repository_root, model_root)
    checkpoint = model_root / "checkpoint-6765/model.safetensors"
    checkpoint.write_bytes(b"corrupted")

    with pytest.raises(ClassifierAssetError, match="SHA-256 mismatch"):
        verify_classifier_assets(
            manifest,
            repository_root=repository_root,
            model_root=model_root,
        )

    assert checkpoint.read_bytes() == b"corrupted"


def test_manifest_rejects_nonfinite_threshold_or_missing_asset(
    tmp_path: Path,
) -> None:
    value = _fixture_manifest(tmp_path / "repository", tmp_path / "model")
    value["classification_policy"]["trusted_model_only_threshold"] = float("nan")
    assert "thresholds are inconsistent" in "; ".join(
        validate_classifier_manifest(value)
    )

    value = _fixture_manifest(tmp_path / "repository-2", tmp_path / "model-2")
    value["classifier"]["files"].pop("label_mapping.json")
    assert "exact frozen asset set" in "; ".join(
        validate_classifier_manifest(value)
    )


def test_loader_rejects_extra_secret_shaped_fields(tmp_path: Path) -> None:
    value = _fixture_manifest(tmp_path / "repository", tmp_path / "model")
    value["private_model_path"] = "/must/not/be/versioned"
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ClassifierAssetError, match="fields are invalid"):
        load_classifier_manifest(manifest_path)
