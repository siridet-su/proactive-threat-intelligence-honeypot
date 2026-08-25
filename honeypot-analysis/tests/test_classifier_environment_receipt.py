from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from production.classification.environment import load_classifier_environment
from production.reproduction.next_behavior.classifier_assets import (
    ClassifierAssetError,
    verify_classifier_source_identity,
)


ROOT = Path(__file__).resolve().parents[1]


def test_classifier_environment_receipt_matches_current_runtime_code() -> None:
    receipt = json.loads(
        (ROOT / "configs/next_behavior_classifier_environment.v1.json").read_text(
            encoding="utf-8"
        )
    )
    classifier = receipt["classifier"]
    assert classifier["adapter_sha256"] == hashlib.sha256(
        (ROOT / "production/classification/securebert_classifier.py").read_bytes()
    ).hexdigest()
    assert classifier["pipeline_sha256"] == hashlib.sha256(
        (ROOT / "production/classification/classification_pipeline.py").read_bytes()
    ).hexdigest()
    assert classifier["operation_parser_sha256"] == hashlib.sha256(
        (ROOT / "production/semantics/command_operations.py").read_bytes()
    ).hexdigest()
    assert receipt["classification_policy"]["rule_policy_sha256"] == (
        hashlib.sha256(
            (ROOT / "configs/classification_rules.trusted.json").read_bytes()
        ).hexdigest()
    )


def test_v3_classifier_source_identity_is_content_bound() -> None:
    receipt = json.loads(
        (ROOT / "configs/next_behavior_classifier_environment.v1.json").read_text(
            encoding="utf-8"
        )
    )
    assert receipt["schema_version"] == "next_behavior_classifier_environment.v3"
    identity = verify_classifier_source_identity(receipt, repository_root=ROOT)
    assert identity is not None
    assert identity["sha256"] == receipt["source_identity"]["sha256"]
    loaded = load_classifier_environment(verify_assets=True)
    assert loaded["environment_schema_version"] == "classification_environment.v3"
    assert loaded["source_identity"]["sha256"] == identity["sha256"]


@pytest.mark.parametrize(
    "relative",
    [
        "production/classification/classification_pipeline.py",
        "production/classification/authority.py",
        "production/classification/environment.py",
        "production/reproduction/next_behavior/classifier_assets.py",
        "production/semantics/command_operations.py",
        "production/prediction/trusted_history.py",
        "production/prediction/next_behavior_runtime.py",
        "configs/classification_rules.trusted.json",
        "production/classification/trust.py",
        "data/feeds/mitre_attack_cache.json",
    ],
)
def test_changed_classifier_source_identity_fails_closed(relative: str) -> None:
    receipt = json.loads(
        (ROOT / "configs/next_behavior_classifier_environment.v1.json").read_text(
            encoding="utf-8"
        )
    )
    receipt["source_identity"]["files"][relative] = "0" * 64
    with pytest.raises(ClassifierAssetError, match="source identity mismatch"):
        verify_classifier_source_identity(receipt, repository_root=ROOT)


def test_historical_v2_classifier_receipt_remains_readable(tmp_path: Path) -> None:
    receipt = json.loads(
        (ROOT / "configs/next_behavior_classifier_environment.v1.json").read_text(
            encoding="utf-8"
        )
    )
    receipt.pop("source_identity")
    receipt["schema_version"] = "next_behavior_classifier_environment.v2"
    receipt["freeze"]["release_revision"] = receipt["freeze"]["basis_commit"]
    path = tmp_path / "historical-v2.json"
    path.write_text(json.dumps(receipt), encoding="utf-8")
    loaded = load_classifier_environment(str(path), repository_root=ROOT, verify_assets=True)
    assert loaded["environment_schema_version"] == "classification_environment.v3"


def test_v3_deployed_marker_requires_release_manifest_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DEPLOYED_COMMIT", "a" * 40)
    with pytest.raises(
        ClassifierAssetError,
        match="classifier environment release binding is unavailable",
    ):
        load_classifier_environment(verify_assets=True)
