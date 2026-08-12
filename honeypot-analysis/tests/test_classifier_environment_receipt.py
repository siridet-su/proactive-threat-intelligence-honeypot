from __future__ import annotations

import hashlib
import json
from pathlib import Path


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
