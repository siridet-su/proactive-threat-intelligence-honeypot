from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from production.classification.classification_pipeline import NotebookParityClassifier
from production.classification.trust import is_trusted_classification_event
from production.utils.config import ProductionConfig
from production.workers import analysis_worker as analysis_worker_module
from production.workers import session_worker as session_worker_module
from production.workers.session_worker import SessionWorker


ROOT = Path(__file__).resolve().parents[1]
RULE_POLICY = str(ROOT / "configs" / "classification_rules.trusted.json")
S1_MANIFEST = ROOT / "models" / "command_ttp_s1" / "20260831_cclr2" / "FINAL_MODEL_MANIFEST.json"


def test_final_config_disables_securebert_without_reinterpreting_historical_threshold() -> None:
    config = ProductionConfig()

    assert config.enable_securebert is False
    assert config.classification_policy["bert_min_confidence"] == 0.55
    assert config.classification_policy["s1_advisory_enabled"] is False


def test_final_workers_do_not_call_securebert_loader_when_disabled(monkeypatch) -> None:
    config = SimpleNamespace(enable_securebert=False)
    environment = {}

    def unexpected_loader(*_args, **_kwargs):
        raise AssertionError("SecureBERT loader must not be called when disabled")

    monkeypatch.setattr(
        session_worker_module,
        "load_securebert_classifier",
        unexpected_loader,
    )
    monkeypatch.setattr(
        analysis_worker_module,
        "load_securebert_classifier",
        unexpected_loader,
    )

    assert session_worker_module._load_securebert_for_final_runtime(config, environment) is None
    assert analysis_worker_module._load_securebert_for_replay(config, environment) is None


def test_securebert_loading_is_an_explicit_compatibility_opt_in(monkeypatch) -> None:
    config = SimpleNamespace(enable_securebert=True)
    environment = {}
    sentinel = object()

    monkeypatch.setattr(
        session_worker_module,
        "load_securebert_classifier",
        lambda *_args, **_kwargs: sentinel,
    )

    assert session_worker_module._load_securebert_for_final_runtime(config, environment) is sentinel


def test_historical_securebert_threshold_has_no_effect_without_model() -> None:
    low = NotebookParityClassifier(
        bert_fn=None,
        high_confidence=0.01,
        rule_policy_path=RULE_POLICY,
    )
    high = NotebookParityClassifier(
        bert_fn=None,
        high_confidence=0.99,
        rule_policy_path=RULE_POLICY,
    )

    for command in ("whoami", "echo literal"):
        assert low.classify(command) == high.classify(command)


def test_s1_disagreement_remains_advisory_and_preserves_trusted_rule() -> None:
    class FakeAdvisory:
        def predict(self, command: str) -> dict:
            del command
            return {
                "schema_version": "s1_advisory_prediction.v1",
                "status": "loaded",
                "predicted_technique": "T1105",
                "topk": [
                    {
                        "technique_id": "T1105",
                        "decision_score": 4.0,
                        "score_type": "linear_svc_decision_margin",
                        "calibrated_probability": None,
                    }
                ],
                "decision_score": 4.0,
                "score_type": "linear_svc_decision_margin",
                "calibrated_probability": None,
                "authority": "advisory_only",
                "trusted_eligible": False,
                "canonical_write_allowed": False,
                "response_authority": False,
            }

    worker = SessionWorker.__new__(SessionWorker)
    worker.classifier = NotebookParityClassifier(bert_fn=None, rule_policy_path=RULE_POLICY)
    worker.s1_advisory_classifier = FakeAdvisory()

    event = worker._classify_with_s1_advisory("whoami")[0]

    assert event["ttp"] == "T1033"
    assert is_trusted_classification_event(event)
    assert event["s1_advisory"]["predicted_technique"] == "T1105"
    assert event["s1_advisory"]["authority"] == "advisory_only"
    assert event["s1_advisory"]["trusted_eligible"] is False
    assert event["s1_advisory"]["canonical_write_allowed"] is False
    assert event["s1_advisory"]["response_authority"] is False


def test_final_s1_manifest_declares_raw_margins_and_advisory_authority() -> None:
    manifest = json.loads(S1_MANIFEST.read_text(encoding="utf-8"))
    recipe = manifest["recipe"]

    assert recipe["model_family"] == "S1_TFIDF_CHAR_WORD_LINEARSVC"
    assert recipe["score_type"] == "linear_svc_decision_margin"
    assert recipe["calibrated_probability"] is None
    assert recipe["authority"] == "advisory_only"
