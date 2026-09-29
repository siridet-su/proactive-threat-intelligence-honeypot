from __future__ import annotations

from pathlib import Path

from production.classification.classification_pipeline import NotebookParityClassifier
from production.classification.s1_advisory_classifier import S1AdvisoryClassifier
from production.classification.trust import is_trusted_classification_event
from production.utils.config import ProductionConfig
from production.workers import analysis_worker as analysis_worker_module
from production.workers import session_worker as session_worker_module
from production.workers.session_worker import SessionWorker


ROOT = Path(__file__).resolve().parents[1]
RULE_POLICY = str(ROOT / "configs" / "classification_rules.trusted.json")


def test_final_config_disables_securebert_without_reinterpreting_historical_threshold() -> None:
    config = ProductionConfig()

    assert config.enable_securebert is False
    assert config.classification_policy["bert_min_confidence"] == 0.55
    assert config.classification_policy["s1_advisory_enabled"] is False


def test_current_workers_do_not_expose_a_securebert_loader() -> None:
    assert not hasattr(session_worker_module, "load_securebert_classifier")
    assert not hasattr(analysis_worker_module, "load_securebert_classifier")


def test_current_workers_do_not_expose_the_retired_securebert_opt_in() -> None:
    assert not hasattr(session_worker_module, "_load_securebert_for_final_runtime")
    assert not hasattr(analysis_worker_module, "_load_securebert_for_replay")


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


def test_s1_runtime_contract_declares_raw_margins_and_advisory_authority() -> None:
    # Private artifact bytes are verified by the package loader and the
    # manifest-bound release gate, not copied into a clean source checkout.
    assert S1AdvisoryClassifier.score_type == "linear_svc_decision_margin"
    assert S1AdvisoryClassifier.calibrated_probability is None
    assert S1AdvisoryClassifier.authority == "advisory_only"
