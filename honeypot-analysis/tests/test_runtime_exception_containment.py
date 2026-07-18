from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from production.enrichment.enrichment_providers import OTXProvider, ProviderResult
from production.enrichment.feed_status import _cache_status
from production.classification.classification_pipeline import load_classification_rule_policy
from production.policies import validate_stix_bundle
from production.policies.threat_hypothesis_behavior_policy import load_behavior_policy
from production.tools import build_external_seed_model as seed_model_module
from production.workers import webhook_dispatcher
from production.workers import sensor_forwarder
from production.workers.threat_hunt_worker import ThreatHuntWorker


BARE_SENTINEL = "containment-probe-7f6e2c"


def _raise_runtime_error(*_args, **_kwargs):
    raise RuntimeError(BARE_SENTINEL)


def test_webhook_result_does_not_render_exception_arguments(monkeypatch) -> None:
    def fail_request(*_args, **_kwargs):
        raise OSError(BARE_SENTINEL)

    monkeypatch.setattr(webhook_dispatcher.urllib.request, "urlopen", fail_request)

    ok, error = webhook_dispatcher.post_webhook(
        "https://example.invalid/webhook",
        {"alert": "test"},
        1.0,
    )

    assert ok is False
    assert error == "OSError: operation_failed"
    assert BARE_SENTINEL not in error


def test_webhook_request_construction_does_not_render_url(monkeypatch) -> None:
    def fail_request(*_args, **_kwargs):
        raise ValueError(BARE_SENTINEL)

    monkeypatch.setattr(webhook_dispatcher.urllib.request, "Request", fail_request)

    ok, error = webhook_dispatcher.post_webhook(
        f"not-a-url?token={BARE_SENTINEL}",
        {"alert": "test"},
        1.0,
    )

    assert ok is False
    assert error == "ValueError: operation_failed"
    assert BARE_SENTINEL not in error


def test_forwarder_invalid_ingest_response_is_contained(tmp_path, monkeypatch) -> None:
    spool_path = tmp_path / "spool.ndjson"
    spool_path.write_text('{"eventid":"unit"}\n', encoding="utf-8")
    config = SimpleNamespace(
        cowrie_log_path=str(tmp_path / "missing-cowrie.json"),
        spool_path=str(spool_path),
        forwarder_batch_size=10,
    )
    monkeypatch.setattr(
        sensor_forwarder,
        "post_events",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError(BARE_SENTINEL)),
    )

    result = sensor_forwarder.forward_once(config)

    assert result.sent == 0
    assert result.remaining == 1
    assert result.error == "ValueError: operation_failed"
    assert BARE_SENTINEL not in json.dumps(result.__dict__)


def test_forwarder_rejects_non_mapping_acknowledgement(tmp_path, monkeypatch) -> None:
    spool_path = tmp_path / "spool.ndjson"
    spool_path.write_text('{"eventid":"unit"}\n', encoding="utf-8")
    config = SimpleNamespace(
        cowrie_log_path=str(tmp_path / "missing-cowrie.json"),
        spool_path=str(spool_path),
        forwarder_batch_size=10,
    )
    monkeypatch.setattr(sensor_forwarder, "post_events", lambda *_args, **_kwargs: [])

    result = sensor_forwarder.forward_once(config)

    assert result.sent == 0
    assert result.remaining == 1
    assert result.error == "ingest returned an invalid response object"


def test_pi_flat_forwarder_exception_fallback_is_constant(monkeypatch) -> None:
    monkeypatch.setattr(sensor_forwarder, "__package__", "production")

    error = sensor_forwarder._safe_exception_text(RuntimeError(BARE_SENTINEL))

    assert error == "operation_failed"
    assert BARE_SENTINEL not in error


def test_threat_hunt_failure_persistence_does_not_render_exception_arguments(monkeypatch) -> None:
    class Storage:
        def __init__(self) -> None:
            self.failure = None

        def claim_threat_hunt_jobs(self, _limit):
            return [{"job_id": "job-1", "attempts": 1}]

        def fail_threat_hunt_job(self, job_id, error, *, retry):
            self.failure = {"job_id": job_id, "error": error, "retry": retry}

    storage = Storage()
    worker = object.__new__(ThreatHuntWorker)
    worker.config = SimpleNamespace(threat_hunt_batch_size=1)
    worker.policy = {"enabled": True}
    worker.storage = storage
    monkeypatch.setattr(worker, "_process_job", _raise_runtime_error)

    assert worker.process_once() == 0
    assert storage.failure == {
        "job_id": "job-1",
        "error": "RuntimeError: operation_failed",
        "retry": True,
    }
    assert BARE_SENTINEL not in json.dumps(storage.failure)


def test_provider_and_provider_status_outputs_reject_unlabeled_exception_text(monkeypatch) -> None:
    provider = OTXProvider(api_key="configured")
    monkeypatch.setattr(provider, "_json_get", _raise_runtime_error)

    result = provider.enrich("ip", "198.51.100.23")

    assert result.error == "RuntimeError: operation_failed"
    assert result.to_status()["error"] == "RuntimeError: operation_failed"
    assert ProviderResult("custom", "error", error=BARE_SENTINEL).to_status()["error"] == "operation_failed"
    assert BARE_SENTINEL not in json.dumps(result.to_status())


def test_corrupt_feed_status_does_not_return_parser_exception_text(tmp_path) -> None:
    cache_path = tmp_path / "feed.json"
    cache_path.write_text(BARE_SENTINEL, encoding="utf-8")

    status = _cache_status(str(cache_path), "entries", 1)

    assert status["status"] == "corrupt"
    assert status["error"] == "ValueError: operation_failed"
    assert BARE_SENTINEL not in json.dumps(status)


def test_external_validator_failure_output_does_not_render_exception_arguments(monkeypatch) -> None:
    monkeypatch.setattr(validate_stix_bundle.importlib.util, "find_spec", lambda _name: object())
    monkeypatch.setattr(validate_stix_bundle.subprocess, "run", _raise_runtime_error)

    result = validate_stix_bundle.run_external_stix_validation("bundle.json")

    assert result["status"] == "failed"
    assert result["errors"] == ["RuntimeError: operation_failed"]
    assert BARE_SENTINEL not in json.dumps(result)


def test_external_validator_process_output_is_suppressed(monkeypatch) -> None:
    monkeypatch.setattr(validate_stix_bundle.importlib.util, "find_spec", lambda _name: object())
    monkeypatch.setattr(
        validate_stix_bundle.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=1,
            stdout=f"invalid value {BARE_SENTINEL}",
            stderr=f"schema rejected {BARE_SENTINEL}",
        ),
    )

    result = validate_stix_bundle.run_external_stix_validation("bundle.json")

    assert result["errors"] == ["external_stix_validator_failed"]
    assert result["output_suppressed"] is True
    assert result["stdout"] == ""
    assert result["stderr"] == ""
    assert BARE_SENTINEL not in json.dumps(result)


def test_runtime_policy_load_errors_do_not_render_parser_input(tmp_path) -> None:
    malformed = tmp_path / f"{BARE_SENTINEL}.json"
    malformed.write_text(BARE_SENTINEL, encoding="utf-8")

    classification = load_classification_rule_policy(str(malformed))
    behavior = load_behavior_policy(str(malformed))

    assert classification["load_errors"] == ["ValueError: operation_failed"]
    assert BARE_SENTINEL not in json.dumps(classification)
    assert BARE_SENTINEL not in json.dumps(behavior)


def test_securebert_fail_fast_error_does_not_render_exception_arguments(monkeypatch) -> None:
    monkeypatch.setattr(
        seed_model_module,
        "SecureBertCommandClassifier",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError(BARE_SENTINEL)),
    )

    with pytest.raises(RuntimeError) as error:
        seed_model_module._load_bert_fn(
            True,
            None,
            f"models/{BARE_SENTINEL}",
            "",
            "cpu",
            128,
            False,
        )

    assert str(error.value) == "RuntimeError: operation_failed"
    assert BARE_SENTINEL not in str(error.value)


@pytest.mark.parametrize(
    "relative_path",
    [
        "production/policies/validate_stix_bundle.py",
        "production/enrichment/threat_feed_loader.py",
        "production/enrichment/mitre_attack_loader.py",
    ],
)
def test_redaction_import_preserves_direct_script_loading(relative_path) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            "import runpy,sys; runpy.run_path(sys.argv[1], run_name='direct_import_test')",
            str(ROOT / relative_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 0, completed.stderr
