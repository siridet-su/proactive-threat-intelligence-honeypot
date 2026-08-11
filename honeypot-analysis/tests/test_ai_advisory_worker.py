from __future__ import annotations

import copy
import json
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from production.ai_advisory.contracts import (
    AIAdvisoryContractError,
    load_ai_advisory_policy,
    validate_provider_output,
)
from production.ai_advisory.projection import build_ai_advisory_projection
from production.ai_advisory.contracts import sha256_json
from production.ai_advisory.provider import AIProviderResponse, AIProviderUnavailable
from production.ai_advisory.security import ProviderAliasScope
from production.reporting.session_assessment_v4 import build_session_assessment_v4
from production.storage.backend import SQLITE_SCHEMA_VERSION, SQLiteStorage, StorageError
from production.utils.config import ProductionConfig
from production.workers.ai_advisory_worker import AIAdvisoryWorker


ROOT = Path(__file__).resolve().parents[1]
BEHAVIOR_POLICY = ROOT / "configs" / "threat_hypothesis_behavior.trusted.json"
CLASSIFICATION_POLICY = ROOT / "configs" / "classification_rules.trusted.json"
RECONCILIATION_CUTOFF = {
    "schema_version": "prediction_evidence_cutoff.v1",
    "received_at": "2026-08-08T10:59:59.000000+00:00",
    "event_id": "event-cutoff",
}


def _report(session_id: str = "ai-worker-session") -> dict:
    event = {
        "session": session_id,
        "src_ip": "192.0.2.220",
        "timestamp": "2026-08-08T11:00:00Z",
        "eventid": "cowrie.command.success",
        "input": "uname -a",
        "success": 1,
    }
    payload = {
        "session_id": session_id,
        "src_ip": "192.0.2.220",
        "commands": ["uname -a"],
        "commands_success": ["uname -a"],
        "classification_events": [],
        "raw_events": [event],
    }
    return build_session_assessment_v4(
        [payload],
        raw_events=[event],
        behavior_policy_path=str(BEHAVIOR_POLICY),
        classification_policy_path=str(CLASSIFICATION_POLICY),
    )


def _storage_with_report(tmp_path: Path, *, enqueue: bool = True):
    storage = SQLiteStorage(f"sqlite:///{tmp_path / 'state.db'}")
    storage.initialize()
    report = _report()
    storage.save_session(
        {"session_id": "ai-worker-session", "src_ip": "192.0.2.220"}
    )
    if enqueue:
        storage.store_event(
            "sensor-test",
            {
                "eventid": "cowrie.session.connect",
                "session": "ai-worker-session",
            },
        )
    job_id = storage.enqueue_analysis_job({"session_id": "ai-worker-session"})
    job = storage.claim_analysis_jobs("analysis-owner", 1, 60, 3)[0]
    report_id = storage.complete_analysis_job(
        job_id,
        "analysis-owner",
        job["claim_token"],
        report,
        enqueue_ai_advisory=enqueue,
        ai_advisory_reconciliation_cutoff=RECONCILIATION_CUTOFF,
    )
    return storage, report, report_id


def _fixture_alias_scope() -> ProviderAliasScope:
    from production.ai_advisory.contracts import sha256_json

    scope = sha256_json(
        {
            "provider_id": "fixture",
            "model_id": "fixture-model",
            "adapter_revision": "fixture.v1",
            "endpoint": "",
            "api_version": "",
        }
    )
    return ProviderAliasScope(b"a" * 32, scope)


def _response(report: dict) -> dict:
    policy, digest, _ = load_ai_advisory_policy()
    projection = build_ai_advisory_projection(
        report,
        policy=policy,
        policy_sha256=digest,
        alias_scope=_fixture_alias_scope(),
    )
    return _response_for_projection(projection)


def _response_for_projection(projection: dict) -> dict:
    finding_id = next(
        item["finding_id"]
        for item in projection["findings"]
        if item["origin"] == "session_assessment.v4"
    )
    return {
        "schema_version": "ai_provider_output.v1",
        "projection_sha256": projection["projection_sha256"],
        "policy_sha256": projection["provenance"]["ai_policy_sha256"],
        "validated_advisory": {
            "schema_version": "ai_validated_advisory_selection.v1",
            "abstained": False,
            "abstention_reason_code": "",
            "selected_finding_ids": [finding_id],
            "selected_relationship_ids": [],
            "ranked_action_ids": [],
            "template_selections": [
                {
                    "template_id": "summarize_selected_findings",
                    "finding_ids": [finding_id],
                    "relationship_ids": [],
                    "action_ids": [],
                    "limitation_codes": [],
                    "reason_codes": ["multiple_supported_findings"],
                }
            ],
        },
        "shadow_candidates": {
            "schema_version": "ai_shadow_candidate_set.v1",
            "candidates": [],
        },
    }


def _config(tmp_path: Path, fixture: Path, *, enabled: bool = True) -> ProductionConfig:
    key_path = tmp_path / "ai-alias.key"
    key_path.write_bytes(b"a" * 32)
    key_path.chmod(0o600)
    checked = datetime.now(timezone.utc) - timedelta(minutes=1)
    receipt_path = tmp_path / "ai-activation.json"
    receipt_path.write_text(
        json.dumps(
            {
                "schema_version": "ai_advisory_activation_receipt.v1",
                "status": "ready",
                "provider_id": "fixture",
                "model_id": "fixture-model",
                "adapter_revision": "fixture.v1",
                "endpoint_sha256": "",
                "provider_adapter_reviewed": True,
                "managed_worker_unit": "honeypot-ai-advisory-worker.service",
                "worker_status": "ready",
                "credentials_status": "not_required",
                "reconciliation_mode": "new_sessions_only",
                "reconciliation_cutoff": RECONCILIATION_CUTOFF,
                "health_checked_at": checked.isoformat(),
                "expires_at": (checked + timedelta(minutes=30)).isoformat(),
            }
        ),
        encoding="utf-8",
    )
    receipt_path.chmod(0o600)
    return ProductionConfig(
        database_backend="sqlite",
        sqlite_database_path=str(tmp_path / "state.db"),
        enable_ai_advisory=enabled,
        ai_advisory_provider="fixture",
        ai_advisory_model="fixture-model",
        ai_advisory_adapter_revision="fixture.v1",
        ai_advisory_fixture_response_path=str(fixture),
        ai_advisory_alias_key_file=str(key_path.resolve()),
        ai_advisory_activation_receipt_path=str(receipt_path.resolve()),
        ai_advisory_reconciliation_cutoff=RECONCILIATION_CUTOFF,
    )


def test_schema_extension_and_optional_atomic_outbox(tmp_path: Path) -> None:
    storage, report, _report_id = _storage_with_report(tmp_path, enqueue=True)
    rows = storage.list_rows("ai_advisory_outbox")
    assert SQLITE_SCHEMA_VERSION == 3
    assert len(rows) == 1
    assert rows[0]["assessment_id"] == report["assessment_id"]
    assert rows[0]["status"] == "queued"

    with storage.connection() as conn:
        assert int(conn.execute("PRAGMA user_version").fetchone()[0]) == 3
        extension = conn.execute(
            """
            SELECT extension_id, checksum FROM schema_extensions
            WHERE extension_id = 'non_authoritative_ai_advisory.v1'
            """
        ).fetchone()
        assert extension["extension_id"] == "non_authoritative_ai_advisory.v1"
        assert len(extension["checksum"]) == 64
        assert conn.execute("PRAGMA quick_check").fetchone()[0] == "ok"


def test_schema_extension_checksum_tampering_fails_closed(tmp_path: Path) -> None:
    storage, _report, _report_id = _storage_with_report(tmp_path, enqueue=False)
    storage.initialize_ai_advisory_extension()
    with storage.connection() as conn:
        conn.execute(
            """
            UPDATE schema_extensions SET checksum=? WHERE extension_id=?
            """,
            ("f" * 64, "non_authoritative_ai_advisory.v1"),
        )
    with pytest.raises(StorageError, match="checksum mismatch"):
        storage.initialize_ai_advisory_extension()


def test_ai_disabled_does_not_process_or_change_canonical_report(tmp_path: Path) -> None:
    storage, report, report_id = _storage_with_report(tmp_path, enqueue=True)
    before = copy.deepcopy(storage.get_report_by_id(report_id)["payload"])
    fixture = tmp_path / "response.json"
    fixture.write_text(json.dumps(_response(report)), encoding="utf-8")
    worker = AIAdvisoryWorker(
        _config(tmp_path, fixture, enabled=False), storage=storage
    )

    assert worker.process_once() == 0
    assert storage.get_report_by_id(report_id)["payload"] == before
    assert storage.get_ai_advisory_for_session("ai-worker-session") is None


def test_success_persists_separate_advisory_and_preserves_report(tmp_path: Path) -> None:
    storage, report, report_id = _storage_with_report(tmp_path, enqueue=True)
    before_row = storage.get_report_by_id(report_id)
    before = copy.deepcopy(before_row["payload"])
    before_json = before_row["payload_json"]
    fixture = tmp_path / "response.json"
    fixture.write_text(json.dumps(_response(report)), encoding="utf-8")
    worker = AIAdvisoryWorker(_config(tmp_path, fixture), storage=storage)

    assert worker.process_once() == 1
    assert storage.get_report_by_id(report_id)["payload"] == before
    assert storage.get_report_by_id(report_id)["payload_json"] == before_json
    row = storage.get_ai_advisory_for_session("ai-worker-session")
    assert row["status"] == "accepted"
    assert row["payload"]["authority"] == "non_authoritative_advisory_only"
    assert row["payload"]["safety"] == {
        "requires_manual_approval": True,
        "safe_to_auto_execute": False,
        "alerts_authorized": False,
        "response_actions_authorized": False,
    }
    assert "uname -a" not in row["payload_json"]
    assert "192.0.2.220" not in row["payload_json"]
    assert "uname -a" not in storage.list_rows("ai_advisory_outbox")[0][
        "payload_json"
    ]
    assert "ai" not in stable_report_keys(before)


def stable_report_keys(value: dict) -> set[str]:
    return {str(key).lower() for key in value}


class _UnavailableProvider:
    provider_id = "fixture"
    model_id = "fixture-model"

    def generate(
        self,
        projection,
        *,
        prompt_contract,
        response_schema,
        schema_sha256,
        policy_sha256,
        timeout_seconds,
        max_response_bytes,
        idempotency_key,
    ):
        del (
            projection,
            prompt_contract,
            response_schema,
            schema_sha256,
            policy_sha256,
            timeout_seconds,
            max_response_bytes,
            idempotency_key,
        )
        raise AIProviderUnavailable("synthetic timeout")


def test_provider_timeout_retries_without_changing_report(tmp_path: Path) -> None:
    storage, report, report_id = _storage_with_report(tmp_path, enqueue=True)
    before = copy.deepcopy(storage.get_report_by_id(report_id)["payload"])
    fixture = tmp_path / "unused.json"
    worker = AIAdvisoryWorker(
        _config(tmp_path, fixture),
        provider=_UnavailableProvider(),
        storage=storage,
    )

    assert worker.process_once() == 0
    assert storage.get_report_by_id(report_id)["payload"] == before
    row = storage.list_rows("ai_advisory_outbox")[0]
    assert row["status"] == "retry"
    assert row["last_error_code"] == "ai_provider_unavailable"
    assert storage.get_ai_advisory_for_session("ai-worker-session") is None


def test_provider_outage_stops_after_bounded_attempts(tmp_path: Path) -> None:
    storage, _report, report_id = _storage_with_report(tmp_path, enqueue=True)
    before_json = storage.get_report_by_id(report_id)["payload_json"]
    fixture = tmp_path / "unused.json"
    config = _config(tmp_path, fixture)
    config.ai_advisory_max_attempts = 1
    worker = AIAdvisoryWorker(
        config,
        provider=_UnavailableProvider(),
        storage=storage,
    )

    assert worker.process_once() == 0
    row = storage.list_rows("ai_advisory_outbox")[0]
    assert row["status"] == "failed"
    assert row["attempts"] == 1
    assert row["last_error_code"] == "ai_provider_unavailable"
    assert storage.get_report_by_id(report_id)["payload_json"] == before_json


def test_malformed_or_invented_output_is_rejected_and_never_canonical(
    tmp_path: Path,
) -> None:
    storage, report, report_id = _storage_with_report(tmp_path, enqueue=True)
    before = copy.deepcopy(storage.get_report_by_id(report_id)["payload"])
    response = _response(report)
    response["validated_advisory"]["selected_finding_ids"] = [
        "finding_ffffffffffffffffffffffffffffffff"
    ]
    fixture = tmp_path / "response.json"
    fixture.write_text(json.dumps(response), encoding="utf-8")
    worker = AIAdvisoryWorker(_config(tmp_path, fixture), storage=storage)

    assert worker.process_once() == 1
    assert storage.get_report_by_id(report_id)["payload"] == before
    row = storage.get_ai_advisory_for_session("ai-worker-session")
    assert row["status"] == "rejected"
    assert row["payload"]["validation"]["reason_code"] == "invented_reference"
    assert row["payload"]["validated_advisory"] == {}
    assert row["payload"]["shadow_candidates"]["candidates"] == []


def test_malformed_provider_json_fails_closed_without_an_advisory(
    tmp_path: Path,
) -> None:
    storage, _report, report_id = _storage_with_report(tmp_path, enqueue=True)
    before_json = storage.get_report_by_id(report_id)["payload_json"]
    fixture = tmp_path / "response.json"
    fixture.write_text('{"not": "closed"', encoding="utf-8")
    worker = AIAdvisoryWorker(_config(tmp_path, fixture), storage=storage)

    assert worker.process_once() == 0
    assert storage.get_report_by_id(report_id)["payload_json"] == before_json
    row = storage.list_rows("ai_advisory_outbox")[0]
    assert row["status"] == "failed"
    assert row["last_error_code"] == "ai_job_invalid"
    assert storage.get_ai_advisory_for_session("ai-worker-session") is None


class _NeverCalledProvider:
    provider_id = "fixture"
    model_id = "fixture-model"
    adapter_revision = "fixture.v1"
    endpoint_sha256 = ""
    api_version = ""
    request_options_sha256 = ""

    def generate(self, projection, **kwargs):  # pragma: no cover - must not run
        del projection, kwargs
        raise AssertionError("the deterministic cache should prevent a provider call")


class _RecordingProvider:
    provider_id = "fixture"
    model_id = "fixture-model"
    adapter_revision = "fixture.v1"
    endpoint_sha256 = ""
    api_version = ""
    request_options_sha256 = ""

    def __init__(
        self,
        *,
        delay: float = 0.0,
        response_hash: str | None = None,
        usage_metadata: dict | None = None,
    ):
        self.delay = delay
        self.response_hash = response_hash
        self.usage_metadata = usage_metadata or {}
        self.idempotency_keys: list[str] = []
        self.projection = None
        self.response = None

    def generate(self, projection, **kwargs):
        self.projection = copy.deepcopy(dict(projection))
        self.idempotency_keys.append(kwargs["idempotency_key"])
        if self.delay:
            time.sleep(self.delay)
        output = _response_for_projection(dict(projection))
        self.response = AIProviderResponse(
            provider_id=self.provider_id,
            model_id=self.model_id,
            structured_output=output,
            response_sha256=(
                self.response_hash
                if self.response_hash is not None
                else sha256_json(output)
            ),
            adapter_revision=self.adapter_revision,
            usage_metadata=self.usage_metadata,
        )
        return self.response


def test_worker_acceptance_and_redundant_provider_scoped_validation_agree(
    tmp_path: Path,
) -> None:
    storage, _report_value, _report_id = _storage_with_report(
        tmp_path, enqueue=True
    )
    provider = _RecordingProvider()
    worker = AIAdvisoryWorker(
        _config(tmp_path, tmp_path / "unused.json"),
        provider=provider,
        storage=storage,
    )

    assert worker.process_once() == 1
    assert storage.get_ai_advisory_for_session("ai-worker-session")[
        "status"
    ] == "accepted"
    assert provider.projection is not None and provider.response is not None
    provider_digest = provider.projection["provenance"]["ai_policy_sha256"]
    assert provider_digest != worker.policy_sha256
    assert validate_provider_output(
        provider.response.structured_output,
        projection=provider.projection,
        policy=worker.policy,
        policy_sha256=provider_digest,
    )["validated_advisory"]


class _AuthenticationFailureProvider(_RecordingProvider):
    def generate(self, projection, **kwargs):
        del projection, kwargs
        raise AIAdvisoryContractError(
            "synthetic redacted authentication failure",
            code="provider_authentication_failed",
        )


class _MismatchedIdentityProvider(_RecordingProvider):
    def generate(self, projection, **kwargs):
        output = _response_for_projection(dict(projection))
        return AIProviderResponse(
            provider_id="different-provider",
            model_id=self.model_id,
            structured_output=output,
            response_sha256=sha256_json(output),
            adapter_revision=self.adapter_revision,
        )


def test_authentication_failure_cannot_change_committed_deterministic_report(
    tmp_path: Path,
) -> None:
    storage, report, report_id = _storage_with_report(tmp_path, enqueue=True)
    before_json = storage.get_report_by_id(report_id)["payload_json"]
    fixture = tmp_path / "unused.json"
    worker = AIAdvisoryWorker(
        _config(tmp_path, fixture),
        provider=_AuthenticationFailureProvider(),
        storage=storage,
    )

    assert worker.process_once() == 0
    assert storage.get_report_by_id(report_id)["payload_json"] == before_json
    assert storage.get_report_by_id(report_id)["payload"] == report
    outbox = storage.list_rows("ai_advisory_outbox")[0]
    assert outbox["status"] == "failed"
    assert outbox["last_error_code"] == "ai_job_invalid"
    assert storage.get_ai_advisory_for_session("ai-worker-session") is None


def test_provider_identity_mismatch_is_rejected_without_changing_report(
    tmp_path: Path,
) -> None:
    storage, _report_value, report_id = _storage_with_report(tmp_path, enqueue=True)
    before_json = storage.get_report_by_id(report_id)["payload_json"]
    fixture = tmp_path / "unused.json"
    worker = AIAdvisoryWorker(
        _config(tmp_path, fixture),
        provider=_MismatchedIdentityProvider(),
        storage=storage,
    )

    assert worker.process_once() == 1
    assert storage.get_report_by_id(report_id)["payload_json"] == before_json
    row = storage.get_ai_advisory_for_session("ai-worker-session")
    assert row["status"] == "rejected"
    assert row["payload"]["validation"]["reason_code"] == (
        "provider_identity_mismatch"
    )


def test_accepted_provider_usage_is_bounded_to_aggregate_metrics(tmp_path: Path) -> None:
    storage, report, _report_id = _storage_with_report(tmp_path, enqueue=True)
    fixture = tmp_path / "unused.json"
    provider = _RecordingProvider(
        usage_metadata={
            "prompt_token_count": 100,
            "candidates_token_count": 20,
            "thoughts_token_count": 5,
            "total_token_count": 125,
            "traffic_type": "ON_DEMAND",
            "unexpected": "must-not-persist",
        }
    )
    worker = AIAdvisoryWorker(
        _config(tmp_path, fixture), provider=provider, storage=storage
    )

    assert worker.process_once() == 1
    metrics = storage.get_ai_advisory_for_session("ai-worker-session")["metrics"]
    assert metrics["provider_prompt_token_count"] == 100
    assert metrics["provider_candidates_token_count"] == 20
    assert metrics["provider_thoughts_token_count"] == 5
    assert metrics["provider_total_token_count"] == 125
    assert metrics["provider_traffic_type"] == "ON_DEMAND"
    assert "unexpected" not in metrics
    assert storage.get_report_by_id(_report_id)["payload"] == report


def test_identical_request_replays_content_addressed_cache(tmp_path: Path) -> None:
    storage, report, _report_id = _storage_with_report(tmp_path, enqueue=True)
    fixture = tmp_path / "response.json"
    fixture.write_text(json.dumps(_response(report)), encoding="utf-8")
    first = AIAdvisoryWorker(_config(tmp_path, fixture), storage=storage)
    assert first.process_once() == 1
    advisory = storage.get_ai_advisory_for_session("ai-worker-session")

    with storage.connection() as conn:
        conn.execute(
            """
            UPDATE ai_advisory_outbox
            SET status='queued', attempts=0, next_retry_at=NULL,
                claim_owner=NULL, claim_token=NULL, claim_expires_at=NULL,
                advisory_id=NULL, completed_at=NULL
            """
        )

    replay = AIAdvisoryWorker(
        _config(tmp_path, fixture),
        provider=_NeverCalledProvider(),
        storage=storage,
    )
    assert replay.process_once() == 1
    row = storage.list_rows("ai_advisory_outbox")[0]
    assert row["status"] == "succeeded"
    assert row["completion_code"] == "cache_replayed"
    assert row["advisory_id"] == advisory["advisory_id"]
    assert len(storage.list_rows("ai_advisories")) == 1


def test_request_budget_rejects_before_provider_invocation(tmp_path: Path) -> None:
    storage, _report, report_id = _storage_with_report(tmp_path, enqueue=True)
    fixture = tmp_path / "unused.json"
    config = _config(tmp_path, fixture)
    config.ai_advisory_max_request_bytes = 1
    worker = AIAdvisoryWorker(
        config,
        provider=_NeverCalledProvider(),
        storage=storage,
    )

    assert worker.process_once() == 0
    row = storage.list_rows("ai_advisory_outbox")[0]
    assert row["status"] == "failed"
    assert row["last_error_code"] == "ai_job_invalid"
    assert storage.get_report_by_id(report_id)["payload"]["schema_version"] == (
        "session_assessment.v4"
    )


def test_provider_options_are_part_of_cache_provenance_identity(tmp_path: Path) -> None:
    storage, report, _report_id = _storage_with_report(tmp_path, enqueue=False)
    fixture = tmp_path / "response.json"
    fixture.write_text(json.dumps(_response(report)), encoding="utf-8")
    first_worker = AIAdvisoryWorker(_config(tmp_path, fixture), storage=storage)
    projection = build_ai_advisory_projection(
        report,
        policy=first_worker.policy,
        policy_sha256=first_worker.policy_sha256,
    )
    first = first_worker._request_identity(projection)
    changed_config = _config(tmp_path, fixture)
    changed_config.ai_advisory_request_options = {"temperature": 0.2}
    second_worker = AIAdvisoryWorker(changed_config, storage=storage)
    second = second_worker._request_identity(projection)
    assert first["request_options_sha256"] != second["request_options_sha256"]
    assert first["request_sha256"] != second["request_sha256"]
    assert first["cache_key"] != second["cache_key"]


def test_advisory_retention_strictly_expires_all_old_extension_rows(
    tmp_path: Path,
) -> None:
    storage, report, _report_id = _storage_with_report(tmp_path, enqueue=True)
    fixture = tmp_path / "response.json"
    fixture.write_text(json.dumps(_response(report)), encoding="utf-8")
    worker = AIAdvisoryWorker(_config(tmp_path, fixture), storage=storage)
    assert worker.process_once() == 1
    first = storage.list_rows("ai_advisories")[0]
    with storage.connection() as conn:
        conn.execute(
            """
            INSERT INTO ai_advisories
            (advisory_id, cache_key, report_id, session_id, assessment_id,
             status, projection_sha256, request_sha256, response_sha256,
             provider_id, model_id, prompt_sha256, schema_sha256,
             policy_sha256, payload_json, metrics_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "ai_advisory_old_00000000000000000000000000000000",
                "ai_cache_old_00000000000000000000000000000000",
                first["report_id"],
                first["session_id"],
                first["assessment_id"],
                "accepted",
                first["projection_sha256"],
                first["request_sha256"],
                first["response_sha256"],
                first["provider_id"],
                first["model_id"],
                first["prompt_sha256"],
                first["schema_sha256"],
                first["policy_sha256"],
                first["payload_json"],
                first["metrics_json"],
                "2020-01-01T00:00:00+00:00",
            ),
        )
        conn.execute(
            "UPDATE ai_advisories SET created_at=? WHERE advisory_id=?",
            ("2020-01-02T00:00:00+00:00", first["advisory_id"]),
        )
        conn.execute(
            "UPDATE ai_advisory_outbox SET updated_at=? WHERE job_id=?",
            ("2020-01-01T00:00:00+00:00", storage.list_rows("ai_advisory_outbox")[0]["job_id"]),
        )

    result = storage.prune_ai_advisories(
        30,
        keep_latest_per_session=False,
        now="2026-08-08T00:00:00+00:00",
    )
    assert result["advisories_deleted"] == 2
    assert result["outbox_deleted"] == 1
    assert storage.list_rows("ai_advisories") == []
    assert storage.list_rows("ai_advisory_outbox") == []


def test_previous_release_reader_can_use_database_with_additive_extension(
    tmp_path: Path,
) -> None:
    storage, _report, report_id = _storage_with_report(tmp_path, enqueue=False)
    database_path = tmp_path / "state.db"
    with sqlite3.connect(database_path) as legacy:
        legacy.row_factory = sqlite3.Row
        assert int(legacy.execute("PRAGMA user_version").fetchone()[0]) == SQLITE_SCHEMA_VERSION
        row = legacy.execute(
            "SELECT report_id, session_id, payload_json FROM reports WHERE report_id=?",
            (report_id,),
        ).fetchone()
        assert row is not None
        assert row["report_id"] == report_id
        assert json.loads(row["payload_json"])["schema_version"] == "session_assessment.v4"
        assert legacy.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0] == 0


def test_canonical_initialize_ignores_broken_optional_ai_storage(tmp_path: Path) -> None:
    database = tmp_path / "state.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE ai_advisories (wrong_column TEXT)")
    storage = SQLiteStorage(f"sqlite:///{database}")
    storage.initialize()
    assert storage.list_rows("reports") == []


def test_canonical_report_commit_survives_ai_enqueue_failure(
    tmp_path: Path, monkeypatch
) -> None:
    storage = SQLiteStorage(f"sqlite:///{tmp_path / 'state.db'}")
    storage.initialize()
    report = _report()
    storage.save_session({"session_id": "ai-worker-session"})
    job_id = storage.enqueue_analysis_job({"session_id": "ai-worker-session"})
    job = storage.claim_analysis_jobs("owner", 1, 60, 3)[0]

    def fail_extension():
        raise StorageError("synthetic optional extension failure")

    monkeypatch.setattr(storage, "initialize_ai_advisory_extension", fail_extension)
    report_id = storage.complete_analysis_job(
        job_id,
        "owner",
        job["claim_token"],
        report,
        enqueue_ai_advisory=True,
    )
    assert report_id
    assert storage.get_report_by_id(report_id)["payload"]["assessment_id"] == report[
        "assessment_id"
    ]


def test_non_sha_provider_hash_is_rejected_with_only_local_digest(
    tmp_path: Path,
) -> None:
    storage, _report_value, _report_id = _storage_with_report(tmp_path, enqueue=True)
    fixture = tmp_path / "unused.json"
    provider = _RecordingProvider(response_hash="attacker-controlled-not-a-sha")
    worker = AIAdvisoryWorker(
        _config(tmp_path, fixture), provider=provider, storage=storage
    )
    assert worker.process_once() == 1
    row = storage.get_ai_advisory_for_session("ai-worker-session")
    assert row["status"] == "rejected"
    assert row["payload"]["validation"]["reason_code"] == "hash_mismatch"
    assert row["response_sha256"] != "attacker-controlled-not-a-sha"
    assert len(row["response_sha256"]) == 64


def test_adapter_that_ignores_timeout_cannot_block_worker(tmp_path: Path) -> None:
    storage, _report_value, _report_id = _storage_with_report(tmp_path, enqueue=True)
    fixture = tmp_path / "unused.json"
    config = _config(tmp_path, fixture)
    config.ai_advisory_timeout_seconds = 0.02
    provider = _RecordingProvider(delay=0.5)
    started = time.monotonic()
    worker = AIAdvisoryWorker(config, provider=provider, storage=storage)
    assert worker.process_once() == 0
    assert time.monotonic() - started < 0.3
    assert storage.list_rows("ai_advisory_outbox")[0]["status"] == "retry"


def test_retry_after_post_provider_crash_reuses_idempotency_key(
    tmp_path: Path, monkeypatch
) -> None:
    storage, _report_value, _report_id = _storage_with_report(tmp_path, enqueue=True)
    fixture = tmp_path / "unused.json"
    provider = _RecordingProvider()
    worker = AIAdvisoryWorker(
        _config(tmp_path, fixture), provider=provider, storage=storage
    )
    original = storage.complete_ai_advisory_job
    calls = 0

    def crash_before_completion(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise StorageError("synthetic crash after provider response")
        return original(*args, **kwargs)

    monkeypatch.setattr(storage, "complete_ai_advisory_job", crash_before_completion)
    assert worker.process_once() == 0
    with storage.connection() as connection:
        connection.execute(
            "UPDATE ai_advisory_outbox SET next_retry_at=NULL WHERE status='retry'"
        )
    assert worker.process_once() == 1
    assert len(provider.idempotency_keys) == 2
    assert provider.idempotency_keys[0] == provider.idempotency_keys[1]
    assert len(storage.list_rows("ai_advisories")) == 1


def test_global_retention_bound_applies_across_unique_sessions(tmp_path: Path) -> None:
    storage, report, _report_id = _storage_with_report(tmp_path, enqueue=True)
    fixture = tmp_path / "response.json"
    fixture.write_text(json.dumps(_response(report)), encoding="utf-8")
    worker = AIAdvisoryWorker(_config(tmp_path, fixture), storage=storage)
    assert worker.process_once() == 1
    source = storage.list_rows("ai_advisories")[0]
    with storage.connection() as connection:
        for index in range(20):
            values = dict(source)
            values.update(
                advisory_id=f"ai_advisory_bound_{index:032d}",
                cache_key=f"ai_cache_bound_{index:032d}",
                session_id=f"unique-session-{index}",
                created_at=f"2026-08-09T00:00:{index:02d}+00:00",
            )
            columns = list(values)
            connection.execute(
                f"INSERT INTO ai_advisories ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",
                tuple(values[column] for column in columns),
            )
    result = storage.prune_ai_advisories(
        30,
        max_records=5,
        max_storage_bytes=10_000_000,
        now="2026-08-10T00:00:00+00:00",
    )
    assert result["records_retained"] == 5
    assert len(storage.list_rows("ai_advisories")) == 5
    assert len({row["session_id"] for row in storage.list_rows("ai_advisories")}) == 5
